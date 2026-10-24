use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use mio::{Events, Interest, Poll, Token, net::UdpSocket};

use crate::{
    config::{RunConfig, StopCondition},
    dns::{
        message::{ResponseError, encode_query, validate_response},
        name::DnsName,
        udp::{QueryOutcome, QueryReport, RejectedPackets},
    },
};

use super::{BenchmarkError, RunReport, RunStats, StopReason};

const SOCKET: Token = Token(0);
const BATCH_SIZE: usize = 256;

#[derive(Debug)]
struct PendingQuery {
    domain_index: usize,
    sent_at: Instant,
}

struct Engine<'a> {
    config: &'a RunConfig,
    domains: &'a [DnsName],
    socket: UdpSocket,
    poll: Poll,
    events: Events,
    pending: HashMap<u16, PendingQuery>,
    deadlines: VecDeque<u16>,
    used_ports: [u64; 1024],
    next_id: u32,
    domain_index: usize,
    sent: u64,
    stats: RunStats,
    query_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    writable: bool,
    send_started: Option<Instant>,
    started: Instant,
    send_until: Option<Instant>,
    stop_reason: Option<StopReason>,
}

pub(super) fn run(config: &RunConfig, domains: &[DnsName]) -> Result<RunReport, BenchmarkError> {
    let mut engine = Engine::new(config, domains)?;

    loop {
        match engine.step() {
            Ok(true) => {}
            Ok(false) => break,
            Err(BenchmarkError::Io(error)) => {
                let kind = error.kind();
                let message = error.to_string();
                if engine.send_started.is_some() || engine.pending.is_empty() {
                    engine.stats.record(QueryReport {
                        outcome: QueryOutcome::SocketError(io::Error::new(kind, message.clone())),
                        sent: false,
                        elapsed: engine
                            .send_started
                            .map_or(Duration::ZERO, |time| time.elapsed()),
                        rejected: RejectedPackets::default(),
                    })?;
                }
                while let Some(&id) = engine.pending.keys().next() {
                    engine.complete(
                        id,
                        QueryOutcome::SocketError(io::Error::new(kind, message.clone())),
                    )?;
                }
                engine.stop_reason = Some(StopReason::SocketError);
                break;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(RunReport {
        stats: engine.stats,
        elapsed: engine.started.elapsed(),
        stop_reason: engine
            .stop_reason
            .expect("finished engine has a stop reason"),
    })
}

impl<'a> Engine<'a> {
    fn new(config: &'a RunConfig, domains: &'a [DnsName]) -> Result<Self, BenchmarkError> {
        let poll = Poll::new()?;
        let mut socket = connect(config.server())?;
        poll.registry()
            .register(&mut socket, SOCKET, Interest::READABLE | Interest::WRITABLE)?;
        let mut used_ports = [0u64; 1024];
        let port = usize::from(socket.local_addr()?.port());
        used_ports[port / 64] |= 1u64 << (port % 64);
        let stats = RunStats::new()?;
        let pending = HashMap::with_capacity(config.concurrency().get());
        let deadlines = VecDeque::with_capacity(config.concurrency().get());
        let events = Events::with_capacity(8);
        let query_buffer = Vec::with_capacity(12 + 255 + 4);
        let receive_buffer = vec![0; 65_535];
        let started = Instant::now();
        let send_until = match config.stop_condition() {
            StopCondition::Duration(duration) => Some(
                started
                    .checked_add(duration)
                    .ok_or(BenchmarkError::ClockRange)?,
            ),
            StopCondition::QueryCount(_) => None,
        };
        Ok(Self {
            config,
            domains,
            socket,
            poll,
            events,
            pending,
            deadlines,
            used_ports,
            next_id: 0,
            domain_index: 0,
            sent: 0,
            stats,
            query_buffer,
            receive_buffer,
            writable: true,
            send_started: None,
            started,
            send_until,
            stop_reason: None,
        })
    }

    fn step(&mut self) -> Result<bool, BenchmarkError> {
        self.expire()?;
        let sent_batch = self.send_batch()?;
        let receive_limit_reached = self.receive_batch()?;
        let next_deadline = self.expire()?;

        // IDs are never reused on a socket, even after their queries have completed.
        if self.next_id > u32::from(u16::MAX)
            && self.pending.is_empty()
            && self.stop_reason.is_none()
        {
            let mut replacement = None;
            for _ in 0..64 {
                let candidate = connect(self.config.server())?;
                let port = usize::from(candidate.local_addr()?.port());
                let mask = 1u64 << (port % 64);
                if self.used_ports[port / 64] & mask == 0 {
                    self.used_ports[port / 64] |= mask;
                    replacement = Some(candidate);
                    break;
                }
            }
            let mut replacement = replacement.ok_or(BenchmarkError::SourcePortsExhausted)?;
            self.poll.registry().deregister(&mut self.socket)?;
            self.poll.registry().register(
                &mut replacement,
                SOCKET,
                Interest::READABLE | Interest::WRITABLE,
            )?;
            self.socket = replacement;
            self.next_id = 0;
            self.deadlines.clear();
            self.writable = true;
            self.stats.socket_rotations += 1;
            return Ok(true);
        }

        if self.stop_reason.is_some() && self.pending.is_empty() {
            return Ok(false);
        }
        // A bounded batch yields to deadlines without losing edge-triggered readiness.
        if sent_batch == BATCH_SIZE
            || receive_limit_reached
            || (self.stop_reason.is_none()
                && self.writable
                && self.next_id <= u32::from(u16::MAX)
                && self.pending.len() < self.config.concurrency().get())
        {
            return Ok(true);
        }

        let mut wake_at = next_deadline;
        if self.stop_reason.is_none() {
            for deadline in [
                self.send_until,
                self.send_started
                    .map(|time| {
                        time.checked_add(self.config.timeout())
                            .ok_or(BenchmarkError::ClockRange)
                    })
                    .transpose()?,
            ]
            .into_iter()
            .flatten()
            {
                wake_at = Some(wake_at.map_or(deadline, |current| current.min(deadline)));
            }
        }
        let timeout = wake_at.map(|time| time.saturating_duration_since(Instant::now()));
        match self.poll.poll(&mut self.events, timeout) {
            Ok(()) => {
                for event in &self.events {
                    if event.token() == SOCKET && event.is_writable() {
                        self.writable = true;
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        Ok(true)
    }

    fn send_batch(&mut self) -> Result<usize, BenchmarkError> {
        let mut sent = 0;
        for _ in 0..BATCH_SIZE {
            if self.stop_reason.is_some() {
                break;
            }
            if self.send_until.is_some_and(|time| Instant::now() >= time) {
                self.stop_reason = Some(StopReason::Duration);
                self.send_started = None;
                break;
            }
            if let StopCondition::QueryCount(count) = self.config.stop_condition()
                && self.sent >= count.get()
            {
                self.stop_reason = Some(StopReason::QueryCount);
                break;
            }
            if self.pending.len() == self.config.concurrency().get()
                || self.next_id > u32::from(u16::MAX)
                || !self.writable
            {
                break;
            }
            let id = self.next_id as u16;
            encode_query(
                &self.domains[self.domain_index],
                id,
                self.config.default_query_type(),
                true,
                &mut self.query_buffer,
            );
            let started = *self.send_started.get_or_insert_with(Instant::now);
            let deadline = started
                .checked_add(self.config.timeout())
                .ok_or(BenchmarkError::ClockRange)?;
            if Instant::now() >= deadline {
                self.stats.record(QueryReport {
                    outcome: QueryOutcome::Timeout,
                    sent: false,
                    elapsed: started.elapsed(),
                    rejected: RejectedPackets::default(),
                })?;
                self.send_started = None;
                self.stop_reason = Some(StopReason::SendDeadline);
                break;
            }
            // Encoding and scheduler work may have consumed the final send window.
            if self.send_until.is_some_and(|time| Instant::now() >= time) {
                self.send_started = None;
                self.stop_reason = Some(StopReason::Duration);
                break;
            }
            match self.socket.send(&self.query_buffer) {
                Ok(length) if length == self.query_buffer.len() => {
                    self.pending.insert(
                        id,
                        PendingQuery {
                            domain_index: self.domain_index,
                            sent_at: started,
                        },
                    );
                    self.deadlines.push_back(id);
                    self.stats.peak_in_flight = self.stats.peak_in_flight.max(self.pending.len());
                    self.next_id += 1;
                    self.domain_index = (self.domain_index + 1) % self.domains.len();
                    self.sent += 1;
                    sent += 1;
                    self.send_started = None;
                }
                Ok(_) => {
                    return Err(io::Error::new(ErrorKind::WriteZero, "incomplete UDP send").into());
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.writable = false;
                    break;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(sent)
    }

    fn receive_batch(&mut self) -> Result<bool, BenchmarkError> {
        for _ in 0..BATCH_SIZE {
            let length = match self.socket.recv(&mut self.receive_buffer) {
                Ok(length) => length,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if length < 12 {
                self.stats.rejected.malformed = self.stats.rejected.malformed.saturating_add(1);
                continue;
            }
            let id = u16::from_be_bytes([self.receive_buffer[0], self.receive_buffer[1]]);
            let Some(pending) = self.pending.get(&id) else {
                self.stats.rejected.mismatched = self.stats.rejected.mismatched.saturating_add(1);
                continue;
            };
            if pending.sent_at.elapsed() >= self.config.timeout() {
                self.complete(id, QueryOutcome::Timeout)?;
                self.stats.rejected.mismatched = self.stats.rejected.mismatched.saturating_add(1);
                continue;
            }
            // Rebuild into one reusable buffer instead of retaining a packet per pending query.
            encode_query(
                &self.domains[pending.domain_index],
                id,
                self.config.default_query_type(),
                true,
                &mut self.query_buffer,
            );
            match validate_response(&self.query_buffer, &self.receive_buffer[..length]) {
                Ok(summary) => {
                    let outcome = if pending.sent_at.elapsed() >= self.config.timeout() {
                        QueryOutcome::Timeout
                    } else {
                        QueryOutcome::Response(summary)
                    };
                    self.complete(id, outcome)?;
                }
                Err(
                    ResponseError::IdMismatch
                    | ResponseError::QuestionMismatch
                    | ResponseError::OpcodeMismatch
                    | ResponseError::NotAResponse,
                ) => {
                    self.stats.rejected.mismatched =
                        self.stats.rejected.mismatched.saturating_add(1);
                }
                Err(_) => {
                    self.stats.rejected.malformed = self.stats.rejected.malformed.saturating_add(1);
                }
            }
        }
        Ok(true)
    }

    fn expire(&mut self) -> Result<Option<Instant>, BenchmarkError> {
        // A fixed timeout keeps deadlines in send order; no heap or full-map scan is needed.
        while let Some(&id) = self.deadlines.front() {
            let Some(pending) = self.pending.get(&id) else {
                self.deadlines.pop_front();
                continue;
            };
            let deadline = pending
                .sent_at
                .checked_add(self.config.timeout())
                .ok_or(BenchmarkError::ClockRange)?;
            if Instant::now() < deadline {
                break;
            }
            self.deadlines.pop_front();
            self.complete(id, QueryOutcome::Timeout)?;
        }
        // An early slow query must not retain an unbounded history of completed IDs.
        if self.deadlines.len() > self.config.concurrency().get() * 2 {
            self.deadlines.retain(|id| self.pending.contains_key(id));
        }
        if self.stop_reason.is_none()
            && self.send_until.is_none_or(|time| Instant::now() < time)
            && let Some(started) = self.send_started
            && started.elapsed() >= self.config.timeout()
        {
            self.stats.record(QueryReport {
                outcome: QueryOutcome::Timeout,
                sent: false,
                elapsed: started.elapsed(),
                rejected: RejectedPackets::default(),
            })?;
            self.send_started = None;
            self.stop_reason = Some(StopReason::SendDeadline);
        }
        self.deadlines
            .front()
            .map(|id| {
                self.pending[id]
                    .sent_at
                    .checked_add(self.config.timeout())
                    .ok_or(BenchmarkError::ClockRange)
            })
            .transpose()
    }

    fn complete(&mut self, id: u16, outcome: QueryOutcome) -> Result<(), BenchmarkError> {
        let pending = self.pending.remove(&id).expect("query is pending");
        self.stats.record(QueryReport {
            outcome,
            sent: true,
            elapsed: pending.sent_at.elapsed(),
            rejected: RejectedPackets::default(),
        })
    }
}

fn connect(server: SocketAddr) -> io::Result<UdpSocket> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(server)?;
    Ok(socket)
}

#[cfg(test)]
mod tests;
