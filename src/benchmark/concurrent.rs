use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use tokio::{io::Interest, net::UdpSocket, sync::watch};

use crate::{
    config::{RunConfig, StopCondition},
    dns::{
        message::{ResponseError, encode_query, validate_response},
        name::DnsName,
        udp::{QueryOutcome, QueryReport, RejectedPackets},
    },
};

use super::{BenchmarkError, RunReport, RunStats, StopReason, workers::Shared};

const BATCH_SIZE: usize = 256;

#[derive(Debug)]
struct PendingQuery {
    domain_index: usize,
    sent_at: Instant,
}

pub(super) struct Engine {
    config: Arc<RunConfig>,
    domains: Arc<[DnsName]>,
    shared: Arc<Shared>,
    max_in_flight: usize,
    socket: UdpSocket,
    stop_updates: watch::Receiver<()>,
    pending: HashMap<u16, PendingQuery>,
    deadlines: VecDeque<u16>,
    next_id: u32,
    domain_index: Option<usize>,
    stats: RunStats,
    query_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    writable: bool,
    send_started: Option<Instant>,
    started: Instant,
    send_until: Option<Instant>,
    stop_reason: Option<StopReason>,
}

impl Engine {
    pub(super) async fn run(mut self, started: Instant) -> Result<RunReport, BenchmarkError> {
        self.started = started;
        self.send_until = match self.config.stop_condition() {
            StopCondition::Duration(duration) => Some(
                started
                    .checked_add(duration)
                    .ok_or(BenchmarkError::ClockRange)?,
            ),
            StopCondition::Once | StopCondition::QueryCount(_) => None,
        };
        loop {
            match self.step().await {
                Ok(true) => tokio::task::yield_now().await,
                Ok(false) => break,
                Err(BenchmarkError::Io(error)) => {
                    let kind = error.kind();
                    let message = error.to_string();
                    if self.send_started.is_some() || self.pending.is_empty() {
                        self.stats.record(QueryReport {
                            outcome: QueryOutcome::SocketError(io::Error::new(
                                kind,
                                message.clone(),
                            )),
                            sent: false,
                            elapsed: self
                                .send_started
                                .map_or(Duration::ZERO, |time| time.elapsed()),
                            rejected: RejectedPackets::default(),
                        })?;
                    }
                    while let Some(&id) = self.pending.keys().next() {
                        self.complete(
                            id,
                            QueryOutcome::SocketError(io::Error::new(kind, message.clone())),
                        )?;
                    }
                    self.shared.cancel(StopReason::SocketError);
                    self.stop_reason = Some(StopReason::SocketError);
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(RunReport {
            workers: 1,
            threads: self.config.threads().get(),
            stats: self.stats,
            elapsed: self.started.elapsed(),
            stop_reason: self.stop_reason.expect("finished engine has a stop reason"),
        })
    }

    pub(super) fn new(
        config: Arc<RunConfig>,
        domains: Arc<[DnsName]>,
        shared: Arc<Shared>,
        max_in_flight: usize,
    ) -> Result<Self, BenchmarkError> {
        let socket = UdpSocket::from_std(shared.connect(config.server())?)?;
        let stop_updates = shared.stop_updates.subscribe();
        let stats = RunStats::new()?;
        let pending = HashMap::with_capacity(max_in_flight);
        let deadlines = VecDeque::with_capacity(max_in_flight);
        let query_buffer = Vec::with_capacity(12 + 255 + 4);
        let receive_buffer = vec![0; 65_535];
        let started = Instant::now();
        let send_until = match config.stop_condition() {
            StopCondition::Duration(duration) => Some(
                started
                    .checked_add(duration)
                    .ok_or(BenchmarkError::ClockRange)?,
            ),
            StopCondition::Once | StopCondition::QueryCount(_) => None,
        };
        Ok(Self {
            config,
            domains,
            shared,
            max_in_flight,
            socket,
            stop_updates,
            pending,
            deadlines,
            next_id: 0,
            domain_index: None,
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

    async fn step(&mut self) -> Result<bool, BenchmarkError> {
        if self.stop_reason.is_none()
            && let Some(reason) = self.shared.stop_reason()
        {
            self.stop_reason = Some(reason);
            self.send_started = None;
            self.domain_index = None;
        }
        self.expire()?;
        let sent_batch = self.send_batch()?;
        let receive_limit_reached = self.receive_batch()?;
        let next_deadline = self.expire()?;

        // IDs are never reused on a socket, even after their queries have completed.
        if self.next_id > u32::from(u16::MAX)
            && self.pending.is_empty()
            && self.stop_reason.is_none()
        {
            let replacement = UdpSocket::from_std(self.shared.connect(self.config.server())?)?;
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
        // Continue draining a full batch before waiting for readiness again.
        if sent_batch == BATCH_SIZE
            || receive_limit_reached
            || (self.stop_reason.is_none()
                && self.writable
                && self.next_id <= u32::from(u16::MAX)
                && self.pending.len() < self.max_in_flight)
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
        let interest = if self.writable || self.stop_reason.is_some() {
            Interest::READABLE
        } else {
            Interest::READABLE | Interest::WRITABLE
        };
        let deadline = async {
            match wake_at {
                Some(time) => tokio::time::sleep_until(time.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            result = self.socket.ready(interest) => {
                if result?.is_writable() {
                    self.writable = true;
                }
            }
            _ = deadline => {}
            _ = self.stop_updates.changed(), if self.stop_reason.is_none() => {}
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
            if self.pending.len() == self.max_in_flight
                || self.next_id > u32::from(u16::MAX)
                || !self.writable
            {
                break;
            }
            if let Some(reason) = self.shared.stop_reason() {
                self.stop_reason = Some(reason);
                self.send_started = None;
                self.domain_index = None;
                break;
            }
            let domain_index = match self.domain_index {
                Some(index) => index,
                None => {
                    let Some(sequence) = self.shared.claim()? else {
                        self.stop_reason = Some(StopReason::QueryCount);
                        break;
                    };
                    let index = (sequence % self.domains.len() as u64) as usize;
                    self.domain_index = Some(index);
                    index
                }
            };
            let id = self.next_id as u16;
            encode_query(
                &self.domains[domain_index],
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
                self.shared.cancel(StopReason::SendDeadline);
                break;
            }
            // Encoding and scheduler work may have consumed the final send window.
            if self.send_until.is_some_and(|time| Instant::now() >= time) {
                self.send_started = None;
                self.stop_reason = Some(StopReason::Duration);
                break;
            }
            match self.socket.try_send(&self.query_buffer) {
                Ok(length) if length == self.query_buffer.len() => {
                    self.pending.insert(
                        id,
                        PendingQuery {
                            domain_index,
                            sent_at: started,
                        },
                    );
                    self.deadlines.push_back(id);
                    self.stats.peak_in_flight = self.stats.peak_in_flight.max(self.pending.len());
                    let active = self.shared.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                    self.shared
                        .peak_in_flight
                        .fetch_max(active, Ordering::Relaxed);
                    self.next_id += 1;
                    self.domain_index = None;
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
            let length = match self.socket.try_recv(&mut self.receive_buffer) {
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
        if self.deadlines.len() > self.max_in_flight * 2 {
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
            self.shared.cancel(StopReason::SendDeadline);
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
        self.shared.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.stats.record(QueryReport {
            outcome,
            sent: true,
            elapsed: pending.sent_at.elapsed(),
            rejected: RejectedPackets::default(),
        })
    }
}

#[cfg(test)]
mod tests;
