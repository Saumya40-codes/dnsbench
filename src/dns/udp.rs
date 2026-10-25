use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use crate::config::QueryType;

use super::{
    message::{ResponseError, ResponseSummary, encode_query, validate_response},
    name::DnsName,
};

const MAX_QUERY_LEN: usize = 12 + 255 + 4;
const RECEIVE_CAPACITY: usize = 65_535;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RejectedPackets {
    pub(crate) mismatched: u64,
    pub(crate) malformed: u64,
}

#[derive(Debug)]
pub(crate) enum QueryOutcome {
    Response(ResponseSummary),
    Timeout,
    SocketError(io::Error),
}

#[derive(Debug)]
pub(crate) struct QueryReport {
    pub(crate) outcome: QueryOutcome,
    pub(crate) sent: bool,
    pub(crate) elapsed: Duration,
    pub(crate) rejected: RejectedPackets,
}

pub(crate) struct UdpClient {
    socket: UdpSocket,
    query_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    receive_len: usize,
}

impl UdpClient {
    pub(crate) fn response_packet(&self) -> &[u8] {
        &self.receive_buffer[..self.receive_len]
    }
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn connect(server: SocketAddr) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(local)?;
        // UDP connect selects a peer and filters incoming sources; no handshake occurs.
        socket.connect(server)?;

        Ok(Self {
            socket,
            query_buffer: Vec::with_capacity(MAX_QUERY_LEN),
            receive_buffer: vec![0; RECEIVE_CAPACITY],
            receive_len: 0,
        })
    }

    // One exchange at a time. The caller must avoid IDs still associated with late replies.
    // send_by stops new sends; a sent query retains its own response timeout.
    pub(crate) fn query(
        &mut self,
        name: &DnsName,
        id: u16,
        query_type: QueryType,
        recursion_desired: bool,
        timeout: Duration,
        send_by: Option<Instant>,
    ) -> io::Result<QueryReport> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "query timeout must be positive",
            ));
        }
        encode_query(
            name,
            id,
            query_type,
            recursion_desired,
            &mut self.query_buffer,
        );

        // Measure the successful send attempt to receipt; accept the sample only after validation.
        let started = Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "query timeout exceeds the clock's range",
            )
        })?;
        let mut rejected = RejectedPackets::default();
        let mut sent_at = None;
        let mut received_at = None;
        let outcome = self.exchange_until(
            deadline,
            send_by,
            timeout,
            &mut rejected,
            &mut sent_at,
            &mut received_at,
        );

        Ok(QueryReport {
            outcome,
            sent: sent_at.is_some(),
            elapsed: received_at
                .unwrap_or_else(Instant::now)
                .saturating_duration_since(sent_at.unwrap_or(started)),
            rejected,
        })
    }

    fn exchange_until(
        &mut self,
        deadline: Instant,
        send_by: Option<Instant>,
        timeout: Duration,
        rejected: &mut RejectedPackets,
        sent_at: &mut Option<Instant>,
        received_at: &mut Option<Instant>,
    ) -> QueryOutcome {
        loop {
            let send_deadline = send_by.map_or(deadline, |limit| limit.min(deadline));
            let remaining = send_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return QueryOutcome::Timeout;
            }
            if let Err(error) = self.socket.set_write_timeout(Some(remaining)) {
                return QueryOutcome::SocketError(error);
            }
            let attempted_at = Instant::now();
            match self.socket.send(&self.query_buffer) {
                Ok(length) if length == self.query_buffer.len() => {
                    *sent_at = Some(attempted_at);
                    break;
                }
                Ok(_) => {
                    return QueryOutcome::SocketError(io::Error::new(
                        ErrorKind::WriteZero,
                        "UDP send did not write the complete query",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return QueryOutcome::SocketError(error),
            }
        }

        let Some(deadline) = sent_at.expect("query was sent").checked_add(timeout) else {
            return QueryOutcome::SocketError(io::Error::new(
                ErrorKind::InvalidInput,
                "query timeout exceeds the clock's range",
            ));
        };
        loop {
            // Recompute the remaining budget, so rejected packets never reset the deadline.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return QueryOutcome::Timeout;
            }
            if let Err(error) = self.socket.set_read_timeout(Some(remaining)) {
                return QueryOutcome::SocketError(error);
            }
            let length = match self.socket.recv(&mut self.receive_buffer) {
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return QueryOutcome::SocketError(error),
            };
            let arrived_at = Instant::now();
            if arrived_at >= deadline {
                *received_at = Some(arrived_at);
                return QueryOutcome::Timeout;
            }

            self.receive_len = length;
            match validate_response(&self.query_buffer, &self.receive_buffer[..length]) {
                Ok(summary) => {
                    *received_at = Some(arrived_at);
                    return QueryOutcome::Response(summary);
                }
                Err(
                    ResponseError::IdMismatch
                    | ResponseError::QuestionMismatch
                    | ResponseError::OpcodeMismatch
                    | ResponseError::NotAResponse,
                ) => {
                    rejected.mismatched = rejected.mismatched.saturating_add(1);
                }
                Err(_) => {
                    rejected.malformed = rejected.malformed.saturating_add(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
