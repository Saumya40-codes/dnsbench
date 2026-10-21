use std::{fmt, time::Duration};

use hdrhistogram::Histogram;

use crate::dns::{
    message::Rcode,
    udp::{QueryOutcome, QueryReport, RejectedPackets},
};

use super::BenchmarkError;

const LATENCY_GROUPS: [&str; 6] = [
    "NOERROR with answers",
    "NOERROR empty",
    "DNS errors",
    "Truncated",
    "Timeout elapsed",
    "Socket error elapsed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopReason {
    QueryCount,
    Duration,
    SocketError,
    SendDeadline,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::QueryCount => "query count reached",
            Self::Duration => "duration reached",
            Self::SocketError => "socket failure; run stopped early",
            Self::SendDeadline => "query deadline expired before sending; run stopped early",
        })
    }
}

pub(crate) struct RunReport {
    pub(crate) workers: usize,
    pub(crate) stats: RunStats,
    pub(crate) elapsed: Duration,
    pub(crate) stop_reason: StopReason,
}

pub(crate) struct RunStats {
    pub(crate) attempted: u64,
    pub(crate) sent: u64,
    pub(crate) responses: u64,
    pub(crate) timeouts: u64,
    pub(crate) socket_errors: u64,
    pub(crate) rejected: RejectedPackets,
    pub(crate) rcodes: [u64; 16],
    pub(crate) socket_rotations: u64,
    pub(crate) peak_in_flight: usize,
    pub(crate) last_socket_error: Option<String>,
    pub(crate) latencies: [Histogram<u64>; 6],
}

impl RunStats {
    pub(crate) fn merge(&mut self, other: Self) -> Result<(), BenchmarkError> {
        self.attempted += other.attempted;
        self.sent += other.sent;
        self.responses += other.responses;
        self.timeouts += other.timeouts;
        self.socket_errors += other.socket_errors;
        self.rejected.mismatched = self
            .rejected
            .mismatched
            .saturating_add(other.rejected.mismatched);
        self.rejected.malformed = self
            .rejected
            .malformed
            .saturating_add(other.rejected.malformed);
        self.socket_rotations += other.socket_rotations;
        if other.last_socket_error.is_some() {
            self.last_socket_error = other.last_socket_error;
        }
        for (count, additional) in self.rcodes.iter_mut().zip(other.rcodes) {
            *count += additional;
        }
        for (histogram, additional) in self.latencies.iter_mut().zip(other.latencies) {
            histogram.add(additional)?;
        }
        Ok(())
    }

    pub(crate) fn new() -> Result<Self, BenchmarkError> {
        // Fixed range and precision bound memory regardless of query count.
        let histogram = Histogram::new_with_bounds(1, u64::MAX, 3)?;
        Ok(Self {
            attempted: 0,
            sent: 0,
            responses: 0,
            timeouts: 0,
            socket_errors: 0,
            rejected: RejectedPackets::default(),
            rcodes: [0; 16],
            socket_rotations: 0,
            peak_in_flight: 0,
            last_socket_error: None,
            latencies: std::array::from_fn(|_| histogram.clone()),
        })
    }

    pub(crate) fn record(&mut self, report: QueryReport) -> Result<(), BenchmarkError> {
        let group = match &report.outcome {
            QueryOutcome::Response(summary) if summary.truncated => 3,
            QueryOutcome::Response(summary) if summary.rcode != Rcode::NoError => 2,
            QueryOutcome::Response(summary) if summary.answer_count == 0 => 1,
            QueryOutcome::Response(_) => 0,
            QueryOutcome::Timeout => 4,
            QueryOutcome::SocketError(_) => 5,
        };
        let nanos =
            u64::try_from(report.elapsed.as_nanos()).map_err(|_| BenchmarkError::LatencyRange)?;
        self.latencies[group].record(nanos)?;
        self.attempted += 1;
        self.sent += u64::from(report.sent);
        self.peak_in_flight = self.peak_in_flight.max(usize::from(report.sent));
        self.rejected.mismatched = self
            .rejected
            .mismatched
            .saturating_add(report.rejected.mismatched);
        self.rejected.malformed = self
            .rejected
            .malformed
            .saturating_add(report.rejected.malformed);
        match report.outcome {
            QueryOutcome::Response(summary) => {
                self.responses += 1;
                let code = match summary.rcode {
                    Rcode::NoError => 0,
                    Rcode::FormErr => 1,
                    Rcode::ServFail => 2,
                    Rcode::NxDomain => 3,
                    Rcode::NotImp => 4,
                    Rcode::Refused => 5,
                    Rcode::Other(code) => usize::from(code),
                };
                self.rcodes[code] += 1;
            }
            QueryOutcome::Timeout => self.timeouts += 1,
            QueryOutcome::SocketError(error) => {
                self.socket_errors += 1;
                self.last_socket_error = Some(error.to_string());
            }
        }
        Ok(())
    }
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stats = &self.stats;
        let seconds = self.elapsed.as_secs_f64();
        let rate = |count: u64| {
            if seconds > 0.0 {
                count as f64 / seconds
            } else {
                0.0
            }
        };
        writeln!(f, "\nStop: {}", self.stop_reason)?;
        writeln!(f, "Workers: {}", self.workers)?;
        writeln!(
            f,
            "Measured elapsed: {:.3}s (includes any final query completion)",
            seconds
        )?;
        writeln!(
            f,
            "Attempted: {} | Sent: {} | Responses: {}",
            stats.attempted, stats.sent, stats.responses
        )?;
        writeln!(
            f,
            "Timeouts: {} | Socket errors: {}",
            stats.timeouts, stats.socket_errors
        )?;
        writeln!(
            f,
            "Sent QPS: {:.2} | Response QPS: {:.2} | NOERROR-with-answers QPS: {:.2}",
            rate(stats.sent),
            rate(stats.responses),
            rate(stats.latencies[0].len())
        )?;
        if stats.sent > 0 {
            writeln!(
                f,
                "Response rate: {:.2}%",
                stats.responses as f64 / stats.sent as f64 * 100.0
            )?;
        } else {
            writeln!(f, "Response rate: n/a (no queries sent)")?;
        }
        writeln!(
            f,
            "Rejected packets: {} mismatched, {} malformed",
            stats.rejected.mismatched, stats.rejected.malformed
        )?;
        writeln!(f, "Socket rotations: {}", stats.socket_rotations)?;
        writeln!(f, "Peak queries in flight: {}", stats.peak_in_flight)?;
        if let Some(error) = &stats.last_socket_error {
            writeln!(f, "Last socket error: {error}")?;
        }
        write!(f, "RCODE counts:")?;
        for (code, count) in stats
            .rcodes
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
        {
            let label = match code {
                0 => "NOERROR",
                1 => "FORMERR",
                2 => "SERVFAIL",
                3 => "NXDOMAIN",
                4 => "NOTIMP",
                5 => "REFUSED",
                _ => "OTHER",
            };
            write!(f, " {label}({code})={count}")?;
        }
        if stats.responses == 0 {
            write!(f, " none")?;
        }
        writeln!(f, "\nLatency / elapsed (ms; HDR, 3 significant digits):")?;
        writeln!(
            f,
            "{:<24} {:>9} {:>11} {:>11} {:>11} {:>11}",
            "Population", "Count", "p50", "p95", "p99", "max"
        )?;
        for (label, histogram) in LATENCY_GROUPS.iter().zip(&stats.latencies) {
            if histogram.is_empty() {
                writeln!(
                    f,
                    "{label:<24} {:>9} {:>11} {:>11} {:>11} {:>11}",
                    0, "n/a", "n/a", "n/a", "n/a"
                )?;
            } else {
                writeln!(
                    f,
                    "{label:<24} {:>9} {:>11.3} {:>11.3} {:>11.3} {:>11.3}",
                    histogram.len(),
                    histogram.value_at_quantile(0.5) as f64 / 1e6,
                    histogram.value_at_quantile(0.95) as f64 / 1e6,
                    histogram.value_at_quantile(0.99) as f64 / 1e6,
                    histogram.max() as f64 / 1e6
                )?;
            }
        }
        writeln!(
            f,
            "NOERROR with answers is a protocol outcome; answer correctness is not checked."
        )?;
        Ok(())
    }
}
