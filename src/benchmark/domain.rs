use crate::dns::{
    message::ResponseSummary,
    udp::{QueryOutcome, QueryReport},
};

#[derive(Debug)]
pub(crate) struct SlowestResponse {
    pub(crate) elapsed_ns: u64,
    pub(crate) summary: ResponseSummary,
    pub(crate) packet: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct DomainStats {
    pub(crate) attempted: u64,
    pub(crate) sent: u64,
    pub(crate) responses: u64,
    pub(crate) timeouts: u64,
    pub(crate) socket_errors: u64,
    pub(crate) slowest: Option<SlowestResponse>,
}

impl DomainStats {
    pub(crate) fn record(&mut self, report: &QueryReport, packet: Option<&[u8]>) {
        self.attempted += 1;
        self.sent += u64::from(report.sent);
        match &report.outcome {
            QueryOutcome::Response(summary) => {
                self.responses += 1;
                let elapsed_ns = report.elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
                if self
                    .slowest
                    .as_ref()
                    .is_none_or(|sample| elapsed_ns > sample.elapsed_ns)
                {
                    self.slowest = Some(SlowestResponse {
                        elapsed_ns,
                        summary: *summary,
                        packet: packet.unwrap_or_default().to_vec(),
                    });
                }
            }
            QueryOutcome::Timeout => self.timeouts += 1,
            QueryOutcome::SocketError(_) => self.socket_errors += 1,
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.attempted += other.attempted;
        self.sent += other.sent;
        self.responses += other.responses;
        self.timeouts += other.timeouts;
        self.socket_errors += other.socket_errors;
        if let Some(sample) = other.slowest
            && self
                .slowest
                .as_ref()
                .is_none_or(|current| sample.elapsed_ns > current.elapsed_ns)
        {
            self.slowest = Some(sample);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{message::Rcode, udp::RejectedPackets};
    use std::time::Duration;

    #[test]
    fn only_a_slower_response_replaces_its_associated_packet() {
        let mut stats = DomainStats::default();
        for (elapsed, packet) in [(20, b"slow".as_slice()), (5, b"fast".as_slice())] {
            stats.record(
                &QueryReport {
                    outcome: QueryOutcome::Response(ResponseSummary {
                        rcode: Rcode::NoError,
                        truncated: false,
                        answer_count: 1,
                    }),
                    sent: true,
                    elapsed: Duration::from_millis(elapsed),
                    rejected: RejectedPackets::default(),
                },
                Some(packet),
            );
        }
        stats.record(
            &QueryReport {
                outcome: QueryOutcome::Timeout,
                sent: true,
                elapsed: Duration::from_secs(2),
                rejected: RejectedPackets::default(),
            },
            None,
        );
        assert_eq!(stats.responses, 2);
        assert_eq!(stats.timeouts, 1);
        let sample = stats.slowest.unwrap();
        assert_eq!(sample.elapsed_ns, 20_000_000);
        assert_eq!(sample.packet, b"slow");
    }
}
