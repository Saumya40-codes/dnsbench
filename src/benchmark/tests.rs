use super::*;
use crate::{
    config::{QueryType, RunConfigInput},
    dns::{
        message::{Rcode, ResponseSummary},
        udp::{QueryReport, RejectedPackets},
    },
};
use std::{
    net::{SocketAddr, UdpSocket},
    num::NonZeroU64,
    thread,
    time::Duration,
};

fn config(server: SocketAddr, stop: StopCondition) -> RunConfig {
    RunConfig::try_from(RunConfigInput {
        server,
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: stop,
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap()
}

fn server() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

fn names() -> Vec<DnsName> {
    ["a.com", "b.com", "c.com", "d.com", "e.com"]
        .into_iter()
        .map(|name| DnsName::parse(name).unwrap())
        .collect()
}

#[test]
fn count_mode_cycles_workload_and_counts_actual_sends() {
    let socket = server();
    let config = config(
        socket.local_addr().unwrap(),
        StopCondition::QueryCount(NonZeroU64::new(7).unwrap()),
    );
    let handle = thread::spawn(move || {
        let mut observed = Vec::new();
        let mut packet = [0; 512];
        for _ in 0..7 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            observed.push((
                u16::from_be_bytes([packet[0], packet[1]]),
                packet[13],
                peer.port(),
            ));
            packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            socket.send_to(&packet[..length], peer).unwrap();
        }
        observed
    });
    let report = run(&config, &mut names()).unwrap();
    let observed = handle.join().unwrap();
    assert_eq!(
        observed.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        observed.iter().map(|entry| entry.1).collect::<Vec<_>>(),
        b"abcdeab"
    );
    assert!(observed.iter().all(|entry| entry.2 == observed[0].2));
    assert_eq!(report.stop_reason, StopReason::QueryCount);
    assert_eq!(report.stats.attempted, 7);
    assert_eq!(report.stats.sent, 7);
    assert_eq!(report.stats.responses, 7);
    assert_eq!(report.stats.latencies[1].len(), 7);
}

#[test]
fn duration_mode_drains_the_outstanding_query_then_stops() {
    let socket = server();
    let mut config = config(
        socket.local_addr().unwrap(),
        StopCondition::Duration(Duration::from_millis(30)),
    );
    config = RunConfig::try_from(RunConfigInput {
        server: config.server(),
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: config.stop_condition(),
        timeout: Duration::from_millis(90),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    let report = run(&config, &mut names()).unwrap();
    assert_eq!(report.stop_reason, StopReason::Duration);
    assert_eq!(report.stats.sent, 1);
    assert_eq!(report.stats.timeouts, 1);
    assert!(report.elapsed >= Duration::from_millis(90));
    socket.set_nonblocking(true).unwrap();
    let mut packet = [0; 512];
    assert!(socket.recv_from(&mut packet).is_ok());
    assert_eq!(
        socket.recv_from(&mut packet).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn an_unsent_timeout_stops_count_mode_instead_of_spinning() {
    let socket = server();
    let config = RunConfig::try_from(RunConfigInput {
        server: socket.local_addr().unwrap(),
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
        timeout: Duration::from_nanos(1),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    let report = run(&config, &mut names()).unwrap();
    assert_eq!(report.stop_reason, StopReason::SendDeadline);
    assert_eq!(report.stats.attempted, 1);
    assert_eq!(report.stats.sent, 0);
    assert_eq!(report.stats.timeouts, 1);
}

#[test]
fn shuffle_is_seeded_preserves_entries_and_repeats_one_permutation() {
    let mut permutations = Vec::new();
    for seed in [42, 42, 0] {
        let socket = server();
        let config = RunConfig::try_from(RunConfigInput {
            server: socket.local_addr().unwrap(),
            transport: crate::config::Transport::Udp,
            domains_path: "domains.txt".into(),
            max_in_flight: 1,
            workers: 1,
            threads: Some(1),
            stop_condition: StopCondition::QueryCount(NonZeroU64::new(10).unwrap()),
            timeout: Duration::from_secs(2),
            default_query_type: QueryType::A,
            order: QueryOrder::Shuffled { seed },
        })
        .unwrap();
        let handle = thread::spawn(move || {
            let mut observed = Vec::new();
            let mut packet = [0; 512];
            for _ in 0..10 {
                let (length, peer) = socket.recv_from(&mut packet).unwrap();
                observed.push(packet[13]);
                packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                socket.send_to(&packet[..length], peer).unwrap();
            }
            observed
        });
        run(&config, &mut names()).unwrap();
        let observed = handle.join().unwrap();
        assert_eq!(&observed[..5], &observed[5..]);
        let mut sorted = observed[..5].to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, b"abcde");
        permutations.push(observed);
    }
    assert_eq!(permutations[0], permutations[1]);
    assert_ne!(permutations[0], permutations[2]);
}

#[test]
fn records_each_outcome_in_exactly_one_latency_population() {
    let mut stats = RunStats::new().unwrap();
    for (outcome, sent) in [
        (
            QueryOutcome::Response(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: false,
                answer_count: 1,
            }),
            true,
        ),
        (
            QueryOutcome::Response(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: false,
                answer_count: 0,
            }),
            true,
        ),
        (
            QueryOutcome::Response(ResponseSummary {
                rcode: Rcode::ServFail,
                truncated: false,
                answer_count: 0,
            }),
            true,
        ),
        (
            QueryOutcome::Response(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: true,
                answer_count: 1,
            }),
            true,
        ),
        (QueryOutcome::Timeout, true),
        (
            QueryOutcome::SocketError(io::Error::from(io::ErrorKind::ConnectionRefused)),
            false,
        ),
    ] {
        stats
            .record(QueryReport {
                outcome,
                sent,
                elapsed: Duration::from_millis(2),
                rejected: RejectedPackets {
                    malformed: 1,
                    mismatched: 2,
                },
            })
            .unwrap();
    }
    assert_eq!(
        stats.attempted,
        stats.responses + stats.timeouts + stats.socket_errors
    );
    assert_eq!(stats.attempted, 6);
    assert_eq!(stats.sent, 5);
    assert_eq!(stats.responses, 4);
    assert_eq!(stats.rcodes[0], 3);
    assert_eq!(stats.rcodes[2], 1);
    assert_eq!(stats.rcodes.iter().sum::<u64>(), stats.responses);
    assert!(stats.latencies.iter().all(|histogram| histogram.len() == 1));
    assert_eq!(
        stats.rejected,
        RejectedPackets {
            malformed: 6,
            mismatched: 12
        }
    );
}

#[test]
fn empty_populations_are_displayed_as_unavailable_not_zero_latency() {
    let report = RunReport {
        workers: 1,
        threads: 1,
        stats: RunStats::new().unwrap(),
        elapsed: Duration::ZERO,
        stop_reason: StopReason::Duration,
    };
    let text = report.to_string();
    assert!(text.contains("n/a"));
    assert!(!text.contains("NaN"));
    assert!(!text.contains("inf"));
}

#[test]
fn rejects_unsupported_max_in_flight_empty_workloads_and_clock_overflow() {
    let mut input = RunConfigInput {
        server: "127.0.0.1:53".parse().unwrap(),
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 65_537,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::Duration(Duration::from_secs(1)),
        timeout: Duration::from_secs(1),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    };
    let unsupported = RunConfig::try_from(input).unwrap();
    assert!(matches!(
        run(&unsupported, &mut names()),
        Err(BenchmarkError::UnsupportedInFlightLimit)
    ));
    input = RunConfigInput {
        server: unsupported.server(),
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::Duration(Duration::MAX),
        timeout: Duration::from_secs(1),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    };
    let oversized = RunConfig::try_from(input).unwrap();
    assert!(matches!(
        run(&oversized, &mut names()),
        Err(BenchmarkError::ClockRange)
    ));
    assert!(matches!(
        run(&oversized, &mut []),
        Err(BenchmarkError::EmptyWorkload)
    ));
}

#[test]
fn id_exhaustion_rotates_source_port_before_reusing_zero() {
    let socket = server();
    let config = config(
        socket.local_addr().unwrap(),
        StopCondition::QueryCount(NonZeroU64::new(65_537).unwrap()),
    );
    let handle = thread::spawn(move || {
        let mut packet = [0; 512];
        let mut first_port = None;
        for index in 0..65_537u32 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), index as u16);
            if index == 0 {
                first_port = Some(peer.port());
            }
            if index == 65_536 {
                assert_ne!(Some(peer.port()), first_port);
            }
            packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            socket.send_to(&packet[..length], peer).unwrap();
        }
    });
    let report = run(&config, &mut names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.sent, 65_537);
    assert_eq!(report.stats.responses, 65_537);
    assert_eq!(report.stats.socket_rotations, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn socket_failure_stops_early_and_preserves_accounting() {
    let socket = server();
    let config = config(
        socket.local_addr().unwrap(),
        StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
    );
    drop(socket);
    let report = run(&config, &mut names()).unwrap();
    assert_eq!(report.stop_reason, StopReason::SocketError);
    assert_eq!(report.stats.attempted, 1);
    assert_eq!(report.stats.sent, 1);
    assert_eq!(report.stats.responses, 0);
    assert_eq!(report.stats.socket_errors, 1);
    assert!(report.stats.last_socket_error.is_some());
    assert_eq!(report.stats.latencies[5].len(), 1);
}
