use std::{collections::HashMap, net::UdpSocket, num::NonZeroU64};

use super::*;
use crate::config::{QueryOrder, QueryType, RunConfigInput};

fn setup(
    concurrency: usize,
    workers: Option<usize>,
    stop: StopCondition,
) -> (UdpSocket, RunConfig) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let config = RunConfig::try_from(RunConfigInput {
        server: socket.local_addr().unwrap(),
        domains_path: "domains.txt".into(),
        concurrency,
        workers,
        stop_condition: stop,
        timeout: Duration::from_millis(200),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    (socket, config)
}

#[test]
fn workers_share_count_and_concurrency_and_match_identical_ids_on_distinct_sockets() {
    let (socket, config) = setup(
        8,
        Some(3),
        StopCondition::QueryCount(NonZeroU64::new(8).unwrap()),
    );
    let handle = thread::spawn(move || {
        let mut packet = [0; 512];
        let mut batch = Vec::new();
        let mut per_port = HashMap::new();
        let mut domains = Vec::new();
        for _ in 0..8 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            per_port
                .entry(peer.port())
                .or_insert_with(Vec::new)
                .push(u16::from_be_bytes([packet[0], packet[1]]));
            domains.push(packet[13]);
            let mut response = packet[..length].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            batch.push((response, peer));
        }
        for (response, peer) in batch.into_iter().rev() {
            socket.send_to(&response, peer).unwrap();
        }
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut packet).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(per_port.len(), 3);
        let mut sizes: Vec<_> = per_port.values().map(Vec::len).collect();
        sizes.sort_unstable();
        assert_eq!(sizes, [2, 3, 3]);
        assert!(per_port.values().all(|ids| ids[0] == 0));
        domains.sort_unstable();
        assert_eq!(domains, b"aaabbbcc");
    });
    let mut domains = ["a.com", "b.com", "c.com"].map(|name| DnsName::parse(name).unwrap());
    let report = crate::benchmark::run(&config, &mut domains).unwrap();
    handle.join().unwrap();
    assert_eq!(report.workers, 3);
    assert_eq!(report.stats.sent, 8);
    assert_eq!(report.stats.attempted, 8);
    assert_eq!(report.stats.responses, 8);
    assert_eq!(report.stats.timeouts, 0);
    assert_eq!(report.stats.latencies[1].len(), 8);
    assert_eq!(report.stats.rcodes[0], 8);
    assert!((3..=8).contains(&report.stats.peak_in_flight));
}

#[test]
fn a_busy_worker_cannot_multiply_the_global_query_budget() {
    let (socket, config) = setup(
        8,
        Some(4),
        StopCondition::QueryCount(NonZeroU64::new(1_003).unwrap()),
    );
    let handle = thread::spawn(move || {
        let mut packet = [0; 512];
        for _ in 0..1_003 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            socket.send_to(&packet[..length], peer).unwrap();
        }
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut packet).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
    let report = run(&config, &[DnsName::parse("a.com").unwrap()]).unwrap();
    handle.join().unwrap();
    assert_eq!(report.workers, 4);
    assert_eq!(report.stats.sent, 1_003);
    assert_eq!(report.stats.responses, 1_003);
    assert_eq!(report.stats.timeouts, 0);
    assert!(report.stats.peak_in_flight <= 8);
}

#[test]
fn every_worker_obeys_the_common_duration_and_drains_its_queries() {
    let (socket, config) = setup(
        8,
        Some(3),
        StopCondition::Duration(Duration::from_millis(60)),
    );
    let report = run(&config, &[DnsName::parse("a.com").unwrap()]).unwrap();
    assert_eq!(report.workers, 3);
    assert_eq!(report.stop_reason, StopReason::Duration);
    assert_eq!(report.stats.sent, 8);
    assert_eq!(report.stats.timeouts, 8);
    assert_eq!(report.stats.attempted, 8);
    assert_eq!(report.stats.peak_in_flight, 8);
    assert!(report.elapsed >= config.timeout());
    let mut ports = HashMap::new();
    for _ in 0..8 {
        let (_, peer) = socket.recv_from(&mut [0; 512]).unwrap();
        *ports.entry(peer.port()).or_insert(0) += 1;
    }
    assert_eq!(ports.len(), 3);
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn default_workers_are_bounded_by_cpus_concurrency_and_count() {
    let (_socket, config) = setup(
        64,
        None,
        StopCondition::QueryCount(NonZeroU64::new(2).unwrap()),
    );
    assert_eq!(
        worker_count(&config),
        thread::available_parallelism()
            .map_or(1, |count| count.get())
            .min(2)
    );
    let (_socket, config) = setup(
        64,
        Some(8),
        StopCondition::QueryCount(NonZeroU64::new(2).unwrap()),
    );
    assert_eq!(worker_count(&config), 2);
}

#[test]
fn query_reservations_are_unique_under_contention() {
    let (_socket, config) = setup(
        8,
        Some(4),
        StopCondition::QueryCount(NonZeroU64::new(1_003).unwrap()),
    );
    let shared = Shared::new(&config);
    let mut sequences = thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let shared = &shared;
                scope.spawn(move || {
                    let mut claimed = Vec::new();
                    while let Some(sequence) = shared.claim().unwrap() {
                        claimed.push(sequence);
                    }
                    claimed
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    sequences.sort_unstable();
    assert_eq!(sequences, (0..1_003).collect::<Vec<_>>());
    assert!(shared.claim().unwrap().is_none());
}

#[test]
fn source_port_history_outlives_individual_worker_sockets() {
    let (_server, config) = setup(
        8,
        Some(4),
        StopCondition::QueryCount(NonZeroU64::new(8).unwrap()),
    );
    let shared = Shared::new(&config);
    let first = shared.connect(config.server()).unwrap();
    let first_port = usize::from(first.local_addr().unwrap().port());
    drop(first);
    let second = shared.connect(config.server()).unwrap();
    let second_port = usize::from(second.local_addr().unwrap().port());
    assert_ne!(first_port, second_port);
    let ports = shared.used_ports.lock().unwrap();
    for port in [first_port, second_port] {
        assert_ne!(ports[port / 64] & (1u64 << (port % 64)), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socket_failure_stops_the_entire_pool_and_preserves_sent_accounting() {
    let (socket, config) = setup(
        8,
        Some(4),
        StopCondition::QueryCount(NonZeroU64::new(1_003).unwrap()),
    );
    drop(socket);
    let report = run(&config, &[DnsName::parse("a.com").unwrap()]).unwrap();
    assert_eq!(report.stop_reason, StopReason::SocketError);
    assert!(report.stats.sent < 1_003);
    assert_eq!(report.stats.responses, 0);
    assert!(report.stats.sent <= report.stats.attempted);
    assert_eq!(
        report.stats.attempted,
        report.stats.socket_errors + report.stats.timeouts
    );
}
