use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    num::NonZeroU64,
    thread,
    time::Duration,
};

use super::*;
use crate::config::{QueryOrder, QueryType, RunConfigInput};

fn setup(concurrency: usize, stop: StopCondition, timeout: Duration) -> (UdpSocket, RunConfig) {
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
        stop_condition: stop,
        timeout,
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    (socket, config)
}

fn names() -> Vec<DnsName> {
    ["a.com", "b.com", "c.com"]
        .into_iter()
        .map(|name| DnsName::parse(name).unwrap())
        .collect()
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut packet = [0; 512];
    let (length, peer) = socket.recv_from(&mut packet).unwrap();
    let mut response = packet[..length].to_vec();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    (response, peer)
}

#[test]
fn sends_a_full_window_before_receiving_and_matches_reversed_responses() {
    let (socket, config) = setup(
        3,
        StopCondition::QueryCount(NonZeroU64::new(7).unwrap()),
        Duration::from_secs(2),
    );
    let handle = thread::spawn(move || {
        let mut observed = Vec::new();
        for count in [3, 3, 1] {
            let batch: Vec<_> = (0..count).map(|_| receive(&socket)).collect();
            for (response, _) in &batch {
                observed.push((u16::from_be_bytes([response[0], response[1]]), response[13]));
            }
            for (response, peer) in batch.into_iter().rev() {
                socket.send_to(&response, peer).unwrap();
            }
        }
        observed
    });
    let report = crate::benchmark::run(&config, &mut names()).unwrap();
    let observed = handle.join().unwrap();
    assert_eq!(
        observed.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        observed.iter().map(|entry| entry.1).collect::<Vec<_>>(),
        b"abcabca"
    );
    assert_eq!(report.stop_reason, StopReason::QueryCount);
    assert_eq!(report.stats.sent, 7);
    assert_eq!(report.stats.attempted, 7);
    assert_eq!(report.stats.responses, 7);
    assert_eq!(report.stats.timeouts, 0);
    assert_eq!(report.stats.peak_in_flight, 3);
    assert_eq!(report.stats.latencies[1].len(), 7);
}

#[test]
fn rejects_wrong_questions_malformed_unknown_and_duplicate_packets() {
    let (socket, config) = setup(
        3,
        StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
        Duration::from_secs(2),
    );
    let handle = thread::spawn(move || {
        let batch: Vec<_> = (0..3).map(|_| receive(&socket)).collect();
        let (response, peer) = &batch[0];
        let mut wrong_question = response.clone();
        wrong_question[13] = b'z';
        socket.send_to(&wrong_question, peer).unwrap();
        let mut malformed = response.clone();
        malformed[6..8].copy_from_slice(&1u16.to_be_bytes());
        socket.send_to(&malformed, peer).unwrap();
        socket.send_to(&[0], peer).unwrap();
        let mut unknown = response.clone();
        unknown[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        socket.send_to(&unknown, peer).unwrap();
        socket.send_to(response, peer).unwrap();
        socket.send_to(response, peer).unwrap();
        for (response, peer) in &batch[1..] {
            socket.send_to(response, peer).unwrap();
        }
    });
    let report = run(&config, &names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.responses, 3);
    assert_eq!(report.stats.timeouts, 0);
    assert_eq!(report.stats.rejected.malformed, 2);
    assert_eq!(report.stats.rejected.mismatched, 3);
}

#[test]
fn refills_completed_slots_while_an_earlier_query_times_out() {
    let (socket, config) = setup(
        3,
        StopCondition::QueryCount(NonZeroU64::new(5).unwrap()),
        Duration::from_millis(150),
    );
    let handle = thread::spawn(move || {
        for _ in 0..5 {
            let (response, peer) = receive(&socket);
            if response[..2] != [0, 1] {
                socket.send_to(&response, peer).unwrap();
            }
        }
    });
    let report = run(&config, &names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.sent, 5);
    assert_eq!(report.stats.responses, 4);
    assert_eq!(report.stats.timeouts, 1);
    assert_eq!(report.stats.attempted, 5);
    assert!(report.elapsed >= config.timeout());
    assert_eq!(report.stats.latencies[4].len(), 1);
}

#[test]
fn duration_stops_new_sends_and_drains_every_pending_query() {
    let (socket, config) = setup(
        4,
        StopCondition::Duration(Duration::from_millis(50)),
        Duration::from_millis(150),
    );
    let report = run(&config, &names()).unwrap();
    assert_eq!(report.stop_reason, StopReason::Duration);
    assert_eq!(report.stats.sent, 4);
    assert_eq!(report.stats.timeouts, 4);
    assert_eq!(report.stats.attempted, 4);
    assert!(report.elapsed >= config.timeout());
    socket.set_nonblocking(true).unwrap();
    for _ in 0..4 {
        assert!(socket.recv_from(&mut [0; 512]).is_ok());
    }
    assert_eq!(
        socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn count_smaller_than_concurrency_does_not_overshoot() {
    let (socket, config) = setup(
        64,
        StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
        Duration::from_secs(2),
    );
    let handle = thread::spawn(move || {
        let batch: Vec<_> = (0..3).map(|_| receive(&socket)).collect();
        for (response, peer) in batch {
            socket.send_to(&response, peer).unwrap();
        }
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    });
    let report = run(&config, &names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.sent, 3);
    assert_eq!(report.stats.responses, 3);
    assert_eq!(report.stats.peak_in_flight, 3);
}

#[test]
fn late_reply_does_not_complete_a_different_pending_query() {
    let (socket, config) = setup(
        2,
        StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
        Duration::from_millis(500),
    );
    let handle = thread::spawn(move || {
        let first = receive(&socket);
        let second = receive(&socket);
        thread::sleep(Duration::from_millis(200));
        socket.send_to(&second.0, second.1).unwrap();
        let third = receive(&socket);
        thread::sleep(Duration::from_millis(350));
        socket.send_to(&first.0, first.1).unwrap();
        socket.send_to(&third.0, third.1).unwrap();
    });
    let report = run(&config, &[DnsName::parse("a.com").unwrap()]).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.sent, 3);
    assert_eq!(report.stats.responses, 2);
    assert_eq!(report.stats.timeouts, 1);
    assert_eq!(report.stats.rejected.mismatched, 1);
}

#[test]
fn slow_first_query_does_not_retain_completed_id_history() {
    let (_socket, config) = setup(
        2,
        StopCondition::QueryCount(NonZeroU64::new(1_000).unwrap()),
        Duration::from_secs(60),
    );
    let domains = names();
    let mut engine = Engine::new(&config, &domains).unwrap();
    for id in [0, 999] {
        engine.pending.insert(
            id,
            PendingQuery {
                domain_index: 0,
                sent_at: Instant::now(),
            },
        );
    }
    engine.deadlines.extend(0..1_000);
    assert!(engine.expire().unwrap().is_some());
    assert_eq!(engine.deadlines, [0, 999]);
    assert_eq!(engine.pending.len(), 2);
}

#[test]
fn blocked_send_has_a_deadline_and_does_not_cancel_sent_queries() {
    let (_socket, config) = setup(
        2,
        StopCondition::QueryCount(NonZeroU64::new(3).unwrap()),
        Duration::from_millis(80),
    );
    let domains = names();
    let mut engine = Engine::new(&config, &domains).unwrap();
    engine.pending.insert(
        0,
        PendingQuery {
            domain_index: 0,
            sent_at: Instant::now(),
        },
    );
    engine.deadlines.push_back(0);
    engine.writable = false;
    engine.send_started = Some(Instant::now() - config.timeout());
    engine.expire().unwrap();
    assert_eq!(engine.stop_reason, Some(StopReason::SendDeadline));
    assert_eq!(engine.pending.len(), 1);
    assert_eq!(engine.stats.sent, 0);
    assert_eq!(engine.stats.timeouts, 1);
    while engine.step().unwrap() {}
    assert_eq!(engine.stats.sent, 1);
    assert_eq!(engine.stats.attempted, 2);
    assert_eq!(engine.stats.timeouts, 2);
}

#[test]
fn a_write_readiness_event_resumes_a_blocked_sender() {
    let (_socket, config) = setup(
        2,
        StopCondition::QueryCount(NonZeroU64::new(2).unwrap()),
        Duration::from_secs(2),
    );
    let domains = names();
    let mut engine = Engine::new(&config, &domains).unwrap();
    engine.writable = false;
    engine.send_started = Some(Instant::now());
    assert!(engine.step().unwrap());
    assert!(engine.writable);
    assert_eq!(engine.sent, 0);
}

#[test]
fn concurrent_aaaa_queries_work_over_ipv6() {
    let socket = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AddrNotAvailable | ErrorKind::Unsupported
            ) =>
        {
            return;
        }
        Err(error) => panic!("IPv6 bind failed: {error}"),
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let config = RunConfig::try_from(RunConfigInput {
        server: socket.local_addr().unwrap(),
        domains_path: "domains.txt".into(),
        concurrency: 2,
        stop_condition: StopCondition::QueryCount(NonZeroU64::new(2).unwrap()),
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::Aaaa,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    let handle = thread::spawn(move || {
        let batch: Vec<_> = (0..2).map(|_| receive(&socket)).collect();
        for (response, peer) in batch.into_iter().rev() {
            assert_eq!(&response[response.len() - 4..], &[0, 28, 0, 1]);
            assert!(peer.is_ipv6());
            socket.send_to(&response, peer).unwrap();
        }
    });
    let report = crate::benchmark::run(&config, &mut names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.responses, 2);
    assert_eq!(report.stats.peak_in_flight, 2);
}

#[test]
fn id_exhaustion_drains_then_rotates_source_port() {
    let (socket, config) = setup(
        8,
        StopCondition::QueryCount(NonZeroU64::new(65_537).unwrap()),
        Duration::from_secs(2),
    );
    let handle = thread::spawn(move || {
        let mut first_port = None;
        let mut last_port = 0;
        for index in 0..65_537u32 {
            let (response, peer) = receive(&socket);
            let id = u16::from_be_bytes([response[0], response[1]]);
            assert_eq!(id, index as u16);
            if index < 65_536 {
                assert_eq!(*first_port.get_or_insert(peer.port()), peer.port());
            } else {
                last_port = peer.port();
            }
            socket.send_to(&response, peer).unwrap();
        }
        assert_ne!(first_port.unwrap(), last_port);
    });
    let report = run(&config, &names()).unwrap();
    handle.join().unwrap();
    assert_eq!(report.stats.sent, 65_537);
    assert_eq!(report.stats.responses, 65_537);
    assert_eq!(report.stats.socket_rotations, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn socket_failure_accounts_for_pending_queries_and_stops() {
    let (socket, config) = setup(
        4,
        StopCondition::QueryCount(NonZeroU64::new(20).unwrap()),
        Duration::from_secs(2),
    );
    drop(socket);
    let report = run(&config, &names()).unwrap();
    assert_eq!(report.stop_reason, StopReason::SocketError);
    assert_eq!(report.stats.responses, 0);
    assert!(report.stats.sent < 20);
    assert!(report.stats.socket_errors >= report.stats.sent);
    assert_eq!(report.stats.attempted, report.stats.socket_errors);
}
