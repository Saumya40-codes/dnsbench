use super::*;
use crate::dns::message::Rcode;
use std::{
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn an_expired_send_window_does_not_send_a_query() {
    let socket = server();
    let mut client = UdpClient::connect(socket.local_addr().unwrap()).unwrap();
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            Some(Instant::now()),
        )
        .unwrap();
    assert!(!report.sent);
    assert!(matches!(report.outcome, QueryOutcome::Timeout));
    socket.set_nonblocking(true).unwrap();
    let mut bytes = [0; MAX_QUERY_LEN];
    assert_eq!(
        socket.recv_from(&mut bytes).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

fn server() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    socket
}

fn serve(
    reply: impl FnOnce(UdpSocket, Vec<u8>, SocketAddr) + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut query = vec![0; MAX_QUERY_LEN];
        let (length, peer) = socket.recv_from(&mut query).unwrap();
        query.truncate(length);
        reply(socket, query, peer);
    });
    (address, handle)
}

fn response_to(query: &[u8], flags: u16) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response
}

#[test]
fn receives_an_answer_and_measures_the_exchange() {
    let delay = Duration::from_millis(15);
    let (address, handle) = serve(move |socket, query, peer| {
        assert_eq!(&query[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut response = response_to(&query, 0x8180);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        thread::sleep(delay);
        socket.send_to(&response, peer).unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            0x1234,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    handle.join().unwrap();

    assert!(matches!(
        report.outcome,
        QueryOutcome::Response(ResponseSummary {
            rcode: Rcode::NoError,
            truncated: false,
            answer_count: 1
        })
    ));
    assert!(report.elapsed >= delay);
    assert_eq!(report.rejected, RejectedPackets::default());
}

#[test]
fn reports_dns_errors_and_truncation_as_responses() {
    for (flags, rcode, truncated) in [
        (0x8183, Rcode::NxDomain, false),
        (0x8182, Rcode::ServFail, false),
        (0x8380, Rcode::NoError, true),
    ] {
        let (address, handle) = serve(move |socket, query, peer| {
            socket.send_to(&response_to(&query, flags), peer).unwrap();
        });
        let mut client = UdpClient::connect(address).unwrap();
        let report = client
            .query(
                &DnsName::parse("example.com").unwrap(),
                1,
                QueryType::A,
                true,
                TEST_TIMEOUT,
                None,
            )
            .unwrap();
        handle.join().unwrap();
        assert!(
            matches!(report.outcome, QueryOutcome::Response(summary) if summary.rcode == rcode && summary.truncated == truncated)
        );
    }
}

#[test]
fn waits_for_matching_response_after_rejected_packets() {
    let (address, handle) = serve(|socket, query, peer| {
        socket.send_to(&[0; 5], peer).unwrap();
        let mut wrong_id = response_to(&query, 0x8180);
        wrong_id[0] ^= 1;
        socket.send_to(&wrong_id, peer).unwrap();
        let mut wrong_question = response_to(&query, 0x8180);
        wrong_question[13] = b'x';
        socket.send_to(&wrong_question, peer).unwrap();
        socket.send_to(&response_to(&query, 0x8180), peer).unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            7,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    handle.join().unwrap();

    assert!(matches!(report.outcome, QueryOutcome::Response(_)));
    assert_eq!(
        report.rejected,
        RejectedPackets {
            mismatched: 2,
            malformed: 1
        }
    );
}

#[test]
fn times_out_when_server_does_not_reply() {
    // Keep the server socket open so the OS does not return port-unreachable.
    let socket = server();
    let mut client = UdpClient::connect(socket.local_addr().unwrap()).unwrap();
    let timeout = Duration::from_millis(40);
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            timeout,
            None,
        )
        .unwrap();

    assert!(matches!(report.outcome, QueryOutcome::Timeout));
    assert!(report.elapsed >= timeout);
    assert_eq!(report.rejected, RejectedPackets::default());
}

#[test]
fn unrelated_packets_do_not_restart_the_deadline() {
    let (stop, stopped) = mpsc::channel();
    let (address, handle) = serve(move |socket, query, peer| {
        let mut mismatch = response_to(&query, 0x8180);
        mismatch[0] ^= 1;
        for _ in 0..60 {
            socket.send_to(&mismatch, peer).unwrap();
            match stopped.recv_timeout(Duration::from_millis(10)) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
        // A client that resets its timeout would accept this late response.
        socket.send_to(&response_to(&query, 0x8180), peer).unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let timeout = Duration::from_millis(100);
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            timeout,
            None,
        )
        .unwrap();
    let _ = stop.send(());
    handle.join().unwrap();

    assert!(matches!(report.outcome, QueryOutcome::Timeout));
    assert!(report.elapsed >= timeout);
    assert!(report.rejected.mismatched > 0);
}

#[test]
fn filters_datagrams_from_other_sources() {
    let (address, handle) = serve(|socket, query, peer| {
        let other = server();
        other.send_to(&response_to(&query, 0x8183), peer).unwrap();
        socket.send_to(&response_to(&query, 0x8180), peer).unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    handle.join().unwrap();

    assert!(
        matches!(report.outcome, QueryOutcome::Response(summary) if summary.rcode == Rcode::NoError)
    );
    assert_eq!(report.rejected, RejectedPackets::default());
}

#[test]
fn reuses_buffers_and_rejects_late_duplicate_responses() {
    let (address, handle) = serve(|socket, first, peer| {
        let response = response_to(&first, 0x8180);
        socket.send_to(&response, peer).unwrap();
        socket.send_to(&response, peer).unwrap();
        let mut second = vec![0; MAX_QUERY_LEN];
        let (length, next_peer) = socket.recv_from(&mut second).unwrap();
        assert_eq!(peer, next_peer);
        socket
            .send_to(&response_to(&second[..length], 0x8180), peer)
            .unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let query_allocation = client.query_buffer.as_ptr();
    let receive_allocation = client.receive_buffer.as_ptr();
    let name = DnsName::parse("example.com").unwrap();
    let first = client
        .query(&name, 1, QueryType::A, true, TEST_TIMEOUT, None)
        .unwrap();
    let second = client
        .query(&name, 2, QueryType::Aaaa, false, TEST_TIMEOUT, None)
        .unwrap();
    handle.join().unwrap();

    assert!(matches!(first.outcome, QueryOutcome::Response(_)));
    assert!(matches!(second.outcome, QueryOutcome::Response(_)));
    assert_eq!(second.rejected.mismatched, 1);
    assert_eq!(client.query_buffer.as_ptr(), query_allocation);
    assert_eq!(client.receive_buffer.as_ptr(), receive_allocation);
}

#[test]
fn receives_large_datagrams_without_local_truncation() {
    let (address, handle) = serve(|socket, query, peer| {
        let mut response = response_to(&query, 0x8180);
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        // Unknown record type with a 1024-byte payload exercises receive capacity.
        response.extend_from_slice(&[0, 0xFD, 0xE8, 0, 1, 0, 0, 0, 0, 4, 0]);
        response.resize(response.len() + 1024, 0);
        socket.send_to(&response, peer).unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    handle.join().unwrap();
    assert!(matches!(report.outcome, QueryOutcome::Response(_)));
}

#[test]
fn can_query_again_after_timeout_without_accepting_the_old_reply() {
    let (address, handle) = serve(|socket, first, peer| {
        thread::sleep(Duration::from_millis(100));
        socket.send_to(&response_to(&first, 0x8180), peer).unwrap();
        let mut second = [0; MAX_QUERY_LEN];
        let (length, next_peer) = socket.recv_from(&mut second).unwrap();
        assert_eq!(peer, next_peer);
        socket
            .send_to(&response_to(&second[..length], 0x8180), peer)
            .unwrap();
    });
    let mut client = UdpClient::connect(address).unwrap();
    let name = DnsName::parse("example.com").unwrap();
    let first = client
        .query(
            &name,
            1,
            QueryType::A,
            true,
            Duration::from_millis(30),
            None,
        )
        .unwrap();
    let second = client
        .query(&name, 2, QueryType::A, true, TEST_TIMEOUT, None)
        .unwrap();
    handle.join().unwrap();

    assert!(matches!(first.outcome, QueryOutcome::Timeout));
    assert!(matches!(second.outcome, QueryOutcome::Response(_)));
    assert_eq!(second.rejected.mismatched, 1);
}

#[test]
fn rejects_invalid_timeouts_before_sending() {
    let socket = server();
    let mut client = UdpClient::connect(socket.local_addr().unwrap()).unwrap();
    let name = DnsName::parse("example.com").unwrap();
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert_eq!(
            client
                .query(&name, 1, QueryType::A, true, timeout, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }
}

#[test]
fn connects_and_queries_an_ipv6_server() {
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
    socket.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    let mut client = UdpClient::connect(socket.local_addr().unwrap()).unwrap();
    let handle = thread::spawn(move || {
        let mut query = [0; MAX_QUERY_LEN];
        let (length, peer) = socket.recv_from(&mut query).unwrap();
        socket
            .send_to(&response_to(&query[..length], 0x8180), peer)
            .unwrap();
    });
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::Aaaa,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    handle.join().unwrap();
    assert!(client.socket.local_addr().unwrap().is_ipv6());
    assert!(matches!(report.outcome, QueryOutcome::Response(_)));
}

#[cfg(target_os = "linux")]
#[test]
fn reports_port_unreachable_as_socket_error() {
    let socket = server();
    let mut client = UdpClient::connect(socket.local_addr().unwrap()).unwrap();
    drop(socket);
    let report = client
        .query(
            &DnsName::parse("example.com").unwrap(),
            1,
            QueryType::A,
            true,
            TEST_TIMEOUT,
            None,
        )
        .unwrap();
    assert!(
        matches!(report.outcome, QueryOutcome::SocketError(error) if error.kind() == ErrorKind::ConnectionRefused)
    );
}
