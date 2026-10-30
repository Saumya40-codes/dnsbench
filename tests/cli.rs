use std::{fs, net::UdpSocket, path::PathBuf, process::Command, thread, time::Duration};

struct DomainsFile(PathBuf, tempfile::TempDir);

impl DomainsFile {
    fn new(label: &str) -> Self {
        let directory = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let path = directory.path().join("domains.txt");
        fs::write(&path, "Example.COM.\nexample.com\n").unwrap();
        Self(path, directory)
    }
}

fn command(file: &DomainsFile) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dns-bench"));
    command
        .env("XDG_STATE_HOME", file.1.path())
        .env("HOME", file.1.path())
        .env("LOCALAPPDATA", file.1.path());
    command
}

#[test]
fn extended_query_types_roundtrip_through_both_engines_and_saved_inspection() {
    let mut soa = vec![0xC0, 0x0C, 0xC0, 0x0C];
    for number in 1u32..=5 {
        soa.extend_from_slice(&number.to_be_bytes());
    }
    let cases = [
        ("NS", 2u16, vec![0xC0, 0x0C], "IN NS example.com."),
        ("CNAME", 5, vec![0xC0, 0x0C], "IN CNAME example.com."),
        ("SOA", 6, soa, "IN SOA example.com. example.com. 1 2 3 4 5"),
        (
            "PTR",
            12,
            b"\x04host\x07example\x03com\0".to_vec(),
            "IN PTR host.example.com.",
        ),
        ("MX", 15, vec![0, 10, 0xC0, 0x0C], "IN MX 10 example.com."),
        (
            "TXT",
            16,
            b"\x03one\x03two".to_vec(),
            "IN TXT \"one\" \"two\"",
        ),
    ];
    for (kind, code, data, expected) in cases {
        for (workers, threads, window) in [(1, 1, 1), (2, 2, 4)] {
            let file = DomainsFile::new("record-types");
            let domain = if kind == "PTR" {
                "1.2.0.192.in-addr.arpa\n"
            } else {
                "example.com\n"
            };
            fs::write(&file.0, domain).unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let address = socket.local_addr().unwrap();
            let data = data.clone();
            let handle = thread::spawn(move || {
                let mut buffer = [0; 512];
                let (length, peer) = socket.recv_from(&mut buffer).unwrap();
                assert_eq!(&buffer[length - 4..length - 2], &code.to_be_bytes());
                let mut response = buffer[..length].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&code.to_be_bytes());
                response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                response.extend_from_slice(&data);
                socket.send_to(&response, peer).unwrap();
            });
            let output = command(&file)
                .args(["--server", &address.to_string(), "--domains"])
                .arg(&file.0)
                .args([
                    "--type",
                    kind,
                    "--workers",
                    &workers.to_string(),
                    "--threads",
                    &threads.to_string(),
                    "--max-in-flight",
                    &window.to_string(),
                ])
                .output()
                .unwrap();
            handle.join().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(&format!("Default query type: {kind}")));
            assert!(text.contains("Attempted: 1 | Sent: 1 | Responses: 1"));
            let output = command(&file).args(["--topk", "1"]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(&format!(" · {kind} · ")));
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
    }
}

#[test]
fn topk_zero_is_silent_and_does_not_need_a_saved_run() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
        .args(["--topk", "0", "--results-file"])
        .arg(directory.path().join("missing.zst"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    for flag in ["--topk", "--bottomk", "--limit"] {
        let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
            .args(["get", flag, "0", "--results-file"])
            .arg(directory.path().join("missing.zst"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn a_run_can_be_inspected_later_without_sending_queries() {
    for (limit, workers, threads) in [(1, 1, 1), (4, 2, 2)] {
        let file = DomainsFile::new("saved-inspection");
        fs::write(&file.0, "slow.example\nfast.example\ntimeout.example\n").unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut responders = Vec::new();
            let mut packet = [0; 512];
            for _ in 0..3 {
                let (length, peer) = socket.recv_from(&mut packet).unwrap();
                let label_len = usize::from(packet[12]);
                let label = &packet[13..13 + label_len];
                if label == b"timeout" {
                    continue;
                }
                let slow = label == b"slow";
                let mut response = packet[..length].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                for offset in [6, 8, 10] {
                    response[offset..offset + 2].copy_from_slice(&1u16.to_be_bytes());
                }
                response.extend_from_slice(&[
                    0xC0,
                    0x0C,
                    0,
                    1,
                    0,
                    1,
                    0,
                    0,
                    0,
                    60,
                    0,
                    4,
                    192,
                    0,
                    2,
                    if slow { 7 } else { 8 },
                ]);
                response.extend_from_slice(&[
                    0xC0, 0x0C, 0, 2, 0, 1, 0, 0, 0, 60, 0, 5, 2, b'n', b's', 0xC0, 0x0C,
                ]);
                response.extend_from_slice(&[
                    2, b'n', b's', 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
                ]);
                response.extend_from_slice(
                    &"2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                let sender = socket.try_clone().unwrap();
                responders.push(thread::spawn(move || {
                    thread::sleep(Duration::from_millis(if slow { 40 } else { 1 }));
                    sender.send_to(&response, peer).unwrap();
                }));
            }
            for responder in responders {
                responder.join().unwrap();
            }
            socket
        });
        let output = command(&file)
            .args(["--server", &address.to_string(), "--domains"])
            .arg(&file.0)
            .args([
                "--max-in-flight",
                &limit.to_string(),
                "--workers",
                &workers.to_string(),
                "--threads",
                &threads.to_string(),
                "--timeout",
                "200ms",
            ])
            .output()
            .unwrap();
        let socket = handle.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Attempted: 3 | Sent: 3 | Responses: 2"));
        let saved_path = text
            .lines()
            .find_map(|line| line.strip_prefix("Saved run: "))
            .unwrap();
        let before = fs::read(saved_path).unwrap();
        let output = command(&file).args(["--topk", "1"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("slow.example"));
        assert!(text.contains("192.0.2.7"));
        assert!(text.contains("NS ns.slow.example."));
        assert!(text.contains("AAAA 2001:db8::1"));
        assert!(!text.contains("fast.example"));
        assert!(!text.contains("timeout.example"));
        assert_eq!(fs::read(saved_path).unwrap(), before);
        let output = command(&file).args(["--topk", "3"]).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("fast.example"));
        let output = command(&file).args(["--topk", "4"]).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("only 3 workload entries"));
        for (flag, expected, excluded) in [
            ("--topk", "slow.example", "fast.example"),
            ("--bottomk", "fast.example", "slow.example"),
            ("--limit", "slow.example", "fast.example"),
        ] {
            let output = command(&file).args(["get", flag, "1"]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(expected));
            assert!(!text.contains(excluded));
        }
        let output = command(&file)
            .args(["get", "--domain", "SLOW.EXAMPLE."])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "slow.example. 60 IN A 192.0.2.7\n"
        );
        assert_eq!(fs::read(saved_path).unwrap(), before);
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn cli_executes_queries_and_separates_answer_and_error_populations() {
    let file = DomainsFile::new("outcomes");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut packet = [0; 512];
        for index in 0..3 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            let mut response = packet[..length].to_vec();
            let flags: u16 = if index == 2 { 0x8183 } else { 0x8180 };
            response[2..4].copy_from_slice(&flags.to_be_bytes());
            if index == 0 {
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response
                    .extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            }
            socket.send_to(&response, peer).unwrap();
        }
    });
    let output = command(&file)
        .args(["--server", &address.to_string(), "--domains"])
        .arg(&file.0)
        .args(["--queries", "3", "--shuffle", "--seed", "42"])
        .output()
        .unwrap();
    handle.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Loaded domains: 2"));
    assert!(text.contains("Max in flight: 2"));
    assert!(text.contains("Workers: 2"));
    assert!(text.contains("Runtime threads: 1"));
    assert!(text.contains("Seed: 42"));
    assert!(text.contains("Attempted: 3 | Sent: 3 | Responses: 3"));
    assert!(text.contains("NOERROR(0)=2 NXDOMAIN(3)=1"));
    for label in ["NOERROR with answers", "NOERROR empty", "DNS errors"] {
        let row = text.lines().find(|line| line.starts_with(label)).unwrap();
        assert_eq!(row.split_whitespace().rev().nth(4), Some("1"));
    }
}

#[test]
fn cli_rejects_max_in_flight_it_cannot_execute() {
    let file = DomainsFile::new("max_in_flight");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let output = command(&file)
        .args([
            "--server",
            &socket.local_addr().unwrap().to_string(),
            "--domains",
        ])
        .arg(&file.0)
        .args([
            "--queries",
            "3",
            "--max-in-flight",
            "65537",
            "--workers",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("max-in-flight must not exceed 65536")
    );
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn cli_defaults_to_one_pass_and_finishes_after_responses_or_timeouts() {
    for (max_in_flight, workers, threads) in [(1, 1, 1), (8, 4, 2)] {
        let file = DomainsFile::new("one-pass");
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut packet = [0; 512];
            for index in 0..2 {
                let (length, peer) = socket.recv_from(&mut packet).unwrap();
                if index == 0 {
                    packet[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
                    socket.send_to(&packet[..length], peer).unwrap();
                }
            }
            socket
        });
        let output = command(&file)
            .args(["--server", &address.to_string(), "--domains"])
            .arg(&file.0)
            .args([
                "--max-in-flight",
                &max_in_flight.to_string(),
                "--workers",
                &workers.to_string(),
                "--threads",
                &threads.to_string(),
                "--timeout",
                "100ms",
            ])
            .output()
            .unwrap();
        let socket = handle.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Mode: one pass through the workload"));
        assert!(text.contains("Stop: workload completed"));
        assert!(text.contains("Attempted: 2 | Sent: 2 | Responses: 1"));
        assert!(text.contains("Timeouts: 1 | Socket errors: 0"));
        assert!(text.contains("NXDOMAIN(3)=1"));
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn cli_executes_concurrent_queries_and_reports_peak_in_flight() {
    let file = DomainsFile::new("concurrent");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut batch = Vec::new();
        let mut packet = [0; 512];
        for _ in 0..3 {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            let mut response = packet[..length].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            batch.push((response, peer));
        }
        for (response, peer) in batch.into_iter().rev() {
            socket.send_to(&response, peer).unwrap();
        }
    });
    let output = command(&file)
        .args(["--server", &address.to_string(), "--domains"])
        .arg(&file.0)
        .args([
            "--queries",
            "3",
            "--max-in-flight",
            "3",
            "--workers",
            "3",
            "--shuffle",
            "--seed",
            "42",
        ])
        .output()
        .unwrap();
    handle.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Max in flight: 3"));
    assert!(text.contains("Workers: 3"));
    assert!(text.contains("Runtime threads: 1"));
    assert!(text.contains("Attempted: 3 | Sent: 3 | Responses: 3"));
    let peak: usize = text
        .lines()
        .find_map(|line| line.strip_prefix("Peak queries in flight: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=3).contains(&peak));
    assert!(text.contains("Timeouts: 0 | Socket errors: 0"));
}

#[cfg(target_os = "linux")]
#[test]
fn cli_prints_partial_results_and_fails_on_socket_error() {
    let file = DomainsFile::new("socket-error");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let output = command(&file)
        .args(["--server", &address.to_string(), "--domains"])
        .arg(&file.0)
        .args(["--queries", "3", "--workers", "1", "--max-in-flight", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("run stopped early"));
    assert!(text.contains("Attempted: 1 | Sent: 1 | Responses: 0"));
    assert!(text.contains("Socket errors: 1"));
    assert!(text.contains("Last socket error:"));
}
