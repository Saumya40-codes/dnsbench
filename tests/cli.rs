use std::{fs, net::UdpSocket, path::PathBuf, process::Command, thread, time::Duration};

struct DomainsFile(PathBuf);

impl DomainsFile {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("dnsbench-{}-{label}.txt", std::process::id()));
        fs::write(&path, "Example.COM.\nexample.com\n").unwrap();
        Self(path)
    }
}

impl Drop for DomainsFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
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
    let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
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
    assert!(text.contains("Concurrency: 1"));
    assert!(text.contains("Workers: 1"));
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
fn cli_rejects_concurrency_it_cannot_execute() {
    let file = DomainsFile::new("concurrency");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
        .args([
            "--server",
            &socket.local_addr().unwrap().to_string(),
            "--domains",
        ])
        .arg(&file.0)
        .args(["--queries", "3", "--concurrency", "65537", "--workers", "1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("concurrency must not exceed 65536"));
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 512]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn cli_defaults_to_one_pass_and_finishes_after_responses_or_timeouts() {
    for (concurrency, workers, threads) in [(1, 1, 1), (8, 4, 2)] {
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
        let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
            .args(["--server", &address.to_string(), "--domains"])
            .arg(&file.0)
            .args([
                "--concurrency",
                &concurrency.to_string(),
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
    let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
        .args(["--server", &address.to_string(), "--domains"])
        .arg(&file.0)
        .args([
            "--queries",
            "3",
            "--concurrency",
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
    assert!(text.contains("Concurrency: 3"));
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
    let output = Command::new(env!("CARGO_BIN_EXE_dns-bench"))
        .args(["--server", &address.to_string(), "--domains"])
        .arg(&file.0)
        .args(["--queries", "3"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("run stopped early"));
    assert!(text.contains("Attempted: 1 | Sent: 1 | Responses: 0"));
    assert!(text.contains("Socket errors: 1"));
    assert!(text.contains("Last socket error:"));
}
