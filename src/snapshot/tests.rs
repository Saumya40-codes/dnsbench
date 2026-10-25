use std::time::Duration;

use super::*;
use crate::{
    benchmark::{RunStats, StopReason},
    config::{QueryOrder, RunConfigInput},
    dns::{
        message::{Rcode, ResponseSummary, encode_query},
        udp::{QueryOutcome, QueryReport, RejectedPackets},
    },
};

fn fixture() -> (RunConfig, Vec<DnsName>, RunReport) {
    let config = RunConfig::try_from(RunConfigInput {
        server: "127.0.0.1:53".parse().unwrap(),
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: 1,
        stop_condition: StopCondition::Once,
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    let domains: Vec<_> = ["a.com", "b.com", "c.com", "a.com", "d.com"]
        .into_iter()
        .map(|domain| DnsName::parse(domain).unwrap())
        .collect();
    let mut stats = RunStats::new().unwrap();
    for (index, millis, address) in [(0, 10, 1), (1, 20, 2), (3, 30, 9)] {
        let mut packet = Vec::new();
        encode_query(
            &domains[index],
            index as u16,
            QueryType::A,
            true,
            &mut packet,
        );
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[
            0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, address,
        ]);
        let report = QueryReport {
            outcome: QueryOutcome::Response(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: false,
                answer_count: 1,
            }),
            sent: true,
            elapsed: Duration::from_millis(millis),
            rejected: RejectedPackets::default(),
        };
        stats
            .domains
            .entry(index)
            .or_default()
            .record(&report, Some(&packet));
        stats.record(report).unwrap();
    }
    let timeout = QueryReport {
        outcome: QueryOutcome::Timeout,
        sent: true,
        elapsed: Duration::from_secs(2),
        rejected: RejectedPackets::default(),
    };
    stats.domains.entry(2).or_default().record(&timeout, None);
    stats.record(timeout).unwrap();
    (
        config,
        domains,
        RunReport {
            workers: 1,
            threads: 1,
            stats,
            elapsed: Duration::from_secs(3),
            stop_reason: StopReason::WorkloadCompleted,
        },
    )
}

#[test]
fn compressed_roundtrip_ranks_domains_and_keeps_the_slowest_samples_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("last-run.jsonl.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, report).unwrap();
    assert_eq!(
        &std::fs::read(&path).unwrap()[..4],
        &[0x28, 0xB5, 0x2F, 0xFD]
    );
    let inspection = inspect(&path, 1).unwrap().unwrap();
    assert_eq!(inspection.header.input_entries, 5);
    assert_eq!(inspection.header.unique_domains, 4);
    assert_eq!(inspection.header.responses, 3);
    assert_eq!(inspection.header.timeouts, 1);
    assert_eq!(inspection.responding_domains, 2);
    assert_eq!(inspection.domains.len(), 1);
    let domain = &inspection.domains[0];
    assert_eq!(domain.domain, "a.com");
    assert_eq!(domain.responses, 2);
    let response = domain.slowest.as_ref().unwrap();
    assert_eq!(response.elapsed_ns, 30_000_000);
    assert_eq!(response.records[0].value, "192.0.2.9");
    assert!(inspection.to_string().contains("192.0.2.9"));
    let all = inspect(&path, 5).unwrap().unwrap();
    assert_eq!(
        all.domains
            .iter()
            .map(|domain| domain.domain.as_str())
            .collect::<Vec<_>>(),
        ["a.com", "b.com"]
    );
    assert!(matches!(
        inspect(&path, 6),
        Err(SnapshotError::TopLimit { .. })
    ));
}

#[test]
fn zero_does_not_open_even_a_missing_file() {
    assert!(
        inspect(Path::new("/does-not-exist/dnsbench.zst"), 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn equal_latencies_are_ranked_by_domain_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, mut report) = fixture();
    report
        .stats
        .domains
        .get_mut(&1)
        .unwrap()
        .slowest
        .as_mut()
        .unwrap()
        .elapsed_ns = 30_000_000;
    save(&path, &config, &domains, report).unwrap();
    assert_eq!(
        inspect(&path, 1).unwrap().unwrap().domains[0].domain,
        "a.com"
    );
}

#[test]
fn incomplete_compressed_frames_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, report).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 6);
    std::fs::write(&path, bytes).unwrap();
    assert!(inspect(&path, 1).is_err());
}

#[test]
fn failed_save_preserves_the_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, report).unwrap();
    let previous = std::fs::read(&path).unwrap();
    let (_, _, mut broken) = fixture();
    broken
        .stats
        .domains
        .get_mut(&3)
        .unwrap()
        .slowest
        .as_mut()
        .unwrap()
        .packet
        .clear();
    assert!(save(&path, &config, &domains, broken).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn unknown_versions_and_missing_domain_lines_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, report).unwrap();
    let data = zstd::decode_all(File::open(&path).unwrap()).unwrap();
    let text = String::from_utf8(data).unwrap();
    let (header, records) = text.split_once('\n').unwrap();
    let mut header: Header = serde_json::from_str(header).unwrap();
    header.version = 999;
    let unknown = format!("{}\n{}", serde_json::to_string(&header).unwrap(), records);
    std::fs::write(&path, zstd::encode_all(unknown.as_bytes(), 1).unwrap()).unwrap();
    assert!(matches!(inspect(&path, 1), Err(SnapshotError::Invalid(_))));
    header.version = VERSION;
    let missing = format!("{}\n", serde_json::to_string(&header).unwrap());
    std::fs::write(&path, zstd::encode_all(missing.as_bytes(), 1).unwrap()).unwrap();
    assert!(matches!(inspect(&path, 1), Err(SnapshotError::Invalid(_))));
}

#[test]
fn streaming_selection_keeps_the_largest_samples_across_many_domains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, report).unwrap();
    let bytes = zstd::decode_all(File::open(&path).unwrap()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let mut header: Header = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    header.input_entries = 1_000;
    header.unique_domains = 1_000;
    header.attempted = 1_000;
    header.sent = 1_000;
    header.responses = 1_000;
    header.timeouts = 0;
    header.rcodes = [0; 16];
    header.rcodes[0] = 1_000;
    let mut encoded = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    serde_json::to_writer(&mut encoded, &header).unwrap();
    encoded.write_all(b"\n").unwrap();
    for index in 0..1_000 {
        let domain = SavedDomain {
            domain: format!("d{index:04}.example"),
            attempted: 1,
            sent: 1,
            responses: 1,
            timeouts: 0,
            socket_errors: 0,
            slowest: Some(SavedResponse {
                elapsed_ns: index,
                rcode: "NOERROR".into(),
                truncated: false,
                answer_count: 0,
                records: Vec::new(),
            }),
        };
        serde_json::to_writer(&mut encoded, &domain).unwrap();
        encoded.write_all(b"\n").unwrap();
    }
    std::fs::write(&path, encoded.finish().unwrap()).unwrap();
    let result = inspect(&path, 3).unwrap().unwrap();
    assert_eq!(result.responding_domains, 1_000);
    assert_eq!(
        result
            .domains
            .iter()
            .map(|domain| domain.domain.as_str())
            .collect::<Vec<_>>(),
        ["d0999.example", "d0998.example", "d0997.example"]
    );
}
