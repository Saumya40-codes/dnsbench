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
        transport: crate::config::Transport::Udp,
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
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
            .get_or_insert(index)
            .record(&report, Some(&packet));
        stats.record(report).unwrap();
    }
    let timeout = QueryReport {
        outcome: QueryOutcome::Timeout,
        sent: true,
        elapsed: Duration::from_secs(2),
        rejected: RejectedPackets::default(),
    };
    stats.domains.get_or_insert(2).record(&timeout, None);
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
    save(&path, &config, &domains, &domains, report).unwrap();
    assert_eq!(
        &std::fs::read(&path).unwrap()[..4],
        &[0x28, 0xB5, 0x2F, 0xFD]
    );
    let inspection = inspect(&path, &Selection::Top(1)).unwrap().unwrap();
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
    let all = inspect(&path, &Selection::Top(5)).unwrap().unwrap();
    assert_eq!(
        all.domains
            .iter()
            .map(|domain| domain.domain.as_str())
            .collect::<Vec<_>>(),
        ["a.com", "b.com"]
    );
    assert!(matches!(
        inspect(&path, &Selection::Top(6)),
        Err(SnapshotError::TopLimit { .. })
    ));
}

#[test]
fn bottom_uses_fastest_sample_and_limit_preserves_input_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    let input = vec![
        domains[2].clone(),
        domains[1].clone(),
        domains[0].clone(),
        domains[3].clone(),
        domains[4].clone(),
    ];
    save(&path, &config, &domains, &input, report).unwrap();
    let bottom = inspect(&path, &Selection::Bottom(2)).unwrap().unwrap();
    assert_eq!(
        bottom
            .domains
            .iter()
            .map(|d| d.domain.as_str())
            .collect::<Vec<_>>(),
        ["a.com", "b.com"]
    );
    assert_eq!(
        bottom.domains[0].fastest.as_ref().unwrap().elapsed_ns,
        10_000_000
    );
    assert!(bottom.to_string().contains("192.0.2.1"));
    assert!(!bottom.to_string().contains("192.0.2.9"));
    let limited = inspect(&path, &Selection::Limit(3)).unwrap().unwrap();
    assert_eq!(
        limited
            .domains
            .iter()
            .map(|d| d.domain.as_str())
            .collect::<Vec<_>>(),
        ["c.com", "b.com", "a.com"]
    );
    assert!(limited.to_string().contains("no validated response"));
    assert_eq!(limited.domains[2].first_index, Some(2));
}

#[test]
fn exact_domain_lookup_normalizes_names_and_returns_only_answers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, mut report) = fixture();
    let sample = report
        .stats
        .domains
        .get_mut(&3)
        .unwrap()
        .slowest
        .as_mut()
        .unwrap();
    let mut packet = sample.packet.to_vec();
    packet[8..10].copy_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&[0xC0, 0x0C, 0, 2, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x0C]);
    sample.packet = packet.into();
    save(&path, &config, &domains, &domains, report).unwrap();
    let lookup = |name| Selection::Domain(DnsName::parse(name).unwrap());
    let found = inspect(&path, &lookup("A.COM.")).unwrap().unwrap();
    assert_eq!(found.to_string(), "a.com. 60 IN A 192.0.2.9\n");
    assert!(matches!(
        inspect(&path, &lookup("missing.com")),
        Err(SnapshotError::DomainNotFound(_))
    ));
    assert!(matches!(
        inspect(&path, &lookup("c.com")),
        Err(SnapshotError::NoResponse(_))
    ));
    assert!(matches!(
        inspect(&path, &lookup("d.com")),
        Err(SnapshotError::NoResponse(_))
    ));
}

#[test]
fn version_one_remains_readable_without_inventing_missing_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, &domains, report).unwrap();
    let bytes = zstd::decode_all(File::open(&path).unwrap()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let mut legacy = String::new();
    for (index, line) in text.lines().enumerate() {
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        if index == 0 {
            value["version"] = 1.into();
            for field in [
                "transport",
                "tls_server_name",
                "tls_connections",
                "tls_setup_ns",
            ] {
                value.as_object_mut().unwrap().remove(field);
            }
        } else {
            value.as_object_mut().unwrap().remove("first_index");
            value.as_object_mut().unwrap().remove("fastest");
        }
        legacy.push_str(&serde_json::to_string(&value).unwrap());
        legacy.push('\n');
    }
    std::fs::write(&path, zstd::encode_all(legacy.as_bytes(), 1).unwrap()).unwrap();
    assert_eq!(
        inspect(&path, &Selection::Top(2))
            .unwrap()
            .unwrap()
            .header
            .transport,
        "UDP"
    );
    assert!(inspect(&path, &Selection::Domain(DnsName::parse("a.com").unwrap())).is_ok());
    for selection in [Selection::Bottom(1), Selection::Limit(1)] {
        assert!(
            inspect(&path, &selection)
                .unwrap_err()
                .to_string()
                .contains("run a new benchmark")
        );
    }
}

#[test]
fn zero_does_not_open_even_a_missing_file() {
    for selection in [Selection::Top(0), Selection::Bottom(0), Selection::Limit(0)] {
        assert!(
            inspect(Path::new("/does-not-exist/dnsbench.zst"), &selection)
                .unwrap()
                .is_none()
        );
    }
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
    save(&path, &config, &domains, &domains, report).unwrap();
    assert_eq!(
        inspect(&path, &Selection::Top(1)).unwrap().unwrap().domains[0].domain,
        "a.com"
    );
}

#[test]
fn incomplete_compressed_frames_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, &domains, report).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 6);
    std::fs::write(&path, bytes).unwrap();
    assert!(inspect(&path, &Selection::Top(1)).is_err());
}

#[test]
fn failed_save_preserves_the_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, &domains, report).unwrap();
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
        .packet = Vec::new().into();
    assert!(save(&path, &config, &domains, &domains, broken).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn unknown_versions_and_missing_domain_lines_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, &domains, report).unwrap();
    let data = zstd::decode_all(File::open(&path).unwrap()).unwrap();
    let text = String::from_utf8(data).unwrap();
    let (header, records) = text.split_once('\n').unwrap();
    let mut header: Header = serde_json::from_str(header).unwrap();
    header.version = 999;
    let unknown = format!("{}\n{}", serde_json::to_string(&header).unwrap(), records);
    std::fs::write(&path, zstd::encode_all(unknown.as_bytes(), 1).unwrap()).unwrap();
    assert!(matches!(
        inspect(&path, &Selection::Top(1)),
        Err(SnapshotError::Invalid(_))
    ));
    header.version = VERSION;
    let missing = format!("{}\n", serde_json::to_string(&header).unwrap());
    std::fs::write(&path, zstd::encode_all(missing.as_bytes(), 1).unwrap()).unwrap();
    assert!(matches!(
        inspect(&path, &Selection::Top(1)),
        Err(SnapshotError::Invalid(_))
    ));
}

#[test]
fn streaming_selection_keeps_the_largest_samples_across_many_domains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run.zst");
    let (config, domains, report) = fixture();
    save(&path, &config, &domains, &domains, report).unwrap();
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
            first_index: Some(index as usize),
            fastest: Some(SavedResponse {
                elapsed_ns: index,
                rcode: "NOERROR".into(),
                truncated: false,
                answer_count: 0,
                records: Vec::new(),
            }),
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
    let result = inspect(&path, &Selection::Top(3)).unwrap().unwrap();
    assert_eq!(result.responding_domains, 1_000);
    assert_eq!(
        result
            .domains
            .iter()
            .map(|domain| domain.domain.as_str())
            .collect::<Vec<_>>(),
        ["d0999.example", "d0998.example", "d0997.example"]
    );
    for selection in [Selection::Bottom(3), Selection::Limit(3)] {
        let result = inspect(&path, &selection).unwrap().unwrap();
        assert_eq!(
            result
                .domains
                .iter()
                .map(|domain| domain.domain.as_str())
                .collect::<Vec<_>>(),
            ["d0000.example", "d0001.example", "d0002.example"]
        );
    }
}

#[test]
fn dot_metadata_survives_compressed_save_and_offline_inspection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dot.zst");
    let (_, domains, mut report) = fixture();
    let config = RunConfig::try_from(RunConfigInput {
        server: "1.1.1.1:853".parse().unwrap(),
        transport: crate::config::Transport::Dot {
            server_name: "cloudflare-dns.com".into(),
        },
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::Once,
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    report.stats.tls_connections = 1;
    report.stats.tls_setup = Duration::from_millis(25);
    save(&path, &config, &domains, &domains, report).unwrap();
    let inspection = inspect(&path, &Selection::Top(1)).unwrap().unwrap();
    assert_eq!(inspection.header.transport, "DoT");
    assert_eq!(
        inspection.header.tls_server_name.as_deref(),
        Some("cloudflare-dns.com")
    );
    assert_eq!(inspection.header.tls_connections, 1);
    assert_eq!(inspection.header.tls_setup_ns, 25_000_000);
    assert!(inspection.to_string().contains("DoT"));
    assert!(inspection.to_string().contains("192.0.2.9"));
}
