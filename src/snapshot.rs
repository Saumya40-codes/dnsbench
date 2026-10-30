use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeMap, BinaryHeap},
    env, fmt,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{
    benchmark::{DomainStats, LATENCY_GROUPS, RESPONSE_TIMING, RunReport},
    config::{QueryType, RunConfig, StopCondition},
    dns::{
        message::{Record, ResponseError, decode_records},
        name::DnsName,
    },
};

const VERSION: u32 = 1;
// Bound individual decompressed lines, including expanded names from large DNS responses.
const MAX_LINE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum SnapshotError {
    #[error("saved-run I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid saved-run JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unable to decode a retained DNS response: {0}")]
    Dns(#[from] ResponseError),
    #[error("invalid saved run: {0}")]
    Invalid(String),
    #[error("requested top {requested}, but this run contains only {entries} workload entries")]
    TopLimit { requested: usize, entries: usize },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Header {
    pub(crate) version: u32,
    pub(crate) latency_definition: String,
    pub(crate) finished_unix_secs: u64,
    pub(crate) server: SocketAddr,
    pub(crate) query_type: String,
    pub(crate) mode: String,
    pub(crate) input_entries: usize,
    pub(crate) unique_domains: usize,
    pub(crate) workers: usize,
    pub(crate) threads: usize,
    pub(crate) max_in_flight: usize,
    pub(crate) timeout_ns: u128,
    pub(crate) shuffle_seed: Option<u64>,
    pub(crate) elapsed_ns: u128,
    pub(crate) stop_reason: String,
    pub(crate) attempted: u64,
    pub(crate) sent: u64,
    pub(crate) responses: u64,
    pub(crate) timeouts: u64,
    pub(crate) socket_errors: u64,
    pub(crate) rejected_mismatched: u64,
    pub(crate) rejected_malformed: u64,
    pub(crate) socket_rotations: u64,
    pub(crate) peak_in_flight: usize,
    pub(crate) rcodes: [u64; 16],
    pub(crate) latencies: Vec<Latency>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Latency {
    population: String,
    count: u64,
    p50_ns: Option<u64>,
    p95_ns: Option<u64>,
    p99_ns: Option<u64>,
    max_ns: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SavedResponse {
    pub(crate) elapsed_ns: u64,
    pub(crate) rcode: String,
    pub(crate) truncated: bool,
    pub(crate) answer_count: u16,
    pub(crate) records: Vec<Record>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SavedDomain {
    pub(crate) domain: String,
    pub(crate) attempted: u64,
    pub(crate) sent: u64,
    pub(crate) responses: u64,
    pub(crate) timeouts: u64,
    pub(crate) socket_errors: u64,
    pub(crate) slowest: Option<SavedResponse>,
}

pub(crate) fn default_path() -> Result<PathBuf, SnapshotError> {
    let base = if cfg!(target_os = "windows") {
        env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"))
    } else {
        env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
    };
    let base = base.filter(|path| path.is_absolute()).ok_or_else(|| {
        SnapshotError::Invalid(
            "unable to determine a state directory; supply --results-file".into(),
        )
    })?;
    Ok(base.join("dnsbench/last-run.jsonl.zst"))
}

pub(crate) fn save(
    path: &Path,
    config: &RunConfig,
    domains: &[DnsName],
    mut report: RunReport,
) -> Result<(), SnapshotError> {
    let mut by_name: BTreeMap<&str, DomainStats> = BTreeMap::new();
    for (index, domain) in domains.iter().enumerate() {
        by_name
            .entry(domain.as_str())
            .or_default()
            .merge(report.stats.domains.remove(&index).unwrap_or_default());
    }
    let header = Header {
        version: VERSION,
        latency_definition: RESPONSE_TIMING.into(),
        finished_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs(),
        server: config.server(),
        query_type: config.default_query_type().to_string(),
        mode: match config.stop_condition() {
            StopCondition::Once => "once".into(),
            StopCondition::QueryCount(count) => format!("{} queries", count.get()),
            StopCondition::Duration(duration) => format!("{duration:?}"),
        },
        input_entries: domains.len(),
        unique_domains: by_name.len(),
        workers: report.workers,
        threads: report.threads,
        max_in_flight: config.max_in_flight().get(),
        timeout_ns: config.timeout().as_nanos(),
        shuffle_seed: match config.order() {
            crate::config::QueryOrder::Sequential => None,
            crate::config::QueryOrder::Shuffled { seed } => Some(seed),
        },
        elapsed_ns: report.elapsed.as_nanos(),
        stop_reason: report.stop_reason.to_string(),
        attempted: report.stats.attempted,
        sent: report.stats.sent,
        responses: report.stats.responses,
        timeouts: report.stats.timeouts,
        socket_errors: report.stats.socket_errors,
        rejected_mismatched: report.stats.rejected.mismatched,
        rejected_malformed: report.stats.rejected.malformed,
        socket_rotations: report.stats.socket_rotations,
        peak_in_flight: report.stats.peak_in_flight,
        rcodes: report.stats.rcodes,
        latencies: LATENCY_GROUPS
            .iter()
            .zip(&report.stats.latencies)
            .map(|(label, histogram)| Latency {
                population: (*label).into(),
                count: histogram.len(),
                p50_ns: (!histogram.is_empty()).then(|| histogram.value_at_quantile(0.5)),
                p95_ns: (!histogram.is_empty()).then(|| histogram.value_at_quantile(0.95)),
                p99_ns: (!histogram.is_empty()).then(|| histogram.value_at_quantile(0.99)),
                max_ns: (!histogram.is_empty()).then(|| histogram.max()),
            })
            .collect(),
    };
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    let mut encoder = zstd::stream::write::Encoder::new(temporary.as_file_mut(), 1)?;
    encoder.include_checksum(true)?;
    let mut writer = BufWriter::new(encoder);
    serde_json::to_writer(&mut writer, &header)?;
    writer.write_all(b"\n")?;
    for (name, stats) in by_name {
        let slowest = stats
            .slowest
            .map(|sample| {
                Ok::<_, SnapshotError>(SavedResponse {
                    elapsed_ns: sample.elapsed_ns,
                    rcode: sample.summary.rcode.to_string(),
                    truncated: sample.summary.truncated,
                    answer_count: sample.summary.answer_count,
                    records: decode_records(&sample.packet)?,
                })
            })
            .transpose()?;
        let domain = SavedDomain {
            domain: name.into(),
            attempted: stats.attempted,
            sent: stats.sent,
            responses: stats.responses,
            timeouts: stats.timeouts,
            socket_errors: stats.socket_errors,
            slowest,
        };
        serde_json::to_writer(&mut writer, &domain)?;
        writer.write_all(b"\n")?;
    }
    writer
        .into_inner()
        .map_err(|error| error.into_error())?
        .finish()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

struct Candidate(SavedDomain);

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .slowest
            .as_ref()
            .map(|sample| sample.elapsed_ns)
            .cmp(&other.0.slowest.as_ref().map(|sample| sample.elapsed_ns))
            .then_with(|| other.0.domain.cmp(&self.0.domain))
    }
}

pub(crate) struct Inspection {
    pub(crate) header: Header,
    pub(crate) domains: Vec<SavedDomain>,
    pub(crate) responding_domains: usize,
}

pub(crate) fn inspect(path: &Path, k: usize) -> Result<Option<Inspection>, SnapshotError> {
    if k == 0 {
        return Ok(None);
    }
    let decoder = zstd::stream::read::Decoder::new(File::open(path)?)?;
    let mut reader = BufReader::new(decoder);
    let header: Header =
        read_line(&mut reader)?.ok_or_else(|| SnapshotError::Invalid("missing header".into()))?;
    if header.version != VERSION {
        return Err(SnapshotError::Invalid(format!(
            "unsupported format version {}",
            header.version
        )));
    }
    if header.unique_domains > header.input_entries || header.input_entries == 0 {
        return Err(SnapshotError::Invalid("inconsistent domain counts".into()));
    }
    if header.query_type.parse::<QueryType>().is_err()
        || header.stop_reason.chars().any(char::is_control)
    {
        return Err(SnapshotError::Invalid("invalid run metadata".into()));
    }
    if k > header.input_entries {
        return Err(SnapshotError::TopLimit {
            requested: k,
            entries: header.input_entries,
        });
    }
    let mut selected: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();
    let mut previous = String::new();
    let mut count = 0;
    let mut responding_domains = 0;
    while let Some(domain) = read_line::<SavedDomain>(&mut reader)? {
        count += 1;
        if count > header.unique_domains
            || domain.domain <= previous
            || DnsName::parse(&domain.domain).is_err()
        {
            return Err(SnapshotError::Invalid(
                "invalid or unordered domain records".into(),
            ));
        }
        previous.clone_from(&domain.domain);
        let completed = domain
            .responses
            .checked_add(domain.timeouts)
            .and_then(|n| n.checked_add(domain.socket_errors));
        if completed != Some(domain.attempted)
            || domain.sent > domain.attempted
            || domain.responses > domain.sent
            || domain.slowest.is_some() != (domain.responses > 0)
        {
            return Err(SnapshotError::Invalid(
                "inconsistent per-domain counts".into(),
            ));
        }
        let Some(sample) = &domain.slowest else {
            continue;
        };
        if sample.rcode.chars().any(char::is_control)
            || sample.records.iter().any(|record| {
                record.name.chars().any(char::is_control)
                    || record.value.chars().any(char::is_control)
            })
        {
            return Err(SnapshotError::Invalid("invalid response text".into()));
        }
        responding_domains += 1;
        let candidate = Candidate(domain);
        if selected.len() < k {
            selected.push(Reverse(candidate));
        } else if selected.peek().is_some_and(|worst| candidate > worst.0) {
            selected.pop();
            selected.push(Reverse(candidate));
        }
    }
    if count != header.unique_domains {
        return Err(SnapshotError::Invalid("missing domain records".into()));
    }
    let mut selected: Vec<_> = selected.into_iter().map(|candidate| candidate.0).collect();
    selected.sort_unstable_by(|a, b| b.cmp(a));
    Ok(Some(Inspection {
        header,
        domains: selected.into_iter().map(|candidate| candidate.0).collect(),
        responding_domains,
    }))
}

fn read_line<T: DeserializeOwned>(reader: &mut impl BufRead) -> Result<Option<T>, SnapshotError> {
    let mut line = String::new();
    let length = reader.take(MAX_LINE_BYTES + 1).read_line(&mut line)?;
    if length == 0 {
        return Ok(None);
    }
    if length as u64 > MAX_LINE_BYTES || !line.ends_with('\n') {
        return Err(SnapshotError::Invalid(
            "oversized or incomplete JSON record".into(),
        ));
    }
    Ok(Some(serde_json::from_str(&line)?))
}

impl fmt::Display for Inspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Last run: {} · {} · {}",
            self.header.server, self.header.query_type, self.header.stop_reason
        )?;
        writeln!(
            f,
            "Top {} of {} responding domains ({} unique domains, {} input entries)",
            self.domains.len(),
            self.responding_domains,
            self.header.unique_domains,
            self.header.input_entries
        )?;
        writeln!(
            f,
            "Ranked by slowest validated response; timeouts and unqueried domains are excluded.\n"
        )?;
        if self.domains.is_empty() {
            return writeln!(f, "No validated responses were recorded.");
        }
        writeln!(
            f,
            "{:>4}  {:<32} {:>12}  {:<8} {:>9} {:>9}",
            "Rank", "Domain", "RTT (ms)", "RCODE", "Responses", "Timeouts"
        )?;
        for (index, domain) in self.domains.iter().enumerate() {
            let sample = domain
                .slowest
                .as_ref()
                .expect("ranked domain has a response");
            writeln!(
                f,
                "{:>4}  {:<32} {:>12.3}  {:<8} {:>9} {:>9}{}",
                index + 1,
                domain.domain,
                sample.elapsed_ns as f64 / 1e6,
                sample.rcode,
                domain.responses,
                domain.timeouts,
                if sample.truncated { " (truncated)" } else { "" }
            )?;
            if sample.records.is_empty() {
                writeln!(f, "      (no returned records)")?;
            }
            for record in &sample.records {
                writeln!(f, "      [{:?}] {record}", record.section)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
