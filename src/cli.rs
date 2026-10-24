use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
    time::Duration,
};

use clap::{ArgGroup, Parser};
use thiserror::Error;

use crate::config::{ConfigError, QueryOrder, QueryType, RunConfig, RunConfigInput, StopCondition};
use crate::duration::parse_duration;

#[derive(Debug, Parser)]
#[command(version, about = "Benchmark a DNS server")]
#[command(group(
    ArgGroup::new("stop")
    .required(true)
    .multiple(false)
    .args(["duration", "queries"])
))]
pub struct Cli {
    /// DNS server IP, optionally including a port; defaults to port 53
    #[arg(long, value_name = "ENDPOINT", value_parser = parse_server)]
    server: SocketAddr,

    /// Workload file containing domain names
    #[arg(long, value_name = "FILE")]
    domains: PathBuf,

    /// Maximum outstanding queries across all workers (at most 65536 per worker)
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Number of logical DNS workers, each owning a socket and histogram
    #[arg(long, default_value_t = 1, value_name = "COUNT")]
    workers: usize,

    /// Number of Tokio runtime threads executing the logical workers
    #[arg(long, default_value_t = 1, value_name = "COUNT")]
    threads: usize,

    /// How long to send queries (integer followed by ns, us, ms, s, m, or h)
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Total number of queries to send
    #[arg(long, value_name = "COUNT")]
    queries: Option<NonZeroU64>,

    /// Timeout for each query
    #[arg(long, default_value = "2s", value_name = "TIME", value_parser = parse_duration)]
    timeout: Duration,

    /// Default query type: A or AAAA
    #[arg(long = "type", default_value = "A", value_name = "TYPE", value_parser = parse_query_type)]
    query_type: QueryType,

    /// Traverse a seeded permutation of the workload
    #[arg(long, requires = "seed")]
    shuffle: bool,

    /// Seed for reproducible shuffled traversal; requires --shuffle
    #[arg(long, requires = "shuffle")]
    seed: Option<u64>,
}

#[derive(Debug, Error)]
pub enum CliConfigError {
    #[error("specify exactly one of --duration or --queries")]
    InvalidStopCondition,

    #[error("--shuffle and --seed must be supplied together")]
    InvalidShuffleOptions,

    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl Cli {
    pub fn into_config(self) -> Result<RunConfig, CliConfigError> {
        let stop_condition = match (self.duration, self.queries) {
            (Some(duration), None) => StopCondition::Duration(duration),
            (None, Some(count)) => StopCondition::QueryCount(count),
            _ => return Err(CliConfigError::InvalidStopCondition),
        };

        let order = match (self.shuffle, self.seed) {
            (false, None) => QueryOrder::Sequential,
            (true, Some(seed)) => QueryOrder::Shuffled { seed },
            _ => return Err(CliConfigError::InvalidShuffleOptions),
        };

        let input = RunConfigInput {
            server: self.server,
            domains_path: self.domains,
            concurrency: self.concurrency,
            workers: self.workers,
            threads: self.threads,
            stop_condition,
            timeout: self.timeout,
            default_query_type: self.query_type,
            order,
        };

        Ok(RunConfig::try_from(input)?)
    }
}

fn parse_server(value: &str) -> Result<SocketAddr, String> {
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        return Ok(endpoint);
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    Err("expected an IP address or IP:port; IPv6 with a port must use [address]:port".into())
}

fn parse_query_type(value: &str) -> Result<QueryType, String> {
    if value.eq_ignore_ascii_case("A") {
        Ok(QueryType::A)
    } else if value.eq_ignore_ascii_case("AAAA") {
        Ok(QueryType::Aaaa)
    } else {
        Err("supported query types are A and AAAA".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    const BASE: [&str; 5] = [
        "dns-bench",
        "--server",
        "127.0.0.1",
        "--domains",
        "domains.txt",
    ];

    fn parse(extra: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(BASE.into_iter().chain(extra.iter().copied()))
    }

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_ipv4_and_ipv6_endpoints() {
        for (input, expected) in [
            ("127.0.0.1", "127.0.0.1:53"),
            ("127.0.0.1:5353", "127.0.0.1:5353"),
            ("::1", "[::1]:53"),
            ("[::1]:5353", "[::1]:5353"),
        ] {
            assert_eq!(
                parse_server(input).unwrap(),
                expected.parse::<SocketAddr>().unwrap()
            );
        }

        for input in ["localhost", "127.0.0.1:70000", "[::1]:bad", ""] {
            assert!(parse_server(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn requires_exactly_one_stop_condition() {
        assert_eq!(
            parse(&[]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse(&["--duration", "30s", "--queries", "100"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict,
        );
    }

    #[test]
    fn shuffle_and_seed_require_each_other() {
        for extra in [
            vec!["--duration", "30s", "--shuffle"],
            vec!["--duration", "30s", "--seed", "42"],
        ] {
            assert_eq!(
                parse(&extra).unwrap_err().kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
    }

    #[test]
    fn converts_count_workload_and_preserves_seed() {
        let config = parse(&[
            "--queries",
            "100",
            "--type",
            "aaaa",
            "--shuffle",
            "--seed",
            "0",
        ])
        .unwrap()
        .into_config()
        .unwrap();

        assert_eq!(config.server(), "127.0.0.1:53".parse().unwrap());
        assert_eq!(config.default_query_type(), QueryType::Aaaa);
        assert_eq!(config.order(), QueryOrder::Shuffled { seed: 0 });
        assert_eq!(
            config.stop_condition(),
            StopCondition::QueryCount(NonZeroU64::new(100).unwrap())
        );
    }

    #[test]
    fn duration_mode_applies_defaults() {
        let config = parse(&["--duration", "30s"])
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(config.concurrency().get(), 1);
        assert_eq!(config.workers().get(), 1);
        assert_eq!(config.threads().get(), 1);
        assert_eq!(config.timeout(), Duration::from_secs(2));
        assert_eq!(config.order(), QueryOrder::Sequential);
        assert_eq!(
            config.stop_condition(),
            StopCondition::Duration(Duration::from_secs(30))
        );
    }

    #[test]
    fn concurrency_does_not_increase_default_workers_or_threads() {
        let config = parse(&["--duration", "30s", "--concurrency", "64"])
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(config.workers().get(), 1);
        assert_eq!(config.threads().get(), 1);
    }

    #[test]
    fn parses_independent_worker_and_thread_counts() {
        let config = parse(&[
            "--queries",
            "100",
            "--concurrency",
            "64",
            "--workers",
            "8",
            "--threads",
            "2",
        ])
        .unwrap()
        .into_config()
        .unwrap();
        assert_eq!(config.concurrency().get(), 64);
        assert_eq!(config.workers().get(), 8);
        assert_eq!(config.threads().get(), 2);
    }

    #[test]
    fn zero_limits_reach_domain_validation() {
        for (extra, expected) in [
            (vec!["--duration", "0s"], ConfigError::ZeroDuration),
            (
                vec!["--duration", "30s", "--timeout", "0ms"],
                ConfigError::ZeroTimeout,
            ),
            (
                vec!["--duration", "30s", "--concurrency", "0"],
                ConfigError::ZeroConcurrency,
            ),
        ] {
            assert!(matches!(
                parse(&extra).unwrap().into_config(),
                Err(CliConfigError::Config(error)) if error == expected
            ));
        }
    }

    #[test]
    fn rejects_invalid_query_count_and_type() {
        assert!(parse(&["--queries", "0"]).is_err());
        assert!(parse(&["--duration", "30s", "--type", "MX"]).is_err());
    }
}
