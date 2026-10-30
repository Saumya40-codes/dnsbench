use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
    time::Duration,
};

use clap::{ArgGroup, Args, Parser, Subcommand};
use thiserror::Error;

use crate::config::{ConfigError, QueryOrder, QueryType, RunConfig, RunConfigInput, StopCondition};
use crate::dns::name::DnsName;
use crate::duration::parse_duration;

#[derive(Debug, Parser)]
#[command(version, about = "Benchmark a DNS server")]
#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
#[command(after_help = "Without --duration or --queries, each workload entry is queried once.")]
#[command(group(
    ArgGroup::new("stop")
    .multiple(false)
    .args(["duration", "queries"])
))]
#[command(group(ArgGroup::new("run").multiple(true).args([
    "server", "domains", "max_in_flight", "workers", "threads", "duration", "queries", "timeout", "query_type", "shuffle", "seed"
])))]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
    /// DNS server IP, optionally including a port; defaults to port 53
    #[arg(long, required_unless_present = "topk", value_name = "ENDPOINT", value_parser = parse_server)]
    server: Option<SocketAddr>,

    /// Workload file containing domain names
    #[arg(long, required_unless_present = "topk", value_name = "FILE")]
    domains: Option<PathBuf>,

    /// Inspect the last run's K slowest responding domains; 0 produces no output
    #[arg(long, value_name = "K", conflicts_with = "run", hide = true)]
    pub(crate) topk: Option<usize>,

    /// Override the saved-run file used for saving or inspection
    #[arg(long, value_name = "PATH")]
    pub(crate) results_file: Option<PathBuf>,

    /// Maximum outstanding queries across all workers (at most 65536 per worker)
    #[arg(long, alias = "concurrency", default_value_t = 2)]
    max_in_flight: usize,

    /// Number of logical DNS workers, each owning a socket and histogram
    #[arg(long, default_value_t = 2, value_name = "COUNT")]
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

    /// Query type: A, AAAA, NS, MX, TXT, SOA, CNAME, or PTR
    #[arg(long = "type", default_value = "A", value_name = "TYPE")]
    query_type: QueryType,

    /// Traverse a seeded permutation of the workload
    #[arg(long, requires = "seed")]
    shuffle: bool,

    /// Seed for reproducible shuffled traversal; requires --shuffle
    #[arg(long, requires = "shuffle")]
    seed: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect a saved benchmark without sending DNS queries
    Get(GetArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("selection").required(true).multiple(false)
    .args(["topk", "bottomk", "limit", "domain"])))]
pub(crate) struct GetArgs {
    /// Override the saved-run file to inspect
    #[arg(long, value_name = "PATH")]
    pub(crate) results_file: Option<PathBuf>,
    /// Domains ranked by their slowest response, descending
    #[arg(long, value_name = "K")]
    pub(crate) topk: Option<usize>,
    /// Domains ranked by their fastest response, ascending
    #[arg(long, value_name = "K")]
    pub(crate) bottomk: Option<usize>,
    /// First K unique domains in workload order
    #[arg(long, alias = "limitk", value_name = "K")]
    pub(crate) limit: Option<usize>,
    /// Answer records from this domain's slowest retained response
    #[arg(long, value_name = "NAME", value_parser = DnsName::parse)]
    pub(crate) domain: Option<DnsName>,
}

#[derive(Debug, Error)]
pub enum CliConfigError {
    #[error("--server and --domains are required to run a benchmark")]
    MissingRunArguments,
    #[error("--duration and --queries cannot be used together")]
    InvalidStopCondition,

    #[error("--shuffle and --seed must be supplied together")]
    InvalidShuffleOptions,

    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl Cli {
    pub fn into_config(self) -> Result<RunConfig, CliConfigError> {
        let (Some(server), Some(domains)) = (self.server, self.domains) else {
            return Err(CliConfigError::MissingRunArguments);
        };
        let stop_condition = match (self.duration, self.queries) {
            (None, None) => StopCondition::Once,
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
            server,
            domains_path: domains,
            max_in_flight: self.max_in_flight,
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
    fn get_requires_one_selector_and_rejects_benchmark_arguments() {
        for flag in ["--topk", "--bottomk", "--limit", "--limitk"] {
            let cli =
                Cli::try_parse_from(["dns-bench", "get", flag, "5", "--results-file", "run.zst"])
                    .unwrap();
            assert!(matches!(cli.command, Some(Command::Get(_))));
            let Some(Command::Get(args)) = cli.command else {
                panic!("missing get")
            };
            assert_eq!(args.results_file.unwrap(), PathBuf::from("run.zst"));
        }
        let cli = Cli::try_parse_from([
            "dns-bench",
            "get",
            "--results-file",
            "run.zst",
            "--domain",
            "EXAMPLE.COM.",
        ])
        .unwrap();
        let Some(Command::Get(args)) = cli.command else {
            panic!("missing get")
        };
        assert_eq!(args.domain.unwrap().as_str(), "example.com");
        for args in [
            vec!["dns-bench", "get"],
            vec!["dns-bench", "get", "--topk", "2", "--bottomk", "2"],
            vec![
                "dns-bench",
                "get",
                "--domain",
                "example.com",
                "--limit",
                "2",
            ],
            vec!["dns-bench", "get", "--domain", "a..com"],
            vec!["dns-bench", "get", "--topk", "2", "--server", "1.1.1.1"],
            vec!["dns-bench", "--server", "1.1.1.1", "get", "--topk", "2"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn inspection_needs_no_run_arguments_and_rejects_run_flags() {
        let cli = Cli::try_parse_from(["dns-bench", "--topk", "0"]).unwrap();
        assert_eq!(cli.topk, Some(0));
        assert!(Cli::try_parse_from(["dns-bench", "--topk", "3", "--server", "1.1.1.1"]).is_err());
        assert!(Cli::try_parse_from(["dns-bench", "--topk", "3", "--workers", "2"]).is_err());
        assert!(Cli::try_parse_from(["dns-bench"]).is_err());
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
    fn defaults_to_one_pass_and_rejects_conflicting_stop_conditions() {
        assert_eq!(
            parse(&[]).unwrap().into_config().unwrap().stop_condition(),
            StopCondition::Once
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
        assert_eq!(config.max_in_flight().get(), 2);
        assert_eq!(config.workers().get(), 2);
        assert_eq!(config.threads().get(), 1);
        assert_eq!(config.timeout(), Duration::from_secs(2));
        assert_eq!(config.order(), QueryOrder::Sequential);
        assert_eq!(
            config.stop_condition(),
            StopCondition::Duration(Duration::from_secs(30))
        );
    }

    #[test]
    fn max_in_flight_does_not_increase_default_workers_or_threads() {
        let config = parse(&["--duration", "30s", "--max-in-flight", "64"])
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(config.workers().get(), 2);
        assert_eq!(config.threads().get(), 1);
    }

    #[test]
    fn parses_independent_worker_and_thread_counts() {
        let config = parse(&[
            "--queries",
            "100",
            "--max-in-flight",
            "64",
            "--workers",
            "8",
            "--threads",
            "2",
        ])
        .unwrap()
        .into_config()
        .unwrap();
        assert_eq!(config.max_in_flight().get(), 64);
        assert_eq!(config.workers().get(), 8);
        assert_eq!(config.threads().get(), 2);
    }

    #[test]
    fn max_in_flight_accepts_the_previous_concurrency_spelling() {
        for flag in ["--max-in-flight", "--concurrency"] {
            let config = parse(&[flag, "8"]).unwrap().into_config().unwrap();
            assert_eq!(config.max_in_flight().get(), 8);
        }
        assert_eq!(
            parse(&["--max-in-flight", "8", "--concurrency", "16"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
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
                vec!["--duration", "30s", "--max-in-flight", "0"],
                ConfigError::ZeroMaxInFlight,
            ),
        ] {
            assert!(matches!(
                parse(&extra).unwrap().into_config(),
                Err(CliConfigError::Config(error)) if error == expected
            ));
        }
    }

    #[test]
    fn accepts_supported_query_types_case_insensitively() {
        for query_type in QueryType::ALL {
            for value in [
                query_type.to_string(),
                query_type.to_string().to_lowercase(),
            ] {
                let config = parse(&["--type", &value]).unwrap().into_config().unwrap();
                assert_eq!(config.default_query_type(), query_type);
            }
        }
    }

    #[test]
    fn rejects_invalid_query_count_and_type() {
        assert!(parse(&["--queries", "0"]).is_err());
        assert!(parse(&["--duration", "30s", "--type", "AXFR"]).is_err());
    }
}
