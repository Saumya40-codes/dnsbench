use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A,
    Aaaa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCondition {
    Duration(Duration),
    QueryCount(NonZeroU64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOrder {
    Sequential,
    Shuffled { seed: u64 },
}

#[derive(Debug)]
pub struct RunConfigInput {
    pub server: SocketAddr,
    pub domains_path: PathBuf,
    pub concurrency: usize,
    pub workers: usize,
    pub threads: usize,
    pub stop_condition: StopCondition,
    pub timeout: Duration,
    pub default_query_type: QueryType,
    pub order: QueryOrder,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    server: SocketAddr,
    domains_path: PathBuf,
    concurrency: NonZeroUsize,
    workers: NonZeroUsize,
    threads: NonZeroUsize,
    stop_condition: StopCondition,
    timeout: Duration,
    default_query_type: QueryType,
    order: QueryOrder,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    #[error("server port must be greater than zero")]
    ZeroServerPort,

    #[error("server address must be a destination IP, not an unspecified address")]
    UnspecifiedServerAddress,

    #[error("domains file path must not be empty")]
    EmptyDomainsPath,

    #[error("concurrency must be greater than zero")]
    ZeroConcurrency,

    #[error("worker count must be greater than zero")]
    ZeroWorkers,

    #[error("runtime thread count must be greater than zero")]
    ZeroThreads,

    #[error("worker count must not exceed concurrency")]
    TooManyWorkers,

    #[error("benchmark duration must be greater than zero")]
    ZeroDuration,

    #[error("query timeout must be greater than zero")]
    ZeroTimeout,
}

impl TryFrom<RunConfigInput> for RunConfig {
    type Error = ConfigError;

    fn try_from(value: RunConfigInput) -> Result<Self, Self::Error> {
        if value.server.port() == 0 {
            return Err(ConfigError::ZeroServerPort);
        }

        if value.server.ip().is_unspecified() {
            return Err(ConfigError::UnspecifiedServerAddress);
        }

        if value.domains_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyDomainsPath);
        }

        let concurrency =
            NonZeroUsize::new(value.concurrency).ok_or(ConfigError::ZeroConcurrency)?;
        let workers = NonZeroUsize::new(value.workers).ok_or(ConfigError::ZeroWorkers)?;
        let threads = NonZeroUsize::new(value.threads).ok_or(ConfigError::ZeroThreads)?;
        if workers.get() > concurrency.get() {
            return Err(ConfigError::TooManyWorkers);
        }

        if let StopCondition::Duration(duration) = value.stop_condition
            && duration.is_zero()
        {
            return Err(ConfigError::ZeroDuration);
        }

        if value.timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout);
        }

        Ok(Self {
            server: value.server,
            domains_path: value.domains_path,
            concurrency,
            workers,
            threads,
            stop_condition: value.stop_condition,
            timeout: value.timeout,
            default_query_type: value.default_query_type,
            order: value.order,
        })
    }
}

impl RunConfig {
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn domains_path(&self) -> &std::path::Path {
        &self.domains_path
    }

    pub fn concurrency(&self) -> NonZeroUsize {
        self.concurrency
    }

    pub fn workers(&self) -> NonZeroUsize {
        self.workers
    }

    pub fn threads(&self) -> NonZeroUsize {
        self.threads
    }

    pub fn stop_condition(&self) -> StopCondition {
        self.stop_condition
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn default_query_type(&self) -> QueryType {
        self.default_query_type
    }

    pub fn order(&self) -> QueryOrder {
        self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> RunConfigInput {
        RunConfigInput {
            server: SocketAddr::from(([127, 0, 0, 1], 53)),
            domains_path: PathBuf::from("domains.txt"),
            concurrency: 64,
            workers: 1,
            threads: 1,
            stop_condition: StopCondition::Duration(Duration::from_secs(30)),
            timeout: Duration::from_secs(2),
            default_query_type: QueryType::A,
            order: QueryOrder::Sequential,
        }
    }

    #[test]
    fn rejects_zero_concurrency() {
        let mut input = valid_input();
        input.concurrency = 0;

        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::ZeroConcurrency,
        );
    }

    #[test]
    fn rejects_zero_duration() {
        let mut input = valid_input();
        input.stop_condition = StopCondition::Duration(Duration::ZERO);

        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::ZeroDuration,
        );
    }

    #[test]
    fn validates_explicit_worker_limits() {
        let mut input = valid_input();
        input.workers = 0;
        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::ZeroWorkers
        );
        let mut input = valid_input();
        input.workers = input.concurrency + 1;
        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::TooManyWorkers
        );
        let mut input = valid_input();
        input.workers = 4;
        assert_eq!(RunConfig::try_from(input).unwrap().workers().get(), 4);
    }

    #[test]
    fn rejects_zero_runtime_threads() {
        let mut input = valid_input();
        input.threads = 0;
        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::ZeroThreads
        );
    }

    #[test]
    fn preserves_count_limit_and_shuffle_seed() {
        let mut input = valid_input();
        let count = NonZeroU64::new(1_000).unwrap();

        input.stop_condition = StopCondition::QueryCount(count);
        input.order = QueryOrder::Shuffled { seed: 42 };

        let config = RunConfig::try_from(input).unwrap();

        assert_eq!(config.stop_condition(), StopCondition::QueryCount(count),);
        assert_eq!(config.order(), QueryOrder::Shuffled { seed: 42 });
    }
}
