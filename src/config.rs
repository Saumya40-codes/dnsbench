use std::{
    fmt,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QueryType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
}

impl QueryType {
    pub(crate) const ALL: [Self; 8] = [
        Self::A,
        Self::Aaaa,
        Self::Ns,
        Self::Mx,
        Self::Txt,
        Self::Soa,
        Self::Cname,
        Self::Ptr,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Ns => "NS",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Soa => "SOA",
            Self::Cname => "CNAME",
            Self::Ptr => "PTR",
        }
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QueryType {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|query_type| value.eq_ignore_ascii_case(query_type.as_str()))
            .ok_or("supported query types are A, AAAA, NS, MX, TXT, SOA, CNAME, and PTR")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCondition {
    Once,
    Duration(Duration),
    QueryCount(NonZeroU64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOrder {
    Sequential,
    Shuffled { seed: u64 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Transport {
    #[default]
    Udp,
    Dot {
        server_name: String,
    },
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Dot { .. } => "DoT",
        }
    }
}

#[derive(Debug)]
pub struct RunConfigInput {
    pub server: SocketAddr,
    pub transport: Transport,
    pub domains_path: PathBuf,
    pub max_in_flight: usize,
    pub workers: usize,
    pub threads: Option<usize>,
    pub stop_condition: StopCondition,
    pub timeout: Duration,
    pub default_query_type: QueryType,
    pub order: QueryOrder,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    server: SocketAddr,
    transport: Transport,
    domains_path: PathBuf,
    max_in_flight: NonZeroUsize,
    workers: NonZeroUsize,
    threads: Option<NonZeroUsize>,
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

    #[error("invalid TLS server name")]
    InvalidTlsServerName,

    #[error("domains file path must not be empty")]
    EmptyDomainsPath,

    #[error("max-in-flight must be greater than zero")]
    ZeroMaxInFlight,

    #[error("worker count must be greater than zero")]
    ZeroWorkers,

    #[error("runtime thread count must be greater than zero")]
    ZeroThreads,

    #[error("--max-in-flight must be at least the worker count")]
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

        if let Transport::Dot { server_name } = &value.transport {
            tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.as_str())
                .map_err(|_| ConfigError::InvalidTlsServerName)?;
        }

        if value.domains_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyDomainsPath);
        }

        let max_in_flight =
            NonZeroUsize::new(value.max_in_flight).ok_or(ConfigError::ZeroMaxInFlight)?;
        let workers = NonZeroUsize::new(value.workers).ok_or(ConfigError::ZeroWorkers)?;
        let threads = value
            .threads
            .map(|count| NonZeroUsize::new(count).ok_or(ConfigError::ZeroThreads))
            .transpose()?;
        if workers.get() > max_in_flight.get() {
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
            transport: value.transport,
            domains_path: value.domains_path,
            max_in_flight,
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

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    pub fn domains_path(&self) -> &std::path::Path {
        &self.domains_path
    }

    pub fn max_in_flight(&self) -> NonZeroUsize {
        self.max_in_flight
    }

    pub fn workers(&self) -> NonZeroUsize {
        self.workers
    }

    pub fn threads(&self) -> Option<NonZeroUsize> {
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
            transport: crate::config::Transport::Udp,
            domains_path: PathBuf::from("domains.txt"),
            max_in_flight: 64,
            workers: 1,
            threads: Some(1),
            stop_condition: StopCondition::Duration(Duration::from_secs(30)),
            timeout: Duration::from_secs(2),
            default_query_type: QueryType::A,
            order: QueryOrder::Sequential,
        }
    }

    #[test]
    fn rejects_zero_max_in_flight() {
        let mut input = valid_input();
        input.max_in_flight = 0;

        assert_eq!(
            RunConfig::try_from(input).unwrap_err(),
            ConfigError::ZeroMaxInFlight,
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
        input.workers = input.max_in_flight + 1;
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
        input.threads = Some(0);
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
