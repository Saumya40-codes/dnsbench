use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{runtime::Builder, sync::watch, task::JoinSet};

use crate::{
    config::{RunConfig, StopCondition},
    dns::name::DnsName,
};

use super::{BenchmarkError, RunReport, RunStats, StopReason, concurrent::Engine};

pub(super) struct Shared {
    next_query: AtomicU64,
    count: Option<u64>,
    stopped: AtomicU8,
    pub(super) stop_updates: watch::Sender<()>,
    pub(super) in_flight: AtomicUsize,
    pub(super) peak_in_flight: AtomicUsize,
    used_ports: Mutex<[u64; 1024]>,
}

impl Shared {
    pub(super) fn new(config: &RunConfig) -> Self {
        Self {
            next_query: AtomicU64::new(0),
            count: match config.stop_condition() {
                StopCondition::QueryCount(count) => Some(count.get()),
                StopCondition::Duration(_) => None,
            },
            stopped: AtomicU8::new(0),
            stop_updates: watch::channel(()).0,
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            used_ports: Mutex::new([0; 1024]),
        }
    }

    pub(super) fn claim(&self) -> Result<Option<u64>, BenchmarkError> {
        match self
            .next_query
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if self.count.is_some_and(|count| next >= count) {
                    None
                } else {
                    next.checked_add(1)
                }
            }) {
            Ok(sequence) => Ok(Some(sequence)),
            Err(next) if self.count.is_some_and(|count| next >= count) => Ok(None),
            Err(_) => Err(BenchmarkError::QueryCounterRange),
        }
    }

    pub(super) fn connect(&self, server: SocketAddr) -> Result<UdpSocket, BenchmarkError> {
        for _ in 0..64 {
            let socket = connect(server)?;
            let port = usize::from(socket.local_addr()?.port());
            let mask = 1u64 << (port % 64);
            let mut ports = self
                .used_ports
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if ports[port / 64] & mask == 0 {
                ports[port / 64] |= mask;
                return Ok(socket);
            }
        }
        Err(BenchmarkError::SourcePortsExhausted)
    }

    pub(super) fn cancel(&self, reason: StopReason) {
        let code = if reason == StopReason::SendDeadline {
            1
        } else {
            2
        };
        self.stopped.fetch_max(code, Ordering::Release);
        self.stop_updates.send_replace(());
    }

    pub(super) fn stop_reason(&self) -> Option<StopReason> {
        match self.stopped.load(Ordering::Acquire) {
            0 => None,
            1 => Some(StopReason::SendDeadline),
            _ => Some(StopReason::SocketError),
        }
    }
}

pub(super) fn run(config: &RunConfig, domains: &[DnsName]) -> Result<RunReport, BenchmarkError> {
    run_with_workers(config, domains, config.workers().get())
}

pub(super) fn run_with_workers(
    config: &RunConfig,
    domains: &[DnsName],
    workers: usize,
) -> Result<RunReport, BenchmarkError> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(config.threads().get())
        .thread_name("dnsbench-runtime")
        .enable_all()
        .build()?;
    let threads = runtime.metrics().num_workers();
    let config = Arc::new(config.clone());
    let domains: Arc<[DnsName]> = Arc::from(domains);
    runtime.block_on(async move {
        let shared = Arc::new(Shared::new(&config));
        let mut stats = RunStats::new()?;
        let mut engines = Vec::with_capacity(workers);
        for index in 0..workers {
            let quota = config.concurrency().get() / workers
                + usize::from(index < config.concurrency().get() % workers);
            engines.push(Engine::new(
                Arc::clone(&config),
                Arc::clone(&domains),
                Arc::clone(&shared),
                quota,
            )?);
        }

        let (start, ready) = watch::channel(None);
        let mut tasks = JoinSet::new();
        for engine in engines {
            let shared = Arc::clone(&shared);
            let mut ready = ready.clone();
            tasks.spawn(async move {
                let started = (*ready
                    .wait_for(|time| time.is_some())
                    .await
                    .expect("coordinator retains start sender"))
                .expect("coordinator supplies start time");
                let result = engine.run(started).await;
                if result.is_err() {
                    shared.cancel(StopReason::SocketError);
                }
                result
            });
        }
        start.send_replace(Some(Instant::now()));
        let mut first_error = None;
        let mut elapsed = Duration::ZERO;
        while let Some(result) = tasks.join_next().await {
            match result
                .map_err(BenchmarkError::Worker)
                .and_then(|result| result)
            {
                Ok(report) => {
                    elapsed = elapsed.max(report.elapsed);
                    if let Err(error) = stats.merge(report.stats) {
                        shared.cancel(StopReason::SocketError);
                        first_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    shared.cancel(StopReason::SocketError);
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        stats.peak_in_flight = shared.peak_in_flight.load(Ordering::Relaxed);
        let stop_reason = shared
            .stop_reason()
            .unwrap_or(match config.stop_condition() {
                StopCondition::Duration(_) => StopReason::Duration,
                StopCondition::QueryCount(_) => StopReason::QueryCount,
            });
        Ok(RunReport {
            workers,
            threads,
            stats,
            elapsed,
            stop_reason,
        })
    })
}

fn connect(server: SocketAddr) -> io::Result<UdpSocket> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(server)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests;
