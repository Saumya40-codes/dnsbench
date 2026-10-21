use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use mio::{Waker, net::UdpSocket};

use crate::{
    config::{RunConfig, StopCondition},
    dns::name::DnsName,
};

use super::{BenchmarkError, RunReport, RunStats, StopReason, concurrent::Engine};

pub(super) struct Shared {
    next_query: AtomicU64,
    count: Option<u64>,
    stopped: AtomicU8,
    pub(super) in_flight: AtomicUsize,
    pub(super) peak_in_flight: AtomicUsize,
    used_ports: Mutex<[u64; 1024]>,
    pub(super) wakers: Mutex<Vec<Arc<Waker>>>,
    started: Mutex<Option<Instant>>,
    start_ready: Condvar,
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
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            used_ports: Mutex::new([0; 1024]),
            wakers: Mutex::new(Vec::new()),
            started: Mutex::new(None),
            start_ready: Condvar::new(),
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
        for waker in self
            .wakers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            let _ = waker.wake();
        }
    }

    pub(super) fn stop_reason(&self) -> Option<StopReason> {
        match self.stopped.load(Ordering::Acquire) {
            0 => None,
            1 => Some(StopReason::SendDeadline),
            _ => Some(StopReason::SocketError),
        }
    }

    fn wait_for_start(&self) -> Instant {
        let started = self
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let started = self
            .start_ready
            .wait_while(started, |time| time.is_none())
            .unwrap_or_else(|error| error.into_inner());
        started.expect("coordinator releases workers with a start time")
    }

    fn start(&self) {
        *self
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Instant::now());
        self.start_ready.notify_all();
    }
}

pub(super) fn worker_count(config: &RunConfig) -> usize {
    let requested = config.workers().map_or_else(
        || thread::available_parallelism().map_or(1, |count| count.get()),
        |count| count.get(),
    );
    let count_limit = match config.stop_condition() {
        StopCondition::QueryCount(count) => usize::try_from(count.get()).unwrap_or(usize::MAX),
        StopCondition::Duration(_) => usize::MAX,
    };
    requested.min(config.concurrency().get()).min(count_limit)
}

pub(super) fn run(config: &RunConfig, domains: &[DnsName]) -> Result<RunReport, BenchmarkError> {
    run_with_workers(config, domains, worker_count(config))
}

pub(super) fn run_with_workers(
    config: &RunConfig,
    domains: &[DnsName],
    workers: usize,
) -> Result<RunReport, BenchmarkError> {
    let shared = Shared::new(config);
    let mut stats = RunStats::new()?;
    let mut engines = Vec::with_capacity(workers);
    for index in 0..workers {
        let quota = config.concurrency().get() / workers
            + usize::from(index < config.concurrency().get() % workers);
        engines.push(Engine::new(config, domains, &shared, quota)?);
    }

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut first_error = None;
        for (index, engine) in engines.into_iter().enumerate() {
            let shared = &shared;
            let handle = thread::Builder::new()
                .name(format!("dnsbench-{index}"))
                .spawn_scoped(scope, move || {
                    let result =
                        catch_unwind(AssertUnwindSafe(|| engine.run(shared.wait_for_start())))
                            .unwrap_or(Err(BenchmarkError::WorkerPanicked));
                    if result.is_err() {
                        shared.cancel(StopReason::SocketError);
                    }
                    result
                });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    shared.cancel(StopReason::SocketError);
                    first_error = Some(BenchmarkError::Io(error));
                    break;
                }
            }
        }
        shared.start();
        let mut elapsed = Duration::ZERO;
        for handle in handles {
            match handle.join().unwrap_or(Err(BenchmarkError::WorkerPanicked)) {
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
    Ok(socket)
}

#[cfg(test)]
mod tests;
