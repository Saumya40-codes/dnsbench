mod concurrent;
mod domain;
mod domain_store;
mod input;
mod results;
mod workers;

pub(crate) use domain::{DomainStats, ResponseSample};
pub(crate) use input::load_domains;

use std::{io, time::Instant};

use thiserror::Error;

use crate::{
    config::{QueryOrder, RunConfig, StopCondition},
    dns::{
        name::DnsName,
        udp::{QueryOutcome, UdpClient},
    },
};
pub(crate) use results::StopReason;
pub(crate) use results::{LATENCY_GROUPS, RESPONSE_TIMING, RunReport, RunStats};

#[derive(Debug, Error)]
pub(crate) enum BenchmarkError {
    #[error("max-in-flight must not exceed 65536 queries per worker")]
    UnsupportedInFlightLimit,
    #[error("the workload contains no domains")]
    EmptyWorkload,
    #[error("duration or timeout exceeds the clock's range")]
    ClockRange,
    #[error("benchmark I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("unable to create latency histogram: {0}")]
    HistogramCreation(#[from] hdrhistogram::CreationError),
    #[error("unable to record latency: {0}")]
    HistogramRecord(#[from] hdrhistogram::RecordError),
    #[error("latency exceeds the histogram's nanosecond range")]
    LatencyRange,
    #[error("unable to allocate a fresh source port for transaction ID reuse")]
    SourcePortsExhausted,
    #[error("unable to merge latency histograms: {0}")]
    HistogramMerge(#[from] hdrhistogram::AdditionError),
    #[error("benchmark worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
    #[error("query sequence exceeds the supported counter range")]
    QueryCounterRange,
}

pub(crate) fn run(
    config: &RunConfig,
    domains: &mut [DnsName],
) -> Result<RunReport, BenchmarkError> {
    if config
        .max_in_flight()
        .get()
        .div_ceil(config.workers().get())
        > usize::from(u16::MAX) + 1
    {
        return Err(BenchmarkError::UnsupportedInFlightLimit);
    }
    if domains.is_empty() {
        return Err(BenchmarkError::EmptyWorkload);
    }
    Instant::now()
        .checked_add(config.timeout())
        .ok_or(BenchmarkError::ClockRange)?;
    if let StopCondition::Duration(duration) = config.stop_condition() {
        Instant::now()
            .checked_add(duration)
            .ok_or(BenchmarkError::ClockRange)?;
    }

    if let QueryOrder::Shuffled { seed } = config.order() {
        let mut state = seed;
        // Fisher-Yates implementation reference: https://github.com/kevin-wayne/algs4/blob/master/src/main/java/edu/princeton/cs/algs4/Knuth.java
        for index in (1..domains.len()).rev() {
            let bound = (index + 1) as u64;
            let threshold = bound.wrapping_neg() % bound;
            loop {
                // SplitMix64 reference implementation: https://prng.di.unimi.it/splitmix64.c
                state = state.wrapping_add(0x9E3779B97F4A7C15);
                let mut random = state;
                random = (random ^ (random >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                random = (random ^ (random >> 27)).wrapping_mul(0x94D049BB133111EB);
                random ^= random >> 31;
                // Reject values below threshold so `% bound` does not favor some positions.
                if random >= threshold {
                    domains.swap(index, (random % bound) as usize);
                    break;
                }
            }
        }
    }

    if config.max_in_flight().get() > 1 || config.threads().is_some_and(|threads| threads.get() > 1)
    {
        return workers::run(config, domains);
    }

    let mut client = UdpClient::connect(config.server())?;
    let mut used_ports = [0u64; 1024];
    let port = usize::from(client.local_addr()?.port());
    used_ports[port / 64] |= 1u64 << (port % 64);
    let mut stats = RunStats::new()?;
    stats.domains.reserve_domains(domains.len());
    let mut next_id = 0u32;
    let mut domain_index = 0;
    let started = Instant::now();
    let query_limit = match config.stop_condition() {
        StopCondition::Once => Some(domains.len() as u64),
        StopCondition::QueryCount(count) => Some(count.get()),
        StopCondition::Duration(_) => None,
    };
    let deadline = match config.stop_condition() {
        StopCondition::Duration(duration) => Some(
            started
                .checked_add(duration)
                .ok_or(BenchmarkError::ClockRange)?,
        ),
        StopCondition::Once | StopCondition::QueryCount(_) => None,
    };

    let stop_reason = loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            break StopReason::Duration;
        }
        if query_limit.is_some_and(|count| stats.sent >= count) {
            break match config.stop_condition() {
                StopCondition::Once => StopReason::WorkloadCompleted,
                _ => StopReason::QueryCount,
            };
        }

        if next_id > u32::from(u16::MAX) {
            // Bind before dropping the old socket so the next ID epoch uses a different port.
            let mut replacement = None;
            // Never reuse a source port within this run, including older ID epochs.
            for _ in 0..64 {
                let candidate = UdpClient::connect(config.server())?;
                let port = usize::from(candidate.local_addr()?.port());
                let mask = 1u64 << (port % 64);
                if used_ports[port / 64] & mask == 0 {
                    used_ports[port / 64] |= mask;
                    replacement = Some(candidate);
                    break;
                }
            }
            client = replacement.ok_or(BenchmarkError::SourcePortsExhausted)?;
            next_id = 0;
            stats.socket_rotations += 1;
        }
        // Socket setup may have taken us past the send window.
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            break StopReason::Duration;
        }
        let report = client.query(
            &domains[domain_index],
            next_id as u16,
            config.default_query_type(),
            true,
            config.timeout(),
            deadline,
        )?;
        if !report.sent
            && matches!(report.outcome, QueryOutcome::Timeout)
            && deadline.is_some_and(|limit| Instant::now() >= limit)
        {
            break StopReason::Duration;
        }
        next_id += 1;
        let socket_failed = matches!(report.outcome, QueryOutcome::SocketError(_));
        let sent = report.sent;
        let packet =
            matches!(report.outcome, QueryOutcome::Response(_)).then(|| client.response_packet());
        stats
            .domains
            .get_or_insert(domain_index)
            .record(&report, packet);
        stats.record(report)?;
        domain_index = (domain_index + 1) % domains.len();
        if socket_failed {
            break StopReason::SocketError;
        }
        if !sent {
            break StopReason::SendDeadline;
        }
    };

    Ok(RunReport {
        workers: 1,
        threads: 1,
        stats,
        elapsed: started.elapsed(),
        stop_reason,
    })
}

#[cfg(test)]
mod tests;
