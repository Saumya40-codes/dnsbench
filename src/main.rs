mod benchmark;
mod cli;
mod config;
mod dns;
mod duration;

use std::process::ExitCode;

use clap::Parser;

use crate::{
    cli::Cli,
    config::{QueryOrder, RunConfig, StopCondition},
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match cli.into_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    let mut domains = match benchmark::load_domains(config.domains_path()) {
        Ok(domains) => domains,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    print_config(&config);
    println!("Loaded domains: {}", domains.len());
    let report = match benchmark::run(&config, &mut domains) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{report}");
    match report.stop_reason {
        benchmark::StopReason::SocketError | benchmark::StopReason::SendDeadline => {
            ExitCode::FAILURE
        }
        _ => ExitCode::SUCCESS,
    }
}

fn print_config(config: &RunConfig) {
    println!("Server: {}", config.server());
    println!("Domains: {}", config.domains_path().display());
    println!("Concurrency: {}", config.concurrency());

    match config.stop_condition() {
        StopCondition::Duration(duration) => println!("Duration: {duration:?}"),
        StopCondition::QueryCount(count) => println!("Queries: {count}"),
    }

    println!("Timeout: {:?}", config.timeout());
    let query_type = match config.default_query_type() {
        config::QueryType::A => "A",
        config::QueryType::Aaaa => "AAAA",
    };
    println!("Default query type: {query_type}");

    match config.order() {
        QueryOrder::Sequential => println!("Order: sequential"),
        QueryOrder::Shuffled { seed } => {
            println!("Order: shuffled");
            println!("Seed: {seed}");
        }
    }
}
