mod benchmark;
mod cli;
mod config;
mod dns;
mod duration;
mod snapshot;

use std::process::ExitCode;

use clap::Parser;

use crate::{
    cli::Cli,
    config::{QueryOrder, RunConfig, StopCondition},
};

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    let mut results_file = cli.results_file.take();
    let selection = match cli.command.take() {
        Some(cli::Command::Get(args)) => {
            results_file = args.results_file;
            Some(match (args.topk, args.bottomk, args.limit, args.domain) {
                (Some(k), _, _, _) => snapshot::Selection::Top(k),
                (_, Some(k), _, _) => snapshot::Selection::Bottom(k),
                (_, _, Some(k), _) => snapshot::Selection::Limit(k),
                (_, _, _, Some(domain)) => snapshot::Selection::Domain(domain),
                _ => unreachable!("clap requires a get selector"),
            })
        }
        None => cli.topk.map(snapshot::Selection::Top),
    };
    if let Some(selection) = selection {
        if selection.is_empty() {
            return ExitCode::SUCCESS;
        }
        let path = match results_file.map(Ok).unwrap_or_else(snapshot::default_path) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::FAILURE;
            }
        };
        return match snapshot::inspect(&path, &selection) {
            Ok(Some(report)) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Ok(None) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error reading {}: {error}", path.display());
                ExitCode::FAILURE
            }
        };
    }
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
    let input_domains = domains.clone();
    let report = match benchmark::run(&config, &mut domains) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{report}");
    let status = match report.stop_reason {
        benchmark::StopReason::SocketError | benchmark::StopReason::SendDeadline => {
            ExitCode::FAILURE
        }
        _ => ExitCode::SUCCESS,
    };
    let path = match results_file.map(Ok).unwrap_or_else(snapshot::default_path) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = snapshot::save(&path, &config, &domains, &input_domains, report) {
        eprintln!("error saving {}: {error}", path.display());
        return ExitCode::FAILURE;
    }
    println!("Saved run: {}", path.display());
    status
}

fn print_config(config: &RunConfig) {
    println!("Server: {}", config.server());
    println!("Domains: {}", config.domains_path().display());
    println!("Max in flight: {}", config.max_in_flight());

    match config.stop_condition() {
        StopCondition::Once => println!("Mode: one pass through the workload"),
        StopCondition::Duration(duration) => println!("Duration: {duration:?}"),
        StopCondition::QueryCount(count) => println!("Queries: {count}"),
    }

    println!("Timeout: {:?}", config.timeout());
    println!("Default query type: {}", config.default_query_type());

    match config.order() {
        QueryOrder::Sequential => println!("Order: sequential"),
        QueryOrder::Shuffled { seed } => {
            println!("Order: shuffled");
            println!("Seed: {seed}");
        }
    }
}
