use std::{error::Error, time::Duration};

use crate::config::{QueryOrder, QueryType, RunConfig, RunConfigInput, StopCondition};

mod config;
fn main() -> Result<(), Box<dyn Error>> {
    let input = RunConfigInput {
        server: "127.0.0.1:53".parse()?,
        domains_path: "domains.txt".into(),
        concurrency: 64,
        stop_condition: StopCondition::Duration(Duration::from_secs(30)),
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    };

    let config = RunConfig::try_from(input)?;

    println!("{config:#?}");

    Ok(())
}
