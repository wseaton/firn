use std::time::{Duration, Instant};

use firn::QueryStatus;
use serde_json::json;

use crate::cli::{Cli, QueryCommand};
use crate::client::Client;
use crate::error::CliError;
use crate::output::{emit_result, emit_value, Resolved};

pub async fn run(cli: &Cli, cmd: &QueryCommand, format: Resolved) -> Result<(), CliError> {
    let client = Client::connect(cli, false).await?;
    let outcome = match cmd {
        QueryCommand::Status { query_id } => {
            let status = client.api.query_status(query_id).await?;
            emit_value(format, &status_json(query_id, &status))
        }
        QueryCommand::Wait {
            query_id,
            interval,
            timeout,
        } => {
            let started = Instant::now();
            loop {
                let status = client.api.query_status(query_id).await?;
                if status.is_terminal() {
                    emit_value(format, &status_json(query_id, &status))?;
                    break if status.is_success() {
                        Ok(())
                    } else {
                        Err(CliError::Api(firn::SnowflakeApiError::ApiError(
                            "QUERY_FAILED".into(),
                            format!("query {query_id} ended with {status:?}"),
                        )))
                    };
                }
                if let Some(t) = timeout {
                    if started.elapsed() >= Duration::from_secs(*t) {
                        break Err(CliError::Timeout(*t));
                    }
                }
                log::debug!("query {query_id} is {status:?}; polling again in {interval}s");
                tokio::time::sleep(Duration::from_secs(*interval)).await;
            }
        }
        QueryCommand::Fetch { query_id } => {
            let result = client.api.fetch_results(query_id).await?;
            emit_result(format, result)
        }
        QueryCommand::Cancel { query_id } => {
            client.api.cancel_query_by_id(query_id).await?;
            emit_value(format, &json!({"query_id": query_id, "cancelled": true}))
        }
    };
    client.finish();
    outcome
}

fn status_json(query_id: &str, status: &QueryStatus) -> serde_json::Value {
    json!({
        "query_id": query_id,
        "status": format!("{status:?}"),
        "terminal": status.is_terminal(),
        "success": status.is_success(),
    })
}
