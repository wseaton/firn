//! Print the Arrow schema Snowflake returns for a query, including the
//! per-field metadata (`logicalType`, `scale`, `precision`, ...) that
//! drives type conversion.
//!
//! ```text
//! cargo run --example arrow_schema -- --session-file ~/.cache/firn/sessions/<id>.json \
//!   --sql "SELECT current_timestamp(), 1.5::number(10,2)"
//! ```

extern crate firn;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use firn::{AuthArgs, QueryData, SessionSnapshot, SnowflakeApiBuilder};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    connection: Option<String>,

    #[arg(long)]
    sql: String,

    /// A saved `SessionSnapshot` (for example one written by `firn`), so no
    /// interactive login is needed
    #[arg(long)]
    session_file: Option<PathBuf>,

    /// Override CLIENT_APP_ID / CLIENT_APP_VERSION (forces a fresh login)
    #[arg(long, num_args = 2, value_names = ["APP_ID", "VERSION"])]
    identity: Option<Vec<String>>,

    /// Print the raw JSON response instead of decoding it (debug builds only)
    #[arg(long)]
    raw: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    let mut builder =
        SnowflakeApiBuilder::new(AuthArgs::from_connection(args.connection.as_deref())?);
    if let Some(id) = &args.identity {
        builder = builder
            .with_client_identity(firn::ClientIdentity {
                app_id: id[0].clone(),
                app_version: id[1].clone(),
            })
            .with_default_token_cache()?;
    } else if let Some(path) = &args.session_file {
        let snapshot: SessionSnapshot = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        builder = builder.with_session_snapshot(snapshot);
    }
    let api = builder.build()?;

    #[cfg(debug_assertions)]
    if args.raw {
        let raw = api.exec_json(&args.sql).await?;
        println!("{raw}");
        return Ok(());
    }

    let result = api.exec(&args.sql).await?;
    for column in &result.metadata.column_schema {
        println!("snowflake column {column:?}");
    }
    match result.data {
        QueryData::Arrow(batches) => {
            for (i, batch) in batches.iter().enumerate() {
                println!("batch {i}: {} rows", batch.num_rows());
                for field in batch.schema().fields() {
                    println!("  {field:?}");
                }
                for (field, column) in batch.schema().fields().iter().zip(batch.columns()) {
                    println!("  {} = {column:?}", field.name());
                }
            }
        }
        QueryData::Json(json) => println!("json result: {json}"),
        QueryData::Empty => println!("(empty)"),
    }
    if let (Some(path), Some(snapshot)) = (&args.session_file, api.session_snapshot()) {
        std::fs::write(path, serde_json::to_string(&snapshot)?)?;
    }
    Ok(())
}
