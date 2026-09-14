//! Connect with a named connection from `connections.toml` / `config.toml`,
//! reusing cached id / MFA tokens and handing the session to the next run.
//!
//! ```text
//! cargo run --example connections_toml --features browser-auth,keyring -- --connection rhsandbox
//! ```
//!
//! The first run of a `externalbrowser` connection opens the browser once;
//! later runs replay the cached id token, and runs inside the session's
//! lifetime reuse the session snapshot written next to this example.

extern crate firn;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use firn::{AuthArgs, QueryData, SessionSnapshot, SnowflakeApiBuilder};

#[derive(Parser, Debug)]
struct Args {
    /// Connection name; defaults to `default_connection_name`
    #[arg(short, long)]
    connection: Option<String>,

    #[arg(long, default_value = "SELECT current_user(), current_role()")]
    sql: String,

    /// Where to keep the session snapshot between runs
    #[arg(long, default_value = "/tmp/firn-session.json")]
    session_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    let mut builder =
        SnowflakeApiBuilder::new(AuthArgs::from_connection(args.connection.as_deref())?)
            .with_default_token_cache()?;

    if let Ok(text) = std::fs::read_to_string(&args.session_file) {
        match serde_json::from_str::<SessionSnapshot>(&text) {
            Ok(snapshot) => builder = builder.with_session_snapshot(snapshot),
            Err(e) => log::warn!("ignoring session file: {e}"),
        }
    }

    let api = builder.build()?;
    let result = api.exec(&args.sql).await?;
    println!("query_id: {}", result.metadata.query_id);
    match result.data {
        QueryData::Arrow(batches) => {
            println!("{}", arrow::util::pretty::pretty_format_batches(&batches)?);
        }
        QueryData::Json(json) => println!("{json}"),
        QueryData::Empty => println!("(no rows)"),
    }

    if let Some(snapshot) = api.session_snapshot() {
        std::fs::write(&args.session_file, serde_json::to_string(&snapshot)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&args.session_file, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
