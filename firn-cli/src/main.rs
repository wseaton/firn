mod cli;
mod client;
mod commands;
mod error;
mod logging;
mod output;
mod session_store;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, LogsCommand};
use crate::error::CliError;
use crate::output::Resolved;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = cli.format.resolve();

    let _logger = match logging::init(cli.verbose, cli.trace) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("warning: {e}; continuing without a log file");
            None
        }
    };

    match dispatch(&cli, format).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            if format.is_json() {
                eprintln!("{}", e.to_json());
            } else {
                eprintln!("error: {e}");
            }
            e.kind().code()
        }
    }
}

async fn dispatch(cli: &Cli, format: Resolved) -> Result<(), CliError> {
    match &cli.command {
        Command::Sql(args) => commands::sql::run(cli, args, format).await,
        Command::Query(cmd) => commands::query::run(cli, cmd, format).await,
        Command::Auth(cmd) => commands::auth::run(cli, cmd, format).await,
        Command::Connection(cmd) => commands::connection::run(cli, cmd, format).await,
        Command::Stage(cmd) => commands::stage::run(cli, cmd, format).await,
        Command::Logs(LogsCommand::Path) => {
            println!("{}", logging::log_dir()?.display());
            Ok(())
        }
    }
}
