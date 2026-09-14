mod cli;
mod client;
mod commands;
mod error;
mod logging;
mod output;
mod session_store;
mod table;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, LogsCommand};
use crate::error::CliError;
use crate::output::Output;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = Output::new(cli.format.resolve(), cli.color);

    let _logger = match logging::init(cli.verbose, cli.trace) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("warning: {e}; continuing without a log file");
            None
        }
    };

    match dispatch(&cli, &format).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            if format.format.is_json() {
                eprintln!("{}", e.to_json());
            } else {
                eprintln!("error: {e}");
            }
            e.kind().code()
        }
    }
}

async fn dispatch(cli: &Cli, out: &Output) -> Result<(), CliError> {
    match &cli.command {
        Command::Sql(args) => commands::sql::run(cli, args, out).await,
        Command::Query(cmd) => commands::query::run(cli, cmd, out).await,
        Command::Auth(cmd) => commands::auth::run(cli, cmd, out).await,
        Command::Connection(cmd) => commands::connection::run(cli, cmd, out).await,
        Command::Stage(cmd) => commands::stage::run(cli, cmd, out).await,
        Command::Logs(LogsCommand::Path) => {
            println!("{}", logging::log_dir()?.display());
            Ok(())
        }
    }
}
