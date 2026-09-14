use crate::cli::{Cli, StageCommand};
use crate::client::Client;
use crate::error::CliError;
use crate::output::{emit_result, Resolved};

pub async fn run(cli: &Cli, cmd: &StageCommand, format: Resolved) -> Result<(), CliError> {
    let client = Client::connect(cli, false).await?;
    let outcome = match cmd {
        StageCommand::List { stage } => {
            let result = client.api.exec(&format!("LIST {}", at(stage))).await?;
            emit_result(format, result)
        }
        StageCommand::Put {
            local_path,
            stage,
            no_compress,
            overwrite,
        } => {
            let mut sql = format!(
                "PUT file://{} {}",
                absolute(local_path)?.display(),
                at(stage)
            );
            if *no_compress {
                sql.push_str(" AUTO_COMPRESS = FALSE");
            }
            if *overwrite {
                sql.push_str(" OVERWRITE = TRUE");
            }
            let result = client.api.exec(&sql).await?;
            emit_result(format, result)
        }
        StageCommand::Get { stage, local_dir } => {
            let dir = absolute(&local_dir.to_string_lossy())?;
            let sql = format!("GET {} file://{}/", at(stage), dir.display());
            let result = client.api.exec(&sql).await?;
            emit_result(format, result)
        }
    };
    client.finish();
    outcome
}

fn absolute(path: &str) -> Result<std::path::PathBuf, CliError> {
    let p = std::path::Path::new(path);
    Ok(if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    })
}

fn at(stage: &str) -> String {
    if stage.starts_with('@') {
        stage.to_owned()
    } else {
        format!("@{stage}")
    }
}
