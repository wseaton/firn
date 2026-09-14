use firn::config;
use firn::QueryData;
use serde_json::{json, Value};

use crate::cli::{Cli, ConnectionCommand};
use crate::client::{Client, Target};
use crate::error::CliError;
use crate::output::{emit_value, Resolved};

pub async fn run(cli: &Cli, cmd: &ConnectionCommand, format: Resolved) -> Result<(), CliError> {
    match cmd {
        ConnectionCommand::List => {
            let dir = config::config_dir()?;
            let default = config::default_connection_name(&dir)?;
            let names = config::list_connections(&dir)?;
            let rows: Vec<Value> = names
                .iter()
                .map(|n| json!({"name": n, "default": *n == default}))
                .collect();
            emit_value(format, &json!({"config_dir": dir, "connections": rows}))
        }
        ConnectionCommand::Show => {
            let target = Target::resolve(cli)?;
            let c = &target.config;
            emit_value(
                format,
                &json!({
                    "name": c.name,
                    "account": c.account,
                    "user": c.user,
                    "host": target.host,
                    "base_url": c.base_url()?.as_str(),
                    "authenticator": c.authenticator.as_deref().unwrap_or("snowflake"),
                    "warehouse": c.warehouse,
                    "database": c.database,
                    "schema": c.schema,
                    "role": c.role,
                    "password": c.password.as_ref().map(|_| "[REDACTED]"),
                    "token": c.token.as_ref().map(|_| "[REDACTED]"),
                    "token_file_path": c.token_file_path,
                    "private_key_file": c.private_key_file,
                    "private_key_file_pwd": c.private_key_file_pwd.as_ref().map(|_| "[REDACTED]"),
                    "token_cache": target.cache_enabled,
                    "login_timeout_secs": c.login_timeout.map(|d| d.as_secs()),
                    "extra": c.extra,
                }),
            )
        }
        ConnectionCommand::Test => {
            let client = Client::connect(cli, false).await?;
            let result = client
                .api
                .exec(
                    "SELECT CURRENT_ACCOUNT() AS account, CURRENT_USER() AS user, \
                     CURRENT_ROLE() AS role, CURRENT_WAREHOUSE() AS warehouse, \
                     CURRENT_DATABASE() AS database, CURRENT_SCHEMA() AS schema, \
                     CURRENT_VERSION() AS version, CURRENT_SESSION() AS session",
                )
                .await?;
            client.finish();
            let mut report = json!({"ok": true, "query_id": result.metadata.query_id});
            if let (QueryData::Arrow(batches), Some(obj)) = (&result.data, report.as_object_mut()) {
                let mut buf = Vec::new();
                let mut writer = arrow::json::writer::ArrayWriter::new(&mut buf);
                for b in batches {
                    writer.write(b)?;
                }
                writer.finish()?;
                if let Ok(Value::Array(rows)) = serde_json::from_slice::<Value>(&buf) {
                    if let Some(Value::Object(first)) = rows.into_iter().next() {
                        for (k, v) in first {
                            obj.insert(k.to_lowercase(), v);
                        }
                    }
                }
            }
            emit_value(format, &report)
        }
    }
}
