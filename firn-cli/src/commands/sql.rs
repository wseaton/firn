use std::io::{IsTerminal, Read};
use std::time::Duration;

use firn::Bind;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, SqlArgs};
use crate::client::Client;
use crate::error::CliError;
use crate::output::{self, emit_result, emit_value, Output, Resolved};

pub async fn run(cli: &Cli, args: &SqlArgs, out: &Output) -> Result<(), CliError> {
    let sql = read_sql(args)?;
    let binds = collect_binds(args)?;
    let params = args
        .params
        .iter()
        .map(|p| parse_param(p))
        .collect::<Result<Vec<_>, _>>()?;

    let client = Client::connect(cli, false).await?;
    let out = &out.with_account(client.account.clone());
    let cancel = CancellationToken::new();
    let started = std::time::Instant::now();
    let work = async {
        let query = client
            .api
            .query(&sql)
            .binds(binds)
            .with_session_params(params)
            .with_cancel(&cancel);

        if args.describe {
            let schema = query.describe().await?;
            let columns: Vec<output::Column> = schema.iter().map(Into::into).collect();
            return emit_value(out, &columns);
        }
        if args.submit {
            let handle = query.submit_async().await?;
            return emit_value(
                out,
                &json!({"query_id": handle.query_id, "request_id": handle.request_id.to_string()}),
            );
        }
        if let Some(count) = args.multi {
            let results = if count == 0 {
                query.execute_multi().await?
            } else {
                query.execute_multi_exact(count).await?
            };
            for result in results {
                emit_result(out, result)?;
            }
            return Ok(());
        }
        match out.format {
            Resolved::Jsonl | Resolved::Csv => {
                let (metadata, stream) = query.execute_stream().await?;
                output::emit_stream(out, &metadata, stream).await
            }
            Resolved::Json | Resolved::Table => emit_result(out, query.execute().await?),
        }
    };

    let outcome = tokio::select! {
        biased;
        r = work => r,
        () = interrupted() => {
            cancel.cancel();
            Err(CliError::Cancelled("(interrupted)".into()))
        }
        () = deadline(args.timeout) => {
            cancel.cancel();
            Err(CliError::Timeout(args.timeout.unwrap_or_default()))
        }
    };
    client.finish();
    match &outcome {
        Ok(()) => log::info!("sql finished in {:?}", started.elapsed()),
        Err(e) => log::info!("sql failed after {:?}: {e}", started.elapsed()),
    }
    outcome
}

async fn interrupted() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn deadline(timeout: Option<u64>) {
    match timeout {
        Some(secs) => tokio::time::sleep(Duration::from_secs(secs)).await,
        None => std::future::pending::<()>().await,
    }
}

fn collect_binds(args: &SqlArgs) -> Result<Vec<Bind>, CliError> {
    if let Some(json) = &args.bind_json {
        let value: Value = serde_json::from_str(json)
            .map_err(|e| CliError::Usage(format!("--bind-json is not valid JSON: {e}")))?;
        return binds_from_json(&value);
    }
    if let Some(path) = &args.rows {
        let text = if path.as_os_str() == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(path)?
        };
        return binds_from_rows(&text);
    }
    Ok(args.binds.iter().map(|b| parse_bind(b)).collect())
}

/// `[1, "a"]` -> positional binds; `{"id": 1}` -> named binds.
pub fn binds_from_json(value: &Value) -> Result<Vec<Bind>, CliError> {
    match value {
        Value::Array(items) => items.iter().map(bind_from_json).collect(),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| Ok(bind_from_json(v)?.named(k.clone())))
            .collect(),
        _ => Err(CliError::Usage(
            "--bind-json must be a JSON array (positional) or object (named)".into(),
        )),
    }
}

fn bind_from_json(value: &Value) -> Result<Bind, CliError> {
    Ok(match value {
        Value::Null => Bind::null("TEXT"),
        Value::Bool(b) => Bind::boolean(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Bind::fixed(i),
            None => Bind::real(n.as_f64().unwrap_or_default()),
        },
        Value::String(s) => Bind::text(s.clone()),
        Value::Array(items) => column_bind(items)?,
        Value::Object(_) => {
            return Err(CliError::Usage(
                "bind values cannot be JSON objects; pass VARIANT data as a string".into(),
            ))
        }
    })
}

/// One array bind from a column of JSON scalars. The column type comes
/// from the first non-null value; nulls take that type.
fn column_bind(items: &[Value]) -> Result<Bind, CliError> {
    let type_ = items
        .iter()
        .find(|v| !v.is_null())
        .map(bind_from_json)
        .transpose()?
        .map_or("TEXT", |b| b.type_name());
    let binds = items
        .iter()
        .map(|v| {
            if v.is_null() {
                Ok(Bind::null(type_))
            } else {
                bind_from_json(v)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Bind::array(binds).map_err(firn::SnowflakeApiError::from)?)
}

/// JSON Lines, one array per row, into one array bind per column.
pub fn binds_from_rows(text: &str) -> Result<Vec<Bind>, CliError> {
    let mut columns: Vec<Vec<Value>> = Vec::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let row: Value = serde_json::from_str(line)
            .map_err(|e| CliError::Usage(format!("--rows line {}: {e}", n + 1)))?;
        let Value::Array(cells) = row else {
            return Err(CliError::Usage(format!(
                "--rows line {}: expected a JSON array",
                n + 1
            )));
        };
        if columns.is_empty() {
            columns = vec![Vec::new(); cells.len()];
        } else if cells.len() != columns.len() {
            return Err(CliError::Usage(format!(
                "--rows line {}: expected {} values, got {}",
                n + 1,
                columns.len(),
                cells.len()
            )));
        }
        for (col, cell) in columns.iter_mut().zip(cells) {
            col.push(cell);
        }
    }
    if columns.is_empty() {
        return Err(CliError::Usage("--rows file has no rows".into()));
    }
    columns.iter().map(|c| column_bind(c)).collect()
}

fn read_sql(args: &SqlArgs) -> Result<String, CliError> {
    if let Some(q) = &args.query {
        return Ok(q.clone());
    }
    let text = match &args.file {
        Some(path) if path.as_os_str() != "-" => std::fs::read_to_string(path)?,
        _ => {
            if args.file.is_none() && std::io::stdin().is_terminal() {
                return Err(CliError::Usage(
                    "no SQL given: pass it as an argument, --file, or on stdin".into(),
                ));
            }
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    if text.trim().is_empty() {
        return Err(CliError::Usage("SQL is empty".into()));
    }
    Ok(text)
}

/// Integers, floats, booleans, and `null` are typed; a single-quoted value
/// is text with the quotes stripped; anything else is text.
pub fn parse_bind(raw: &str) -> Bind {
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return Bind::text(&raw[1..raw.len() - 1]);
    }
    if raw.eq_ignore_ascii_case("null") {
        return Bind::null("TEXT");
    }
    if raw.eq_ignore_ascii_case("true") {
        return Bind::boolean(true);
    }
    if raw.eq_ignore_ascii_case("false") {
        return Bind::boolean(false);
    }
    if let Ok(n) = raw.parse::<i64>() {
        return Bind::fixed(n);
    }
    if let Ok(f) = raw.parse::<f64>() {
        if raw.contains(['.', 'e', 'E']) {
            return Bind::real(f);
        }
    }
    Bind::text(raw)
}

pub fn parse_param(raw: &str) -> Result<(String, serde_json::Value), CliError> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| CliError::Usage(format!("--param expects KEY=VALUE, got `{raw}`")))?;
    if key.trim().is_empty() {
        return Err(CliError::Usage(format!(
            "--param has an empty key: `{raw}`"
        )));
    }
    Ok((key.trim().to_uppercase(), json!(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(b: &Bind) -> serde_json::Value {
        serde_json::to_value(b).unwrap()
    }

    #[test]
    fn bind_inference() {
        assert_eq!(
            wire(&parse_bind("42")),
            json!({"type": "FIXED", "value": "42"})
        );
        assert_eq!(
            wire(&parse_bind("-7")),
            json!({"type": "FIXED", "value": "-7"})
        );
        assert_eq!(
            wire(&parse_bind("1.5")),
            json!({"type": "REAL", "value": "1.5"})
        );
        assert_eq!(
            wire(&parse_bind("true")),
            json!({"type": "BOOLEAN", "value": "true"})
        );
        assert_eq!(
            wire(&parse_bind("NULL")),
            json!({"type": "TEXT", "value": null})
        );
        assert_eq!(
            wire(&parse_bind("'42'")),
            json!({"type": "TEXT", "value": "42"})
        );
        assert_eq!(
            wire(&parse_bind("hello")),
            json!({"type": "TEXT", "value": "hello"})
        );
        assert_eq!(
            wire(&parse_bind("''")),
            json!({"type": "TEXT", "value": ""})
        );
    }

    #[test]
    fn bind_json_positional_named_and_arrays() {
        let pos = binds_from_json(&json!([1, "a", true, null, 2.5])).unwrap();
        assert_eq!(pos.len(), 5);
        assert!(pos.iter().all(|b| b.name().is_none()));
        assert_eq!(wire(&pos[0]), json!({"type": "FIXED", "value": "1"}));
        assert_eq!(wire(&pos[3]), json!({"type": "TEXT", "value": null}));
        assert_eq!(wire(&pos[4]), json!({"type": "REAL", "value": "2.5"}));

        let named = binds_from_json(&json!({"id": 7, "tags": ["x", null]})).unwrap();
        let by_name: std::collections::HashMap<_, _> =
            named.iter().map(|b| (b.name().unwrap(), b)).collect();
        assert_eq!(wire(by_name["id"]), json!({"type": "FIXED", "value": "7"}));
        assert_eq!(
            wire(by_name["tags"]),
            json!({"type": "TEXT", "value": ["x", null]})
        );

        assert!(binds_from_json(&json!("scalar")).is_err());
        assert!(binds_from_json(&json!([{"o": 1}])).is_err());
        assert!(binds_from_json(&json!([[1, "mixed"]])).is_err());
    }

    #[test]
    fn rows_become_column_array_binds() {
        let binds = binds_from_rows("[1, \"a\"]\n\n[null, \"b\"]\n[3, null]\n").unwrap();
        assert_eq!(binds.len(), 2);
        assert_eq!(
            wire(&binds[0]),
            json!({"type": "FIXED", "value": ["1", null, "3"]})
        );
        assert_eq!(
            wire(&binds[1]),
            json!({"type": "TEXT", "value": ["a", "b", null]})
        );
        assert!(binds_from_rows("[1]\n[1, 2]\n").is_err());
        assert!(binds_from_rows("{\"a\": 1}\n").is_err());
        assert!(binds_from_rows("\n").is_err());
    }

    #[test]
    fn param_parsing() {
        assert_eq!(
            parse_param("query_tag=agent-7").unwrap(),
            ("QUERY_TAG".to_owned(), json!("agent-7"))
        );
        assert_eq!(
            parse_param("TIMEZONE=UTC=weird").unwrap(),
            ("TIMEZONE".to_owned(), json!("UTC=weird"))
        );
        assert!(parse_param("novalue").is_err());
        assert!(parse_param("=x").is_err());
    }
}
