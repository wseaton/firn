//! Result rendering. Rows stream to stdout as they arrive for jsonl and csv;
//! table and json buffer because they need the whole set.

use std::io::{self, IsTerminal, Write};

use arrow::array::RecordBatch;
use arrow::csv::WriterBuilder as CsvWriterBuilder;
use arrow::json::writer::{ArrayWriter, LineDelimitedWriter};
use firn::{FieldSchema, JsonResult, QueryData, QueryMetadata, QueryResult, RecordBatchStream};
use futures::StreamExt;
use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::{ColorMode, Format};
use crate::error::CliError;
use crate::table::{self, Style};

/// Where and how results go: the resolved format plus the account, which
/// turns query ids into Snowsight links on a terminal.
pub struct Output {
    pub format: Resolved,
    pub color: ColorMode,
    pub account: Option<String>,
}

impl Output {
    pub fn new(format: Resolved, color: ColorMode) -> Self {
        Self {
            format,
            color,
            account: None,
        }
    }

    pub fn with_account(&self, account: Option<String>) -> Self {
        Self {
            format: self.format,
            color: self.color,
            account,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    Jsonl,
    Json,
    Csv,
    Table,
}

impl Format {
    pub fn resolve(self) -> Resolved {
        match self {
            Format::Auto => {
                if io::stdout().is_terminal() {
                    Resolved::Table
                } else {
                    Resolved::Jsonl
                }
            }
            Format::Jsonl => Resolved::Jsonl,
            Format::Json => Resolved::Json,
            Format::Csv => Resolved::Csv,
            Format::Table => Resolved::Table,
        }
    }
}

impl Resolved {
    pub fn is_json(self) -> bool {
        matches!(self, Self::Jsonl | Self::Json)
    }
}

#[derive(Serialize)]
pub struct Meta {
    pub query_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<i64>,
    /// Named when the code is one gosnowflake documents, otherwise null;
    /// `statement_type_id` always carries the raw code.
    pub statement_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_type_id: Option<i64>,
    pub columns: Vec<Column>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warehouse: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Serialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub nullable: bool,
}

impl Meta {
    pub fn from(metadata: &QueryMetadata) -> Self {
        Self {
            query_id: metadata.query_id.clone(),
            rows: metadata.total_rows,
            statement_type: metadata.statement_type().and_then(|t| match t {
                firn::StatementType::Other(_) => None,
                named => Some(format!("{named:?}")),
            }),
            statement_type_id: metadata.statement_type_id,
            columns: metadata.column_schema.iter().map(Column::from).collect(),
            warehouse: metadata.warehouse.clone(),
            database: metadata.database.clone(),
            schema: metadata.schema.clone(),
            role: metadata.role.clone(),
        }
    }
}

impl From<&FieldSchema> for Column {
    fn from(f: &FieldSchema) -> Self {
        Self {
            name: f.name.clone(),
            type_: f
                .ext_type_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", f.type_).to_uppercase()),
            nullable: f.nullable,
        }
    }
}

/// Print any serializable value the way the chosen format wants it.
pub fn emit_value<T: Serialize>(out: &Output, value: &T) -> Result<(), CliError> {
    let format = out.format;
    let mut out = io::stdout().lock();
    match format {
        Resolved::Jsonl | Resolved::Csv => {
            serde_json::to_writer(&mut out, value)?;
            out.write_all(b"\n")?;
        }
        Resolved::Json | Resolved::Table => {
            serde_json::to_writer_pretty(&mut out, value)?;
            out.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Render a complete result.
pub fn emit_result(out: &Output, result: QueryResult) -> Result<(), CliError> {
    let meta = Meta::from(&result.metadata);
    match result.data {
        QueryData::Arrow(batches) => emit_batches(out, &meta, batches),
        QueryData::Json(json) => emit_json_rows(out, &meta, &json),
        QueryData::Empty => emit_batches(out, &meta, Vec::new()),
    }
}

/// Render a streaming Arrow result. jsonl and csv write each batch as it
/// arrives; the other formats collect first.
pub async fn emit_stream(
    out: &Output,
    metadata: &QueryMetadata,
    mut stream: RecordBatchStream,
) -> Result<(), CliError> {
    let meta = Meta::from(metadata);
    match out.format {
        Resolved::Jsonl => {
            let out = io::stdout().lock();
            let mut writer = LineDelimitedWriter::new(out);
            while let Some(batch) = stream.next().await {
                writer.write(&batch?)?;
            }
            writer.finish()?;
            emit_meta_stderr(&meta)
        }
        Resolved::Csv => {
            let out = io::stdout().lock();
            let mut writer = CsvWriterBuilder::new().with_header(true).build(out);
            while let Some(batch) = stream.next().await {
                writer.write(&batch?)?;
            }
            emit_meta_stderr(&meta)
        }
        Resolved::Json | Resolved::Table => {
            let mut batches = Vec::new();
            while let Some(batch) = stream.next().await {
                batches.push(batch?);
            }
            emit_batches(out, &meta, batches)
        }
    }
}

fn emit_batches(out: &Output, meta: &Meta, batches: Vec<RecordBatch>) -> Result<(), CliError> {
    let format = out.format;
    let mut stdout = io::stdout().lock();
    match format {
        Resolved::Jsonl => {
            let mut writer = LineDelimitedWriter::new(&mut stdout);
            for batch in &batches {
                writer.write(batch)?;
            }
            writer.finish()?;
            drop(stdout);
            emit_meta_stderr(meta)
        }
        Resolved::Csv => {
            let mut writer = CsvWriterBuilder::new().with_header(true).build(&mut stdout);
            for batch in &batches {
                writer.write(batch)?;
            }
            drop(writer);
            drop(stdout);
            emit_meta_stderr(meta)
        }
        Resolved::Json => {
            write!(stdout, "{{\"meta\":")?;
            serde_json::to_writer(&mut stdout, meta)?;
            write!(stdout, ",\"rows\":")?;
            if batches.is_empty() {
                write!(stdout, "[]")?;
            } else {
                let mut writer = ArrayWriter::new(&mut stdout);
                for batch in &batches {
                    writer.write(batch)?;
                }
                writer.finish()?;
            }
            writeln!(stdout, "}}")?;
            Ok(())
        }
        Resolved::Table => {
            let style = Style::detect(out.color);
            writeln!(stdout, "{}", table::render_batches(&style, &batches)?)?;
            drop(stdout);
            emit_meta_stderr_human(out, &style, meta)
        }
    }
}

/// Non-SELECT results arrive as a JSON array of arrays; name the columns.
fn emit_json_rows(out: &Output, meta: &Meta, json: &JsonResult) -> Result<(), CliError> {
    let format = out.format;
    let names: Vec<&str> = json.schema.iter().map(|f| f.name.as_str()).collect();
    let rows: Vec<Value> = json
        .value
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| match row.as_array() {
                    Some(cells) => Value::Object(
                        names
                            .iter()
                            .zip(cells)
                            .map(|(n, c)| ((*n).to_owned(), c.clone()))
                            .collect(),
                    ),
                    None => row.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut stdout = io::stdout().lock();
    match format {
        Resolved::Jsonl => {
            for row in &rows {
                serde_json::to_writer(&mut stdout, row)?;
                stdout.write_all(b"\n")?;
            }
            drop(stdout);
            emit_meta_stderr(meta)
        }
        Resolved::Json => {
            serde_json::to_writer(&mut stdout, &json!({"meta": meta, "rows": rows}))?;
            stdout.write_all(b"\n")?;
            Ok(())
        }
        Resolved::Csv => {
            writeln!(stdout, "{}", names.join(","))?;
            for row in &rows {
                let cells: Vec<String> = names
                    .iter()
                    .map(|n| match row.get(*n) {
                        Some(Value::String(s)) => csv_quote(s),
                        Some(Value::Null) | None => String::new(),
                        Some(other) => csv_quote(&other.to_string()),
                    })
                    .collect();
                writeln!(stdout, "{}", cells.join(","))?;
            }
            drop(stdout);
            emit_meta_stderr(meta)
        }
        Resolved::Table => {
            let style = Style::detect(out.color);
            writeln!(stdout, "{}", table::render_json_rows(&style, &names, &rows))?;
            drop(stdout);
            emit_meta_stderr_human(out, &style, meta)
        }
    }
}

fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// One JSON line of metadata on stderr, so a caller reading stdout as rows
/// still gets the query id.
pub fn emit_meta_stderr(meta: &Meta) -> Result<(), CliError> {
    let mut err = io::stderr().lock();
    serde_json::to_writer(&mut err, meta)?;
    err.write_all(b"\n")?;
    Ok(())
}

/// `N rows, query_id <id>` with the id linking to Snowsight query history
/// when the terminal supports OSC 8 and the account has an org name.
fn emit_meta_stderr_human(out: &Output, style: &Style, meta: &Meta) -> Result<(), CliError> {
    let rows = meta.rows.map_or(String::new(), |n| format!("{n} rows, "));
    let id = match out
        .account
        .as_deref()
        .and_then(|a| table::snowsight_query_url(a, &meta.query_id))
    {
        Some(url) => table::hyperlink(style, &url, &meta.query_id),
        None => meta.query_id.clone(),
    };
    let dim = |t: String| {
        if style.color() {
            format!("\x1b[2m{t}\x1b[0m")
        } else {
            t
        }
    };
    eprintln!("{}", dim(format!("{rows}query_id {id}")));
    Ok(())
}
