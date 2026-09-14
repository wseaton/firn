//! Terminal table rendering: rounded Unicode borders, columns fitted to the
//! terminal width, numbers right-aligned, NULLs dimmed. Styling is only
//! emitted on a TTY without `NO_COLOR`, so piped output stays plain.

use std::io::IsTerminal;

use arrow::array::{Array, RecordBatch};
use arrow::datatypes::DataType;
use arrow::util::display::{ArrayFormatter, FormatOptions};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};
use serde_json::Value;

use crate::error::CliError;

const NULL: &str = "NULL";
const MIN_WIDTH: u16 = 40;
const FALLBACK_WIDTH: u16 = 120;

/// One rendered cell before styling.
struct CellValue {
    text: String,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Null,
    Number,
    Bool,
    Temporal,
    Text,
}

pub struct Style {
    color: bool,
}

impl Style {
    /// Colors and attributes only when stdout is a terminal and `NO_COLOR`
    /// is unset.
    pub fn detect() -> Self {
        Self {
            color: std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
        }
    }

    #[cfg(test)]
    pub fn plain() -> Self {
        Self { color: false }
    }

    pub fn color(&self) -> bool {
        self.color
    }
}

fn base_table(style: &Style, headers: &[String]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    if !style.color {
        table.force_no_tty();
    }
    // A pty with no size (CI, some multiplexers) reports 0 columns, which
    // Dynamic arrangement would squeeze to one character per column.
    if table.width().is_none_or(|w| w < MIN_WIDTH) {
        table.set_width(FALLBACK_WIDTH);
    }
    table.set_header(headers.iter().map(|h| {
        let cell = Cell::new(h);
        if style.color {
            cell.add_attribute(Attribute::Bold).fg(Color::Cyan)
        } else {
            cell
        }
    }));
    table
}

fn styled(style: &Style, value: CellValue) -> Cell {
    let mut cell = Cell::new(&value.text);
    if matches!(value.kind, Kind::Number | Kind::Null) {
        cell = cell.set_alignment(CellAlignment::Right);
    }
    if !style.color {
        return cell;
    }
    match value.kind {
        Kind::Null => cell.add_attribute(Attribute::Dim),
        Kind::Number => cell.fg(Color::Yellow),
        Kind::Bool => cell.fg(if value.text == "true" {
            Color::Green
        } else {
            Color::Red
        }),
        Kind::Temporal => cell.fg(Color::Magenta),
        Kind::Text => cell,
    }
}

fn kind_of(dt: &DataType) -> Kind {
    match dt {
        DataType::Boolean => Kind::Bool,
        dt if dt.is_numeric() => Kind::Number,
        dt if dt.is_temporal() => Kind::Temporal,
        _ => Kind::Text,
    }
}

/// Render Arrow batches. Returns the table text without a trailing newline.
pub fn render_batches(style: &Style, batches: &[RecordBatch]) -> Result<String, CliError> {
    let Some(first) = batches.first() else {
        return Ok("(no rows)".to_owned());
    };
    let headers: Vec<String> = first
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();
    let mut table = base_table(style, &headers);
    let options = FormatOptions::default().with_null(NULL);

    for batch in batches {
        let formatters = batch
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c.as_ref(), &options))
            .collect::<Result<Vec<_>, _>>()?;
        let kinds: Vec<Kind> = batch
            .columns()
            .iter()
            .map(|c| kind_of(c.data_type()))
            .collect();
        for row in 0..batch.num_rows() {
            let cells =
                formatters
                    .iter()
                    .zip(&kinds)
                    .zip(batch.columns())
                    .map(|((f, kind), column)| {
                        let value = if column.is_null(row) {
                            CellValue {
                                text: NULL.to_owned(),
                                kind: Kind::Null,
                            }
                        } else {
                            CellValue {
                                text: f.value(row).to_string(),
                                kind: *kind,
                            }
                        };
                        styled(style, value)
                    });
            table.add_row(cells);
        }
    }
    Ok(table.to_string())
}

/// Render JSON rows (DML / DDL results, PUT / GET) keyed by column name.
pub fn render_json_rows(style: &Style, names: &[&str], rows: &[Value]) -> String {
    let headers: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let mut table = base_table(style, &headers);
    for row in rows {
        table.add_row(names.iter().map(|n| {
            let value = match row.get(*n) {
                Some(Value::Null) | None => CellValue {
                    text: NULL.to_owned(),
                    kind: Kind::Null,
                },
                Some(Value::Bool(b)) => CellValue {
                    text: b.to_string(),
                    kind: Kind::Bool,
                },
                Some(Value::Number(n)) => CellValue {
                    text: n.to_string(),
                    kind: Kind::Number,
                },
                Some(Value::String(s)) => CellValue {
                    kind: if s.parse::<f64>().is_ok() {
                        Kind::Number
                    } else {
                        Kind::Text
                    },
                    text: s.clone(),
                },
                Some(other) => CellValue {
                    text: other.to_string(),
                    kind: Kind::Text,
                },
            };
            styled(style, value)
        }));
    }
    table.to_string()
}

/// OSC 8 hyperlink when the terminal can show one, plain text otherwise.
pub fn hyperlink(style: &Style, url: &str, text: &str) -> String {
    if style.color && std::io::stderr().is_terminal() {
        format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
    } else {
        text.to_owned()
    }
}

/// Snowsight query-history URL for an `org-account` identifier. Legacy
/// locator accounts (`xy12345`) have no org part and get no link.
pub fn snowsight_query_url(account_identifier: &str, query_id: &str) -> Option<String> {
    let (org, account) = account_identifier.split_once('-')?;
    if org.is_empty() || account.is_empty() {
        return None;
    }
    Some(format!(
        "https://app.snowflake.com/{}/{}/#/compute/history/queries/{query_id}/detail",
        org.to_lowercase(),
        account.to_lowercase()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Float64Array, Int64Array, StringArray};
    use arrow::datatypes::{Field, Schema};
    use std::sync::Arc;

    #[test]
    fn plain_table_has_unicode_borders_and_right_aligned_numbers() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("ID", DataType::Int64, false),
            Field::new("NAME", DataType::Utf8, true),
            Field::new("X", DataType::Float64, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![1, 22])),
                Arc::new(StringArray::from(vec![Some("ann"), None])),
                Arc::new(Float64Array::from(vec![Some(1.5), None])),
            ],
        )
        .unwrap();
        let text = render_batches(&Style::plain(), &[batch]).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with('╭'), "{text}");
        assert!(lines[1].contains("│ ID"), "{text}");
        assert!(text.contains("│  1 ┆"), "numbers right-aligned: {text}");
        assert!(text.contains("│ 22 ┆"), "{text}");
        assert!(text.contains("┆  1.5 │"), "{text}");
        assert!(text.contains("NULL"), "{text}");
        assert!(!text.contains('\x1b'), "no escapes when plain");
        assert!(lines.last().unwrap().starts_with('╰'), "{text}");
    }

    #[test]
    fn json_rows_table_and_empty_batches() {
        let rows = vec![serde_json::json!({"status": "ok", "n": "3"})];
        let text = render_json_rows(&Style::plain(), &["status", "n"], &rows);
        assert!(text.contains("status"));
        assert!(text.contains("ok"));
        assert_eq!(render_batches(&Style::plain(), &[]).unwrap(), "(no rows)");
    }

    #[test]
    fn snowsight_url_only_for_org_accounts() {
        assert_eq!(
            snowsight_query_url("GDADCLC-RHSANDBOX", "01c7-abc").as_deref(),
            Some("https://app.snowflake.com/gdadclc/rhsandbox/#/compute/history/queries/01c7-abc/detail")
        );
        assert_eq!(snowsight_query_url("HNB22701", "q"), None);
        assert_eq!(snowsight_query_url("-x", "q"), None);
    }

    #[test]
    fn hyperlink_is_plain_without_color() {
        assert_eq!(hyperlink(&Style::plain(), "https://x", "id"), "id");
    }
}
