//! Spawns the real `firn` binary against a local HTTP server that speaks
//! Snowflake's internal REST shape.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use arrow::array::{Int64Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use base64::Engine;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";

struct Sandbox {
    home: PathBuf,
    state: PathBuf,
    logs: PathBuf,
}

impl Sandbox {
    fn new(server: &MockServer, extra_toml: &str) -> Self {
        let root = std::env::temp_dir().join(format!("firn-cli-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        let state = root.join("state");
        let logs = root.join("logs");
        std::fs::create_dir_all(&home).unwrap();
        let addr = server.address();
        let toml = format!(
            "[dev]\naccount = \"acct\"\nuser = \"alice\"\npassword = \"pw\"\nhost = \"{}\"\nport = {}\nprotocol = \"http\"\nrole = \"analyst\"\n{extra_toml}\n[other]\naccount = \"o\"\nuser = \"u\"\npassword = \"p\"\n",
            addr.ip(),
            addr.port()
        );
        let path = home.join("connections.toml");
        std::fs::write(&path, toml).unwrap();
        std::fs::write(
            home.join("config.toml"),
            "default_connection_name = \"dev\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [&path, &home.join("config.toml")] {
                std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        Self { home, state, logs }
    }

    fn firn(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_firn"))
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("SNOWFLAKE_HOME", &self.home)
            .env("FIRN_STATE_DIR", &self.state)
            .env("FIRN_LOG_DIR", &self.logs)
            .env("FIRN_NO_CACHE", "true")
            .output()
            .unwrap()
    }

    fn session_files(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.state.join("sessions"))
            .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(root) = self.home.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn json_lines(s: &str) -> Vec<Value> {
    s.lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn login_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "sessionId": 1, "token": "sess-1", "masterToken": "master-1",
            "serverVersion": "9.0.0", "parameters": [],
            "sessionInfo": {"databaseName": null, "schemaName": null, "warehouseName": null, "roleName": "ANALYST"},
            "masterValidityInSeconds": 14400, "validityInSeconds": 3600
        },
        "code": null, "message": null, "success": true
    }))
}

fn login_failed() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"authnMethod": "PASSWORD", "errorCode": "390100"},
        "code": "390100", "message": "Incorrect username or password was specified.", "success": false
    }))
}

fn meta(logical: &str, scale: &str, precision: &str) -> std::collections::HashMap<String, String> {
    [
        ("logicalType", logical),
        ("scale", scale),
        ("precision", precision),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

/// Two rows the way Snowflake encodes them: a plain Int64, a nullable text,
/// a `NUMBER(10,2)` as Int16, and a `TIMESTAMP_NTZ(9)` as `{epoch, fraction}`.
fn arrow_rows() -> String {
    use arrow::array::{Int16Array, Int32Array, StructArray};
    let ts_fields = arrow::datatypes::Fields::from(vec![
        Field::new("epoch", DataType::Int64, true),
        Field::new("fraction", DataType::Int32, true),
    ]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("ID", DataType::Int64, false).with_metadata(meta("FIXED", "0", "38")),
        Field::new("NAME", DataType::Utf8, true).with_metadata(meta("TEXT", "0", "38")),
        Field::new("PRICE", DataType::Int16, true).with_metadata(meta("FIXED", "2", "10")),
        Field::new("AT", DataType::Struct(ts_fields.clone()), true).with_metadata(meta(
            "TIMESTAMP_NTZ",
            "9",
            "0",
        )),
    ]));
    let at = StructArray::new(
        ts_fields,
        vec![
            Arc::new(Int64Array::from(vec![Some(1_700_000_000), None])),
            Arc::new(Int32Array::from(vec![Some(500_000_000), None])),
        ],
        Some(vec![true, false].into()),
    );
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec![Some("ann"), None])),
            Arc::new(Int16Array::from(vec![Some(150), Some(-5)])),
            Arc::new(at),
        ],
    )
    .unwrap();
    let mut buf = Vec::new();
    {
        let mut w = arrow::ipc::writer::StreamWriter::try_new(&mut buf, &schema).unwrap();
        w.write(&batch).unwrap();
        w.finish().unwrap();
    }
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn select_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "parameters": [],
            "rowtype": [
                {"name": "ID", "byteLength": null, "length": null, "type": "fixed", "scale": 0, "precision": 38, "nullable": false},
                {"name": "NAME", "byteLength": 16777216, "length": 16777216, "type": "text", "scale": null, "precision": null, "nullable": true},
                {"name": "PRICE", "byteLength": null, "length": null, "type": "fixed", "scale": 2, "precision": 10, "nullable": true},
                {"name": "AT", "byteLength": null, "length": null, "type": "timestamp_ntz", "scale": 9, "precision": 0, "nullable": true}
            ],
            "rowsetBase64": arrow_rows(),
            "total": 2, "returned": 2,
            "queryId": "01b00000-0000-0000-0000-00000000abcd",
            "finalRoleName": "ANALYST", "finalWarehouseName": "WH",
            "statementTypeId": 4096, "version": 1
        },
        "code": null, "message": null, "success": true
    }))
}

fn dml_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "parameters": [],
            "rowtype": [{"name": "number of rows inserted", "byteLength": null, "length": null, "type": "fixed", "scale": 0, "precision": 19, "nullable": false}],
            "rowset": [["3"]],
            "total": 1, "returned": 1,
            "queryId": "01b00000-0000-0000-0000-00000000dddd",
            "finalRoleName": "ANALYST",
            "statementTypeId": 12544, "version": 1
        },
        "code": null, "message": null, "success": true
    }))
}

fn sql_error() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"age": 0, "errorCode": "002003", "internalError": false,
                 "queryId": "01b00000-0000-0000-0000-00000000eeee", "sqlState": "42S02", "line": 1, "pos": 14},
        "code": "002003", "message": "SQL compilation error: Object 'NOPE' does not exist", "success": false
    }))
}

async fn server_with(select: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(select)
        .mount(&server)
        .await;
    server
}

async fn logins(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == LOGIN)
        .count()
}

#[tokio::test]
async fn sql_jsonl_rows_and_meta_and_session_reuse() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");

    let out = sb.firn(&["sql", "SELECT id, name FROM t"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        json_lines(&stdout(&out)),
        vec![
            json!({"ID": 1, "NAME": "ann", "PRICE": 1.5, "AT": "2023-11-14T22:13:20.500"}),
            json!({"ID": 2, "PRICE": -0.05})
        ]
    );
    let meta = json_lines(&stderr(&out));
    assert_eq!(meta.len(), 1, "one meta line on stderr: {}", stderr(&out));
    assert_eq!(meta[0]["query_id"], "01b00000-0000-0000-0000-00000000abcd");
    assert_eq!(meta[0]["rows"], 2);
    assert_eq!(meta[0]["columns"][0]["name"], "ID");
    assert_eq!(meta[0]["columns"][3]["type"], "TIMESTAMPNTZ");
    assert_eq!(meta[0]["warehouse"], "WH");
    assert_eq!(sb.session_files().len(), 1, "session persisted");

    let out = sb.firn(&["sql", "SELECT 1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(logins(&server).await, 1, "second call reuses the session");

    let out = sb.firn(&["--no-session", "sql", "SELECT 1"]);
    assert!(out.status.success());
    assert_eq!(logins(&server).await, 2, "--no-session logs in again");

    let log_file = std::fs::read_dir(&sb.logs)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|x| x == "log"))
        .expect("log file written");
    let log = std::fs::read_to_string(log_file).unwrap();
    assert!(log.contains("restored session"), "{log}");
    assert!(!log.contains("sess-1"), "session token must not be logged");
}

#[tokio::test]
async fn sql_json_csv_and_table_formats() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");

    let out = sb.firn(&["--format", "json", "sql", "SELECT 1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        doc["meta"]["query_id"],
        "01b00000-0000-0000-0000-00000000abcd"
    );
    assert_eq!(
        doc["rows"],
        json!([
            {"ID": 1, "NAME": "ann", "PRICE": 1.5, "AT": "2023-11-14T22:13:20.500"},
            {"ID": 2, "PRICE": -0.05}
        ])
    );

    let out = sb.firn(&["--format", "csv", "sql", "SELECT 1"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        "ID,NAME,PRICE,AT\n1,ann,1.50,2023-11-14T22:13:20.500\n2,,-0.05,\n"
    );

    let out = sb.firn(&["--format", "table", "sql", "SELECT 1"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.starts_with('╭'), "{text}");
    assert!(text.contains("│ ID"), "{text}");
    assert!(text.contains("ann"), "{text}");
    assert!(text.contains("1.50"), "{text}");
    assert!(text.contains("2023-11-14T22:13:20.500"), "{text}");
    assert!(text.contains("NULL"), "{text}");
    assert!(!text.contains('\x1b'), "no escapes when piped: {text}");
    assert!(
        stderr(&out).contains("2 rows, query_id 01b00000"),
        "{}",
        stderr(&out)
    );
}

#[tokio::test]
async fn dml_json_rowset_is_named_by_column() {
    let server = server_with(dml_ok()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["sql", "INSERT INTO t SELECT 1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        json_lines(&stdout(&out)),
        vec![json!({"number of rows inserted": "3"})]
    );
    assert_eq!(json_lines(&stderr(&out))[0]["statement_type"], "Insert");
}

#[tokio::test]
async fn sql_error_exits_4_with_structured_error() {
    let server = server_with(sql_error()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["sql", "SELECT * FROM nope"]);
    assert_eq!(out.status.code(), Some(4));
    let err = json_lines(&stderr(&out));
    assert_eq!(err[0]["error"]["kind"], "query");
    assert_eq!(err[0]["error"]["code"], "002003");
    assert!(err[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("does not exist"));
}

#[tokio::test]
async fn auth_failure_exits_3() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_failed())
        .mount(&server)
        .await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["sql", "SELECT 1"]);
    assert_eq!(out.status.code(), Some(3));
    let err = json_lines(&stderr(&out));
    assert_eq!(err[0]["error"]["kind"], "auth");
    assert_eq!(err[0]["error"]["code"], "390100");
    assert!(sb.session_files().is_empty());
}

#[tokio::test]
async fn missing_connection_exits_2() {
    let server = MockServer::start().await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["-c", "nope", "sql", "SELECT 1"]);
    assert_eq!(out.status.code(), Some(2));
    let msg = json_lines(&stderr(&out))[0]["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(msg.contains("nope") && msg.contains("dev"), "{msg}");
}

#[tokio::test]
async fn binds_and_params_reach_the_wire() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&[
        "sql",
        "SELECT ? , ?, ?",
        "-b",
        "7",
        "-b",
        "'7'",
        "-b",
        "true",
        "-p",
        "query_tag=agent-1",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let reqs = server.received_requests().await.unwrap();
    let q = reqs.iter().find(|r| r.url.path() == QUERY).unwrap();
    let body: Value = q.body_json().unwrap();
    assert_eq!(
        body["bindings"]["1"],
        json!({"type": "FIXED", "value": "7"})
    );
    assert_eq!(body["bindings"]["2"], json!({"type": "TEXT", "value": "7"}));
    assert_eq!(
        body["bindings"]["3"],
        json!({"type": "BOOLEAN", "value": "true"})
    );
    assert_eq!(body["parameters"]["QUERY_TAG"], "agent-1");
    let login = reqs.iter().find(|r| r.url.path() == LOGIN).unwrap();
    assert_eq!(
        login
            .url
            .query_pairs()
            .find(|(k, _)| k == "roleName")
            .map(|(_, v)| v.into_owned()),
        Some("ANALYST".into())
    );
    let login_body: Value = login.body_json().unwrap();
    assert!(login_body["data"]["CLIENT_ENVIRONMENT"]["APPLICATION"]
        .as_str()
        .unwrap()
        .starts_with("firn-cli/"));
}

#[tokio::test]
async fn bind_json_and_rows_reach_the_wire() {
    let server = server_with(dml_ok()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&[
        "sql",
        "INSERT INTO t VALUES (:id, :name)",
        "--bind-json",
        r#"{"id": 7, "name": "ann"}"#,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let rows = sb.home.join("rows.jsonl");
    std::fs::write(&rows, "[1, \"a\"]\n[2, null]\n").unwrap();
    let out = sb.firn(&[
        "sql",
        "INSERT INTO t VALUES (?, ?)",
        "--rows",
        rows.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let reqs = server.received_requests().await.unwrap();
    let bodies: Vec<Value> = reqs
        .iter()
        .filter(|r| r.url.path() == QUERY)
        .map(|r| r.body_json().unwrap())
        .collect();
    assert_eq!(
        bodies[0]["bindings"],
        json!({"id": {"type": "FIXED", "value": "7"}, "name": {"type": "TEXT", "value": "ann"}})
    );
    assert_eq!(bodies.len(), 2, "each statement is sent exactly once");
    assert_eq!(
        bodies[1]["bindings"],
        json!({"1": {"type": "FIXED", "value": ["1", "2"]}, "2": {"type": "TEXT", "value": ["a", null]}})
    );

    let out = sb.firn(&["sql", "SELECT ?", "--bind-json", "not json"]);
    assert_eq!(out.status.code(), Some(2));
}

#[tokio::test]
async fn context_overrides_on_a_restored_session_use_statements() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["sql", "SELECT 1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = sb.firn(&[
        "--database",
        "SANDBOX",
        "--schema",
        "odd name",
        "--role",
        "ADMIN",
        "sql",
        "SELECT 2",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let sqls: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == QUERY)
        .map(|r| {
            r.body_json::<Value>().unwrap()["sqlText"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        sqls,
        vec![
            "SELECT 1",
            "USE ROLE ADMIN",
            "USE DATABASE SANDBOX",
            "USE SCHEMA \"odd name\"",
            "SELECT 2"
        ]
    );
    assert_eq!(logins(&server).await, 1);
}

#[tokio::test]
async fn context_overrides_apply() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["--warehouse", "big", "--role", "admin", "sql", "SELECT 1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let reqs = server.received_requests().await.unwrap();
    let login = reqs.iter().find(|r| r.url.path() == LOGIN).unwrap();
    let pairs: Vec<(String, String)> = login
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(pairs.contains(&("warehouse".into(), "BIG".into())));
    assert!(pairs.contains(&("roleName".into(), "ADMIN".into())));
}

#[tokio::test]
async fn sql_from_stdin_and_file() {
    let server = server_with(select_ok()).await;
    let sb = Sandbox::new(&server, "");
    let file = sb.home.join("q.sql");
    std::fs::write(&file, "SELECT 42\n").unwrap();
    let out = sb.firn(&["sql", "-f", file.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    let mut child = Command::new(env!("CARGO_BIN_EXE_firn"))
        .args(["sql"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("SNOWFLAKE_HOME", &sb.home)
        .env("FIRN_STATE_DIR", &sb.state)
        .env("FIRN_LOG_DIR", &sb.logs)
        .env("FIRN_NO_CACHE", "true")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        child.stdin.take().unwrap().write_all(b"SELECT 43").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let reqs = server.received_requests().await.unwrap();
    let sqls: Vec<String> = reqs
        .iter()
        .filter(|r| r.url.path() == QUERY)
        .map(|r| {
            r.body_json::<Value>().unwrap()["sqlText"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(sqls, vec!["SELECT 42\n".to_owned(), "SELECT 43".to_owned()]);
}

#[tokio::test]
async fn connection_list_show_and_auth_status_logout() {
    let server = server_with(select_ok()).await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": null, "code": null, "message": null, "success": true
        })))
        .mount(&server)
        .await;
    let sb = Sandbox::new(&server, "");

    let out = sb.firn(&["connection", "list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        doc["connections"],
        json!([{"name": "dev", "default": true}, {"name": "other", "default": false}])
    );

    let out = sb.firn(&["connection", "show"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["name"], "dev");
    assert_eq!(doc["password"], "[REDACTED]");
    assert!(!stdout(&out).contains("\"pw\""));

    let out = sb.firn(&["auth", "status"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["session_saved"], false);
    assert_eq!(doc["token_cache"], false);

    let out = sb.firn(&["auth", "login"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["logged_in"], true);
    assert_eq!(doc["session_saved"], true);
    assert_eq!(sb.session_files().len(), 1);

    let out = sb.firn(&["auth", "status"]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["session_saved"], true);

    let out = sb.firn(&["auth", "logout"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["session_closed"], true);
    assert_eq!(doc["session_removed"], true);
    assert!(sb.session_files().is_empty());
    let closes = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/session")
        .count();
    assert_eq!(closes, 1);
}

#[tokio::test]
async fn logs_path_and_help_need_no_connection() {
    let server = MockServer::start().await;
    let sb = Sandbox::new(&server, "");
    let out = sb.firn(&["logs", "path"]);
    assert!(out.status.success());
    assert_eq!(Path::new(stdout(&out).trim()), sb.logs);
    let out = sb.firn(&["--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("firn"));
}
