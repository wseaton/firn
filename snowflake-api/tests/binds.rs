//! Bind parameters as they reach the wire.

use firn::{
    AuthArgs, AuthType, Bind, BindError, SecretString, SnowflakeApiBuilder, SnowflakeApiError,
};
use serde_json::{json, Value};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn login_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "sessionId": 1, "token": "s", "masterToken": "m", "serverVersion": "9",
            "parameters": [],
            "sessionInfo": {"databaseName": null, "schemaName": null, "warehouseName": null, "roleName": "R"},
            "masterValidityInSeconds": 14400, "validityInSeconds": 3600
        },
        "code": null, "message": null, "success": true
    }))
}

fn dml_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "parameters": [],
            "rowtype": [{"name": "number of rows inserted", "byteLength": null, "length": null,
                         "type": "fixed", "scale": 0, "precision": 19, "nullable": false}],
            "rowset": [["2"]], "total": 1, "returned": 1,
            "queryId": "01b00000-0000-0000-0000-000000000001",
            "finalRoleName": "R", "statementTypeId": 12544, "version": 1
        },
        "code": null, "message": null, "success": true
    }))
}

async fn api() -> (MockServer, firn::SnowflakeApi) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/session/v1/login-request"))
        .respond_with(login_ok())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/queries/v1/query-request"))
        .respond_with(dml_ok())
        .mount(&server)
        .await;
    let args = AuthArgs {
        base_url: Some(Url::parse(&format!("{}/", server.uri())).unwrap()),
        ..AuthArgs::new(
            "acct",
            "alice",
            AuthType::Password {
                password: SecretString::from("pw"),
                passcode: None,
            },
        )
    };
    let api = SnowflakeApiBuilder::new(args).build().unwrap();
    (server, api)
}

async fn last_bindings(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    let q = reqs
        .iter()
        .rev()
        .find(|r| r.url.path() == "/queries/v1/query-request")
        .unwrap();
    q.body_json::<Value>().unwrap()["bindings"].clone()
}

#[tokio::test]
async fn positional_binds_are_one_indexed() {
    let (server, api) = api().await;
    api.query("INSERT INTO t VALUES (?, ?, ?)")
        .bind(7_i64)
        .bind("x")
        .bind(Bind::null("REAL"))
        .execute()
        .await
        .unwrap();
    assert_eq!(
        last_bindings(&server).await,
        json!({
            "1": {"type": "FIXED", "value": "7"},
            "2": {"type": "TEXT", "value": "x"},
            "3": {"type": "REAL", "value": null}
        })
    );
}

#[tokio::test]
async fn named_binds_use_the_placeholder_name() {
    let (server, api) = api().await;
    api.query("INSERT INTO t VALUES (:id, :label)")
        .bind_named("id", 7_i64)
        .bind_named("label", Bind::text("x"))
        .execute()
        .await
        .unwrap();
    assert_eq!(
        last_bindings(&server).await,
        json!({
            "id": {"type": "FIXED", "value": "7"},
            "label": {"type": "TEXT", "value": "x"}
        })
    );
}

#[tokio::test]
async fn mixing_named_and_positional_is_rejected_before_sending() {
    let (server, api) = api().await;
    let err = api
        .query("INSERT INTO t VALUES (:id, ?)")
        .bind_named("id", 7_i64)
        .bind("x")
        .execute()
        .await
        .err()
        .expect("mixed binds must fail");
    assert!(matches!(
        err,
        SnowflakeApiError::BindError(BindError::Mixed)
    ));
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| r.url.path() != "/queries/v1/query-request"));
}

#[tokio::test]
async fn array_binds_send_a_column_per_placeholder() {
    let (server, api) = api().await;
    let ids = Bind::array([Bind::fixed(1), Bind::null("FIXED"), Bind::fixed(3)]).unwrap();
    let names = Bind::array(["a", "b", "c"].map(Bind::text)).unwrap();
    assert!(ids.is_array());
    api.query("INSERT INTO t VALUES (?, ?)")
        .bind(ids)
        .bind(names)
        .execute()
        .await
        .unwrap();
    assert_eq!(
        last_bindings(&server).await,
        json!({
            "1": {"type": "FIXED", "value": ["1", null, "3"]},
            "2": {"type": "TEXT", "value": ["a", "b", "c"]}
        })
    );
}

#[test]
fn array_bind_validation() {
    assert_eq!(
        Bind::array([Bind::fixed(1), Bind::text("x")]).err(),
        Some(BindError::MixedArrayTypes {
            expected: "FIXED",
            got: "TEXT"
        })
    );
    assert_eq!(Bind::array([]).err(), Some(BindError::EmptyArray));
    let inner = Bind::array([Bind::fixed(1)]).unwrap();
    assert_eq!(Bind::array([inner]).err(), Some(BindError::NestedArray));
}

#[test]
fn temporal_and_binary_binds_use_gosnowflake_encodings() {
    let wire = |b: Bind| serde_json::to_value(b).unwrap();
    assert_eq!(
        wire(Bind::binary(b"\x7a\xff")),
        json!({"type": "BINARY", "value": "7aff"})
    );
    assert_eq!(
        wire(Bind::date_millis(1_700_000_000_000)),
        json!({"type": "DATE", "value": "1700000000000"})
    );
    assert_eq!(
        wire(Bind::time_nanos(3_600_000_000_000)),
        json!({"type": "TIME", "value": "3600000000000"})
    );
    assert_eq!(
        wire(Bind::timestamp_ntz_nanos(1_700_000_000_000_000_000)),
        json!({"type": "TIMESTAMP_NTZ", "value": "1700000000000000000"})
    );
    assert_eq!(
        wire(Bind::timestamp_ltz_nanos(5)),
        json!({"type": "TIMESTAMP_LTZ", "value": "5"})
    );
    assert_eq!(
        wire(Bind::timestamp_tz_nanos(5, -300)),
        json!({"type": "TIMESTAMP_TZ", "value": "5 1140"})
    );
    assert_eq!(Bind::fixed(1).named("n").name(), Some("n"));
    assert_eq!(Bind::real(1.5).type_name(), "REAL");
}
