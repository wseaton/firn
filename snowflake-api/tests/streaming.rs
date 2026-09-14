//! Streaming results, including JSON-shaped (DML) responses.

use arrow_array::cast::AsArray;
use arrow_array::Array;
use firn::{AuthArgs, AuthType, SecretString, SnowflakeApiBuilder};
use futures::StreamExt;
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const QUERY: &str = "/queries/v1/query-request";

#[tokio::test]
async fn dml_result_streams_as_one_utf8_batch_without_re_executing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/session/v1/login-request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "sessionId": 1, "token": "s", "masterToken": "m", "serverVersion": "9",
                "parameters": [],
                "sessionInfo": {"databaseName": null, "schemaName": null, "warehouseName": null, "roleName": "R"},
                "masterValidityInSeconds": 14400, "validityInSeconds": 3600
            },
            "code": null, "message": null, "success": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "parameters": [],
                "rowtype": [
                    {"name": "number of rows inserted", "byteLength": null, "length": null,
                     "type": "fixed", "scale": 0, "precision": 19, "nullable": false},
                    {"name": "note", "byteLength": null, "length": null,
                     "type": "text", "scale": null, "precision": null, "nullable": true}
                ],
                "rowset": [["2", null], ["3", "x"]], "total": 2, "returned": 2,
                "queryId": "01b00000-0000-0000-0000-000000000001",
                "finalRoleName": "R", "statementTypeId": 12544, "version": 1
            },
            "code": null, "message": null, "success": true
        })))
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

    let (metadata, mut stream) = api
        .query("INSERT INTO t VALUES (?)")
        .bind(1_i64)
        .execute_stream()
        .await
        .unwrap();
    assert_eq!(metadata.total_rows, Some(2));
    let batch = stream.next().await.unwrap().unwrap();
    assert!(stream.next().await.is_none());
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(batch.schema().field(0).name(), "number of rows inserted");
    let counts = batch.column(0).as_string::<i32>();
    assert_eq!(counts.value(0), "2");
    assert_eq!(counts.value(1), "3");
    let notes = batch.column(1).as_string::<i32>();
    assert!(notes.is_null(0));
    assert_eq!(notes.value(1), "x");

    let sent = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == QUERY)
        .count();
    assert_eq!(
        sent, 1,
        "a DML statement must never be re-run for streaming"
    );
}
