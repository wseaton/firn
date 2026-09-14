//! Login flows against a local HTTP server that speaks Snowflake's internal
//! REST shape. Exercises the public API only: what a CLI would call.

use std::sync::Arc;

use firn::{
    AuthArgs, AuthType, CredentialKey, CredentialKind, MemoryTokenCache, SecretString,
    SnowflakeApi, SnowflakeApiBuilder, SnowflakeApiError, TokenCache,
};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use url::Url;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";
const RENEW: &str = "/session/token-request";

// Tests that touch process env serialize on this.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn login_ok(session: &str, master: &str, extra: Value) -> ResponseTemplate {
    let mut data = json!({
        "sessionId": 1,
        "token": session,
        "masterToken": master,
        "serverVersion": "9.0.0",
        "parameters": [],
        "sessionInfo": {"databaseName": null, "schemaName": null, "warehouseName": null, "roleName": "PUBLIC"},
        "masterValidityInSeconds": 14400,
        "validityInSeconds": 3600
    });
    if let (Some(base), Some(add)) = (data.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }
    ResponseTemplate::new(200).set_body_json(json!({
        "data": data, "code": null, "message": null, "success": true
    }))
}

fn login_failed(code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"authnMethod": "PASSWORD", "errorCode": code},
        "code": code, "message": message, "success": false
    }))
}

fn query_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "parameters": [],
            "rowtype": [{"name": "1", "byteLength": null, "length": null, "type": "fixed",
                         "scale": 0, "precision": 1, "nullable": false}],
            "rowset": [["1"]],
            "total": 1,
            "returned": 1,
            "queryId": "01b00000-0000-0000-0000-000000000001",
            "finalRoleName": "PUBLIC",
            "statementTypeId": 4096,
            "version": 1
        },
        "code": null, "message": null, "success": true
    }))
}

fn query_error(code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"age": 0, "errorCode": code, "internalError": false, "queryId": null, "sqlState": "08001"},
        "code": code, "message": message, "success": false
    }))
}

fn renew_ok(session: &str, master: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"sessionToken": session, "validityInSecondsST": 3600,
                 "masterToken": master, "validityInSecondsMT": 14400, "sessionId": 1},
        "code": null, "message": null, "success": true
    }))
}

fn base_url(server: &MockServer) -> Url {
    Url::parse(&format!("{}/", server.uri())).unwrap()
}

fn args(server: &MockServer, auth_type: AuthType) -> AuthArgs {
    AuthArgs {
        account_identifier: "myorg-myacct".into(),
        warehouse: Some("wh".into()),
        database: Some("db".into()),
        schema: Some("sch".into()),
        username: "alice".into(),
        role: Some("analyst".into()),
        auth_type,
        base_url: Some(base_url(server)),
    }
}

fn password(pw: &str) -> AuthType {
    AuthType::Password {
        password: SecretString::from(pw),
        passcode: None,
    }
}

async fn requests_to(server: &MockServer, p: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}

fn body(req: &Request) -> Value {
    req.body_json::<Value>().unwrap()
}

fn auth_header(req: &Request) -> String {
    req.headers
        .get("authorization")
        .expect("authorization header")
        .to_str()
        .unwrap()
        .to_owned()
}

fn query_param(req: &Request, key: &str) -> Option<String> {
    req.url
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
async fn password_login_body_and_session_token_reuse() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-1", "master-1", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let api = SnowflakeApiBuilder::new(args(&server, password("hunter2")))
        .build()
        .unwrap();
    api.exec("SELECT 1").await.unwrap();
    api.exec("SELECT 1").await.unwrap();

    let logins = requests_to(&server, LOGIN).await;
    assert_eq!(logins.len(), 1, "second query must reuse the session");
    let login = &logins[0];
    let data = &body(login)["data"];
    assert_eq!(data["ACCOUNT_NAME"], "MYORG-MYACCT");
    assert_eq!(data["LOGIN_NAME"], "ALICE");
    assert_eq!(data["PASSWORD"], "hunter2");
    assert!(data.get("AUTHENTICATOR").is_none());
    assert!(data.get("PASSCODE").is_none());
    assert!(data.get("TOKEN").is_none());
    assert_eq!(
        data["SESSION_PARAMETERS"],
        json!({"CLIENT_VALIDATE_DEFAULT_PARAMETERS": true})
    );
    assert_eq!(data["CLIENT_ENVIRONMENT"]["APPLICATION"], "firn");
    assert_eq!(query_param(login, "warehouse").as_deref(), Some("WH"));
    assert_eq!(query_param(login, "databaseName").as_deref(), Some("DB"));
    assert_eq!(query_param(login, "schemaName").as_deref(), Some("SCH"));
    assert_eq!(query_param(login, "roleName").as_deref(), Some("ANALYST"));
    assert!(query_param(login, "requestId").is_some());

    let queries = requests_to(&server, QUERY).await;
    assert_eq!(queries.len(), 2);
    for q in &queries {
        assert_eq!(auth_header(q), "Snowflake Token=\"sess-1\"");
    }
    assert_eq!(body(&queries[0])["sequenceId"], 1);
    assert_eq!(body(&queries[1])["sequenceId"], 2);
}

#[tokio::test]
async fn password_with_passcode_sets_duo_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("s", "m", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let auth = AuthType::Password {
        password: SecretString::from("pw"),
        passcode: Some(SecretString::from("123456")),
    };
    SnowflakeApiBuilder::new(args(&server, auth))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();

    let data = body(&requests_to(&server, LOGIN).await[0])["data"].clone();
    assert_eq!(data["PASSCODE"], "123456");
    assert_eq!(data["EXT_AUTHN_DUO_METHOD"], "passcode");
}

#[tokio::test]
async fn pat_and_oauth_login_bodies() {
    for (auth, wire) in [
        (
            AuthType::ProgrammaticAccessToken {
                token: SecretString::from("pat-token"),
            },
            "PROGRAMMATIC_ACCESS_TOKEN",
        ),
        (
            AuthType::OAuth {
                token: SecretString::from("pat-token"),
            },
            "OAUTH",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .respond_with(login_ok("s", "m", json!({})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(QUERY))
            .respond_with(query_ok())
            .mount(&server)
            .await;

        SnowflakeApiBuilder::new(args(&server, auth))
            .build()
            .unwrap()
            .exec("SELECT 1")
            .await
            .unwrap();

        let data = body(&requests_to(&server, LOGIN).await[0])["data"].clone();
        assert_eq!(data["AUTHENTICATOR"], wire);
        assert_eq!(data["TOKEN"], "pat-token");
        assert_eq!(data["LOGIN_NAME"], "ALICE");
        assert!(data.get("PASSWORD").is_none());
    }
}

#[tokio::test]
async fn auth_failure_is_reported_with_code() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_failed(
            "390100",
            "Incorrect username or password was specified.",
        ))
        .mount(&server)
        .await;

    let err = SnowflakeApiBuilder::new(args(&server, password("wrong")))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .err()
        .expect("login must fail");
    let msg = err.to_string();
    assert!(msg.contains("390100"), "{msg}");
    assert!(matches!(err, SnowflakeApiError::AuthError(_)));
}

fn mfa(passcode: Option<&str>) -> AuthType {
    AuthType::UsernamePasswordMfa {
        password: SecretString::from("pw"),
        passcode: passcode.map(SecretString::from),
    }
}

fn mfa_key(server: &MockServer) -> CredentialKey {
    CredentialKey::new(
        base_url(server).host_str().unwrap(),
        "alice",
        CredentialKind::MfaToken,
    )
    .unwrap()
}

#[tokio::test]
async fn mfa_caches_token_and_replays_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(json!({"data": {"PASSCODE": "111111"}})))
        .respond_with(login_ok(
            "s1",
            "m1",
            json!({"mfaToken": "mfa-cached", "mfaTokenValidityInSeconds": 3600}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(json!({"data": {"TOKEN": "mfa-cached"}})))
        .respond_with(login_ok("s2", "m2", json!({"mfaToken": "mfa-rotated"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let cache: Arc<dyn TokenCache> = Arc::new(MemoryTokenCache::new());

    // First process: passcode login, token cached.
    SnowflakeApiBuilder::new(args(&server, mfa(Some("111111"))))
        .with_token_cache(Arc::clone(&cache))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();
    let first = body(&requests_to(&server, LOGIN).await[0])["data"].clone();
    assert_eq!(first["AUTHENTICATOR"], "USERNAME_PASSWORD_MFA");
    assert_eq!(first["PASSWORD"], "pw");
    assert_eq!(first["PASSCODE"], "111111");
    assert_eq!(first["EXT_AUTHN_DUO_METHOD"], "passcode");
    assert_eq!(
        first["SESSION_PARAMETERS"]["CLIENT_REQUEST_MFA_TOKEN"],
        true
    );
    assert!(first.get("TOKEN").is_none());
    assert_eq!(
        cache
            .get(&mfa_key(&server))
            .unwrap()
            .unwrap()
            .expose_secret(),
        "mfa-cached"
    );

    // Second process: no passcode available, cached token replayed and rotated.
    SnowflakeApiBuilder::new(args(&server, mfa(None)))
        .with_token_cache(Arc::clone(&cache))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();
    let logins = requests_to(&server, LOGIN).await;
    assert_eq!(logins.len(), 2);
    let second = body(&logins[1])["data"].clone();
    assert_eq!(second["TOKEN"], "mfa-cached");
    assert_eq!(second["PASSWORD"], "pw");
    assert!(second.get("PASSCODE").is_none());
    assert_eq!(
        cache
            .get(&mfa_key(&server))
            .unwrap()
            .unwrap()
            .expose_secret(),
        "mfa-rotated"
    );
}

#[tokio::test]
async fn rejected_mfa_token_is_dropped_and_passcode_login_follows() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(json!({"data": {"TOKEN": "stale"}})))
        .respond_with(login_failed("390195", "MFA token is invalid"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(json!({"data": {"PASSCODE": "222222"}})))
        .respond_with(login_ok("s", "m", json!({"mfaToken": "fresh"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let cache: Arc<dyn TokenCache> = Arc::new(MemoryTokenCache::new());
    cache
        .set(&mfa_key(&server), &SecretString::from("stale"))
        .unwrap();

    SnowflakeApiBuilder::new(args(&server, mfa(Some("222222"))))
        .with_token_cache(Arc::clone(&cache))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();

    let logins = requests_to(&server, LOGIN).await;
    assert_eq!(logins.len(), 2);
    assert_eq!(body(&logins[0])["data"]["TOKEN"], "stale");
    assert_eq!(body(&logins[1])["data"]["PASSCODE"], "222222");
    assert!(body(&logins[1])["data"].get("TOKEN").is_none());
    assert_eq!(
        cache
            .get(&mfa_key(&server))
            .unwrap()
            .unwrap()
            .expose_secret(),
        "fresh"
    );
}

#[tokio::test]
async fn without_a_cache_mfa_never_requests_a_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("s", "m", json!({"mfaToken": "ignored"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    SnowflakeApiBuilder::new(args(&server, mfa(Some("333333"))))
        .build()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();
    let data = body(&requests_to(&server, LOGIN).await[0])["data"].clone();
    assert!(data["SESSION_PARAMETERS"]
        .get("CLIENT_REQUEST_MFA_TOKEN")
        .is_none());
}

#[cfg(feature = "browser-auth")]
mod browser {
    use super::*;

    const AUTHENTICATOR: &str = "/session/authenticator-request";

    fn id_key(server: &MockServer) -> CredentialKey {
        CredentialKey::new(
            base_url(server).host_str().unwrap(),
            "alice",
            CredentialKind::IdToken,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn cached_id_token_logs_in_without_a_browser() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .and(body_partial_json(
                json!({"data": {"AUTHENTICATOR": "ID_TOKEN", "TOKEN": "id-1"}}),
            ))
            .respond_with(login_ok("s", "m", json!({"idToken": "id-2"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(QUERY))
            .respond_with(query_ok())
            .mount(&server)
            .await;

        let cache: Arc<dyn TokenCache> = Arc::new(MemoryTokenCache::new());
        cache
            .set(&id_key(&server), &SecretString::from("id-1"))
            .unwrap();

        SnowflakeApiBuilder::new(args(&server, AuthType::ExternalBrowser))
            .with_token_cache(Arc::clone(&cache))
            .build()
            .unwrap()
            .exec("SELECT 1")
            .await
            .unwrap();

        assert!(requests_to(&server, AUTHENTICATOR).await.is_empty());
        let data = body(&requests_to(&server, LOGIN).await[0])["data"].clone();
        assert_eq!(data["AUTHENTICATOR"], "ID_TOKEN");
        assert_eq!(data["TOKEN"], "id-1");
        assert_eq!(data["LOGIN_NAME"], "ALICE");
        assert_eq!(
            data["SESSION_PARAMETERS"]["CLIENT_STORE_TEMPORARY_CREDENTIAL"],
            true
        );
        assert_eq!(
            cache
                .get(&id_key(&server))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "id-2"
        );
    }

    #[tokio::test]
    async fn rejected_id_token_is_dropped_before_the_browser_flow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .respond_with(login_failed("390195", "ID token expired"))
            .mount(&server)
            .await;
        // The browser flow starts with authenticator-request; fail it so the
        // test never opens a real browser.
        Mock::given(method("POST"))
            .and(path(AUTHENTICATOR))
            .respond_with(login_failed("390144", "no sso"))
            .mount(&server)
            .await;

        let cache: Arc<dyn TokenCache> = Arc::new(MemoryTokenCache::new());
        cache
            .set(&id_key(&server), &SecretString::from("expired"))
            .unwrap();

        let err = SnowflakeApiBuilder::new(args(&server, AuthType::ExternalBrowser))
            .with_token_cache(Arc::clone(&cache))
            .build()
            .unwrap()
            .exec("SELECT 1")
            .await
            .err()
            .expect("login must fail");
        assert!(err.to_string().contains("390144"), "{err}");

        assert!(cache.get(&id_key(&server)).unwrap().is_none());
        let auth_req = body(&requests_to(&server, AUTHENTICATOR).await[0])["data"].clone();
        assert_eq!(auth_req["AUTHENTICATOR"], "EXTERNALBROWSER");
        assert!(auth_req["PROOF_KEY"]
            .as_str()
            .is_some_and(|k| !k.is_empty()));
        assert!(auth_req["BROWSER_MODE_REDIRECT_PORT"]
            .as_str()
            .is_some_and(|p| p.parse::<u16>().is_ok()));
    }

    #[tokio::test]
    async fn clear_cached_credentials_removes_id_and_mfa_tokens() {
        let server = MockServer::start().await;
        let cache: Arc<dyn TokenCache> = Arc::new(MemoryTokenCache::new());
        cache
            .set(&id_key(&server), &SecretString::from("id"))
            .unwrap();
        cache
            .set(&mfa_key(&server), &SecretString::from("mfa"))
            .unwrap();
        let api = SnowflakeApiBuilder::new(args(&server, AuthType::ExternalBrowser))
            .with_token_cache(Arc::clone(&cache))
            .build()
            .unwrap();
        api.clear_cached_credentials().unwrap();
        assert!(cache.get(&id_key(&server)).unwrap().is_none());
        assert!(cache.get(&mfa_key(&server)).unwrap().is_none());
    }
}

#[tokio::test]
async fn session_snapshot_carries_tokens_to_a_new_process() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-1", "master-1", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let first = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .build()
        .unwrap();
    assert!(
        first.session_snapshot().is_none(),
        "no session before login"
    );
    first.exec("SELECT 1").await.unwrap();
    let snapshot = first.session_snapshot().expect("snapshot after login");
    assert_eq!(snapshot.user(), "ALICE");
    assert_eq!(snapshot.host(), base_url(&server).host_str().unwrap());
    assert!(!snapshot.is_expired());
    assert!(!format!("{snapshot:?}").contains("sess-1"));

    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: firn::SessionSnapshot = serde_json::from_str(&json).unwrap();

    let second = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .with_session_snapshot(restored)
        .build()
        .unwrap();
    second.exec("SELECT 1").await.unwrap();

    assert_eq!(requests_to(&server, LOGIN).await.len(), 1);
    let queries = requests_to(&server, QUERY).await;
    assert_eq!(queries.len(), 2);
    assert_eq!(auth_header(&queries[1]), "Snowflake Token=\"sess-1\"");
    assert_eq!(body(&queries[1])["sequenceId"], 2, "sequence continues");
}

#[tokio::test]
async fn snapshot_for_another_user_is_ignored() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-1", "master-1", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let alice = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .build()
        .unwrap();
    alice.exec("SELECT 1").await.unwrap();
    let snapshot = alice.session_snapshot().unwrap();

    let mut bob_args = args(&server, password("pw"));
    bob_args.username = "bob".into();
    let bob = SnowflakeApiBuilder::new(bob_args)
        .with_session_snapshot(snapshot)
        .build()
        .unwrap();
    bob.exec("SELECT 1").await.unwrap();

    let logins = requests_to(&server, LOGIN).await;
    assert_eq!(logins.len(), 2);
    assert_eq!(body(&logins[1])["data"]["LOGIN_NAME"], "BOB");
}

#[tokio::test]
async fn expired_session_mid_query_is_renewed_and_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-1", "master-1", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_error("390112", "Session token has expired"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(RENEW))
        .respond_with(renew_ok("sess-2", "master-2"))
        .mount(&server)
        .await;

    let api = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .build()
        .unwrap();
    api.exec("SELECT 1").await.unwrap();

    let renews = requests_to(&server, RENEW).await;
    assert_eq!(renews.len(), 1);
    assert_eq!(auth_header(&renews[0]), "Snowflake Token=\"master-1\"");
    assert_eq!(body(&renews[0])["oldSessionToken"], "sess-1");
    assert_eq!(body(&renews[0])["requestType"], "RENEW");

    let queries = requests_to(&server, QUERY).await;
    assert_eq!(queries.len(), 2);
    assert_eq!(auth_header(&queries[0]), "Snowflake Token=\"sess-1\"");
    assert_eq!(auth_header(&queries[1]), "Snowflake Token=\"sess-2\"");
    assert_eq!(requests_to(&server, LOGIN).await.len(), 1);
}

#[tokio::test]
async fn rejected_renew_falls_back_to_a_fresh_login() {
    // A snapshot from a previous process whose server-side session has been
    // killed: the query gets 390112, the renew is refused, so log in again.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-1", "master-1", json!({})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;
    let seed = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .build()
        .unwrap();
    seed.exec("SELECT 1").await.unwrap();
    let snapshot = seed.session_snapshot().unwrap();
    server.reset().await;

    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("sess-2", "master-2", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .and(header("authorization", "Snowflake Token=\"sess-1\""))
        .respond_with(query_error("390112", "Session token has expired"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .and(header("authorization", "Snowflake Token=\"sess-2\""))
        .respond_with(query_ok())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(RENEW))
        .respond_with(login_failed("390104", "Session no longer exists"))
        .mount(&server)
        .await;

    let api = SnowflakeApiBuilder::new(args(&server, password("pw")))
        .with_session_snapshot(snapshot)
        .build()
        .unwrap();
    api.exec("SELECT 1").await.unwrap();

    assert_eq!(requests_to(&server, RENEW).await.len(), 1);
    assert_eq!(requests_to(&server, LOGIN).await.len(), 1);
    let queries = requests_to(&server, QUERY).await;
    assert_eq!(queries.len(), 2);
    assert_eq!(auth_header(&queries[1]), "Snowflake Token=\"sess-2\"");
    assert_eq!(
        body(&queries[0])["sequenceId"],
        2,
        "continues the snapshot's ids"
    );
}

#[cfg(feature = "browser-auth")]
#[tokio::test]
async fn sso_url_handler_replaces_the_browser() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/session/authenticator-request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"tokenUrl": null, "ssoUrl": "https://idp.example/sso?x=1", "proofKey": "pk"},
            "code": null, "message": null, "success": true
        })))
        .mount(&server)
        .await;

    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let handler: firn::SsoUrlHandler = Arc::new(move |url: &str| {
        sink.lock().unwrap().push(url.to_owned());
    });
    let api = SnowflakeApiBuilder::new(args(&server, AuthType::ExternalBrowser))
        .with_sso_url_handler(handler)
        .with_login_timeout(std::time::Duration::from_millis(300))
        .build()
        .unwrap();
    // Nobody completes the SSO, so the login times out; the handler must
    // still have been called with the URL and no browser opened.
    let err = api
        .exec("SELECT 1")
        .await
        .err()
        .expect("no callback arrives");
    assert!(err.to_string().contains("timed out"), "{err}");
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["https://idp.example/sso?x=1"]
    );
}

struct EnvGuard(Vec<(String, Option<String>)>);

impl EnvGuard {
    fn set(vars: &[(&str, Option<String>)]) -> Self {
        let saved = vars
            .iter()
            .map(|(k, v)| {
                let old = std::env::var(k).ok();
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
                ((*k).to_owned(), old)
            })
            .collect();
        Self(saved)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, old) in self.0.drain(..) {
            match old {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }
}

#[tokio::test]
async fn from_env_honours_host_port_and_protocol() {
    let _l = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("s", "m", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let addr = server.address();
    let _env = EnvGuard::set(&[
        ("SNOWFLAKE_ACCOUNT", Some("envacct".into())),
        ("SNOWFLAKE_USER", Some("envuser".into())),
        ("SNOWFLAKE_PASSWORD", Some("envpw".into())),
        ("SNOWFLAKE_HOST", Some(addr.ip().to_string())),
        ("SNOWFLAKE_PORT", Some(addr.port().to_string())),
        ("SNOWFLAKE_PROTOCOL", Some("http".into())),
        ("SNOWFLAKE_WAREHOUSE", Some("envwh".into())),
        ("SNOWFLAKE_AUTHENTICATOR", None),
        ("SNOWFLAKE_TOKEN", None),
        ("SNOWFLAKE_PRIVATE_KEY", None),
    ]);

    SnowflakeApi::from_env()
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();
    let login = &requests_to(&server, LOGIN).await[0];
    assert_eq!(body(login)["data"]["ACCOUNT_NAME"], "ENVACCT");
    assert_eq!(body(login)["data"]["LOGIN_NAME"], "ENVUSER");
    assert_eq!(query_param(login, "warehouse").as_deref(), Some("ENVWH"));
}

#[tokio::test]
async fn from_connection_reads_connections_toml_under_snowflake_home() {
    let _l = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(login_ok("s", "m", json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(QUERY))
        .respond_with(query_ok())
        .mount(&server)
        .await;

    let home = std::env::temp_dir().join(format!("firn-home-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let addr = server.address();
    let toml = format!(
        "[ci]\naccount = \"tomlacct\"\nuser = \"tomluser\"\nauthenticator = \"programmatic_access_token\"\ntoken = \"pat-1\"\nhost = \"{}\"\nport = {}\nprotocol = \"http\"\nrole = \"tomlrole\"\n",
        addr.ip(),
        addr.port()
    );
    let path = home.join("connections.toml");
    std::fs::write(&path, toml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let _env = EnvGuard::set(&[
        ("SNOWFLAKE_HOME", Some(home.to_string_lossy().into_owned())),
        ("SNOWFLAKE_DEFAULT_CONNECTION_NAME", Some("ci".into())),
        ("SNOWFLAKE_ACCOUNT", None),
        ("SNOWFLAKE_USER", None),
        ("SNOWFLAKE_PASSWORD", None),
        ("SNOWFLAKE_HOST", None),
        ("SNOWFLAKE_PORT", None),
        ("SNOWFLAKE_PROTOCOL", None),
        ("SNOWFLAKE_WAREHOUSE", None),
        ("SNOWFLAKE_AUTHENTICATOR", None),
        ("SNOWFLAKE_TOKEN", None),
        ("SNOWFLAKE_PRIVATE_KEY", None),
    ]);

    SnowflakeApi::from_connection(None)
        .unwrap()
        .exec("SELECT 1")
        .await
        .unwrap();
    let login = &requests_to(&server, LOGIN).await[0];
    let data = body(login)["data"].clone();
    assert_eq!(data["ACCOUNT_NAME"], "TOMLACCT");
    assert_eq!(data["LOGIN_NAME"], "TOMLUSER");
    assert_eq!(data["AUTHENTICATOR"], "PROGRAMMATIC_ACCESS_TOKEN");
    assert_eq!(data["TOKEN"], "pat-1");
    assert_eq!(query_param(login, "roleName").as_deref(), Some("TOMLROLE"));
    let _ = std::fs::remove_dir_all(home);
}
