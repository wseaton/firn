use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "cert-auth")]
use crate::jwt::generate_jwt_token;
use arc_swap::ArcSwapOption;
use futures::lock::Mutex;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::connection;
use crate::connection::{Connection, QueryType};
use crate::requests::{
    Authenticator, ClientEnvironment, LoginRequest, LoginRequestData, RenewSessionRequest,
    SessionParameters,
};
use crate::responses::{AuthResponse, BaseRestResponse, LoginResponseData};
use crate::token_cache::{CredentialKey, CredentialKind, TokenCache, TokenCacheError};
use crate::AuthType;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error(transparent)]
    #[cfg(feature = "cert-auth")]
    JwtError(#[from] crate::jwt::JwtError),

    #[error(transparent)]
    RequestError(#[from] connection::ConnectionError),

    #[error("Unexpected API response")]
    UnexpectedResponse,

    // todo: add code mapping to meaningful message and/or refer to docs
    //   eg https://docs.snowflake.com/en/user-guide/key-pair-auth-troubleshooting
    #[error("Failed to authenticate. Error code: {0}. Message: {1}")]
    AuthFailed(String, String),

    #[error("Can not renew closed session token")]
    OutOfOrderRenew,

    #[error("Login timed out after {0:?}")]
    LoginTimeout(Duration),

    #[error("Enable the cert-auth feature to use certificate authentication")]
    CertAuthNotEnabled,

    #[error("Enable the browser-auth feature to use external browser authentication")]
    BrowserAuthNotEnabled,

    #[cfg(feature = "browser-auth")]
    #[error(transparent)]
    BrowserAuthError(#[from] crate::browser::BrowserAuthError),

    #[error(transparent)]
    TokenCache(#[from] TokenCacheError),
}

#[derive(Debug)]
struct AuthState {
    session_token: AuthToken,
    master_token: AuthToken,
    // Precomputed so the hot path in `get_token` doesn't reformat per query.
    auth_header: Arc<str>,
}

impl AuthState {
    fn new(session_token: AuthToken, master_token: AuthToken) -> Self {
        let auth_header = Arc::from(session_token.auth_header());
        Self {
            session_token,
            master_token,
            auth_header,
        }
    }

    fn is_fresh(&self) -> bool {
        !self.master_token.is_expired() && !self.session_token.is_expired()
    }
}

#[derive(Clone)]
struct AuthToken {
    token: SecretString,
    /// `None` means the server reported a negative validity, i.e. no expiry.
    expires_at: Option<SystemTime>,
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AuthParts {
    pub session_token_auth_header: Arc<str>,
    pub sequence_id: u64,
}

impl AuthToken {
    pub fn new(token: &str, validity_in_seconds: i64) -> Self {
        let expires_at = u64::try_from(validity_in_seconds)
            .ok()
            .and_then(|secs| SystemTime::now().checked_add(Duration::from_secs(secs)));
        Self {
            token: SecretString::from(token),
            expires_at,
        }
    }

    fn from_expiry(token: &str, expires_at: Option<SystemTime>) -> Self {
        Self {
            token: SecretString::from(token),
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| SystemTime::now() >= expires_at)
    }

    pub fn auth_header(&self) -> String {
        format!("Snowflake Token=\"{}\"", self.token.expose_secret())
    }
}

/// Serializable copy of a live session so a short-lived process (a CLI
/// invocation) can hand its session to the next one instead of logging in
/// again. Holds raw tokens: store it with the same care as a password.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    host: String,
    user: String,
    session_token: String,
    master_token: String,
    session_expires_at: Option<u64>,
    master_expires_at: Option<u64>,
    sequence_id: u64,
}

impl std::fmt::Debug for SessionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSnapshot")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("session_token", &"[REDACTED]")
            .field("master_token", &"[REDACTED]")
            .field("session_expires_at", &self.session_expires_at)
            .field("master_expires_at", &self.master_expires_at)
            .field("sequence_id", &self.sequence_id)
            .finish()
    }
}

impl SessionSnapshot {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    /// True once the master token has expired; the snapshot can no longer be
    /// renewed and the holder should discard it.
    pub fn is_expired(&self) -> bool {
        self.master_expires_at
            .is_some_and(|secs| unix_now() >= secs)
    }

    pub fn master_expires_at(&self) -> Option<SystemTime> {
        self.master_expires_at.map(from_unix)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn to_unix(t: Option<SystemTime>) -> Option<u64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

fn from_unix(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Called with the SSO URL instead of opening a browser. Lets headless
/// callers print or forward the URL; the local callback listener still
/// receives the token once the user finishes in some browser.
pub type SsoUrlHandler = Arc<dyn Fn(&str) + Send + Sync>;

/// Everything `Session` needs to log in. Built by `SnowflakeApiBuilder`.
pub struct SessionConfig {
    pub base_url: Url,
    pub account_identifier: String,
    pub username: String,
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    pub auth_type: AuthType,
    pub token_cache: Option<Arc<dyn TokenCache>>,
    pub login_timeout: Duration,
    pub application: String,
    pub client_identity: ClientIdentity,
    pub sso_url_handler: Option<SsoUrlHandler>,
}

/// `CLIENT_APP_ID` / `CLIENT_APP_VERSION` sent at login. Snowflake gates
/// some server behaviour on the driver it thinks it is talking to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub app_id: String,
    pub app_version: String,
}

impl Default for ClientIdentity {
    fn default() -> Self {
        Self {
            app_id: CLIENT_APP_ID.to_owned(),
            app_version: CLIENT_APP_VERSION.to_owned(),
        }
    }
}

/// Requests, caches, and renews authentication tokens.
/// Tokens are given as response to creating new session in Snowflake. Session persists
/// the configuration state and temporary objects (tables, procedures, etc).
// todo: close session after object is dropped
pub struct Session {
    connection: Arc<Connection>,

    auth_state: ArcSwapOption<AuthState>,
    sequence_id: AtomicU64,
    // Single-flights login/renew so concurrent first-callers share one
    // round-trip instead of racing each other.
    refresh_lock: Mutex<()>,
    auth_type: AuthType,
    token_cache: Option<Arc<dyn TokenCache>>,
    base_url: Url,
    account_identifier: String,

    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,

    username: String,
    role: Option<String>,
    login_timeout: Duration,
    application: String,
    client_identity: ClientIdentity,
    #[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
    sso_url_handler: Option<SsoUrlHandler>,
}

/// <https://github.com/snowflakedb/gosnowflake/blob/v2.0.2/internal/config/dsn.go#L27-L28>
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_mins(5);

const CLIENT_APP_ID: &str = "Go";
const CLIENT_APP_VERSION: &str = "2.2.0";

struct LoginOutcome {
    state: AuthState,
    #[cfg(feature = "browser-auth")]
    id_token: Option<SecretString>,
    mfa_token: Option<SecretString>,
}

impl Session {
    pub fn new(connection: Arc<Connection>, config: SessionConfig) -> Self {
        Self {
            connection,
            auth_state: ArcSwapOption::empty(),
            sequence_id: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            auth_type: config.auth_type,
            token_cache: config.token_cache,
            base_url: config.base_url,
            account_identifier: config.account_identifier.to_uppercase(),
            warehouse: config.warehouse.map(|s| s.to_uppercase()),
            database: config.database.map(|s| s.to_uppercase()),
            schema: config.schema.map(|s| s.to_uppercase()),
            username: config.username.to_uppercase(),
            role: config.role.map(|s| s.to_uppercase()),
            login_timeout: config.login_timeout,
            application: config.application,
            client_identity: config.client_identity,
            sso_url_handler: config.sso_url_handler,
        }
    }

    fn host(&self) -> &str {
        self.base_url.host_str().unwrap_or_default()
    }

    /// Adopt tokens from a previous process. Ignored (with a warning) if the
    /// snapshot was taken against a different host or user, or if its
    /// master token has already expired.
    pub fn restore(&self, snapshot: &SessionSnapshot) {
        if !snapshot.host.eq_ignore_ascii_case(self.host())
            || !snapshot.user.eq_ignore_ascii_case(&self.username)
        {
            log::warn!(
                "ignoring session snapshot for {}@{}; this session is {}@{}",
                snapshot.user,
                snapshot.host,
                self.username,
                self.host()
            );
            return;
        }
        if snapshot.is_expired() {
            log::debug!("ignoring expired session snapshot");
            return;
        }
        let state = AuthState::new(
            AuthToken::from_expiry(
                &snapshot.session_token,
                snapshot.session_expires_at.map(from_unix),
            ),
            AuthToken::from_expiry(
                &snapshot.master_token,
                snapshot.master_expires_at.map(from_unix),
            ),
        );
        self.sequence_id
            .store(snapshot.sequence_id, Ordering::Relaxed);
        self.auth_state.store(Some(Arc::new(state)));
    }

    /// Copy of the live tokens, or `None` if no session exists yet or the
    /// master token has expired.
    pub fn snapshot(&self) -> Option<SessionSnapshot> {
        let state = self.auth_state.load_full()?;
        if state.master_token.is_expired() {
            return None;
        }
        Some(SessionSnapshot {
            host: self.host().to_owned(),
            user: self.username.clone(),
            session_token: state.session_token.token.expose_secret().to_owned(),
            master_token: state.master_token.token.expose_secret().to_owned(),
            session_expires_at: to_unix(state.session_token.expires_at),
            master_expires_at: to_unix(state.master_token.expires_at),
            sequence_id: self.sequence_id.load(Ordering::Relaxed),
        })
    }

    /// Drop any cached id / MFA token for this host and user, forcing the
    /// next login to go interactive.
    pub fn clear_cached_credentials(&self) -> Result<(), AuthError> {
        let Some(cache) = &self.token_cache else {
            return Ok(());
        };
        for kind in [CredentialKind::IdToken, CredentialKind::MfaToken] {
            cache.remove(&self.credential_key(kind)?)?;
        }
        Ok(())
    }

    /// Get cached auth + a fresh sequence id. Hot path is lock-free
    /// (`ArcSwap` load + atomic `fetch_add`). Refresh single-flights
    /// via `refresh_lock`.
    pub async fn get_token(&self) -> Result<AuthParts, AuthError> {
        if let Some(state) = self.auth_state.load_full() {
            if state.is_fresh() {
                return Ok(self.build_parts(&state));
            }
        }

        let _refresh_guard = self.refresh_lock.lock().await;

        // Re-check: another caller may have refreshed while we waited.
        if let Some(state) = self.auth_state.load_full() {
            if state.is_fresh() {
                return Ok(self.build_parts(&state));
            }
        }

        let current = self.auth_state.load_full();
        let need_full_create = current
            .as_deref()
            .is_none_or(|s| s.master_token.is_expired());

        let new_state = if need_full_create {
            self.login().await?
        } else {
            match current {
                Some(state) => self.renew_or_login(&state).await?,
                None => return Err(AuthError::OutOfOrderRenew),
            }
        };

        let new_state = Arc::new(new_state);
        self.auth_state.store(Some(Arc::clone(&new_state)));
        Ok(self.build_parts(&new_state))
    }

    fn build_parts(&self, state: &AuthState) -> AuthParts {
        // +1 to match pre-refactor semantics where first id returned is 1.
        let sequence_id = self.sequence_id.fetch_add(1, Ordering::Relaxed) + 1;
        AuthParts {
            session_token_auth_header: Arc::clone(&state.auth_header),
            sequence_id,
        }
    }

    /// Renew now, regardless of TTL. For callers that observed an explicit
    /// `390112` from the server mid-flight and need to refresh before
    /// retrying. Falls back to a full re-create if the master token is
    /// gone or itself expired.
    pub async fn force_renew(&self) -> Result<AuthParts, AuthError> {
        let _refresh_guard = self.refresh_lock.lock().await;

        let current = self.auth_state.load_full();
        let new_state = match current.as_deref() {
            Some(s) if !s.master_token.is_expired() => self.renew_or_login(s).await?,
            _ => self.login().await?,
        };

        let new_state = Arc::new(new_state);
        self.auth_state.store(Some(Arc::clone(&new_state)));
        Ok(self.build_parts(&new_state))
    }

    // &self (not &mut): only mutation is ArcSwap, so Arc<Session> callers can close.
    pub async fn close(&self) -> Result<(), AuthError> {
        let Some(state) = self.auth_state.swap(None) else {
            return Ok(());
        };
        log::debug!("Closing sessions");

        let resp = self
            .connection
            .request::<AuthResponse>(
                QueryType::CloseSession,
                &self.base_url,
                &[("delete", "true")],
                Some(&state.auth_header),
                serde_json::Value::default(),
                None,
            )
            .await?;

        match resp {
            AuthResponse::Close(_) => Ok(()),
            AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                e.code.unwrap_or_default(),
                e.message.unwrap_or_default(),
            )),
            _ => Err(AuthError::UnexpectedResponse),
        }
    }

    /// Full login for the configured auth type, bounded by `login_timeout`
    /// (<https://github.com/snowflakedb/gosnowflake/blob/v2.0.2/internal/config/dsn.go#L27-L28>,
    /// default 300s) end to end, browser round-trips included. Resets the
    /// sequence counter because a new Snowflake session starts its own id
    /// space.
    async fn login(&self) -> Result<AuthState, AuthError> {
        let timeout = self.login_timeout;
        let state = tokio::time::timeout(timeout, self.login_inner())
            .await
            .map_err(|_| AuthError::LoginTimeout(timeout))??;
        self.sequence_id.store(0, Ordering::Relaxed);
        Ok(state)
    }

    async fn login_inner(&self) -> Result<AuthState, AuthError> {
        match &self.auth_type {
            #[cfg(feature = "cert-auth")]
            AuthType::Certificate { private_key_pem } => {
                log::info!("Starting session with certificate authentication");
                Ok(self
                    .create(self.cert_request_body(private_key_pem)?)
                    .await?
                    .state)
            }
            #[cfg(not(feature = "cert-auth"))]
            AuthType::Certificate { .. } => Err(AuthError::CertAuthNotEnabled),
            AuthType::Password { password, passcode } => {
                log::info!("Starting session with password authentication");
                let mut body = self.login_request_data();
                body.password = Some(password.expose_secret().to_owned());
                set_passcode(&mut body, passcode.as_ref());
                Ok(self.create(body).await?.state)
            }
            AuthType::UsernamePasswordMfa { password, passcode } => {
                log::info!("Starting session with MFA authentication");
                self.login_mfa(password, passcode.as_ref()).await
            }
            AuthType::OAuth { token } => {
                log::info!("Starting session with OAuth authentication");
                let mut body = self.login_request_data();
                body.authenticator = Some(Authenticator::OAuth);
                body.token = Some(token.expose_secret().to_owned());
                Ok(self.create(body).await?.state)
            }
            AuthType::ProgrammaticAccessToken { token } => {
                log::info!("Starting session with programmatic access token");
                let mut body = self.login_request_data();
                body.authenticator = Some(Authenticator::ProgrammaticAccessToken);
                body.token = Some(token.expose_secret().to_owned());
                Ok(self.create(body).await?.state)
            }
            #[cfg(feature = "browser-auth")]
            AuthType::ExternalBrowser => {
                log::info!("Starting session with external browser authentication");
                self.login_browser().await
            }
        }
    }

    /// MFA login with token caching. A cached `mfaToken` replaces the
    /// passcode; if Snowflake rejects it the entry is dropped and the login
    /// is retried with the passcode.
    async fn login_mfa(
        &self,
        password: &SecretString,
        passcode: Option<&SecretString>,
    ) -> Result<AuthState, AuthError> {
        let key = self.cache_key(CredentialKind::MfaToken)?;
        let base = || {
            let mut body = self.login_request_data();
            body.authenticator = Some(Authenticator::UsernamePasswordMfa);
            body.password = Some(password.expose_secret().to_owned());
            if key.is_some() {
                body.session_parameters = Some(SessionParameters {
                    client_request_mfa_token: Some(true),
                    ..Self::session_parameters()
                });
            }
            body
        };

        if let Some(token) = self.cached_credential(key.as_ref()) {
            log::debug!("replaying cached MFA token");
            let mut attempt = base();
            attempt.token = Some(token.expose_secret().to_owned());
            match self.create(attempt).await {
                Ok(outcome) => {
                    self.store_credential(key.as_ref(), outcome.mfa_token.as_ref());
                    return Ok(outcome.state);
                }
                Err(AuthError::AuthFailed(code, message)) => {
                    log::info!("cached MFA token rejected ({code}: {message}); logging in fresh");
                    self.forget_credential(key.as_ref());
                }
                Err(e) => return Err(e),
            }
        }

        let mut body = base();
        set_passcode(&mut body, passcode);
        let outcome = self.create(body).await?;
        self.store_credential(key.as_ref(), outcome.mfa_token.as_ref());
        Ok(outcome.state)
    }

    #[cfg(feature = "cert-auth")]
    fn cert_request_body(
        &self,
        private_key_pem: &SecretString,
    ) -> Result<LoginRequestData, AuthError> {
        let full_identifier = format!("{}.{}", self.account_identifier, self.username);
        let jwt_token = generate_jwt_token(private_key_pem.expose_secret(), &full_identifier)?;

        let mut body = self.login_request_data();
        body.authenticator = Some(Authenticator::SnowflakeJwt);
        body.token = Some(jwt_token);
        Ok(body)
    }

    /// Start new session, all the Snowflake temporary objects will be scoped towards it,
    /// as well as temporary configuration parameters.
    async fn create(&self, body: LoginRequestData) -> Result<LoginOutcome, AuthError> {
        let mut get_params = Vec::new();
        if let Some(warehouse) = &self.warehouse {
            get_params.push(("warehouse", warehouse.as_str()));
        }

        if let Some(database) = &self.database {
            get_params.push(("databaseName", database.as_str()));
        }

        if let Some(schema) = &self.schema {
            get_params.push(("schemaName", schema.as_str()));
        }

        if let Some(role) = &self.role {
            get_params.push(("roleName", role.as_str()));
        }

        log::trace!("Login request: {body:?}");
        let resp = self
            .connection
            .request::<AuthResponse>(
                QueryType::LoginRequest,
                &self.base_url,
                &get_params,
                None,
                LoginRequest { data: body },
                None,
            )
            .await?;
        log::trace!("Auth response: {resp:?}");

        match resp {
            AuthResponse::Login(lr) => {
                log::debug!(
                    "session {} opened: token valid {}s, master {}s, id_token {}, mfa_token {}",
                    lr.data.session_id,
                    lr.data.validity_in_seconds,
                    lr.data.master_validity_in_seconds,
                    lr.data.id_token.as_ref().is_some_and(|t| !t.is_empty()),
                    lr.data.mfa_token.as_ref().is_some_and(|t| !t.is_empty()),
                );
                Ok(login_outcome(lr.data))
            }
            AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                e.code.unwrap_or_default(),
                e.message.unwrap_or_default(),
            )),
            _ => Err(AuthError::UnexpectedResponse),
        }
    }

    fn session_parameters() -> SessionParameters {
        SessionParameters {
            client_validate_default_parameters: true,
            client_store_temporary_credential: None,
            client_request_mfa_token: None,
        }
    }

    fn login_request_data(&self) -> LoginRequestData {
        LoginRequestData {
            client_app_id: self.client_identity.app_id.clone(),
            client_app_version: self.client_identity.app_version.clone(),
            svn_revision: String::new(),
            account_name: self.account_identifier.clone(),
            login_name: Some(self.username.clone()),
            password: None,
            passcode: None,
            ext_authn_duo_method: None,
            authenticator: None,
            token: None,
            proof_key: None,
            browser_mode_redirect_port: None,
            session_parameters: Some(Self::session_parameters()),
            client_environment: ClientEnvironment {
                application: self.application.clone(),
                // gosnowflake reports `runtime.GOOS` (lowercase: darwin /
                // linux / windows). Rust's std::env::consts::OS matches
                // except macOS reports as "macos"; remap.
                os: match std::env::consts::OS {
                    "macos" => "darwin".to_owned(),
                    other => other.to_owned(),
                },
                // gosnowflake's `os_version` carries the runtime arch
                // (the prior hardcoded "gc-arm64" was a stale Go-runtime
                // tag). Use Rust's target arch: x86_64 / aarch64 / etc.
                os_version: std::env::consts::ARCH.to_owned(),
                ocsp_mode: "FAIL_OPEN".to_string(),
            },
        }
    }

    fn cache_key(&self, kind: CredentialKind) -> Result<Option<CredentialKey>, AuthError> {
        if self.token_cache.is_none() {
            return Ok(None);
        }
        Ok(Some(self.credential_key(kind)?))
    }

    fn credential_key(&self, kind: CredentialKind) -> Result<CredentialKey, AuthError> {
        Ok(CredentialKey::new(self.host(), &self.username, kind)?)
    }

    /// Cache read failures are logged, not fatal: a broken cache degrades
    /// to an interactive login rather than blocking it.
    fn cached_credential(&self, key: Option<&CredentialKey>) -> Option<SecretString> {
        let (Some(cache), Some(key)) = (&self.token_cache, key) else {
            return None;
        };
        match cache.get(key) {
            Ok(token) => token,
            Err(e) => {
                log::warn!("token cache read failed for {}: {e}", key.kind().as_str());
                None
            }
        }
    }

    fn store_credential(&self, key: Option<&CredentialKey>, token: Option<&SecretString>) {
        let (Some(cache), Some(key), Some(token)) = (&self.token_cache, key, token) else {
            return;
        };
        match cache.set(key, token) {
            Ok(()) => log::debug!("cached {} for {}", key.kind().as_str(), self.username),
            Err(e) => log::warn!("token cache write failed for {}: {e}", key.kind().as_str()),
        }
    }

    fn forget_credential(&self, key: Option<&CredentialKey>) {
        let (Some(cache), Some(key)) = (&self.token_cache, key) else {
            return;
        };
        if let Err(e) = cache.remove(key) {
            log::warn!("token cache remove failed for {}: {e}", key.kind().as_str());
        }
    }

    /// Browser SSO with id-token replay. A cached `idToken` logs in without
    /// a browser; if Snowflake rejects it, the entry is dropped and the
    /// interactive flow runs. A fresh login stores the returned `idToken`.
    #[cfg(feature = "browser-auth")]
    async fn login_browser(&self) -> Result<AuthState, AuthError> {
        let key = self.cache_key(CredentialKind::IdToken)?;
        if let Some(token) = self.cached_credential(key.as_ref()) {
            log::debug!("replaying cached id token");
            let mut body = self.login_request_data();
            body.authenticator = Some(Authenticator::IdToken);
            body.token = Some(token.expose_secret().to_owned());
            body.session_parameters = Some(SessionParameters {
                client_store_temporary_credential: Some(true),
                ..Self::session_parameters()
            });
            match self.create(body).await {
                Ok(outcome) => {
                    self.store_credential(key.as_ref(), outcome.id_token.as_ref());
                    return Ok(outcome.state);
                }
                Err(AuthError::AuthFailed(code, message)) => {
                    log::info!("cached id token rejected ({code}: {message}); opening browser");
                    self.forget_credential(key.as_ref());
                }
                Err(e) => return Err(e),
            }
        }

        let outcome = self.create_browser_session(key.is_some()).await?;
        self.store_credential(key.as_ref(), outcome.id_token.as_ref());
        Ok(outcome.state)
    }

    /// Browser SSO authentication flow:
    /// 1. Create local TCP listener for callback
    /// 2. Generate proof key
    /// 3. Send authenticator-request to get SSO URL
    /// 4. Open browser with SSO URL
    /// 5. Wait for token on local listener
    /// 6. Send login-request with token and proof key
    #[cfg(feature = "browser-auth")]
    async fn create_browser_session(
        &self,
        request_id_token: bool,
    ) -> Result<LoginOutcome, AuthError> {
        use crate::browser::{
            create_local_listener, generate_proof_key, open_browser, wait_for_token,
        };

        // Step 1: Create local listener for callback
        let (listener, port) = create_local_listener().await?;

        // Step 2: Generate proof key
        let proof_key = generate_proof_key();

        // Step 3: Send authenticator-request to get SSO URL
        let mut auth_request = self.login_request_data();
        auth_request.authenticator = Some(Authenticator::ExternalBrowser);
        auth_request.browser_mode_redirect_port = Some(port.to_string());
        auth_request.proof_key = Some(proof_key.clone());
        auth_request.session_parameters = None;

        let resp = self
            .connection
            .request::<AuthResponse>(
                QueryType::AuthenticatorRequest,
                &self.base_url,
                &[],
                None,
                LoginRequest { data: auth_request },
                None,
            )
            .await?;

        let (sso_url, server_proof_key) = match resp {
            AuthResponse::Auth(auth_resp) => (auth_resp.data.sso_url, auth_resp.data.proof_key),
            AuthResponse::Error(e) => {
                return Err(AuthError::AuthFailed(
                    e.code.unwrap_or_default(),
                    e.message.unwrap_or_default(),
                ));
            }
            _ => return Err(AuthError::UnexpectedResponse),
        };

        // Use the server-returned proof_key for the login request
        // The server may modify the proof key, and the login request must match
        let final_proof_key = if server_proof_key.is_empty() {
            proof_key
        } else {
            server_proof_key
        };

        // Step 4: Open browser with SSO URL, or hand it to the caller
        match &self.sso_url_handler {
            Some(handler) => handler(&sso_url),
            None => open_browser(&sso_url)?,
        }

        // Step 5: Wait for token on local listener
        let token = wait_for_token(&listener).await?;

        // Step 6: Send login-request with token and proof key
        let mut login_request = self.login_request_data();
        login_request.authenticator = Some(Authenticator::ExternalBrowser);
        login_request.token = Some(token);
        login_request.proof_key = Some(final_proof_key);
        if request_id_token {
            login_request.session_parameters = Some(SessionParameters {
                client_store_temporary_credential: Some(true),
                ..Self::session_parameters()
            });
        }

        self.create(login_request).await
    }

    /// Renew, and if Snowflake rejects the master token (session killed,
    /// snapshot from a dead session) fall back to a full login.
    async fn renew_or_login(&self, old: &AuthState) -> Result<AuthState, AuthError> {
        match self.renew(old).await {
            Ok(state) => Ok(state),
            Err(AuthError::AuthFailed(code, message)) => {
                log::info!("session renew rejected ({code}: {message}); logging in again");
                self.login().await
            }
            Err(e) => Err(e),
        }
    }

    // Caller must NOT reset `sequence_id`: renewals preserve the Snowflake
    // session id space.
    async fn renew(&self, old: &AuthState) -> Result<AuthState, AuthError> {
        log::debug!("Renewing the token");
        let auth = old.master_token.auth_header();
        let body = RenewSessionRequest {
            old_session_token: old.session_token.token.expose_secret().to_string(),
            request_type: "RENEW".to_string(),
        };

        let resp = self
            .connection
            .request(
                QueryType::TokenRequest,
                &self.base_url,
                &[],
                Some(&auth),
                body,
                None,
            )
            .await?;

        match resp {
            AuthResponse::Renew(rs) => {
                let session_token =
                    AuthToken::new(&rs.data.session_token, rs.data.validity_in_seconds_s_t);
                let master_token =
                    AuthToken::new(&rs.data.master_token, rs.data.validity_in_seconds_m_t);
                Ok(AuthState::new(session_token, master_token))
            }
            AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                e.code.unwrap_or_default(),
                e.message.unwrap_or_default(),
            )),
            _ => Err(AuthError::UnexpectedResponse),
        }
    }

    /// Hit `/session/heartbeat` to keep the cached session token fresh. No-op
    /// if no session has been created yet (we don't auth purely to heartbeat).
    /// On `390112` we force-renew once and retry; the next tick handles any
    /// further failures.
    pub async fn heartbeat(&self) -> Result<(), AuthError> {
        if self.auth_state.load().is_none() {
            return Ok(());
        }
        let parts = self.get_token().await?;
        let resp = self
            .send_heartbeat(&parts.session_token_auth_header)
            .await?;
        if resp.success {
            return Ok(());
        }
        if resp.code.as_deref() == Some("390112") {
            log::debug!("Heartbeat saw 390112; renewing and retrying once");
            let parts = self.force_renew().await?;
            let resp = self
                .send_heartbeat(&parts.session_token_auth_header)
                .await?;
            if resp.success {
                return Ok(());
            }
            return Err(AuthError::AuthFailed(
                resp.code.unwrap_or_default(),
                resp.message.unwrap_or_default(),
            ));
        }
        Err(AuthError::AuthFailed(
            resp.code.unwrap_or_default(),
            resp.message.unwrap_or_default(),
        ))
    }

    async fn send_heartbeat(
        &self,
        auth_header: &str,
    ) -> Result<BaseRestResponse<serde_json::Value>, AuthError> {
        Ok(self
            .connection
            .request::<BaseRestResponse<serde_json::Value>>(
                QueryType::Heartbeat,
                &self.base_url,
                &[],
                Some(auth_header),
                serde_json::Value::Null,
                None,
            )
            .await?)
    }
}

fn set_passcode(body: &mut LoginRequestData, passcode: Option<&SecretString>) {
    if let Some(passcode) = passcode {
        body.passcode = Some(passcode.expose_secret().to_owned());
        body.ext_authn_duo_method = Some("passcode".to_owned());
    }
}

fn login_outcome(data: LoginResponseData) -> LoginOutcome {
    let session_token = AuthToken::new(&data.token, data.validity_in_seconds);
    let master_token = AuthToken::new(&data.master_token, data.master_validity_in_seconds);
    LoginOutcome {
        state: AuthState::new(session_token, master_token),
        #[cfg(feature = "browser-auth")]
        id_token: data
            .id_token
            .filter(|t| !t.is_empty())
            .map(SecretString::from),
        mfa_token: data
            .mfa_token
            .filter(|t| !t.is_empty())
            .map(SecretString::from),
    }
}
