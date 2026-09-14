use std::collections::HashMap;

use serde::Serialize;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecRequest {
    pub sql_text: String,
    pub async_exec: bool,
    pub sequence_id: u64,
    pub is_internal: bool,
    /// When true, Snowflake parses + validates + returns schema metadata
    /// without executing. Skipped from the wire when false to keep normal
    /// requests untouched.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub describe_only: bool,
    /// Positional bindings for `?` placeholders. Keys are 1-indexed string
    /// positions ("1", "2", ...) per Snowflake's internal API. `None` is
    /// serialized as omitted so unbound queries don't send the field at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<HashMap<String, BindParam>>,
    /// Per-statement parameters injected into the request body. Used today
    /// for `MULTI_STATEMENT_COUNT`; gosnowflake's `parameters` field on the
    /// same endpoint takes any session-level parameter name as a key.
    /// Empty -> omitted from the wire.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Value>,
}

/// One positional bind parameter on the wire. The Snowflake type name goes in
/// `type_` (TEXT, FIXED, REAL, BOOLEAN, ...); the value is JSON, but in
/// practice almost always a stringified primitive.
#[derive(Serialize, Debug, Clone)]
pub struct BindParam {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub value: serde_json::Value,
}

/// A typed bind value. Construct via the inherent constructors
/// (`Bind::text`, `Bind::fixed`, etc.) or via `Into` from common primitive
/// types, then hand them to the query builder. Positional binds fill `?`
/// placeholders in order; [`Bind::named`] binds fill `:name` placeholders.
#[derive(Debug, Clone)]
pub struct Bind {
    pub(crate) name: Option<String>,
    pub(crate) param: BindParam,
}

/// Serializes as the wire form, `{"type": "FIXED", "value": "42"}`.
impl Serialize for Bind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.param.serialize(serializer)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindError {
    #[error("positional (`?`) and named (`:name`) binds cannot be mixed in one statement")]
    Mixed,

    #[error("array bind mixes types: expected {expected}, got {got}")]
    MixedArrayTypes {
        expected: &'static str,
        got: &'static str,
    },

    #[error("array bind needs at least one value")]
    EmptyArray,

    #[error("array bind elements cannot themselves be arrays")]
    NestedArray,
}

impl Bind {
    fn scalar(type_: &'static str, value: serde_json::Value) -> Self {
        Self {
            name: None,
            param: BindParam { type_, value },
        }
    }

    /// Bind to a `:name` placeholder instead of the next `?`.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Snowflake type name on the wire (`TEXT`, `FIXED`, ...).
    pub fn type_name(&self) -> &'static str {
        self.param.type_
    }

    /// VARCHAR / TEXT / STRING.
    pub fn text(s: impl Into<String>) -> Self {
        Self::scalar("TEXT", serde_json::Value::String(s.into()))
    }

    /// Integer (NUMBER with scale 0). Snowflake expects FIXED values as
    /// strings to preserve full 38-digit precision through JSON.
    pub fn fixed(n: i64) -> Self {
        Self::scalar("FIXED", serde_json::Value::String(n.to_string()))
    }

    /// Floating-point (NUMBER / FLOAT / DOUBLE).
    pub fn real(f: f64) -> Self {
        Self::scalar("REAL", serde_json::Value::String(f.to_string()))
    }

    /// BOOLEAN.
    pub fn boolean(b: bool) -> Self {
        Self::scalar("BOOLEAN", serde_json::Value::String(b.to_string()))
    }

    /// BINARY, sent hex-encoded.
    pub fn binary(bytes: &[u8]) -> Self {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Self::scalar("BINARY", serde_json::Value::String(hex))
    }

    /// DATE from milliseconds since the Unix epoch (gosnowflake's encoding).
    pub fn date_millis(ms: i64) -> Self {
        Self::scalar("DATE", serde_json::Value::String(ms.to_string()))
    }

    /// TIME from nanoseconds since midnight.
    pub fn time_nanos(ns: i64) -> Self {
        Self::scalar("TIME", serde_json::Value::String(ns.to_string()))
    }

    /// `TIMESTAMP_NTZ` from nanoseconds since the Unix epoch.
    pub fn timestamp_ntz_nanos(ns: i64) -> Self {
        Self::scalar("TIMESTAMP_NTZ", serde_json::Value::String(ns.to_string()))
    }

    /// `TIMESTAMP_LTZ` from nanoseconds since the Unix epoch.
    pub fn timestamp_ltz_nanos(ns: i64) -> Self {
        Self::scalar("TIMESTAMP_LTZ", serde_json::Value::String(ns.to_string()))
    }

    /// `TIMESTAMP_TZ` from nanoseconds since the Unix epoch plus a UTC offset
    /// in minutes. Snowflake's wire form is `"<nanos> <offset + 1440>"`.
    pub fn timestamp_tz_nanos(ns: i64, offset_minutes: i32) -> Self {
        Self::scalar(
            "TIMESTAMP_TZ",
            serde_json::Value::String(format!("{ns} {}", i64::from(offset_minutes) + 1440)),
        )
    }

    /// SQL NULL with a type hint. The type matters because Snowflake's
    /// type inference happens at bind time; a mistyped NULL can change
    /// query semantics.
    pub fn null(type_: &'static str) -> Self {
        Self::scalar(type_, serde_json::Value::Null)
    }

    /// Array binding: one bind whose value is a column of values, so a
    /// single `INSERT INTO t VALUES (?, ?)` inserts one row per element.
    /// Every element must have the same type; typed NULLs (`Bind::null`)
    /// are allowed when their type matches.
    pub fn array<I>(values: I) -> Result<Self, BindError>
    where
        I: IntoIterator<Item = Bind>,
    {
        let mut type_: Option<&'static str> = None;
        let mut out = Vec::new();
        for b in values {
            if b.param.value.is_array() {
                return Err(BindError::NestedArray);
            }
            match type_ {
                None => type_ = Some(b.param.type_),
                Some(t) if t != b.param.type_ => {
                    return Err(BindError::MixedArrayTypes {
                        expected: t,
                        got: b.param.type_,
                    })
                }
                Some(_) => {}
            }
            out.push(b.param.value);
        }
        let type_ = type_.ok_or(BindError::EmptyArray)?;
        Ok(Self::scalar(type_, serde_json::Value::Array(out)))
    }

    pub fn is_array(&self) -> bool {
        self.param.value.is_array()
    }
}

/// Build the `bindings` request field: keys are 1-indexed positions for
/// positional binds or the placeholder name for named binds.
pub fn bindings_map(binds: &[Bind]) -> Result<Option<HashMap<String, BindParam>>, BindError> {
    if binds.is_empty() {
        return Ok(None);
    }
    let named = binds.iter().filter(|b| b.name.is_some()).count();
    if named != 0 && named != binds.len() {
        return Err(BindError::Mixed);
    }
    Ok(Some(
        binds
            .iter()
            .enumerate()
            .map(|(i, b)| {
                (
                    b.name.clone().unwrap_or_else(|| (i + 1).to_string()),
                    b.param.clone(),
                )
            })
            .collect(),
    ))
}

impl From<&str> for Bind {
    fn from(s: &str) -> Self {
        Bind::text(s)
    }
}
impl From<String> for Bind {
    fn from(s: String) -> Self {
        Bind::text(s)
    }
}
impl From<i32> for Bind {
    fn from(n: i32) -> Self {
        Bind::fixed(i64::from(n))
    }
}
impl From<i64> for Bind {
    fn from(n: i64) -> Self {
        Bind::fixed(n)
    }
}
impl From<u32> for Bind {
    fn from(n: u32) -> Self {
        Bind::fixed(i64::from(n))
    }
}
impl From<f32> for Bind {
    fn from(f: f32) -> Self {
        Bind::real(f64::from(f))
    }
}
impl From<f64> for Bind {
    fn from(f: f64) -> Self {
        Bind::real(f)
    }
}
impl From<bool> for Bind {
    fn from(b: bool) -> Self {
        Bind::boolean(b)
    }
}

/// Body for `/queries/v1/abort-request`. The `request_id` is the UUID generated
/// for the original query POST (the one we want to cancel), serialized as
/// `requestId`. The cancel POST itself carries its own `request_id`/`request_guid`
/// in URL params.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AbortRequest {
    pub request_id: String,
}

/// Wire name Snowflake expects in the `AUTHENTICATOR` login field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authenticator {
    UsernamePasswordMfa,
    #[cfg(feature = "cert-auth")]
    SnowflakeJwt,
    OAuth,
    ProgrammaticAccessToken,
    #[cfg(feature = "browser-auth")]
    ExternalBrowser,
    #[cfg(feature = "browser-auth")]
    IdToken,
}

impl Authenticator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UsernamePasswordMfa => "USERNAME_PASSWORD_MFA",
            #[cfg(feature = "cert-auth")]
            Self::SnowflakeJwt => "SNOWFLAKE_JWT",
            Self::OAuth => "OAUTH",
            Self::ProgrammaticAccessToken => "PROGRAMMATIC_ACCESS_TOKEN",
            #[cfg(feature = "browser-auth")]
            Self::ExternalBrowser => "EXTERNALBROWSER",
            #[cfg(feature = "browser-auth")]
            Self::IdToken => "ID_TOKEN",
        }
    }
}

impl Serialize for Authenticator {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Serialize, Debug)]
pub struct LoginRequest {
    pub data: LoginRequestData,
}

/// Body of `/session/v1/login-request` and `/session/authenticator-request`.
/// One struct with optional fields, matching gosnowflake's `authRequestData`;
/// each auth flow fills in the subset it needs.
#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct LoginRequestData {
    pub client_app_id: String,
    pub client_app_version: String,
    pub svn_revision: String,
    pub account_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_authn_duo_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<Authenticator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_mode_redirect_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_parameters: Option<SessionParameters>,
    pub client_environment: ClientEnvironment,
}

impl std::fmt::Debug for LoginRequestData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("LoginRequestData")
            .field("client_app_id", &self.client_app_id)
            .field("client_app_version", &self.client_app_version)
            .field("account_name", &self.account_name)
            .field("login_name", &self.login_name)
            .field("password", &redact(&self.password))
            .field("passcode", &redact(&self.passcode))
            .field("ext_authn_duo_method", &self.ext_authn_duo_method)
            .field("authenticator", &self.authenticator)
            .field("token", &redact(&self.token))
            .field("proof_key", &redact(&self.proof_key))
            .field(
                "browser_mode_redirect_port",
                &self.browser_mode_redirect_port,
            )
            .field("session_parameters", &self.session_parameters)
            .field("client_environment", &self.client_environment)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SessionParameters {
    pub client_validate_default_parameters: bool,
    /// Ask Snowflake for an `idToken` on SSO logins so later sessions can
    /// replay it instead of opening a browser. Needs `ALLOW_ID_TOKEN = true`
    /// on the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_store_temporary_credential: Option<bool>,
    /// Ask Snowflake for an `mfaToken` on MFA logins. Needs
    /// `ALLOW_CLIENT_MFA_CACHING = true` on the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_request_mfa_token: Option<bool>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ClientEnvironment {
    pub application: String,
    pub os: String,
    pub os_version: String,
    pub ocsp_mode: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RenewSessionRequest {
    pub old_session_token: String,
    pub request_type: String,
}
