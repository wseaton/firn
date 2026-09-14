use std::process::ExitCode;

use firn::{ConfigError, SnowflakeApiError, TokenCacheError};
use serde::Serialize;
use thiserror::Error;

/// Exit codes agents can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Anything else
    Other = 1,
    /// Bad arguments, unreadable config, missing connection
    Usage = 2,
    /// Login or token problems
    Auth = 3,
    /// Snowflake rejected or failed the statement
    Query = 4,
    /// Cancelled by the user or timed out
    Cancelled = 5,
}

impl ExitKind {
    pub fn code(self) -> ExitCode {
        ExitCode::from(self as u8)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::Usage => "usage",
            Self::Auth => "auth",
            Self::Query => "query",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Api(#[from] SnowflakeApiError),

    #[error(transparent)]
    TokenCache(#[from] TokenCacheError),

    #[error("query {0} was cancelled")]
    Cancelled(String),

    #[error("timed out after {0}s")]
    Timeout(u64),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Arrow(#[from] arrow::error::ArrowError),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    message: String,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

impl CliError {
    pub fn kind(&self) -> ExitKind {
        match self {
            Self::Usage(_) | Self::Config(_) => ExitKind::Usage,
            Self::TokenCache(_) => ExitKind::Auth,
            Self::Cancelled(_) | Self::Timeout(_) => ExitKind::Cancelled,
            Self::Api(e) => match e {
                SnowflakeApiError::AuthError(_) | SnowflakeApiError::TokenCacheError(_) => {
                    ExitKind::Auth
                }
                SnowflakeApiError::ConfigError(_) => ExitKind::Usage,
                SnowflakeApiError::QueryCancelled => ExitKind::Cancelled,
                SnowflakeApiError::ApiError(..) => ExitKind::Query,
                _ => ExitKind::Other,
            },
            Self::Io(_) | Self::Json(_) | Self::Arrow(_) => ExitKind::Other,
        }
    }

    /// Snowflake error code when there is one (`390100`, `002003`, ...).
    pub fn snowflake_code(&self) -> Option<&str> {
        match self {
            Self::Api(SnowflakeApiError::ApiError(code, _)) => Some(code),
            Self::Api(SnowflakeApiError::AuthError(firn::AuthError::AuthFailed(code, _))) => {
                Some(code)
            }
            _ => None,
        }
    }

    pub fn to_json(&self) -> String {
        let envelope = ErrorEnvelope {
            error: ErrorBody {
                kind: self.kind().as_str(),
                code: self.snowflake_code(),
                message: self.to_string(),
            },
        };
        serde_json::to_string(&envelope).unwrap_or_else(|_| self.to_string())
    }
}
