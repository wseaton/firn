use firn::CredentialKind;
use serde_json::json;

use crate::cli::{AuthCommand, Cli};
use crate::client::{Client, Target};
use crate::error::CliError;
use crate::output::{emit_value, Resolved};
use crate::session_store::SessionStore;

pub async fn run(cli: &Cli, cmd: &AuthCommand, format: Resolved) -> Result<(), CliError> {
    match cmd {
        AuthCommand::Login => {
            let client = Client::connect(cli, true).await?;
            let result = client.api.exec("SELECT CURRENT_SESSION()").await?;
            client.finish();
            let snapshot = client.api.session_snapshot();
            emit_value(
                format,
                &json!({
                    "logged_in": true,
                    "query_id": result.metadata.query_id,
                    "session_saved": snapshot.is_some() && !cli.no_session,
                    "session_expires_at": snapshot.and_then(|s| s.master_expires_at()).map(unix),
                }),
            )
        }
        AuthCommand::Status => {
            let target = Target::resolve(cli)?;
            let store = SessionStore::from_env()?;
            let session = store.load(&target.host, &target.user);
            let cache = target.token_cache()?;
            let cached = |kind: CredentialKind| -> Result<bool, CliError> {
                let Some(cache) = &cache else {
                    return Ok(false);
                };
                Ok(cache.get(&target.credential_key(kind)?)?.is_some())
            };
            emit_value(
                format,
                &json!({
                    "connection": target.config.name,
                    "host": target.host,
                    "user": target.user,
                    "authenticator": target.config.authenticator.as_deref().unwrap_or("snowflake"),
                    "token_cache": target.cache_enabled,
                    "id_token_cached": cached(CredentialKind::IdToken)?,
                    "mfa_token_cached": cached(CredentialKind::MfaToken)?,
                    "session_saved": session.is_some(),
                    "session_expires_at": session.and_then(|s| s.master_expires_at()).map(unix),
                }),
            )
        }
        AuthCommand::Logout { tokens } => {
            let target = Target::resolve(cli)?;
            let store = SessionStore::from_env()?;
            let mut closed = false;
            if store.load(&target.host, &target.user).is_some() {
                let client = Client::connect(cli, false).await?;
                match client.api.close_session().await {
                    Ok(()) => closed = true,
                    Err(e) => log::warn!("could not close the server session: {e}"),
                }
            }
            let removed = store.remove(&target.host, &target.user)?;
            let mut tokens_cleared = false;
            if *tokens {
                if let Some(cache) = target.token_cache()? {
                    for kind in [CredentialKind::IdToken, CredentialKind::MfaToken] {
                        cache.remove(&target.credential_key(kind)?)?;
                    }
                    tokens_cleared = true;
                }
            }
            emit_value(
                format,
                &json!({
                    "session_closed": closed,
                    "session_removed": removed,
                    "tokens_cleared": tokens_cleared,
                }),
            )
        }
    }
}

fn unix(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
