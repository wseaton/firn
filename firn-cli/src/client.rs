//! Turns the global flags into a connected `SnowflakeApi`, restoring a saved
//! session first and persisting it afterwards.

use std::sync::Arc;
use std::time::Duration;

use firn::config::{self, ConnectionConfig};
use firn::{
    default_token_cache, CredentialKey, CredentialKind, SnowflakeApi, SnowflakeApiBuilder,
    SsoUrlHandler, TokenCache,
};

use crate::cli::{Cli, ContextOverrides};
use crate::error::CliError;
use crate::session_store::SessionStore;

/// What `firn` knows about the target before connecting: enough for `auth
/// status` and for keying the caches.
pub struct Target {
    pub config: ConnectionConfig,
    pub host: String,
    pub user: String,
    pub cache_enabled: bool,
}

impl Target {
    pub fn resolve(cli: &Cli) -> Result<Self, CliError> {
        let mut config = config::load_connection(cli.connection.as_deref())?;
        if let Some(w) = &cli.context.warehouse {
            config.warehouse = Some(w.clone());
        }
        if let Some(d) = &cli.context.database {
            config.database = Some(d.clone());
        }
        if let Some(s) = &cli.context.schema {
            config.schema = Some(s.clone());
        }
        if let Some(r) = &cli.context.role {
            config.role = Some(r.clone());
        }
        if let Some(t) = cli.login_timeout {
            config.login_timeout = Some(Duration::from_secs(t));
        }
        let host = config.base_url()?.host_str().unwrap_or_default().to_owned();
        let user = config
            .user
            .clone()
            .ok_or(firn::ConfigError::Missing("user"))?;
        // The whole point of this CLI: cache unless the connection or the
        // caller says otherwise.
        let cache_enabled = !cli.no_cache
            && config.client_store_temporary_credential != Some(false)
            && config.client_request_mfa_token != Some(false);
        Ok(Self {
            config,
            host,
            user,
            cache_enabled,
        })
    }

    pub fn token_cache(&self) -> Result<Option<Arc<dyn TokenCache>>, CliError> {
        if !self.cache_enabled {
            return Ok(None);
        }
        Ok(Some(default_token_cache()?))
    }

    pub fn credential_key(&self, kind: CredentialKind) -> Result<CredentialKey, CliError> {
        Ok(CredentialKey::new(&self.host, &self.user, kind)?)
    }
}

pub struct Client {
    pub api: SnowflakeApi,
    /// Account identifier, for Snowsight links in table output.
    pub account: Option<String>,
    store: Option<SessionStore>,
    restored: bool,
}

impl Client {
    /// Connect using the saved session when there is one. `fresh` forces a
    /// new login (still persisted afterwards). Context overrides
    /// (`--role`, `--warehouse`, `--database`, `--schema`) ride along with
    /// a fresh login; on a restored session they are applied with `USE`.
    pub async fn connect(cli: &Cli, fresh: bool) -> Result<Self, CliError> {
        let client = Self::build(cli, fresh)?;
        if client.restored {
            client.apply_context(&cli.context).await?;
        }
        Ok(client)
    }

    async fn apply_context(&self, ctx: &ContextOverrides) -> Result<(), CliError> {
        let uses = [
            ("ROLE", &ctx.role),
            ("WAREHOUSE", &ctx.warehouse),
            ("DATABASE", &ctx.database),
            ("SCHEMA", &ctx.schema),
        ];
        for (kind, value) in uses {
            if let Some(name) = value {
                let sql = format!("USE {kind} {}", quote_identifier(name));
                log::info!("restored session: {sql}");
                self.api.exec(&sql).await?;
            }
        }
        Ok(())
    }

    fn build(cli: &Cli, fresh: bool) -> Result<Self, CliError> {
        let target = Target::resolve(cli)?;
        let store = if cli.no_session {
            None
        } else {
            Some(SessionStore::from_env()?)
        };
        let snapshot = match (&store, fresh) {
            (Some(store), false) => store.load(&target.host, &target.user),
            _ => None,
        };
        let restored = snapshot.is_some();

        let mut builder = SnowflakeApiBuilder::from_connection_config(target.config.clone())?
            .with_application(format!("firn-cli/{}", env!("CARGO_PKG_VERSION")));
        if let Some(cache) = target.token_cache()? {
            builder = builder.with_token_cache(cache);
        }
        if let Some(snapshot) = snapshot {
            builder = builder.with_session_snapshot(snapshot);
        }
        if cli.headless {
            let handler: SsoUrlHandler = Arc::new(|url: &str| {
                eprintln!("Open this URL in a browser to finish signing in:\n{url}");
            });
            builder = builder.with_sso_url_handler(handler);
        }
        log::info!(
            "connection {} host {} user {}",
            target.config.name.as_deref().unwrap_or("-"),
            target.host,
            target.user
        );
        Ok(Self {
            api: builder.build()?,
            account: target.config.account.clone(),
            store,
            restored,
        })
    }

    /// Persist the live session for the next invocation. Call once the
    /// command is done; errors here are logged, never fatal.
    pub fn finish(&self) {
        let Some(store) = &self.store else {
            return;
        };
        if let Some(snapshot) = self.api.session_snapshot() {
            if let Err(e) = store.save(&snapshot) {
                log::warn!("could not save session: {e}");
            }
        }
    }
}

/// Identifiers from the command line are used as typed unless already
/// quoted; a `db.schema` path stays a path.
fn quote_identifier(name: &str) -> String {
    let plain = name.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    });
    if plain || name.starts_with('"') {
        name.to_owned()
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

#[cfg(test)]
mod tests {
    use super::quote_identifier;

    #[test]
    fn identifiers_are_quoted_only_when_needed() {
        assert_eq!(quote_identifier("SANDBOX_DB"), "SANDBOX_DB");
        assert_eq!(quote_identifier("db.schema"), "db.schema");
        assert_eq!(quote_identifier("\"Odd Name\""), "\"Odd Name\"");
        assert_eq!(quote_identifier("odd name"), "\"odd name\"");
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
    }
}
