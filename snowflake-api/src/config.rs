//! `connections.toml` / `config.toml` and `SNOWFLAKE_*` environment loading.
//!
//! Follows the shared client config spec so a connection defined for `snow`,
//! the Python connector, or gosnowflake works here unchanged:
//!
//! ```text
//! config dir  = $SNOWFLAKE_HOME
//!             | ~/.snowflake                       (if it exists)
//!             | ~/Library/Application Support/snowflake   (macOS)
//!             | ~/.config/snowflake               (Linux)
//!             | %LOCALAPPDATA%\snowflake          (Windows)
//!
//! connections = <dir>/connections.toml   [name]              (preferred)
//!             | <dir>/config.toml        [connections.name]
//!
//! precedence  = SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>
//!             > file
//!             > SNOWFLAKE_<KEY>
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use secrecy::SecretString;
use thiserror::Error;
use url::Url;

use crate::{AuthArgs, AuthType};

pub const SNOWFLAKE_HOME_ENV: &str = "SNOWFLAKE_HOME";
pub const DEFAULT_CONNECTION_NAME_ENV: &str = "SNOWFLAKE_DEFAULT_CONNECTION_NAME";
pub const CONNECTIONS_FILE: &str = "connections.toml";
pub const CONFIG_FILE: &str = "config.toml";
const SKIP_PERMISSION_CHECK_ENVS: [&str; 2] = [
    "SF_SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION",
    "SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION",
];
const DEFAULT_CONNECTION_NAME: &str = "default";
const DEFAULT_DOMAIN: &str = "snowflakecomputing.com";
const CN_DOMAIN: &str = "snowflakecomputing.cn";

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("no home directory; set {SNOWFLAKE_HOME_ENV}")]
    NoConfigDir,

    #[error(
        "no connections file: neither {connections} nor a [connections] table in {config} exists"
    )]
    NoConnectionsFile {
        connections: PathBuf,
        config: PathBuf,
    },

    #[error("connection `{name}` not found in {path}; available: {available:?}")]
    ConnectionNotFound {
        name: String,
        path: PathBuf,
        available: Vec<String>,
    },

    #[error("{path} is writable or executable by group/others (mode {mode:o})")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("{path}: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("connection parameter `{key}` has an invalid value: {reason}")]
    InvalidValue { key: String, reason: String },

    #[error("connection parameter `{0}` is required")]
    Missing(&'static str),

    #[error("authenticator `{0}` is not supported")]
    UnsupportedAuthenticator(String),

    #[error("private_key_file_pwd is set but the cert-auth feature is off")]
    EncryptedKeyUnsupported,

    #[cfg(feature = "cert-auth")]
    #[error("could not decrypt private key: {0}")]
    PrivateKeyDecrypt(#[from] pkcs8::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),
}

/// One connection's parameters before they are turned into auth arguments.
/// Field names follow the TOML keys; unknown keys land in `extra`.
#[derive(Debug, Default, Clone)]
pub struct ConnectionConfig {
    pub name: Option<String>,
    pub account: Option<String>,
    pub user: Option<String>,
    pub password: Option<SecretString>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub region: Option<String>,
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    /// Lowercased raw value of `authenticator`.
    pub authenticator: Option<String>,
    pub token: Option<SecretString>,
    pub token_file_path: Option<PathBuf>,
    /// PEM contents (`private_key_raw` in the TOML, `SNOWFLAKE_PRIVATE_KEY` in the env).
    pub private_key: Option<SecretString>,
    pub private_key_file: Option<PathBuf>,
    pub private_key_file_pwd: Option<SecretString>,
    pub passcode: Option<SecretString>,
    pub client_store_temporary_credential: Option<bool>,
    pub client_request_mfa_token: Option<bool>,
    pub login_timeout: Option<Duration>,
    pub application: Option<String>,
    pub extra: BTreeMap<String, String>,
}

/// Where the config files live.
pub fn config_dir() -> Result<PathBuf, ConfigError> {
    if let Some(home) = std::env::var_os(SNOWFLAKE_HOME_ENV).filter(|h| !h.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(dot) = dirs::home_dir().map(|h| h.join(".snowflake")) {
        if dot.is_dir() {
            return Ok(dot);
        }
    }
    let base = if cfg!(windows) {
        dirs::data_local_dir()
    } else {
        dirs::config_dir()
    };
    base.map(|b| b.join("snowflake"))
        .ok_or(ConfigError::NoConfigDir)
}

/// `SNOWFLAKE_DEFAULT_CONNECTION_NAME`, then `default_connection_name` in
/// `config.toml`, then `"default"`.
pub fn default_connection_name(dir: &Path) -> Result<String, ConfigError> {
    if let Some(name) = std::env::var_os(DEFAULT_CONNECTION_NAME_ENV)
        .and_then(|n| n.into_string().ok())
        .filter(|n| !n.is_empty())
    {
        return Ok(name);
    }
    let config_path = dir.join(CONFIG_FILE);
    if config_path.is_file() {
        let table = read_toml(&config_path)?;
        if let Some(name) = table
            .get("default_connection_name")
            .and_then(toml::Value::as_str)
        {
            return Ok(name.to_owned());
        }
    }
    Ok(DEFAULT_CONNECTION_NAME.to_owned())
}

/// Names of every connection defined in the config dir.
pub fn list_connections(dir: &Path) -> Result<Vec<String>, ConfigError> {
    let (_, table) = connections_table(dir)?;
    Ok(table.keys().cloned().collect())
}

/// Load `name` (or the default connection) from the config dir, then apply
/// `SNOWFLAKE_CONNECTIONS_<NAME>_*` overrides and `SNOWFLAKE_*` fallbacks.
pub fn load_connection(name: Option<&str>) -> Result<ConnectionConfig, ConfigError> {
    let dir = config_dir()?;
    load_connection_from(&dir, name)
}

pub fn load_connection_from(
    dir: &Path,
    name: Option<&str>,
) -> Result<ConnectionConfig, ConfigError> {
    let name = match name {
        Some(n) => n.to_owned(),
        None => default_connection_name(dir)?,
    };
    let (path, table) = connections_table(dir)?;
    let Some(section) = table.get(&name).and_then(toml::Value::as_table) else {
        return Err(ConfigError::ConnectionNotFound {
            name,
            path,
            available: table.keys().cloned().collect(),
        });
    };

    let mut cfg = ConnectionConfig {
        name: Some(name.clone()),
        ..ConnectionConfig::default()
    };
    for (key, value) in section {
        cfg.apply(key, &toml_scalar(key, value)?)?;
    }

    let prefix = format!("SNOWFLAKE_CONNECTIONS_{}_", name.to_uppercase());
    for (var, value) in std::env::vars() {
        if let Some(key) = var.strip_prefix(&prefix) {
            cfg.apply(key, &value)?;
        }
    }

    cfg.fill_missing_from(ConnectionConfig::from_env()?);
    Ok(cfg)
}

fn connections_table(dir: &Path) -> Result<(PathBuf, toml::Table), ConfigError> {
    let connections_path = dir.join(CONNECTIONS_FILE);
    if connections_path.is_file() {
        let table = read_toml(&connections_path)?;
        return Ok((connections_path, table));
    }
    let config_path = dir.join(CONFIG_FILE);
    if config_path.is_file() {
        let mut table = read_toml(&config_path)?;
        if let Some(toml::Value::Table(connections)) = table.remove("connections") {
            return Ok((config_path, connections));
        }
    }
    Err(ConfigError::NoConnectionsFile {
        connections: connections_path,
        config: config_path,
    })
}

fn read_toml(path: &Path) -> Result<toml::Table, ConfigError> {
    check_permissions(path)?;
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    text.parse::<toml::Table>()
        .map_err(|source| ConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })
}

/// gosnowflake's rules: group/other write or any execute bit is fatal,
/// group/other read only warns.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    if SKIP_PERMISSION_CHECK_ENVS
        .iter()
        .any(|env| std::env::var(env).is_ok_and(|v| v.eq_ignore_ascii_case("true")))
    {
        return Ok(());
    }
    let mode = fs::metadata(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o022 != 0 || mode & 0o111 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    if mode & 0o044 != 0 {
        log::warn!(
            "{} is readable by group or others (mode {mode:o})",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

fn toml_scalar(key: &str, value: &toml::Value) -> Result<String, ConfigError> {
    match value {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Float(f) => Ok(f.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        other => Err(ConfigError::InvalidValue {
            key: key.to_owned(),
            reason: format!("expected a scalar, got {}", other.type_str()),
        }),
    }
}

/// `private_key_file` == `privateKeyFile` == `PRIVATE_KEY_FILE`.
fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidValue {
            key: key.to_owned(),
            reason: format!("expected a boolean, got `{value}`"),
        }),
    }
}

impl ConnectionConfig {
    /// Read `SNOWFLAKE_<KEY>` for every known key.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();
        for (var, value) in std::env::vars() {
            if let Some(key) = var.strip_prefix("SNOWFLAKE_") {
                if key.starts_with("CONNECTIONS_")
                    || key == "HOME"
                    || key == "DEFAULT_CONNECTION_NAME"
                {
                    continue;
                }
                cfg.apply(key, &value)?;
            }
        }
        cfg.extra.clear();
        Ok(cfg)
    }

    /// Set one parameter by its TOML / env key. Unknown keys are kept in
    /// `extra` so callers can forward them as session parameters.
    pub fn apply(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        let owned = || value.to_owned();
        let secret = || SecretString::from(value);
        match normalize_key(key).as_str() {
            "account" | "accountname" => self.account = Some(owned()),
            "user" | "username" | "login" | "loginname" => self.user = Some(owned()),
            "password" => self.password = Some(secret()),
            "host" => self.host = Some(owned()),
            "port" => {
                self.port = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| ConfigError::InvalidValue {
                            key: key.to_owned(),
                            reason: format!("expected a port number, got `{value}`"),
                        })?,
                );
            }
            "protocol" => self.protocol = Some(value.to_ascii_lowercase()),
            "region" => self.region = Some(owned()),
            "warehouse" => self.warehouse = Some(owned()),
            "database" | "dbname" => self.database = Some(owned()),
            "schema" | "schemaname" => self.schema = Some(owned()),
            "role" | "rolename" => self.role = Some(owned()),
            "authenticator" => self.authenticator = Some(value.trim().to_ascii_lowercase()),
            "token" => self.token = Some(secret()),
            "tokenfilepath" | "tokenfile" => self.token_file_path = Some(PathBuf::from(value)),
            "privatekey" | "privatekeyraw" => self.private_key = Some(secret()),
            "privatekeyfile" | "privatekeypath" => {
                self.private_key_file = Some(PathBuf::from(value));
            }
            "privatekeyfilepwd" | "privatekeypwd" | "privatekeypassphrase" => {
                self.private_key_file_pwd = Some(secret());
            }
            "passcode" => self.passcode = Some(secret()),
            "clientstoretemporarycredential" => {
                self.client_store_temporary_credential = Some(parse_bool(key, value)?);
            }
            "clientrequestmfatoken" => {
                self.client_request_mfa_token = Some(parse_bool(key, value)?);
            }
            "logintimeout" => {
                let secs: u64 = value
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue {
                        key: key.to_owned(),
                        reason: format!("expected seconds, got `{value}`"),
                    })?;
                self.login_timeout = Some(Duration::from_secs(secs));
            }
            "application" => self.application = Some(owned()),
            _ => {
                self.extra.insert(key.to_owned(), owned());
            }
        }
        Ok(())
    }

    /// Fill every unset field from `other`. `extra` keys are merged the same way.
    pub fn fill_missing_from(&mut self, other: Self) {
        macro_rules! fill {
            ($($field:ident),*) => {
                $( if self.$field.is_none() { self.$field = other.$field; } )*
            };
        }
        fill!(
            account,
            user,
            password,
            host,
            port,
            protocol,
            region,
            warehouse,
            database,
            schema,
            role,
            authenticator,
            token,
            token_file_path,
            private_key,
            private_key_file,
            private_key_file_pwd,
            passcode,
            client_store_temporary_credential,
            client_request_mfa_token,
            login_timeout,
            application
        );
        for (k, v) in other.extra {
            self.extra.entry(k).or_insert(v);
        }
    }

    /// Account identifier, derived from the host when not set explicitly.
    pub fn account_identifier(&self) -> Result<String, ConfigError> {
        if let Some(account) = &self.account {
            return Ok(account.clone());
        }
        self.host
            .as_deref()
            .and_then(|h| h.split('.').next())
            .filter(|a| !a.is_empty())
            .map(str::to_owned)
            .ok_or(ConfigError::Missing("account"))
    }

    /// `protocol://host:port/` following gosnowflake's account-to-host rules.
    pub fn base_url(&self) -> Result<Url, ConfigError> {
        let host = match &self.host {
            Some(h) if !h.is_empty() => h.clone(),
            _ => {
                let account = self.account_identifier()?;
                match self.region.as_deref().filter(|r| !r.is_empty()) {
                    Some(region) => {
                        let domain = if region.starts_with("cn-") {
                            CN_DOMAIN
                        } else {
                            DEFAULT_DOMAIN
                        };
                        format!("{account}.{region}.{domain}")
                    }
                    None => format!("{account}.{DEFAULT_DOMAIN}"),
                }
            }
        };
        let protocol = self.protocol.as_deref().unwrap_or("https");
        let port = self.port.unwrap_or(443);
        Ok(Url::parse(&format!("{protocol}://{host}:{port}/"))?)
    }

    /// Resolve the token from `token` or `token_file_path`.
    pub fn resolve_token(&self) -> Result<Option<SecretString>, ConfigError> {
        if let Some(path) = &self.token_file_path {
            let text = read_secret_file(path)?;
            return Ok(Some(SecretString::from(text.trim().to_owned())));
        }
        Ok(self.token.clone())
    }

    /// Resolve the private key PEM from `private_key` or `private_key_file`,
    /// decrypting it when `private_key_file_pwd` is set.
    pub fn resolve_private_key(&self) -> Result<Option<SecretString>, ConfigError> {
        let pem = match (&self.private_key, &self.private_key_file) {
            (Some(pem), _) => pem.clone(),
            (None, Some(path)) => SecretString::from(read_secret_file(path)?),
            (None, None) => return Ok(None),
        };
        match &self.private_key_file_pwd {
            None => Ok(Some(pem)),
            #[cfg(feature = "cert-auth")]
            Some(pwd) => {
                use secrecy::ExposeSecret;
                Ok(Some(decrypt_private_key_pem(
                    pem.expose_secret(),
                    pwd.expose_secret(),
                )?))
            }
            #[cfg(not(feature = "cert-auth"))]
            Some(_) => Err(ConfigError::EncryptedKeyUnsupported),
        }
    }
}

impl ConnectionConfig {
    /// Pick the auth method from `authenticator` and the credentials present.
    /// With no authenticator the order is password, then private key, then
    /// token, which matches what `SnowflakeApi::from_env` always did.
    pub fn into_auth_args(self) -> Result<AuthArgs, ConfigError> {
        let base_url = self.base_url()?;
        let account_identifier = self.account_identifier()?;
        let username = self.user.clone().ok_or(ConfigError::Missing("user"))?;

        let auth_type = match self.authenticator.as_deref().unwrap_or_default() {
            "" | "snowflake" => {
                if let Some(password) = self.password.clone() {
                    AuthType::Password {
                        password,
                        passcode: self.passcode.clone(),
                    }
                } else if let Some(private_key_pem) = self.resolve_private_key()? {
                    AuthType::Certificate { private_key_pem }
                } else if let Some(token) = self.resolve_token()? {
                    AuthType::OAuth { token }
                } else {
                    return Err(ConfigError::Missing(
                        "password, private_key_file, private_key, or token",
                    ));
                }
            }
            "snowflake_jwt" => AuthType::Certificate {
                private_key_pem: self
                    .resolve_private_key()?
                    .ok_or(ConfigError::Missing("private_key_file or private_key"))?,
            },
            "oauth" => AuthType::OAuth {
                token: self
                    .resolve_token()?
                    .ok_or(ConfigError::Missing("token or token_file_path"))?,
            },
            "programmatic_access_token" | "pat" => AuthType::ProgrammaticAccessToken {
                token: self
                    .resolve_token()?
                    .ok_or(ConfigError::Missing("token or token_file_path"))?,
            },
            "username_password_mfa" => AuthType::UsernamePasswordMfa {
                password: self
                    .password
                    .clone()
                    .ok_or(ConfigError::Missing("password"))?,
                passcode: self.passcode.clone(),
            },
            #[cfg(feature = "browser-auth")]
            "externalbrowser" => AuthType::ExternalBrowser,
            other => return Err(ConfigError::UnsupportedAuthenticator(other.to_owned())),
        };

        Ok(AuthArgs {
            account_identifier,
            warehouse: self.warehouse,
            database: self.database,
            schema: self.schema,
            username,
            role: self.role,
            auth_type,
            base_url: Some(base_url),
        })
    }
}

/// Passphrase-protected PKCS#8 PEM (`ENCRYPTED PRIVATE KEY`) to plain PKCS#8
/// PEM, which is what `snowflake_jwt::generate_jwt_token` accepts.
#[cfg(feature = "cert-auth")]
fn decrypt_private_key_pem(
    encrypted_pem: &str,
    passphrase: &str,
) -> Result<SecretString, ConfigError> {
    use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    let key = rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(encrypted_pem, passphrase)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    Ok(SecretString::from(pem.to_string()))
}

fn read_secret_file(path: &Path) -> Result<String, ConfigError> {
    check_permissions(path)?;
    fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    // Tests mutate process env; serialize them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard(Vec<(String, Option<String>)>);

    impl EnvGuard {
        fn set(vars: &[(&str, Option<&str>)]) -> Self {
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

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "firn-config-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_private(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    const CLEAN_ENV: &[(&str, Option<&str>)] = &[
        ("SNOWFLAKE_HOME", None),
        ("SNOWFLAKE_DEFAULT_CONNECTION_NAME", None),
        ("SNOWFLAKE_ACCOUNT", None),
        ("SNOWFLAKE_USER", None),
        ("SNOWFLAKE_PASSWORD", None),
        ("SNOWFLAKE_WAREHOUSE", None),
        ("SNOWFLAKE_ROLE", None),
        ("SNOWFLAKE_AUTHENTICATOR", None),
        ("SNOWFLAKE_TOKEN", None),
        ("SNOWFLAKE_PRIVATE_KEY", None),
        ("SNOWFLAKE_CONNECTIONS_DEV_ROLE", None),
        ("SNOWFLAKE_CONNECTIONS_DEV_PORT", None),
    ];

    #[test]
    fn loads_named_connection_from_connections_toml() {
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(CLEAN_ENV);
        let dir = tempdir();
        write_private(
            &dir.join(CONNECTIONS_FILE),
            r#"
[dev]
account = "myorg-myacct"
user = "alice"
password = "hunter2"
warehouse = "WH"
authenticator = "SNOWFLAKE"
private_key_file = "/keys/dev.p8"
client_store_temporary_credential = true
login_timeout = 42
custom_thing = "kept"

[prod]
account = "other"
"#,
        );
        let cfg = load_connection_from(&dir, Some("dev")).unwrap();
        assert_eq!(cfg.name.as_deref(), Some("dev"));
        assert_eq!(cfg.account.as_deref(), Some("myorg-myacct"));
        assert_eq!(cfg.user.as_deref(), Some("alice"));
        assert_eq!(cfg.password.as_ref().unwrap().expose_secret(), "hunter2");
        assert_eq!(cfg.warehouse.as_deref(), Some("WH"));
        assert_eq!(cfg.authenticator.as_deref(), Some("snowflake"));
        assert_eq!(
            cfg.private_key_file.as_deref(),
            Some(Path::new("/keys/dev.p8"))
        );
        assert_eq!(cfg.client_store_temporary_credential, Some(true));
        assert_eq!(cfg.login_timeout, Some(Duration::from_secs(42)));
        assert_eq!(
            cfg.extra.get("custom_thing").map(String::as_str),
            Some("kept")
        );
        assert_eq!(
            list_connections(&dir).unwrap(),
            vec!["dev".to_owned(), "prod".to_owned()]
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn falls_back_to_config_toml_connections_table_and_default_name() {
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(CLEAN_ENV);
        let dir = tempdir();
        write_private(
            &dir.join(CONFIG_FILE),
            r#"
default_connection_name = "sandbox"

[cli.logs]
level = "info"

[connections.sandbox]
account = "sb"
user = "bob"
authenticator = "externalbrowser"
host = "sb.eu-west-1.snowflakecomputing.com"
"#,
        );
        let cfg = load_connection_from(&dir, None).unwrap();
        assert_eq!(cfg.name.as_deref(), Some("sandbox"));
        assert_eq!(cfg.authenticator.as_deref(), Some("externalbrowser"));
        assert_eq!(
            cfg.base_url().unwrap().as_str(),
            "https://sb.eu-west-1.snowflakecomputing.com/"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn connections_toml_wins_over_config_toml() {
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(CLEAN_ENV);
        let dir = tempdir();
        write_private(
            &dir.join(CONNECTIONS_FILE),
            "[a]\naccount = \"from-connections\"\n",
        );
        write_private(
            &dir.join(CONFIG_FILE),
            "[connections.a]\naccount = \"from-config\"\n",
        );
        let cfg = load_connection_from(&dir, Some("a")).unwrap();
        assert_eq!(cfg.account.as_deref(), Some("from-connections"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn env_precedence_connection_scoped_over_file_over_generic() {
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(&[
            ("SNOWFLAKE_HOME", None),
            ("SNOWFLAKE_DEFAULT_CONNECTION_NAME", Some("dev")),
            ("SNOWFLAKE_CONNECTIONS_DEV_ROLE", Some("FROM_SCOPED_ENV")),
            ("SNOWFLAKE_CONNECTIONS_DEV_PORT", Some("8443")),
            ("SNOWFLAKE_ROLE", Some("FROM_GENERIC_ENV")),
            ("SNOWFLAKE_WAREHOUSE", Some("GENERIC_WH")),
            ("SNOWFLAKE_ACCOUNT", None),
            ("SNOWFLAKE_USER", None),
            ("SNOWFLAKE_PASSWORD", None),
            ("SNOWFLAKE_AUTHENTICATOR", None),
            ("SNOWFLAKE_TOKEN", None),
            ("SNOWFLAKE_PRIVATE_KEY", None),
        ]);
        let dir = tempdir();
        write_private(
            &dir.join(CONNECTIONS_FILE),
            "[dev]\naccount = \"acct\"\nrole = \"FROM_FILE\"\n",
        );
        let cfg = load_connection_from(&dir, None).unwrap();
        assert_eq!(cfg.role.as_deref(), Some("FROM_SCOPED_ENV"));
        assert_eq!(cfg.port, Some(8443));
        assert_eq!(cfg.warehouse.as_deref(), Some("GENERIC_WH"));
        assert_eq!(
            cfg.base_url().unwrap().as_str(),
            "https://acct.snowflakecomputing.com:8443/"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_connection_lists_available_names() {
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(CLEAN_ENV);
        let dir = tempdir();
        write_private(
            &dir.join(CONNECTIONS_FILE),
            "[a]\naccount = \"x\"\n[b]\naccount = \"y\"\n",
        );
        let err = load_connection_from(&dir, Some("zzz")).unwrap_err();
        match err {
            ConfigError::ConnectionNotFound {
                name, available, ..
            } => {
                assert_eq!(name, "zzz");
                assert_eq!(available, vec!["a".to_owned(), "b".to_owned()]);
            }
            other => panic!("unexpected error {other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_config_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let _l = ENV_LOCK.lock().unwrap();
        let _env = EnvGuard::set(&[
            ("SF_SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION", None),
            ("SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION", None),
        ]);
        let dir = tempdir();
        let path = dir.join(CONNECTIONS_FILE);
        fs::write(&path, "[a]\naccount = \"x\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            load_connection_from(&dir, Some("a")),
            Err(ConfigError::InsecurePermissions { mode: 0o666, .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn key_normalization_accepts_camel_snake_and_upper() {
        let mut cfg = ConnectionConfig::default();
        cfg.apply("privateKeyFile", "/a").unwrap();
        cfg.apply("TOKEN_FILE_PATH", "/t").unwrap();
        cfg.apply("clientRequestMfaToken", "yes").unwrap();
        cfg.apply("LOGIN_TIMEOUT", "7").unwrap();
        assert_eq!(cfg.private_key_file.as_deref(), Some(Path::new("/a")));
        assert_eq!(cfg.token_file_path.as_deref(), Some(Path::new("/t")));
        assert_eq!(cfg.client_request_mfa_token, Some(true));
        assert_eq!(cfg.login_timeout, Some(Duration::from_secs(7)));
        assert!(matches!(
            cfg.apply("port", "nope"),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn base_url_from_account_region_and_explicit_host() {
        let mut cfg = ConnectionConfig {
            account: Some("acct".into()),
            ..Default::default()
        };
        assert_eq!(
            cfg.base_url().unwrap().as_str(),
            "https://acct.snowflakecomputing.com/"
        );
        cfg.region = Some("cn-north-1".into());
        assert_eq!(
            cfg.base_url().unwrap().as_str(),
            "https://acct.cn-north-1.snowflakecomputing.cn/"
        );
        cfg.host = Some("acct.privatelink.snowflakecomputing.com".into());
        cfg.protocol = Some("http".into());
        cfg.port = Some(8080);
        assert_eq!(
            cfg.base_url().unwrap().as_str(),
            "http://acct.privatelink.snowflakecomputing.com:8080/"
        );
        let host_only = ConnectionConfig {
            host: Some("derived.snowflakecomputing.com".into()),
            ..Default::default()
        };
        assert_eq!(host_only.account_identifier().unwrap(), "derived");
        assert!(matches!(
            ConnectionConfig::default().base_url(),
            Err(ConfigError::Missing("account"))
        ));
    }

    #[test]
    fn token_file_path_wins_over_inline_token() {
        let dir = tempdir();
        let path = dir.join("token");
        write_private(&path, "  file-token\n");
        let cfg = ConnectionConfig {
            token: Some(SecretString::from("inline")),
            token_file_path: Some(path),
            ..Default::default()
        };
        assert_eq!(
            cfg.resolve_token().unwrap().unwrap().expose_secret(),
            "file-token"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn auth_dispatch_without_authenticator_prefers_password_then_key_then_token() {
        let base = ConnectionConfig {
            account: Some("a".into()),
            user: Some("u".into()),
            ..Default::default()
        };
        let pw = ConnectionConfig {
            password: Some(SecretString::from("p")),
            private_key: Some(SecretString::from("pem")),
            token: Some(SecretString::from("t")),
            ..base.clone()
        };
        assert!(matches!(
            pw.into_auth_args().unwrap().auth_type,
            AuthType::Password { .. }
        ));
        let key = ConnectionConfig {
            private_key: Some(SecretString::from("pem")),
            token: Some(SecretString::from("t")),
            ..base.clone()
        };
        assert!(matches!(
            key.into_auth_args().unwrap().auth_type,
            AuthType::Certificate { .. }
        ));
        let tok = ConnectionConfig {
            token: Some(SecretString::from("t")),
            ..base.clone()
        };
        assert!(matches!(
            tok.into_auth_args().unwrap().auth_type,
            AuthType::OAuth { .. }
        ));
        assert!(matches!(
            base.into_auth_args(),
            Err(ConfigError::Missing(_))
        ));
    }

    #[test]
    fn auth_dispatch_by_authenticator() {
        let base = ConnectionConfig {
            account: Some("a".into()),
            user: Some("u".into()),
            password: Some(SecretString::from("p")),
            passcode: Some(SecretString::from("123456")),
            token: Some(SecretString::from("t")),
            ..Default::default()
        };
        let with = |auth: &str| ConnectionConfig {
            authenticator: Some(auth.into()),
            ..base.clone()
        };
        assert!(matches!(
            with("programmatic_access_token")
                .into_auth_args()
                .unwrap()
                .auth_type,
            AuthType::ProgrammaticAccessToken { .. }
        ));
        assert!(matches!(
            with("oauth").into_auth_args().unwrap().auth_type,
            AuthType::OAuth { .. }
        ));
        match with("username_password_mfa")
            .into_auth_args()
            .unwrap()
            .auth_type
        {
            AuthType::UsernamePasswordMfa { passcode, .. } => {
                assert_eq!(passcode.unwrap().expose_secret(), "123456");
            }
            _ => panic!("expected MFA"),
        }
        #[cfg(feature = "browser-auth")]
        assert!(matches!(
            with("externalbrowser").into_auth_args().unwrap().auth_type,
            AuthType::ExternalBrowser
        ));
        assert!(matches!(
            with("workload_identity").into_auth_args(),
            Err(ConfigError::UnsupportedAuthenticator(_))
        ));
        assert!(matches!(
            with("snowflake_jwt").into_auth_args(),
            Err(ConfigError::Missing(_))
        ));
        let args = with("pat").into_auth_args().unwrap();
        assert_eq!(args.account_identifier, "a");
        assert_eq!(
            args.base_url.unwrap().as_str(),
            "https://a.snowflakecomputing.com/"
        );
    }
}
