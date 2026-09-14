//! Persistent cache for long-lived credentials Snowflake hands back after an
//! interactive login (SSO id tokens, MFA tokens, OAuth tokens).
//!
//! The on-disk layout of [`FileTokenCache`] matches the Python connector's
//! `credential_cache_v1.json` so `snow` and this crate share tokens on Linux.
//! Keys are `sha256("{HOST}:{USER}:{KIND}")` with every component uppercased.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CACHE_DIR_ENV: &str = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR";
pub const CACHE_FILE_NAME: &str = "credential_cache_v1.json";

#[derive(Error, Debug)]
pub enum TokenCacheError {
    #[error("credential key needs a non-empty host and user")]
    EmptyKeyComponent,

    #[error("could not resolve a cache directory: set {CACHE_DIR_ENV}, XDG_CACHE_HOME, or HOME")]
    NoCacheDir,

    #[error("{path} is accessible by group or others (mode {mode:o}); refusing to use it")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("cache file {path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("cache file {path} is not valid JSON: {source}")]
    Corrupt {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("cache lock poisoned")]
    Poisoned,

    #[cfg(feature = "keyring")]
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    IdToken,
    MfaToken,
    OAuthAccessToken,
    OAuthRefreshToken,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => "ID_TOKEN",
            Self::MfaToken => "MFA_TOKEN",
            Self::OAuthAccessToken => "OAUTH_ACCESS_TOKEN",
            Self::OAuthRefreshToken => "OAUTH_REFRESH_TOKEN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialKey {
    host: String,
    user: String,
    kind: CredentialKind,
}

impl CredentialKey {
    pub fn new(host: &str, user: &str, kind: CredentialKind) -> Result<Self, TokenCacheError> {
        if host.is_empty() || user.is_empty() {
            return Err(TokenCacheError::EmptyKeyComponent);
        }
        Ok(Self {
            host: host.to_uppercase(),
            user: user.to_uppercase(),
            kind,
        })
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    pub fn string_key(&self) -> String {
        format!("{}:{}:{}", self.host, self.user, self.kind.as_str())
    }

    pub fn hash_key(&self) -> String {
        let digest = Sha256::digest(self.string_key().as_bytes());
        let mut out = String::with_capacity(64);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

pub trait TokenCache: Send + Sync + fmt::Debug {
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, TokenCacheError>;
    fn set(&self, key: &CredentialKey, token: &SecretString) -> Result<(), TokenCacheError>;
    fn remove(&self, key: &CredentialKey) -> Result<(), TokenCacheError>;
}

/// Process-local cache. Useful for tests and for long-lived services that
/// want id-token replay without touching disk.
#[derive(Default)]
pub struct MemoryTokenCache {
    tokens: Mutex<HashMap<String, SecretString>>,
}

impl MemoryTokenCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for MemoryTokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.tokens.lock().map_or(0, |t| t.len());
        f.debug_struct("MemoryTokenCache")
            .field("entries", &n)
            .finish()
    }
}

impl TokenCache for MemoryTokenCache {
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, TokenCacheError> {
        let tokens = self.tokens.lock().map_err(|_| TokenCacheError::Poisoned)?;
        Ok(tokens.get(&key.hash_key()).cloned())
    }

    fn set(&self, key: &CredentialKey, token: &SecretString) -> Result<(), TokenCacheError> {
        let mut tokens = self.tokens.lock().map_err(|_| TokenCacheError::Poisoned)?;
        tokens.insert(key.hash_key(), token.clone());
        Ok(())
    }

    fn remove(&self, key: &CredentialKey) -> Result<(), TokenCacheError> {
        let mut tokens = self.tokens.lock().map_err(|_| TokenCacheError::Poisoned)?;
        tokens.remove(&key.hash_key());
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    #[serde(default)]
    tokens: HashMap<String, String>,
}

/// JSON file cache compatible with the Python connector's Linux layout.
/// Writes go through a temp file and rename so readers never see a torn file.
#[derive(Debug)]
pub struct FileTokenCache {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl FileTokenCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    /// `$SF_TEMPORARY_CREDENTIAL_CACHE_DIR`, then `$XDG_CACHE_HOME/snowflake`,
    /// then `$HOME/.cache/snowflake`.
    pub fn default_dir() -> Result<PathBuf, TokenCacheError> {
        if let Some(dir) = std::env::var_os(CACHE_DIR_ENV).filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(dir));
        }
        if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(xdg).join("snowflake"));
        }
        std::env::var_os("HOME")
            .filter(|d| !d.is_empty())
            .map(|home| PathBuf::from(home).join(".cache").join("snowflake"))
            .ok_or(TokenCacheError::NoCacheDir)
    }

    pub fn from_default_dir() -> Result<Self, TokenCacheError> {
        Ok(Self::new(Self::default_dir()?.join(CACHE_FILE_NAME)))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn io(&self, source: io::Error) -> TokenCacheError {
        TokenCacheError::Io {
            path: self.path.clone(),
            source,
        }
    }

    fn read(&self) -> Result<CacheFile, TokenCacheError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(CacheFile::default()),
            Err(e) => return Err(self.io(e)),
        };
        check_private(&self.path)?;
        serde_json::from_slice(&bytes).map_err(|source| TokenCacheError::Corrupt {
            path: self.path.clone(),
            source,
        })
    }

    fn write(&self, file: &CacheFile) -> Result<(), TokenCacheError> {
        let dir = self.path.parent().ok_or(TokenCacheError::NoCacheDir)?;
        fs::create_dir_all(dir).map_err(|e| self.io(e))?;
        set_private_dir(dir).map_err(|e| self.io(e))?;

        let tmp = dir.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(CACHE_FILE_NAME),
            std::process::id()
        ));
        let body = serde_json::to_vec(file).map_err(|source| TokenCacheError::Corrupt {
            path: self.path.clone(),
            source,
        })?;
        write_private(&tmp, &body).map_err(|e| self.io(e))?;
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            self.io(e)
        })
    }

    fn update(&self, f: impl FnOnce(&mut HashMap<String, String>)) -> Result<(), TokenCacheError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| TokenCacheError::Poisoned)?;
        let mut file = self.read()?;
        f(&mut file.tokens);
        self.write(&file)
    }
}

impl TokenCache for FileTokenCache {
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, TokenCacheError> {
        let file = self.read()?;
        Ok(file
            .tokens
            .get(&key.hash_key())
            .map(|t| SecretString::from(t.as_str())))
    }

    fn set(&self, key: &CredentialKey, token: &SecretString) -> Result<(), TokenCacheError> {
        let hash = key.hash_key();
        let token = token.expose_secret().to_owned();
        self.update(|tokens| {
            tokens.insert(hash, token);
        })
    }

    fn remove(&self, key: &CredentialKey) -> Result<(), TokenCacheError> {
        let hash = key.hash_key();
        self.update(|tokens| {
            tokens.remove(&hash);
        })
    }
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), TokenCacheError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| TokenCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(TokenCacheError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), TokenCacheError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    fs::write(path, body)
}

/// OS credential store backend (macOS Keychain, Windows Credential Manager,
/// Linux Secret Service). Entries live under `service` with the hashed key
/// as the account, which is the layout the Python connector uses, so the
/// default service name lets `snow` and this crate share tokens.
#[cfg(feature = "keyring")]
#[derive(Debug, Clone)]
pub struct KeyringTokenCache {
    service: String,
}

#[cfg(feature = "keyring")]
impl KeyringTokenCache {
    pub const PYTHON_CONNECTOR_SERVICE: &'static str = "com.snowflake.connector.python";

    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &CredentialKey) -> Result<keyring::Entry, TokenCacheError> {
        Ok(keyring::Entry::new(&self.service, &key.hash_key())?)
    }
}

#[cfg(feature = "keyring")]
impl Default for KeyringTokenCache {
    fn default() -> Self {
        Self::new(Self::PYTHON_CONNECTOR_SERVICE)
    }
}

#[cfg(feature = "keyring")]
impl TokenCache for KeyringTokenCache {
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, TokenCacheError> {
        match self.entry(key)?.get_password() {
            Ok(token) => Ok(Some(SecretString::from(token))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &CredentialKey, token: &SecretString) -> Result<(), TokenCacheError> {
        Ok(self.entry(key)?.set_password(token.expose_secret())?)
    }

    fn remove(&self, key: &CredentialKey) -> Result<(), TokenCacheError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> CredentialKey {
        CredentialKey::new(
            "myorg-myacct.snowflakecomputing.com",
            "alice",
            CredentialKind::IdToken,
        )
        .unwrap()
    }

    #[test]
    fn string_key_is_uppercased_host_user_kind() {
        assert_eq!(
            key().string_key(),
            "MYORG-MYACCT.SNOWFLAKECOMPUTING.COM:ALICE:ID_TOKEN"
        );
    }

    #[test]
    fn hash_key_matches_python_connector() {
        // echo -n 'MYORG-MYACCT.SNOWFLAKECOMPUTING.COM:ALICE:ID_TOKEN' | sha256sum
        assert_eq!(
            key().hash_key(),
            "332c512e86397db396683b4f51ec91a8d7a0c14efc5c9e6d4f92112acbc71b92"
        );
    }

    #[test]
    fn empty_components_are_rejected() {
        assert!(matches!(
            CredentialKey::new("", "u", CredentialKind::MfaToken),
            Err(TokenCacheError::EmptyKeyComponent)
        ));
        assert!(matches!(
            CredentialKey::new("h", "", CredentialKind::MfaToken),
            Err(TokenCacheError::EmptyKeyComponent)
        ));
    }

    #[test]
    fn memory_cache_round_trips() {
        let cache = MemoryTokenCache::new();
        assert!(cache.get(&key()).unwrap().is_none());
        cache.set(&key(), &SecretString::from("tok")).unwrap();
        assert_eq!(cache.get(&key()).unwrap().unwrap().expose_secret(), "tok");
        cache.remove(&key()).unwrap();
        assert!(cache.get(&key()).unwrap().is_none());
    }

    #[test]
    fn file_cache_round_trips_and_uses_python_layout() {
        let dir = tempdir();
        let cache = FileTokenCache::new(dir.join("sub").join(CACHE_FILE_NAME));
        assert!(cache.get(&key()).unwrap().is_none());

        cache.set(&key(), &SecretString::from("tok")).unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(cache.path()).unwrap()).unwrap();
        assert_eq!(raw["tokens"][key().hash_key()], "tok");
        assert_eq!(cache.get(&key()).unwrap().unwrap().expose_secret(), "tok");

        let other = CredentialKey::new("h", "u", CredentialKind::MfaToken).unwrap();
        cache.set(&other, &SecretString::from("mfa")).unwrap();
        cache.remove(&key()).unwrap();
        assert!(cache.get(&key()).unwrap().is_none());
        assert_eq!(cache.get(&other).unwrap().unwrap().expose_secret(), "mfa");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = fs::metadata(cache.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
            let dir_mode = fs::metadata(cache.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn file_cache_reads_python_written_file() {
        let dir = tempdir();
        let path = dir.join(CACHE_FILE_NAME);
        fs::create_dir_all(&dir).unwrap();
        let body = format!(r#"{{"tokens": {{"{}": "from-python"}}}}"#, key().hash_key());
        write_private(&path, body.as_bytes()).unwrap();
        let cache = FileTokenCache::new(&path);
        assert_eq!(
            cache.get(&key()).unwrap().unwrap().expose_secret(),
            "from-python"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn file_cache_refuses_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.join(CACHE_FILE_NAME);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, r#"{"tokens":{}}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let cache = FileTokenCache::new(&path);
        assert!(matches!(
            cache.get(&key()),
            Err(TokenCacheError::InsecurePermissions { mode: 0o640, .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_wipe() {
        let dir = tempdir();
        let path = dir.join(CACHE_FILE_NAME);
        fs::create_dir_all(&dir).unwrap();
        write_private(&path, b"not json").unwrap();
        let cache = FileTokenCache::new(&path);
        assert!(matches!(
            cache.set(&key(), &SecretString::from("x")),
            Err(TokenCacheError::Corrupt { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), b"not json");
        let _ = fs::remove_dir_all(dir);
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "firn-token-cache-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
