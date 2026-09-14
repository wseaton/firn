//! Persisted `SessionSnapshot`s, one file per host and user, so consecutive
//! invocations share a Snowflake session.

use std::fs;
use std::path::{Path, PathBuf};

use firn::SessionSnapshot;
use sha2::{Digest, Sha256};

use crate::error::CliError;

pub const STATE_DIR_ENV: &str = "FIRN_STATE_DIR";

pub struct SessionStore {
    dir: PathBuf,
}

impl SessionStore {
    /// `$FIRN_STATE_DIR`, else the platform cache dir (`~/Library/Caches/firn`,
    /// `~/.cache/firn`, `%LOCALAPPDATA%\firn`).
    pub fn from_env() -> Result<Self, CliError> {
        let dir = match std::env::var_os(STATE_DIR_ENV).filter(|d| !d.is_empty()) {
            Some(d) => PathBuf::from(d),
            None => dirs::cache_dir()
                .map(|d| d.join("firn"))
                .ok_or_else(|| CliError::Usage(format!("no cache dir; set {STATE_DIR_ENV}")))?,
        };
        Ok(Self {
            dir: dir.join("sessions"),
        })
    }

    fn path(&self, host: &str, user: &str) -> PathBuf {
        let digest = Sha256::digest(format!("{}:{}", host.to_uppercase(), user.to_uppercase()));
        let mut name = String::with_capacity(32);
        for byte in &digest[..16] {
            use std::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        self.dir.join(format!("{name}.json"))
    }

    /// The saved session for this host and user, if it exists and its master
    /// token has not expired. An unreadable or expired file is removed.
    pub fn load(&self, host: &str, user: &str) -> Option<SessionSnapshot> {
        let path = self.path(host, user);
        let text = fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<SessionSnapshot>(&text) {
            Ok(snapshot) if !snapshot.is_expired() => {
                log::info!("restored session from {}", path.display());
                Some(snapshot)
            }
            Ok(_) => {
                log::debug!("saved session expired; removing {}", path.display());
                let _ = fs::remove_file(&path);
                None
            }
            Err(e) => {
                log::warn!("ignoring unreadable session file {}: {e}", path.display());
                let _ = fs::remove_file(&path);
                None
            }
        }
    }

    pub fn save(&self, snapshot: &SessionSnapshot) -> Result<(), CliError> {
        fs::create_dir_all(&self.dir)?;
        set_private_dir(&self.dir)?;
        let path = self.path(snapshot.host(), snapshot.user());
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        write_private(&tmp, serde_json::to_string(snapshot)?.as_bytes())?;
        fs::rename(&tmp, &path).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        log::info!("saved session to {}", path.display());
        Ok(())
    }

    pub fn remove(&self, host: &str, user: &str) -> Result<bool, CliError> {
        match fs::remove_file(self.path(host, user)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn set_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
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
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    fs::write(path, body)
}
