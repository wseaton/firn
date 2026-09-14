use std::path::PathBuf;

use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, LoggerHandle, Naming};

use crate::error::CliError;

pub const LOG_DIR_ENV: &str = "FIRN_LOG_DIR";
const KEEP_LOG_FILES: usize = 7;

/// `$FIRN_LOG_DIR`, else the platform data dir (`~/Library/Application
/// Support/firn/logs`, `~/.local/share/firn/logs`, `%APPDATA%\firn\logs`).
pub fn log_dir() -> Result<PathBuf, CliError> {
    if let Some(dir) = std::env::var_os(LOG_DIR_ENV).filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::data_dir()
        .map(|d| d.join("firn").join("logs"))
        .ok_or_else(|| CliError::Usage(format!("no data dir; set {LOG_DIR_ENV}")))
}

/// Always-on daily-rotated file log, plus stderr at the level `-v` asks
/// for. The file gets one line per connection and query at info; `-vv`
/// raises it to debug, `-vvv` or `--trace` to trace with HTTP detail.
/// Secrets are redacted by the crate's `Debug` impls before they reach here.
pub fn init(verbosity: u8, trace: bool) -> Result<LoggerHandle, CliError> {
    let dir = log_dir()?;
    let file_spec = match (trace, verbosity) {
        (true, _) | (false, 3..) => {
            "info, firn=trace, firn_cli=trace, reqwest=trace, hyper_util=debug, rustls=debug"
        }
        (false, 2) => "warn, firn=debug, firn_cli=debug",
        (false, _) => "warn, firn=info, firn_cli=info",
    };
    let stderr = match verbosity {
        0 => Duplicate::Warn,
        1 => Duplicate::Info,
        2 => Duplicate::Debug,
        _ => Duplicate::Trace,
    };
    std::fs::create_dir_all(&dir)?;
    set_private_dir(&dir)?;
    let handle = flexi_logger::Logger::try_with_str(file_spec)
        .map_err(|e| CliError::Usage(format!("bad log spec: {e}")))?
        .log_to_file(
            FileSpec::default()
                .directory(&dir)
                .basename("firn")
                .suppress_timestamp(),
        )
        .append()
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(KEEP_LOG_FILES),
        )
        .format_for_files(flexi_logger::detailed_format)
        .format_for_stderr(flexi_logger::default_format)
        .duplicate_to_stderr(stderr)
        .start()
        .map_err(|e| CliError::Usage(format!("cannot open log file in {}: {e}", dir.display())))?;
    log::info!(
        "firn {} pid {} argv {:?}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        std::env::args().skip(1).collect::<Vec<_>>()
    );
    Ok(handle)
}

#[cfg(unix)]
fn set_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}
