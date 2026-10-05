//! Logging for the desktop shell.
//!
//! Logs go to a rolling file under the data directory, not to the console: a GUI application
//! has no console to write to on Windows, and a user who wants logs should not have to launch a
//! terminal. The same file is offered in Settings for export.

use std::path::Path;

use tracing_subscriber::EnvFilter;

/// Initialises tracing with a rolling file appender.
///
/// The level comes from configuration when the file is readable, and falls back to `info`.
/// `RUST_LOG` still wins, so a developer can raise verbosity without editing settings.
pub fn init() {
    let directory = sentinel_platform::AppPaths::discover().map(|paths| paths.logs_dir);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinel=info,sentinel_desktop=info,warn"));

    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(true);

    match directory {
        Ok(directory) if ensure_log_dir(&directory) => {
            // A rolling appender needs an explicit guard to keep flushing, so the result is kept
            // alive for the life of the process. Dropping it would stop logging.
            match rolling_file(&directory) {
                Ok(guard) => {
                    builder.with_writer(guard).with_ansi(false).init();
                    tracing::info!(log_directory = %directory.display(), "logging initialised");
                    std::mem::forget(guard);
                }
                Err(err) => {
                    builder.with_writer(std::io::stderr).init();
                    tracing::warn!(error = %err, "could not open the log file; logging to stderr");
                }
            }
        }
        _ => {
            builder.with_writer(std::io::stderr).init();
            tracing::warn!("log directory is unavailable; logging to stderr");
        }
    }
}

/// Creates the log directory.
fn ensure_log_dir(directory: &Path) -> bool {
    std::fs::create_dir_all(directory).is_ok()
}

/// Builds a daily rolling file appender named after the current date.
fn rolling_file(directory: &Path) -> anyhow_lite::Result<tracing_appender::rolling::RollingFileAppender> {
    let name = format!("sentinel-{}.log", sentinel_common::clock::unix_micros_to_rfc3339(sentinel_common::clock::now_unix_micros())[..10.min(sentinel_common::clock::unix_micros_to_rfc3339(sentinel_common::clock::now_unix_micros()).len())].replace(['-', ':'], ""));
    tracing_appender::rolling::daily(directory, name)
}

/// Minimal error alias, so the logging module does not need an error crate dependency.
mod anyhow_lite {
    /// A boxed error, sufficient for the one call site above.
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
