//! Logging for the desktop shell.
//!
//! Logs go to a rolling file under the data directory rather than to the console: a GUI
//! application has no console on Windows, and a user who wants logs should not have to open a
//! terminal first. Settings shows the directory for export.

use std::path::Path;

use tracing_subscriber::EnvFilter;

/// Initialises tracing with a rolling file appender.
///
/// The filter comes from `RUST_LOG` when set, so a developer can raise verbosity without
/// editing settings, and otherwise defaults to a level that keeps a busy capture quiet.
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinel=info,sentinel_desktop=info,warn"));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);

    // A missing data directory is not worth failing over: the app still works, and losing logs
    // is better than refusing to start.
    let Some(directory) = log_directory() else {
        builder.with_writer(std::io::stderr).init();
        tracing::warn!("log directory is unavailable; logging to stderr");
        return;
    };

    builder
        .with_writer(build_appender(&directory))
        .with_ansi(false)
        .init();

    tracing::info!(log_directory = %directory.display(), "logging initialised");
}

/// The log directory, created if absent.
fn log_directory() -> Option<std::path::PathBuf> {
    let directory = sentinel_platform::AppPaths::discover().ok()?.logs_dir;
    std::fs::create_dir_all(&directory).ok()?;
    Some(directory)
}

/// Builds a daily rolling appender named after today's date.
///
/// The date is computed from Sentinel's own clock rather than from a date-formatting crate:
/// the log filename only needs to sort chronologically, and adding a dependency for `YYYY-MM-DD`
/// would be the only reason to have one.
fn build_appender(directory: &Path) -> tracing_appender::rolling::RollingFileAppender {
    let now = sentinel_common::clock::now_unix_micros();
    let stamp = sentinel_common::clock::unix_micros_to_rfc3339(now);
    // `unix_micros_to_rfc3339` yields `YYYY-MM-DDThh:mm:ss.sssZ`; the first ten characters are
    // the date, and dropping the separators keeps the filename sortable.
    let date = stamp.get(..10).unwrap_or("unknown").replace(['-', ':'], "");
    let name = format!("sentinel-{date}.log");

    // `daily` panics only if the prefix or the rotation interval is empty, and neither can be
    // here. Returning the appender directly avoids a `Result` that could never be an error.
    tracing_appender::rolling::daily(directory, name)
}
