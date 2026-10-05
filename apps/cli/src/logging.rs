//! Structured logging for the CLI.
//!
//! Logs go to stderr so that command output on stdout stays pipeable into `jq` or a file. Log
//! files are not written by the CLI: the desktop application owns rolling logs, and two
//! processes writing the same log file would fight over it.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

/// Initialises logging from verbosity flags.
///
/// `-v` enables warnings and above, `-vv` adds info, `-vvv` adds debug. Trace is deliberately
/// not reachable from the command line: per-packet tracing on a busy link produces output that
/// is not useful interactively.
pub fn init(verbose: u8, quiet: bool) -> Result<()> {
    let default_level = match (quiet, verbose) {
        (true, _) => "error",
        (_, 0) => "warn",
        (_, 1) => "info",
        (_, 2) => "debug",
        _ => "debug",
    };

    // `RUST_LOG` wins when set, so an operator can investigate without a rebuild.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sentinel={default_level},warn")));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .without_time()
        .init();

    Ok(())
}
