//! The Iklwa Sentinel command line interface.
//!
//! Every subcommand is a thin client over [`sentinel_api::Frontend`]. The CLI performs no
//! analysis of its own, which is what keeps it consistent with the desktop application: if the
//! two ever disagreed, the same logic would exist twice and one of them would be wrong.

mod commands;
mod logging;
mod output;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Sentinel: local-first network visibility and threat detection.
#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Monitor and understand your network activity, locally.",
    long_about = "Iklwa Sentinel monitors network activity on this machine, reconstructs connections, \
                  and stores the result in a local database. Nothing is sent anywhere.\n\n\
                  Packet capture needs elevated privileges on most systems; run `sentinel doctor` \
                  to check whether this build can capture at all."
)]
struct Cli {
    /// Increase log detail. Repeat for more (`-vv` is debug).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress informational output.
    #[arg(short, long)]
    quiet: bool,

    /// Emit machine-readable JSON instead of formatted text.
    #[arg(long)]
    json: bool,

    /// The command to run.
    #[command(subcommand)]
    command: Command,
}

/// The available commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// List network interfaces available for monitoring.
    Interfaces,

    /// Monitor an interface and print live statistics.
    Capture {
        /// Interface id, as shown by `sentinel interfaces`. Defaults to the best candidate.
        #[arg(short, long)]
        interface: Option<String>,

        /// Stop after this many seconds. Without it, capture runs until interrupted.
        #[arg(short, long)]
        duration: Option<u64>,

        /// Print one line per new connection instead of a periodic summary.
        #[arg(long)]
        connections: bool,
    },

    /// Print the current session state and counters.
    Status,

    /// Analyse a PCAP capture file and print what it contains.
    Analyze {
        /// Path to a classic PCAP file.
        path: PathBuf,

        /// Print every connection instead of only the busiest ones.
        #[arg(long)]
        all: bool,
    },

    /// Export stored connections as CSV or JSON.
    Export {
        /// Destination file. Defaults to `sentinel-export-<timestamp>.csv`.
        path: Option<PathBuf>,

        /// Emit JSON instead of CSV.
        #[arg(long)]
        json: bool,

        /// How many of the most recent connections to export.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },

    /// Report whether packet capture is possible in this environment, and why.
    Doctor,

    /// Remove stored data older than the configured retention period.
    Prune {
        /// Report what would be removed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },

    /// Print the version of this build and the schema it expects.
    Version,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logging::init(cli.verbose, cli.quiet)?;

    // `version` needs no engine, so it is handled before the runtime is built.
    if let Command::Version = cli.command {
        commands::version(&commands::Context {
            json: cli.json,
            quiet: cli.quiet,
        });
        return Ok(());
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let context = commands::Context {
        json: cli.json,
        quiet: cli.quiet,
    };

    runtime.block_on(async move {
        match cli.command {
            Command::Interfaces => commands::interfaces(&context).await,
            Command::Capture {
                interface,
                duration,
                connections,
            } => commands::capture(&context, interface, duration, connections).await,
            Command::Status => commands::status(&context).await,
            Command::Analyze { path, all } => commands::analyze(&context, path, all).await,
            Command::Export { path, json, limit } => {
                commands::export(&context, path, json, limit).await
            }
            Command::Doctor => commands::doctor(&context).await,
            Command::Prune { dry_run } => commands::prune(&context, dry_run).await,
            // Handled above.
            Command::Version => Ok(()),
        }
    })
}
