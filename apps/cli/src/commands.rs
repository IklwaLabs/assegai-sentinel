//! Command implementations.
//!
//! Each function is a thin sequence: ask the engine, format the answer, print it. Anything that
//! looks like a decision (which interface to prefer, what counts as "top talkers") is a
//! presentation choice made here and stated in a comment, never a security judgement.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use sentinel_api::types::{Command, CommandResult};
use sentinel_api::{ApiError, Frontend};
use sentinel_common::clock;

use crate::output::{self, Table};

/// Shared flags for a command run.
pub struct Context {
    /// Emit JSON rather than formatted text.
    pub json: bool,
    /// Suppress informational notes.
    pub quiet: bool,
}

impl Context {
    /// Prints a value in the requested format.
    fn emit<T: serde::Serialize>(&self, value: &T, human: impl FnOnce()) -> Result<()> {
        output::emit(self.json, value, human)
    }
}

/// `sentinel interfaces`
pub async fn interfaces(context: &Context) -> Result<()> {
    let frontend = Frontend::start_default().await?;
    let result = frontend.send(Command::ListInterfaces).await?;
    frontend.shutdown();

    let CommandResult::Interfaces { interfaces } = result else {
        return Err(unexpected("listInterfaces"));
    };

    context.emit(&interfaces, || {
        if interfaces.is_empty() {
            println!("No network interfaces were found.");
            output::note(
                context.quiet,
                "Run `sentinel doctor` to check whether packet capture is available.",
            );
            return;
        }
        let mut table = Table::new(&["ID", "NAME", "TYPE", "ADDRESSES", "STATE"], 0);
        for iface in &interfaces {
            table.push(vec![
                iface.id.clone(),
                iface.name.clone(),
                iface.kind.label().to_string(),
                iface.address_summary(),
                match (&iface.capture_ready, iface.is_loopback) {
                    (false, _) => "unavailable".to_string(),
                    (true, true) => "loopback".to_string(),
                    (true, false) => "ready".to_string(),
                },
            ]);
        }
        println!("Available network interfaces\n");
        table.print();
        output::note(
            context.quiet,
            "\nStart monitoring with: sentinel capture --interface <ID>",
        );
    })
}

/// `sentinel capture`
pub async fn capture(
    context: &Context,
    interface: Option<String>,
    duration_seconds: Option<u64>,
    show_connections: bool,
) -> Result<()> {
    let frontend = Frontend::start_default().await?;

    let interface_id = match interface {
        Some(id) => id,
        None => match default_interface(&frontend).await? {
            Some(id) => id,
            None => {
                frontend.shutdown();
                return Err(ApiError {
                    kind: sentinel_api::ApiErrorKind::Interface,
                    title: "No interface was selected".to_string(),
                    summary: "Sentinel could not choose a network interface to monitor."
                        .to_string(),
                    hint: vec![
                        "Run `sentinel interfaces` to see what is available.".to_string(),
                        "Then start monitoring with: sentinel capture --interface <ID>".to_string(),
                    ],
                    details: None,
                }
                .into());
            }
        },
    };

    match frontend
        .send(Command::Start {
            interface_id: interface_id.clone(),
        })
        .await
    {
        Ok(CommandResult::Started { state }) => {
            output::note(
                context.quiet,
                format!("Monitoring {}. Press Ctrl+C to stop.", state.label()),
            );
        }
        Ok(_) => {
            frontend.shutdown();
            return Err(ApiError {
                kind: sentinel_api::ApiErrorKind::InvalidState,
                title: "Monitoring did not start".to_string(),
                summary: format!(
                    "Sentinel could not start monitoring on interface '{interface_id}'."
                ),
                hint: vec!["Run `sentinel doctor` to check capture permissions.".to_string()],
                details: None,
            }
            .into());
        }
        Err(err) => {
            frontend.shutdown();
            return Err(err.into());
        }
    }

    let deadline =
        duration_seconds.map(|seconds| std::time::Instant::now() + Duration::from_secs(seconds));
    let mut seen_connections: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut last_snapshot: Option<sentinel_api::types::EngineSnapshot> = None;

    loop {
        if let Some(deadline) = deadline
            && std::time::Instant::now() >= deadline
        {
            break;
        }

        let CommandResult::Snapshot { snapshot } = frontend.send(Command::Snapshot).await? else {
            return Err(unexpected("snapshot"));
        };

        if show_connections {
            for row in &snapshot.connections {
                if seen_connections.insert(row.id.clone()) {
                    println!(
                        "{:<24} {:<28} {:<5} {:>10} {:>10}",
                        row.process.as_deref().unwrap_or("-"),
                        row.destination,
                        row.protocol,
                        output::bytes(row.upload_bytes),
                        output::bytes(row.download_bytes),
                    );
                }
            }
        } else if context.json {
            // JSON consumers want the full series, not a human summary.
            println!("{}", serde_json::to_string(&snapshot)?);
        } else if last_snapshot
            .as_ref()
            .is_none_or(|previous| previous.total_packets != snapshot.total_packets)
        {
            print_summary(&snapshot);
        }

        last_snapshot = Some(*snapshot);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    frontend.send(Command::Stop).await?;
    let CommandResult::Snapshot { snapshot } = frontend.send(Command::Snapshot).await? else {
        return Err(unexpected("snapshot"));
    };
    frontend.shutdown();

    context.emit(&snapshot, || {
        println!("\nSession summary\n");
        println!("  Packets       {}", snapshot.total_packets);
        println!(
            "  Uploaded      {}",
            output::bytes(snapshot.total_upload_bytes)
        );
        println!(
            "  Downloaded    {}",
            output::bytes(snapshot.total_download_bytes)
        );
        println!("  Connections   {}", snapshot.connections.len());
        println!("  Frames lost   {}", snapshot.stats.queue.dropped);
        if snapshot.stats.queue.dropped > 0 {
            println!("\n  Some frames were dropped because Sentinel could not keep up.");
            println!("  The totals above are therefore incomplete.");
        }
    })
}

/// Prints a one-line traffic summary.
fn print_summary(snapshot: &sentinel_api::types::EngineSnapshot) {
    use std::io::Write;
    print!(
        "\r  down {:>10}   up {:>10}   connections {:>5}   packets {:>9}   ",
        output::rate(snapshot.download_bps),
        output::rate(snapshot.upload_bps),
        snapshot.connections.len(),
        snapshot.total_packets,
    );
    let _ = std::io::stdout().flush();
}

/// Chooses the interface to monitor when the user did not name one.
///
/// Preference order: connected non-loopback adapters with an IPv4 address, then any connected
/// non-loopback adapter. Loopback is last because it hides everything else. This is a display
/// convenience, not a security judgement, so it is stated here rather than hidden in the
/// platform layer.
async fn default_interface(frontend: &Frontend) -> Result<Option<String>> {
    let CommandResult::Interfaces { interfaces } = frontend.send(Command::ListInterfaces).await?
    else {
        return Err(unexpected("listInterfaces"));
    };

    let usable: Vec<_> = interfaces
        .iter()
        .filter(|iface| iface.capture_ready && !iface.is_loopback)
        .collect();

    let preferred = usable
        .iter()
        .find(|iface| iface.primary_ipv4().is_some())
        .or_else(|| usable.first())
        .copied()
        .or_else(|| {
            interfaces
                .iter()
                .find(|iface| iface.is_loopback && iface.capture_ready)
        });

    Ok(preferred.map(|iface| iface.id.clone()))
}

/// `sentinel status`
pub async fn status(context: &Context) -> Result<()> {
    let frontend = Frontend::start_default().await?;
    let CommandResult::Snapshot { snapshot } = frontend.send(Command::Snapshot).await? else {
        return Err(unexpected("snapshot"));
    };
    frontend.shutdown();

    context.emit(&snapshot, || {
        println!("Iklwa Sentinel\n");
        println!("  State         {}", snapshot.state.label());
        if let Some(iface) = &snapshot.interface {
            println!(
                "  Interface     {} ({})",
                iface.name,
                iface.address_summary()
            );
        }
        println!("  Packets       {}", snapshot.total_packets);
        println!(
            "  Uploaded      {}",
            output::bytes(snapshot.total_upload_bytes)
        );
        println!(
            "  Downloaded    {}",
            output::bytes(snapshot.total_download_bytes)
        );
        println!("  Connections   {}", snapshot.connections.len());
        println!("  Frames lost   {}", snapshot.stats.queue.dropped);
    })
}

/// `sentinel analyze`
pub async fn analyze(context: &Context, path: PathBuf, all: bool) -> Result<()> {
    let frontend = Frontend::start_default().await?;

    let CommandResult::Started { state } = frontend
        .send(Command::Analyze {
            path: display_path(&path),
        })
        .await?
    else {
        return Err(unexpected("analyze"));
    };
    output::note(context.quiet, format!("{}...", state.label()));

    // The file is finite, so the engine finishes on its own. Polling is the same shape the
    // desktop app uses, which is the point: one engine, several frontends.
    let limit = 200u64;
    let mut snapshot = None;
    for _ in 0..limit {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let CommandResult::Snapshot { snapshot: current } =
            frontend.send(Command::Snapshot).await?
        else {
            return Err(unexpected("snapshot"));
        };
        let finished = !current.state.is_active();
        snapshot = Some(current);
        if finished {
            break;
        }
    }

    let Some(snapshot) = snapshot else {
        frontend.shutdown();
        return Err(ApiError {
            kind: sentinel_api::ApiErrorKind::Engine,
            title: "Analysis did not finish".to_string(),
            summary: "The engine stopped answering before the capture was fully analysed."
                .to_string(),
            hint: vec!["Try a smaller capture file.".to_string()],
            details: None,
        }
        .into());
    };
    frontend.shutdown();

    context.emit(&snapshot, || print_analysis(context, &snapshot, all))
}

/// Prints an analysis report.
fn print_analysis(context: &Context, snapshot: &sentinel_api::types::EngineSnapshot, all: bool) {
    println!("Capture analysis\n");
    println!("  Packets       {}", snapshot.total_packets);
    println!(
        "  Uploaded      {}",
        output::bytes(snapshot.total_upload_bytes)
    );
    println!(
        "  Downloaded    {}",
        output::bytes(snapshot.total_download_bytes)
    );
    println!("  Connections   {}", snapshot.connections.len());

    // The span comes from the engine's own frame timestamps rather than from bucket
    // boundaries, which are quantised to whole seconds.
    let span_us = snapshot.duration_us();
    println!(
        "  Time span     {}",
        output::duration_seconds_micros(span_us)
    );

    if snapshot.connections.is_empty() {
        println!("\nNo IP connections were found in this capture.");
        return;
    }

    let mut rows: Vec<_> = snapshot.connections.clone();
    // Busiest first, which is the ordering a person looking at a capture wants.
    rows.sort_by_key(|row| std::cmp::Reverse(row.total_bytes()));
    if !all {
        rows.truncate(20);
    }

    println!("\nConnections\n");
    let mut table = Table::new(
        &[
            "SOURCE",
            "DESTINATION",
            "PROTO",
            "SERVICE",
            "UPLOAD",
            "DOWNLOAD",
            "PACKETS",
            "LAST SEEN",
        ],
        4,
    );
    for row in &rows {
        table.push(vec![
            row.source.clone(),
            row.destination.clone(),
            row.protocol.clone(),
            row.service
                .clone()
                .or_else(|| row.domain.clone())
                .unwrap_or_else(|| "-".to_string()),
            output::bytes(row.upload_bytes),
            output::bytes(row.download_bytes),
            row.packets.to_string(),
            output::timestamp(row.last_seen_us),
        ]);
    }
    table.print();

    // Direction and locality are separate facts, so both are stated rather than implied by
    // column order.
    let undirected = rows.iter().filter(|row| !row.initiator_known).count();
    if undirected > 0 {
        output::note(
            context.quiet,
            format!(
                "\n  {undirected} of these have no identifiable client port, so their direction is unknown."
            ),
        );
    }
    let offhost = rows.iter().filter(|row| row.local.is_none()).count();
    if offhost > 0 {
        output::note(
            context.quiet,
            format!(
                "\n  {offhost} of these do not involve this machine, so no local side is shown."
            ),
        );
    }

    if !all && snapshot.connections.len() > rows.len() {
        output::note(
            true,
            format!(
                "\n  {} more connections; use --all to see them.",
                snapshot.connections.len() - rows.len()
            ),
        );
    }
}

/// `sentinel export`
pub async fn export(
    context: &Context,
    path: Option<PathBuf>,
    as_json: bool,
    limit: usize,
) -> Result<()> {
    let paths = sentinel_platform::AppPaths::discover()?;
    let database = sentinel_storage::Database::open(
        &paths.database_file,
        sentinel_storage::DatabaseOptions::default(),
    )?;
    let flows = database.recent_flows(limit)?;

    let json = as_json || context.json;
    let destination = path.unwrap_or_else(|| {
        let stamp =
            clock::unix_micros_to_rfc3339(clock::now_unix_micros()).replace([':', '-', '.'], "");
        paths.exports_dir.join(format!(
            "sentinel-export-{}.{}",
            if json { "json" } else { "csv" },
            &stamp[..15.min(stamp.len())]
        ))
    });

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if json {
        let rows: Vec<serde_json::Value> = flows
            .iter()
            .map(|record| {
                serde_json::json!({
                    "id": record.id,
                    "local": record.flow.key.endpoint_a.display(),
                    "remote": record.flow.key.endpoint_b.display(),
                    "protocol": record.flow.key.protocol.label(),
                    "service": record.flow.service,
                    "domain": record.flow.domain,
                    "process": record.flow.process.as_ref().map(|process| process.name.clone()),
                    "uploadBytes": record.flow.bytes_sent,
                    "downloadBytes": record.flow.bytes_received,
                    "packets": record.flow.total_packets(),
                    "firstSeen": clock::unix_micros_to_rfc3339(record.flow.first_seen_us),
                    "lastSeen": clock::unix_micros_to_rfc3339(record.flow.last_seen_us),
                    "riskScore": record.flow.risk_score,
                })
            })
            .collect();
        std::fs::write(&destination, serde_json::to_string_pretty(&rows)?)?;
    } else {
        let mut csv = String::from(
            "id,local,remote,protocol,service,domain,process,upload_bytes,download_bytes,packets,first_seen,last_seen,risk_score\n",
        );
        for record in &flows {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_field(&record.id),
                csv_field(&record.flow.key.endpoint_a.display()),
                csv_field(&record.flow.key.endpoint_b.display()),
                record.flow.key.protocol.label(),
                csv_field(record.flow.service.as_deref().unwrap_or("")),
                csv_field(record.flow.domain.as_deref().unwrap_or("")),
                csv_field(
                    record
                        .flow
                        .process
                        .as_ref()
                        .map(|p| p.name.as_str())
                        .unwrap_or("")
                ),
                record.flow.bytes_sent,
                record.flow.bytes_received,
                record.flow.total_packets(),
                clock::unix_micros_to_rfc3339(record.flow.first_seen_us),
                clock::unix_micros_to_rfc3339(record.flow.last_seen_us),
                record
                    .flow
                    .risk_score
                    .map(|score| score.to_string())
                    .unwrap_or_default(),
            ));
        }
        std::fs::write(&destination, csv)?;
    }

    output::note(
        context.quiet,
        format!(
            "Exported {} connections to {}",
            flows.len(),
            destination.display()
        ),
    );
    Ok(())
}

/// Escapes a CSV field.
///
/// Only the two characters that can break a field are escaped, plus quoting. Values are
/// Sentinel's own (addresses, service names, process names), but a process name can contain a
/// comma on any platform, and a malformed export is worse than a slightly larger file.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// `sentinel doctor`
pub async fn doctor(context: &Context) -> Result<()> {
    let report = sentinel_platform::capabilities();
    let paths = sentinel_platform::AppPaths::discover();
    let data_exists = paths
        .as_ref()
        .ok()
        .map(|p| p.data_dir.is_dir())
        .unwrap_or(false);
    let database_exists = paths
        .as_ref()
        .ok()
        .map(|p| p.database_file.is_file())
        .unwrap_or(false);

    let value = serde_json::json!({
        "platform": sentinel_platform::os::platform_name(),
        "capabilities": report.as_ref().ok(),
        "capabilityError": report.as_ref().err().map(|err| err.to_string()),
        "dataDirectory": paths.as_ref().map(|p| p.data_dir.display().to_string()).ok(),
        "dataDirectoryExists": data_exists,
        "databaseExists": database_exists,
        "captureAvailable": report.as_ref().map(|c| c.capture_available_now()).unwrap_or(false),
    });

    output::emit(context.json, &value, || {
        println!("Iklwa Sentinel diagnostics\n");
        println!(
            "  Platform            {}",
            sentinel_platform::os::platform_name()
        );

        match &report {
            Ok(capabilities) => {
                println!("  Capture backend     {}", capabilities.backend.label());
                println!(
                    "  Driver present      {}",
                    yes_no(capabilities.library_present)
                );
                println!("  Privilege state     {}", capabilities.privilege.label());
                println!(
                    "  Capture available   {}",
                    yes_no(capabilities.capture_available_now())
                );
                println!(
                    "  Loopback supported  {}",
                    yes_no(capabilities.loopback_supported)
                );
                println!("  Max snapshot length {} bytes", capabilities.max_snaplen);
                if !capabilities.notes.is_empty() {
                    println!("\n  Notes");
                    for note in &capabilities.notes {
                        println!("    - {note}");
                    }
                }
            }
            Err(err) => {
                println!("  Capture backend     unavailable");
                println!("\n  {err}");
            }
        }

        match &paths {
            Ok(paths) => {
                println!("\n  Data directory      {}", paths.data_dir.display());
                println!("  Directory exists    {}", yes_no(data_exists));
                println!("  Database present    {}", yes_no(database_exists));
                println!("  Logs                {}", paths.logs_dir.display());
            }
            Err(err) => println!("\n  Data directory      unavailable: {err}"),
        }

        match &report {
            Ok(capabilities) if !capabilities.capture_available_now() => {
                println!("\n  Packet capture is not available yet.");
                for note in &capabilities.notes {
                    println!("    - {note}");
                }
            }
            _ => {}
        }
    })
}

/// `sentinel prune`
pub async fn prune(context: &Context, dry_run: bool) -> Result<()> {
    let paths = sentinel_platform::AppPaths::discover()?;
    let mut database = sentinel_storage::Database::open(
        &paths.database_file,
        sentinel_storage::DatabaseOptions::default(),
    )?;

    let config = sentinel_platform::settings::SettingsStore::new(&paths.config_file)
        .load()
        .config;
    let job = sentinel_storage::RetentionJob::from_config(&config, clock::now_unix_micros());

    if dry_run {
        let flows_cutoff = job.flows_cutoff();
        let samples_cutoff = job.samples_cutoff();
        let report = job.run(&mut database)?;

        let value = serde_json::json!({
            "dryRun": true,
            "flowsCutoff": flows_cutoff.map(clock::unix_micros_to_rfc3339),
            "samplesCutoff": samples_cutoff.map(clock::unix_micros_to_rfc3339),
            "wouldRemove": { "flows": report.flows_removed, "samples": report.samples_removed },
        });
        output::emit(context.json, &value, || {
            println!("Retention dry run\n");
            println!("  Flows removed       {}", report.flows_removed);
            println!("  Samples removed     {}", report.samples_removed);
            println!("\n  Nothing was deleted. Run `sentinel prune` to apply.");
        })?;
        return Ok(());
    }

    let report = job.run(&mut database)?;
    let value = serde_json::json!({ "flowsRemoved": report.flows_removed, "samplesRemoved": report.samples_removed });
    output::emit(context.json, &value, || println!("{}", report.summary()))
}

/// `sentinel version`
pub fn version(context: &Context) {
    let schema = sentinel_storage::migrations::TARGET_VERSION;
    let value = serde_json::json!({
        "name": "Iklwa Sentinel",
        "vendor": "IklwaLabs",
        "version": env!("CARGO_PKG_VERSION"),
        "schemaVersion": schema,
        "platform": sentinel_platform::os::platform_name(),
    });

    let _ = output::emit(context.json, &value, || {
        println!("Iklwa Sentinel {}", env!("CARGO_PKG_VERSION"));
        println!("Built by IklwaLabs");
        println!("Database schema version {schema}");
        println!("Platform {}", sentinel_platform::os::platform_name());
    });
}

/// Formats a path for display and for handing to the engine.
fn display_path(path: &Path) -> String {
    path.display().to_string()
}

/// Builds an error for a response the engine should not have produced.
fn unexpected(what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the engine returned an unexpected response to {what}; this is a bug in Sentinel"
    )
}

/// Formats a boolean as `yes`/`no`.
fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
