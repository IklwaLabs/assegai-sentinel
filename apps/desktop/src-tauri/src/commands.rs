//! Tauri commands.
//!
//! Each command is a thin translation between the wire types in `sentinel-api` and Tauri's
//! JSON boundary. No analysis, no filtering, no caching: if a command needed any of those, the
//! logic belongs in the engine and the command would disappear.

use sentinel_api::types::{AppConfig, Capabilities, Command, CommandResult, EngineSnapshot, NetworkInterface, SessionState};
use tauri::{AppHandle, Emitter, State};

use crate::state::{AppState, shutting_down};

/// Event name for engine events pushed to the window.
pub const EVENT_NAME: &str = "sentinel://event";

/// Lists network interfaces available for monitoring.
#[tauri::command]
pub async fn list_interfaces(state: State<'_, AppState>) -> Result<Vec<NetworkInterface>, sentinel_api::ApiError> {
    match state.send(Command::ListInterfaces).await? {
        CommandResult::Interfaces { interfaces } => Ok(interfaces),
        _ => Err(unexpected("listInterfaces")),
    }
}

/// Reports what packet capture is possible in this process.
#[tauri::command]
pub async fn capabilities(state: State<'_, AppState>) -> Result<Capabilities, sentinel_api::ApiError> {
    // Capabilities are answered by the platform layer directly rather than through a session, so
    // they stay available even when the engine is busy or has stopped.
    match state.send(Command::Capabilities).await? {
        CommandResult::Capabilities { capabilities } => Ok(capabilities),
        // The engine publishes the failure as a notice event and acknowledges the request, so
        // the UI can render a partial answer plus a message.
        CommandResult::Acknowledged => Err(sentinel_api::ApiError {
            kind: sentinel_api::ApiErrorKind::Driver,
            title: "Capture capabilities are unavailable".to_string(),
            summary: "Sentinel could not determine what this machine can capture.".to_string(),
            hint: vec![
                "Check that a packet capture driver is installed.".to_string(),
                "See the details in the logs for the underlying reason.".to_string(),
            ],
            details: None,
        }),
        _ => Err(unexpected("capabilities")),
    }
}

/// Starts monitoring an interface.
#[tauri::command]
pub async fn start_monitoring(
    app: AppHandle,
    state: State<'_, AppState>,
    interface_id: String,
) -> Result<SessionState, sentinel_api::ApiError> {
    match state.send(Command::Start { interface_id }).await? {
        CommandResult::Started { state } => {
            forward_events(&app, &state).await;
            Ok(state)
        }
        _ => Err(unexpected("startMonitoring")),
    }
}

/// Stops the current session.
#[tauri::command]
pub async fn stop_monitoring(state: State<'_, AppState>) -> Result<(), sentinel_api::ApiError> {
    state.send(Command::Stop).await?;
    Ok(())
}

/// Analyses a PCAP file offline.
#[tauri::command]
pub async fn analyze_capture(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<SessionState, sentinel_api::ApiError> {
    match state.send(Command::Analyze { path }).await? {
        CommandResult::Started { state } => {
            forward_events(&app, &state).await;
            Ok(state)
        }
        _ => Err(unexpected("analyzeCapture")),
    }
}

/// Fetches a full snapshot.
#[tauri::command]
pub async fn get_snapshot(state: State<'_, AppState>) -> Result<EngineSnapshot, sentinel_api::ApiError> {
    match state.send(Command::Snapshot).await? {
        CommandResult::Snapshot { snapshot } => Ok(*snapshot),
        _ => Err(unexpected("getSnapshot")),
    }
}

/// Reads the effective configuration.
#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<AppConfig, sentinel_api::ApiError> {
    match state.send(Command::GetConfig).await? {
        CommandResult::Config { config } => Ok(*config),
        _ => Err(unexpected("getSettings")),
    }
}

/// Replaces the effective configuration and writes it to disk.
#[tauri::command]
pub async fn save_settings(
    state: State<'_, AppState>,
    config: AppConfig,
) -> Result<AppConfig, sentinel_api::ApiError> {
    // Applied to the running engine first: an invalid value is rejected there, before it can
    // reach the settings file and break the next start-up.
    let applied = match state.send(Command::SetConfig { config }).await? {
        CommandResult::Config { config } => *config,
        _ => return Err(unexpected("saveSettings")),
    };
    state.save_settings(&applied)?;
    Ok(applied)
}

/// Returns the application directories and any start-up warnings, for the Settings view.
#[tauri::command]
pub async fn get_diagnostics(
    state: State<'_, AppState>,
) -> Result<sentinel_api::types::Diagnostics, sentinel_api::ApiError> {
    Ok(sentinel_api::types::Diagnostics {
        data_directory: state.paths().data_dir.display().to_string(),
        database_file: state.paths().database_file.display().to_string(),
        logs_directory: state.paths().logs_dir.display().to_string(),
        exports_directory: state.paths().exports_dir.display().to_string(),
        warnings: state.startup_warnings().to_vec(),
    })
}

/// Subscribes the window to engine events for as long as the session lasts.
///
/// The engine publishes aggregate snapshots and state changes; the window renders them. This
/// task holds no state of its own and exits when the app does.
async fn forward_events(app: &AppHandle, _state: &SessionState) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Subscribing through the frontend requires the guard, which is held by the caller for
        // the duration of its command. A second short lock is taken here so the subscription
        // outlives that command: otherwise the window would receive nothing after start-up.
        let receiver = {
            let frontend = app.state::<AppState>().frontend().await;
            match frontend.as_ref() {
                Some(frontend) => Some(frontend.subscribe()),
                None => None,
            }
        };

        let Some(mut events) = receiver else {
            tracing::warn!("cannot subscribe to engine events: the engine is not running");
            return;
        };

        while let Some(event) = events.recv().await {
            if let Err(err) = app.emit(EVENT_NAME, &event) {
                // A closed window is normal on quit, not an error worth escalating.
                tracing::debug!(error = %err, "could not emit an engine event to the window");
                break;
            }
        }
    });
}

/// The error for a response the engine should not have produced.
fn unexpected(what: &str) -> sentinel_api::ApiError {
    sentinel_api::ApiError {
        kind: sentinel_api::ApiErrorKind::Engine,
        title: "Sentinel received an unexpected response".to_string(),
        summary: format!("The engine did not answer `{what}` with the expected result."),
        hint: vec!["This is a bug in Sentinel.".to_string(), "Export your logs before reporting it.".to_string()],
        details: Some(format!("command: {what}")),
    }
}

/// Returns the shutting-down error, for callers outside the command layer.
#[must_use]
pub fn engine_gone() -> sentinel_api::ApiError {
    shutting_down()
}
