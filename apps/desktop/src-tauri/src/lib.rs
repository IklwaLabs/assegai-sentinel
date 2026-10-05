//! The Iklwa Sentinel desktop shell.
//!
//! Tauri is a window and a JSON bridge. Everything that matters happens in `sentinel-core`:
//! this crate starts the engine, forwards aggregate events to the window, and translates
//! commands. There is no analysis here, and no state a user would have to trust the shell to
//! hold.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod logging;
mod state;

use tauri::{Emitter, Manager};

use crate::state::AppState;

/// Starts the desktop application.
///
/// The engine is started on Tauri's own runtime rather than inside a `#[main]` attribute, so
/// that this stays an ordinary function a test or a different launcher can call.
///
/// # Errors
/// Returns an error when the engine cannot start, for example because the data directory is
/// not writable. The message is already user-facing.
pub fn run() -> Result<(), sentinel_api::ApiError> {
    logging::init();

    let state = tauri::async_runtime::block_on(AppState::new())?;

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::capabilities,
            commands::start_monitoring,
            commands::stop_monitoring,
            commands::analyze_capture,
            commands::get_snapshot,
            commands::get_settings,
            commands::save_settings,
            commands::get_diagnostics,
        ])
        .setup(|app| {
            // One subscription for the whole window, created once rather than per session. The
            // window is the only consumer, and re-subscribing on every start would race the
            // previous task and leave two streams feeding one renderer.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                subscribe(&handle).await;
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // Shutting the engine down explicitly lets it flush and join its writer thread
                // rather than being dropped mid-write.
                shutdown(window);
            }
        })
        .run(tauri::generate_context!())
        .map_err(|err| sentinel_api::ApiError {
            kind: sentinel_api::ApiErrorKind::Engine,
            title: "Sentinel could not open its window".to_string(),
            summary: "The desktop interface failed to start.".to_string(),
            hint: vec![
                "Restart Sentinel.".to_string(),
                "Export your logs before reporting the problem.".to_string(),
            ],
            details: Some(err.to_string()),
        })?;

    Ok(())
}

/// Forwards engine events to the window for the life of the process.
async fn subscribe(app: &tauri::AppHandle) {
    let receiver: Option<tokio::sync::mpsc::UnboundedReceiver<sentinel_core::EngineEvent>> = {
        let state = app.state::<AppState>();
        let guard = state.frontend().await;
        guard.as_ref().map(sentinel_api::Frontend::subscribe)
    };

    let Some(mut events) = receiver else {
        tracing::warn!("cannot subscribe to engine events: the engine is not running");
        return;
    };

    while let Some(event) = events.recv().await {
        if let Err(err) = app.emit(commands::EVENT_NAME, &event) {
            // A closed window is normal on quit, not an error worth escalating.
            tracing::debug!(error = %err, "could not emit an engine event to the window");
            break;
        }
    }
}

/// Stops the engine when the window closes.
fn shutdown(window: &tauri::Window) {
    let app = window.app_handle().clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let guard = state.frontend().await;
        if let Some(frontend) = guard.as_ref() {
            frontend.shutdown();
        }
        tracing::info!("engine shut down");
    });
}
