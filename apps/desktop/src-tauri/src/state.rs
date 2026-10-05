//! Process-wide state for the desktop shell.
//!
//! Holds the engine client and the settings store for the lifetime of the process. The
//! frontend holds no analysis state, so this is the only place the two halves meet.

use std::sync::Arc;

use sentinel_api::Frontend;
use sentinel_common::config::AppConfig;
use sentinel_common::error::UserFacing;
use sentinel_platform::settings::SettingsStore;
use tokio::sync::{Mutex, MutexGuard};

/// Everything a Tauri command handler needs.
pub struct AppState {
    /// The engine client, behind a mutex: starting and stopping a session must not interleave.
    frontend: Mutex<Option<Frontend>>,
    /// Configuration file access.
    settings: Arc<SettingsStore>,
    /// Resolved data, config, log and export directories, for display in Settings.
    paths: sentinel_platform::AppPaths,
    /// Non-fatal problems found while loading settings, shown as a banner.
    startup_warnings: Vec<String>,
}

impl AppState {
    /// Builds the state, starting the engine.
    ///
    /// # Errors
    /// Returns an error when the data directory or database cannot be opened. The message is
    /// already user-facing, because a desktop app that cannot write anywhere cannot start.
    pub async fn new() -> Result<Self, sentinel_api::ApiError> {
        let paths = sentinel_platform::AppPaths::discover().map_err(|err| storage_error(&err))?;
        paths.ensure().map_err(|err| storage_error(&err))?;

        let settings = Arc::new(SettingsStore::new(paths.config_file.clone()));
        let loaded = settings.load();

        // The engine starts with the configuration that is actually on disk, so the first
        // snapshot reports the same values the user would see in Settings.
        let frontend = Frontend::start(sentinel_core::EngineOptions {
            config: loaded.config,
            ..sentinel_core::EngineOptions::default()
        })
        .await?;

        Ok(Self {
            frontend: Mutex::new(Some(frontend)),
            settings,
            paths,
            startup_warnings: loaded.warnings,
        })
    }

    /// Locks the engine client.
    ///
    /// The guard serialises session transitions, so a start cannot race a stop. Ordinary reads
    /// such as a snapshot take the same lock; they are microseconds long, so at four snapshots
    /// per second there is nothing to contend over.
    pub async fn frontend(&self) -> MutexGuard<'_, Option<Frontend>> {
        self.frontend.lock().await
    }

    /// The engine client, or an error explaining that Sentinel is shutting down.
    ///
    /// # Errors
    /// Returns [`shutting_down`] when the engine has already been torn down.
    pub async fn require_frontend(
        &self,
    ) -> Result<MutexGuard<'_, Option<Frontend>>, sentinel_api::ApiError> {
        let guard = self.frontend.lock().await;
        if guard.is_none() {
            return Err(shutting_down());
        }
        Ok(guard)
    }

    /// The engine client without the lifetime dance, for commands that only need to send one
    /// command and drop the guard afterwards.
    ///
    /// # Errors
    /// Returns [`shutting_down`] when the engine has already been torn down.
    pub async fn send(
        &self,
        command: sentinel_api::types::Command,
    ) -> Result<sentinel_api::types::CommandResult, sentinel_api::ApiError> {
        let guard = self.require_frontend().await?;
        let frontend = guard.as_ref().ok_or_else(shutting_down)?;
        frontend.send(command).await
    }

    /// Persists configuration.
    ///
    /// # Errors
    /// Returns a storage error when the file cannot be written.
    pub fn save_settings(&self, config: &AppConfig) -> Result<(), sentinel_api::ApiError> {
        self.settings
            .save(config)
            .map_err(|err| storage_error(&err))
    }

    /// The application directories, for display in Settings.
    #[must_use]
    pub const fn paths(&self) -> &sentinel_platform::AppPaths {
        &self.paths
    }

    /// Non-fatal problems from loading settings at start-up.
    #[must_use]
    pub fn startup_warnings(&self) -> &[String] {
        &self.startup_warnings
    }
}

/// Converts a storage-layer error into the API error shape.
fn storage_error(err: &impl UserFacing) -> sentinel_api::ApiError {
    sentinel_api::ApiError::from_error(err, sentinel_api::ApiErrorKind::Storage)
}

/// The error returned when the engine has already been torn down.
#[must_use]
pub fn shutting_down() -> sentinel_api::ApiError {
    sentinel_api::ApiError {
        kind: sentinel_api::ApiErrorKind::Engine,
        title: "Sentinel is shutting down".to_string(),
        summary: "The monitoring engine is no longer available.".to_string(),
        hint: vec!["Restart Sentinel to resume monitoring.".to_string()],
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shutdown_error_explains_itself() {
        let err = shutting_down();
        assert_eq!(err.kind, sentinel_api::ApiErrorKind::Engine);
        assert!(err.hint.iter().any(|hint| hint.contains("Restart")));
        assert!(err.to_plain_text().contains("no longer available"));
    }
}
