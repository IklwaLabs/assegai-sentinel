//! Configuration file persistence.
//!
//! Loading is deliberately forgiving in one specific way: a malformed or unreadable
//! file never prevents Sentinel from starting. The user gets default settings plus a
//! visible warning that names the problem, because a broken settings file should not
//! make a security tool unusable.

use std::fs;
use std::path::Path;

use sentinel_common::config::AppConfig;

use crate::error::{PlatformError, Result};

/// Reads and writes the configuration file.
#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: std::path::PathBuf,
}

/// Outcome of loading configuration, including anything the user should know.
#[derive(Debug, Clone, Default)]
pub struct LoadedConfig {
    /// The effective configuration.
    pub config: AppConfig,
    /// Non-fatal problems, suitable for a UI banner.
    pub warnings: Vec<String>,
}

impl SettingsStore {
    /// Creates a store for a configuration file path.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The configuration file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads configuration, falling back to defaults with a warning on any problem.
    pub fn load(&self) -> LoadedConfig {
        let mut warnings = Vec::new();
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return LoadedConfig {
                    config: AppConfig::default(),
                    warnings,
                };
            }
            Err(err) => {
                warnings.push(format!(
                    "Settings could not be read ({}); default settings are in use.",
                    err.kind()
                ));
                return LoadedConfig {
                    config: AppConfig::default(),
                    warnings,
                };
            }
        };

        let mut config = match AppConfig::from_json(&text) {
            Ok(config) => config,
            Err(err) => {
                warnings.push(format!(
                    "Settings file is invalid ({err}); default settings are in use."
                ));
                AppConfig::default()
            }
        };
        config.migrate();

        if let Err(err) = config.validate() {
            warnings.push(format!(
                "A setting was out of range ({err}); that value was reset to its default."
            ));
            if let Ok(sanitised) = sanitise(&config) {
                config = sanitised;
            }
        }

        LoadedConfig { config, warnings }
    }

    /// Writes configuration atomically via a temporary file and rename.
    ///
    /// # Errors
    /// Returns [`PlatformError::Io`] when the file cannot be written or replaced.
    pub fn save(&self, config: &AppConfig) -> Result<()> {
        let text = config.to_json().map_err(|err| PlatformError::Io {
            context: "serializing settings",
            details: err.to_string(),
        })?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| PlatformError::Io {
                context: "creating the settings directory",
                details: err.to_string(),
            })?;
        }

        let temp = self.path.with_extension("json.tmp");
        fs::write(&temp, text).map_err(|err| PlatformError::Io {
            context: "writing the settings file",
            details: err.to_string(),
        })?;
        // Windows rename fails if the destination exists, so remove it first. The window
        // is tiny and the previous file is always a valid configuration.
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
        fs::rename(&temp, &self.path).map_err(|err| PlatformError::Io {
            context: "replacing the settings file",
            details: err.to_string(),
        })
    }
}

/// Resets out-of-range values to defaults so a bad value cannot block start-up.
fn sanitise(config: &AppConfig) -> std::result::Result<AppConfig, ()> {
    let defaults = AppConfig::default();
    let mut out = config.clone();
    if !(256..=1_048_576).contains(&out.capture.queue_capacity) {
        out.capture.queue_capacity = defaults.capture.queue_capacity;
    }
    if !(100..=1_000_000).contains(&out.capture.max_tracked_flows) {
        out.capture.max_tracked_flows = defaults.capture.max_tracked_flows;
    }
    if !(1..=60).contains(&out.capture.ui_update_hz) {
        out.capture.ui_update_hz = defaults.capture.ui_update_hz;
    }
    if out.capture.flow_idle_timeout_secs < 5 {
        out.capture.flow_idle_timeout_secs = defaults.capture.flow_idle_timeout_secs;
    }
    if out.advanced.write_batch_size == 0 {
        out.advanced.write_batch_size = defaults.advanced.write_batch_size;
    }
    out.validate().map(|()| out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::config::AppConfig;

    fn store_in(dir: &Path) -> SettingsStore {
        SettingsStore::new(dir.join("config.json"))
    }

    #[test]
    fn missing_file_yields_defaults_without_warning() {
        let temp = tempfile::tempdir().expect("temp dir");
        let loaded = store_in(temp.path()).load();
        assert_eq!(loaded.config, AppConfig::default());
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = store_in(temp.path());
        let mut config = AppConfig::default();
        config.capture.ui_update_hz = 10;
        config.capture.interface_id = Some("3".to_string());
        store.save(&config).expect("save succeeds");
        let loaded = store.load();
        assert_eq!(loaded.config, config);
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    }

    #[test]
    fn malformed_file_falls_back_with_warning() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("config.json");
        fs::write(&path, "{ not json").expect("write fixture");
        let loaded = SettingsStore::new(path).load();
        assert_eq!(loaded.config, AppConfig::default());
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("invalid"));
    }

    #[test]
    fn out_of_range_value_is_repaired_with_warning() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("config.json");
        fs::write(&path, r#"{"capture":{"queueCapacity":4}}"#).expect("write fixture");
        let loaded = SettingsStore::new(path).load();
        assert_eq!(loaded.warnings.len(), 1);
        assert_eq!(
            loaded.config.capture.queue_capacity,
            AppConfig::default().capture.queue_capacity
        );
    }

    #[test]
    fn save_creates_missing_parent_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = SettingsStore::new(temp.path().join("a").join("b").join("config.json"));
        store
            .save(&AppConfig::default())
            .expect("save creates parents");
        assert!(store.path().is_file());
        assert!(
            !store.path().with_extension("json.tmp").exists(),
            "temp file must be renamed away"
        );
    }
}
