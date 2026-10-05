//! Per-OS application directories.
//!
//! Sentinel keeps everything it owns under one platform-appropriate root so uninstall
//! is predictable and nothing is written next to the executable. `IKLWA_HOME` overrides
//! the location, which is how tests and portable installs work.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{PlatformError, Result};

/// Environment variable that overrides every Sentinel path.
pub const HOME_ENV: &str = "IKLWA_HOME";

/// Resolved locations for Sentinel data, configuration, logs and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    /// Root directory owned by Sentinel.
    pub data_dir: PathBuf,
    /// Configuration file.
    pub config_file: PathBuf,
    /// SQLite database.
    pub database_file: PathBuf,
    /// Rolling log directory.
    pub logs_dir: PathBuf,
    /// Generated reports and exports.
    pub exports_dir: PathBuf,
}

impl AppPaths {
    /// Builds paths for a given data root.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config_file: root.join("config.json"),
            database_file: root.join("sentinel.db"),
            logs_dir: root.join("logs"),
            exports_dir: root.join("exports"),
            data_dir: root,
        }
    }

    /// Resolves the paths for this machine.
    ///
    /// # Errors
    /// Returns [`PlatformError::Io`] when a required environment variable is missing and
    /// no home directory can be determined.
    pub fn discover() -> Result<Self> {
        Ok(Self::with_root(default_root()?))
    }

    /// Creates every directory, restricting permissions to the current user on Unix.
    ///
    /// # Errors
    /// Returns [`PlatformError::Io`] when a directory cannot be created.
    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.data_dir, &self.logs_dir, &self.exports_dir] {
            fs::create_dir_all(dir).map_err(|err| PlatformError::Io {
                context: "creating the Sentinel data directory",
                details: format!("{}: {err}", dir.display()),
            })?;
            restrict_to_current_user(dir)?;
        }
        Ok(())
    }
}

/// Makes a directory owner-only on Unix; a no-op elsewhere.
fn restrict_to_current_user(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(dir)?.permissions();
        if permissions.mode() & 0o077 != 0 {
            permissions.set_mode(0o700);
            fs::set_permissions(dir, permissions)?;
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Platform default root directory.
fn default_root() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os(HOME_ENV) {
        let path = PathBuf::from(explicit);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }

    if cfg!(target_os = "windows") {
        // Local app data first: it is not synced to other machines, which is the right default
        // for a database full of network observations.
        if let Some(local) = non_empty_env("LOCALAPPDATA") {
            return Ok(local.join("IklwaLabs").join("Iklwa Sentinel"));
        }
        if let Some(roaming) = non_empty_env("APPDATA") {
            return Ok(roaming.join("IklwaLabs").join("Iklwa Sentinel"));
        }
    } else if cfg!(target_os = "macos") {
        if let Some(home) = home_dir() {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Iklwa Sentinel"));
        }
    } else if cfg!(target_os = "android") {
        // On Android the app's internal storage directory is provided by the platform
        // bridge. Without it we must fail loudly rather than write to a shared location.
        return Err(PlatformError::Io {
            context: "resolving the Android data directory",
            details: format!(
                "{HOME_ENV} is not set. The Android host must provide the app-private directory."
            ),
        });
    } else {
        if let Some(data_home) = non_empty_env("XDG_DATA_HOME") {
            return Ok(data_home.join("iklwa-sentinel"));
        }
        if let Some(home) = home_dir() {
            return Ok(home.join(".local").join("share").join("iklwa-sentinel"));
        }
    }

    Err(PlatformError::Io {
        context: "resolving the Sentinel data directory",
        details: format!("Neither {HOME_ENV} nor a platform home directory is available"),
    })
}

fn non_empty_env(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_dir() -> Option<PathBuf> {
    non_empty_env("HOME").or_else(|| non_empty_env("USERPROFILE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_derived_from_root() {
        let paths = AppPaths::with_root("/tmp/sentinel");
        assert!(paths.database_file.ends_with("sentinel.db"));
        assert!(paths.config_file.ends_with("config.json"));
        assert!(paths.logs_dir.ends_with("logs"));
        assert!(paths.exports_dir.ends_with("exports"));
    }

    #[test]
    fn ensure_creates_directories_and_is_idempotent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let paths = AppPaths::with_root(temp.path().join("nested").join("sentinel"));
        paths.ensure().expect("first ensure");
        paths.ensure().expect("second ensure must be idempotent");
        assert!(paths.logs_dir.is_dir());
        assert!(paths.exports_dir.is_dir());
    }
}
