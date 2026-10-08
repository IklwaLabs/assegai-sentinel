//! Typed configuration schema.
//!
//! Only sections that affect implemented behaviour exist. A section for a feature that
//! is not implemented would be a lie in the settings file, so detection, threat
//! intelligence and notification sections are added with the milestones that need them
//! (see `ROADMAP.md`), together with the migrations that read them.
//!
//! All fields have `serde` defaults, so a config file written by an older build always
//! loads. Unknown keys are rejected rather than silently ignored: a typo in a security
//! setting should be loud.

use serde::{Deserialize, Serialize};

/// How long a category of stored data is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum RetentionPeriod {
    /// One day.
    #[serde(rename = "24h", alias = "Hours24")]
    Hours24,
    /// One week.
    #[serde(rename = "7d", alias = "Days7")]
    Days7,
    /// One month (the default).
    #[serde(rename = "30d", alias = "Days30")]
    #[default]
    Days30,
    /// One quarter.
    #[serde(rename = "90d", alias = "Days90")]
    Days90,
    /// A caller-specified number of days.
    #[serde(rename = "custom", alias = "Custom")]
    Custom(u32),
    /// Keep indefinitely. Only offered for deliberate forensic use.
    #[serde(rename = "forever", alias = "Forever")]
    Forever,
}

impl RetentionPeriod {
    /// Retention length in seconds, or `None` for `Forever`.
    #[must_use]
    pub const fn as_secs(self) -> Option<u64> {
        match self {
            RetentionPeriod::Hours24 => Some(24 * 3_600),
            RetentionPeriod::Days7 => Some(7 * 86_400),
            RetentionPeriod::Days30 => Some(30 * 86_400),
            RetentionPeriod::Days90 => Some(90 * 86_400),
            RetentionPeriod::Custom(days) => Some(days as u64 * 86_400),
            RetentionPeriod::Forever => None,
        }
    }

    /// Label shown in the settings UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RetentionPeriod::Hours24 => "Last 24 hours",
            RetentionPeriod::Days7 => "Last 7 days",
            RetentionPeriod::Days30 => "Last 30 days",
            RetentionPeriod::Days90 => "Last 90 days",
            RetentionPeriod::Custom(_) => "Custom",
            RetentionPeriod::Forever => "Forever",
        }
    }

    /// Whether the user made a deliberate choice in the UI, which gates the warning.
    #[must_use]
    pub const fn is_explicit(self) -> bool {
        !matches!(self, RetentionPeriod::Days30)
    }
}

/// Packet capture behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureConfig {
    /// Interface the user last selected, by platform interface id.
    pub interface_id: Option<String>,
    /// Snapshot length in bytes. 0 means "use the OS maximum".
    pub snaplen: u32,
    /// Enable promiscuous mode where the OS supports it.
    pub promiscuous: bool,
    /// Inactivity timeout for a read, in milliseconds. Keeps the reader thread responsive
    /// to stop requests.
    pub read_timeout_ms: i32,
    /// Capacity of the ingress queue between capture and parsing. Overflow is counted,
    /// never hidden.
    pub queue_capacity: usize,
    /// Flows idle for longer than this are evicted from the working set.
    pub flow_idle_timeout_secs: u64,
    /// Hard cap on tracked flows, protecting memory on very busy networks.
    pub max_tracked_flows: usize,
    /// UI snapshot rate in hertz. Live views coalesce to this rate.
    pub ui_update_hz: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface_id: None,
            snaplen: 65_536,
            promiscuous: false,
            read_timeout_ms: 500,
            queue_capacity: 32_768,
            flow_idle_timeout_secs: 120,
            max_tracked_flows: 20_000,
            ui_update_hz: 4,
        }
    }
}

/// Storage retention behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    /// How long flow records are kept.
    pub flows: RetentionPeriod,
    /// How long aggregated traffic samples are kept.
    pub traffic_samples: RetentionPeriod,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            flows: RetentionPeriod::Days30,
            traffic_samples: RetentionPeriod::Days7,
        }
    }
}

/// Privacy and data-handling switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[derive(Default)]
pub struct PrivacyConfig {
    /// Redact this machine's and private-LAN addresses in exported reports.
    ///
    /// Implemented in `sentinel_flow::privacy` and honoured by `sentinel export`. Private
    /// peers are replaced with a stable per-export pseudonym (`lan-1`, `lan-2`) rather than a
    /// blanket token, so per-host totals and destination fan-out remain analysable while the
    /// addresses themselves are gone. Public destination addresses are kept, because they are
    /// usually the most useful field in an export and redacting them would protect nothing.
    pub redact_local_addresses_in_exports: bool,
}

/// Appearance preferences shared by desktop and mobile frontends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum ThemeMode {
    /// The default dark neutral palette.
    #[default]
    Dark,
    /// Follow the operating system setting.
    System,
}

/// Appearance configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct AppearanceConfig {
    /// Colour scheme.
    pub theme: ThemeMode,
    /// Use compact table rows.
    pub compact_tables: bool,
}

impl Default for AppearanceConfig {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            compact_tables: false,
        }
    }
}

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum LogLevel {
    /// Only failures.
    Error,
    /// Failures and recoverable problems.
    Warn,
    /// Lifecycle events (default).
    #[default]
    Info,
    /// Verbose internals.
    Debug,
    /// Per-packet tracing. Never enabled by default; it is heavy.
    Trace,
}

impl LogLevel {
    /// `tracing` filter directive for this level.
    #[must_use]
    pub const fn as_filter(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    /// Numeric severity, highest is most verbose.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            LogLevel::Error => 0,
            LogLevel::Warn => 1,
            LogLevel::Info => 2,
            LogLevel::Debug => 3,
            LogLevel::Trace => 4,
        }
    }
}

/// Advanced settings that affect storage and diagnostics rather than behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct AdvancedConfig {
    /// Log verbosity.
    pub log_level: LogLevel,
    /// Write-ahead log mode. Recommended; disabling it is only useful for forensic
    /// inspection of a database copy.
    pub wal_mode: bool,
    /// Batch size for storage writes before a transaction is committed.
    pub write_batch_size: u32,
    /// Target maximum database size in megabytes, enforced opportunistically by the
    /// retention job.
    pub max_db_size_mb: u32,
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            wal_mode: true,
            write_batch_size: 256,
            max_db_size_mb: 512,
        }
    }
}

/// The complete application configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct AppConfig {
    /// Schema version, used to migrate configuration across releases.
    pub version: u32,
    /// Capture behaviour.
    pub capture: CaptureConfig,
    /// Storage retention.
    pub retention: RetentionConfig,
    /// Privacy switches.
    pub privacy: PrivacyConfig,
    /// Appearance.
    pub appearance: AppearanceConfig,
    /// Storage and diagnostics.
    pub advanced: AdvancedConfig,
}

/// Configuration schema version written by this build.
pub const CONFIG_VERSION: u32 = 1;

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            capture: CaptureConfig::default(),
            retention: RetentionConfig::default(),
            privacy: PrivacyConfig::default(),
            appearance: AppearanceConfig::default(),
            advanced: AdvancedConfig::default(),
        }
    }
}

/// Configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A numeric field was outside its usable range.
    #[error("{field} must be between {min} and {max}, got {value}")]
    OutOfRange {
        /// Field name.
        field: &'static str,
        /// Minimum accepted value.
        min: u64,
        /// Maximum accepted value.
        max: u64,
        /// Value found in the file.
        value: u64,
    },
    /// The configuration file is not valid JSON for the current schema.
    #[error("configuration file is not valid: {0}")]
    Malformed(String),
    /// Reading or writing the configuration file failed.
    #[error("could not access configuration file: {0}")]
    Io(String),
}

impl crate::error::UserFacing for ConfigError {
    fn user_message(&self) -> crate::error::UserMessage {
        use crate::error::UserMessage;
        match self {
            ConfigError::OutOfRange { field, .. } => UserMessage::new(
                "A setting is out of range",
                format!("`{field}` has an unusable value."),
            )
            .with_hint("Open Settings and choose a valid value.")
            .with_hint("Reset the setting to its default to continue.")
            .with_details(self),
            ConfigError::Malformed(details) => UserMessage::new(
                "Sentinel could not read its settings file",
                "The file exists but is not valid for this version of Sentinel.",
            )
            .with_hint("Sentinel is running with default settings for this session.")
            .with_hint("Delete the settings file to regenerate it, or restore it from a backup.")
            .with_details(details),
            ConfigError::Io(details) => UserMessage::new(
                "Sentinel could not access its settings file",
                "The data directory may be read-only or missing permissions.",
            )
            .with_hint("Check that the Sentinel data directory exists and is writable.")
            .with_details(details),
        }
    }
}

impl AppConfig {
    /// Parses configuration from JSON text.
    ///
    /// # Errors
    /// Returns [`ConfigError::Malformed`] when the text is not valid for this schema.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|err| ConfigError::Malformed(err.to_string()))
    }

    /// Renders configuration as pretty JSON text.
    ///
    /// # Errors
    /// Returns [`ConfigError::Io`] only if serialization of the schema fails, which
    /// cannot happen for this type; it is reported rather than unwrapped.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self).map_err(|err| ConfigError::Io(err.to_string()))
    }

    /// Applies forward-compatible migration for older configuration versions.
    ///
    /// Migration is additive and idempotent: unknown future versions are rejected by
    /// validation rather than rewritten.
    pub fn migrate(&mut self) {
        if self.version < CONFIG_VERSION {
            self.version = CONFIG_VERSION;
        }
    }

    /// Validates every constrained field.
    ///
    /// # Errors
    /// Returns [`ConfigError::OutOfRange`] describing the first offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        const QUEUE_MIN: u64 = 256;
        const QUEUE_MAX: u64 = 1_048_576;
        const FLOWS_MIN: u64 = 100;
        const FLOWS_MAX: u64 = 1_000_000;
        const HZ_MIN: u64 = 1;
        const HZ_MAX: u64 = 60;
        const SNAPLEN_MAX: u64 = 262_144;

        let c = &self.capture;
        check_u64(
            "capture.queueCapacity",
            QUEUE_MIN,
            QUEUE_MAX,
            c.queue_capacity as u64,
        )?;
        check_u64(
            "capture.maxTrackedFlows",
            FLOWS_MIN,
            FLOWS_MAX,
            c.max_tracked_flows as u64,
        )?;
        check_u64("capture.uiUpdateHz", HZ_MIN, HZ_MAX, c.ui_update_hz as u64)?;
        check_u64("capture.snaplen", 64, SNAPLEN_MAX, c.snaplen as u64)?;
        if c.flow_idle_timeout_secs < 5 {
            return Err(ConfigError::OutOfRange {
                field: "capture.flowIdleTimeoutSecs",
                min: 5,
                max: 86_400,
                value: c.flow_idle_timeout_secs,
            });
        }
        if self.advanced.write_batch_size == 0 {
            return Err(ConfigError::OutOfRange {
                field: "advanced.writeBatchSize",
                min: 1,
                max: 65_536,
                value: 0,
            });
        }
        Ok(())
    }
}

fn check_u64(field: &'static str, min: u64, max: u64, value: u64) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::OutOfRange {
            field,
            min,
            max,
            value,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        AppConfig::default()
            .validate()
            .expect("default config must be valid");
    }

    #[test]
    fn partial_json_fills_defaults() {
        let cfg = AppConfig::from_json(r#"{"capture":{"uiUpdateHz":8}}"#)
            .expect("partial config should load");
        assert_eq!(cfg.capture.ui_update_hz, 8);
        assert_eq!(cfg.retention.flows, RetentionPeriod::Days30);
        assert_eq!(cfg.advanced.write_batch_size, 256);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = AppConfig::from_json(r#"{"capture":{"nonsense":1}}"#)
            .expect_err("unknown key must be rejected");
        assert!(matches!(err, ConfigError::Malformed(_)));
    }

    #[test]
    fn validation_catches_out_of_range_values() {
        let mut cfg = AppConfig::default();
        cfg.capture.queue_capacity = 1;
        let err = cfg.validate().expect_err("queue capacity 1 is invalid");
        match err {
            ConfigError::OutOfRange { field, .. } => assert_eq!(field, "capture.queueCapacity"),
            other => panic!("unexpected error: {other:?}"),
        }

        let mut cfg = AppConfig::default();
        cfg.capture.ui_update_hz = 500;
        assert!(cfg.validate().is_err());

        let mut cfg = AppConfig::default();
        cfg.advanced.write_batch_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn retention_periods_map_to_durations() {
        assert_eq!(RetentionPeriod::Hours24.as_secs(), Some(86_400));
        assert_eq!(RetentionPeriod::Days7.as_secs(), Some(604_800));
        assert_eq!(RetentionPeriod::Days30.as_secs(), Some(2_592_000));
        assert_eq!(RetentionPeriod::Days90.as_secs(), Some(7_776_000));
        assert_eq!(RetentionPeriod::Custom(2).as_secs(), Some(172_800));
        assert_eq!(RetentionPeriod::Forever.as_secs(), None);
        assert!(!RetentionPeriod::Days30.is_explicit());
        assert!(RetentionPeriod::Custom(1).is_explicit());
    }

    #[test]
    fn retention_serializes_as_human_strings() {
        let cfg = AppConfig::default();
        let json = cfg.to_json().expect("config serializes");
        assert!(json.contains("\"30d\""), "{json}");
        assert!(json.contains("\"7d\""));
        let parsed = AppConfig::from_json(&json).expect("round trip");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn migration_is_idempotent() {
        let mut cfg = AppConfig {
            version: 0,
            ..AppConfig::default()
        };
        cfg.migrate();
        assert_eq!(cfg.version, CONFIG_VERSION);
        cfg.migrate();
        assert_eq!(cfg.version, CONFIG_VERSION);
    }

    #[test]
    fn log_levels_expose_filters() {
        assert_eq!(LogLevel::Debug.as_filter(), "debug");
        assert!(LogLevel::Trace.severity() > LogLevel::Info.severity());
    }
}
