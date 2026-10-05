//! The command and event contract every Iklwa Sentinel frontend uses.
//!
//! # Why this crate exists
//!
//! The desktop shell, the CLI and a future remote sensor all talk to the same engine. This crate
//! is the single definition of that conversation:
//!
//! - [`Frontend`]: a thin client over the engine, holding no analysis state.
//! - [`Command`]: one request enum, serializable, so a frontend can send work without knowing
//!   anything about the pipeline.
//! - [`ApiError`]: one error shape for the wire, with the user-facing message already attached.
//!
//! # What frontends must not do
//!
//! - Perform analysis. If a number is needed, the engine computes it.
//! - Hold authoritative state. A frontend keeps a cache for rendering and discards it freely.
//! - Subscribe to per-packet events. The engine publishes aggregate snapshots at a fixed rate.
//!
//! # Stability
//!
//! Field names are `camelCase` and additive changes only. Renaming or removing a field is a
//! breaking change to every frontend at once, so new information goes in a new field and old
//! fields are retired with the version that introduced them.

pub mod error;
pub mod frontend;

pub use error::{ApiError, ApiErrorKind, ApiResult};
pub use frontend::Frontend;

/// Serializable re-exports of the engine's data model.
///
/// Frontends import these types rather than restating the shapes, so a Rust change and a
/// TypeScript change cannot drift apart silently.
pub mod types {
    pub use sentinel_common::config::{
        AdvancedConfig, AppConfig, AppearanceConfig, CaptureConfig, LogLevel, PrivacyConfig,
        RetentionConfig, RetentionPeriod, ThemeMode,
    };
    pub use sentinel_common::error::UserMessage;
    pub use sentinel_common::metrics::MetricsSnapshot;
    pub use sentinel_common::net::{InterfaceAddress, InterfaceKind, NetworkInterface};
    pub use sentinel_core::error::CoreError;
    pub use sentinel_core::event::{
        ConnectionRow, EngineEvent, EngineSnapshot, EventKind, TrafficPoint,
    };
    pub use sentinel_core::pipeline::{PipelineCounters, PipelineStats, QueueAccounting};
    pub use sentinel_core::request::Response;
    pub use sentinel_core::session::{SessionState, SessionSummary};
    pub use sentinel_platform::capabilities::{Capabilities, CaptureBackend, PrivilegeState};

    /// A request a frontend can send to the engine.
    ///
    /// Mirrors [`sentinel_core::request::EngineRequest`] but adds a serializable form so a
    /// frontend can construct one from JSON. The engine itself takes the core enum; the
    /// conversion happens in [`Frontend`].
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(
        tag = "type",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )]
    pub enum Command {
        /// List capturable network interfaces.
        ListInterfaces,
        /// Report what capture is possible in this process.
        Capabilities,
        /// Report the current session state.
        Status,
        /// Start monitoring an interface.
        Start {
            /// Interface id from `ListInterfaces`.
            interface_id: String,
        },
        /// Stop monitoring.
        Stop,
        /// Analyse a capture file offline.
        Analyze {
            /// Path to a classic PCAP file.
            path: String,
        },
        /// Fetch a snapshot now instead of waiting for the next heartbeat.
        Snapshot,
        /// Read the effective configuration.
        GetConfig,
        /// Replace the effective configuration.
        SetConfig {
            /// Complete configuration. Validated by the engine before it is applied.
            config: AppConfig,
        },
    }

    /// A response to a [`Command`], in serializable form.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(
        tag = "type",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )]
    pub enum CommandResult {
        /// Available interfaces.
        Interfaces {
            /// The list, ordered with the most plausible capture target first.
            interfaces: Vec<NetworkInterface>,
        },
        /// Platform capabilities.
        Capabilities {
            /// What this process can do.
            capabilities: Capabilities,
        },
        /// Current state and counters.
        Status {
            /// Session state.
            state: SessionState,
            /// Counters for the current or most recent session.
            summary: SessionSummary,
        },
        /// A session started.
        Started {
            /// The new state.
            state: SessionState,
        },
        /// A session stopped.
        Stopped,
        /// A full snapshot.
        Snapshot {
            /// Everything a view needs.
            snapshot: Box<EngineSnapshot>,
        },
        /// The effective configuration.
        Config {
            /// Configuration in force.
            config: AppConfig,
        },
        /// The request completed with nothing to return.
        Acknowledged,
    }

    /// Where Sentinel keeps its data, and anything it wants to say on start-up.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Diagnostics {
        /// Root directory for everything Sentinel owns.
        pub data_directory: String,
        /// SQLite database file.
        pub database_file: String,
        /// Rolling log directory.
        pub logs_directory: String,
        /// Generated reports and exports.
        pub exports_directory: String,
        /// Non-fatal problems found at start-up, such as a repaired settings value.
        pub warnings: Vec<String>,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::types::*;

    #[test]
    fn commands_round_trip_through_json() {
        let command = Command::Start {
            interface_id: "3".to_string(),
        };
        let json = serde_json::to_value(&command).expect("serialize");
        assert_eq!(json, json!({"type": "start", "interfaceId": "3"}));

        let parsed: Command = serde_json::from_value(json).expect("deserialize");
        assert_eq!(parsed, command);
    }

    #[test]
    fn unit_commands_have_no_payload() {
        for command in [
            Command::ListInterfaces,
            Command::Capabilities,
            Command::Status,
            Command::Stop,
            Command::Snapshot,
            Command::GetConfig,
        ] {
            let json = serde_json::to_value(&command).expect("serialize");
            assert_eq!(json["type"], json!(command_tag(&command)));
            assert_eq!(
                json.as_object().expect("object").len(),
                1,
                "a unit command has no fields"
            );
        }
    }

    /// The wire tag for a command, for symmetry with the serialization test above.
    fn command_tag(command: &Command) -> String {
        serde_json::to_value(command).expect("serialize")["type"]
            .as_str()
            .expect("a string tag")
            .to_string()
    }

    #[test]
    fn an_unknown_command_is_rejected_rather_than_ignored() {
        // A typo in a frontend must fail loudly, not silently do nothing.
        let parsed: Result<Command, _> = serde_json::from_value(json!({"type": "listInterfacez"}));
        assert!(parsed.is_err(), "an unknown command type must be an error");
    }

    #[test]
    fn results_are_tagged() {
        let result = CommandResult::Stopped;
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json, json!({"type": "stopped"}));
    }

    #[test]
    fn session_states_serialize_with_their_payload() {
        let monitoring = SessionState::Monitoring {
            interface: "3".to_string(),
            interface_name: "Ethernet".to_string(),
        };
        let json = serde_json::to_value(&monitoring).expect("serialize");

        // Adjacently tagged: the tag is `state` and the payload sits under `detail`.
        assert_eq!(json["state"], json!("monitoring"));
        assert_eq!(json["detail"]["interface"], json!("3"));
        assert_eq!(json["detail"]["interfaceName"], json!("Ethernet"));

        let idle = serde_json::to_value(SessionState::Idle).expect("serialize");
        assert_eq!(idle["state"], json!("idle"));

        let failed = serde_json::to_value(SessionState::failed("denied")).expect("serialize");
        assert_eq!(failed["state"], json!("failed"));
        assert_eq!(failed["detail"]["reason"], json!("denied"));
    }

    #[test]
    fn retention_periods_serialize_as_human_strings() {
        let config = AppConfig::default();
        let json = serde_json::to_value(&config).expect("serialize config");
        assert_eq!(json["retention"]["flows"], json!("30d"));
        assert_eq!(json["retention"]["trafficSamples"], json!("7d"));
        assert_eq!(json["capture"]["uiUpdateHz"], json!(4));
    }

    #[test]
    fn interface_kinds_serialize_as_lowercase_tags() {
        let kind = serde_json::to_value(InterfaceKind::Wireless).expect("serialize");
        assert_eq!(kind, json!("wireless"));
    }
}
