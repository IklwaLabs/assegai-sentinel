//! The frontend client.
//!
//! [`Frontend`] is what a Tauri command handler or a CLI command calls. It owns an engine
//! handle, converts [`Command`] into an engine request, and converts the answer into a
//! [`CommandResult`]. It holds **no** analysis state: everything a view needs is computed by
//! the engine and arrives as a snapshot.
//!
//! Keeping this layer thin is deliberate. The moment it starts caching, filtering or
//! prioritising results itself, the same logic exists twice and the CLI and the desktop app
//! begin to disagree.

use sentinel_core::request::EngineRequest;
use sentinel_core::{Engine, EngineHandle, EngineOptions};

use crate::error::{ApiError, ApiResult};
use crate::types::{Command, CommandResult};

/// A client for one engine session.
pub struct Frontend {
    engine: Engine,
}

impl Frontend {
    /// Starts an engine and returns a client for it.
    ///
    /// # Errors
    /// Returns an [`ApiError`] when the data directory or database cannot be opened.
    pub async fn start(options: EngineOptions) -> ApiResult<Self> {
        let engine = Engine::start(options).await.map_err(ApiError::from)?;
        Ok(Self { engine })
    }

    /// Starts an engine with default options.
    ///
    /// # Errors
    /// Returns an [`ApiError`] when the engine cannot start.
    pub async fn start_default() -> ApiResult<Self> {
        Self::start(EngineOptions::default()).await
    }

    /// The engine handle, for event subscription and diagnostics.
    #[must_use]
    pub fn handle(&self) -> EngineHandle {
        self.engine.handle()
    }

    /// Subscribes to the engine's event stream.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<sentinel_core::EngineEvent> {
        self.engine.handle().subscribe()
    }

    /// Sends a command and returns its result.
    ///
    /// # Errors
    /// Returns an [`ApiError`] carrying the user-facing message for any failure.
    pub async fn send(&self, command: Command) -> ApiResult<CommandResult> {
        let request = to_request(command);
        let response = self
            .engine
            .handle()
            .request(request)
            .await
            .map_err(ApiError::from)?;
        to_result(response)
    }

    /// Stops the engine, flushing pending writes.
    pub fn shutdown(&self) {
        self.engine.shutdown();
    }
}

/// Converts a serializable command into an engine request.
fn to_request(command: Command) -> EngineRequest {
    match command {
        Command::ListInterfaces => EngineRequest::ListInterfaces,
        Command::Capabilities => EngineRequest::Capabilities,
        Command::Status => EngineRequest::Status,
        Command::Start { interface_id } => EngineRequest::Start { interface_id },
        Command::Stop => EngineRequest::Stop,
        Command::Analyze { path } => EngineRequest::Analyze { path },
        Command::Snapshot => EngineRequest::Snapshot,
        Command::GetConfig => EngineRequest::GetConfig,
        Command::SetConfig { config } => EngineRequest::SetConfig { config },
    }
}

/// Converts an engine response into a serializable result.
fn to_result(response: sentinel_core::request::Response) -> ApiResult<CommandResult> {
    use sentinel_core::request::Response;
    Ok(match response {
        Response::Interfaces(interfaces) => CommandResult::Interfaces { interfaces },
        Response::Capabilities(capabilities) => CommandResult::Capabilities {
            capabilities: *capabilities,
        },
        Response::Status { state, summary } => CommandResult::Status { state, summary },
        Response::Started { state } => CommandResult::Started { state },
        Response::Stopped => CommandResult::Stopped,
        Response::Snapshot(snapshot) => CommandResult::Snapshot { snapshot },
        Response::Config(config) => CommandResult::Config { config: *config },
        Response::Acknowledged => CommandResult::Acknowledged,
    })
}

#[cfg(test)]
mod tests {
    use sentinel_common::config::AppConfig;

    use super::*;

    /// Points `IKLWA_HOME` at a private directory for one test.
    ///
    /// The engine resolves its data root from the environment, which is process-wide, so every
    /// test in this binary shares that one variable. Each test therefore gets a *distinct*
    /// directory named after itself: two tests writing the same SQLite database would corrupt
    /// each other's state, and a shared mutex would serialise the suite for no benefit.
    ///
    /// The most recently started test wins the variable. That is harmless because an engine
    /// resolves its root once, inside `Engine::start`, before it processes anything.
    ///
    /// # Safety
    /// `set_var` is unsafe because it is not thread-safe against a concurrent reader. These tests
    /// are `#[tokio::test]` on single-threaded runtimes, and the variable is read only inside
    /// `Engine::start`, which has already returned for any engine still running.
    fn use_temp_home(name: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("temp dir");
        let home = temp.path().join(name);
        // SAFETY: see the note above; no concurrent environment access in this test binary.
        unsafe {
            std::env::set_var("IKLWA_HOME", &home);
        }
        temp
    }

    #[tokio::test]
    async fn a_session_starts_and_stops_through_commands() {
        let _home = use_temp_home("session");
        let frontend = Frontend::start(EngineOptions {
            queue_capacity: 512,
            ..EngineOptions::default()
        })
        .await
        .expect("start engine");

        // Interfaces: either a real list or a typed error, never a panic.
        match frontend.send(Command::ListInterfaces).await {
            Ok(CommandResult::Interfaces { interfaces }) => {
                assert!(
                    !interfaces.iter().any(|iface| iface.id.is_empty()),
                    "ids must be populated"
                );
            }
            Err(err) => {
                // A missing capture driver is a legitimate environment, and it must arrive as a
                // message rather than a crash.
                assert!(!err.title.is_empty());
            }
            Ok(other) => panic!("unexpected result: {other:?}"),
        }

        // Capabilities always answer, because diagnostics must work even without a driver.
        let capabilities = frontend.send(Command::Capabilities).await;
        assert!(
            matches!(
                capabilities,
                Ok(CommandResult::Capabilities { .. }) | Ok(CommandResult::Acknowledged)
            ),
            "capabilities must always produce a usable answer"
        );

        let CommandResult::Status { state, .. } =
            frontend.send(Command::Status).await.expect("status")
        else {
            panic!("expected a status result");
        };
        assert!(state.is_idle(), "a fresh engine is idle, got {state:?}");

        // Starting a non-existent interface fails with a typed error naming it.
        let err = frontend
            .send(Command::Start {
                interface_id: "sentinel-missing".to_string(),
            })
            .await
            .expect_err("a missing interface cannot be started");
        assert!(
            err.hint
                .iter()
                .any(|hint| hint.contains("interface picker")),
            "{err:?}"
        );

        // Stopping while idle is an invalid state, reported as such.
        assert!(frontend.send(Command::Stop).await.is_err());

        frontend.shutdown();
    }

    #[tokio::test]
    async fn configuration_round_trips_and_is_validated() {
        let _home = use_temp_home("config");
        let frontend = Frontend::start(EngineOptions::default())
            .await
            .expect("start engine");

        let CommandResult::Config { config } = frontend
            .send(Command::GetConfig)
            .await
            .expect("read config")
        else {
            panic!("expected a config result");
        };
        assert_eq!(config, AppConfig::default());

        let mut updated = config;
        updated.capture.ui_update_hz = 8;
        let CommandResult::Config { config: applied } = frontend
            .send(Command::SetConfig { config: updated })
            .await
            .expect("set config")
        else {
            panic!("expected a config result");
        };
        assert_eq!(applied.capture.ui_update_hz, 8);

        // An out-of-range value is rejected at the boundary, with an explanation.
        let mut invalid = applied.clone();
        invalid.capture.ui_update_hz = 0;
        let err = frontend
            .send(Command::SetConfig { config: invalid })
            .await
            .expect_err("an out-of-range value must be rejected");
        assert!(!err.summary.is_empty());

        frontend.shutdown();
    }

    #[tokio::test]
    async fn analysing_a_missing_file_fails_with_an_explanation() {
        let _home = use_temp_home("missing");
        let frontend = Frontend::start(EngineOptions::default())
            .await
            .expect("start engine");
        let err = frontend
            .send(Command::Analyze {
                path: "definitely-missing.pcap".to_string(),
            })
            .await
            .expect_err("a missing file cannot be analysed");
        assert!(!err.title.is_empty());

        frontend.shutdown();
    }

    #[tokio::test]
    async fn a_snapshot_is_available_before_any_traffic_exists() {
        let _home = use_temp_home("empty");
        let frontend = Frontend::start(EngineOptions::default())
            .await
            .expect("start engine");
        let CommandResult::Snapshot { snapshot } =
            frontend.send(Command::Snapshot).await.expect("snapshot")
        else {
            panic!("expected a snapshot result");
        };

        assert_eq!(snapshot.total_packets, 0);
        assert!(snapshot.connections.is_empty());
        assert!(snapshot.traffic.is_empty());
        assert!(snapshot.state.is_idle());
        // The configuration travels with the snapshot so a view can display effective values.
        assert_eq!(snapshot.config, AppConfig::default());

        frontend.shutdown();
    }

    #[tokio::test]
    async fn analysing_a_capture_file_produces_flows_through_the_same_api() {
        use sentinel_parser::fixtures;
        use sentinel_parser::pcap::{LINKTYPE_ETHERNET, PcapWriter};

        let home = use_temp_home("analyze");
        let capture_path = home.path().join("fixture.pcap");
        {
            let mut writer = PcapWriter::create(&capture_path, LINKTYPE_ETHERNET, 65_535)
                .expect("create capture");
            writer
                .write_packet(1_000_000, &fixtures::tcp_frame(52_341, 443, 0x02, &[]))
                .expect("write request");
            writer
                .write_packet(
                    1_000_100,
                    &fixtures::tcp_reply_frame(443, 52_341, 0x12, &[]),
                )
                .expect("write reply");
            writer.flush().expect("flush");
        }

        let frontend = Frontend::start(EngineOptions::default())
            .await
            .expect("start engine");
        let CommandResult::Started { state } = frontend
            .send(Command::Analyze {
                path: capture_path.display().to_string(),
            })
            .await
            .expect("analysis starts")
        else {
            panic!("expected a started result");
        };
        assert!(state.is_active());

        // The engine drains the file on its own tick, so the snapshot is polled rather than
        // requested once. This is exactly the shape a UI uses. The connection list is read
        // before the state check, because a short file finishes within a tick and the final
        // snapshot is the one that still carries its flows.
        let mut connections = Vec::new();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let CommandResult::Snapshot { snapshot } =
                frontend.send(Command::Snapshot).await.expect("snapshot")
            else {
                panic!("expected a snapshot result");
            };
            connections = snapshot.connections.clone();
            if !snapshot.state.is_active() {
                break;
            }
        }

        assert_eq!(
            connections.len(),
            1,
            "the exchange is one bidirectional flow"
        );
        assert_eq!(connections[0].protocol, "TCP");
        assert_eq!(connections[0].service.as_deref(), Some("HTTPS"));
        assert_eq!(connections[0].packets, 2);
        assert!(connections[0].total_bytes() > 0);

        frontend.shutdown();
    }
}
