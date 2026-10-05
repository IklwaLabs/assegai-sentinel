//! Engine errors.

use sentinel_common::error::{UserFacing, UserMessage};

/// Result alias for engine operations.
pub type Result<T> = std::result::Result<T, CoreError>;

/// A failure in the engine or one of its stages.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Capture could not be started or continued.
    #[error("capture failed: {0}")]
    Capture(#[from] sentinel_capture::CaptureError),

    /// The operating system layer failed.
    #[error("platform integration failed: {0}")]
    Platform(#[from] sentinel_platform::PlatformError),

    /// Local storage failed.
    #[error("storage failed: {0}")]
    Storage(#[from] sentinel_storage::StorageError),

    /// A configuration value was unusable.
    #[error("configuration is invalid: {0}")]
    Config(#[from] sentinel_common::config::ConfigError),

    /// The requested interface is not in the current interface list.
    #[error("interface '{0}' was not found among the available network interfaces")]
    UnknownInterface(String),

    /// The engine is already running a capture session.
    #[error("monitoring is already running on interface '{0}'")]
    AlreadyRunning(String),

    /// The engine is not running a capture session.
    #[error("monitoring is not running")]
    NotRunning,

    /// The engine's own task ended unexpectedly.
    #[error("the engine stopped unexpectedly: {0}")]
    EngineStopped(String),

    /// A request could not be delivered or answered.
    #[error("the engine did not answer: {0}")]
    RequestFailed(String),
}

impl UserFacing for CoreError {
    fn user_message(&self) -> UserMessage {
        match self {
            CoreError::Capture(err) => err.user_message(),
            CoreError::Platform(err) => err.user_message(),
            CoreError::Storage(err) => err.user_message(),
            CoreError::Config(err) => err.user_message(),

            CoreError::UnknownInterface(id) => UserMessage::new(
                "That network interface is no longer available",
                format!("Sentinel could not find an interface identified as '{id}'."),
            )
            .with_hint("Adapters can be renamed or disconnected while the app is open.")
            .with_hint("Open the interface picker and choose the adapter again.")
            .with_details(format!("requested interface id: {id}")),

            CoreError::AlreadyRunning(id) => UserMessage::new(
                "Monitoring is already running",
                format!("Sentinel is already capturing from '{id}'."),
            )
            .with_hint("Stop the current session before starting another one."),

            CoreError::NotRunning => UserMessage::new(
                "Monitoring is not running",
                "This action needs an active capture session.",
            )
            .with_hint("Select a network interface and start monitoring first."),

            CoreError::EngineStopped(details) => UserMessage::new(
                "Sentinel lost its monitoring engine",
                "The internal engine task stopped, so no network data is being analysed.",
            )
            .with_hint("Restart Sentinel to resume monitoring.")
            .with_hint(
                "Export your logs from Settings before restarting, so the cause is recorded.",
            )
            .with_details(details.clone()),

            CoreError::RequestFailed(details) => UserMessage::new(
                "Sentinel could not complete that request",
                "The engine did not respond in time. Live monitoring may be busy.",
            )
            .with_hint("Try again; if it keeps happening, restart Sentinel.")
            .with_details(details.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_produces_actionable_guidance() {
        let errors = [
            CoreError::UnknownInterface("3".to_string()),
            CoreError::AlreadyRunning("Ethernet".to_string()),
            CoreError::NotRunning,
            CoreError::EngineStopped("task panicked".to_string()),
            CoreError::RequestFailed("timeout".to_string()),
        ];
        for err in errors {
            let message = err.user_message();
            assert!(!message.title.is_empty(), "{err:?} has no title");
            assert!(!message.summary.is_empty(), "{err:?} has no summary");
            assert!(
                !message.hint.is_empty(),
                "{err:?} tells the user nothing to do"
            );
        }
    }

    #[test]
    fn state_errors_name_the_interface() {
        let err = CoreError::UnknownInterface("Wi-Fi".to_string());
        assert!(err.to_string().contains("Wi-Fi"));
        assert!(
            err.user_message()
                .hint
                .iter()
                .any(|hint| hint.contains("interface picker"))
        );
    }

    #[test]
    fn subordinate_errors_keep_their_own_messages() {
        let err = CoreError::Capture(sentinel_capture::CaptureError::PermissionDenied {
            details: "denied".to_string(),
        });
        let message = err.user_message();
        assert!(message.title.contains("permission"), "{message:?}");
    }

    #[test]
    fn not_running_tells_the_user_what_to_do() {
        let message = CoreError::NotRunning.user_message();
        assert!(
            message
                .hint
                .iter()
                .any(|hint| hint.contains("start monitoring"))
        );
    }
}
