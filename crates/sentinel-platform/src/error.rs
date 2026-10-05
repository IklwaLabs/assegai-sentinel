//! Platform errors with actionable, per-operating-system messages.

use sentinel_common::error::{UserFacing, UserMessage};

/// Result alias for platform operations.
pub type Result<T> = std::result::Result<T, PlatformError>;

/// A failure originating in operating system integration.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The process lacks the privileges required for the requested operation.
    #[error("{operation} requires elevated privileges")]
    PermissionDenied {
        /// What was attempted, e.g. "packet capture".
        operation: &'static str,
    },

    /// The capture library or driver is not installed.
    #[error("{library} is not available: {details}")]
    LibraryUnavailable {
        /// `Npcap`, `libpcap` or similar.
        library: &'static str,
        /// Underlying detail.
        details: String,
    },

    /// The requested interface does not exist or cannot be opened.
    #[error("network interface '{id}' cannot be opened: {details}")]
    InterfaceUnavailable {
        /// Requested interface id.
        id: String,
        /// Underlying detail.
        details: String,
    },

    /// The feature is not available on this operating system or in this build.
    #[error("{feature} is not available on {platform}")]
    Unsupported {
        /// Short feature name.
        feature: &'static str,
        /// Platform name.
        platform: &'static str,
    },

    /// A filesystem operation failed.
    #[error("{context}: {details}")]
    Io {
        /// What Sentinel was doing.
        context: &'static str,
        /// Underlying detail.
        details: String,
    },

    /// The interface list could not be read.
    #[error("could not enumerate network interfaces: {details}")]
    Enumeration {
        /// Underlying detail.
        details: String,
    },
}

impl PlatformError {
    /// The platform this error was produced on, used for message routing.
    pub const fn platform_name() -> &'static str {
        if cfg!(target_os = "windows") {
            "Windows"
        } else if cfg!(target_os = "linux") {
            "Linux"
        } else if cfg!(target_os = "macos") {
            "macOS"
        } else if cfg!(target_os = "android") {
            "Android"
        } else {
            "this platform"
        }
    }
}

impl From<std::io::Error> for PlatformError {
    fn from(err: std::io::Error) -> Self {
        PlatformError::Io {
            context: "local filesystem operation",
            details: err.to_string(),
        }
    }
}

impl UserFacing for PlatformError {
    fn user_message(&self) -> UserMessage {
        match self {
            PlatformError::PermissionDenied { operation } => {
                let mut msg = UserMessage::new(
                    format!("{operation} permission is missing"),
                    "Sentinel needs additional privileges to read network packets, and the current process does not have them.",
                );
                msg.hint.push(if cfg!(target_os = "windows") {
                    "Close Sentinel and reopen it from an elevated PowerShell prompt: right-click PowerShell, choose Run as administrator, then run Sentinel again.".to_string()
                } else if cfg!(target_os = "linux") {
                    "Grant packet capture capability: run `sudo setcap cap_net_raw,cap_net_admin=eip $(which sentinel)` once, then start Sentinel again.".to_string()
                } else if cfg!(target_os = "macos") {
                    "Run Sentinel with elevated privileges: `sudo sentinel capture`. On macOS 13 or newer you can instead grant access to /dev/bpf* to your user.".to_string()
                } else {
                    "Restart the application with the privileges your system requires for packet capture.".to_string()
                });
                if cfg!(target_os = "windows") {
                    msg.hint
                        .push("Verify that Npcap is installed and that you allowed driver-only or full installation.".to_string());
                }
                msg.with_details(self)
            }
            PlatformError::LibraryUnavailable { library, details } => {
                let mut msg = UserMessage::new(
                    format!("{library} is not installed"),
                    "Sentinel relies on a packet capture driver that is not available on this machine.",
                );
                if cfg!(target_os = "windows") {
                    msg.hint.push("Install Npcap from https://npcap.com (choose \"Install Npcap in WinPcap API-compatible mode\").".to_string());
                    msg.hint
                        .push("Restart Windows after installing Npcap.".to_string());
                } else if cfg!(target_os = "linux") {
                    msg.hint.push("Install libpcap: `sudo apt install libpcap0.8` (Debian/Ubuntu) or `sudo dnf install libpcap` (Fedora).".to_string());
                } else if cfg!(target_os = "macos") {
                    msg.hint.push(
                        "Install libpcap: `brew install libpcap` or `xcode-select --install`."
                            .to_string(),
                    );
                }
                msg.hint
                    .push("After installing, run `sentinel doctor` to verify.".to_string());
                msg.with_details(details.clone())
            }
            PlatformError::InterfaceUnavailable { id, details } => UserMessage::new(
                "Sentinel could not access this network interface",
                format!("The interface '{id}' was not available when capture was requested."),
            )
            .with_hint("Pick the interface again; it may have been renamed or disconnected.")
            .with_hint("Run `sentinel interfaces` to see the current list.")
            .with_details(details.clone()),
            PlatformError::Unsupported { feature, platform } => UserMessage::new(
                format!("{feature} is not available here"),
                format!("This capability does not exist on {platform} in this build."),
            )
            .with_details(details_or_self(self, platform, feature)),
            PlatformError::Io { context, details } => UserMessage::new(
                "Sentinel could not access its data directory",
                format!("A local file operation failed while {context}."),
            )
            .with_hint("Check available disk space and folder permissions.")
            .with_hint("See Settings for the data directory location.")
            .with_details(details.clone()),
            PlatformError::Enumeration { details } => UserMessage::new(
                "Sentinel could not list network interfaces",
                "The operating system did not return a usable interface list.",
            )
            .with_hint("Confirm that at least one network adapter is enabled.")
            .with_hint(
                "Run `sentinel doctor` and include the details in a bug report if this persists.",
            )
            .with_details(details.clone()),
        }
    }
}

fn details_or_self(err: &PlatformError, platform: &str, feature: &str) -> String {
    let rendered = err.to_string();
    if rendered.contains(platform) && rendered.contains(feature) {
        rendered
    } else {
        format!("{rendered} (platform: {platform}, feature: {feature})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_error_names_the_operation() {
        let msg = PlatformError::PermissionDenied {
            operation: "packet capture",
        }
        .user_message();
        assert!(msg.title.contains("packet capture"));
        assert!(!msg.hint.is_empty(), "elevation hints must be actionable");
    }

    #[test]
    fn interface_error_suggests_relisting() {
        let msg = PlatformError::InterfaceUnavailable {
            id: "eth0".to_string(),
            details: "no such device".to_string(),
        }
        .user_message();
        assert!(msg.title.contains("could not access"));
        assert!(msg.hint.iter().any(|h| h.contains("sentinel interfaces")));
        assert_eq!(msg.details.as_deref(), Some("no such device"));
    }

    #[test]
    fn io_error_mentions_data_directory() {
        let msg = PlatformError::Io {
            context: "writing the database",
            details: "disk full".to_string(),
        }
        .user_message();
        assert!(msg.title.contains("data directory"));
        assert!(msg.summary.contains("writing the database"));
    }

    #[test]
    fn unsupported_error_keeps_platform_context() {
        let msg = PlatformError::Unsupported {
            feature: "interface capture",
            platform: PlatformError::platform_name(),
        }
        .user_message();
        assert!(msg.summary.contains(PlatformError::platform_name()));
    }
}
