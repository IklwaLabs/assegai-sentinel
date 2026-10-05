//! Capture errors with per-operating-system guidance.
//!
//! Capture fails for a small number of reasons, and each has a specific fix that depends on
//! the operating system. These errors exist so the user is told what to do, not just what
//! failed.

use sentinel_common::error::{UserFacing, UserMessage};

/// Result alias for capture operations.
pub type Result<T> = std::result::Result<T, CaptureError>;

/// A capture failure.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// The interface disappeared or cannot be opened.
    #[error("could not open interface '{interface}': {details}")]
    InterfaceUnavailable {
        /// Interface identifier.
        interface: String,
        /// Underlying detail.
        details: String,
    },

    /// The process lacks capture privileges.
    #[error("packet capture permission is missing: {details}")]
    PermissionDenied {
        /// Underlying detail.
        details: String,
    },

    /// The capture library or driver is missing.
    #[error("capture driver is unavailable: {details}")]
    DriverUnavailable {
        /// Underlying detail.
        details: String,
    },

    /// The capture buffer overflowed, so the kernel dropped frames.
    #[error("capture buffer overflowed: {dropped} packets dropped by the driver")]
    BufferOverflow {
        /// Number of dropped packets.
        dropped: u32,
    },

    /// A blocking read returned an error the adapter cannot interpret.
    #[error("capture read failed: {0}")]
    ReadFailed(String),

    /// An offline capture file could not be read.
    #[error("{0}")]
    File(sentinel_parser::PcapFileError),

    /// The capture was stopped while a read was in progress.
    #[error("capture stopped")]
    Stopped,
}

impl From<sentinel_parser::PcapFileError> for CaptureError {
    fn from(err: sentinel_parser::PcapFileError) -> Self {
        CaptureError::File(err)
    }
}

impl UserFacing for CaptureError {
    fn user_message(&self) -> UserMessage {
        match self {
            CaptureError::InterfaceUnavailable { interface, details } => UserMessage::new(
                "Sentinel could not open this network interface",
                format!("The interface '{interface}' was not available when capture started."),
            )
            .with_hint("It may have been renamed or disconnected since the list was shown.")
            .with_hint("Run `sentinel interfaces` to see the current list, then try again.")
            .with_details(details.clone()),

            CaptureError::PermissionDenied { details } => {
                let mut message = UserMessage::new(
                    "Packet capture permission is missing",
                    "Sentinel needs elevated privileges to read network packets, and this process does not have them.",
                );
                if cfg!(target_os = "windows") {
                    message.hint.push(
                        "Close Sentinel and reopen it from an elevated PowerShell prompt: \
                         right-click PowerShell, choose Run as administrator, then run Sentinel again."
                            .to_string(),
                    );
                    message.hint.push(
                        "Verify that Npcap is installed and that you allowed the driver-only or full installation."
                            .to_string(),
                    );
                } else if cfg!(target_os = "linux") {
                    message.hint.push(
                        "Grant packet capability once: \
                         sudo setcap cap_net_raw,cap_net_admin=eip $(which sentinel)"
                            .to_string(),
                    );
                    message.hint.push("Or add your user to the `pcap` group and start Sentinel again.".to_string());
                } else if cfg!(target_os = "macos") {
                    message.hint.push("Run Sentinel elevated: sudo sentinel capture".to_string());
                    message.hint.push(
                        "On macOS 13 or newer you can instead grant access to /dev/bpf* to your user."
                            .to_string(),
                    );
                }
                message.with_details(details.clone())
            }

            CaptureError::DriverUnavailable { details } => {
                let mut message = UserMessage::new(
                    "The packet capture driver is not available",
                    "Sentinel relies on a system capture driver that is not installed on this machine.",
                );
                if cfg!(target_os = "windows") {
                    message.hint.push("Install Npcap from https://npcap.com, then restart Windows.".to_string());
                } else if cfg!(target_os = "linux") {
                    message.hint
                        .push("Install libpcap: sudo apt install libpcap0.8 (Debian/Ubuntu).".to_string());
                } else if cfg!(target_os = "macos") {
                    message.hint.push("Install libpcap: brew install libpcap, or xcode-select --install.".to_string());
                }
                message.hint.push("After installing, run `sentinel doctor` to verify.".to_string());
                message.with_details(details.clone())
            }

            CaptureError::BufferOverflow { dropped } => UserMessage::new(
                "Sentinel lost some packets at the driver level",
                format!(
                    "The operating system dropped {dropped} packets because the capture buffer filled before Sentinel read them. Statistics for this session are incomplete."
                ),
            )
            .with_hint("Close other traffic-heavy applications, or monitor a less busy interface.")
            .with_hint("This is a system-level limit, not a Sentinel fault; the count is shown in the diagnostics panel."),

            CaptureError::ReadFailed(details) => UserMessage::new(
                "Sentinel lost contact with the network interface",
                "Reading from the capture device failed and monitoring has been stopped.",
            )
            .with_hint("Restart monitoring to try again.")
            .with_hint("If this repeats, the adapter may be unstable; check the driver.")
            .with_details(details.clone()),

            CaptureError::File(err) => err.user_message(),

            CaptureError::Stopped => UserMessage::new(
                "Monitoring stopped",
                "Packet capture was stopped.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_error_gives_platform_specific_steps() {
        let err = CaptureError::PermissionDenied {
            details: "permission denied".to_string(),
        };
        let message = err.user_message().to_plain_text();

        assert!(
            message.contains("administrator")
                || message.contains("setcap")
                || message.contains("sudo")
        );
        assert!(
            message.contains("permission denied"),
            "technical detail must survive"
        );
    }

    #[test]
    fn interface_error_suggests_relisting() {
        let message = CaptureError::InterfaceUnavailable {
            interface: "Ethernet".to_string(),
            details: "no such device".to_string(),
        }
        .user_message();
        assert!(
            message
                .hint
                .iter()
                .any(|hint| hint.contains("sentinel interfaces"))
        );
    }

    #[test]
    fn buffer_overflow_is_blamed_on_the_system_not_sentinel() {
        let message = CaptureError::BufferOverflow { dropped: 1_234 }.user_message();
        assert!(message.summary.contains("1234"));
        assert!(message.summary.contains("incomplete"));
        assert!(!message.hint.is_empty());
    }

    #[test]
    fn file_errors_pass_through_their_own_messages() {
        let err = CaptureError::File(sentinel_parser::PcapFileError::TruncatedPacket);
        let message = err.user_message();
        assert!(message.title.contains("ends unexpectedly"), "{message:?}");
    }

    #[test]
    fn pcapng_is_reported_with_a_conversion_hint() {
        let err = CaptureError::from(sentinel_parser::PcapFileError::UnsupportedFormat("PCAPNG"));
        assert!(err.user_message().to_plain_text().contains("editcap"));
    }
}
