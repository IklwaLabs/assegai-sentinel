//! Platform-specific user guidance.
//!
//! # Why this lives here
//!
//! Telling someone how to grant packet-capture privileges is unavoidably platform-specific:
//! Windows wants an elevated shell, Linux wants a file capability, macOS wants group
//! membership. The temptation is to branch on `cfg(target_os)` at the point of use, and that is
//! exactly what this crate exists to prevent -- a `cfg` in business logic means the same
//! question gets answered differently in two places, and one of them will be wrong.
//!
//! So the platform is asked once, here, and every other crate asks this module what to tell
//! the user. Adding a platform means adding a file and one `cfg` line, not auditing every
//! error message that mentions a driver.

use sentinel_common::error::UserMessage;

/// Builds the guidance for a missing packet-capture permission.
///
/// Returns a message with the platform's own remedy attached. On an unrecognised platform the
/// remedy is the generic one, which is still better than an error with no next step.
#[must_use]
pub fn capture_permission_message(mut message: UserMessage) -> UserMessage {
    if cfg!(target_os = "windows") {
        message.hint.push(
            "Close Sentinel and reopen it from an elevated PowerShell prompt: \
             right-click PowerShell, choose Run as administrator, then start Sentinel again."
                .to_string(),
        );
        message.hint.push(
            "Confirm Npcap is installed and that you allowed the driver-only or full installation."
                .to_string(),
        );
    } else if cfg!(target_os = "linux") {
        message.hint.push(
            "Grant the capability once: \
             sudo setcap cap_net_raw,cap_net_admin=eip $(which sentinel)"
                .to_string(),
        );
        message
            .hint
            .push("Or add your user to the `pcap` group and start Sentinel again.".to_string());
    } else if cfg!(target_os = "macos") {
        message
            .hint
            .push("Run Sentinel with sudo: sudo sentinel capture".to_string());
        message.hint.push(
            "On macOS 13 or newer you can instead grant your user access to /dev/bpf*.".to_string(),
        );
    } else if cfg!(target_os = "android") {
        message.hint.push(
            "Grant the packet permission when Android asks for it, or enable the local VPN \
             capture mode in Settings."
                .to_string(),
        );
    } else {
        message.hint.push(
            "Capture needs elevated privileges on every platform Sentinel supports.".to_string(),
        );
    }
    message
}

/// Builds the guidance for a missing capture driver.
///
/// The install command differs per platform and per package manager, so this names the
/// distribution's package rather than guessing a single universal instruction.
#[must_use]
pub fn missing_driver_message(mut message: UserMessage) -> UserMessage {
    if cfg!(target_os = "windows") {
        message
            .hint
            .push("Install Npcap from https://npcap.com, then restart Windows.".to_string());
    } else if cfg!(target_os = "linux") {
        message.hint.push(
            "Install libpcap: sudo apt install libpcap0.8-dev (Debian, Ubuntu) or \
             sudo dnf install libpcap-devel (Fedora, RHEL)."
                .to_string(),
        );
    } else if cfg!(target_os = "macos") {
        message.hint.push(
            "Install the command line tools: xcode-select --install. libpcap itself ships with macOS."
                .to_string(),
        );
    } else if cfg!(target_os = "android") {
        message
            .hint
            .push("Capture on Android uses a local VPN and needs no separate driver.".to_string());
    } else {
        message
            .hint
            .push("Install a libpcap-compatible capture driver for this platform.".to_string());
    }
    message
}

/// Builds the guidance for an interface that cannot be captured.
///
/// Some adapters cannot be opened at all -- down, virtual, or refused by the driver. Saying so
/// plainly is better than hiding the row and leaving a person to wonder where their Wi-Fi went.
#[must_use]
pub fn interface_unavailable_message(mut message: UserMessage) -> UserMessage {
    if cfg!(target_os = "windows") {
        message.hint.push(
            "Npcap cannot open some adapters, including certain virtual and VPN interfaces. \
             Choose a physical adapter instead."
                .to_string(),
        );
    } else if cfg!(target_os = "linux") {
        message.hint.push(
            "Some virtual interfaces (Docker bridges, VPN tunnels) cannot be captured even when \
             listed. Choose a physical adapter instead."
                .to_string(),
        );
    } else {
        // macOS and anything unrecognised get the same generic advice, which is honest: it is
        // the part that holds on every platform. The platform-specific remedies above are where
        // a real difference exists, and inventing one where it does not would be noise.
        message
            .hint
            .push("Bring the interface up first, or choose a different adapter.".to_string());
    }
    message
}

/// Builds the guidance for a capture file whose format is not supported.
///
/// PCAPNG is a different container with per-block compression. Rather than half-reading it,
/// Sentinel refuses and says how to convert, because a wrong answer here looks like a clean
/// capture of nothing.
#[must_use]
pub fn unsupported_file_format_message(mut message: UserMessage) -> UserMessage {
    message.hint.push(
        "Convert it to classic PCAP first: editcap -F pcap input.pcapng output.pcap".to_string(),
    );
    message.hint.push(
        "editcap ships with Wireshark. Any tool that reads PCAPNG can usually export PCAP."
            .to_string(),
    );
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> UserMessage {
        UserMessage::new("Something went wrong", "A short explanation.")
    }

    #[test]
    fn every_guidance_function_returns_at_least_one_next_step() {
        // An error with no hint is the failure mode this module exists to prevent: the user
        // knows something is wrong and nothing about what to do.
        assert!(!capture_permission_message(base()).hint.is_empty());
        assert!(!missing_driver_message(base()).hint.is_empty());
        assert!(!interface_unavailable_message(base()).hint.is_empty());
        assert!(!unsupported_file_format_message(base()).hint.is_empty());
    }

    #[test]
    fn the_conversion_hint_names_the_concrete_command() {
        let message = unsupported_file_format_message(base());
        assert!(
            message
                .hint
                .iter()
                .any(|hint| hint.contains("editcap -F pcap")),
            "the hint must be runnable, not a description of a hint: {:?}",
            message.hint
        );
    }

    #[test]
    fn guidance_preserves_the_caller_s_title_and_summary() {
        let original = UserMessage::new("Title stays", "Summary stays too.");
        let guided = capture_permission_message(original);
        assert_eq!(guided.title, "Title stays");
        assert_eq!(guided.summary, "Summary stays too.");
    }

    #[test]
    fn guidance_does_not_disturb_technical_details() {
        let mut original = base();
        original.details = Some("LNK1181: cannot open input file 'wpcap.lib'".to_string());
        let guided = missing_driver_message(original);
        assert_eq!(
            guided.details.as_deref(),
            Some("LNK1181: cannot open input file 'wpcap.lib'"),
            "the detail must survive, because a bug report needs it"
        );
    }

    #[test]
    fn a_permission_hint_names_the_remedy_for_this_platform() {
        let hint = capture_permission_message(base()).hint.join(" ");
        let expected: &[&str] = if cfg!(target_os = "windows") {
            &["administrator"]
        } else if cfg!(target_os = "linux") {
            &["setcap"]
        } else if cfg!(target_os = "macos") {
            &["sudo", "/dev/bpf"]
        } else {
            &["privileges", "VPN"]
        };
        assert!(
            expected.iter().any(|needle| hint.contains(needle)),
            "expected one of {expected:?} in {hint:?}"
        );
    }
}
