//! Locates the system capture library for linking.
//!
//! The lookup lives in `sentinel-platform/build_support.rs` and is included here rather than
//! copied, so both crates that link libpcap agree on where to find it.

include!("../sentinel-platform/build_support.rs");

fn main() {
    configure_capture_lib();
}
