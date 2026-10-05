//! Locates the system capture library for linking.
//!
//! See `build_support.rs` for the logic and the reasoning. This script exists only so
//! `build_support.rs` can be compiled once per crate instead of duplicated.

include!("build_support.rs");

fn main() {
    configure_capture_lib();
}
