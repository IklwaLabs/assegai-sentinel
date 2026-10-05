//! Locates the system capture library for linking, transitively.
//!
//! `sentinel-api` does not link libpcap itself, but it depends on `sentinel-core`, which does.
//! Cargo runs build scripts per package, not per dependency graph, so the search path is emitted
//! here too. The logic is shared, not copied.

include!("../sentinel-platform/build_support.rs");

fn main() {
    configure_capture_lib();
}
