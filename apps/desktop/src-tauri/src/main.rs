//! Windows release binary entry point.
//!
//! The real work lives in the library so the same code serves the desktop app and any future
//! packaging harness. Keeping `main` this small means there is no logic here that a test or a
//! different launcher cannot reach.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sentinel_desktop_lib::run()
}
