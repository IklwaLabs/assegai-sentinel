//! Windows release binary entry point.
//!
//! The real work lives in the library so the same code serves the desktop app and any future
//! packaging harness. Keeping `main` this small means there is no logic here that a test or a
//! different launcher cannot reach.
//!
//! A start-up failure prints the user-facing message and exits non-zero rather than panicking:
//! a window that never appears needs an explanation somewhere the user will see it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(err) = sentinel_desktop_lib::run() {
        eprintln!("{}", err.to_plain_text());
        std::process::exit(1);
    }
}
