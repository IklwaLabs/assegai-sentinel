//! Desktop shell build configuration.
//!
//! Deliberately minimal. Tauri generates its context from `tauri.conf.json`; there is no
//! codegen, no asset pipeline and nothing to configure here beyond what Tauri itself requires.

fn main() {
    tauri_build::build()
}
