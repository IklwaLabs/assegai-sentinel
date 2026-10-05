// Shared build script logic for crates that link the system capture library.
//
// On Windows the `pcap` crate links `wpcap.lib`, which ships in the Npcap SDK rather than in
// the Npcap runtime. A machine with Npcap installed but without the SDK therefore fails to link
// with `LNK1181: cannot open input file 'wpcap.lib'`, which is a confusing message for a
// problem that has a simple fix.
//
// Resolution order, first match wins:
//   1. IKLWA_PCAP_LIB - an explicit path to a directory containing the library, or to the
//      library file itself. The escape hatch for unusual layouts and CI images.
//   2. The standard Npcap SDK locations under Program Files.
//
// Non-Windows targets need nothing: Linux finds libpcap.so from libpcap-dev, and macOS ships
// the BPF framework. Both use the normal linker search path.
//
// This file is included by the build script of every crate that links libpcap, so the lookup
// exists in exactly one place. Plain comments rather than doc comments, because the file is
// `include!`d rather than compiled as its own module.

use std::path::PathBuf;

/// Environment variable naming the capture import library or its directory.
const LIB_ENV: &str = "IKLWA_PCAP_LIB";

/// Import library file name on Windows.
const IMPORT_LIB: &str = "wpcap.lib";

/// Emits linker search paths for the capture library, or a warning explaining how to fix it.
fn configure_capture_lib() {
    println!("cargo:rerun-if-env-changed={LIB_ENV}");

    if !cfg!(target_os = "windows") {
        return;
    }

    match find_import_library() {
        Some(library) => {
            let directory = library.parent().unwrap_or(&library);
            println!("cargo:rerun-if-changed={}", library.display());
            println!("cargo:rustc-link-search=native={}", directory.display());
        }
        None => {
            // Not fatal: the library may still be reachable through LIB or a system path, and
            // failing here would break cross-compilation and documentation builds. The warning
            // turns a bare LNK1181 into an actionable message.
            println!(
                "cargo:warning=Sentinel: {IMPORT_LIB} not found. Install the Npcap SDK \
                 (https://npcap.com/dist/) or set {LIB_ENV} to the directory containing it."
            );
        }
    }
}

/// Locates `wpcap.lib`, or `None` when it is not present.
fn find_import_library() -> Option<PathBuf> {
    if let Some(configured) = non_empty_env(LIB_ENV) {
        let path = configured;
        if path.is_file() {
            return Some(path);
        }
        let candidate = path.join(IMPORT_LIB);
        if candidate.is_file() {
            return Some(candidate);
        }
        // An explicit override that does not resolve is a configuration error, and falling
        // through to the system search path would hide it behind a confusing linker failure.
        panic!(
            "{LIB_ENV} is set to {} but {IMPORT_LIB} was not found there",
            path.display()
        );
    }

    candidate_roots()
        .into_iter()
        .flat_map(|root| {
            let mut paths = vec![root.join("Npcap SDK"), root.join("Npcap"), root.join("npcap-sdk")];
            if cfg!(target_arch = "x86_64") {
                // Npcap's installer may place the import library under a versioned directory.
                paths.push(root.join("Npcap SDK").join("Lib"));
            }
            paths
        })
        .map(|directory| directory.join(IMPORT_LIB))
        .find(|candidate| candidate.is_file())
}

/// Program-files roots to search, honouring both the 32- and 64-bit variables.
fn candidate_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in ["ProgramFiles", "ProgramW6432"] {
        if let Some(root) = non_empty_env(key) {
            roots.push(root);
        }
    }
    roots
}

/// Reads a non-empty environment variable as a path.
fn non_empty_env(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}
