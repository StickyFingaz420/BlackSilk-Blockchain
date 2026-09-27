//! Sets `BLACKSILK_BUILD_COMMIT` for the node crate (library and binary): the
//! git commit the sources were built from, or `unknown`. Pure Rust, no `git`
//! process; see `build_id.rs` for the resolution order and why there is no
//! dirty flag.

#![forbid(unsafe_code)]

#[path = "build_id.rs"]
mod build_id;

use std::path::{Path, PathBuf};

const VAR: &str = "BLACKSILK_BUILD_COMMIT";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_id.rs");
    println!("cargo:rerun-if-env-changed={VAR}");

    let overridden = std::env::var(VAR)
        .ok()
        .and_then(|v| build_id::sanitize_override(&v));
    let commit = match overridden {
        Some(v) => v,
        None => from_git().unwrap_or_else(|| build_id::UNKNOWN.to_string()),
    };
    println!("cargo:rustc-env={VAR}={commit}");
}

fn from_git() -> Option<String> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    // The crate directory and the workspace root.
    let dot_git = build_id::find_dot_git(&manifest, 2, &|p: &Path| p.exists())?;
    let found = build_id::resolve(
        &dot_git,
        &|p: &Path| std::fs::read_to_string(p).ok(),
        &|p: &Path| p.is_dir(),
    );
    // Only existing paths: cargo treats a missing one as always changed.
    for p in found.watch.iter().filter(|p| p.exists()) {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    found.commit
}
