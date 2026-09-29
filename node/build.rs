//! Sets `BLACKSILK_BUILD_COMMIT` for the node crate (library and binary): the
//! git commit the sources were built from, `<commit>-dirty` when tracked
//! build inputs differ from it, or `unknown`. Pure Rust, no `git` process;
//! see `build_id.rs` for the resolution order and the dirty check.
//!
//! A release build (`PROFILE=release`) of a dirty tree is refused unless
//! `BLACKSILK_ALLOW_DIRTY=1` (RTFP3-9): a trial binary must be built from the
//! announced commit, unchanged. Development builds of uncommitted work set
//! the variable; their commit still shows `-dirty`.

#![forbid(unsafe_code)]

#[path = "build_id.rs"]
mod build_id;

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const VAR: &str = "BLACKSILK_BUILD_COMMIT";
const ALLOW_DIRTY: &str = "BLACKSILK_ALLOW_DIRTY";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_id.rs");
    println!("cargo:rerun-if-env-changed={VAR}");
    println!("cargo:rerun-if-env-changed={ALLOW_DIRTY}");

    let overridden = std::env::var(VAR)
        .ok()
        .and_then(|v| build_id::sanitize_override(&v));
    let (mut commit, dirty) = match overridden {
        Some(v) => {
            let dirty = v.ends_with(build_id::DIRTY_SUFFIX);
            (v, dirty)
        }
        None => match from_git() {
            Some((commit, dirty)) => (commit, dirty),
            None => (build_id::UNKNOWN.to_string(), false),
        },
    };
    if dirty && !commit.ends_with(build_id::DIRTY_SUFFIX) {
        commit.push_str(build_id::DIRTY_SUFFIX);
    }
    if dirty {
        let allowed = std::env::var(ALLOW_DIRTY).is_ok_and(|v| v == "1");
        let release = std::env::var("PROFILE").is_ok_and(|p| p == "release");
        if release && !allowed {
            panic!(
                "refusing a release build of a dirty tree ({commit}): tracked build inputs \
                 differ from the commit. Build trial binaries from a clean checkout of the \
                 announced commit; for development builds of uncommitted work set \
                 {ALLOW_DIRTY}=1 (the commit then shows `-dirty`)."
            );
        }
        println!("cargo:warning=blacksilk-node: building a dirty tree, commit {commit}");
    }
    println!("cargo:rustc-env={VAR}={commit}");
}

/// The commit from `.git` and whether the tracked build inputs differ from
/// it. Prints the files whose change must rerun this script.
fn from_git() -> Option<(String, bool)> {
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
    let commit = found.commit?;
    let dirty = match (&found.git_dir, dot_git.parent()) {
        (Some(git_dir), Some(root)) => is_dirty(git_dir, found.common_dir.as_deref(), root),
        _ => false,
    };
    Some((commit, dirty))
}

/// Compares the tracked build inputs under `root` with the index, and asks
/// cargo to rerun this script when the index or any of them changes.
fn is_dirty(git_dir: &Path, common_dir: Option<&Path>, root: &Path) -> bool {
    let index_path = git_dir.join("index");
    let Ok(index) = std::fs::read(&index_path) else {
        // No index (a fresh repository): nothing is tracked yet.
        return false;
    };
    println!("cargo:rerun-if-changed={}", index_path.display());
    let config = common_dir.and_then(|c| std::fs::read_to_string(c.join("config")).ok());
    let oid_len = build_id::oid_len(config.as_deref());
    let Some(entries) = build_id::parse_index(&index, oid_len) else {
        println!("cargo:warning=blacksilk-node: unreadable git index; the tree counts as dirty");
        return true;
    };
    for e in entries
        .iter()
        .filter(|e| build_id::is_build_input(&e.path) && root.join(&e.path).exists())
    {
        println!("cargo:rerun-if-changed={}", root.join(&e.path).display());
    }
    let stat = |p: &Path| {
        let m = std::fs::metadata(p).ok()?;
        let t = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
        Some(build_id::Stat {
            size: m.len(),
            mtime_s: t.as_secs() as u32,
            mtime_ns: t.subsec_nanos(),
        })
    };
    let dirty = build_id::dirty_paths(
        root,
        &entries,
        &stat,
        &|p: &Path| std::fs::read(p).ok(),
        oid_len == 20,
    );
    for p in dirty.iter().take(10) {
        println!("cargo:warning=blacksilk-node: differs from the commit: {p}");
    }
    !dirty.is_empty()
}
