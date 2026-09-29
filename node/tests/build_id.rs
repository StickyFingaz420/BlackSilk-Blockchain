//! The build-commit reader used by `build.rs` (`build_id.rs`): its parsing of
//! `HEAD`, `.git` files and `packed-refs`, and its fallbacks. The module's own
//! tests run here, since tests inside a build script never do.

#[path = "../build_id.rs"]
mod build_id;

/// The commit baked into this build is either a commit id (with the dirty
/// mark when tracked build inputs differed from it), an accepted override,
/// or `unknown`, never empty.
#[test]
fn baked_commit_is_well_formed() {
    let c = blacksilk_node::fingerprint::BUILD_COMMIT;
    let id = c.strip_suffix(build_id::DIRTY_SUFFIX).unwrap_or(c);
    assert!(
        c == build_id::UNKNOWN
            || build_id::is_commit_id(id)
            || build_id::sanitize_override(c).as_deref() == Some(c),
        "{c:?}"
    );
}

/// The reader parses this repository's own index, when the sources are a
/// git checkout (skipped otherwise: a source archive or a Docker context).
#[test]
fn this_repository_index_parses() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(dot_git) = build_id::find_dot_git(manifest, 2, &|p| p.exists()) else {
        return;
    };
    let found = build_id::resolve(&dot_git, &|p| std::fs::read_to_string(p).ok(), &|p| {
        p.is_dir()
    });
    let Some(index) = found
        .git_dir
        .and_then(|g| std::fs::read(g.join("index")).ok())
    else {
        return;
    };
    let config = found
        .common_dir
        .and_then(|c| std::fs::read_to_string(c.join("config")).ok());
    let entries = build_id::parse_index(&index, build_id::oid_len(config.as_deref()))
        .expect("the repository's index parses");
    assert!(entries.iter().any(|e| e.path == "node/build.rs"));
    assert!(entries.iter().any(|e| e.path == "Cargo.lock"));
}
