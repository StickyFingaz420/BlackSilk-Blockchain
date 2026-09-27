//! The build-commit reader used by `build.rs` (`build_id.rs`): its parsing of
//! `HEAD`, `.git` files and `packed-refs`, and its fallbacks. The module's own
//! tests run here, since tests inside a build script never do.

#[path = "../build_id.rs"]
mod build_id;

/// The commit baked into this build is either a commit id, an accepted
/// override, or `unknown`, never empty.
#[test]
fn baked_commit_is_well_formed() {
    let c = blacksilk_node::fingerprint::BUILD_COMMIT;
    assert!(
        c == build_id::UNKNOWN
            || build_id::is_commit_id(c)
            || build_id::sanitize_override(c).as_deref() == Some(c),
        "{c:?}"
    );
}
