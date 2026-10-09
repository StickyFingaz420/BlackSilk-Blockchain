//! The build guard of the bridge's binaries (W4-GUARD), as
//! `tools/labnet/src/build_guard.rs`: their output is evidence, so a build
//! with test-only code (`cargo test` unifies dev-dependency features into the
//! binaries it writes) refuses to run at all, on any network; and
//! `--version` prints the `build flags:` line that `tools/check-build-flags.sh`
//! and `.github/scripts/build-guard.sh` require.

use blacksilk_chain::build_flags::BuildFlags;

/// Exit status of a refused build.
pub const BUILD_EXIT_CODE: i32 = 2;

/// The commit, when `BLACKSILK_BUILD_COMMIT` was set at build time.
pub const BUILD_COMMIT: &str = match option_env!("BLACKSILK_BUILD_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

/// The `-V` and `--version` texts: `<version> (commit <commit>)` and the
/// build flags line.
pub fn version_texts() -> (&'static str, &'static str) {
    let (short, long) =
        BuildFlags::of_chain_layer().version_texts(env!("CARGO_PKG_VERSION"), BUILD_COMMIT);
    (
        Box::leak(short.into_boxed_str()),
        Box::leak(long.into_boxed_str()),
    )
}

/// Exits with [`BUILD_EXIT_CODE`] when this binary has test-only code;
/// otherwise returns its `build flags: none` line, for the log.
pub fn require_clean_build(binary: &str) -> String {
    let flags = BuildFlags::of_chain_layer();
    if let Err(e) = flags.check_clean(binary) {
        eprintln!("error: {e}");
        std::process::exit(BUILD_EXIT_CODE);
    }
    flags.line()
}

/// Parses the command line with [`version_texts`] as `-V` and `--version`.
pub fn parse_args<T: clap::Parser>() -> T {
    let (short, long) = version_texts();
    let matches = T::command().version(short).long_version(long).get_matches();
    T::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}
