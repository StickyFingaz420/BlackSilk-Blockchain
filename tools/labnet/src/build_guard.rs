//! The build guard of the labnet's own binaries (W4-GUARD), shared by
//! `blacksilk-labnet`, `blacksilk-labnet-report` and `blacksilk-rx-verify`
//! (each includes this file): their output is evidence, so a build with
//! test-only code (`cargo test` unifies dev-dependency features into the
//! binaries it writes) refuses to run at all, on any network.

use blacksilk_chain::build_flags::BuildFlags;

/// Exit status of a refused build.
pub const BUILD_EXIT_CODE: i32 = 2;

/// The `-V` and `--version` texts: the version, the commit when
/// `BLACKSILK_BUILD_COMMIT` was set at build time, and the build flags line.
pub fn version_texts() -> (&'static str, &'static str) {
    let commit = option_env!("BLACKSILK_BUILD_COMMIT").unwrap_or("unknown");
    let (short, long) =
        BuildFlags::of_chain_layer().version_texts(env!("CARGO_PKG_VERSION"), commit);
    (
        Box::leak(short.into_boxed_str()),
        Box::leak(long.into_boxed_str()),
    )
}

/// Exits with [`BUILD_EXIT_CODE`] when this binary has test-only code;
/// otherwise returns its `build flags: none` line, for the output.
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
