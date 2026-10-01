//! The miner binary's build flags (W4-GUARD): `--version` has a
//! `build flags:` line naming the test-only code compiled in, and
//! `--require-clean-build` (or its environment variable) refuses a marked
//! binary before it contacts a node. This test is built with the same
//! features as the binary it runs, so it knows which case applies.

use blacksilk_chain::build_flags::{BuildFlags, REQUIRE_CLEAN_ENV};
use std::process::{Command, Stdio};

const MINER: &str = env!("CARGO_BIN_EXE_blacksilk-miner");

#[test]
fn version_has_the_build_flags_line() {
    let flags = BuildFlags::of_chain_layer();
    let out = Command::new(MINER).arg("--version").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    assert!(first.starts_with("blacksilk-miner "), "{text}");
    assert!(first.contains("(commit "), "{text}");
    assert_eq!(lines.next(), Some(flags.line().as_str()), "{text}");
    let short = Command::new(MINER).arg("-V").output().unwrap();
    let text = String::from_utf8_lossy(&short.stdout);
    assert!(text.trim_end().ends_with(&flags.suffix()), "{text}");
}

#[test]
fn a_clean_build_can_be_required() {
    let flags = BuildFlags::of_chain_layer();
    // A node address nothing listens on: a clean binary gets past the build
    // check and fails on the connection, a marked one is refused first with
    // the configuration exit status.
    for (flag, env) in [(true, None), (false, Some("1"))] {
        let mut cmd = Command::new(MINER);
        cmd.args(["--node", "127.0.0.1:9", "--address", "x"])
            .env_remove(REQUIRE_CLEAN_ENV)
            .env_remove("BLACKSILK_RPC_COOKIE")
            .stdin(Stdio::null());
        if flag {
            cmd.arg("--require-clean-build");
        }
        if let Some(v) = env {
            cmd.env(REQUIRE_CLEAN_ENV, v);
        }
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        if flags.is_clean() {
            assert!(!err.contains("clean build is required"), "{err}");
        } else {
            assert_eq!(out.status.code(), Some(78), "{err}");
            assert!(err.contains("clean build is required"), "{err}");
        }
    }
}
