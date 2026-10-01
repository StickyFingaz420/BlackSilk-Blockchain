//! The build guard of the `blacksilk-node` binary (W4-GUARD, RT-STATEFUL):
//! a binary with test-only code compiled in names it and runs only on
//! regtest.
//!
//! The binary these tests run is such a binary: `cargo test` builds it with
//! this crate's dev-dependency features unified (chain's `test-hooks`, which
//! enables tx's and px's), exactly as RT-STATEFUL found it written to
//! `target/release`. So the tests check the refusal on the real executable:
//! - `--version` and `-V` name the markers;
//! - `--network testnet` (on the command line or in a configuration file)
//!   exits with status 2 before touching the data directory;
//! - regtest starts and logs the markers with a warning.
//!
//! Mainnet cannot be selected at all (the configuration parser refuses it),
//! so its build refusal is covered by `blacksilk_chain::build_flags`'s and
//! `fingerprint`'s unit tests.

use blacksilk_node::fingerprint::build_flags;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const NODE: &str = env!("CARGO_BIN_EXE_blacksilk-node");

fn output(args: &[&str]) -> std::process::Output {
    Command::new(NODE)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// This test build is marked, so the tests below exercise the refusal.
#[test]
fn the_test_build_is_marked() {
    let flags = build_flags();
    assert!(
        flags.markers().contains(&"+test-hooks:chain"),
        "a node test build without chain's test-hooks: {flags:?}"
    );
}

#[test]
fn version_names_the_test_code() {
    let flags = build_flags();
    let long = output(&["--version"]);
    assert!(long.status.success());
    let text = String::from_utf8_lossy(&long.stdout);
    assert!(text.lines().any(|l| l == flags.line()), "{text}");
    for m in flags.markers() {
        assert!(text.contains(m), "{m} missing:\n{text}");
    }
    let short = output(&["-V"]);
    assert!(short.status.success());
    let text = String::from_utf8_lossy(&short.stdout);
    assert!(text.trim_end().ends_with(&flags.suffix()), "{text}");
    // The manifest's comment header names them too.
    let manifest = output(&["--print-manifest", "regtest"]);
    assert!(manifest.status.success());
    let text = String::from_utf8_lossy(&manifest.stdout);
    assert!(text.contains(&format!("# {}\n", flags.line())), "{text}");
}

fn assert_refused(out: &std::process::Output, data: &Path) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("refusing to run on testnet"), "{err}");
    for m in build_flags().markers() {
        assert!(err.contains(m), "{m} missing: {err}");
    }
    // Refused before the data directory is created or locked.
    assert!(!data.exists(), "{} was created", data.display());
}

#[test]
fn a_hooked_node_refuses_testnet() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let d = data.display().to_string();
    let out = output(&["--network", "testnet", "--no-p2p", "--data-dir", &d]);
    assert_refused(&out, &data);

    // The same from a configuration file, and as the default network.
    let conf = dir.path().join("node.toml");
    std::fs::write(&conf, "network = \"testnet\"\n").unwrap();
    let c = conf.display().to_string();
    let out = output(&["--config", &c, "--no-p2p", "--data-dir", &d]);
    assert_refused(&out, &data);
    let out = output(&["--no-p2p", "--data-dir", &d]);
    assert_refused(&out, &data);
}

#[test]
fn a_hooked_node_starts_on_regtest_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let log = dir.path().join("node.log");
    let f = std::fs::File::create(&log).unwrap();
    let mut child = Command::new(NODE)
        .args([
            "--network",
            "regtest",
            "--no-p2p",
            "--rpc-bind",
            "127.0.0.1:0",
        ])
        .arg("--data-dir")
        .arg(&data)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let start = Instant::now();
    let text = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("RPC listening on") {
            break text;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the node exited ({status}):\n{text}");
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the node did not start:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    let flags = build_flags();
    assert!(text.contains(&format!(", {}", flags.line())), "{text}");
    assert!(text.contains("test-only code compiled in"), "{text}");
}

/// `--require-clean-build` and its environment variable refuse the marked
/// node on regtest too, with status 2, before the data directory is created.
#[test]
fn a_clean_build_can_be_required_on_regtest() {
    let env = blacksilk_chain::build_flags::REQUIRE_CLEAN_ENV;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let d = data.display().to_string();
    let base = ["--network", "regtest", "--no-p2p", "--data-dir", &d];
    for by_env in [false, true] {
        let mut cmd = Command::new(NODE);
        cmd.args(base).env_remove(env).stdin(Stdio::null());
        if by_env {
            cmd.env(env, "1");
        } else {
            cmd.arg("--require-clean-build");
        }
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("clean build is required"), "{err}");
        for m in build_flags().markers() {
            assert!(err.contains(m), "{m} missing: {err}");
        }
        assert!(!data.exists(), "{} was created", data.display());
    }
}
