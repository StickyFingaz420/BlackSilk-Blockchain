//! The wallet binary's commands for timed vault locks, refunds and recovery
//! (FX-RTW1C "Owed"), the header check flag (dossier 39 W5) and the seed
//! confirmation (F37-11), run against a regtest node over RPC. Nothing here
//! builds a PX proof: every vault command is refused before proving, or
//! finds nothing to do.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_node::{router, Shared};
use blacksilk_rpc::Client;
use blacksilk_tx::params::TxRules;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

/// A regtest node serving RPC on a local port, with `blocks` blocks mined.
struct Node {
    _rt: tokio::runtime::Runtime,
    addr: String,
}

fn node(blocks: u64) -> Node {
    let params = ChainParams::regtest();
    let rules = TxRules::at_height(&params, 0);
    let manager = ChainManager::open(
        params,
        rules,
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    let shared: Shared = Arc::new(Mutex::new(manager));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let app = router(shared);
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = Client::new(&addr);
    let to = blacksilk_wallet::Wallet::from_seed(blacksilk_consensus::Network::Regtest, [1; 32], 1)
        .primary();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for _ in 0..blocks {
        let t = client.template().unwrap();
        let time = ChainParams::regtest().genesis.timestamp + 120 * t.height;
        let b = blacksilk_miner::build_block(&t, &to, &[9; 32], time, &mut rng).unwrap();
        assert!(client.submit_block(&b.encode()).unwrap().accepted);
    }
    Node { _rt: rt, addr }
}

/// Runs the wallet binary on `wallet` with `args`, `stdin` as its input.
fn run(wallet: &Path, node: Option<&str>, args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blacksilk-wallet"));
    cmd.arg("--wallet").arg(wallet);
    if let Some(n) = node {
        cmd.args(["--node", n]);
    }
    let mut child = cmd
        .args(args)
        .env("BLACKSILK_WALLET_PASSWORD", "pw")
        .env_remove("BLACKSILK_RPC_COOKIE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A new regtest wallet file (birthday 0: it scans from block 1).
fn create(dir: &Path) -> (std::path::PathBuf, String) {
    let path = dir.join("w.wallet");
    let out = run(
        &path,
        None,
        &["create", "--network", "regtest", "--birthday-height", "0"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let words = text(&out.stdout)
        .lines()
        .find(|l| l.split(' ').count() == 27)
        .expect("the words are printed once at creation")
        .to_string();
    (path, words)
}

/// F37-11: `seed` shows the words only after the confirmation is typed.
#[test]
fn the_seed_is_shown_only_after_a_typed_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let (path, words) = create(dir.path());
    for refused in ["", "no\n", "yes\n", "SHOW\n"] {
        let out = run(&path, None, &["seed"], refused);
        assert!(!out.status.success(), "{refused:?}");
        assert!(!text(&out.stdout).contains(&words), "{refused:?}");
        assert!(text(&out.stderr).contains("not shown"), "{refused:?}");
    }
    let out = run(&path, None, &["seed"], "show\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), words);
    assert!(text(&out.stderr).contains("full control"));
}

/// The timed-lock, refund and recovery commands exist and refuse what they
/// must before any proving; the header check flag syncs a regtest chain.
#[test]
fn vault_timeout_refund_and_recovery_commands() {
    let node = node(20);
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = create(dir.path());
    let n = Some(node.addr.as_str());
    let contract = format!("01{}", "0".repeat(62));

    let out = run(&path, n, &["--verify-headers", "sync"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("synced to height 20"));

    // A timeout that is not a multiple of 16 is refused (before any proving).
    let out = run(
        &path,
        n,
        &[
            // The test chain's timestamps are from 2023 (RTW3-6).
            "--allow-stale-tip",
            "px-vault-lock",
            "--contract",
            &contract,
            "--amount",
            "1",
            "--timeout",
            "1001",
        ],
        "",
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("multiple of 16"),
        "{}",
        text(&out.stderr)
    );
    assert!(text(&out.stderr).contains("not a trustless swap or an HTLC"));

    // Claim terms that do not parse are refused before anything else.
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "02".to_string() + &"0".repeat(62)).unwrap();
    let out = run(
        &path,
        n,
        &[
            "px-vault-claim",
            "--record",
            &contract,
            "--secret-file",
            secret.to_str().unwrap(),
            "--terms",
            "not-terms",
        ],
        "",
    );
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("claim_lock:refund_lock:timeout"));

    // No stored terms: nothing to refund.
    let out = run(
        &path,
        n,
        &[
            "--allow-stale-tip",
            "px-vault-refund",
            "--record",
            &contract,
        ],
        "",
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("no stored terms"),
        "{}",
        text(&out.stderr)
    );

    // Recovery on a wallet that never locked anything.
    let out = run(&path, n, &["px-vault-recover"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("found 0 vault lock(s)"));

    // The options are documented.
    let help = text(&run(&path, n, &["px-vault-lock", "--help"], "").stdout);
    assert!(help.contains("--timeout"));
    let help = text(&run(&path, n, &["px-vault-claim", "--help"], "").stdout);
    assert!(help.contains("--terms"));
}

/// W4-GUARD: a wallet binary with test-only code compiled in (`cargo test`
/// unifies dev-dependency features into the binaries it writes, as in a
/// workspace test run) names it in `--version` and works only on regtest
/// wallets; a clean build is not refused for its build. This test's own
/// build has the same features as the binary it runs, so it knows which case
/// applies.
#[test]
fn a_wallet_with_test_code_works_only_on_regtest() {
    let flags = blacksilk_chain::build_flags::BuildFlags::of_chain_layer();
    let v = Command::new(env!("CARGO_BIN_EXE_blacksilk-wallet"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(v.status.success());
    let version = text(&v.stdout).replace("\r", "");
    let mut lines = version.lines();
    let first = lines.next().unwrap_or_default();
    assert!(first.starts_with("blacksilk-wallet "), "{version}");
    assert!(first.contains("(commit "), "{version}");
    assert_eq!(lines.next(), Some(flags.line().as_str()), "{version}");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.wallet");
    let out = run(
        &path,
        None,
        &["create", "--network", "testnet", "--birthday-height", "0"],
        "",
    );
    if flags.is_clean() {
        // Not the build refusal (the testnet itself may still be refused:
        // its genesis is not final yet).
        let err = text(&out.stderr);
        assert_ne!(out.status.code(), Some(2), "{err}");
        assert!(!err.contains("test-only code"), "{err}");
    } else {
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("refusing to run on testnet"), "{err}");
        assert!(err.contains(&flags.render()), "{err}");
        assert!(!path.exists(), "a refused wallet was written");
    }
}

/// W4-GUARD: `--require-clean-build` (or BLACKSILK_REQUIRE_CLEAN_BUILD)
/// refuses a wallet binary with test-only code on regtest too, before any
/// file is written; a clean binary is not refused.
#[test]
fn a_clean_wallet_build_can_be_required() {
    let flags = blacksilk_chain::build_flags::BuildFlags::of_chain_layer();
    let env = blacksilk_chain::build_flags::REQUIRE_CLEAN_ENV;
    let dir = tempfile::tempdir().unwrap();
    for (i, by_env) in [false, true].into_iter().enumerate() {
        let path = dir.path().join(format!("r{i}.wallet"));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_blacksilk-wallet"));
        cmd.arg("--wallet").arg(&path).env_remove(env);
        if by_env {
            cmd.env(env, "1");
        } else {
            cmd.arg("--require-clean-build");
        }
        let out = cmd
            .args(["create", "--network", "regtest", "--birthday-height", "0"])
            .env("BLACKSILK_WALLET_PASSWORD", "pw")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let err = text(&out.stderr);
        if flags.is_clean() {
            assert!(out.status.success(), "{err}");
        } else {
            assert_eq!(out.status.code(), Some(2), "{err}");
            assert!(err.contains("clean build is required"), "{err}");
            assert!(!path.exists(), "a refused wallet was written");
        }
    }
}

/// Runs the wallet binary like [`run`], with the password `pw` and the
/// extra environment `env`.
fn run_pw(wallet: &Path, args: &[&str], pw: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blacksilk-wallet"));
    cmd.arg("--wallet")
        .arg(wallet)
        .args(args)
        .env("BLACKSILK_WALLET_PASSWORD", pw)
        .env_remove("BLACKSILK_WALLET_NEW_PASSWORD")
        .env_remove("BLACKSILK_RPC_COOKIE")
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// TM2 cross-check gap 1: a new wallet's password may not be empty (create
/// and restore share the check, `file::check_new_password`); a short one is
/// accepted with a warning. Before, any password was accepted, the empty one
/// included, so a wallet file in a synced folder was readable by anyone who
/// got the file.
#[test]
fn an_empty_wallet_password_is_refused_and_a_short_one_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let create = ["create", "--network", "regtest", "--birthday-height", "0"];
    let path = dir.path().join("empty.wallet");
    let out = run_pw(&path, &create, "", &[]);
    assert!(!out.status.success(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("empty password"),
        "{}",
        text(&out.stderr)
    );
    assert!(!path.exists(), "no wallet file written");

    let path = dir.path().join("short.wallet");
    let out = run_pw(&path, &create, "pw", &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("weak password"),
        "{}",
        text(&out.stderr)
    );

    let path = dir.path().join("long.wallet");
    let out = run_pw(&path, &create, "correct horse battery", &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!text(&out.stderr).contains("weak password"));
}

/// A wallet saved with an empty password before the check still opens,
/// with a warning that names the way out, and `change-password` sets a new
/// password without losing anything; it refuses an empty new one.
#[test]
fn a_wallet_with_an_empty_password_opens_and_can_get_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.wallet");
    let mut w =
        blacksilk_wallet::Wallet::from_seed(blacksilk_consensus::Network::Regtest, [5; 32], 1);
    let primary = w.address(0, 0);
    blacksilk_wallet::save(&w, &path, b"", blacksilk_wallet::file::KdfParams::default()).unwrap();

    let out = run_pw(&path, &["address"], "", &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), primary);
    let err = text(&out.stderr);
    assert!(
        err.contains("empty password") && err.contains("change-password"),
        "{err}"
    );

    let out = run_pw(
        &path,
        &["change-password"],
        "",
        &[("BLACKSILK_WALLET_NEW_PASSWORD", "")],
    );
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("empty password"));

    let new = "a much better password";
    let out = run_pw(
        &path,
        &["change-password"],
        "",
        &[("BLACKSILK_WALLET_NEW_PASSWORD", new)],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = run_pw(&path, &["address"], "", &[]);
    assert!(
        !out.status.success(),
        "the empty password no longer opens it"
    );
    let out = run_pw(&path, &["address"], new, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), primary);
    assert!(!text(&out.stderr).contains("empty password"));
}
