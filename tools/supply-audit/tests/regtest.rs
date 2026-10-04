//! The supply audit on an in-process regtest chain (node router over real
//! RPC, the miner library, wallets doing v1 transfers). No PX proving: the PX
//! side is exercised only as zero (empty pool, no records).

use blacksilk_chain::emission::{block_reward, COIN};
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, Network, PowFunction};
use blacksilk_crypto::keys::Address;
use blacksilk_node::router;
use blacksilk_rpc::Client;
use blacksilk_supply_audit::{audit, Entry, Report};
use blacksilk_tx::params::TxRules;
use blacksilk_wallet::file::KdfParams;
use blacksilk_wallet::Wallet;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

/// Every hash meets every difficulty (RandomX is tested in its own crates).
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

struct Net {
    _rt: tokio::runtime::Runtime,
    addr: String,
    client: Client,
    rng: ChaCha20Rng,
    rules: TxRules,
}

impl Net {
    fn start() -> Self {
        let params = ChainParams::regtest();
        let rules = TxRules::for_chain(&params);
        let manager = ChainManager::open(
            params,
            rules,
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [3; 32],
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(manager));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let app = router(shared);
        rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _rt: rt,
            client: Client::new(&addr),
            addr,
            rng: ChaCha20Rng::seed_from_u64(7),
            rules,
        }
    }

    fn mine_n(&mut self, n: u64, to: &Address) {
        for _ in 0..n {
            let t = self.client.template().unwrap();
            let time = ChainParams::regtest().genesis.timestamp + 120 * t.height;
            let b = blacksilk_miner::build_block(&t, to, &[9; 32], time, &mut self.rng).unwrap();
            let r = self.client.submit_block(&b.encode()).unwrap();
            assert!(r.accepted, "{:?}", r.error);
        }
    }
}

fn wallet(seed: u8) -> Wallet {
    let mut w = Wallet::from_seed(Network::Regtest, [seed; 32], 1);
    // The regtest chain here carries fixed 2023 timestamps, so its tip is
    // "stale" by this computer's clock; the scenario still builds its
    // transfers (RTW3-6's refusal is for real networks).
    w.set_allow_stale_tip(true);
    w
}

fn generated_at(height: u64) -> u64 {
    let mut g = 0;
    for h in 1..=height {
        g += block_reward(h, g);
    }
    g
}

/// A chain of 102 blocks with a miner and two wallets: miner → Alice twice
/// (blocks 91 and 92), Alice → Bob (block 102, confirmed), and one more
/// Alice → Bob left unconfirmed in the mempool.
fn scenario() -> (Net, Wallet, Wallet, Wallet) {
    let mut net = Net::start();
    let mut miner = wallet(1);
    let mut alice = wallet(2);
    let bob = wallet(3);
    let m = miner.primary();
    net.mine_n(90, &m);
    miner
        .transfer(
            &net.client,
            &alice.primary(),
            5 * COIN,
            &net.rules,
            &mut net.rng,
        )
        .unwrap();
    net.mine_n(1, &m);
    miner
        .transfer(
            &net.client,
            &alice.primary(),
            3 * COIN,
            &net.rules,
            &mut net.rng,
        )
        .unwrap();
    net.mine_n(10, &m);
    alice
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    net.mine_n(1, &m);
    // Unconfirmed: Alice's inputs are reserved, the change does not exist yet.
    alice
        .transfer(
            &net.client,
            &bob.primary(),
            COIN / 2,
            &net.rules,
            &mut net.rng,
        )
        .unwrap();
    assert_eq!(net.client.info().unwrap().mempool_txs, 1);
    (net, miner, alice, bob)
}

fn entries(ws: Vec<(&str, Wallet)>) -> Vec<Entry> {
    ws.into_iter()
        .map(|(n, w)| Entry {
            name: n.into(),
            wallet: w,
        })
        .collect()
}

fn check_zero(r: &Report, height: u64) {
    assert_eq!(r.height, height);
    assert!(r.chain_failures.is_empty(), "{:?}", r.chain_failures);
    assert_eq!(r.chain.generated, generated_at(height));
    assert_eq!(r.chain.px_pool, 0);
    assert_eq!(r.totals.v1, r.chain.generated as u128);
    assert_eq!(r.totals.px, 0);
    assert_eq!(r.v1_difference, 0, "{}", r.text());
    assert_eq!(r.px_difference, 0);
    assert_eq!(r.total_difference, 0);
    assert!(r.complete() && !r.alarm());
    assert_eq!(r.exit_code(true), 0);
}

#[test]
fn complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount() {
    let (net, miner, alice, bob) = scenario();
    let height = net.client.info().unwrap().height;
    assert_eq!(height, 102);

    let mut all = entries(vec![("miner", miner), ("alice", alice), ("bob", bob)]);
    let r = audit(&net.client, &mut all, None).unwrap();
    check_zero(&r, height);
    assert_eq!(r.node_generated, r.chain.generated);
    assert_eq!(r.chain.transfers, 3);
    assert!(r.chain.fees > 0);
    assert_eq!(
        r.chain.coinbase_paid,
        r.chain.generated as u128 + r.chain.fees
    );
    let (m, a, b) = (&r.wallets[0], &r.wallets[1], &r.wallets[2]);
    // Fees are not burned: they come back in the miner's coinbase.
    assert_eq!(
        m.v1_unspent + a.v1_unspent + b.v1_unspent,
        r.chain.generated as u128
    );
    assert!(
        m.v1_immature_coinbase > 0,
        "the last 59 coinbases are immature"
    );
    // Bob holds exactly the confirmed payment; the unconfirmed one is not his yet.
    assert_eq!(b.v1_unspent, COIN as u128);
    // Alice's inputs to the unconfirmed transfer are reserved but still hers
    // on chain; her wallet's own balance leaves them out.
    assert!(a.v1_reserved > 0);
    assert_eq!(a.pending_txs, 2);
    assert_eq!(a.wallet_balance as u128, a.v1_unspent - a.v1_reserved);
    let bob_amount = b.v1_unspent;
    let miner_amount = m.v1_unspent;

    // The JSON form carries the same numbers.
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["v1_difference"], 0);
    assert_eq!(j["totals"]["v1"].as_u64().unwrap(), r.chain.generated);

    // Bob omitted: the difference is exactly what Bob holds.
    let mut ws: Vec<Entry> = all.into_iter().collect();
    let bob_entry = ws.pop().unwrap();
    let r = audit(&net.client, &mut ws, None).unwrap();
    assert_eq!(r.v1_difference, bob_amount as i128);
    assert_eq!(r.total_difference, bob_amount as i128);
    assert_eq!(r.px_difference, 0);
    assert!(!r.complete() && !r.alarm());
    assert_eq!(r.exit_code(true), 3);
    assert_eq!(r.exit_code(false), 0);
    assert!(r.text().contains("INCOMPLETE"));

    // The miner omitted instead.
    let miner_entry = ws.remove(0);
    ws.push(bob_entry);
    let r = audit(&net.client, &mut ws, None).unwrap();
    assert_eq!(r.v1_difference, miner_amount as i128);

    // The same wallet twice is counted once, and reported.
    let alice_again = Entry {
        name: "alice (copy)".into(),
        wallet: wallet(2),
    };
    ws.push(miner_entry);
    ws.push(alice_again);
    let r = audit(&net.client, &mut ws, None).unwrap();
    check_zero(&r, height);
    assert!(r.totals.v1_duplicates > 0);
    assert_eq!(r.totals.px_duplicates, 0);
}

#[test]
fn audit_at_an_earlier_height_rewinds_the_wallets_to_it() {
    let (net, miner, alice, bob) = scenario();
    let mut all = entries(vec![("miner", miner), ("alice", alice), ("bob", bob)]);
    // Wallets synced at the tip, then audited below it: before Alice → Bob.
    audit(&net.client, &mut all, None).unwrap();
    let r = audit(&net.client, &mut all, Some(95)).unwrap();
    check_zero(&r, 95);
    assert_eq!(r.chain.transfers, 2);
    assert_eq!(r.wallets[2].v1_unspent, 0, "Bob has nothing yet at 95");
    assert_eq!(r.wallets[1].v1_unspent, 8 * COIN as u128);
    // And the genesis: nothing exists.
    let r = audit(&net.client, &mut all, Some(0)).unwrap();
    check_zero(&r, 0);
    // Above the node: refused.
    assert!(audit(&net.client, &mut all, Some(1_000)).is_err());
}

#[test]
fn a_wallet_that_cannot_reach_the_audit_block_is_refused() {
    let (net, miner, _alice, _bob) = scenario();
    // Scanning starts above the audit height: it never reaches the audit block.
    let late = Wallet::from_seed(Network::Regtest, [4; 32], 500);
    let mut ws = entries(vec![("miner", miner), ("late", late)]);
    let e = audit(&net.client, &mut ws, None).unwrap_err();
    assert!(e.contains("late") && e.contains("refusing"), "{e}");
    // A wallet of another network is refused too.
    let mut ws = entries(vec![(
        "testnet",
        Wallet::from_seed(Network::Testnet, [5; 32], 1),
    )]);
    assert!(audit(&net.client, &mut ws, None).is_err());
}

#[test]
fn the_binary_is_read_only_and_reports_json_and_exit_codes() {
    let (net, miner, alice, bob) = scenario();
    let dir = tempfile::tempdir().unwrap();
    let fast = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };
    let mut paths = Vec::new();
    for (name, w) in [("miner", &miner), ("alice", &alice), ("bob", &bob)] {
        let p = dir.path().join(format!("{name}.wallet"));
        blacksilk_wallet::save(w, &p, name.as_bytes(), fast).unwrap();
        let pw = dir.path().join(format!("{name}.pw"));
        std::fs::write(&pw, format!("{name}\r\n")).unwrap();
        paths.push((p, pw));
    }
    let run = |set: &[&(std::path::PathBuf, std::path::PathBuf)], extra: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_blacksilk-supply-audit"));
        cmd.args(["--node", &net.addr]);
        for (p, pw) in set {
            cmd.arg("--wallet").arg(p).arg("--password-file").arg(pw);
        }
        cmd.args(extra);
        cmd.output().unwrap()
    };
    let before: Vec<Vec<u8>> = paths
        .iter()
        .map(|(p, _)| std::fs::read(p).unwrap())
        .collect();
    let all: Vec<_> = paths.iter().collect();

    let out = run(&all, &["--json", "--expect-complete"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["total_difference"], 0);
    assert_eq!(j["wallets"].as_array().unwrap().len(), 3);
    // The build flags of the auditing build (W4-GUARD); this test is built
    // with the same features as the binary.
    let flags = blacksilk_chain::build_flags::BuildFlags::of_chain_layer();
    assert_eq!(j["build_flags"], flags.line());
    // `--require-clean-build`: a marked binary does not run (1), a clean
    // one audits as before.
    let required = run(&all, &["--json", "--require-clean-build"]);
    assert_eq!(
        required.status.code(),
        Some(if flags.is_clean() { 0 } else { 1 }),
        "{}",
        String::from_utf8_lossy(&required.stderr)
    );
    // Not saved: the files are byte-for-byte unchanged.
    for ((p, _), b) in paths.iter().zip(&before) {
        assert_eq!(&std::fs::read(p).unwrap(), b);
    }
    // No rebroadcast: the unconfirmed transfer is still the only one pooled.
    assert_eq!(net.client.info().unwrap().mempool_txs, 1);

    // Bob missing: exit 3 with --expect-complete, 0 without; text output.
    let out = run(&all[..2], &["--expect-complete"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stdout).contains("INCOMPLETE"));
    assert_eq!(run(&all[..2], &[]).status.code(), Some(0));

    // A wrong password: the audit does not run.
    let bad = dir.path().join("bad.pw");
    std::fs::write(&bad, "nope").unwrap();
    let wrong = (paths[0].0.clone(), bad);
    assert_eq!(run(&[&wrong], &[]).status.code(), Some(1));

    // --save writes the synced wallet back, readable with the same password.
    let out = run(&all[..1], &["--save"]);
    assert_eq!(out.status.code(), Some(0));
    assert_ne!(std::fs::read(&paths[0].0).unwrap(), before[0]);
    let w = blacksilk_wallet::load(&paths[0].0, b"miner").unwrap();
    assert_eq!(w.synced_height(), 102);
}
