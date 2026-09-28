//! The `/template` gate over the real router (docs/blocks.md §9.4).
//!
//! - **Catch-up latch** (RTW3-1, replacing the W2-09b gate): a node refuses
//!   templates (`503`) until it has first caught up (tip recent against the
//!   clock, bodies at most 2 blocks below the best header); from then on no
//!   header lead closes the gate. The W2-09b gate recomputed the header gap
//!   on every request, so three bodiless headers on a synced node's tip
//!   stopped it from mining; `a_synced_node_keeps_serving_templates_behind_bodiless_headers`
//!   fails on the base commit cbd50c6.
//! - **Operator fork** (RTW3-8): while a heavier chain is refused only
//!   because of an operator verdict, `/template` refuses unless the node
//!   runs with `--mine-despite-operator-fork` ([`MiningPolicy`]).
//!
//! `/info` reports `template_ready`, `template_latched` and the operator
//! fork.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_node::{router_with, App, MiningPolicy, Shared};
use blacksilk_rpc::{Client, RpcError};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn open(p: &ChainParams) -> Shared {
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    Arc::new(Mutex::new(m))
}

/// The router over `shared` with `mining`, served on a loopback port.
fn serve(shared: Shared, mining: MiningPolicy) -> (tokio::runtime::Runtime, SocketAddr) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = l.local_addr().unwrap();
    let mut app = App::shared(shared, None);
    app.mining = mining;
    let app = router_with(app);
    rt.spawn(async move { axum::serve(l, app).await });
    (rt, addr)
}

/// `/info`'s raw JSON (the fields beyond `rpc::Info`).
fn info_json(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET /info HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.split("\r\n\r\n").nth(1).unwrap().to_string()
}

/// `n` linked headers on `parent`, `dt` seconds apart, valid under
/// `ZeroPow` (their bodies are never sent).
fn headers_on(m: &ChainManager, n: usize, dt: u64) -> Vec<BlockHeader> {
    let mut g = HeaderChain::new(m.params().clone(), Arc::new(ZeroPow));
    for h in 1..=m.height() {
        g.accept(m.block_at(h).unwrap().header, u64::MAX / 2)
            .unwrap();
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + dt),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: 9,
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// A coinbase-only block on `m`'s tip stamped `time` (at least the
/// template's minimum), submitted at the clock reading `now`.
fn mine_at(m: &mut ChainManager, rng: &mut ChaCha20Rng, time: u64, now: u64) -> Block {
    let (keys, _) = WalletKeys::generate(rng);
    let t = m.template();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: keys.address(SubaddressIndex::PRIMARY),
            amount: t.reward,
        }],
        &keys.hedge_secret(),
        rng,
    )
    .unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(time),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
    };
    let b = Block { header, txs };
    m.submit_block(b.clone(), now).unwrap();
    b
}

/// RTW3-1 over HTTP, on regtest (no clock rule): a node serving templates
/// latches, and bodiless header leads of 3 and 12 blocks leave `/template`
/// open.
#[test]
fn a_synced_node_keeps_serving_templates_behind_bodiless_headers() {
    let p = ChainParams::regtest();
    let shared = open(&p);
    let (_rt, addr) = serve(shared.clone(), MiningPolicy::default());
    let c = Client::new(&addr.to_string());
    // A lone node at genesis (no peers): templates are served.
    assert_eq!(c.template().expect("a lone node mines").height, 1);
    assert!(info_json(addr).contains("\"template_latched\":true"));

    let headers = headers_on(&shared.lock().unwrap(), 12, 10);
    shared
        .lock()
        .unwrap()
        .accept_headers(&headers[..3], u64::MAX / 2)
        .unwrap();
    assert_eq!(c.template().expect("a 3-header lead").height, 1);
    shared
        .lock()
        .unwrap()
        .accept_headers(&headers[3..], u64::MAX / 2)
        .unwrap();
    assert_eq!(c.info().unwrap().header_height, 12);
    assert_eq!(c.template().expect("a 12-header lead").height, 1);
    assert_eq!(c.info().unwrap().template_ready, Some(true));
    assert!(c.tip(None, 0).unwrap().template_ready);
}

/// RTW3-1 on testnet parameters (tip-age bound 48 minutes): a node whose
/// tip is its old genesis refuses templates until a recent block arrives,
/// latches at its next request, and then keeps serving behind a bodiless
/// header lead.
#[test]
fn a_node_refuses_templates_until_caught_up_then_latches() {
    let p = ChainParams::testnet();
    let shared = open(&p);
    let (_rt, addr) = serve(shared.clone(), MiningPolicy::default());
    let c = Client::new(&addr.to_string());
    let now = wall_clock();
    assert!(p.genesis.timestamp + 24 * 120 < now, "the genesis is old");
    match c.template() {
        Err(RpcError::Status(503, body)) => {
            assert!(
                body.starts_with("syncing: height 0, headers 0, tip "),
                "{body}"
            );
            assert!(body.contains("--mine-from-stale-tip"), "{body}");
        }
        other => panic!("expected 503 on an old tip, got {other:?}"),
    }
    assert_eq!(c.info().unwrap().template_ready, Some(false));
    assert!(info_json(addr).contains("\"template_latched\":false"));
    assert!(!c.tip(None, 0).unwrap().template_ready);

    // A block of the network, stamped now, arrives: caught up.
    let mut rng = ChaCha20Rng::seed_from_u64(0x1a7c);
    mine_at(&mut shared.lock().unwrap(), &mut rng, now, now);
    assert_eq!(c.info().unwrap().template_ready, Some(true));
    assert_eq!(c.template().expect("caught up").height, 2);
    assert!(info_json(addr).contains("\"template_latched\":true"));

    // Three bodiless headers on the tip: templates are still served.
    let headers = headers_on(&shared.lock().unwrap(), 3, 1);
    shared
        .lock()
        .unwrap()
        .accept_headers(&headers, now)
        .unwrap();
    assert_eq!(c.info().unwrap().header_height, 4);
    assert_eq!(c.template().expect("latched").height, 2);
    assert_eq!(c.info().unwrap().template_ready, Some(true));
}

/// RTW3-1: a node catching up (headers far ahead of its bodies, a recent
/// tip) refuses templates.
#[test]
fn a_node_with_bodies_far_behind_its_headers_refuses_templates() {
    let p = ChainParams::testnet();
    let shared = open(&p);
    let (_rt, addr) = serve(shared.clone(), MiningPolicy::default());
    let c = Client::new(&addr.to_string());
    let now = wall_clock();
    let mut rng = ChaCha20Rng::seed_from_u64(0xca7c);
    // The network's chain: 8 blocks, the last one 100 s old.
    let src = open(&p);
    let blocks: Vec<Block> = {
        let mut m = src.lock().unwrap();
        (0..8u64)
            .map(|i| mine_at(&mut m, &mut rng, now - 800 + 100 * i, now))
            .collect()
    };
    {
        let mut m = shared.lock().unwrap();
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        m.accept_headers(&headers, now).unwrap();
        for b in &blocks[..3] {
            m.submit_block(b.clone(), now).unwrap();
        }
        assert_eq!((m.height(), m.header_height()), (3, 8));
        assert!(!m.template_latched(), "never caught up");
    }
    match c.template() {
        Err(RpcError::Status(503, body)) => {
            assert!(body.starts_with("syncing: height 3, headers 8"), "{body}")
        }
        other => panic!("expected 503 with a header gap of 5, got {other:?}"),
    }
    assert_eq!(c.info().unwrap().template_ready, Some(false));
}

/// RTW3-8: the operator invalidates a block the heavier chain contains:
/// `/template` refuses with the reason, `/info` reports the fork, and
/// `--mine-despite-operator-fork` serves templates anyway.
#[test]
fn an_operator_fork_refuses_templates_unless_overridden() {
    let p = ChainParams::regtest();
    let shared = open(&p);
    let mut rng = ChaCha20Rng::seed_from_u64(0x0f0f);
    let bad = {
        let mut m = shared.lock().unwrap();
        let blocks: Vec<Block> = (1..=6)
            .map(|h| mine_at(&mut m, &mut rng, p.genesis.timestamp + 10 * h, u64::MAX / 2))
            .collect();
        let bad = blocks[3].id(p.network_id);
        m.invalidate_block(bad).unwrap();
        assert_eq!(m.height(), 3);
        bad
    };
    let (_rt, addr) = serve(shared.clone(), MiningPolicy::default());
    let c = Client::new(&addr.to_string());
    match c.template() {
        Err(RpcError::Status(503, body)) => {
            assert!(body.starts_with("operator fork"), "{body}");
            assert!(body.contains(&hex::encode(bad)), "{body}");
            assert!(body.contains("second channel"), "{body}");
            assert!(body.contains("--mine-despite-operator-fork"), "{body}");
        }
        other => panic!("expected 503 during an operator fork, got {other:?}"),
    }
    assert_eq!(c.info().unwrap().template_ready, Some(false));
    assert!(!c.tip(None, 0).unwrap().template_ready);
    let info = info_json(addr);
    assert!(info.contains("\"operator_fork\":{"), "{info}");
    assert!(
        info.contains(&format!("\"block\":\"{}\"", hex::encode(bad))),
        "{info}"
    );
    assert!(info.contains("\"branch_height\":6"), "{info}");
    assert!(info.contains("\"templates_refused\":true"), "{info}");

    // The override.
    let despite = MiningPolicy {
        despite_operator_fork: true,
    };
    let (_rt2, addr2) = serve(shared, despite);
    let c2 = Client::new(&addr2.to_string());
    assert_eq!(c2.template().expect("overridden").height, 4);
    assert_eq!(c2.info().unwrap().template_ready, Some(true));
    assert!(info_json(addr2).contains("\"templates_refused\":false"));
}
