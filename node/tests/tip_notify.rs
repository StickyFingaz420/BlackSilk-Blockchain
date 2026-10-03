//! Tip notification (dossier 09 I1) and the next RandomX key on `/template`
//! (09 I3), over the real router.
//!
//! - `GET /tip` answers from the published chain snapshot, never a chain
//!   command: it stays prompt while the chain is busy.
//! - `GET /tip?after=<id>&wait=<s>` is held until the tip differs from
//!   `after` (a miner learns of a new block at once), or for `wait` seconds.
//! - `/template` carries `next_seed_id` exactly in the `seed_lag` heights
//!   before a key switch.
//! - `/info` and `/tip` report `template_ready`.

mod common;

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_node::{router, Shared, TIP_POLL_INTERVAL};
use blacksilk_rpc::{Client, MAX_TIP_WAIT_SECS};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use common::HeldChain;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// Regtest with the short key epoch of the chain tests (16, lag 4: the
/// first switch at height 21, key = block 16).
fn params() -> ChainParams {
    let mut p = ChainParams::regtest();
    p.seed_epoch = 16;
    p.seed_lag = 4;
    p
}

struct Node {
    _rt: tokio::runtime::Runtime,
    addr: SocketAddr,
    shared: Shared,
    rng: ChaCha20Rng,
}

impl Node {
    fn start() -> Self {
        let p = params();
        let m = ChainManager::open(
            p.clone(),
            TxRules::for_chain(&p),
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [3; 32],
        )
        .unwrap();
        let shared: Shared = Arc::new(Mutex::new(m));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let l = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = l.local_addr().unwrap();
        let app = router(shared.clone());
        rt.spawn(async move { axum::serve(l, app).await });
        Self {
            _rt: rt,
            addr,
            shared,
            rng: ChaCha20Rng::seed_from_u64(5),
        }
    }

    fn client(&self) -> Client {
        Client::new(&self.addr.to_string())
    }

    /// A coinbase-only block on the tip, connected; returns its id.
    fn mine(&mut self) -> Hash {
        let mut m = self.shared.lock().unwrap();
        let (keys, _) = WalletKeys::generate(&mut self.rng);
        let t = m.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
            }],
            &keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let txs = vec![Transaction::Coinbase(cb)];
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(m.params().genesis.timestamp + 10 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        let b = Block { header, txs };
        m.submit_block(b, u64::MAX / 2).unwrap().id
    }

    fn tip_id(&self) -> Hash {
        self.shared.lock().unwrap().tip_id()
    }
}

/// A raw GET, for the status of a malformed query.
fn status_of(addr: SocketAddr, target: &str) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn tip_without_after_answers_at_once_from_the_snapshot() {
    let mut n = Node::start();
    let c = n.client();
    let t = c.tip(None, MAX_TIP_WAIT_SECS).unwrap();
    assert_eq!(t.height, 0);
    assert_eq!(t.tip, hex::encode(n.tip_id()));
    assert!(t.template_ready);
    let id = n.mine();
    assert_eq!(c.tip(None, 0).unwrap().tip, hex::encode(id));
    // No chain command: answered while the chain lock is held (on a thread
    // of its own, so that a failing check does not poison it: INV-70).
    let held = HeldChain::hold(&n.shared);
    let started = Instant::now();
    assert_eq!(c.tip(None, 0).unwrap().height, 1);
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(held);
    // A tip other than the node's (stale, or unknown) answers at once.
    let started = Instant::now();
    assert_eq!(c.tip(Some(&[9; 32]), 20).unwrap().height, 1);
    assert!(started.elapsed() < Duration::from_secs(5));
    // `after` must be a 32-byte id.
    assert_eq!(status_of(n.addr, "/tip?after=zz&wait=1"), 400);
    assert_eq!(status_of(n.addr, "/tip?after=abcd&wait=1"), 400);
}

/// The long poll is held while the tip is `after`, and answered within a
/// poll interval (plus scheduling) once a block changes it.
#[test]
fn a_long_poll_returns_as_soon_as_the_tip_changes() {
    let mut n = Node::start();
    let c = n.client();
    let genesis = n.tip_id();
    let poll = std::thread::spawn(move || {
        let started = Instant::now();
        let t = c.tip(Some(&genesis), 20).unwrap();
        (t, started.elapsed(), Instant::now())
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(!poll.is_finished(), "held while the tip is unchanged");
    let id = n.mine();
    let mined = Instant::now();
    let (t, held, answered) = poll.join().unwrap();
    assert_eq!((t.height, t.tip), (1, hex::encode(id)));
    // Held until the block: answered only after it was mined (`held` counts
    // from the thread's start, which a loaded machine delays, so it is not
    // asserted; the unfinished poll at 500 ms above shows the hold).
    assert!(
        answered >= mined,
        "answered before the block (held {held:?})"
    );
    let latency = answered.saturating_duration_since(mined);
    assert!(
        latency < Duration::from_secs(2),
        "answered {latency:?} after the block (poll interval {TIP_POLL_INTERVAL:?})"
    );
}

/// Without a new block the poll ends after `wait` with the same tip.
#[test]
fn a_long_poll_ends_after_its_wait_with_the_same_tip() {
    let n = Node::start();
    let tip = n.tip_id();
    let started = Instant::now();
    let t = n.client().tip(Some(&tip), 1).unwrap();
    let held = started.elapsed();
    assert_eq!(t.tip, hex::encode(tip));
    assert!(held >= Duration::from_millis(900), "{held:?}");
    assert!(held < Duration::from_secs(10), "{held:?}");
}

/// `next_seed_id` appears exactly for template heights 17..=20 (the lag
/// window before the switch at 21) and is the key block 16, which the
/// first template after the switch uses as its `seed_id`.
#[test]
fn the_template_announces_the_next_key_in_the_lag_window() {
    let mut n = Node::start();
    let c = n.client();
    let mut ids = vec![n.tip_id()];
    for _ in 1..=23 {
        let t = c.mining_template().unwrap();
        let h = t.template.height;
        assert_eq!(h as usize, ids.len());
        let expected = (17..=20).contains(&h).then(|| hex::encode(ids[16]));
        assert_eq!(t.next_seed_id, expected, "template height {h}");
        if h == 21 {
            assert_eq!(t.template.seed_id, hex::encode(ids[16]), "the switch");
        }
        // An older client decodes the same answer as a plain template.
        assert_eq!(c.template().unwrap().height, h);
        ids.push(n.mine());
    }
}

/// `/info` and `/tip` report whether templates are served. On regtest (no
/// clock rule) the node latches at its first input, so a bodiless header
/// lead leaves templates served (RTW3-1; the catch-up refusal is tested on
/// testnet parameters in `template_gate.rs`).
#[test]
fn info_reports_template_readiness() {
    let n = Node::start();
    let c = n.client();
    assert_eq!(c.info().unwrap().template_ready, Some(true));
    // Three headers ahead of the bodies (built on a scratch chain).
    let mut src = Node::start();
    for _ in 0..3 {
        src.mine();
    }
    let headers: Vec<BlockHeader> = {
        let m = src.shared.lock().unwrap();
        (1..=3).map(|h| m.block_at(h).unwrap().header).collect()
    };
    n.shared
        .lock()
        .unwrap()
        .accept_headers(&headers, u64::MAX / 2)
        .unwrap();
    assert!(n.shared.lock().unwrap().template_latched());
    assert_eq!(c.info().unwrap().header_height, 3);
    assert_eq!(c.info().unwrap().template_ready, Some(true));
    assert!(c.tip(None, 0).unwrap().template_ready);
    assert_eq!(c.template().unwrap().height, 1);
}
