//! `GET /headers?from=h&count=n` (docs/blocks.md §9; W3-39b): the headers of
//! the connected blocks by height, the feed a wallet's header check reads
//! from the genesis. It serves the connected chain, also while a heavier
//! header branch whose bodies are missing is the best header chain, and
//! bounds the count.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_node::{connected_headers, router, Shared};
use blacksilk_rpc::{Client, RpcError, HEADER_BYTES, MAX_HEADERS_PER_REQUEST};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn node() -> Shared {
    let p = ChainParams::regtest();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    Arc::new(Mutex::new(m))
}

/// Mines `n` coinbase-only blocks on the connected tip, 120 s apart.
fn mine(shared: &Shared, n: u64) {
    let keys = WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(1)).0;
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut c = shared.lock().unwrap();
    for _ in 0..n {
        let t = c.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
            }],
            &keys.hedge_secret(),
            &mut rng,
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
                .max(c.params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        let now = header.timestamp;
        c.submit_block(Block { header, txs }, now).unwrap();
    }
}

/// The connected blocks' headers `from..=to`, read block by block.
fn expected(m: &ChainManager, from: u64, to: u64) -> Vec<BlockHeader> {
    (from..=to).map(|h| m.block_at(h).unwrap().header).collect()
}

fn serve(shared: Shared) -> (tokio::runtime::Runtime, SocketAddr) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = l.local_addr().unwrap();
    let app = router(shared);
    rt.spawn(async move { axum::serve(l, app).await });
    (rt, addr)
}

fn decode(hex_headers: &str) -> Vec<BlockHeader> {
    let bytes = hex::decode(hex_headers).unwrap();
    assert_eq!(bytes.len() % HEADER_BYTES, 0);
    bytes
        .chunks(HEADER_BYTES)
        .map(|c| BlockHeader::from_bytes(c).unwrap())
        .collect()
}

#[test]
fn headers_are_the_connected_blocks_by_height_and_bounded() {
    let shared = node();
    mine(&shared, 30);
    {
        let m = shared.lock().unwrap();
        for (from, count) in [(0, 1), (0, 31), (0, 2_000), (5, 10), (25, 100), (30, 1)] {
            let to = (from + count - 1).min(30);
            assert_eq!(
                connected_headers(&m, from, count),
                expected(&m, from, to),
                "{from} {count}"
            );
        }
        assert!(connected_headers(&m, 31, 5).is_empty(), "above the tip");
        assert!(connected_headers(&m, 3, 0).is_empty());
    }
    let (_rt, addr) = serve(shared.clone());
    let c = Client::new(&addr.to_string());
    let r = c.headers(0, MAX_HEADERS_PER_REQUEST).unwrap();
    assert_eq!((r.from, r.height), (0, 30));
    assert_eq!(decode(&r.headers), expected(&shared.lock().unwrap(), 0, 30));
    let r = c.headers(12, 3).unwrap();
    assert_eq!(r.from, 12);
    assert_eq!(
        decode(&r.headers),
        expected(&shared.lock().unwrap(), 12, 14)
    );
    assert_eq!(c.headers(40, 3).unwrap().headers, "");
    for count in [0, MAX_HEADERS_PER_REQUEST + 1] {
        assert!(
            matches!(c.headers(0, count), Err(RpcError::Status(400, _))),
            "{count}"
        );
    }
}

/// A heavier header branch whose bodies are missing becomes the best header
/// chain; the connected chain (the one whose bodies the node has) is what
/// `/headers` serves, above and below the fork point.
#[test]
fn headers_follow_the_connected_chain_not_a_bodiless_heavier_branch() {
    let shared = node();
    mine(&shared, 20);
    let p = ChainParams::regtest();
    // The branch: the connected headers up to 10, then 30 headers of its own.
    let mut g = HeaderChain::new(p.clone(), Arc::new(ZeroPow));
    {
        let m = shared.lock().unwrap();
        for h in expected(&m, 1, 10) {
            g.accept(h, u64::MAX / 2).unwrap();
        }
    }
    let mut branch = Vec::new();
    for _ in 0..30 {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + 7),
            difficulty: t.difficulty,
            tx_root: [1; 32],
            nonce: 0,
        };
        g.accept(h, u64::MAX / 2).unwrap();
        branch.push(h);
    }
    let mut m = shared.lock().unwrap();
    m.accept_headers(&branch, u64::MAX / 2).unwrap();
    assert_eq!((m.height(), m.header_height()), (20, 40));
    assert!(!m.headers().is_on_main(&m.tip_id()));
    for (from, count) in [(0, 2_000), (5, 10), (11, 3), (15, 100), (20, 1)] {
        let to = (from + count - 1).min(20);
        assert_eq!(
            connected_headers(&m, from, count),
            expected(&m, from, to),
            "{from} {count}"
        );
    }
    assert!(connected_headers(&m, 21, 10).is_empty());
}
