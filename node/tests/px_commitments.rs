//! `/px/commitments` pagination (review R12-3): the page arithmetic on a state
//! with many synthetic PX records, and the HTTP parameter handling over the
//! real router.
//!
//! The records are applied directly to a `MemoryChain` (its `apply_block`
//! trusts that blocks were validated), so no PX proof is generated here.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_node::{px_commitments_page, router, Shared};
use blacksilk_rpc::{self as rpc, Client, RpcError};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::{digest_bytes, PxTx};
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const DEFAULT: u64 = rpc::DEFAULT_PX_COMMITMENTS_PER_REQUEST;
const MAX: u64 = rpc::MAX_PX_COMMITMENTS_PER_REQUEST;

fn synthetic_px(chain: &MemoryChain, tag: u32) -> Transaction {
    Transaction::Px(Box::new(PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: 0,
        bridge_in: 0,
        bridge_out: 0,
        window: Default::default(),
        anchor: chain.px().root(),
        nullifiers: [[tag, 1, 0, 0, 0, 0, 0, 0], [tag, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[tag, 3, 0, 0, 0, 0, 0, 0], [tag, 4, 0, 0, 0, 0, 0, 0]],
        ciphertexts: [vec![0xAA; 600], vec![0xBB; 600]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }))
}

/// A chain whose blocks carry `per_block[h]` PX transactions each (two
/// records per transaction).
fn chain(per_block: &[usize]) -> MemoryChain {
    let mut c = MemoryChain::new();
    let mut tag = 1;
    for &n in per_block {
        let txs: Vec<_> = (0..n)
            .map(|_| {
                tag += 1;
                synthetic_px(&c, tag)
            })
            .collect();
        c.apply_block(&txs).unwrap();
    }
    c
}

/// Enough records for several default pages and more than one maximal page.
fn big_chain() -> MemoryChain {
    // 1 + 20 blocks of 125 transactions = 5 000 records.
    let mut blocks = vec![0];
    blocks.extend(std::iter::repeat_n(125, 20));
    chain(&blocks)
}

fn hex(d: &[u32; 8]) -> String {
    hex::encode(digest_bytes(d))
}

/// The full list, as the node used to return it (unpaged).
fn full_list(c: &MemoryChain) -> Vec<(u64, String)> {
    c.px_records(0, u64::MAX)
        .iter()
        .map(|r| (r.height, hex(&r.commitment)))
        .collect()
}

fn page(c: &MemoryChain, from: Option<u64>, limit: Option<u64>) -> rpc::PxCommitments {
    px_commitments_page(c, c.next_height() - 1, from, limit).unwrap()
}

#[test]
fn pages_reassemble_the_full_list() {
    let c = big_chain();
    let full = full_list(&c);
    let total = full.len() as u64;
    assert_eq!(total, 5000);
    for limit in [None, Some(1), Some(7), Some(1000), Some(MAX)] {
        let mut got = Vec::new();
        let mut from = 0;
        let mut pages = 0;
        loop {
            let p = page(&c, Some(from), limit);
            pages += 1;
            assert_eq!(p.from, from);
            assert_eq!(p.total, total);
            assert_eq!(p.root, hex(&c.px().root()));
            assert_eq!(p.height, 20);
            let want = limit.unwrap_or(DEFAULT).min(total - from);
            assert_eq!(p.commitments.len() as u64, want, "limit {limit:?}");
            got.extend(p.commitments);
            match p.next {
                Some(n) => {
                    assert_eq!(n, got.len() as u64);
                    from = n;
                }
                None => break,
            }
        }
        assert_eq!(got, full, "limit {limit:?}");
        let per = limit.unwrap_or(DEFAULT);
        assert_eq!(pages, total.div_ceil(per), "limit {limit:?}");
    }
}

/// No parameters: the first default-size page, with `next`.
#[test]
fn no_parameters_return_the_first_bounded_page() {
    let c = big_chain();
    let p = page(&c, None, None);
    assert_eq!(p.from, 0);
    assert_eq!(p.commitments.len() as u64, DEFAULT);
    assert_eq!(p.next, Some(DEFAULT));
    assert_eq!(p.commitments, full_list(&c)[..DEFAULT as usize]);
}

#[test]
fn limit_bounds() {
    let c = chain(&[0, 3]);
    let h = c.next_height() - 1;
    assert!(px_commitments_page(&c, h, None, Some(0)).is_err());
    assert!(px_commitments_page(&c, h, None, Some(MAX + 1)).is_err());
    assert!(px_commitments_page(&c, h, None, Some(u64::MAX)).is_err());
    let p = page(&c, None, Some(MAX));
    assert_eq!(p.commitments.len(), 6);
    assert_eq!(p.next, None);
    // The cap applies on a big chain too.
    let c = big_chain();
    let p = page(&c, Some(10), Some(MAX));
    assert_eq!(p.commitments.len() as u64, MAX);
    assert_eq!(p.next, Some(10 + MAX));
}

#[test]
fn from_at_or_beyond_the_end() {
    let c = chain(&[0, 2, 0, 1]);
    let full = full_list(&c);
    assert_eq!(full.len(), 6);
    // The last entry alone.
    let p = page(&c, Some(5), None);
    assert_eq!(p.commitments, full[5..]);
    assert_eq!(p.next, None);
    for from in [6, 7, 1_000_000, u64::MAX] {
        let p = page(&c, Some(from), Some(MAX));
        assert_eq!(p.from, from, "from is echoed");
        assert!(p.commitments.is_empty());
        assert_eq!(p.total, 6);
        assert_eq!(p.next, None);
    }
}

/// Heights and root follow a reorganization of the state.
#[test]
fn pages_follow_undo() {
    let mut c = chain(&[0, 2, 1]);
    assert_eq!(page(&c, None, None).total, 6);
    c.undo_block();
    let p = page(&c, None, None);
    assert_eq!(p.total, 4);
    assert_eq!(p.height, 1);
    assert_eq!(p.commitments, full_list(&c));
    assert_eq!(p.root, hex(&c.px().root()));
}

/// The existing wallet's loop (`wallet/src/px.rs::sync_commitments`): request
/// `from` = what it has, append, stop when it has `total`. It needs no change
/// for the smaller default page.
#[test]
fn wallet_style_sync_completes() {
    let c = big_chain();
    let mut have: Vec<(u64, String)> = Vec::new();
    loop {
        let from = have.len() as u64;
        let p = page(&c, Some(from), None);
        assert_eq!(p.from, from);
        let added = p.commitments.len();
        have.extend(p.commitments);
        if added == 0 || have.len() as u64 == p.total {
            break;
        }
    }
    assert_eq!(have, full_list(&c));
}

// ---- over HTTP ----

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

struct Server {
    _rt: tokio::runtime::Runtime,
    addr: std::net::SocketAddr,
    shared: Shared,
}

fn serve() -> Server {
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
    let shared: Shared = Arc::new(Mutex::new(manager));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(shared.clone());
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        _rt: rt,
        addr,
        shared,
    }
}

/// A raw GET, returning the status code and body.
fn raw_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp[9..12].parse().unwrap();
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    (status, body.to_string())
}

#[test]
fn http_parameters() {
    let srv = serve();
    let client = Client::new(&srv.addr.to_string());
    let (root, height) = {
        let m = srv.shared.lock().unwrap();
        (hex(&m.state().px().root()), m.height())
    };

    // No parameters (compatibility): the first page.
    let (status, body) = raw_get(srv.addr, "/px/commitments");
    assert_eq!(status, 200, "{body}");
    for field in [
        "\"from\":0".to_string(),
        "\"total\":0".to_string(),
        "\"commitments\":[]".to_string(),
        "\"next\":null".to_string(),
        format!("\"root\":\"{root}\""),
        format!("\"height\":{height}"),
    ] {
        assert!(body.contains(&field), "{field} in {body}");
    }

    // `from` alone (what the existing wallet sends) and with `limit`.
    let p = client.px_commitments(0).unwrap();
    assert_eq!(p.from, 0);
    assert_eq!(p.total, 0);
    assert!(p.commitments.is_empty());
    assert_eq!(p.next, None);
    assert_eq!(p.root, root);
    assert_eq!(p.height, height);
    assert_eq!(client.px_commitments_page(0, MAX).unwrap(), p);
    let past = client.px_commitments_page(42, 1).unwrap();
    assert_eq!(past.from, 42);
    assert!(past.commitments.is_empty());
    assert_eq!(past.next, None);

    // Out-of-range and malformed limits are rejected.
    for limit in [0, MAX + 1] {
        match client.px_commitments_page(0, limit) {
            Err(RpcError::Status(400, _)) => {}
            other => panic!("limit {limit}: {other:?}"),
        }
    }
    for path in [
        "/px/commitments?limit=abc",
        "/px/commitments?from=-1",
        "/px/commitments?limit=18446744073709551616",
    ] {
        assert_eq!(raw_get(srv.addr, path).0, 400, "{path}");
    }
}
