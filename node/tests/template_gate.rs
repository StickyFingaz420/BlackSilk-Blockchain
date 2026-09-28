//! The `/template` readiness gate (dossier 09 M9-2; decisions "W2-09"):
//! while the node's bodies are more than `TEMPLATE_SYNC_SLACK` (2) blocks
//! behind its best header, or a bounded drain is in progress, `/template`
//! answers `503` instead of a template on a tip the network has passed. No
//! peer-count rule: a lone node at genesis serves templates.
//!
//! Written to fail on the base commit (9457c2a), where `/template` always
//! answered from the connected tip.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, PowFunction};
use blacksilk_node::{router, Shared};
use blacksilk_rpc::{Client, RpcError};
use blacksilk_tx::params::TxRules;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// `n` linked headers on genesis, 60 s apart, valid under `ZeroPow`.
fn header_branch(p: &ChainParams, n: usize) -> Vec<BlockHeader> {
    let mut g = HeaderChain::new(p.clone(), Arc::new(ZeroPow));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + 60),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: 0,
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// The router over `shared`, served on a loopback port.
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

#[test]
fn template_answers_503_while_bodies_are_more_than_two_blocks_behind() {
    let p = ChainParams::regtest();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    let shared: Shared = Arc::new(Mutex::new(m));
    let (_rt, addr) = serve(shared.clone());
    let c = Client::new(&addr.to_string());
    // A lone node at genesis (no peers): templates are served.
    assert_eq!(c.template().expect("a lone node mines").height, 1);

    // Headers without bodies, as during a sync.
    let headers = header_branch(&shared.lock().unwrap().params().clone(), 3);
    shared
        .lock()
        .unwrap()
        .accept_headers(&headers[..2], u64::MAX / 2)
        .unwrap();
    assert_eq!(
        c.template()
            .expect("a header gap of 2 is within the slack")
            .height,
        1
    );
    shared
        .lock()
        .unwrap()
        .accept_headers(&headers[2..], u64::MAX / 2)
        .unwrap();
    match c.template() {
        Err(RpcError::Status(503, body)) => {
            assert!(body.starts_with("syncing"), "{body}");
            assert!(body.contains("height 0, headers 3"), "{body}");
        }
        other => panic!("expected 503 with a header gap of 3, got {other:?}"),
    }
}
