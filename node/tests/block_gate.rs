//! The RPC `/block` gate uses the shared anti-DoS work gate
//! (`blacksilk_chain::sync_policy::worth_verifying`, R16-5; decisions "Agent
//! 07" W2): one rule for P2P headers and RPC blocks.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, PowFunction};
use blacksilk_node::rpc_block_admissible;
use blacksilk_tx::params::TxRules;
use std::sync::Arc;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
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
            ..Default::default()
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// A block on the connected tip is admitted while our best header chain is
/// near it, and refused (`LowWork`, before any proof of work) once our best
/// header chain is more than `ANTI_DOS_BLOCKS` of work ahead, as during an
/// initial sync, whatever difficulty the block claims.
#[test]
fn the_rpc_block_gate_applies_the_shared_work_gate() {
    let p = ChainParams::regtest();
    let mut m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    // The candidate: a child of the connected tip (genesis).
    let own = {
        let t = m.headers().template_on(m.tip_id()).unwrap();
        BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp + 1,
            difficulty: t.difficulty,
            tx_root: [1; 32],
            nonce: 0,
            ..Default::default()
        }
    };
    assert_eq!(rpc_block_admissible(&m, &own), Ok(()));

    // Headers without bodies: the connected tip stays at genesis while our
    // best header chain moves 200 blocks ahead.
    let ahead = header_branch(&p, 200);
    m.accept_headers(&ahead, u64::MAX / 2).unwrap();
    assert_eq!((m.height(), m.header_height()), (0, 200));
    let refused = rpc_block_admissible(&m, &own).unwrap_err();
    assert!(refused.starts_with("LowWork"), "{refused}");
    // The claimed difficulty buys nothing: the gate charges the required one.
    let claiming = BlockHeader {
        difficulty: u64::MAX,
        ..own
    };
    let refused = rpc_block_admissible(&m, &claiming).unwrap_err();
    assert!(refused.starts_with("LowWork"), "{refused}");

    // Within the anti-DoS window the block is admitted again.
    let mut m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    m.accept_headers(&ahead[..100], u64::MAX / 2).unwrap();
    assert_eq!(rpc_block_admissible(&m, &own), Ok(()));
}
