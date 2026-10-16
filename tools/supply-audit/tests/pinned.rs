//! `Pinned`, the node as the audited wallets see it (G8 T1, T1c): nothing
//! above the audit height, the audit height and block id reported as the
//! node's, and no transaction ever submitted.
//!
//! The inner node here over-serves on purpose: it answers every request
//! with everything it has from `from` up to its own tip (height 20),
//! whatever count was asked. Pinned sits at height 10. Every expected value
//! below is a constant of this test (10, 20, `HEADER_BYTES`), not a value
//! computed by the code under test. Pinned bounds what it returns by the
//! audit height, not by the requested count (the wallets' feeds check the
//! count themselves), so only the height bound is asserted.

use blacksilk_rpc as rpc;
use blacksilk_supply_audit::Pinned;
use blacksilk_wallet::node::NodeApi;
use std::cell::{Cell, RefCell};

const AUDIT: u64 = 10;
const INNER_TIP: u64 = 20;

/// A node at `tip` that over-serves `blocks` and `headers`, records every
/// request it receives, and counts `submit_tx` calls.
struct Overserving {
    tip: u64,
    requests: RefCell<Vec<(&'static str, u64, u64)>>,
    submitted: Cell<u32>,
}

impl Overserving {
    fn new(tip: u64) -> Self {
        Self {
            tip,
            requests: RefCell::new(Vec::new()),
            submitted: Cell::new(0),
        }
    }
}

fn info_at(height: u64, tip: &str) -> rpc::Info {
    serde_json::from_value(serde_json::json!({
        "network": "regtest",
        "network_id": 1,
        "height": height,
        "tip": tip,
        "difficulty": 1,
        "generated": 0,
        "mempool_txs": 0,
        "mempool_bytes": 0,
        "outputs": 0,
        "header_height": height,
    }))
    .unwrap()
}

impl NodeApi for Overserving {
    fn info(&self) -> Result<rpc::Info, String> {
        Ok(info_at(self.tip, &format!("t{}", self.tip)))
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        self.requests.borrow_mut().push(("blocks", from, count));
        let blocks = (from..=self.tip)
            .map(|h| rpc::BlockEntry {
                height: h,
                id: format!("{h:064x}"),
                first_output: 0,
                hex: "00".into(),
            })
            .collect();
        Ok(rpc::Blocks { blocks })
    }
    fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
        self.requests.borrow_mut().push(("headers", from, count));
        let n = (self.tip + 1).saturating_sub(from) as usize;
        Ok(rpc::Headers {
            from,
            headers: "ab".repeat(n * rpc::HEADER_BYTES),
            height: self.tip,
        })
    }
    fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
        Err("not served".into())
    }
    fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
        Err("not served".into())
    }
    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        self.submitted.set(self.submitted.get() + 1);
        Err("the inner node received a transaction".into())
    }
    fn px_commitments(&self, _: u64) -> Result<rpc::PxCommitments, String> {
        Err("not served".into())
    }
    fn px_contracts(&self, _: u64) -> Result<rpc::PxContracts, String> {
        Err("not served".into())
    }
}

fn heights(b: &rpc::Blocks) -> Vec<u64> {
    b.blocks.iter().map(|e| e.height).collect()
}

/// T1: blocks, headers and info are cut at the audit height, whatever the
/// inner node sends; `submit_tx` never reaches it.
#[test]
fn pinned_serves_exactly_the_audit_height() {
    let inner = Overserving::new(INNER_TIP);
    let p = Pinned::new(&inner, AUDIT, "t10".into());

    // Blocks: 1..=10 and nothing above, the audit block itself included.
    assert_eq!(
        heights(&p.blocks(1, 100).unwrap()),
        (1..=10).collect::<Vec<_>>()
    );
    assert_eq!(heights(&p.blocks(10, 1).unwrap()), vec![10]);
    assert_eq!(heights(&p.blocks(10, 50).unwrap()), vec![10]);
    assert!(p.blocks(11, 5).unwrap().blocks.is_empty());
    assert!(p.blocks(15, 1).unwrap().blocks.is_empty());
    assert!(p.blocks(5, 0).unwrap().blocks.is_empty());

    // Headers: exactly the headers of 1..=10 (HEADER_BYTES each, as hex),
    // and the audit height reported as the node's.
    let one = rpc::HEADER_BYTES * 2;
    let h = p.headers(1, 100).unwrap();
    assert_eq!(h.headers.len(), 10 * one);
    assert_eq!((h.from, h.height), (1, AUDIT));
    let h = p.headers(10, 1).unwrap();
    assert_eq!(h.headers.len(), one);
    assert_eq!((h.from, h.height), (10, AUDIT));
    let h = p.headers(7, 100).unwrap();
    assert_eq!(h.headers.len(), 4 * one);
    for (from, count) in [(11, 1), (15, 100), (5, 0)] {
        let h = p.headers(from, count).unwrap();
        assert!(h.headers.is_empty(), "headers({from}, {count})");
        assert_eq!(
            (h.from, h.height),
            (from, AUDIT),
            "headers({from}, {count})"
        );
    }

    // Info: the audit height and block id, the header height capped.
    let i = p.info().unwrap();
    assert_eq!(i.height, AUDIT);
    assert_eq!(i.header_height, AUDIT);
    assert_eq!(i.tip, "t10");

    // Read-only: refused, and the inner node never saw it.
    assert!(p.submit_tx(&[1, 2, 3]).is_err());
    assert_eq!(inner.submitted.get(), 0);
}

/// T1c: Pinned never asks the inner node for anything above the audit height,
/// so its answers do not depend on how the node treats such requests.
#[test]
fn pinned_never_requests_above_the_audit_height() {
    let inner = Overserving::new(INNER_TIP);
    let p = Pinned::new(&inner, AUDIT, "t10".into());
    for (from, count) in [
        (1, 100),
        (4, 3),
        (10, 1),
        (10, 50),
        (7, 100),
        (11, 5),
        (5, 0),
    ] {
        p.blocks(from, count).unwrap();
        p.headers(from, count).unwrap();
    }
    let requests = inner.requests.borrow();
    assert!(!requests.is_empty());
    for &(what, from, count) in requests.iter() {
        assert!(count >= 1, "{what}({from}, {count})");
        assert!(
            from + count - 1 <= AUDIT,
            "{what}({from}, {count}) reaches above {AUDIT}"
        );
    }
}

/// A node below the audit height (a reorganization during the audit) is an
/// error, not a shorter view.
#[test]
fn pinned_refuses_a_node_below_the_audit_height() {
    let inner = Overserving::new(9);
    let p = Pinned::new(&inner, AUDIT, "t10".into());
    assert!(p.info().is_err());
}
