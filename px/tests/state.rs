//! PX consensus state: anchors, double spends, the pool, atomic blocks and
//! exact undo (docs/px.md §5).

use blacksilk_px::state::{State, StateError, ROOT_WINDOW};
use blacksilk_px_core::kernel::Public;
use blacksilk_px_core::Digest;

fn d(x: u32) -> Digest {
    [x, 1, 2, 3, 4, 5, 6, 7]
}

fn tx(anchor: Digest, nf: [u32; 2], cm: [u32; 2], bridge_in: u64, bridge_out: u64) -> Public {
    Public {
        anchor,
        nullifiers: [d(nf[0]), d(nf[1])],
        commitments: [d(cm[0]), d(cm[1])],
        bridge_in,
        bridge_out,
        n_fn: 0,
        functions: [([0; 8], [0; 8]); 2],
    }
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    root: Digest,
    size: u64,
    pool: u128,
    spent: Vec<bool>,
}

fn snap(s: &State, nfs: &[u32]) -> Snapshot {
    Snapshot {
        root: s.root(),
        size: s.size(),
        pool: s.pool(),
        spent: nfs.iter().map(|&n| s.is_spent(&d(n))).collect(),
    }
}

#[test]
fn blocks_apply_and_undo_exactly() {
    let mut s = State::new();
    let genesis = s.root();
    let nfs = [1, 2, 3, 4, 5, 6];
    let before = snap(&s, &nfs);
    let u1 = s
        .apply_block(&[tx(genesis, [1, 2], [10, 11], 100, 0)])
        .unwrap();
    assert_eq!(s.pool(), 100);
    assert_eq!(s.size(), 2);
    let r1 = s.root();
    assert_ne!(r1, genesis);
    let mid = snap(&s, &nfs);
    // Anchors may be the genesis root or r1.
    let u2 = s
        .apply_block(&[
            tx(r1, [3, 4], [12, 13], 0, 40),
            tx(genesis, [5, 6], [14, 15], 0, 60),
        ])
        .unwrap();
    assert_eq!(s.pool(), 0);
    assert_eq!(s.size(), 6);
    s.undo(u2);
    assert_eq!(snap(&s, &nfs), mid);
    s.undo(u1);
    assert_eq!(snap(&s, &nfs), before);
}

#[test]
fn double_spends_are_rejected_and_leave_no_trace() {
    let mut s = State::new();
    let g = s.root();
    s.apply_block(&[tx(g, [1, 2], [10, 11], 10, 0)]).unwrap();
    let nfs = [1, 2, 3, 4, 5, 7];
    let before = snap(&s, &nfs);
    // Spent in an earlier block.
    assert_eq!(
        s.apply_block(&[tx(g, [3, 2], [12, 13], 0, 0)]).err(),
        Some(StateError::DoubleSpend(d(2)))
    );
    assert_eq!(snap(&s, &nfs), before);
    // Twice in one block (a valid first transfer is rolled back too).
    assert_eq!(
        s.apply_block(&[tx(g, [3, 4], [12, 13], 0, 0), tx(g, [5, 4], [14, 15], 0, 0)])
            .err(),
        Some(StateError::DoubleSpend(d(4)))
    );
    assert_eq!(snap(&s, &nfs), before);
    // Twice in one transfer.
    assert_eq!(
        s.apply_block(&[tx(g, [7, 7], [12, 13], 0, 0)]).err(),
        Some(StateError::DoubleSpend(d(7)))
    );
    assert_eq!(snap(&s, &nfs), before);
}

#[test]
fn the_pool_never_goes_negative() {
    let mut s = State::new();
    let g = s.root();
    s.apply_block(&[tx(g, [1, 2], [10, 11], 50, 0)]).unwrap();
    assert_eq!(
        s.apply_block(&[tx(g, [3, 4], [12, 13], 0, 51)]).err(),
        Some(StateError::PoolUnderflow)
    );
    assert_eq!(s.pool(), 50);
    // Order inside a block matters: withdraw after deposit is fine.
    s.apply_block(&[
        tx(g, [3, 4], [12, 13], 10, 0),
        tx(g, [5, 6], [14, 15], 0, 60),
    ])
    .unwrap();
    assert_eq!(s.pool(), 0);
    // Maximal amounts are exact (u128 pool).
    s.apply_block(&[
        tx(g, [7, 8], [16, 17], u64::MAX, 0),
        tx(g, [9, 10], [18, 19], u64::MAX, 0),
        tx(g, [11, 12], [20, 21], 0, u64::MAX),
    ])
    .unwrap();
    assert_eq!(s.pool(), u64::MAX as u128);
}

#[test]
fn anchors_must_be_recent_block_roots() {
    let mut s = State::new();
    let g = s.root();
    assert_eq!(
        s.apply_block(&[tx(d(99), [1, 2], [10, 11], 0, 0)]).err(),
        Some(StateError::UnknownAnchor)
    );
    // The genesis root stays valid for ROOT_WINDOW blocks, then expires.
    let mut n = 100;
    for _ in 0..ROOT_WINDOW {
        assert!(s.is_recent_root(&g));
        s.apply_block(&[tx(g, [n, n + 1], [n, n + 1], 0, 0)])
            .unwrap();
        n += 2;
    }
    assert!(!s.is_recent_root(&g));
    assert_eq!(
        s.apply_block(&[tx(g, [n, n + 1], [n, n + 1], 0, 0)]).err(),
        Some(StateError::UnknownAnchor)
    );
    // An empty block still records a root.
    let r = s.root();
    s.apply_block(&[]).unwrap();
    assert!(s.is_recent_root(&r));
}
