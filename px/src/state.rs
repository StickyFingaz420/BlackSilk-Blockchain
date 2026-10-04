//! The PX consensus state (zk.md §4.5, §4.7; docs/px.md §5).
//!
//! - the commitment tree frontier;
//! - the root window: the tree roots after each of the last [`ROOT_WINDOW`]
//!   blocks (initially the empty tree's root); a transfer's anchor must be
//!   one of them;
//! - the nullifier set: a nullifier can appear once, ever;
//! - the pool: the BLK value inside PX, which can never go negative. Even a
//!   complete break of the proof system cannot withdraw more than was
//!   deposited (containment).
//!
//! Blocks are applied atomically: a block with one invalid transfer changes
//! nothing. [`State::apply_block`] returns an [`Undo`] that restores the
//! previous state exactly, for reorganizations.
//!
//! The proofs are checked separately ([`crate::prove::verify_transfer`]),
//! before the state rules; this module handles only the public statements.

use crate::perm::HostPerm;
use crate::tree::{empty_roots, Frontier};
use blacksilk_px_core::kernel::{Public, TREE_DEPTH};
use blacksilk_px_core::Digest;
use std::collections::{HashSet, VecDeque};

/// Number of recent block roots a transfer may use as anchor.
pub const ROOT_WINDOW: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The anchor is not a recent root.
    UnknownAnchor,
    /// The nullifier was already spent (in the chain or earlier in the block).
    DoubleSpend(Digest),
    /// The pool would go negative.
    PoolUnderflow,
    TreeFull,
}

#[derive(Clone, Debug)]
pub struct State {
    frontier: Frontier,
    roots: VecDeque<Digest>,
    nullifiers: HashSet<Digest>,
    pool: u128,
    empty: [Digest; TREE_DEPTH + 1],
}

/// What [`State::apply_block`] changed: only what it cannot recompute
/// (21-F, dossier 21 F21-4). About 90 bytes for a block without PX
/// transfers, which is most blocks, instead of the whole root window (3.2 KB)
/// and frontier (about 1 KB) for every block.
#[derive(Clone, Debug)]
pub struct Undo {
    /// The frontier before the block; `None` if the block appended nothing.
    frontier: Option<Box<Frontier>>,
    /// The root the block's own root pushed out of the window, if the
    /// window was full.
    evicted: Option<Digest>,
    pool: u128,
    nullifiers: Vec<Digest>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        let frontier = Frontier::default();
        let root = frontier.root(&mut perm, &empty);
        State {
            frontier,
            roots: VecDeque::from([root]),
            nullifiers: HashSet::new(),
            pool: 0,
            empty,
        }
    }

    pub fn pool(&self) -> u128 {
        self.pool
    }

    pub fn root(&self) -> Digest {
        *self.roots.back().expect("the window is never empty")
    }

    pub fn is_recent_root(&self, anchor: &Digest) -> bool {
        self.roots.contains(anchor)
    }

    pub fn is_spent(&self, nf: &Digest) -> bool {
        self.nullifiers.contains(nf)
    }

    pub fn size(&self) -> u64 {
        self.frontier.size()
    }

    /// The tree's root after appending `leaves` (in order) to the current
    /// tree, without changing the state: the root the block appending them
    /// records (rule B-PXR, docs/px.md §5). `None` if they do not fit
    /// ([`StateError::TreeFull`]; rule B8 refuses such a block first).
    pub fn root_after(&self, leaves: &[Digest]) -> Option<Digest> {
        if leaves.is_empty() {
            return Some(self.root());
        }
        let mut perm = HostPerm::new();
        let mut frontier = self.frontier.clone();
        for cm in leaves {
            frontier.append(&mut perm, *cm).ok()?;
        }
        Some(frontier.root(&mut perm, &self.empty))
    }

    /// Leaves the tree can still take: `CAPACITY − size`.
    pub fn free_leaves(&self) -> u64 {
        crate::tree::CAPACITY - self.frontier.size()
    }

    /// A state whose tree holds `size` leaves all equal to `leaf`, with that
    /// tree's root as the only recent root and `pool` in the pool (tests
    /// only: a tree near capacity cannot be reached by applying blocks).
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn with_uniform_tree_for_tests(size: u64, leaf: Digest, pool: u128) -> Self {
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        let frontier = Frontier::uniform_for_tests(&mut perm, leaf, size);
        let root = frontier.root(&mut perm, &empty);
        State {
            frontier,
            roots: VecDeque::from([root]),
            nullifiers: HashSet::new(),
            pool,
            empty,
        }
    }

    /// Applies the (already proof-verified) transfers of a block, in order.
    /// On error nothing changes.
    pub fn apply_block(&mut self, transfers: &[Public]) -> Result<Undo, StateError> {
        let mut undo = Undo {
            frontier: (!transfers.is_empty()).then(|| Box::new(self.frontier.clone())),
            evicted: None,
            pool: self.pool,
            nullifiers: Vec::new(),
        };
        match self.apply_inner(transfers, &mut undo) {
            Ok(()) => Ok(undo),
            Err(e) => {
                // Every failure happens before the block's root is pushed:
                // restore what the transfers changed.
                for nf in &undo.nullifiers {
                    self.nullifiers.remove(nf);
                }
                if let Some(f) = undo.frontier {
                    self.frontier = *f;
                }
                self.pool = undo.pool;
                Err(e)
            }
        }
    }

    /// Applies the transfers, recording spent nullifiers in `undo`.
    fn apply_inner(&mut self, transfers: &[Public], undo: &mut Undo) -> Result<(), StateError> {
        let mut perm = HostPerm::new();
        for t in transfers {
            // Anchors refer to roots at the end of earlier blocks, never to
            // a state inside this block.
            if !self.roots.contains(&t.anchor) {
                return Err(StateError::UnknownAnchor);
            }
            for nf in &t.nullifiers {
                if !self.nullifiers.insert(*nf) {
                    return Err(StateError::DoubleSpend(*nf));
                }
                undo.nullifiers.push(*nf);
            }
            let pool = self.pool + t.bridge_in as u128;
            self.pool = pool
                .checked_sub(t.bridge_out as u128)
                .ok_or(StateError::PoolUnderflow)?;
            for cm in &t.commitments {
                self.frontier
                    .append(&mut perm, *cm)
                    .map_err(|_| StateError::TreeFull)?;
            }
        }
        let root = self.frontier.root(&mut perm, &self.empty);
        self.roots.push_back(root);
        // The window grows by one root per block and never holds more than
        // ROOT_WINDOW, so at most one root leaves it.
        if self.roots.len() > ROOT_WINDOW {
            undo.evicted = self.roots.pop_front();
        }
        debug_assert!(self.roots.len() <= ROOT_WINDOW);
        Ok(())
    }

    /// Reverts the most recent successful [`apply_block`](Self::apply_block),
    /// whose `Undo` this is: removes the nullifiers it inserted, restores the
    /// frontier (if it appended) and the pool, drops its root from the window
    /// and puts back the root it evicted.
    pub fn undo(&mut self, undo: Undo) {
        for nf in &undo.nullifiers {
            self.nullifiers.remove(nf);
        }
        if let Some(f) = undo.frontier {
            self.frontier = *f;
        }
        self.roots.pop_back();
        if let Some(r) = undo.evicted {
            self.roots.push_front(r);
        }
        self.pool = undo.pool;
    }
}

#[cfg(test)]
mod tests {
    //! 21-F: the compact undo is behaviour-identical to the former full
    //! clone. Seeded random apply/undo sequences (valid and failing blocks,
    //! anchors inside and outside the window, double spends, pool
    //! underflows, the window's eviction) are compared with the reference:
    //! a clone of the whole state taken before each block.
    use super::*;
    use blacksilk_px_core::call::MAX_FN;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn same(a: &State, b: &State) -> bool {
        a.frontier == b.frontier
            && a.roots == b.roots
            && a.nullifiers == b.nullifiers
            && a.pool == b.pool
    }

    fn d(x: u64) -> Digest {
        [x as u32, (x >> 32) as u32, 1, 2, 3, 4, 5, 6]
    }

    fn transfer(rng: &mut ChaCha20Rng, s: &State, next_cm: &mut u64) -> Public {
        // Mostly a recent root; sometimes an unknown one.
        let anchor = if rng.next_u64().is_multiple_of(8) {
            d(1 << 40 | (rng.next_u64() % 4))
        } else {
            s.roots[(rng.next_u64() % s.roots.len() as u64) as usize]
        };
        // Nullifiers from a small space: double spends are frequent.
        let nullifiers = [d(rng.next_u64() % 400), d(rng.next_u64() % 400)];
        *next_cm += 2;
        let (bridge_in, bridge_out) = match rng.next_u64() % 3 {
            0 => (rng.next_u64() % 1_000, 0),
            1 => (0, rng.next_u64() % 1_000),
            _ => (0, 0),
        };
        Public {
            anchor,
            nullifiers,
            commitments: [d(*next_cm), d(*next_cm + 1)],
            bridge_in,
            bridge_out,
            n_fn: 0,
            functions: [([0; 8], [0; 8]); MAX_FN],
        }
    }

    /// `root_after` past the capacity is `None`, as `apply_block` fails
    /// there; up to it, the full tree's root (21-D).
    #[test]
    fn root_after_follows_the_capacity() {
        let cap = crate::tree::CAPACITY;
        let s = State::with_uniform_tree_for_tests(cap - 1, d(7), 0);
        assert!(s.root_after(&[d(7)]).is_some());
        assert_eq!(s.root_after(&[d(7), d(8)]), None);
        assert_eq!(s.root_after(&[]), Some(s.root()));
        let full = State::with_uniform_tree_for_tests(cap, d(7), 0);
        assert_eq!(s.root_after(&[d(7)]), Some(full.root()));
    }

    #[test]
    fn compact_undo_equals_the_full_clone_reference() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x21F);
        let mut s = State::new();
        // (undo, the state before the block) for every applied block.
        let mut stack: Vec<(Undo, State)> = Vec::new();
        let (mut applied, mut failed, mut undone, mut evicting) = (0, 0, 0, 0);
        let mut next_cm = 0u64;
        for step in 0..4_000 {
            if !stack.is_empty() && rng.next_u64().is_multiple_of(5) {
                let (u, before) = stack.pop().unwrap();
                s.undo(u);
                assert!(same(&s, &before), "undo at step {step}");
                undone += 1;
                continue;
            }
            let n = (rng.next_u64() % 4) as usize; // 0 to 3 transfers
            let block: Vec<Public> = (0..n)
                .map(|_| transfer(&mut rng, &s, &mut next_cm))
                .collect();
            let before = s.clone();
            let full = s.roots.len() == ROOT_WINDOW;
            let leaves: Vec<Digest> = block.iter().flat_map(|t| t.commitments).collect();
            let predicted = s.root_after(&leaves);
            match s.apply_block(&block) {
                Ok(u) => {
                    // B-PXR: the predicted root is the one the block records.
                    assert_eq!(predicted, Some(s.root()), "root_after at step {step}");
                    assert_eq!(u.frontier.is_some(), n > 0);
                    assert_eq!(u.evicted.is_some(), full);
                    evicting += usize::from(full);
                    applied += 1;
                    stack.push((u, before));
                }
                Err(_) => {
                    assert!(same(&s, &before), "failed block at step {step}");
                    failed += 1;
                }
            }
        }
        // Unwind everything: back to the genesis state.
        while let Some((u, before)) = stack.pop() {
            s.undo(u);
            assert!(same(&s, &before));
        }
        assert!(same(&s, &State::new()));
        assert!(
            applied > 500 && failed > 200 && undone > 500,
            "{applied} {failed} {undone}"
        );
        assert!(evicting > 100, "the window's eviction ran ({evicting})");
    }

    /// The undo of a block without PX transfers holds no frontier and no
    /// root: a few dozen bytes, nothing on the heap.
    #[test]
    fn an_empty_blocks_undo_is_small() {
        let size = std::mem::size_of::<Undo>();
        assert!(size <= 96, "{size}");
        let mut s = State::new();
        let u = s.apply_block(&[]).unwrap();
        assert!(u.frontier.is_none() && u.evicted.is_none() && u.nullifiers.is_empty());
    }

    /// The test-only near-capacity state: `free_leaves` counts down to 0,
    /// the append that fills the tree records the full root (21-D) as the
    /// block's root, and a block that would overflow fails with `TreeFull`
    /// and changes nothing.
    #[test]
    fn a_block_filling_the_tree_is_applied_and_one_more_leaf_is_refused() {
        let cap = crate::tree::CAPACITY;
        let mut s = State::with_uniform_tree_for_tests(cap - 4, d(9), 0);
        let g = s.root();
        assert_eq!(s.free_leaves(), 4);
        let t = |a: Digest, n: u64| Public {
            anchor: a,
            nullifiers: [d(n), d(n + 1)],
            commitments: [d(n + 2), d(n + 3)],
            bridge_in: 0,
            bridge_out: 0,
            n_fn: 0,
            functions: [([0; 8], [0; 8]); MAX_FN],
        };
        let before = s.clone();
        // Three transfers need six leaves: refused, nothing changes.
        assert_eq!(
            s.apply_block(&[t(g, 10), t(g, 20), t(g, 30)]).err(),
            Some(StateError::TreeFull)
        );
        assert!(same(&s, &before));
        // Two transfers fill it exactly.
        let u = s.apply_block(&[t(g, 10), t(g, 20)]).unwrap();
        assert_eq!(s.free_leaves(), 0);
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        assert_ne!(
            s.root(),
            empty[TREE_DEPTH],
            "the full root, not the empty one"
        );
        let full = s.root();
        assert!(s.is_recent_root(&full));
        // Any further leaf is refused; an empty block is fine.
        assert_eq!(
            s.apply_block(&[t(full, 40)]).err(),
            Some(StateError::TreeFull)
        );
        let e = s.apply_block(&[]).unwrap();
        s.undo(e);
        s.undo(u);
        assert!(same(&s, &before), "undo is exact at capacity");
    }

    /// RT-W1b: deep reorganizations across capacity. From 12 free leaves,
    /// 800 blocks (random 0-3 transfers each, anchors anywhere in the
    /// window, so the window evicts and the tree fills; later blocks keep
    /// trying to append and fail with `TreeFull`) are applied; then every
    /// block is undone, one by one, back to the start, each step compared
    /// with a clone taken before the block. Replaying the same accepted
    /// blocks reaches the same full root.
    #[test]
    fn deep_reorg_across_capacity_is_exact() {
        let cap = crate::tree::CAPACITY;
        let start = State::with_uniform_tree_for_tests(cap - 12, d(9), 1 << 40);
        let mut s = start.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(0xB8);
        let mut stack: Vec<(Undo, State)> = Vec::new();
        let mut accepted: Vec<Vec<Public>> = Vec::new();
        let (mut full_refused, mut n) = (0, 1_000u64);
        for _ in 0..800 {
            let k = (rng.next_u64() % 4) as usize;
            let block: Vec<Public> = (0..k)
                .map(|_| {
                    n += 4;
                    Public {
                        anchor: s.roots[(rng.next_u64() % s.roots.len() as u64) as usize],
                        nullifiers: [d(n), d(n + 1)],
                        commitments: [d(n + 2), d(n + 3)],
                        bridge_in: 1,
                        bridge_out: 0,
                        n_fn: 0,
                        functions: [([0; 8], [0; 8]); MAX_FN],
                    }
                })
                .collect();
            let before = s.clone();
            match s.apply_block(&block) {
                Ok(u) => {
                    stack.push((u, before));
                    accepted.push(block);
                }
                Err(StateError::TreeFull) => {
                    assert!(same(&s, &before));
                    full_refused += 1;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(s.free_leaves(), 0, "the tree filled");
        assert!(full_refused > 50, "{full_refused}");
        let full_root = s.root();
        let full_state = s.clone();
        let depth = stack.len();
        assert!(depth > ROOT_WINDOW + 50, "the window evicted ({depth})");
        while let Some((u, before)) = stack.pop() {
            s.undo(u);
            assert!(same(&s, &before), "undo {} of {depth}", depth - stack.len());
        }
        assert!(same(&s, &start), "back to the start");
        for b in &accepted {
            s.apply_block(b).unwrap();
        }
        assert!(same(&s, &full_state), "replay reaches the same state");
        assert_eq!(s.root(), full_root);
    }
}
