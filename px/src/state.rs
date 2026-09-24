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

/// What [`State::apply_block`] changed.
#[derive(Clone, Debug)]
pub struct Undo {
    frontier: Frontier,
    roots: VecDeque<Digest>,
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

    /// Applies the (already proof-verified) transfers of a block, in order.
    /// On error nothing changes.
    pub fn apply_block(&mut self, transfers: &[Public]) -> Result<Undo, StateError> {
        let mut undo = Undo {
            frontier: self.frontier.clone(),
            roots: self.roots.clone(),
            pool: self.pool,
            nullifiers: Vec::new(),
        };
        match self.apply_inner(transfers, &mut undo) {
            Ok(()) => Ok(undo),
            Err(e) => {
                self.undo(undo);
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
        while self.roots.len() > ROOT_WINDOW {
            self.roots.pop_front();
        }
        Ok(())
    }

    /// Reverts the most recent [`apply_block`](Self::apply_block).
    pub fn undo(&mut self, undo: Undo) {
        for nf in &undo.nullifiers {
            self.nullifiers.remove(nf);
        }
        self.frontier = undo.frontier;
        self.roots = undo.roots;
        self.pool = undo.pool;
    }
}
