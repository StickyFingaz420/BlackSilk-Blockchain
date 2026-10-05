//! The wallet's own PX commitment tree (dossier 39 W1, finding F39-1).
//!
//! The wallet builds the tree from the blocks it scans (their transactions
//! are bound to the header by `tx_root`, and the headers to each other by
//! `prev_id`), not from a list the node supplies. It mirrors the consensus
//! state of `blacksilk_px::state` exactly:
//! - the same tree (depth 32, node hash `blacksilk_px_core::hash::node`,
//!   empty leaves 0), appended with the two commitments of every PX
//!   transaction in block order;
//! - the same root window: the roots after each of the last
//!   [`ROOT_WINDOW`] blocks, initially the empty tree's root.
//!
//! Every anchor of a scanned PX transaction must be in the wallet's own
//! window, as consensus requires of every block ([`WalletTree::check_anchor`]).
//! A node whose blocks or commitment list disagree with the tree they imply
//! is refused. The wallet anchors its own spends at the root it computed
//! itself, so a node cannot choose it.
//!
//! **Below the restore height** the wallet does not scan blocks: the
//! commitments there come once from the node's bulk list (`/px/commitments`,
//! fetched whole: it tells the node nothing), the *backfill*. It is bound
//! to the chain as soon as a scanned PX transaction anchors at a root that
//! includes a commitment of a scanned block ([`WalletTree::is_confirmed`]):
//! the backfill is then the chain's exact list, by the collision resistance
//! of the node hash and the uniqueness of commitments. Until then the
//! wallet's spend policy decides what the backfill may be used for
//! (`crate::px::PxStore::anchor_for`).
//!
//! **Witnesses** (in-tree, decisions "Agent 39"): an incremental witness per
//! leaf the wallet may spend. Its left siblings (ommers) are taken from the
//! frontier when the leaf is appended; its right siblings are recorded when
//! the frontier completes them. A path at an anchor with `S` leaves uses the
//! completed right siblings that fit in `S`, the one partially filled
//! sibling computed from the frontier at the anchor (kept at every multiple
//! of 16, where anchors lie), and empty subtrees above. Paths are checked
//! against [`blacksilk_px::tree::Tree`] in the tests.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::state::ROOT_WINDOW;
use blacksilk_px::tree::{empty_roots, CAPACITY};
use blacksilk_px_core::hash::node;
use blacksilk_px_core::kernel::TREE_DEPTH;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// Scanned blocks whose commitments the tree keeps, for rewinds: the
/// wallet's reorganization window (720 blocks) plus a root window, so the
/// root window can be rebuilt after the deepest rewind the wallet makes
/// without a rescan.
pub const KEPT_TREE_BLOCKS: usize = 720 + ROOT_WINDOW;

/// Frontier checkpoints are kept at heights that are multiples of this: the
/// wallet's anchors lie there (`crate::px::ANCHOR_INTERVAL`).
pub const CHECKPOINT_INTERVAL: u64 = 16;

/// Commitments at the end of the backfill kept until the first commitment
/// of a scanned block is checked against them: a node that labels the
/// chain's first commitments after the restore height as older ones (so that
/// the wallet's tree runs ahead of the chain's) is caught there.
pub const BACKFILL_TAIL: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    /// The tree is full (`CAPACITY` leaves).
    Full,
    /// The node's data is inconsistent with the tree it implies.
    Inconsistent(String),
    /// The wallet's tree does not reach back far enough: rescan.
    NeedsRescan,
    /// No path: the leaf is not in the tree at the anchor, or no witness is
    /// held for it.
    NoPath(String),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::Full => write!(f, "the PX tree is full"),
            TreeError::Inconsistent(e) => write!(f, "{e}"),
            TreeError::NeedsRescan => write!(f, "the PX tree must be rebuilt by a rescan"),
            TreeError::NoPath(e) => write!(f, "no authentication path: {e}"),
        }
    }
}

/// The frontier of the consensus tree (`blacksilk_px::tree::Frontier`,
/// which consensus owns and this does not touch), reporting every subtree
/// an append completes, for the witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    branch: [Digest; TREE_DEPTH],
    /// The root once the tree is full (see `blacksilk_px::tree::Frontier`).
    full_root: Option<Digest>,
}

impl Default for Frontier {
    fn default() -> Self {
        Frontier {
            size: 0,
            branch: [ZERO_DIGEST; TREE_DEPTH],
            full_root: None,
        }
    }
}

impl Frontier {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends `leaf`; calls `done(level, index, root)` for every subtree the
    /// append completes, from the leaf itself (level 0) up. Returns the
    /// leaf's position.
    fn append(
        &mut self,
        perm: &mut HostPerm,
        leaf: Digest,
        mut done: impl FnMut(usize, u64, &Digest),
    ) -> Result<u64, TreeError> {
        if self.size >= CAPACITY {
            return Err(TreeError::Full);
        }
        let pos = self.size;
        let mut cur = leaf;
        for h in 0..TREE_DEPTH {
            // `cur` is the root of the complete subtree of level `h` that
            // ends at `pos`.
            done(h, pos >> h, &cur);
            if (pos >> h) & 1 == 0 {
                self.branch[h] = cur;
                break;
            }
            cur = node(perm, &self.branch[h], &cur);
        }
        if pos == CAPACITY - 1 {
            done(TREE_DEPTH, 0, &cur);
            self.full_root = Some(cur);
        }
        self.size += 1;
        Ok(pos)
    }

    /// The root of the subtree of level `level` that holds position `size`
    /// (the first empty leaf): the frontier's left nodes folded with empty
    /// subtrees on the right. At `TREE_DEPTH`, the tree's root.
    fn fold(&self, perm: &mut HostPerm, empty: &[Digest; TREE_DEPTH + 1], level: usize) -> Digest {
        if level == TREE_DEPTH {
            if let Some(full) = self.full_root {
                return full;
            }
        }
        let mut cur = ZERO_DIGEST;
        for (h, e) in empty.iter().enumerate().take(level) {
            cur = if (self.size >> h) & 1 == 1 {
                node(perm, &self.branch[h], &cur)
            } else {
                node(perm, &cur, e)
            };
        }
        cur
    }

    pub fn root(&self, perm: &mut HostPerm, empty: &[Digest; TREE_DEPTH + 1]) -> Digest {
        self.fold(perm, empty, TREE_DEPTH)
    }
}

/// The incremental witness of the leaf at `pos`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pos: u64,
    leaf: Digest,
    /// At every level where `pos` is a right child: the left sibling,
    /// complete when the leaf was appended.
    ommers: [Option<Digest>; TREE_DEPTH],
    /// At every level where `pos` is a left child: the right sibling, once
    /// the frontier completed it.
    fills: [Option<Digest>; TREE_DEPTH],
}

impl Witness {
    fn new(pos: u64, leaf: Digest, frontier: &Frontier) -> Self {
        let mut ommers = [None; TREE_DEPTH];
        for (h, o) in ommers.iter_mut().enumerate() {
            if (pos >> h) & 1 == 1 {
                *o = Some(frontier.branch[h]);
            }
        }
        Witness {
            pos,
            leaf,
            ommers,
            fills: [None; TREE_DEPTH],
        }
    }

    /// Records the completed subtree `(level, index)` if it is this leaf's
    /// right sibling.
    fn note(&mut self, level: usize, index: u64, root: &Digest) {
        if level < TREE_DEPTH && (self.pos >> level) & 1 == 0 && (self.pos >> level) + 1 == index {
            self.fills[level] = Some(*root);
        }
    }

    /// Forgets right siblings completed after the tree held `size` leaves.
    fn truncate(&mut self, size: u64) {
        for (h, f) in self.fills.iter_mut().enumerate() {
            let sibling = (self.pos >> h) + 1;
            if (sibling + 1) << h > size {
                *f = None;
            }
        }
    }

    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn leaf(&self) -> Digest {
        self.leaf
    }

    /// The authentication path in the tree whose frontier is `at` (the tree
    /// at an anchor).
    fn path(
        &self,
        perm: &mut HostPerm,
        empty: &[Digest; TREE_DEPTH + 1],
        at: &Frontier,
    ) -> Result<[Digest; TREE_DEPTH], TreeError> {
        let size = at.size;
        if self.pos >= size {
            return Err(TreeError::NoPath(format!(
                "leaf {} is not in the tree of {size} leaves at the anchor",
                self.pos
            )));
        }
        let mut path = [ZERO_DIGEST; TREE_DEPTH];
        for (h, s) in path.iter_mut().enumerate() {
            let index = self.pos >> h;
            *s = if index & 1 == 1 {
                self.ommers[h].ok_or_else(|| TreeError::NoPath("missing left sibling".into()))?
            } else {
                let sibling = index + 1;
                if (sibling + 1) << h <= size {
                    self.fills[h]
                        .ok_or_else(|| TreeError::NoPath("missing right sibling".into()))?
                } else if sibling << h < size {
                    // The one partially filled subtree: `size`'s own.
                    debug_assert_eq!(size >> h, sibling);
                    at.fold(perm, empty, h)
                } else {
                    empty[h]
                }
            };
        }
        Ok(path)
    }
}

/// A scanned block's commitments and the tree after it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockLog {
    height: u64,
    commitments: Vec<Digest>,
    root: Digest,
    size: u64,
}

/// The tree as of the end of the backfill (block `height`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Base {
    height: u64,
    frontier: Frontier,
    /// The root window at `height`: `(root, size)`, oldest first.
    window: Vec<(Digest, u64)>,
}

/// The wallet's PX tree (module docs).
#[derive(Clone, Debug)]
pub struct WalletTree {
    frontier: Frontier,
    /// The root window: `(root, tree size)` after each of the last
    /// `ROOT_WINDOW` blocks, oldest first; the last is after block `top`
    /// (the first may be the root before genesis).
    window: VecDeque<(Digest, u64)>,
    top: u64,
    base: Base,
    blocks: VecDeque<BlockLog>,
    /// The commitments of the block being appended.
    current: Vec<Digest>,
    checkpoints: BTreeMap<u64, Frontier>,
    witnesses: BTreeMap<u64, Witness>,
    /// The height of the block whose anchor bound the backfill to the chain
    /// (`Some(base height)` when there is no backfill).
    confirmed_at: Option<u64>,
    /// The end of the backfill, until the first scanned commitment is
    /// checked against it (`BACKFILL_TAIL`).
    tail: Vec<Digest>,
    empty: [Digest; TREE_DEPTH + 1],
}

impl PartialEq for WalletTree {
    fn eq(&self, o: &Self) -> bool {
        self.frontier == o.frontier
            && self.window == o.window
            && self.top == o.top
            && self.base == o.base
            && self.blocks == o.blocks
            && self.checkpoints == o.checkpoints
            && self.witnesses == o.witnesses
            && self.confirmed_at == o.confirmed_at
            && self.tail == o.tail
    }
}

impl WalletTree {
    /// The tree after block `height` from the chain's commitments up to it
    /// (`(block height, commitment)` in tree order, heights non-decreasing
    /// and at most `height`), with the root window those heights imply.
    /// `backfilled`: the list came from the node (it is bound to the chain
    /// later, `is_confirmed`); `false` only when it is known to be exact
    /// (no commitment exists below the first scanned block).
    pub fn new(
        height: u64,
        commitments: &[(u64, Digest)],
        backfilled: bool,
    ) -> Result<Self, TreeError> {
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        let mut frontier = Frontier::default();
        let mut window = VecDeque::from([(frontier.root(&mut perm, &empty), 0)]);
        let mut last = 0;
        for &(h, _) in commitments {
            if h < last || h > height {
                return Err(TreeError::Inconsistent(
                    "the commitment list is out of height order".into(),
                ));
            }
            last = h;
        }
        // Roots are computed only for the blocks the window holds.
        let first = height.saturating_sub(ROOT_WINDOW as u64 - 1);
        let mut i = 0;
        while i < commitments.len() && commitments[i].0 < first {
            frontier.append(&mut perm, commitments[i].1, |_, _, _| {})?;
            i += 1;
        }
        for h in first..=height {
            while i < commitments.len() && commitments[i].0 == h {
                frontier.append(&mut perm, commitments[i].1, |_, _, _| {})?;
                i += 1;
            }
            let root = match window.back() {
                Some(&(root, s)) if s == frontier.size => root,
                _ => frontier.root(&mut perm, &empty),
            };
            window.push_back((root, frontier.size));
            if window.len() > ROOT_WINDOW {
                window.pop_front();
            }
        }
        let tail_from = commitments.len().saturating_sub(BACKFILL_TAIL);
        Ok(WalletTree {
            base: Base {
                height,
                frontier: frontier.clone(),
                window: window.iter().copied().collect(),
            },
            checkpoints: BTreeMap::from([(height, frontier.clone())]),
            frontier,
            window,
            top: height,
            blocks: VecDeque::new(),
            current: Vec::new(),
            witnesses: BTreeMap::new(),
            confirmed_at: (!backfilled).then_some(height),
            tail: if backfilled {
                commitments[tail_from..].iter().map(|&(_, c)| c).collect()
            } else {
                Vec::new()
            },
            empty,
        })
    }

    /// Leaves in the tree.
    pub fn size(&self) -> u64 {
        self.frontier.size
    }

    /// The height of the last block appended (or of the backfill).
    pub fn height(&self) -> u64 {
        self.top
    }

    /// The height the backfill ends at: the tree cannot be rewound below it.
    pub fn base_height(&self) -> u64 {
        self.base.height
    }

    /// Leaves from the backfill.
    pub fn base_size(&self) -> u64 {
        self.base.frontier.size
    }

    /// Whether the backfill is bound to the chain (module docs).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }

    pub fn root(&self) -> Digest {
        self.window.back().expect("the window is never empty").0
    }

    /// Whether `anchor` is in the root window before the next block, as
    /// consensus requires of every PX transaction in it: `None` if not,
    /// else whether that root includes a commitment of a scanned block (a
    /// match then binds the backfill to the chain, [`Self::confirm`]).
    pub fn check_anchor(&self, anchor: &Digest) -> Option<bool> {
        let base = self.base_size();
        self.window
            .iter()
            .find(|(r, _)| r == anchor)
            .map(|&(_, size)| size > base)
    }

    /// Records that a PX transaction of block `height` anchored at a root
    /// that includes a scanned block's commitment (`check_anchor`): the
    /// backfill is the chain's exact list (module docs).
    pub fn confirm(&mut self, height: u64) {
        if self.confirmed_at.is_none() {
            self.confirmed_at = Some(height);
            self.tail.clear();
        }
    }

    /// The root and size of the tree after block `height`, if that is in the
    /// root window. (The window's oldest entry may be the root before
    /// genesis; it is never returned.)
    pub fn root_at(&self, height: u64) -> Option<(Digest, u64)> {
        let back = self.top.checked_sub(height)?;
        let i = (self.window.len() as u64).checked_sub(back + 1)?;
        Some(self.window[i as usize])
    }

    /// Appends a commitment of the block being scanned. The first one after
    /// the backfill must not be in the backfill's tail (`BACKFILL_TAIL`).
    pub fn append(&mut self, cm: Digest) -> Result<u64, TreeError> {
        if !self.tail.is_empty() {
            if self.tail.contains(&cm) {
                return Err(TreeError::Inconsistent(
                    "a scanned commitment is also in the node's list below the restore height"
                        .into(),
                ));
            }
            self.tail.clear();
        }
        let mut perm = HostPerm::new();
        let witnesses = &mut self.witnesses;
        let pos = self.frontier.append(&mut perm, cm, |level, index, root| {
            for w in witnesses.values_mut() {
                w.note(level, index, root);
            }
        })?;
        self.current.push(cm);
        Ok(pos)
    }

    /// Keeps a witness for the leaf just appended at `pos`.
    pub fn mark(&mut self, pos: u64) -> Result<(), TreeError> {
        if pos + 1 != self.frontier.size {
            return Err(TreeError::NoPath(
                "a witness starts with the last leaf appended".into(),
            ));
        }
        let leaf = *self.current.last().ok_or_else(|| {
            TreeError::NoPath("a witness starts with a leaf of the current block".into())
        })?;
        self.witnesses
            .entry(pos)
            .or_insert_with(|| Witness::new(pos, leaf, &self.frontier));
        Ok(())
    }

    /// Ends block `height` (the next one after `height()`): its root enters
    /// the window, and the block is logged for rewinds.
    pub fn end_block(&mut self, height: u64) -> Result<(), TreeError> {
        if height != self.top + 1 {
            return Err(TreeError::Inconsistent(format!(
                "block {height} does not follow the tree's block {}",
                self.top
            )));
        }
        let size = self.frontier.size;
        // A block without PX commitments leaves the root as it was (most
        // blocks): no hashing.
        let root = match self.window.back() {
            Some(&(root, s)) if s == size => root,
            _ => self.frontier.root(&mut HostPerm::new(), &self.empty),
        };
        self.window.push_back((root, size));
        if self.window.len() > ROOT_WINDOW {
            self.window.pop_front();
        }
        self.top = height;
        self.blocks.push_back(BlockLog {
            height,
            commitments: std::mem::take(&mut self.current),
            root,
            size,
        });
        if self.blocks.len() > KEPT_TREE_BLOCKS {
            self.blocks.pop_front();
        }
        if height.is_multiple_of(CHECKPOINT_INTERVAL) {
            self.checkpoints.insert(height, self.frontier.clone());
        }
        // Checkpoints below the kept blocks can no longer be replayed from.
        let oldest = self.blocks.front().map_or(height, |b| b.height);
        let base = self.base.height;
        self.checkpoints
            .retain(|&h, _| h == base || h + 1 >= oldest);
        Ok(())
    }

    /// Forgets the blocks above `height`. `NeedsRescan` if the tree does not
    /// reach back that far (below the backfill, or beyond the kept blocks):
    /// the caller then rescans.
    pub fn rewind(&mut self, height: u64) -> Result<(), TreeError> {
        if height >= self.top {
            return Ok(());
        }
        if height < self.base.height {
            return Err(TreeError::NeedsRescan);
        }
        let (&cp, frontier) = self
            .checkpoints
            .range(..=height)
            .next_back()
            .ok_or(TreeError::NeedsRescan)?;
        // Every block in (cp, height] must be logged, and the root window at
        // `height` must be rebuildable.
        let logged: Vec<&BlockLog> = self
            .blocks
            .iter()
            .filter(|b| b.height > self.base.height && b.height <= height)
            .collect();
        let first_logged = logged.first().map(|b| b.height);
        let contiguous = match first_logged {
            None => height == self.base.height,
            Some(f) => {
                f <= cp + 1 && logged.len() as u64 == height - f + 1 && {
                    // The window reaches back to the base or is covered.
                    f == self.base.height + 1 || logged.len() >= ROOT_WINDOW
                }
            }
        };
        if !contiguous {
            return Err(TreeError::NeedsRescan);
        }
        let mut perm = HostPerm::new();
        let mut f = frontier.clone();
        for b in logged.iter().filter(|b| b.height > cp) {
            for &cm in &b.commitments {
                f.append(&mut perm, cm, |_, _, _| {})?;
            }
        }
        let mut window: VecDeque<(Digest, u64)> = self.base.window.iter().copied().collect();
        for b in &logged {
            window.push_back((b.root, b.size));
            if window.len() > ROOT_WINDOW {
                window.pop_front();
            }
        }
        debug_assert_eq!(window.back().map(|w| w.1), Some(f.size));
        self.frontier = f;
        self.window = window;
        self.top = height;
        self.blocks.retain(|b| b.height <= height);
        self.checkpoints.retain(|&h, _| h <= height);
        self.current.clear();
        let size = self.frontier.size;
        self.witnesses.retain(|&p, _| p < size);
        for w in self.witnesses.values_mut() {
            w.truncate(size);
        }
        if self.confirmed_at.is_some_and(|c| c > height) {
            self.confirmed_at = None;
        }
        Ok(())
    }

    /// The authentication path of the witnessed leaf `pos` in the tree after
    /// block `anchor` (a multiple of `CHECKPOINT_INTERVAL`, or the backfill's
    /// height), with that tree's root. The path is checked against the root
    /// before it is returned.
    pub fn path(&self, pos: u64, anchor: u64) -> Result<([Digest; TREE_DEPTH], Digest), TreeError> {
        let at = self
            .checkpoints
            .get(&anchor)
            .ok_or_else(|| TreeError::NoPath(format!("no tree state kept at block {anchor}")))?;
        let w = self
            .witnesses
            .get(&pos)
            .ok_or_else(|| TreeError::NoPath(format!("no witness kept for leaf {pos}")))?;
        let mut perm = HostPerm::new();
        let path = w.path(&mut perm, &self.empty, at)?;
        let root = at.root(&mut perm, &self.empty);
        if blacksilk_px::tree::root_from_path(&mut perm, w.leaf, pos, &path) != root {
            return Err(TreeError::NoPath(
                "the witness does not verify against the wallet's root".into(),
            ));
        }
        Ok((path, root))
    }

    /// Keeps only the witnesses of the leaves `keep` accepts.
    pub fn retain_witnesses(&mut self, keep: impl Fn(u64) -> bool) {
        self.witnesses.retain(|&p, _| keep(p));
    }

    /// The height of the block holding leaf `pos`, if it is a scanned block
    /// still logged.
    pub fn height_of(&self, pos: u64) -> Option<u64> {
        self.blocks
            .iter()
            .find(|b| pos >= b.size - b.commitments.len() as u64 && pos < b.size)
            .map(|b| b.height)
    }

    /// A witness for the leaf `cm` of a scanned block the tree still logs
    /// (RTW3-15: an imported record is placed without asking the node for
    /// anything). The tree state is replayed from the last checkpoint below
    /// that block through the logged blocks, and must end at the tree's own
    /// frontier. Returns the leaf's position and block height, or `None` if
    /// `cm` is not in a logged block that can be replayed.
    pub fn witness_from_log(&mut self, cm: &Digest) -> Result<Option<(u64, u64)>, TreeError> {
        let Some((block, pos)) = self.blocks.iter().find_map(|b| {
            let first = b.size - b.commitments.len() as u64;
            b.commitments
                .iter()
                .position(|c| c == cm)
                .map(|i| (b.height, first + i as u64))
        }) else {
            return Ok(None);
        };
        if let Some(w) = self.witnesses.get(&pos) {
            return Ok((w.leaf == *cm).then_some((pos, block)));
        }
        let Some((&cp, frontier)) = self.checkpoints.range(..block).next_back() else {
            return Ok(None);
        };
        // Every block after the checkpoint must be logged.
        let replay: Vec<&BlockLog> = self.blocks.iter().filter(|b| b.height > cp).collect();
        if replay.first().map(|b| b.height) != Some(cp + 1)
            || replay.len() as u64 != self.top - cp
            || !self.current.is_empty()
        {
            return Ok(None);
        }
        let mut perm = HostPerm::new();
        let mut f = frontier.clone();
        let mut witness: Option<Witness> = None;
        for b in replay {
            for &c in &b.commitments {
                let at = f.append(&mut perm, c, |level, index, root| {
                    if let Some(w) = witness.as_mut() {
                        w.note(level, index, root);
                    }
                })?;
                if at == pos {
                    witness = Some(Witness::new(pos, c, &f));
                }
            }
        }
        if f != self.frontier {
            return Err(TreeError::Inconsistent(
                "the logged blocks do not replay to the wallet's tree".into(),
            ));
        }
        let w = witness.expect("the leaf is in a replayed block");
        self.witnesses.insert(pos, w);
        Ok(Some((pos, block)))
    }

    /// Witnesses for the leaves `positions` of the chain's commitment list
    /// `list` (every commitment, in tree order), after checking that its
    /// first `size()` entries give this tree's root: the list is then the
    /// chain's (collision resistance), and nothing of it is trusted.
    pub fn witness_from_list(
        &mut self,
        list: &[Digest],
        positions: &[u64],
    ) -> Result<(), TreeError> {
        let size = self.size() as usize;
        if list.len() < size {
            return Err(TreeError::Inconsistent(
                "the commitment list is shorter than the wallet's tree".into(),
            ));
        }
        let mut perm = HostPerm::new();
        let mut f = Frontier::default();
        let mut found: BTreeMap<u64, Witness> = BTreeMap::new();
        let wanted: HashSet<u64> = positions.iter().copied().collect();
        for (i, &cm) in list[..size].iter().enumerate() {
            let pos = f.append(&mut perm, cm, |level, index, root| {
                for w in found.values_mut() {
                    w.note(level, index, root);
                }
            })?;
            if wanted.contains(&pos) {
                found.insert(pos, Witness::new(pos, cm, &f));
            }
            debug_assert_eq!(pos, i as u64);
        }
        if f.root(&mut perm, &self.empty) != self.frontier.root(&mut perm, &self.empty) {
            return Err(TreeError::Inconsistent(
                "the commitment list does not give the wallet's PX root".into(),
            ));
        }
        for (p, w) in found {
            self.witnesses.entry(p).or_insert(w);
        }
        Ok(())
    }
}

// ---- persistence ----

fn hex_digest(d: &Digest) -> String {
    crate::px::digest_hex(d)
}

fn parse_digest(s: &str) -> Result<Digest, String> {
    crate::px::digest_from_hex(s).map_err(|e| e.to_string())
}

fn opt_digests(v: &[Option<Digest>; TREE_DEPTH]) -> Vec<Option<String>> {
    v.iter().map(|d| d.as_ref().map(hex_digest)).collect()
}

fn parse_opt_digests(v: &[Option<String>]) -> Result<[Option<Digest>; TREE_DEPTH], String> {
    if v.len() != TREE_DEPTH {
        return Err("witness depth".into());
    }
    let mut out = [None; TREE_DEPTH];
    for (o, s) in out.iter_mut().zip(v) {
        *o = s.as_deref().map(parse_digest).transpose()?;
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
struct FrontierFile {
    size: u64,
    branch: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    full_root: Option<String>,
}

impl FrontierFile {
    fn of(f: &Frontier) -> Self {
        // Only the levels below the size's highest bit hold anything.
        let used = (u64::BITS - f.size.leading_zeros()) as usize;
        FrontierFile {
            size: f.size,
            branch: f.branch[..used.min(TREE_DEPTH)]
                .iter()
                .map(hex_digest)
                .collect(),
            full_root: f.full_root.as_ref().map(hex_digest),
        }
    }

    fn load(&self) -> Result<Frontier, String> {
        if self.size > CAPACITY || self.branch.len() > TREE_DEPTH {
            return Err("frontier size".into());
        }
        let mut branch = [ZERO_DIGEST; TREE_DEPTH];
        for (b, s) in branch.iter_mut().zip(&self.branch) {
            *b = parse_digest(s)?;
        }
        Ok(Frontier {
            size: self.size,
            branch,
            full_root: self.full_root.as_deref().map(parse_digest).transpose()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct WitnessFile {
    pos: u64,
    leaf: String,
    ommers: Vec<Option<String>>,
    fills: Vec<Option<String>>,
}

#[derive(Serialize, Deserialize)]
struct BlockFile {
    height: u64,
    commitments: Vec<String>,
    root: String,
    size: u64,
}

/// The persisted tree (hex digests).
#[derive(Serialize, Deserialize)]
pub struct TreeFile {
    frontier: FrontierFile,
    window: Vec<(String, u64)>,
    top: u64,
    base_height: u64,
    base_frontier: FrontierFile,
    base_window: Vec<(String, u64)>,
    blocks: Vec<BlockFile>,
    checkpoints: Vec<(u64, FrontierFile)>,
    witnesses: Vec<WitnessFile>,
    confirmed_at: Option<u64>,
    #[serde(default)]
    tail: Vec<String>,
}

fn window_file(w: impl Iterator<Item = (Digest, u64)>) -> Vec<(String, u64)> {
    w.map(|(d, s)| (hex_digest(&d), s)).collect()
}

fn parse_window(w: &[(String, u64)]) -> Result<Vec<(Digest, u64)>, String> {
    if w.is_empty() || w.len() > ROOT_WINDOW {
        return Err("root window length".into());
    }
    w.iter().map(|(d, s)| Ok((parse_digest(d)?, *s))).collect()
}

impl Serialize for WalletTree {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        TreeFile {
            frontier: FrontierFile::of(&self.frontier),
            window: window_file(self.window.iter().copied()),
            top: self.top,
            base_height: self.base.height,
            base_frontier: FrontierFile::of(&self.base.frontier),
            base_window: window_file(self.base.window.iter().copied()),
            blocks: self
                .blocks
                .iter()
                .map(|b| BlockFile {
                    height: b.height,
                    commitments: b.commitments.iter().map(hex_digest).collect(),
                    root: hex_digest(&b.root),
                    size: b.size,
                })
                .collect(),
            checkpoints: self
                .checkpoints
                .iter()
                .map(|(h, f)| (*h, FrontierFile::of(f)))
                .collect(),
            witnesses: self
                .witnesses
                .values()
                .map(|w| WitnessFile {
                    pos: w.pos,
                    leaf: hex_digest(&w.leaf),
                    ommers: opt_digests(&w.ommers),
                    fills: opt_digests(&w.fills),
                })
                .collect(),
            confirmed_at: self.confirmed_at,
            tail: self.tail.iter().map(hex_digest).collect(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for WalletTree {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let f = TreeFile::deserialize(d)?;
        WalletTree::load(f).map_err(D::Error::custom)
    }
}

impl WalletTree {
    fn load(f: TreeFile) -> Result<Self, String> {
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        let frontier = f.frontier.load()?;
        let window: VecDeque<(Digest, u64)> = parse_window(&f.window)?.into();
        let base = Base {
            height: f.base_height,
            frontier: f.base_frontier.load()?,
            window: parse_window(&f.base_window)?,
        };
        let blocks = f
            .blocks
            .iter()
            .map(|b| {
                Ok(BlockLog {
                    height: b.height,
                    commitments: b
                        .commitments
                        .iter()
                        .map(|c| parse_digest(c))
                        .collect::<Result<_, String>>()?,
                    root: parse_digest(&b.root)?,
                    size: b.size,
                })
            })
            .collect::<Result<VecDeque<_>, String>>()?;
        let checkpoints = f
            .checkpoints
            .iter()
            .map(|(h, c)| Ok((*h, c.load()?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let witnesses = f
            .witnesses
            .iter()
            .map(|w| {
                Ok((
                    w.pos,
                    Witness {
                        pos: w.pos,
                        leaf: parse_digest(&w.leaf)?,
                        ommers: parse_opt_digests(&w.ommers)?,
                        fills: parse_opt_digests(&w.fills)?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let tail = f
            .tail
            .iter()
            .map(|c| parse_digest(c))
            .collect::<Result<_, _>>()?;
        let t = WalletTree {
            frontier,
            window,
            top: f.top,
            base,
            blocks,
            current: Vec::new(),
            checkpoints,
            witnesses,
            confirmed_at: f.confirmed_at,
            tail,
            empty,
        };
        // The stored frontier must give the stored root: a damaged file is
        // refused rather than used to anchor spends.
        if t.frontier.root(&mut perm, &t.empty) != t.root()
            || t.window.back().map(|w| w.1) != Some(t.frontier.size)
        {
            return Err("the stored PX tree is inconsistent".into());
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    //! The wallet's tree against the consensus references: the full tree
    //! (`blacksilk_px::tree::Tree`, paths) and the PX state
    //! (`blacksilk_px::state::State`, the root window), on seeded random
    //! chains.

    use super::*;
    use blacksilk_px::state::State;
    use blacksilk_px::tree::Tree;
    use blacksilk_px_core::kernel::Public;
    use blacksilk_px_core::P;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn digest(rng: &mut ChaCha20Rng) -> Digest {
        let mut d = [0u32; 8];
        for x in d.iter_mut() {
            *x = rng.next_u32() % P;
        }
        d
    }

    /// A random chain of `blocks` blocks: each appends 0 to 4 leaves; a
    /// fifth of the leaves are witnessed. Returns the tree, the reference
    /// tree's root after every block, and every leaf.
    fn random_chain(
        rng: &mut ChaCha20Rng,
        blocks: u64,
    ) -> (WalletTree, Vec<Digest>, Vec<Digest>, Vec<u64>) {
        let mut perm = HostPerm::new();
        let mut reference = Tree::new(&mut perm);
        let mut t = WalletTree::new(0, &[], false).unwrap();
        let mut roots = vec![reference.root()];
        let mut leaves = Vec::new();
        let mut sizes = vec![0];
        for h in 1..=blocks {
            for _ in 0..rng.next_u32() % 5 {
                let leaf = digest(rng);
                let pos = t.append(leaf).unwrap();
                assert_eq!(reference.append(&mut perm, leaf).unwrap(), pos);
                if rng.next_u32().is_multiple_of(5) {
                    t.mark(pos).unwrap();
                }
                leaves.push(leaf);
            }
            t.end_block(h).unwrap();
            roots.push(reference.root());
            sizes.push(reference.size());
            assert_eq!(t.root(), reference.root(), "block {h}");
        }
        (t, roots, leaves, sizes)
    }

    /// Every witnessed leaf's path at every kept anchor equals the reference
    /// tree's path at that size, and verifies against the root there.
    #[test]
    fn witness_paths_equal_the_reference_trees() {
        let mut perm = HostPerm::new();
        for seed in 0..12u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (t, roots, leaves, sizes) = random_chain(&mut rng, 150);
            let mut checked = 0;
            for anchor in (0..=150u64).step_by(CHECKPOINT_INTERVAL as usize) {
                let size = sizes[anchor as usize];
                let mut reference = Tree::new(&mut perm);
                for &l in &leaves[..size as usize] {
                    reference.append(&mut perm, l).unwrap();
                }
                assert_eq!(reference.root(), roots[anchor as usize]);
                for &pos in t.witnesses.keys() {
                    match t.path(pos, anchor) {
                        Ok((path, root)) => {
                            assert!(pos < size);
                            assert_eq!(root, roots[anchor as usize]);
                            assert_eq!(Some(path), reference.path(pos), "{seed} {anchor} {pos}");
                            checked += 1;
                        }
                        Err(_) => assert!(pos >= size, "{seed} {anchor} {pos}"),
                    }
                }
            }
            assert!(checked > 50, "{checked}");
        }
    }

    /// The root window is the consensus state's: for random chains of PX
    /// transfers whose anchors are drawn from every root so far (recent or
    /// evicted) or at random, the wallet accepts exactly the anchors
    /// consensus accepts, across window eviction.
    #[test]
    fn the_root_window_is_the_consensus_states() {
        for seed in 0..4u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(100 + seed);
            let mut state = State::new();
            let mut t = WalletTree::new(0, &[], false).unwrap();
            // The genesis block: no transfer.
            state.apply_block(&[]).unwrap();
            let mut history = vec![state.root()];
            for h in 1..=260u64 {
                let mut transfers = Vec::new();
                for _ in 0..rng.next_u32() % 3 {
                    let anchor = match rng.next_u32() % 4 {
                        0 => digest(&mut rng),
                        _ => history[(rng.next_u64() % history.len() as u64) as usize],
                    };
                    let accepted = state.is_recent_root(&anchor);
                    assert_eq!(t.check_anchor(&anchor).is_some(), accepted, "{seed} {h}");
                    if accepted {
                        transfers.push(Public {
                            anchor,
                            nullifiers: [digest(&mut rng), digest(&mut rng)],
                            commitments: [digest(&mut rng), digest(&mut rng)],
                            bridge_in: 0,
                            bridge_out: 0,
                            n_fn: 0,
                            functions: Default::default(),
                        });
                    }
                }
                state.apply_block(&transfers).unwrap();
                for p in &transfers {
                    for cm in p.commitments {
                        t.append(cm).unwrap();
                    }
                }
                t.end_block(h).unwrap();
                assert_eq!(t.root(), state.root());
                history.push(state.root());
            }
        }
    }

    /// A rewind within the kept blocks gives exactly the tree built to that
    /// height; beyond them it asks for a rescan.
    #[test]
    fn a_rewind_equals_building_to_that_height() {
        for seed in 0..6u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(200 + seed);
            let (full, ..) = random_chain(&mut rng, 300);
            for depth in [0u64, 1, 2, 3, 15, 16, 17, 99, 100, 101, 250, 299] {
                let height = 300 - depth;
                let mut r = full.clone();
                r.rewind(height).unwrap();
                // The same chain, stopped at `height`.
                let mut rng = ChaCha20Rng::seed_from_u64(200 + seed);
                let (short, _) = random_chain_to(&mut rng, 300, height);
                assert_eq!(r, short, "{seed}: rewound by {depth}");
            }
        }
        // Beyond the kept blocks.
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (mut long, ..) = random_chain(&mut rng, 900);
        let mut deep = long.clone();
        assert_eq!(deep.rewind(900 - 720), Ok(()));
        assert_eq!(long.rewind(900 - 830), Err(TreeError::NeedsRescan));
    }

    /// `random_chain` of `blocks` blocks, stopped after block `stop` (the
    /// same draws up to there).
    fn random_chain_to(rng: &mut ChaCha20Rng, blocks: u64, stop: u64) -> (WalletTree, Vec<Digest>) {
        let mut t = WalletTree::new(0, &[], false).unwrap();
        let mut leaves = Vec::new();
        for h in 1..=blocks.min(stop) {
            for _ in 0..rng.next_u32() % 5 {
                let leaf = digest(rng);
                let pos = t.append(leaf).unwrap();
                if rng.next_u32().is_multiple_of(5) {
                    t.mark(pos).unwrap();
                }
                leaves.push(leaf);
            }
            t.end_block(h).unwrap();
        }
        (t, leaves)
    }

    /// A tree from a backfill (a list with heights) has the roots and the
    /// root window of the tree scanned block by block from the genesis.
    #[test]
    fn a_backfill_gives_the_scanned_trees_window() {
        for (seed, base) in [(1u64, 5u64), (2, 98), (3, 99), (4, 100), (5, 240)] {
            let mut rng = ChaCha20Rng::seed_from_u64(300 + seed);
            let mut scanned = WalletTree::new(0, &[], false).unwrap();
            let mut list = Vec::new();
            for h in 1..=base {
                for _ in 0..rng.next_u32() % 3 {
                    let leaf = digest(&mut rng);
                    scanned.append(leaf).unwrap();
                    list.push((h, leaf));
                }
                scanned.end_block(h).unwrap();
            }
            let backfilled = WalletTree::new(base, &list, true).unwrap();
            assert_eq!(backfilled.window, scanned.window, "base {base}");
            assert_eq!(backfilled.frontier, scanned.frontier);
            assert!(!backfilled.is_confirmed() && scanned.is_confirmed());
            // Out of height order, or above the base: refused.
            let mut bad = list.clone();
            bad.push((base + 1, digest(&mut rng)));
            assert!(WalletTree::new(base, &bad, true).is_err());
        }
    }

    /// Witnesses from the chain's whole list are built only if the list
    /// gives the tree's root, and equal the reference paths.
    #[test]
    fn witnesses_from_a_list_are_checked_against_the_root() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let (mut t, _, leaves, _) = random_chain(&mut rng, 64);
        let mut tampered = leaves.clone();
        tampered[3] = digest(&mut rng);
        assert!(t.witness_from_list(&tampered, &[3]).is_err());
        assert!(t
            .witness_from_list(&leaves[..leaves.len() - 1], &[3])
            .is_err());
        t.witness_from_list(&leaves, &[3, 10]).unwrap();
        let mut perm = HostPerm::new();
        let mut reference = Tree::new(&mut perm);
        for &l in &leaves {
            reference.append(&mut perm, l).unwrap();
        }
        let (path, _) = t.path(3, 64).unwrap();
        assert_eq!(Some(path), reference.path(3));
        // Later appends keep it current.
        for h in 65..=80 {
            let leaf = digest(&mut rng);
            t.append(leaf).unwrap();
            reference.append(&mut perm, leaf).unwrap();
            t.end_block(h).unwrap();
        }
        let (path, root) = t.path(10, 80).unwrap();
        assert_eq!((Some(path), root), (reference.path(10), reference.root()));
    }

    /// The tree survives serialization exactly; a stored window that does
    /// not end with the frontier's root is refused.
    #[test]
    fn the_tree_round_trips_and_a_damaged_one_is_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let (t, ..) = random_chain(&mut rng, 130);
        let json = serde_json::to_string(&t).unwrap();
        let back: WalletTree = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["frontier"]["size"] = (t.size() + 1).into();
        assert!(serde_json::from_value::<WalletTree>(v).is_err());
    }
}
