//! The output Merkle mountain range (docs/consensus.md §7.1; rule B-OMR,
//! docs/blocks.md §5).
//!
//! Every block header commits to the v1 output set of its chain: the number of
//! outputs through the block (`output_count`) and the root of a Merkle mountain
//! range (MMR) over them in global-index order (`output_root`). With the
//! header chain alone, anyone holding a list of outputs can check that it is
//! the chain's exact list (position, key, commitment, height, coinbase flag).
//!
//! ```text
//! leaf(o)     = H32("output-mmr/leaf", one_time_key ‖ commitment ‖ LE64(height) ‖ u8(coinbase))
//! node(l, r)  = H32("output-mmr/node", l ‖ r)
//! peaks(n)    = the roots of the perfect subtrees of the binary decomposition of n,
//!               largest (oldest) first
//! root(0)     = 32 zero bytes
//! root(n)     = H32("output-mmr/root", LE64(n) ‖ peaks(n)[0] ‖ … ‖ peaks(n)[k−1])
//! ```
//!
//! Appending leaf number `c` (0-based) pushes it as a new peak, then merges the
//! two rightmost peaks `trailing_ones(c)` times (`node(left, right)`). Hashes
//! are domain-separated (`blacksilk_crypto::hash`), so a leaf, a node and a root
//! can never be confused; the root binds `n`, which fixes the number and heights
//! of the peaks.
//!
//! - [`OutputFrontier`]: the peaks and the count, what block validation and a
//!   miner need to extend the range by one block (at most 64 hashes).
//! - [`OutputMmr`]: every node, for the node's state ([`crate::state::MemoryChain`]):
//!   it gives the frontier after any earlier block, so reorganizations and
//!   templates on side branches need no recomputation.

use crate::types::{Hash, Transaction};
use blacksilk_crypto::hash::{h32, tags};

/// `leaf(o)`: the hash of one output record.
pub fn leaf(one_time_key: &[u8; 32], commitment: &[u8; 32], height: u64, coinbase: bool) -> Hash {
    h32(
        tags::OUTPUT_MMR_LEAF,
        &[
            one_time_key,
            commitment,
            &height.to_le_bytes(),
            &[u8::from(coinbase)],
        ],
    )
}

/// `node(l, r)`.
pub fn node(l: &Hash, r: &Hash) -> Hash {
    h32(tags::OUTPUT_MMR_NODE, &[l, r])
}

/// `root(n)` from the peaks of `n` leaves (largest first).
fn bag(count: u64, peaks: &[Hash]) -> Hash {
    if count == 0 {
        return [0; 32];
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(peaks.len() + 1);
    let n = count.to_le_bytes();
    parts.push(&n);
    parts.extend(peaks.iter().map(|p| p.as_slice()));
    h32(tags::OUTPUT_MMR_ROOT, &parts)
}

/// The number of nodes of an MMR of `n` leaves: `2n − popcount(n)`.
pub fn mmr_size(n: u64) -> u64 {
    2 * n - u64::from(n.count_ones())
}

/// The leaf hashes of a block's outputs, in block order (coinbase first): the
/// order of their global indices.
pub fn block_leaves(height: u64, txs: &[Transaction]) -> impl Iterator<Item = Hash> + '_ {
    txs.iter().flat_map(move |tx| {
        let coinbase = tx.is_coinbase();
        tx.output_keys().into_iter().map(move |k| {
            leaf(
                k.one_time_key.bytes(),
                k.commitment.bytes(),
                height,
                coinbase,
            )
        })
    })
}

/// The right edge of the range: the count and the peaks (largest first).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputFrontier {
    count: u64,
    peaks: Vec<Hash>,
}

impl OutputFrontier {
    /// The empty range (the genesis state).
    pub fn new() -> Self {
        Self::default()
    }

    /// A frontier from its parts (a template): `None` unless there is one
    /// peak per set bit of `count`.
    pub fn from_parts(count: u64, peaks: Vec<Hash>) -> Option<Self> {
        (peaks.len() == count.count_ones() as usize).then_some(Self { count, peaks })
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn peaks(&self) -> &[Hash] {
        &self.peaks
    }

    /// Appends one leaf hash.
    pub fn push(&mut self, leaf: Hash) {
        let merges = self.count.trailing_ones();
        self.peaks.push(leaf);
        for _ in 0..merges {
            let r = self.peaks.pop().expect("a peak per merge");
            let l = self.peaks.pop().expect("a peak per merge");
            self.peaks.push(node(&l, &r));
        }
        // A count is a number of outputs that exist: it cannot reach 2^64.
        self.count = self.count.checked_add(1).expect("fewer than 2^64 outputs");
    }

    /// Appends the outputs of block `height` (all its transactions, coinbase
    /// first).
    pub fn append_block(&mut self, height: u64, txs: &[Transaction]) {
        for l in block_leaves(height, txs) {
            self.push(l);
        }
    }

    /// `root(count)`.
    pub fn root(&self) -> Hash {
        bag(self.count, &self.peaks)
    }
}

/// Every node of the range, in append order (post-order), for the node's
/// state: the frontier after any earlier count is a lookup.
#[derive(Clone, Debug, Default)]
pub struct OutputMmr {
    count: u64,
    nodes: Vec<Hash>,
}

impl OutputMmr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Appends one leaf hash.
    pub fn push(&mut self, leaf: Hash) {
        let merges = self.count.trailing_ones();
        self.nodes.push(leaf);
        for k in 0..merges {
            let last = self.nodes.len() - 1;
            // The left sibling of the subtree of height k ending at `last`.
            let left = self.nodes[last - ((1usize << (k + 1)) - 1)];
            let parent = node(&left, &self.nodes[last]);
            self.nodes.push(parent);
        }
        self.count = self.count.checked_add(1).expect("fewer than 2^64 outputs");
        debug_assert_eq!(self.nodes.len() as u64, mmr_size(self.count));
    }

    /// Drops every leaf from `count` on (undo); no-op if there are fewer.
    pub fn truncate(&mut self, count: u64) {
        if count < self.count {
            self.nodes.truncate(mmr_size(count) as usize);
            self.count = count;
        }
    }

    /// The frontier after the first `count` leaves; `None` past the end.
    pub fn frontier_at(&self, count: u64) -> Option<OutputFrontier> {
        if count > self.count {
            return None;
        }
        let mut peaks = Vec::with_capacity(count.count_ones() as usize);
        let mut offset = 0u64;
        for h in (0..64).rev() {
            if (count >> h) & 1 == 1 {
                let size = (1u64 << (h + 1)) - 1;
                peaks.push(self.nodes[(offset + size - 1) as usize]);
                offset += size;
            }
        }
        Some(OutputFrontier { count, peaks })
    }

    /// The frontier of the whole range.
    pub fn frontier(&self) -> OutputFrontier {
        self.frontier_at(self.count).expect("count is in range")
    }

    pub fn root(&self) -> Hash {
        self.frontier().root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(i: u64) -> Hash {
        leaf(
            &[i as u8; 32],
            &[(i >> 8) as u8; 32],
            i,
            i.is_multiple_of(3),
        )
    }

    /// The recursive definition, written independently of the incremental
    /// algorithms: peaks of the largest power of two first.
    fn reference_root(leaves: &[Hash]) -> Hash {
        fn tree(xs: &[Hash]) -> Hash {
            if xs.len() == 1 {
                return xs[0];
            }
            let half = xs.len() / 2;
            node(&tree(&xs[..half]), &tree(&xs[half..]))
        }
        let n = leaves.len() as u64;
        let mut peaks = Vec::new();
        let mut at = 0usize;
        for h in (0..64).rev() {
            if (n >> h) & 1 == 1 {
                let size = 1usize << h;
                peaks.push(tree(&leaves[at..at + size]));
                at += size;
            }
        }
        bag(n, &peaks)
    }

    #[test]
    fn the_empty_range_has_the_zero_root() {
        assert_eq!(OutputFrontier::new().root(), [0; 32]);
        assert_eq!(OutputMmr::new().root(), [0; 32]);
        assert_eq!(OutputFrontier::new().count(), 0);
    }

    #[test]
    fn small_shapes() {
        let mut f = OutputFrontier::new();
        f.push(l(0));
        assert_eq!(f.peaks(), &[l(0)]);
        assert_eq!(
            f.root(),
            h32(tags::OUTPUT_MMR_ROOT, &[&1u64.to_le_bytes(), &l(0)])
        );
        f.push(l(1));
        assert_eq!(f.peaks(), &[node(&l(0), &l(1))]);
        f.push(l(2));
        assert_eq!(f.peaks(), &[node(&l(0), &l(1)), l(2)]);
        f.push(l(3));
        let four = node(&node(&l(0), &l(1)), &node(&l(2), &l(3)));
        assert_eq!(f.peaks(), &[four]);
        assert_eq!(
            f.root(),
            h32(tags::OUTPUT_MMR_ROOT, &[&4u64.to_le_bytes(), &four])
        );
    }

    /// The frontier, the full range (at every earlier count too) and the
    /// recursive definition agree for every size up to 300.
    #[test]
    fn frontier_full_range_and_definition_agree() {
        let leaves: Vec<Hash> = (0..300).map(l).collect();
        let mut f = OutputFrontier::new();
        let mut m = OutputMmr::new();
        for n in 0..=leaves.len() {
            assert_eq!(f.root(), reference_root(&leaves[..n]), "{n}");
            assert_eq!(m.frontier(), f, "{n}");
            assert_eq!(f.peaks().len(), (n as u64).count_ones() as usize);
            if n < leaves.len() {
                f.push(leaves[n]);
                m.push(leaves[n]);
            }
        }
        for n in 0..=300u64 {
            assert_eq!(
                m.frontier_at(n).unwrap().root(),
                reference_root(&leaves[..n as usize])
            );
        }
        assert_eq!(m.frontier_at(301), None);
    }

    /// Undo: truncating to an earlier count gives that count's range, and
    /// appending again gives the same range as never undoing.
    #[test]
    fn truncate_then_append_equals_the_original() {
        let mut m = OutputMmr::new();
        for i in 0..100 {
            m.push(l(i));
        }
        let at = |k: u64| {
            let mut x = OutputMmr::new();
            for i in 0..k {
                x.push(l(i));
            }
            x
        };
        for k in [0, 1, 2, 3, 7, 8, 9, 63, 64, 65, 99, 100] {
            let mut t = m.clone();
            t.truncate(k);
            assert_eq!(t.count(), k);
            assert_eq!(t.nodes, at(k).nodes, "{k}");
            for i in k..100 {
                t.push(l(i));
            }
            assert_eq!(t.nodes, m.nodes, "{k}");
        }
        let mut t = m.clone();
        t.truncate(1_000);
        assert_eq!(t.count(), 100);
    }

    /// The root binds the count and the order: a prefix, a reordering and a
    /// changed field each give another root.
    #[test]
    fn the_root_binds_count_order_and_fields() {
        let root = |xs: &[Hash]| {
            let mut f = OutputFrontier::new();
            xs.iter().for_each(|x| f.push(*x));
            f.root()
        };
        let base: Vec<Hash> = (0..5).map(l).collect();
        let r = root(&base);
        assert_ne!(r, root(&base[..4]));
        let mut swapped = base.clone();
        swapped.swap(1, 2);
        assert_ne!(r, root(&swapped));
        // A single "leaf" equal to an inner node does not reproduce a root.
        assert_ne!(root(&[node(&l(0), &l(1))]), root(&base[..2]));
        // Each leaf field.
        let k = [1; 32];
        let c = [2; 32];
        let x = leaf(&k, &c, 5, false);
        assert_ne!(x, leaf(&[3; 32], &c, 5, false));
        assert_ne!(x, leaf(&k, &[3; 32], 5, false));
        assert_ne!(x, leaf(&k, &c, 6, false));
        assert_ne!(x, leaf(&k, &c, 5, true));
    }

    #[test]
    fn from_parts_needs_one_peak_per_bit() {
        let mut f = OutputFrontier::new();
        for i in 0..11 {
            f.push(l(i));
        }
        let peaks = f.peaks().to_vec();
        assert_eq!(peaks.len(), 3);
        assert_eq!(OutputFrontier::from_parts(11, peaks.clone()), Some(f));
        assert_eq!(OutputFrontier::from_parts(12, peaks.clone()), None);
        assert_eq!(OutputFrontier::from_parts(11, peaks[..2].to_vec()), None);
        assert_eq!(
            OutputFrontier::from_parts(0, vec![]),
            Some(OutputFrontier::new())
        );
    }

    #[test]
    fn sizes() {
        let mut m = OutputMmr::new();
        for n in 0..200u64 {
            assert_eq!(m.nodes.len() as u64, mmr_size(n));
            m.push(l(n));
        }
        assert_eq!(mmr_size(0), 0);
        assert_eq!(mmr_size(1), 1);
        assert_eq!(mmr_size(2), 3);
        assert_eq!(mmr_size(4), 7);
    }
}
