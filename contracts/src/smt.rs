//! Sparse Merkle tree over 256-bit paths (docs/contracts.md §10.2).
//!
//! ```text
//! empty subtree                    = 0^32
//! subtree with exactly one leaf    = H32("contract/state-node", 0x01 ‖ path ‖ leaf)
//! subtree with two or more leaves  = H32("contract/state-node", 0x00 ‖ left ‖ right)
//! ```
//!
//! Paths are hashes (bit 0 = most significant bit of byte 0), so a single leaf
//! is placed at the top of its otherwise-empty subtree and carries its full path.
//! This is the "shortcut" sparse tree used by Diem's Jellyfish tree. Updates
//! are O(depth of the path's branch points).
//!
//! Hashes of branch subtrees are cached and invalidated along a changed path,
//! so the root after a few updates costs a few hundred hashes, not a full recomputation.

use blacksilk_crypto::hash::{h32, tags};
use std::collections::{BTreeMap, HashMap};

pub type Hash = [u8; 32];
pub const EMPTY: Hash = [0; 32];

#[derive(Default, Clone)]
pub struct Smt {
    leaves: BTreeMap<Hash, Hash>,
    cache: HashMap<(u16, Hash), Hash>,
}

fn bit(path: &Hash, depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
}

/// `path` with every bit at position ≥ `depth` cleared.
fn prefix(path: &Hash, depth: usize) -> Hash {
    let mut p = *path;
    for (i, byte) in p.iter_mut().enumerate() {
        let start = i * 8;
        if start >= depth {
            *byte = 0;
        } else if start + 8 > depth {
            *byte &= 0xffu8 << (8 - (depth - start));
        }
    }
    p
}

/// The largest path with the given `depth`-bit prefix.
fn upper(prefix: &Hash, depth: usize) -> Hash {
    let mut p = *prefix;
    for (i, byte) in p.iter_mut().enumerate() {
        let start = i * 8;
        if start >= depth {
            *byte = 0xff;
        } else if start + 8 > depth {
            *byte |= 0xffu8 >> (depth - start);
        }
    }
    p
}

fn with_bit(prefix: &Hash, depth: usize) -> Hash {
    let mut p = *prefix;
    p[depth / 8] |= 0x80 >> (depth % 8);
    p
}

pub fn leaf_node(path: &Hash, leaf: &Hash) -> Hash {
    h32(tags::CONTRACT_STATE_NODE, &[&[1], path, leaf])
}

pub fn branch_node(left: &Hash, right: &Hash) -> Hash {
    h32(tags::CONTRACT_STATE_NODE, &[&[0], left, right])
}

impl Smt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, path: &Hash) -> Option<&Hash> {
        self.leaves.get(path)
    }

    /// Sets (`Some`) or removes (`None`) the leaf at `path`.
    pub fn update(&mut self, path: Hash, leaf: Option<Hash>) {
        let changed = match leaf {
            Some(l) => self.leaves.insert(path, l) != Some(l),
            None => self.leaves.remove(&path).is_some(),
        };
        if changed {
            for d in 0..256 {
                self.cache.remove(&(d as u16, prefix(&path, d)));
            }
        }
    }

    pub fn root(&mut self) -> Hash {
        self.node(0, [0; 32])
    }

    fn node(&mut self, depth: usize, pre: Hash) -> Hash {
        if let Some(h) = self.cache.get(&(depth as u16, pre)) {
            return *h;
        }
        let mut range = self.leaves.range(pre..=upper(&pre, depth));
        let Some((first_path, first_leaf)) = range.next() else {
            return EMPTY;
        };
        if range.next().is_none() {
            return leaf_node(first_path, first_leaf);
        }
        // Two or more leaves share this prefix; paths are distinct, so depth < 256.
        let left = self.node(depth + 1, pre);
        let right = self.node(depth + 1, with_bit(&pre, depth));
        let h = branch_node(&left, &right);
        self.cache.insert((depth as u16, pre), h);
        h
    }
}

/// Reference implementation: recomputes the root from scratch, recursively
/// splitting the sorted leaves by bit. Used by tests to check the cached tree.
pub fn reference_root(leaves: &[(Hash, Hash)]) -> Hash {
    fn go(leaves: &[(Hash, Hash)], depth: usize) -> Hash {
        match leaves {
            [] => EMPTY,
            [(p, l)] => leaf_node(p, l),
            _ => {
                let split = leaves.partition_point(|(p, _)| !bit(p, depth));
                branch_node(
                    &go(&leaves[..split], depth + 1),
                    &go(&leaves[split..], depth + 1),
                )
            }
        }
    }
    let mut sorted = leaves.to_vec();
    sorted.sort();
    go(&sorted, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u64) -> Hash {
        h32(tags::MASK, &[&i.to_le_bytes()])
    }

    #[test]
    fn empty_and_single_leaf() {
        let mut t = Smt::new();
        assert_eq!(t.root(), EMPTY);
        t.update(h(1), Some(h(100)));
        assert_eq!(t.root(), leaf_node(&h(1), &h(100)));
        t.update(h(1), None);
        assert_eq!(t.root(), EMPTY);
    }

    #[test]
    fn matches_reference_under_random_updates() {
        let mut t = Smt::new();
        let mut model: BTreeMap<Hash, Hash> = BTreeMap::new();
        for step in 0..600u64 {
            let key = h(step % 97);
            if step % 5 == 0 {
                t.update(key, None);
                model.remove(&key);
            } else {
                t.update(key, Some(h(step + 10_000)));
                model.insert(key, h(step + 10_000));
            }
            if step % 37 == 0 || step == 599 {
                let pairs: Vec<_> = model.iter().map(|(k, v)| (*k, *v)).collect();
                assert_eq!(t.root(), reference_root(&pairs), "step {step}");
            }
        }
        assert_eq!(t.len(), model.len());
    }

    #[test]
    fn order_of_insertion_does_not_matter() {
        let mut a = Smt::new();
        let mut b = Smt::new();
        for i in 0..50 {
            a.update(h(i), Some(h(i + 1)));
        }
        for i in (0..50).rev() {
            b.update(h(i), Some(h(i + 1)));
        }
        assert_eq!(a.root(), b.root());
        // Changing any single leaf changes the root; restoring it restores the root.
        let before = a.root();
        a.update(h(17), Some(h(999)));
        assert_ne!(a.root(), before);
        a.update(h(17), Some(h(18)));
        assert_eq!(a.root(), before);
    }

    #[test]
    fn adjacent_paths_are_handled() {
        // Paths differing only in the last bit force a branch at depth 255.
        let mut p = [0xab; 32];
        let mut q = p;
        p[31] &= 0xfe;
        q[31] |= 0x01;
        let mut t = Smt::new();
        t.update(p, Some(h(1)));
        t.update(q, Some(h(2)));
        assert_eq!(t.root(), reference_root(&[(p, h(1)), (q, h(2))]));
        // All-zero and all-one paths.
        t.update([0; 32], Some(h(3)));
        t.update([0xff; 32], Some(h(4)));
        assert_eq!(
            t.root(),
            reference_root(&[(p, h(1)), (q, h(2)), ([0; 32], h(3)), ([0xff; 32], h(4))])
        );
    }

    #[test]
    fn prefix_helpers() {
        let p = [0xff; 32];
        assert_eq!(prefix(&p, 0), [0; 32]);
        assert_eq!(prefix(&p, 256), p);
        let q = prefix(&p, 12);
        assert_eq!((q[0], q[1], q[2]), (0xff, 0xf0, 0));
        assert_eq!(upper(&[0; 32], 0), [0xff; 32]);
        let u = upper(&[0; 32], 12);
        assert_eq!((u[0], u[1], u[2]), (0, 0x0f, 0xff));
    }
}
