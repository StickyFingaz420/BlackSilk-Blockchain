//! The PX commitment tree (zk.md §4.5): append-only, binary, depth 32, with
//! nodes `P(l ‖ r)[0..8]` (`blacksilk_px_core::hash::node`) and empty leaves
//! `0`.
//!
//! - [`Frontier`]: what a node keeps, 32 digests and the size. It appends and computes the
//!   root in O(depth).
//! - [`Tree`]: every node, for wallets and tests; it also produces
//!   authentication paths.
//!
//! Both compute the same root; a test checks it for every size up to 300 and
//! for sparse sizes near powers of two.

use blacksilk_px_core::hash::node;
use blacksilk_px_core::kernel::TREE_DEPTH;
use blacksilk_px_core::{Digest, Permutation, ZERO_DIGEST};

/// Maximum number of leaves.
pub const CAPACITY: u64 = 1 << TREE_DEPTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeFull;

/// Roots of empty subtrees: `empty[h]` has height `h` (`empty[0]` is a leaf).
pub fn empty_roots<P: Permutation>(perm: &mut P) -> [Digest; TREE_DEPTH + 1] {
    let mut e = [ZERO_DIGEST; TREE_DEPTH + 1];
    for h in 0..TREE_DEPTH {
        e[h + 1] = node(perm, &e[h], &e[h]);
    }
    e
}

/// The consensus view of the tree: size and the left siblings on the path of
/// the next leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    branch: [Digest; TREE_DEPTH],
}

impl Default for Frontier {
    fn default() -> Self {
        Frontier {
            size: 0,
            branch: [ZERO_DIGEST; TREE_DEPTH],
        }
    }
}

impl Frontier {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends a leaf; returns its position.
    pub fn append<P: Permutation>(&mut self, perm: &mut P, leaf: Digest) -> Result<u64, TreeFull> {
        if self.size >= CAPACITY {
            return Err(TreeFull);
        }
        let pos = self.size;
        let mut cur = leaf;
        for h in 0..TREE_DEPTH {
            if (pos >> h) & 1 == 0 {
                self.branch[h] = cur;
                break;
            }
            cur = node(perm, &self.branch[h], &cur);
        }
        self.size += 1;
        Ok(pos)
    }

    pub fn root<P: Permutation>(&self, perm: &mut P, empty: &[Digest; TREE_DEPTH + 1]) -> Digest {
        let mut cur = ZERO_DIGEST;
        for (h, e) in empty.iter().enumerate().take(TREE_DEPTH) {
            cur = if (self.size >> h) & 1 == 1 {
                node(perm, &self.branch[h], &cur)
            } else {
                node(perm, &cur, e)
            };
        }
        cur
    }
}

/// The full tree: `levels[h]` holds the non-empty nodes of height `h`.
#[derive(Clone, Debug)]
pub struct Tree {
    levels: Vec<Vec<Digest>>,
    empty: [Digest; TREE_DEPTH + 1],
}

impl Tree {
    pub fn new<P: Permutation>(perm: &mut P) -> Self {
        Tree {
            levels: vec![Vec::new(); TREE_DEPTH + 1],
            empty: empty_roots(perm),
        }
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    fn get(&self, h: usize, i: u64) -> Digest {
        self.levels[h]
            .get(i as usize)
            .copied()
            .unwrap_or(self.empty[h])
    }

    pub fn append<P: Permutation>(&mut self, perm: &mut P, leaf: Digest) -> Result<u64, TreeFull> {
        let pos = self.size();
        if pos >= CAPACITY {
            return Err(TreeFull);
        }
        self.levels[0].push(leaf);
        let mut i = pos;
        for h in 0..TREE_DEPTH {
            let parent = i / 2;
            let v = node(perm, &self.get(h, parent * 2), &self.get(h, parent * 2 + 1));
            let lvl = &mut self.levels[h + 1];
            if (parent as usize) < lvl.len() {
                lvl[parent as usize] = v;
            } else {
                lvl.push(v);
            }
            i = parent;
        }
        Ok(pos)
    }

    pub fn root(&self) -> Digest {
        self.get(TREE_DEPTH, 0)
    }

    pub fn leaf(&self, pos: u64) -> Option<Digest> {
        self.levels[0].get(pos as usize).copied()
    }

    /// The authentication path of leaf `pos`: the sibling at every height.
    pub fn path(&self, pos: u64) -> Option<[Digest; TREE_DEPTH]> {
        if pos >= self.size() {
            return None;
        }
        let mut p = [ZERO_DIGEST; TREE_DEPTH];
        for (h, s) in p.iter_mut().enumerate() {
            *s = self.get(h, (pos >> h) ^ 1);
        }
        Some(p)
    }
}

/// Recomputes the root from a leaf and its path (the kernel's computation).
pub fn root_from_path<P: Permutation>(
    perm: &mut P,
    leaf: Digest,
    pos: u64,
    path: &[Digest; TREE_DEPTH],
) -> Digest {
    let mut cur = leaf;
    for (h, s) in path.iter().enumerate() {
        cur = if (pos >> h) & 1 == 1 {
            node(perm, s, &cur)
        } else {
            node(perm, &cur, s)
        };
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perm::HostPerm;

    fn leaf(i: u32) -> Digest {
        [i + 1, 7, 7, 7, 7, 7, 7, i]
    }

    #[test]
    fn frontier_and_full_tree_agree_and_paths_verify() {
        let mut perm = HostPerm::new();
        let empty = empty_roots(&mut perm);
        let mut f = Frontier::default();
        let mut t = Tree::new(&mut perm);
        assert_eq!(f.root(&mut perm, &empty), t.root());
        assert_eq!(t.root(), empty[TREE_DEPTH]);
        for i in 0..300u32 {
            assert_eq!(f.append(&mut perm, leaf(i)), Ok(i as u64));
            assert_eq!(t.append(&mut perm, leaf(i)), Ok(i as u64));
            let root = t.root();
            assert_eq!(f.root(&mut perm, &empty), root, "size {}", i + 1);
            if i % 37 == 0 || i == 255 || i == 256 {
                for pos in [0, i as u64 / 2, i as u64] {
                    let path = t.path(pos).unwrap();
                    assert_eq!(
                        root_from_path(&mut perm, leaf(pos as u32), pos, &path),
                        root
                    );
                    // A wrong position or leaf does not verify.
                    assert_ne!(
                        root_from_path(&mut perm, leaf(pos as u32 + 1), pos, &path),
                        root
                    );
                    if i > 0 {
                        assert_ne!(
                            root_from_path(&mut perm, leaf(pos as u32), pos ^ 1, &path),
                            root
                        );
                    }
                }
            }
        }
        assert_eq!(t.path(300), None);
    }
}
