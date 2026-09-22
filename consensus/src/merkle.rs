//! Transaction Merkle root (spec §7).

use crate::hash::{Hash, H};

fn leaf(id: &Hash) -> Hash {
    H::new().chain(&[0x00]).chain(id).finish()
}

fn node(l: &Hash, r: &Hash) -> Hash {
    H::new().chain(&[0x01]).chain(l).chain(r).finish()
}

/// Merkle root of ordered transaction ids (coinbase first). Empty list -> all zeros.
pub fn tx_root(ids: &[Hash]) -> Hash {
    if ids.is_empty() {
        return [0; 32];
    }
    let mut level: Vec<Hash> = ids.iter().map(leaf).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                [odd] => *odd, // carried up unchanged
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Hash {
        [n; 32]
    }

    #[test]
    fn shapes() {
        assert_eq!(tx_root(&[]), [0; 32]);
        assert_eq!(tx_root(&[id(1)]), leaf(&id(1)));
        assert_eq!(tx_root(&[id(1), id(2)]), node(&leaf(&id(1)), &leaf(&id(2))));
        assert_eq!(
            tx_root(&[id(1), id(2), id(3)]),
            node(&node(&leaf(&id(1)), &leaf(&id(2))), &leaf(&id(3)))
        );
    }

    #[test]
    fn no_duplicate_malleability() {
        // With Bitcoin-style duplication, [a, b, c] and [a, b, c, c] share a root.
        let three = tx_root(&[id(1), id(2), id(3)]);
        let four = tx_root(&[id(1), id(2), id(3), id(3)]);
        assert_ne!(three, four);
    }

    #[test]
    fn order_and_leaf_node_separation() {
        assert_ne!(tx_root(&[id(1), id(2)]), tx_root(&[id(2), id(1)]));
        // An inner node value used as a single leaf does not reproduce the root.
        let inner = node(&leaf(&id(1)), &leaf(&id(2)));
        assert_ne!(tx_root(&[inner]), tx_root(&[id(1), id(2)]));
    }
}
