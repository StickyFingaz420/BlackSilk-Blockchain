//! Group generators (spec §1.3).
//!
//! `G` is the Ristretto255 base point (blinding and key generator). `H` (value
//! generator) and the Bulletproofs+ vectors are hash-to-group outputs, so no
//! discrete-log relation between any of them is known to anyone.

use crate::hash::{hash_to_point, tags};
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use std::sync::OnceLock;

pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

/// Maximum Bulletproofs+ vector length: 64 bits × 16 outputs.
pub const BP_MAX_GENERATORS: usize = 1024;

/// The value generator `H = Hp("generator/H", "")`.
pub fn h() -> &'static RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    H.get_or_init(|| hash_to_point(tags::GENERATOR_H, &[]))
}

/// Precomputed multiples of `H`, for constant-time `a·H`.
pub fn h_table() -> &'static RistrettoBasepointTable {
    static TABLE: OnceLock<RistrettoBasepointTable> = OnceLock::new();
    TABLE.get_or_init(|| RistrettoBasepointTable::create(h()))
}

pub struct BpGenerators {
    pub g: Vec<RistrettoPoint>,
    pub h: Vec<RistrettoPoint>,
}

/// `Gbp[i] = Hp("generator/bp+/G", LE32(i))`, `Hbp[i] = Hp("generator/bp+/H", LE32(i))`.
pub fn bp_generators() -> &'static BpGenerators {
    static GENS: OnceLock<BpGenerators> = OnceLock::new();
    GENS.get_or_init(|| {
        let make = |tag| {
            (0..BP_MAX_GENERATORS as u32)
                .map(|i| hash_to_point(tag, &[&i.to_le_bytes()]))
                .collect()
        };
        BpGenerators {
            g: make(tags::GENERATOR_BP_G),
            h: make(tags::GENERATOR_BP_H),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::IsIdentity;
    use std::collections::HashSet;

    #[test]
    fn generators_are_distinct_and_non_trivial() {
        let gens = bp_generators();
        let mut seen = HashSet::new();
        for p in [G, *h()].iter().chain(&gens.g).chain(&gens.h) {
            assert!(!p.is_identity());
            assert!(seen.insert(p.compress().to_bytes()), "duplicate generator");
        }
        assert_eq!(seen.len(), 2 + 2 * BP_MAX_GENERATORS);
    }

    #[test]
    fn h_table_matches_h() {
        let s = curve25519_dalek::scalar::Scalar::from(123_456_789u64);
        assert_eq!(&s * h_table(), s * h());
    }
}
