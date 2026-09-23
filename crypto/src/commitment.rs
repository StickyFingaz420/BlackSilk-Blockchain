//! Pedersen commitments (spec §1.4): `Com(a, y) = y·G + a·H`.

use crate::generators::h_table;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Commitment to `amount` with blinding `mask` (constant time in both).
pub fn commit(amount: u64, mask: &Scalar) -> RistrettoPoint {
    RistrettoPoint::mul_base(mask) + &Scalar::from(amount) * h_table()
}

/// The implicit commitment of a coinbase output: `1·G + a·H` (spec §4.3).
pub fn coinbase_commitment(amount: u64) -> RistrettoPoint {
    commit(amount, &Scalar::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::{h, G};

    #[test]
    fn homomorphic() {
        let (a1, a2) = (1_000u64, 234u64);
        let (y1, y2) = (Scalar::from(11u64), Scalar::from(22u64));
        assert_eq!(
            commit(a1, &y1) + commit(a2, &y2),
            commit(a1 + a2, &(y1 + y2))
        );
    }

    #[test]
    fn matches_definition() {
        let y = Scalar::from(5u64);
        assert_eq!(commit(9, &y), y * G + Scalar::from(9u64) * h());
        assert_eq!(coinbase_commitment(9), G + Scalar::from(9u64) * h());
    }
}
