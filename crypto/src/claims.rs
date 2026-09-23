//! Confidential claims: facts about committed amounts (contracts spec §8).
//!
//! | Claim | Statement about `C = y·G + v·H` | Proof |
//! |---|---|---|
//! | Range | `min ≤ v ≤ max` | Bulletproofs+ over `V0 = C − min·H` and `V1 = max·H − C` |
//! | Equal | `C_a` and `C_b` hold the same amount | Schnorr (`contract/claim-eq`) with key `C_a − C_b` |
//! | Reveal | `v` equals a public value | Schnorr (`contract/claim-val`) with key `C − v·H` |
//!
//! **Range soundness.** The BP+ proof shows `V0` and `V1` commit to
//! `a0, a1 ∈ [0, 2^64)`. Since `V0 + V1 = (max − min)·H`, binding gives
//! `a0 + a1 ≡ max − min (mod ℓ)`, and because both sides are below `2^65 ≪ ℓ`,
//! `a0 + a1 = max − min` over the integers. With `v ≡ min + a0 (mod ℓ)` and
//! `min + a0 = max − a1 ∈ [min, max] ⊂ [0, 2^64)`, the committed amount `v` is an
//! integer in `[min, max]`. This does **not** require `C` itself to have been
//! range-proven.
//!
//! **Equality / reveal soundness.** A valid signature proves knowledge of `x`
//! with `C_a − C_b = x·G` (resp. `C − v·H = x·G`). If the amounts differed, the
//! prover would know a discrete-log relation between `G` and `H` (binding, DL).
//! Both keys must not be the identity (the Schnorr rule), so a claim between a
//! commitment and itself, or over a commitment with mask exactly zero, is refused.

use crate::bulletproofs_plus::{self, BppError, BppProof};
use crate::generators;
use crate::hash::tags;
use crate::point::Point;
use crate::schnorr::{self, SchnorrError, Signature};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// `min > max`, or the amount is outside `[min, max]`.
    OutOfRange,
    /// The given opening does not match the commitment.
    WrongOpening,
    /// Both commitments are equal (or the key is otherwise the identity).
    Degenerate,
    Proof(BppError),
}

impl From<SchnorrError> for ClaimError {
    fn from(e: SchnorrError) -> Self {
        match e {
            SchnorrError::WrongSecret => ClaimError::WrongOpening,
            SchnorrError::IdentityKey => ClaimError::Degenerate,
        }
    }
}

fn value_point(v: u64) -> RistrettoPoint {
    generators::h() * Scalar::from(v)
}

fn opening_matches(commitment: &Point, amount: u64, mask: &Scalar) -> bool {
    crate::commitment::commit(amount, mask) == *commitment.point()
}

/// `(V0, V1) = (C − min·H, max·H − C)`.
fn range_commitments(commitment: &Point, min: u64, max: u64) -> [Point; 2] {
    let c = commitment.point();
    [
        Point::from_point(c - value_point(min)),
        Point::from_point(value_point(max) - c),
    ]
}

/// Proves `min ≤ amount ≤ max` for `commitment = mask·G + amount·H`.
pub fn prove_range<R: RngCore + CryptoRng>(
    commitment: &Point,
    amount: u64,
    mask: &Scalar,
    min: u64,
    max: u64,
    rng: &mut R,
) -> Result<BppProof, ClaimError> {
    if min > max || amount < min || amount > max {
        return Err(ClaimError::OutOfRange);
    }
    if !opening_matches(commitment, amount, mask) {
        return Err(ClaimError::WrongOpening);
    }
    let (proof, commitments) =
        bulletproofs_plus::prove(&[amount - min, max - amount], &[*mask, -mask], rng)
            .map_err(ClaimError::Proof)?;
    debug_assert_eq!(commitments, range_commitments(commitment, min, max));
    Ok(proof)
}

/// Verifies a range claim. `min > max` is never valid.
pub fn verify_range(commitment: &Point, min: u64, max: u64, proof: &BppProof) -> bool {
    min <= max && bulletproofs_plus::verify(proof, &range_commitments(commitment, min, max))
}

fn equal_key(a: &Point, b: &Point) -> Point {
    Point::from_point(a.point() - b.point())
}

fn reveal_key(c: &Point, value: u64) -> Point {
    Point::from_point(c.point() - value_point(value))
}

/// Proves that `a = mask_a·G + v·H` and `b = mask_b·G + v·H` hold the same `v`.
/// Signs `message` (the transaction's `sig_message`).
pub fn prove_equal<R: RngCore + CryptoRng>(
    a: &Point,
    mask_a: &Scalar,
    b: &Point,
    mask_b: &Scalar,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<Signature, ClaimError> {
    let key = equal_key(a, b);
    Ok(schnorr::sign(
        tags::CONTRACT_CLAIM_EQ,
        &(mask_a - mask_b),
        &key,
        message,
        rng,
    )?)
}

pub fn verify_equal(a: &Point, b: &Point, message: &[u8; 32], sig: &Signature) -> bool {
    schnorr::verify(tags::CONTRACT_CLAIM_EQ, &equal_key(a, b), message, sig)
}

/// Proves that `commitment = mask·G + value·H`.
pub fn prove_reveal<R: RngCore + CryptoRng>(
    commitment: &Point,
    value: u64,
    mask: &Scalar,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<Signature, ClaimError> {
    let key = reveal_key(commitment, value);
    Ok(schnorr::sign(
        tags::CONTRACT_CLAIM_VAL,
        mask,
        &key,
        message,
        rng,
    )?)
}

pub fn verify_reveal(commitment: &Point, value: u64, message: &[u8; 32], sig: &Signature) -> bool {
    schnorr::verify(
        tags::CONTRACT_CLAIM_VAL,
        &reveal_key(commitment, value),
        message,
        sig,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::commit;
    use crate::nonce::test_rng::seeded;

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn committed(v: u64, rng: &mut impl RngCore) -> (Point, Scalar) {
        let y = random_scalar(rng);
        (Point::from_point(commit(v, &y)), y)
    }

    #[test]
    fn range_claims_hold_exactly_at_the_bounds() {
        let mut rng = seeded(920);
        let cases: &[(u64, u64, u64)] = &[
            (500, 500, 500),
            (500, 0, 500),
            (500, 500, u64::MAX),
            (0, 0, 0),
            (0, 0, u64::MAX),
            (u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, 0, u64::MAX),
            (1_000_000, 999_999, 1_000_001),
        ];
        for &(v, min, max) in cases {
            let (c, y) = committed(v, &mut rng);
            let proof = prove_range(&c, v, &y, min, max, &mut rng).unwrap();
            assert!(verify_range(&c, min, max, &proof), "{v} in [{min}, {max}]");
            // The proof is bound to its bounds: changing either one invalidates it.
            if min < v {
                assert!(!verify_range(&c, min + 1, max, &proof));
            }
            if max > v {
                assert!(!verify_range(&c, min, max - 1, &proof));
            }
        }
    }

    #[test]
    fn honest_prover_refuses_false_or_bad_statements() {
        let mut rng = seeded(921);
        let (c, y) = committed(100, &mut rng);
        for (min, max) in [(101, 200), (0, 99), (5, 4)] {
            assert_eq!(
                prove_range(&c, 100, &y, min, max, &mut rng),
                Err(ClaimError::OutOfRange),
                "[{min}, {max}]"
            );
        }
        // Claiming a different amount than committed.
        assert_eq!(
            prove_range(&c, 150, &y, 100, 200, &mut rng),
            Err(ClaimError::WrongOpening)
        );
    }

    #[test]
    fn a_false_range_statement_cannot_be_proven_by_shifting_openings() {
        // The cheater commits to 50 and wants "≥ 100". It proves a true statement
        // for a different commitment and presents it for C: must fail.
        let mut rng = seeded(922);
        let (c, _) = committed(50, &mut rng);
        let (c_big, y_big) = committed(150, &mut rng);
        let proof = prove_range(&c_big, 150, &y_big, 100, 200, &mut rng).unwrap();
        assert!(verify_range(&c_big, 100, 200, &proof));
        assert!(!verify_range(&c, 100, 200, &proof));
        // A wrap-around attempt: "v ≥ min" with v − min negative is a huge a0
        // mod ℓ, which no proof over [0, 2^64) can cover. The prover must build
        // V0 = C − min·H itself: with amount 50 and min 100 the BP+ prover would
        // need a0 = −50 mod ℓ, which is not a u64 at all.
        assert_eq!(
            prove_range(&c, 50, &Scalar::ONE, 100, 200, &mut rng),
            Err(ClaimError::OutOfRange)
        );
        assert!(
            !verify_range(&c, 200, 100, &proof),
            "min > max never verifies"
        );
    }

    #[test]
    fn range_proof_mutations_are_rejected() {
        let mut rng = seeded(923);
        let (c, y) = committed(7_000, &mut rng);
        let proof = prove_range(&c, 7_000, &y, 1_000, 10_000, &mut rng).unwrap();
        let mut bad = proof.clone();
        bad.r1 += Scalar::ONE;
        assert!(!verify_range(&c, 1_000, 10_000, &bad));
        let mut bad = proof.clone();
        bad.l[0] = Point::from_point(bad.l[0].point() + generators::h());
        assert!(!verify_range(&c, 1_000, 10_000, &bad));
        let mut bad = proof;
        bad.l.pop();
        assert!(!verify_range(&c, 1_000, 10_000, &bad));
    }

    #[test]
    fn equality_claims() {
        let mut rng = seeded(924);
        let m = [5u8; 32];
        let (a, ya) = committed(42, &mut rng);
        let (b, yb) = committed(42, &mut rng);
        let (d, yd) = committed(43, &mut rng);
        let sig = prove_equal(&a, &ya, &b, &yb, &m, &mut rng).unwrap();
        assert!(verify_equal(&a, &b, &m, &sig));
        assert!(
            !verify_equal(&b, &a, &m, &sig),
            "order is part of the statement"
        );
        assert!(!verify_equal(&a, &d, &m, &sig));
        assert!(
            !verify_equal(&a, &b, &[6; 32], &sig),
            "bound to the message"
        );
        // Different amounts: the mask difference is not a G-opening of a − d.
        assert_eq!(
            prove_equal(&a, &ya, &d, &yd, &m, &mut rng),
            Err(ClaimError::WrongOpening)
        );
        // A commitment against itself is refused (identity key).
        assert_eq!(
            prove_equal(&a, &ya, &a, &ya, &m, &mut rng),
            Err(ClaimError::Degenerate)
        );
        // A forged signature for unequal amounts fails.
        let forged = schnorr::sign(
            tags::CONTRACT_CLAIM_EQ,
            &(ya - yd),
            &Point::from_point(RistrettoPoint::mul_base(&(ya - yd))),
            &m,
            &mut rng,
        )
        .unwrap();
        assert!(!verify_equal(&a, &d, &m, &forged));
    }

    #[test]
    fn reveal_claims() {
        let mut rng = seeded(925);
        let m = [1u8; 32];
        let (c, y) = committed(12_500_000_000, &mut rng);
        let sig = prove_reveal(&c, 12_500_000_000, &y, &m, &mut rng).unwrap();
        assert!(verify_reveal(&c, 12_500_000_000, &m, &sig));
        assert!(!verify_reveal(&c, 12_500_000_001, &m, &sig));
        assert!(!verify_reveal(&c, 12_500_000_000, &[2; 32], &sig));
        assert_eq!(
            prove_reveal(&c, 1, &y, &m, &mut rng),
            Err(ClaimError::WrongOpening)
        );
        // Public notes and coinbase outputs use mask 1: revealable like any other.
        let public = Point::from_point(commit(9, &Scalar::ONE));
        let sig = prove_reveal(&public, 9, &Scalar::ONE, &m, &mut rng).unwrap();
        assert!(verify_reveal(&public, 9, &m, &sig));
    }

    #[test]
    fn claim_tags_are_not_interchangeable() {
        // An equality signature over key K is not a reveal signature over the same
        // key, and vice versa.
        let mut rng = seeded(926);
        let m = [3u8; 32];
        let (a, ya) = committed(10, &mut rng);
        let (b, yb) = committed(10, &mut rng);
        let eq = prove_equal(&a, &ya, &b, &yb, &m, &mut rng).unwrap();
        // A reveal of value 0 for C' = a − b has the same key as the equality
        // claim; only the tag separates the two statements.
        let c_prime = Point::from_point(a.point() - b.point());
        assert!(!verify_reveal(&c_prime, 0, &m, &eq));
        assert!(!schnorr::verify(tags::CONTRACT_AUTH, &c_prime, &m, &eq));
    }
}
