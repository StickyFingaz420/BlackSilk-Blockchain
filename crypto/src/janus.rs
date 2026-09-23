//! The Janus anchor (spec §12).
//!
//! **Problem.** Someone who knows two of a wallet's subaddresses `(D_a, C_a)`
//! and `(D_b, C_b)` can build an output with `R = r·D_a` and `S = r·C_a` but
//! `O = Hs(S)·G + D_b`. A plain CryptoNote wallet recognizes it as a payment to
//! `b`, which happens only if `a` and `b` share a view key. The victim's reaction
//! ("I got paid at b") links the two subaddresses.
//!
//! **Construction.** The sender derives the ephemeral secret from a fresh 16-byte
//! anchor, bound to the transaction and the recipient address, and sends the
//! anchor encrypted under the shared secret:
//!
//! ```text
//! r          = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)
//! R          = r·D
//! enc_anchor = anchor ⊕ H64("anchor", S)[0..16]
//! ```
//!
//! After recognizing subaddress `(D', C')`, the recipient decrypts the anchor,
//! recomputes `r` for `(D', C')` and requires `r·D' = R`. With that check, every
//! accepted output is exactly the honest construction for `(D', C')`. Its
//! acceptance therefore depends only on data the sender could compute from that
//! one address, and reveals nothing about any other address of the wallet
//! (spec §12.4). The check needs only the view key.

use crate::hash::{h64, hash_to_scalar, tags};
use crate::keys::Address;
use crate::point::Point;
use crate::stealth::SharedSecret;
use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const ANCHOR_BYTES: usize = 16;

/// A Janus anchor: 16 bytes from the sender's hedged CSPRNG, unique per output.
#[derive(Clone, PartialEq, Eq)]
pub struct Anchor(pub [u8; ANCHOR_BYTES]);

impl std::fmt::Debug for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Anchor(…)")
    }
}

impl Drop for Anchor {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)`.
pub fn ephemeral_secret(anchor: &Anchor, ctx: &[u8; 32], address: &Address) -> Scalar {
    hash_to_scalar(
        tags::EPHEMERAL,
        &[
            &anchor.0,
            ctx,
            address.spend().bytes(),
            address.view().bytes(),
        ],
    )
}

fn pad(s: &SharedSecret) -> [u8; ANCHOR_BYTES] {
    let mut full = h64(tags::ANCHOR, &[s.as_bytes()]);
    let mut out = [0u8; ANCHOR_BYTES];
    out.copy_from_slice(&full[..ANCHOR_BYTES]);
    full.zeroize();
    out
}

/// `enc_anchor = anchor ⊕ H64("anchor", S)[0..16]`.
pub fn seal(anchor: &Anchor, s: &SharedSecret) -> [u8; ANCHOR_BYTES] {
    let mut out = pad(s);
    for (o, a) in out.iter_mut().zip(&anchor.0) {
        *o ^= a;
    }
    out
}

/// Inverse of [`seal`].
pub fn open(enc_anchor: &[u8; ANCHOR_BYTES], s: &SharedSecret) -> Anchor {
    let mut out = pad(s);
    for (o, e) in out.iter_mut().zip(enc_anchor) {
        *o ^= e;
    }
    Anchor(out)
}

/// The recipient's check: `Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)·D = R`.
pub fn verify(anchor: &Anchor, ctx: &[u8; 32], address: &Address, ephemeral: &Point) -> bool {
    let mut r = ephemeral_secret(anchor, ctx, address);
    let expected = Point::from_point(r * address.spend().point());
    r.zeroize();
    // r = 0 gives R = identity, which consensus never allows; reject it here too.
    !expected.is_identity() && bool::from(expected.bytes().ct_eq(ephemeral.bytes()))
}

#[cfg(test)]
mod tests {
    //! Attack scenarios (spec §12.6). "Eve" knows public addresses only.

    use super::*;
    use crate::commitment::commit;
    use crate::hash::{h32, hash_to_scalar};
    use crate::keys::{SubaddressIndex, SubaddressTable, ViewKeys, WalletKeys};
    use crate::nonce::test_rng::seeded;
    use crate::stealth::tests::{fields, random_anchor};
    use crate::stealth::{
        create_output, scan_output, CreatedOutput, OutputAmount, OutputFields, OutputKind,
        ScanOutcome, ScanRejection,
    };
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand_core::RngCore;

    const CTX: [u8; 32] = [0x42; 32];

    /// Eve's Janus output: shared secret computed for `via`, one-time key for `target`.
    /// `r` is Eve's ephemeral secret; `anchor` is what she puts in `enc_anchor`.
    fn janus_output(via: &Address, target: &Address, r: Scalar, anchor: &Anchor) -> CreatedOutput {
        let ephemeral = Point::from_point(r * via.spend().point());
        let s = SharedSecret::from_point(&(r * via.view().point()));
        let x = hash_to_scalar(tags::OUTPUT_KEY, &[s.as_bytes()]);
        let y = hash_to_scalar(tags::MASK, &[s.as_bytes()]);
        let amount = 1u64;
        let mut enc_amount = amount.to_le_bytes();
        let pad = h64(tags::AMOUNT, &[s.as_bytes()]);
        for i in 0..8 {
            enc_amount[i] ^= pad[i];
        }
        CreatedOutput {
            one_time_key: Point::from_point(RistrettoPoint::mul_base(&x) + target.spend().point()),
            ephemeral,
            view_tag: h32(tags::VIEW_TAG, &[s.as_bytes()])[0],
            commitment: Point::from_point(commit(amount, &y)),
            enc_amount,
            enc_anchor: seal(anchor, &s),
            amount,
            mask: y,
        }
    }

    /// Recognition as in CryptoNote/Monero, without the anchor check (steps 1-4).
    fn legacy_recognizes(
        view: &ViewKeys,
        table: &SubaddressTable,
        o: &CreatedOutput,
    ) -> Option<SubaddressIndex> {
        let s = SharedSecret::from_point(&(view.view_secret() * o.ephemeral.point()));
        if h32(tags::VIEW_TAG, &[s.as_bytes()])[0] != o.view_tag {
            return None;
        }
        let x = hash_to_scalar(tags::OUTPUT_KEY, &[s.as_bytes()]);
        let d = o.one_time_key.point() - RistrettoPoint::mul_base(&x);
        table.lookup(&d.compress().to_bytes()).map(|(i, _)| *i)
    }

    fn scan(view: &ViewKeys, table: &SubaddressTable, o: &CreatedOutput) -> ScanOutcome {
        scan_output(view, table, &CTX, &fields(o, OutputKind::Transfer))
    }

    fn is_janus_rejection(o: &ScanOutcome) -> bool {
        matches!(
            o,
            ScanOutcome::Rejected {
                reason: ScanRejection::JanusAnchorMismatch,
                ..
            }
        )
    }

    struct Victim {
        keys: WalletKeys,
        table: SubaddressTable,
        a: Address,
        b: Address,
    }

    fn victim(seed: u64) -> Victim {
        let (keys, _) = WalletKeys::generate(&mut seeded(seed));
        let table = SubaddressTable::new(keys.view_keys(), 2, 8);
        let a = keys.address(SubaddressIndex::new(0, 3));
        let b = keys.address(SubaddressIndex::new(1, 5));
        Victim { keys, table, a, b }
    }

    /// A1: the classic attack. `r` derived honestly for `a`, the key points at `b`.
    #[test]
    fn classic_janus_is_detected() {
        let v = victim(100);
        let mut rng = seeded(101);
        let anchor = random_anchor(&mut rng);
        let r = ephemeral_secret(&anchor, &CTX, &v.a);
        let o = janus_output(&v.a, &v.b, r, &anchor);

        // Without the anchor, the wallet would accept it as a payment to b:
        // this is the vulnerability.
        assert_eq!(
            legacy_recognizes(v.keys.view_keys(), &v.table, &o),
            Some(SubaddressIndex::new(1, 5))
        );
        // With the anchor, it is refused.
        assert!(is_janus_rejection(&scan(v.keys.view_keys(), &v.table, &o)));
    }

    /// A2: Eve uses an anchor that is honest for b while `R` is built from a.
    #[test]
    fn anchor_for_target_with_ephemeral_from_other_address_is_detected() {
        let v = victim(102);
        let mut rng = seeded(103);
        let anchor = random_anchor(&mut rng);
        let r_b = ephemeral_secret(&anchor, &CTX, &v.b);
        let o = janus_output(&v.a, &v.b, r_b, &anchor);
        assert!(legacy_recognizes(v.keys.view_keys(), &v.table, &o).is_some());
        assert!(is_janus_rejection(&scan(v.keys.view_keys(), &v.table, &o)));
    }

    /// A3: Eve ignores the anchor derivation entirely (random r, random anchor bytes).
    #[test]
    fn arbitrary_ephemeral_is_detected() {
        let v = victim(104);
        let mut rng = seeded(105);
        for _ in 0..16 {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let r = Scalar::from_bytes_mod_order_wide(&wide);
            let o = janus_output(&v.a, &v.b, r, &random_anchor(&mut rng));
            assert!(is_janus_rejection(&scan(v.keys.view_keys(), &v.table, &o)));
        }
    }

    /// A4: the mirrored direction (via b, target a) and same-account pairs.
    #[test]
    fn all_address_pairs_are_protected() {
        let v = victim(106);
        let mut rng = seeded(107);
        let idx = [
            SubaddressIndex::PRIMARY,
            SubaddressIndex::new(0, 1),
            SubaddressIndex::new(1, 0),
            SubaddressIndex::new(1, 7),
        ];
        for &i in &idx {
            for &j in &idx {
                if i == j {
                    continue;
                }
                let (via, target) = (v.keys.address(i), v.keys.address(j));
                let anchor = random_anchor(&mut rng);
                let r = ephemeral_secret(&anchor, &CTX, &via);
                let o = janus_output(&via, &target, r, &anchor);
                assert!(
                    is_janus_rejection(&scan(v.keys.view_keys(), &v.table, &o)),
                    "{i:?}->{j:?}"
                );
            }
        }
    }

    /// A5: what Eve can observe is identical whether or not a and b share a wallet.
    /// In both worlds the victim's set of received outputs is empty.
    #[test]
    fn outcome_is_independent_of_address_linkage() {
        let mut rng = seeded(108);
        // World 1: a and b in the same wallet.
        let same = victim(109);
        // World 2: a belongs to someone else; the victim owns only b.
        let (other, _) = WalletKeys::generate(&mut rng);
        let a_other = other.address(SubaddressIndex::new(0, 3));

        for (via, target, v) in [(same.a, same.b, &same), (a_other, same.b, &same)] {
            let anchor = random_anchor(&mut rng);
            let r = ephemeral_secret(&anchor, &CTX, &via);
            let o = janus_output(&via, &target, r, &anchor);
            let outcome = scan(v.keys.view_keys(), &v.table, &o);
            // Rejected and NotOwned are handled identically: nothing is received.
            assert!(outcome.owned().is_none());
        }
    }

    /// A6: view-only wallets detect the attack exactly like full wallets.
    #[test]
    fn view_only_wallet_detects_janus() {
        let v = victim(110);
        let view_only = ViewKeys::new(
            *v.keys.view_keys().view_secret(),
            *v.keys.view_keys().spend_public(),
        )
        .unwrap();
        let table = SubaddressTable::new(&view_only, 2, 8);
        let mut rng = seeded(111);
        let anchor = random_anchor(&mut rng);
        let o = janus_output(&v.a, &v.b, ephemeral_secret(&anchor, &CTX, &v.a), &anchor);
        assert!(is_janus_rejection(&scan(&view_only, &table, &o)));
        // And accept honest payments.
        let honest = create_output(
            &v.b,
            9,
            &CTX,
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        assert!(scan(&view_only, &table, &honest).owned().is_some());
    }

    /// A7: tampering with enc_anchor of an honest output makes it unacceptable
    /// (on chain the signature prevents this; here we test the wallet check itself).
    #[test]
    fn tampered_anchor_is_rejected() {
        let v = victim(112);
        let mut rng = seeded(113);
        let honest = create_output(
            &v.b,
            9,
            &CTX,
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        assert!(scan(v.keys.view_keys(), &v.table, &honest)
            .owned()
            .is_some());
        for bit in 0..128 {
            let mut o = honest.clone();
            o.enc_anchor[bit / 8] ^= 1 << (bit % 8);
            assert!(
                is_janus_rejection(&scan(v.keys.view_keys(), &v.table, &o)),
                "bit {bit}"
            );
        }
    }

    /// Simulatability (spec §12.4, Lemma 1), tested on random honest and adversarial
    /// outputs: whenever the wallet accepts an output as subaddress j, that output is
    /// byte-for-byte the honest construction for j's public address.
    #[test]
    fn accepted_outputs_are_honest_constructions() {
        let v = victim(114);
        let mut rng = seeded(115);
        let addresses: Vec<(SubaddressIndex, Address)> = (0..4)
            .map(|i| SubaddressIndex::new(i % 2, i))
            .map(|i| (i, v.keys.address(i)))
            .collect();
        let mut accepted = 0;
        for round in 0..64 {
            let (_, via) = addresses[round % 4];
            let (_, target) = addresses[(round / 4) % 4];
            let anchor = random_anchor(&mut rng);
            let o = if round % 3 == 0 {
                create_output(&target, 1, &CTX, &anchor, OutputKind::Transfer).unwrap()
            } else {
                janus_output(
                    &via,
                    &target,
                    ephemeral_secret(&anchor, &CTX, &via),
                    &anchor,
                )
            };
            let outcome = scan(v.keys.view_keys(), &v.table, &o);
            if let ScanOutcome::Owned(r) = outcome {
                accepted += 1;
                let addr = v.keys.address(r.subaddress);
                let s = SharedSecret::from_point(
                    &(v.keys.view_keys().view_secret() * o.ephemeral.point()),
                );
                let recovered_anchor = open(&o.enc_anchor, &s);
                let rebuilt = create_output(
                    &addr,
                    r.amount,
                    &CTX,
                    &recovered_anchor,
                    OutputKind::Transfer,
                )
                .unwrap();
                assert_eq!(rebuilt.one_time_key, o.one_time_key);
                assert_eq!(rebuilt.ephemeral, o.ephemeral);
                assert_eq!(rebuilt.view_tag, o.view_tag);
                assert_eq!(rebuilt.commitment, o.commitment);
                assert_eq!(rebuilt.enc_amount, o.enc_amount);
                assert_eq!(rebuilt.enc_anchor, o.enc_anchor);
            }
        }
        assert!(accepted > 0);
    }

    /// Privacy: enc_anchor carries no visible structure. Across many outputs every
    /// bit is set about half the time, including when the anchor itself is constant
    /// (a completely broken RNG).
    #[test]
    fn enc_anchor_is_uniform_to_observers() {
        let mut rng = seeded(116);
        let (w, _) = WalletKeys::generate(&mut rng);
        let addr = w.address(SubaddressIndex::PRIMARY);
        let n = 2048u32;
        let mut ones = [0u32; 128];
        for i in 0..n {
            let ctx = h32(tags::MASK, &[&i.to_le_bytes()]);
            let o = create_output(&addr, 1, &ctx, &Anchor([0; 16]), OutputKind::Transfer).unwrap();
            for (bit, count) in ones.iter_mut().enumerate() {
                *count += ((o.enc_anchor[bit / 8] >> (bit % 8)) & 1) as u32;
            }
        }
        // Binomial(2048, 1/2): sd ≈ 22.6; allow 5 sd.
        for (bit, &c) in ones.iter().enumerate() {
            assert!((c as i64 - 1024).abs() < 113, "bit {bit}: {c}");
        }
    }

    /// The recipient can recompute `r` for its own outputs, and only for them.
    #[test]
    fn recipient_recovers_ephemeral_secret() {
        let mut rng = seeded(117);
        let (w, _) = WalletKeys::generate(&mut rng);
        let addr = w.address(SubaddressIndex::new(0, 2));
        let anchor = random_anchor(&mut rng);
        let o = create_output(&addr, 3, &CTX, &anchor, OutputKind::Transfer).unwrap();
        let s = SharedSecret::from_point(&(w.view_keys().view_secret() * o.ephemeral.point()));
        assert_eq!(open(&o.enc_anchor, &s), anchor);
        assert!(verify(&anchor, &CTX, &addr, &o.ephemeral));
        // The same anchor does not verify for another address or context.
        assert!(!verify(
            &anchor,
            &CTX,
            &w.address(SubaddressIndex::new(0, 3)),
            &o.ephemeral
        ));
        assert!(!verify(&anchor, &[0; 32], &addr, &o.ephemeral));
    }

    #[test]
    fn identity_ephemeral_never_verifies() {
        let mut rng = seeded(118);
        let (w, _) = WalletKeys::generate(&mut rng);
        let id = Point::decode(&[0; 32]).unwrap();
        assert!(!verify(
            &random_anchor(&mut rng),
            &CTX,
            &w.address(SubaddressIndex::PRIMARY),
            &id
        ));
    }

    #[test]
    fn coinbase_outputs_carry_anchors_too() {
        let v = victim(119);
        let mut rng = seeded(120);
        let o = create_output(
            &v.b,
            50,
            &CTX,
            &random_anchor(&mut rng),
            OutputKind::Coinbase,
        )
        .unwrap();
        let f = OutputFields {
            amount: OutputAmount::Clear(50),
            ..fields(&o, OutputKind::Coinbase)
        };
        assert!(scan_output(v.keys.view_keys(), &v.table, &CTX, &f)
            .owned()
            .is_some());
        let mut bad = o.clone();
        bad.enc_anchor[0] ^= 1;
        let f = fields(&bad, OutputKind::Coinbase);
        assert!(is_janus_rejection(&scan_output(
            v.keys.view_keys(),
            &v.table,
            &CTX,
            &f
        )));
    }
}
