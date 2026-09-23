//! One-time stealth outputs, view tags and scanning (spec §3).
//!
//! Sender, for recipient address `(D, C)`, transaction context `ctx` and anchor:
//!
//! ```text
//! r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)         (janus::ephemeral_secret)
//! R = r·D                     S = r·C  (= k_v·R)
//! x = Hs("output-key", S)     O = x·G + D
//! view_tag = H32("view-tag", S)[0]
//! y = Hs("mask", S)           Cm = y·G + a·H        (coinbase: Cm = G + a·H)
//! enc_amount = LE64(a) ⊕ H64("amount", S)[0..8]
//! enc_anchor = anchor  ⊕ H64("anchor", S)[0..16]
//! ```
//!
//! Receiver: [`scan_output`] (spec §3.3), including the Janus anchor check.

use crate::commitment::{coinbase_commitment, commit};
use crate::hash::{h32, h64, hash_to_scalar, tags};
use crate::janus::{self, Anchor, ANCHOR_BYTES};
use crate::keys::{Address, SubaddressIndex, SubaddressTable, ViewKeys};
use crate::point::Point;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// The Diffie–Hellman shared secret `S`, as its canonical encoding. Secret.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub(crate) fn from_point(s: &RistrettoPoint) -> Self {
        Self(s.compress().to_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `ctx` of a transfer: `H32("input-context", I_0 ‖ … ‖ I_{n-1})` (spec §3.1).
pub fn transfer_context(key_images: &[Point]) -> [u8; 32] {
    let parts: Vec<&[u8]> = key_images.iter().map(|k| k.bytes().as_slice()).collect();
    h32(tags::INPUT_CONTEXT, &parts)
}

/// `ctx` of a coinbase: `H32("input-context/coinbase", LE64(height))`.
pub fn coinbase_context(height: u64) -> [u8; 32] {
    h32(tags::INPUT_CONTEXT_COINBASE, &[&height.to_le_bytes()])
}

fn view_tag(s: &SharedSecret) -> u8 {
    h32(tags::VIEW_TAG, &[s.as_bytes()])[0]
}

fn output_key_offset(s: &SharedSecret) -> Scalar {
    hash_to_scalar(tags::OUTPUT_KEY, &[s.as_bytes()])
}

fn mask(s: &SharedSecret) -> Scalar {
    hash_to_scalar(tags::MASK, &[s.as_bytes()])
}

fn xor_amount(amount_bytes: [u8; 8], s: &SharedSecret) -> [u8; 8] {
    let mut pad = h64(tags::AMOUNT, &[s.as_bytes()]);
    let mut out = amount_bytes;
    for (o, p) in out.iter_mut().zip(&pad[..8]) {
        *o ^= p;
    }
    pad.zeroize();
    out
}

/// Whether the amount is hidden in a commitment (transfers) or public (coinbase).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputKind {
    Transfer,
    Coinbase,
}

/// A newly created output plus the opening the sender needs (amount and mask).
#[derive(Clone, Debug)]
pub struct CreatedOutput {
    pub one_time_key: Point,
    pub ephemeral: Point,
    pub view_tag: u8,
    /// Transmitted for transfers. For coinbase outputs it is implicit (`G + a·H`).
    pub commitment: Point,
    /// Transmitted for transfers only.
    pub enc_amount: [u8; 8],
    pub enc_anchor: [u8; ANCHOR_BYTES],
    pub amount: u64,
    pub mask: Scalar,
}

/// Builds an output paying `amount` to `address` (spec §3.2).
///
/// Returns `None` only if the anchor yields `r = 0` (probability 2^-252). The
/// caller then retries with a fresh anchor.
pub fn create_output(
    address: &Address,
    amount: u64,
    ctx: &[u8; 32],
    anchor: &Anchor,
    kind: OutputKind,
) -> Option<CreatedOutput> {
    let mut r = janus::ephemeral_secret(anchor, ctx, address);
    if r == Scalar::ZERO {
        return None;
    }
    let ephemeral = Point::from_point(r * address.spend().point());
    let s = SharedSecret::from_point(&(r * address.view().point()));
    r.zeroize();

    let x = output_key_offset(&s);
    let one_time_key = Point::from_point(RistrettoPoint::mul_base(&x) + address.spend().point());
    let (commitment, mask) = match kind {
        OutputKind::Transfer => {
            let y = mask(&s);
            (Point::from_point(commit(amount, &y)), y)
        }
        OutputKind::Coinbase => (Point::from_point(coinbase_commitment(amount)), Scalar::ONE),
    };
    Some(CreatedOutput {
        one_time_key,
        ephemeral,
        view_tag: view_tag(&s),
        commitment,
        enc_amount: xor_amount(amount.to_le_bytes(), &s),
        enc_anchor: janus::seal(anchor, &s),
        amount,
        mask,
    })
}

/// How an output's amount appears on chain.
#[derive(Clone, Copy, Debug)]
pub enum OutputAmount<'a> {
    Hidden {
        commitment: &'a Point,
        enc_amount: &'a [u8; 8],
    },
    /// Coinbase: amount in the clear, commitment `G + a·H`.
    Clear(u64),
}

/// The on-chain fields of one output, as seen by a scanning wallet.
#[derive(Clone, Copy, Debug)]
pub struct OutputFields<'a> {
    pub one_time_key: &'a Point,
    pub ephemeral: &'a Point,
    pub view_tag: u8,
    pub amount: OutputAmount<'a>,
    pub enc_anchor: &'a [u8; ANCHOR_BYTES],
}

/// A received output with everything needed to spend it later.
#[derive(Clone, Debug)]
pub struct ReceivedOutput {
    pub subaddress: SubaddressIndex,
    pub amount: u64,
    pub mask: Scalar,
    /// `x`; the one-time secret is `x + d(a,i)` (`WalletKeys::one_time_secret`).
    pub output_key_offset: Scalar,
}

/// Why a recognized output was refused. A wallet must treat refused outputs
/// exactly like outputs that are not its own (spec §12.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanRejection {
    /// The ephemeral key was not built for the recognized subaddress: a Janus
    /// probe or a malformed output.
    JanusAnchorMismatch,
    /// The decrypted amount does not open the commitment.
    CommitmentMismatch,
}

#[derive(Clone, Debug)]
pub enum ScanOutcome {
    NotOwned,
    Owned(ReceivedOutput),
    Rejected {
        subaddress: SubaddressIndex,
        reason: ScanRejection,
    },
}

impl ScanOutcome {
    pub fn owned(&self) -> Option<&ReceivedOutput> {
        match self {
            ScanOutcome::Owned(r) => Some(r),
            _ => None,
        }
    }
}

/// Scans one output (spec §3.3). Needs only view keys.
pub fn scan_output(
    view: &ViewKeys,
    table: &SubaddressTable,
    ctx: &[u8; 32],
    out: &OutputFields<'_>,
) -> ScanOutcome {
    // 1-2: shared secret and view tag.
    let s = SharedSecret::from_point(&(view.view_secret() * out.ephemeral.point()));
    if view_tag(&s) != out.view_tag {
        return ScanOutcome::NotOwned;
    }
    // 3-4: candidate subaddress spend key.
    let x = output_key_offset(&s);
    let candidate = out.one_time_key.point() - RistrettoPoint::mul_base(&x);
    let Some((subaddress, address)) = table.lookup(&candidate.compress().to_bytes()) else {
        return ScanOutcome::NotOwned;
    };
    let subaddress = *subaddress;
    // 5: Janus anchor.
    let anchor = janus::open(out.enc_anchor, &s);
    if !janus::verify(&anchor, ctx, address, out.ephemeral) {
        return ScanOutcome::Rejected {
            subaddress,
            reason: ScanRejection::JanusAnchorMismatch,
        };
    }
    // 6: amount.
    let (amount, mask) = match out.amount {
        OutputAmount::Hidden {
            commitment,
            enc_amount,
        } => {
            let amount = u64::from_le_bytes(xor_amount(*enc_amount, &s));
            let y = mask(&s);
            let expected = Point::from_point(commit(amount, &y));
            if !bool::from(expected.bytes().ct_eq(commitment.bytes())) {
                return ScanOutcome::Rejected {
                    subaddress,
                    reason: ScanRejection::CommitmentMismatch,
                };
            }
            (amount, y)
        }
        OutputAmount::Clear(amount) => (amount, Scalar::ONE),
    };
    ScanOutcome::Owned(ReceivedOutput {
        subaddress,
        amount,
        mask,
        output_key_offset: x,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::WalletKeys;
    use crate::nonce::test_rng::seeded;
    use rand_core::RngCore;

    pub(crate) fn random_anchor(rng: &mut impl RngCore) -> Anchor {
        let mut a = [0u8; ANCHOR_BYTES];
        rng.fill_bytes(&mut a);
        Anchor(a)
    }

    pub(crate) fn fields(o: &CreatedOutput, kind: OutputKind) -> OutputFields<'_> {
        OutputFields {
            one_time_key: &o.one_time_key,
            ephemeral: &o.ephemeral,
            view_tag: o.view_tag,
            amount: match kind {
                OutputKind::Transfer => OutputAmount::Hidden {
                    commitment: &o.commitment,
                    enc_amount: &o.enc_amount,
                },
                OutputKind::Coinbase => OutputAmount::Clear(o.amount),
            },
            enc_anchor: &o.enc_anchor,
        }
    }

    #[test]
    fn round_trip_primary_and_subaddresses() {
        let mut rng = seeded(10);
        let (w, _) = WalletKeys::generate(&mut rng);
        let table = SubaddressTable::new(w.view_keys(), 2, 10);
        let ctx = [7u8; 32];
        for (idx, kind) in [
            (SubaddressIndex::PRIMARY, OutputKind::Transfer),
            (SubaddressIndex::new(0, 9), OutputKind::Transfer),
            (SubaddressIndex::new(1, 3), OutputKind::Coinbase),
        ] {
            let amount = rng.next_u64();
            let o = create_output(
                &w.address(idx),
                amount,
                &ctx,
                &random_anchor(&mut rng),
                kind,
            )
            .unwrap();
            let got = scan_output(w.view_keys(), &table, &ctx, &fields(&o, kind));
            let r = got.owned().expect("recipient detects its output");
            assert_eq!(r.subaddress, idx);
            assert_eq!(r.amount, amount);
            assert_eq!(r.mask, o.mask);
            // The one-time secret opens O.
            let p = w.one_time_secret(idx, &r.output_key_offset);
            assert_eq!(RistrettoPoint::mul_base(&p), *o.one_time_key.point());
            // The mask opens the commitment.
            assert_eq!(commit(amount, &r.mask), *o.commitment.point());
        }
    }

    #[test]
    fn other_wallets_do_not_detect() {
        let mut rng = seeded(11);
        let (alice, _) = WalletKeys::generate(&mut rng);
        let (bob, _) = WalletKeys::generate(&mut rng);
        let bob_table = SubaddressTable::new(bob.view_keys(), 1, 20);
        let mut tag_hits = 0;
        for i in 0..200u32 {
            let idx = SubaddressIndex::new(0, i % 20);
            let o = create_output(
                &alice.address(idx),
                5,
                &[i as u8; 32],
                &random_anchor(&mut rng),
                OutputKind::Transfer,
            )
            .unwrap();
            let f = fields(&o, OutputKind::Transfer);
            let got = scan_output(bob.view_keys(), &bob_table, &[i as u8; 32], &f);
            assert!(matches!(got, ScanOutcome::NotOwned));
            // Count how often the view tag alone would have matched.
            let s =
                SharedSecret::from_point(&(bob.view_keys().view_secret() * f.ephemeral.point()));
            if view_tag(&s) == f.view_tag {
                tag_hits += 1;
            }
        }
        // View tags filter ~255/256 of foreign outputs.
        assert!(tag_hits <= 6, "{tag_hits}");
    }

    #[test]
    fn view_only_wallet_scans_like_full_wallet() {
        let mut rng = seeded(12);
        let (w, _) = WalletKeys::generate(&mut rng);
        // A view-only wallet is built from (k_v, K_s) alone.
        let view_only =
            ViewKeys::new(*w.view_keys().view_secret(), *w.view_keys().spend_public()).unwrap();
        let table = SubaddressTable::new(&view_only, 1, 5);
        let ctx = [3u8; 32];
        let o = create_output(
            &w.address(SubaddressIndex::new(0, 4)),
            777,
            &ctx,
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        let got = scan_output(&view_only, &table, &ctx, &fields(&o, OutputKind::Transfer));
        assert_eq!(got.owned().unwrap().amount, 777);
    }

    #[test]
    fn wrong_context_is_rejected() {
        // The anchor binds the output to its transaction's input context.
        let mut rng = seeded(13);
        let (w, _) = WalletKeys::generate(&mut rng);
        let table = SubaddressTable::new(w.view_keys(), 1, 2);
        let o = create_output(
            &w.address(SubaddressIndex::PRIMARY),
            1,
            &[1; 32],
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        let got = scan_output(
            w.view_keys(),
            &table,
            &[2; 32],
            &fields(&o, OutputKind::Transfer),
        );
        assert!(matches!(
            got,
            ScanOutcome::Rejected {
                reason: ScanRejection::JanusAnchorMismatch,
                ..
            }
        ));
    }

    #[test]
    fn bogus_amount_is_rejected() {
        let mut rng = seeded(14);
        let (w, _) = WalletKeys::generate(&mut rng);
        let table = SubaddressTable::new(w.view_keys(), 1, 1);
        let ctx = [0u8; 32];
        let mut o = create_output(
            &w.address(SubaddressIndex::PRIMARY),
            100,
            &ctx,
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        // A sender claims 1,000,000 in the encrypted field but commits to 100
        // (XOR the plaintext difference into the ciphertext).
        let lie = 1_000_000u64.to_le_bytes();
        for ((e, h), l) in o.enc_amount.iter_mut().zip(100u64.to_le_bytes()).zip(lie) {
            *e ^= h ^ l;
        }
        let got = scan_output(
            w.view_keys(),
            &table,
            &ctx,
            &fields(&o, OutputKind::Transfer),
        );
        assert!(matches!(
            got,
            ScanOutcome::Rejected {
                reason: ScanRejection::CommitmentMismatch,
                ..
            }
        ));
    }

    #[test]
    fn outputs_to_the_same_address_are_unlinkable_on_chain() {
        // Two payments to one address share no public field.
        let mut rng = seeded(15);
        let (w, _) = WalletKeys::generate(&mut rng);
        let addr = w.address(SubaddressIndex::PRIMARY);
        let a = create_output(
            &addr,
            5,
            &[1; 32],
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        let b = create_output(
            &addr,
            5,
            &[1; 32],
            &random_anchor(&mut rng),
            OutputKind::Transfer,
        )
        .unwrap();
        assert_ne!(a.one_time_key, b.one_time_key);
        assert_ne!(a.ephemeral, b.ephemeral);
        assert_ne!(a.commitment, b.commitment);
        assert_ne!(a.enc_amount, b.enc_amount);
        assert_ne!(a.enc_anchor, b.enc_anchor);
        assert_ne!(a.one_time_key.bytes(), addr.spend().bytes());
    }
}
