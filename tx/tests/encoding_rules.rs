//! Encoding rules of tx/src/types.rs that mutation run E
//! (docs/evidence/mutation-runE-2026-10-01/) found untested: T1's size caps
//! at the decoder are inclusive, per kind, and the CLSAG message of a
//! transfer covers its range proof (spec §4.4).

mod common;

use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::codec::DecodeError;
use blacksilk_tx::params::*;
use blacksilk_tx::types::Transaction;
use common::*;

/// A buffer of exactly a kind's cap is not refused for its size (it fails
/// later, on its all-zero body); one byte more is. The PX and deploy caps
/// are above the transfer cap, so a PX transaction or a deploy is not held
/// to the transfer's 100 000 bytes.
#[test]
fn each_kinds_size_cap_is_inclusive() {
    const { assert!(MAX_PX_TX_SIZE > MAX_TX_SIZE && MAX_DEPLOY_TX_SIZE > MAX_TX_SIZE) };
    for (kind, cap) in [
        (KIND_COINBASE, MAX_TX_SIZE),
        (KIND_TRANSFER, MAX_TX_SIZE),
        (KIND_PX, MAX_PX_TX_SIZE),
        (KIND_PX_DEPLOY, MAX_DEPLOY_TX_SIZE),
    ] {
        for len in [cap, cap + 1] {
            let mut b = vec![0u8; len];
            b[0] = TX_VERSION as u8;
            b[1] = kind;
            let r = Transaction::decode(&b);
            if len == cap {
                assert!(
                    r.is_err() && r != Err(DecodeError::TooLarge),
                    "kind {kind} at its cap: {r:?}"
                );
            } else {
                assert_eq!(r, Err(DecodeError::TooLarge), "kind {kind} over its cap");
            }
        }
    }
}

/// The range proof is the start of a transfer's prunable part, and the
/// message its CLSAGs sign changes with it: a signed transfer cannot carry
/// another range proof.
#[test]
fn a_transfers_signature_message_covers_its_range_proof() {
    let mut net = TestNet::new(73, 80);
    let alice = Wallet::new(&mut rng(1073));
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    let domain = net.rules.domain();
    let rp = tx.range_proof_bytes();
    // 3 points, 3 scalars, then L and R (one point per round each).
    assert_eq!(rp.len(), 32 * (6 + 2 * tx.range_proof.l.len()));
    assert!(tx.prunable_bytes().starts_with(&rp));
    assert_eq!(&rp[..32], tx.range_proof.a.bytes());

    let mut other = tx.clone();
    other.range_proof.a = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(5u64)));
    assert_ne!(other.range_proof_bytes(), rp);
    assert_ne!(
        other.signature_message(domain),
        tx.signature_message(domain)
    );
    // Nothing else changed: the prefix and the pseudo-outputs are the same.
    assert_eq!(other.prefix_bytes(), tx.prefix_bytes());
    assert_eq!(other.base_bytes(), tx.base_bytes());
}

/// The CLSAG message of a transfer covers its pseudo-outputs (spec §4.4:
/// the base part), not only through each signature's own transcript
/// (RT-MUTE: with the base hash left out of the message, every tx test
/// passed; only the node's pinned fingerprint sample would notice).
#[test]
fn a_transfers_signature_message_covers_its_pseudo_outputs() {
    let mut net = TestNet::new(74, 80);
    let alice = Wallet::new(&mut rng(1074));
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    let domain = net.rules.domain();
    let mut other = tx.clone();
    other.pseudo_outs[0] = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(5u64)));
    assert_eq!(other.prefix_bytes(), tx.prefix_bytes());
    assert_eq!(other.range_proof_bytes(), tx.range_proof_bytes());
    assert_ne!(
        other.signature_message(domain),
        tx.signature_message(domain)
    );
}
