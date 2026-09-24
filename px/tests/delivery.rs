//! Record delivery: only the addressed recipient opens a ciphertext, every
//! tampering is detected, and records inconsistent with the commitment are
//! refused (docs/px.md §6).

use blacksilk_px::delivery::{open, seal, SealError, CIPHERTEXT_BYTES};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use rand_chacha::rand_core::SeedableRng;

fn setup() -> (rand_chacha::ChaCha20Rng, Account, Account) {
    (
        rand_chacha::ChaCha20Rng::seed_from_u64(21),
        Account::from_seed(&[5; 32]),
        Account::from_seed(&[6; 32]),
    )
}

#[test]
fn the_recipient_opens_and_nobody_else_does() {
    let (mut rng, bob, eve) = setup();
    let addr = bob.address(3);
    let rho = wallet::random_digest(&mut rng);
    let rec = Record::plain(
        addr.owner,
        123_456_789,
        [9; 8],
        rho,
        wallet::random_digest(&mut rng),
    );
    let cm = rec.commit(&mut HostPerm::new());
    let c = seal(&mut rng, &addr, &rec, &cm).unwrap();
    assert_eq!(c.len(), CIPHERTEXT_BYTES);
    assert_eq!(
        open(&bob.delivery_keys(3), &addr.owner, &c, &cm, &rho),
        Some(rec)
    );
    // Another address of the same wallet, or another wallet, cannot open it.
    assert_eq!(
        open(&bob.delivery_keys(4), &bob.owner(4), &c, &cm, &rho),
        None
    );
    assert_eq!(
        open(&eve.delivery_keys(3), &eve.owner(3), &c, &cm, &rho),
        None
    );
    // Addresses of one wallet share nothing visible.
    let a4 = bob.address(4);
    assert_ne!(addr.view, a4.view);
    assert_ne!(addr.ek, a4.ek);
    assert_ne!(addr.owner, a4.owner);
}

#[test]
fn every_tampering_is_detected() {
    let (mut rng, bob, _) = setup();
    let addr = bob.address(0);
    let keys = bob.delivery_keys(0);
    let rho = wallet::random_digest(&mut rng);
    let rec = Record::plain(addr.owner, 42, [0; 8], rho, wallet::random_digest(&mut rng));
    let cm = rec.commit(&mut HostPerm::new());
    let c = seal(&mut rng, &addr, &rec, &cm).unwrap();
    // Flip one bit in every region: R, tag, KEM ciphertext, body, AEAD tag.
    for pos in [
        0,
        31,
        32,
        33,
        500,
        33 + 1087,
        33 + 1088,
        CIPHERTEXT_BYTES - 1,
    ] {
        let mut t = c.clone();
        t[pos] ^= 1;
        assert_eq!(open(&keys, &addr.owner, &t, &cm, &rho), None, "byte {pos}");
    }
    // The ciphertext is bound to its commitment and rho.
    let mut other_cm = cm;
    other_cm[0] ^= 1;
    assert_eq!(open(&keys, &addr.owner, &c, &other_cm, &rho), None);
    let mut other_rho = rho;
    other_rho[0] ^= 1;
    assert_eq!(open(&keys, &addr.owner, &c, &cm, &other_rho), None);
    assert_eq!(open(&keys, &addr.owner, &c[..c.len() - 1], &cm, &rho), None);
}

/// Janus principle: a sender that encrypts contents different from the
/// committed record (a probe) is ignored by the recipient.
#[test]
fn a_record_inconsistent_with_its_commitment_is_refused() {
    let (mut rng, bob, _) = setup();
    let addr = bob.address(1);
    let rho = wallet::random_digest(&mut rng);
    let real = Record::plain(addr.owner, 10, [0; 8], rho, wallet::random_digest(&mut rng));
    let cm = real.commit(&mut HostPerm::new());
    let mut probe = real;
    probe.value = 11;
    let c = seal(&mut rng, &addr, &probe, &cm).unwrap();
    assert_eq!(
        open(&bob.delivery_keys(1), &addr.owner, &c, &cm, &rho),
        None
    );
}

#[test]
fn malformed_addresses_are_refused() {
    let (mut rng, bob, _) = setup();
    let mut addr = bob.address(0);
    let rec = Record::plain(addr.owner, 1, [0; 8], [1; 8], [2; 8]);
    let cm = rec.commit(&mut HostPerm::new());
    addr.ek.pop();
    assert_eq!(seal(&mut rng, &addr, &rec, &cm), Err(SealError::BadAddress));
    let mut addr = bob.address(0);
    addr.view = [0xff; 32];
    assert_eq!(seal(&mut rng, &addr, &rec, &cm), Err(SealError::BadAddress));
}
