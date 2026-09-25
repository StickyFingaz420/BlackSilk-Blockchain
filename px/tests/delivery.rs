//! Record delivery: only the addressed recipient opens a ciphertext, every
//! tampering is detected, and records inconsistent with the commitment are
//! refused (docs/px.md §6). Contract records reach the party they are
//! addressed to, and openings can be shared off chain (§13).

use blacksilk_px::delivery::{open, seal, SealError, CIPHERTEXT_BYTES};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::share::{open_share, seal_share, SHARE_BYTES};
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
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

const CONTRACT: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];

fn contract_record(rng: &mut rand_chacha::ChaCha20Rng, value: u64) -> Record {
    Record {
        owner: ZERO_DIGEST,
        contract: CONTRACT,
        asset: ZERO_DIGEST,
        value,
        data: [7; 8],
        rho: wallet::random_digest(rng),
        rcm: wallet::random_digest(rng),
    }
}

/// A contract record (owner 0) is delivered to whichever address its creator
/// chose; it opens there, as a contract record, and nowhere else. Its
/// ciphertext has the same length as a user record's.
#[test]
fn contract_records_reach_the_addressed_party() {
    let (mut rng, bob, eve) = setup();
    let rec = contract_record(&mut rng, 500);
    let cm = rec.commit(&mut HostPerm::new());
    let to = bob.address(2);
    let c = seal(&mut rng, &to, &rec, &cm).unwrap();
    assert_eq!(c.len(), CIPHERTEXT_BYTES);
    let got = open(&bob.delivery_keys(2), &to.owner, &c, &cm, &rec.rho).unwrap();
    assert_eq!(got, rec);
    assert_eq!((got.owner, got.contract), (ZERO_DIGEST, CONTRACT));
    assert_eq!(
        open(&bob.delivery_keys(3), &bob.owner(3), &c, &cm, &rec.rho),
        None
    );
    assert_eq!(
        open(&eve.delivery_keys(2), &eve.owner(2), &c, &cm, &rec.rho),
        None
    );
}

/// The record kind is bound by the commitment: a sender cannot present a user
/// record as a contract record, or a contract record as the recipient's own.
#[test]
fn the_record_kind_cannot_be_misrepresented() {
    let (mut rng, bob, _) = setup();
    let to = bob.address(0);
    let keys = bob.delivery_keys(0);
    // A user record, claimed to be a contract record.
    let user = Record::plain(to.owner, 5, [0; 8], wallet::random_digest(&mut rng), [3; 8]);
    let cm = user.commit(&mut HostPerm::new());
    let mut probe = user;
    probe.contract = CONTRACT;
    let c = seal(&mut rng, &to, &probe, &cm).unwrap();
    assert_eq!(open(&keys, &to.owner, &c, &cm, &user.rho), None);
    // A contract record, claimed to be a user record of the recipient.
    let rec = contract_record(&mut rng, 9);
    let cm = rec.commit(&mut HostPerm::new());
    let mut probe = rec;
    probe.contract = ZERO_DIGEST;
    let c = seal(&mut rng, &to, &probe, &cm).unwrap();
    assert_eq!(open(&keys, &to.owner, &c, &cm, &rec.rho), None);
}

/// Off-chain sharing: only the addressee opens a share, which yields the
/// record and its commitment; any change is refused.
#[test]
fn shared_openings_reach_only_their_addressee() {
    let (mut rng, bob, eve) = setup();
    let rec = contract_record(&mut rng, 77);
    let cm = rec.commit(&mut HostPerm::new());
    let to = eve.address(5);
    let share = seal_share(&mut rng, &to, &rec, &cm).unwrap();
    assert_eq!(share.len(), SHARE_BYTES);
    assert_eq!(
        open_share(&eve.delivery_keys(5), &to.owner, &share),
        Some((rec, cm))
    );
    assert_eq!(
        open_share(&bob.delivery_keys(5), &bob.owner(5), &share),
        None
    );
    // Version, commitment, rho, ciphertext and length are all checked.
    for pos in [0, 1, 40, 70, SHARE_BYTES - 1] {
        let mut t = share.clone();
        t[pos] ^= 1;
        assert_eq!(
            open_share(&eve.delivery_keys(5), &to.owner, &t),
            None,
            "byte {pos}"
        );
    }
    assert_eq!(
        open_share(&eve.delivery_keys(5), &to.owner, &share[..SHARE_BYTES - 1]),
        None
    );
}
