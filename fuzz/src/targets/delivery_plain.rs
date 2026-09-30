//! Target body (RT-FUZZ): record delivery from a MALICIOUS SENDER. The
//! sender knows its own ephemeral secrets, so it can make the victim's view
//! tag and AEAD pass for any plaintext it likes. `delivery_open` cannot
//! reach the code after decryption (a mutated ciphertext fails the tag or
//! the AEAD); this target seals fuzzed plaintexts with the real `seal` and
//! checks what `open` and `open_share` do with them.
//!
//! Input: a mode byte, then words (LE u32): contract (8), value (2), data
//! (8), rcm (8), rho (8), cm (8), owner (8). Missing bytes are zero.
//! Mode bits: 1 = reduce contract/data/rcm mod P (reach the commitment
//! check); 2 = cm is the honest commitment of the record the victim
//! rebuilds (when it can be computed); 4 = contract zero (a user record);
//! 8 = the honest commitment uses the input's `owner` instead of the
//! victim's (a record paid to someone else, re-encrypted to the victim).
//!
//! Invariants, beyond "no panic":
//! - `open` returns a record exactly when contract, data and rcm are
//!   canonical and the rebuilt record (owner = the victim's tag for a user
//!   record, 0 for a contract record) commits to `cm`; and then it is that
//!   record;
//! - the same ciphertext under another `cm` never opens (AAD binding);
//! - `open_share` of the same delivery as a share gives the same verdict.

use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::share;
use blacksilk_px::wallet::Account;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use rand_chacha::rand_core::SeedableRng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Inputs that opened (a record returned), and contract records among them.
pub static OPENED: AtomicU64 = AtomicU64::new(0);
pub static OPENED_CONTRACT: AtomicU64 = AtomicU64::new(0);

fn victim() -> &'static Account {
    static A: OnceLock<Account> = OnceLock::new();
    A.get_or_init(|| Account::from_seed(&[42; 32]))
}

fn canonical(d: &Digest) -> bool {
    d.iter().all(|&x| x < P)
}

pub fn run(data: &[u8]) {
    let mode = data.first().copied().unwrap_or(0);
    let mut w = [0u32; 50];
    for (i, c) in data.get(1..).unwrap_or(&[]).chunks(4).take(50).enumerate() {
        let mut b = [0u8; 4];
        b[..c.len()].copy_from_slice(c);
        w[i] = u32::from_le_bytes(b);
    }
    let d = |k: usize| -> Digest { w[k..k + 8].try_into().expect("8 words") };
    let (mut contract, value, mut data_d, mut rcm) =
        (d(0), w[8] as u64 | (w[9] as u64) << 32, d(10), d(18));
    let rho = d(26).map(|x| x % P);
    let owner_in = d(42).map(|x| x % P);
    if mode & 1 != 0 {
        for dd in [&mut contract, &mut data_d, &mut rcm] {
            *dd = dd.map(|x| x % P);
        }
    }
    if mode & 4 != 0 {
        contract = ZERO_DIGEST;
    }
    let a = victim();
    let keys = a.delivery_keys(0);
    let to = a.address(0);
    let parse_ok = canonical(&contract) && canonical(&data_d) && canonical(&rcm);
    let rebuilt = Record {
        owner: if contract == ZERO_DIGEST {
            to.owner
        } else {
            ZERO_DIGEST
        },
        contract,
        asset: ZERO_DIGEST,
        value,
        data: data_d,
        rho,
        rcm,
    };
    let mut cm = d(34);
    if mode & 2 != 0 && parse_ok {
        let mut r = rebuilt;
        if mode & 8 != 0 {
            r.owner = owner_in;
        }
        cm = r.commit(&mut HostPerm::new());
    }
    // What the sender encrypts: the plaintext fields (the owner is not in
    // the plaintext; seal only reads contract, value, data, rcm and rho).
    let sent = Record {
        owner: owner_in,
        ..rebuilt
    };
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(mode));
    let ct = delivery::seal(&mut rng, &[0x5e; 32], &to, &sent, &cm).expect("seal");
    let expected = (parse_ok && rebuilt.commit(&mut HostPerm::new()) == cm).then_some(rebuilt);
    let got = delivery::open(&keys, &to.owner, &ct, &cm, &rho);
    assert_eq!(got, expected, "open's verdict (mode {mode})");
    if let Some(r) = expected {
        OPENED.fetch_add(1, Ordering::Relaxed);
        if r.contract != ZERO_DIGEST {
            OPENED_CONTRACT.fetch_add(1, Ordering::Relaxed);
        }
        let mut other = cm;
        other[0] ^= 1;
        assert_eq!(
            delivery::open(&keys, &to.owner, &ct, &other, &rho),
            None,
            "a ciphertext opens under another cm"
        );
    }
    // The same delivery as a share: its header's cm and rho are parsed with
    // the canonical check.
    let sh = share::seal_share(&mut rng, &[0x5e; 32], &to, &sent, &cm).expect("seal_share");
    let got = share::open_share(&keys, &to.owner, &sh);
    let expected_share = if canonical(&cm) {
        expected.map(|r| (r, cm))
    } else {
        None
    };
    assert_eq!(got, expected_share, "open_share's verdict (mode {mode})");
}

/// Seed inputs (named).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let words = |mode: u8, ws: &[u32]| {
        let mut v = vec![mode];
        for x in ws {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    };
    let mut plain = vec![0u32; 50];
    plain[8] = 5;
    for (i, x) in plain.iter_mut().enumerate().skip(10) {
        *x = i as u32;
    }
    let mut contract = plain.clone();
    contract[0] = 0x100;
    let mut noncanon = plain.clone();
    noncanon[12] = P;
    vec![
        ("user_honest", words(2 | 4, &plain)),
        ("contract_honest", words(2, &contract)),
        ("user_other_owner", words(2 | 4 | 8, &plain)),
        ("non_canonical_data", words(4, &noncanon)),
        ("wrong_cm", words(4, &plain)),
        ("empty", vec![]),
    ]
}
