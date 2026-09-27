//! Transaction non-malleability (T-1 a).
//!
//! Exhaustive single-byte mutations of a valid transfer and a valid coinbase:
//! every mutant that still decodes must
//! - re-encode to exactly its own bytes (one encoding per object),
//! - have a different transaction id from the original (two distinct encodings
//!   never share an id), and
//! - for a transfer, be rejected by full validation (a third party cannot turn a
//!   valid transaction into a different valid one).
//!
//! A coinbase is not signed, so a changed coinbase can be valid; its id changes,
//! which changes the block's `tx_root` and therefore the block id
//! (`chain/tests/block_malleability.rs`).
//!
//! Also: the non-canonical encodings `s + ℓ` of every CLSAG and Bulletproofs+
//! scalar, and the non-canonical encoding `p − s` of every point of a transfer,
//! are rejected by decoding.
//!
//! No PX proving here (PX transaction malleability: `fuzz_decode.rs`).

mod common;

use blacksilk_crypto::Scalar;
use blacksilk_tx::codec::DecodeError;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::validate_mempool_tx;
use common::*;

/// Single-byte mutations applied at every position.
type Mutation = (&'static str, fn(u8) -> u8);
const MUTATIONS: [Mutation; 5] = [
    ("xor 0x01", |b| b ^ 0x01),
    ("xor 0x80", |b| b ^ 0x80),
    ("xor 0x10", |b| b ^ 0x10),
    ("set 0x00", |_| 0x00),
    ("set 0xff", |_| 0xff),
];

#[derive(Default, Debug)]
struct Tally {
    mutants: usize,
    decoded: usize,
    rejected: usize,
}

fn sweep(bytes: &[u8], mut on_decoded: impl FnMut(usize, &str, Transaction, &[u8])) -> Tally {
    let original = Transaction::decode(bytes).expect("seed decodes");
    let id = original.hash();
    let mut t = Tally::default();
    for pos in 0..bytes.len() {
        for (name, f) in MUTATIONS {
            let mut m = bytes.to_vec();
            m[pos] = f(m[pos]);
            if m == bytes {
                continue;
            }
            t.mutants += 1;
            let Ok(tx) = Transaction::decode(&m) else {
                continue;
            };
            t.decoded += 1;
            assert_eq!(tx.encode(), m, "byte {pos} {name}: not canonical");
            assert_ne!(tx.hash(), id, "byte {pos} {name}: same id, different bytes");
            assert_ne!(tx, original);
            on_decoded(pos, name, tx, &m);
        }
    }
    t
}

#[test]
fn every_decodable_transfer_mutant_is_rejected_or_distinct() {
    let mut net = TestNet::new(501, 90);
    let payer = net.miner_clone();
    let alice = Wallet::new(&mut net.rng);
    let transfer = Transaction::from(net.pay(&payer, &[(alice.primary(), 12_345)]));
    let height = net.height();
    assert_eq!(
        validate_mempool_tx(&transfer, &net.chain, height, &net.rules),
        Ok(())
    );
    let bytes = transfer.encode();
    let mut rejected = 0;
    let t = sweep(&bytes, |pos, name, tx, _| {
        assert!(
            validate_mempool_tx(&tx, &net.chain, height, &net.rules).is_err(),
            "transfer mutant at byte {pos} ({name}) validates"
        );
        rejected += 1;
    });
    let t = Tally { rejected, ..t };
    println!("transfer: {} bytes, {t:?}", bytes.len());
    assert_eq!(t.mutants, bytes.len() * MUTATIONS.len() - skipped(&bytes));
    assert_eq!(t.rejected, t.decoded);
    assert!(t.decoded > 0, "the sweep must reach validation");
}

#[test]
fn every_decodable_coinbase_mutant_has_a_different_id() {
    let mut net = TestNet::new(502, 1);
    let coinbase = net.coinbase(0);
    let bytes = coinbase.encode();
    let t = sweep(&bytes, |_, _, _, _| {});
    println!("coinbase: {} bytes, {t:?}", bytes.len());
    assert!(t.decoded > 0);
}

/// Mutations that leave the byte unchanged (skipped by `sweep`).
fn skipped(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .map(|&b| MUTATIONS.iter().filter(|(_, f)| f(b) == b).count())
        .sum()
}

// ---------------------------------------------------- non-canonical encodings

/// ℓ and p = 2^255 − 19, little-endian.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
const P_BYTES: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut out, mut carry) = ([0u8; 32], 0u16);
    for i in 0..32 {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    out
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut out, mut borrow) = ([0u8; 32], 0i16);
    for i in 0..32 {
        let mut v = a[i] as i16 - b[i] as i16 - borrow;
        borrow = (v < 0) as i16;
        if v < 0 {
            v += 256;
        }
        out[i] = v as u8;
    }
    assert_eq!(borrow, 0);
    out
}

/// Replaces the (unique) occurrence of `field` in `bytes` with `with`.
fn replace(bytes: &[u8], field: &[u8; 32], with: &[u8; 32]) -> Vec<u8> {
    let hits: Vec<usize> = (0..=bytes.len() - 32)
        .filter(|&i| &bytes[i..i + 32] == field)
        .collect();
    assert_eq!(hits.len(), 1, "field occurs once");
    let mut m = bytes.to_vec();
    m[hits[0]..hits[0] + 32].copy_from_slice(with);
    m
}

#[test]
fn non_canonical_scalars_and_points_do_not_decode() {
    let mut net = TestNet::new(503, 90);
    let payer = net.miner_clone();
    let alice = Wallet::new(&mut net.rng);
    let tx = net.pay(&payer, &[(alice.primary(), 777)]);
    let bytes = Transaction::from(tx.clone()).encode();

    // Scalars: s + ℓ (reduces to s, so a reducing decoder would accept a second
    // encoding of the same signature/proof).
    let mut scalars: Vec<(String, Scalar)> = vec![
        ("r1".into(), tx.range_proof.r1),
        ("s1".into(), tx.range_proof.s1),
        ("d1".into(), tx.range_proof.d1),
    ];
    for (k, sig) in tx.signatures.iter().enumerate() {
        scalars.push((format!("clsag[{k}].c0"), sig.c0));
        for (i, s) in sig.s.iter().enumerate() {
            scalars.push((format!("clsag[{k}].s[{i}]"), *s));
        }
    }
    for (what, s) in &scalars {
        let m = replace(&bytes, &s.to_bytes(), &add(&s.to_bytes(), &L_BYTES));
        assert_eq!(
            Transaction::decode(&m),
            Err(DecodeError::InvalidScalar),
            "{what} + ℓ"
        );
    }

    // Points: p − s encodes the same Ristretto element as s ("negative" field
    // element) and must be refused, as must s + p where it fits (s < 19 only).
    let mut points = vec![
        ("A", tx.range_proof.a),
        ("A1", tx.range_proof.a1),
        ("B", tx.range_proof.b),
    ];
    for l in &tx.range_proof.l {
        points.push(("L", *l));
    }
    for r in &tx.range_proof.r {
        points.push(("R", *r));
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        points.push(("key image", input.key_image));
        points.push(("pseudo-out", tx.pseudo_outs[i]));
        points.push(("D", tx.signatures[i].d));
    }
    for o in &tx.outputs {
        points.push(("one-time key", o.one_time_key));
        points.push(("ephemeral", o.ephemeral));
        points.push(("commitment", o.commitment));
    }
    for (what, p) in &points {
        let m = replace(&bytes, p.bytes(), &sub(&P_BYTES, p.bytes()));
        assert_eq!(
            Transaction::decode(&m),
            Err(DecodeError::InvalidPoint),
            "{what}: p − s"
        );
        let mut high = *p.bytes();
        high[31] |= 0x80;
        let m = replace(&bytes, p.bytes(), &high);
        assert_eq!(
            Transaction::decode(&m),
            Err(DecodeError::InvalidPoint),
            "{what}: high bit"
        );
    }
    println!(
        "{} scalars and {} points checked",
        scalars.len(),
        points.len()
    );
}
