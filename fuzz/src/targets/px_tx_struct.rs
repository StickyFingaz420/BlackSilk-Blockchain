//! Target body: structure-aware PX transaction edits (W4-FUZZ2). The input is
//! an edit script applied to the DECODED fields of one real PX transaction
//! (inputs, outputs, payouts, amounts, the validity window, the public
//! statement, ciphertexts, functions, pseudo-outputs, the range proof,
//! signatures and the proof bytes); the edited transaction is re-encoded, so
//! the framing stays consistent and the decoder's and the stateless rules'
//! own checks are what refuses it.
//!
//! Input: 4 bytes per edit, `site, a, b, c` (missing bytes are zero); at
//! most 64 edits.
//!
//! Invariants, beyond "no panic":
//! - encoding the edited transaction and decoding it gives back exactly the
//!   edited transaction, or a decode error (the decoder never "repairs" a
//!   value), whenever the edited value's encoding carries every length the
//!   decoder needs (`self_delimited`: five lengths are implied by other
//!   fields, as the format intends);
//! - a decoded transaction re-encodes to the same bytes, and
//!   `encoded_len` is the length of its encoding;
//! - the stateless rules (`check_px_structure`, `check_px_balance`), the
//!   binding, the public statement, the hash and the weight never panic.

use blacksilk_crypto::bulletproofs_plus::rounds;
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px_core::P;
use blacksilk_tx::px::{check_px_balance, check_px_structure, PxFunction, PxTx};
use blacksilk_tx::types::Transaction;

/// Values an amount is set to: the edges of `u64`, of the field, and of the
/// money supply's order of magnitude.
const AMOUNTS: [u64; 8] = [
    0,
    1,
    u64::MAX,
    u64::MAX - 1,
    P as u64,
    (P as u64) << 31,
    1 << 63,
    10_000_000,
];

/// Words a digest element is set to: the field's edges, and beyond.
const WORDS: [u32; 6] = [0, 1, P - 1, P, P + 1, u32::MAX];

pub fn run(base: &PxTx, domain: blacksilk_tx::params::SigDomain, data: &[u8]) {
    let mut tx = base.clone();
    for step in data.chunks(4).take(64) {
        let [site, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
        edit(&mut tx, site, a as usize, b as usize, c);
    }
    let framed = self_delimited(&tx);
    let edited = Transaction::Px(Box::new(tx));
    let bytes = edited.encode();
    let Ok(decoded) = Transaction::decode(&bytes) else {
        return;
    };
    if framed {
        assert_eq!(decoded, edited, "decoding returns exactly what was encoded");
    }
    assert_eq!(
        decoded.encode(),
        bytes,
        "a decoded transaction re-encodes exactly"
    );
    let _ = decoded.hash();
    let _ = decoded.weight();
    let Transaction::Px(t) = &decoded else {
        panic!("a PX transaction decodes as another kind");
    };
    assert_eq!(t.encoded_len(), bytes.len(), "encoded_len");
    let _ = check_px_structure(t);
    let _ = check_px_balance(t);
    let _ = t.binding(domain);
    let _ = t.public();
    let _ = t.output_keys();
}

/// Whether `t`'s encoding carries every length the decoder needs. Five
/// lengths are implied rather than written: each ciphertext is
/// `CIPHERTEXT_BYTES`; there is one pseudo-output and one signature per
/// input; a range proof exactly when there are outputs, with
/// `rounds(outputs)` points in each of `l` and `r`. A value that breaks one
/// of them is outside the decoder's range (no decoding produces it, and
/// only a local builder could), so its bytes may decode to another value;
/// for it only the canonical re-encoding is checked.
fn self_delimited(t: &PxTx) -> bool {
    let n = t.inputs.len();
    let bpp_ok = match (&t.range_proof, rounds(t.outputs.len())) {
        (None, _) => t.outputs.is_empty(),
        (Some(p), Some(k)) => p.l.len() == k && p.r.len() == k,
        (Some(_), None) => false,
    };
    t.ciphertexts.iter().all(|c| c.len() == CIPHERTEXT_BYTES)
        && t.pseudo_outs.len() == n
        && t.signatures.len() == n
        && bpp_ok
}

fn vec_edit<T: Clone>(v: &mut Vec<T>, a: usize, b: usize, op: u8) {
    let n = v.len();
    match op % 7 {
        0 => v.truncate(a % (n + 1)),
        1 if n > 0 => {
            v.remove(a % n);
        }
        2 if n > 0 => {
            let x = v[a % n].clone();
            v.insert(b % (n + 1), x);
        }
        3 if n > 0 => v.swap(a % n, b % n),
        4 if n > 0 => {
            let x = v[n - 1].clone();
            for _ in 0..1 + b % 20 {
                v.push(x.clone());
            }
        }
        5 => v.clear(),
        6 => v.reverse(),
        _ => {}
    }
}

fn amount(x: &mut u64, a: usize, c: u8) {
    *x = match c % 4 {
        0 => AMOUNTS[a % AMOUNTS.len()],
        1 => x.wrapping_add(1 + a as u64),
        2 => x.wrapping_sub(1 + a as u64),
        _ => *x ^ (1 << (a % 64)),
    };
}

fn word(d: &mut [u32; 8], a: usize, b: usize) {
    d[a % 8] = WORDS[b % WORDS.len()];
}

fn edit(t: &mut PxTx, site: u8, a: usize, b: usize, c: u8) {
    match site % 24 {
        0 => vec_edit(&mut t.inputs, a, b, c),
        1 => {
            // A ring member, or a key image taken from another point.
            if let Some(n) = t.inputs.len().checked_sub(1) {
                let i = &mut t.inputs[a % (n + 1)];
                if c & 1 == 0 {
                    let r = b % i.ring.len();
                    i.ring[r] = match c % 4 {
                        0 => 0,
                        _ => i.ring[r].wrapping_add(1 + (c as u64 >> 2)),
                    };
                } else if let Some(o) = t.outputs.first() {
                    i.key_image = o.one_time_key;
                }
            }
        }
        2 => vec_edit(&mut t.outputs, a, b, c),
        3 => {
            if let Some(n) = t.outputs.len().checked_sub(1) {
                let o = &mut t.outputs[a % (n + 1)];
                match c % 3 {
                    0 => o.view_tag = b as u8,
                    1 => o.enc_amount[b % 8] ^= 1 << (c % 8),
                    _ => std::mem::swap(&mut o.one_time_key, &mut o.commitment),
                }
            }
        }
        4 => vec_edit(&mut t.payouts, a, b, c),
        5 => {
            if let Some(n) = t.payouts.len().checked_sub(1) {
                amount(&mut t.payouts[a % (n + 1)].amount, b, c);
            }
        }
        6 => amount(&mut t.fee, a, c),
        7 => amount(&mut t.bridge_in, a, c),
        8 => amount(&mut t.bridge_out, a, c),
        9 => {
            if c & 1 == 0 {
                amount(&mut t.window.not_before, a, c >> 1);
            } else {
                amount(&mut t.window.not_after, a, c >> 1);
            }
        }
        10 => word(&mut t.anchor, a, b),
        11 => word(&mut t.nullifiers[c as usize % 2], a, b),
        12 => word(&mut t.commitments[c as usize % 2], a, b),
        13 => match c % 3 {
            0 => t.nullifiers[1] = t.nullifiers[0],
            1 => t.nullifiers.swap(0, 1),
            _ => t.commitments.swap(0, 1),
        },
        14 => vec_edit(&mut t.ciphertexts[b % 2], a, b, c),
        15 => t.ciphertexts.swap(0, 1),
        16 => {
            // Add a function (the statement's function count changes).
            if c & 1 == 0 {
                let f = PxFunction {
                    contract: [a as u32; 8],
                    program_id: [b as u8; 32],
                    io_hash: t.anchor,
                    outputs: vec![b as u32; c as usize % 9],
                };
                for _ in 0..1 + a % 3 {
                    t.functions.push(f.clone());
                }
            } else {
                vec_edit(&mut t.functions, a, b, c >> 1);
            }
        }
        17 => {
            if let Some(n) = t.functions.len().checked_sub(1) {
                let f = &mut t.functions[a % (n + 1)];
                match c % 3 {
                    0 => vec_edit(&mut f.outputs, a, b, c >> 2),
                    1 => word(&mut f.contract, a, b),
                    _ => word(&mut f.io_hash, a, b),
                }
            }
        }
        18 => vec_edit(&mut t.pseudo_outs, a, b, c),
        19 => {
            // Drop the range proof, or resize its vectors.
            match (c % 3, t.range_proof.as_mut()) {
                (0, _) => t.range_proof = None,
                (1, Some(r)) => vec_edit(&mut r.l, a, b, c >> 2),
                (_, Some(r)) => vec_edit(&mut r.r, a, b, c >> 2),
                _ => {}
            }
        }
        20 => vec_edit(&mut t.signatures, a, b, c),
        21 => {
            if let Some(n) = t.signatures.len().checked_sub(1) {
                let s = &mut t.signatures[a % (n + 1)];
                match c % 3 {
                    0 => {
                        let n = s.s.len();
                        s.s.swap(b % n, (b / 16) % n);
                    }
                    1 => s.c0 = s.s[b % s.s.len()],
                    _ => {
                        if let Some(p) = t.pseudo_outs.first() {
                            s.d = *p;
                        }
                    }
                }
            }
        }
        22 => vec_edit(&mut t.proof, a * 257 + b, b, c),
        _ => {
            if !t.proof.is_empty() {
                let n = t.proof.len();
                t.proof[(a * 256 + b) % n] ^= 1 << (c % 8);
            }
        }
    }
}

/// Seed inputs (named): one per kind of edit, and the unedited transaction.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("none", vec![]),
        ("drop_input", vec![0, 0, 0, 1]),
        ("ring_member", vec![1, 0, 3, 2]),
        ("dup_output", vec![2, 0, 0, 2]),
        ("payout", vec![4, 0, 0, 4]),
        ("fee_max", vec![6, 2, 0, 0]),
        ("bridge_in_field", vec![7, 4, 0, 0]),
        ("window", vec![9, 3, 0, 1]),
        ("anchor_p", vec![10, 0, 3, 0]),
        ("same_nullifiers", vec![13, 0, 0, 0]),
        ("ciphertext_short", vec![14, 100, 0, 0]),
        ("function", vec![16, 0, 1, 2]),
        ("no_range_proof", vec![19, 0, 0, 0]),
        // W4-FUZZ2's first crash: `l` one point short, `r` one long (the
        // implied lengths; `self_delimited`).
        ("bpp_l_short_r_long", vec![19, 5, 0, 28, 19, 0, 0, 17]),
        ("drop_signature", vec![20, 0, 0, 1]),
        ("proof_empty", vec![22, 0, 0, 5]),
    ]
}
