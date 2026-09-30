//! Target body: structure-aware PX proof edits (W4-FUZZ2). Byte-level
//! mutation of a 2.4 MB proof almost never keeps its postcard framing, so
//! `proof_decode` rarely gets past the first broken length. Here the input is
//! an edit script applied to the DECODED fields of one real transfer proof
//! (resize, drop or duplicate vectors; flip options; change the degree bits
//! and the FRI arity schedule; move field elements and commitments between
//! places), and the edited proof is re-encoded, so every length prefix is
//! consistent and the decoder's own rules are what refuses it.
//!
//! Input: 4 bytes per edit, `site, a, b, c` (missing bytes are zero); at
//! most 64 edits. The site picks a field (below), `a` and `b` pick indices,
//! `c` the operation.
//!
//! Invariants, beyond "no panic":
//! - the unedited proof decodes under `prove::PROOF_LIMITS` and has the
//!   statement's shape (checked once per base);
//! - decoding the re-encoded bytes (`decode_proof_with`, PX limits) either
//!   refuses them or returns a proof with exactly those bytes (canonical);
//! - the PX limits are narrower than the envelope: a proof that decodes
//!   under `PROOF_LIMITS` decodes under `DecodeLimits::ENVELOPE` too, to the
//!   same bytes;
//! - the shape check (`prove::check_shape_bits` for the base statement, a
//!   plain transfer) accepts exactly the proofs whose degree bits are the
//!   base's.
//!
//! Not run: `prove::verify`. At about 0.2 s or more per proof it would cap
//! the target at a few executions per second. Fiat-Shamir makes any edit
//! fail the query proof of work (16 bits) long before the FRI checks, so
//! verifying edited proofs shows robustness, not soundness (F41-8).

use blacksilk_px::prove::{check_shape_bits, PROOF_LIMITS};
use blacksilk_px_core::call::{Window, MAX_FN};
use blacksilk_px_core::kernel::Public;
use blacksilk_zk::{decode_proof_with, encode_proof, DecodeLimits, Proof};

/// A proof to edit: its bytes, and the statement it has the shape of.
pub struct Base {
    bytes: Vec<u8>,
    degree_bits: Vec<usize>,
    public: Public,
}

impl Base {
    /// `bytes` must be a PX proof for `public` (with no functions).
    pub fn new(bytes: Vec<u8>, public: Public) -> Self {
        let proof = decode_proof_with(&bytes, &PROOF_LIMITS).expect("the base proof decodes");
        assert_eq!(public.n_fn, 0, "a plain transfer statement");
        let degree_bits = proof.degree_bits.clone();
        assert!(
            shape_ok(&public, &degree_bits),
            "the base proof has its statement's shape"
        );
        Base {
            bytes,
            degree_bits,
            public,
        }
    }

    /// A base for a proof of a plain transfer: the shape does not depend on
    /// the statement's values.
    pub fn transfer(bytes: Vec<u8>) -> Self {
        Base::new(
            bytes,
            Public {
                anchor: [0; 8],
                nullifiers: [[0; 8]; 2],
                commitments: [[0; 8]; 2],
                bridge_in: 0,
                bridge_out: 0,
                n_fn: 0,
                functions: [([0; 8], [0; 8]); MAX_FN],
            },
        )
    }
}

fn shape_ok(public: &Public, degree_bits: &[usize]) -> bool {
    check_shape_bits(
        public,
        &[],
        &Window::UNBOUNDED,
        [1; 32],
        degree_bits,
        |_, _| None,
    )
    .is_ok()
}

pub fn run(base: &Base, data: &[u8]) {
    let mut proof = decode_proof_with(&base.bytes, &PROOF_LIMITS).expect("the base decodes");
    for step in data.chunks(4).take(64) {
        let [site, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
        edit(&mut proof, site, a as usize, b as usize, c);
    }
    let bytes = encode_proof(&proof);
    drop(proof);
    if let Ok(p) = decode_proof_with(&bytes, &PROOF_LIMITS) {
        assert_eq!(
            encode_proof(&p),
            bytes,
            "a decoded proof re-encodes exactly"
        );
        let wide = decode_proof_with(&bytes, &DecodeLimits::ENVELOPE)
            .expect("within the PX limits, within the envelope");
        assert_eq!(encode_proof(&wide), bytes);
        assert_eq!(
            shape_ok(&base.public, &p.degree_bits),
            p.degree_bits == base.degree_bits,
            "the shape check accepts exactly the base's degree bits"
        );
    }
}

/// A vector edit, by `op`: truncate, remove, duplicate, swap, push a copy,
/// clear, reverse, or rotate.
fn vec_edit<T: Clone>(v: &mut Vec<T>, a: usize, b: usize, op: u8) {
    let n = v.len();
    match op % 8 {
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
            for _ in 0..1 + b % 4 {
                v.push(x.clone());
            }
        }
        5 => v.clear(),
        6 => v.reverse(),
        7 if n > 0 => v.rotate_left(a % n),
        _ => {}
    }
}

/// The same for elements that cannot be cloned: truncate, remove, swap,
/// reverse, rotate.
fn vec_edit_move<T>(v: &mut Vec<T>, a: usize, b: usize, op: u8) {
    let n = v.len();
    match op % 5 {
        0 => v.truncate(a % (n + 1)),
        1 if n > 0 => {
            v.remove(a % n);
        }
        2 if n > 0 => v.swap(a % n, b % n),
        3 => v.reverse(),
        4 if n > 0 => v.rotate_left(a % n),
        _ => {}
    }
}

/// An edit of a nested vector: `op`'s high bits pick the depth.
fn nested2<T: Clone>(v: &mut Vec<Vec<T>>, a: usize, b: usize, op: u8) {
    if op & 0x80 == 0 || v.is_empty() {
        vec_edit(v, a, b, op);
    } else {
        let n = v.len();
        vec_edit(&mut v[a % n], b, a, op);
    }
}

fn nested3<T: Clone>(v: &mut Vec<Vec<Vec<T>>>, a: usize, b: usize, op: u8) {
    if op & 0x40 == 0 || v.is_empty() {
        nested2(v, a, b, op);
    } else {
        let n = v.len();
        nested2(&mut v[a % n], b, a, op);
    }
}

fn nested4<T: Clone>(v: &mut Vec<Vec<Vec<Vec<T>>>>, a: usize, b: usize, op: u8) {
    if op & 0x20 == 0 || v.is_empty() {
        nested3(v, a, b, op);
    } else {
        let n = v.len();
        nested3(&mut v[a % n], b, a, op);
    }
}

/// Flips an option: `Some` to `None`, `None` to `Some(fill())`.
fn flip<T>(o: &mut Option<T>, fill: impl FnOnce() -> Option<T>) {
    *o = match o.take() {
        Some(_) => None,
        None => fill(),
    };
}

/// Interesting degree bits: small, around the real ones, and large.
fn bits(b: usize, c: u8) -> usize {
    match c % 4 {
        0 => b % 32,
        1 => b,
        2 => usize::MAX - b % 4,
        _ => 1 << (b % 64),
    }
}

fn edit(p: &mut Proof, site: u8, a: usize, b: usize, c: u8) {
    let n_inst = p.opened_values.instances.len();
    match site % 32 {
        // The degree bits (the statement's shape).
        0 => {
            if let Some(n) = p.degree_bits.len().checked_sub(1) {
                p.degree_bits[a % (n + 1)] = bits(b, c);
            }
        }
        1 => vec_edit(&mut p.degree_bits, a, b, c),
        // Lookup terminals.
        2 => vec_edit(&mut p.lookup_terminals, a, b, c),
        3 => {
            let some = p.lookup_terminals.iter().flatten().next().copied();
            if let Some(n) = p.lookup_terminals.len().checked_sub(1) {
                flip(&mut p.lookup_terminals[a % (n + 1)], || some);
            }
        }
        // Opened values per instance.
        4 => vec_edit_move(&mut p.opened_values.instances, a, b, c),
        5..=13 if n_inst > 0 => {
            let i = &mut p.opened_values.instances[a % n_inst];
            let o = &mut i.base_opened_values;
            let local = o.trace_local.clone();
            match site % 32 {
                5 => vec_edit(&mut o.trace_local, b, a, c),
                6 => flip(&mut o.trace_next, || Some(local)),
                7 => flip(&mut o.preprocessed_local, || Some(local)),
                8 => flip(&mut o.preprocessed_next, || Some(local)),
                9 => nested2(&mut o.quotient_chunks, b, a, c),
                10 => flip(&mut o.random, || Some(local)),
                11 => vec_edit(&mut i.permutation_local, b, a, c),
                12 => vec_edit(&mut i.permutation_next, b, a, c),
                _ => {
                    if let Some(v) = o.trace_next.as_mut() {
                        vec_edit(v, b, a, c);
                    }
                }
            }
        }
        // Commitments.
        14 => {
            let main = p.commitments.main.clone();
            flip(&mut p.commitments.permutation, || Some(main));
        }
        15 => {
            let main = p.commitments.main.clone();
            flip(&mut p.commitments.random, || Some(main));
        }
        16 => {
            // Move a commitment: the FRI round commitments share the type.
            let caps = &p.opening_proof.1.commit_phase_commits;
            if !caps.is_empty() {
                let cap = caps[b % caps.len()].clone();
                match c % 3 {
                    0 => p.commitments.main = cap,
                    1 => p.commitments.quotient_chunks = cap,
                    _ => p.commitments.random = Some(cap),
                }
            }
        }
        // The hiding PCS's openings of the random polynomials.
        17 => nested4(&mut p.opening_proof.0, a, b, c),
        // FRI.
        18 => vec_edit(&mut p.opening_proof.1.commit_phase_commits, a, b, c),
        19 => vec_edit(&mut p.opening_proof.1.commit_pow_witnesses, a, b, c),
        20 => vec_edit(&mut p.opening_proof.1.input_openings, a, b, c),
        21..=23 => {
            let io = &mut p.opening_proof.1.input_openings;
            if let Some(n) = io.len().checked_sub(1) {
                let o = &mut io[a % (n + 1)];
                match site % 32 {
                    21 => nested3(&mut o.opened_values, b, a, c),
                    22 => nested3(&mut o.opening_proof.0, b, a, c),
                    _ => vec_edit(&mut o.opening_proof.1.sibling_hashes, b, a, c),
                }
            }
        }
        24 => vec_edit(&mut p.opening_proof.1.commit_phase_openings, a, b, c),
        25..=28 => {
            let steps = &mut p.opening_proof.1.commit_phase_openings;
            if let Some(n) = steps.len().checked_sub(1) {
                let s = &mut steps[a % (n + 1)];
                match site % 32 {
                    // The arity schedule.
                    25 => s.log_arity = (b % 8) as u8,
                    26 => nested2(&mut s.sibling_values, b, a, c),
                    27 => nested3(&mut s.opening_proof.0, b, a, c),
                    _ => vec_edit(&mut s.opening_proof.1.sibling_hashes, b, a, c),
                }
            }
        }
        29 => vec_edit(&mut p.opening_proof.1.final_poly, a, b, c),
        30 => {
            // The query proof-of-work witness: another element of the proof.
            let w = &p.opening_proof.1.commit_pow_witnesses;
            if !w.is_empty() {
                p.opening_proof.1.query_pow_witness = w[a % w.len()];
            }
        }
        _ => {
            // Swap two opened values between instances.
            if n_inst > 1 {
                let (x, y) = (a % n_inst, b % n_inst);
                let inst = &mut p.opened_values.instances;
                let tmp = std::mem::take(&mut inst[x].base_opened_values.trace_local);
                inst[x].base_opened_values.trace_local =
                    std::mem::replace(&mut inst[y].base_opened_values.trace_local, tmp);
            }
        }
    }
}

/// Seed inputs (named): one per kind of edit, and the unedited proof.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("none", vec![]),
        ("degree_bits_small", vec![0, 0, 3, 0]),
        ("degree_bits_huge", vec![0, 1, 0, 2]),
        ("degree_bits_pop", vec![1, 0, 0, 1]),
        ("lookup_flip", vec![3, 0, 0, 0]),
        ("instance_drop", vec![4, 3, 0, 1]),
        ("trace_next_flip", vec![6, 0, 0, 0]),
        ("quotient_chunks_dup", vec![9, 0, 0, 2]),
        ("permutation_commit_flip", vec![14, 0, 0, 0]),
        ("fri_round_drop", vec![18, 0, 0, 1]),
        ("arity_change", vec![25, 0, 3, 0]),
        ("arity_zero", vec![25, 1, 0, 0]),
        ("final_poly_grow", vec![29, 0, 3, 4]),
        ("salts_inner", vec![22, 0, 0, 0xc4]),
        ("siblings_drop", vec![28, 0, 0, 1]),
        ("pow_witness", vec![30, 1, 0, 0]),
    ]
}
