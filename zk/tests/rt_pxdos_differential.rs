//! Red team RT-PXDOS: a differential between the decoder's pre-scan
//! (`blacksilk_zk::bounds`, RT-FUZZ-1) and `postcard` on arbitrary bytes.
//!
//! For every input the test decodes the body with `postcard` directly and
//! checks the verdict of `decode_proof_with` against an independent reading
//! of the caps on the decoded struct:
//! - a struct beyond a cap is refused by the pre-scan (before `postcard`
//!   allocates anything);
//! - a struct within the caps that re-encodes to the input and passes the
//!   canonical-form rules is accepted (the valid set is unchanged);
//! - whenever the pre-scan accepts, `postcard` reads the same layout: it
//!   consumes the body exactly, or fails only on a field element out of range.
//!
//! Inputs: byte-level mutations (flips, special bytes, insertions,
//! deletions, truncations, overlong and overflowing varints) of synthetic
//! proofs, an exhaustive positional sweep over a tiny proof, structural edits
//! with large lengths, and, if `RT_PXDOS_REAL` names a real proof file,
//! mutations of it.

#[path = "support/synthetic.rs"]
mod synthetic;

use blacksilk_zk::bounds::{MAX_FRI_ROUNDS, MAX_PRUNED_SIBLINGS};
use blacksilk_zk::config::{Challenge, Val};
use blacksilk_zk::params::{
    EXTENSION_DEGREE, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY, MAX_PROOF_BYTES, MERKLE_SALT_ELEMS,
    NUM_QUERIES, NUM_RANDOM_CODEWORDS, OPENING_POINTS,
};
use blacksilk_zk::{decode_proof_with, encode_proof, DecodeLimits, Proof, ZkError, PROOF_VERSION};
use p3_field::PrimeCharacteristicRing;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::panic::{catch_unwind, AssertUnwindSafe};
use synthetic::Spec;

const TIGHT: DecodeLimits = DecodeLimits {
    max_instances: 3,
    max_opened_width: 12,
    max_quotient_chunks: 4,
};
const PX: DecodeLimits = DecodeLimits {
    max_instances: 23,
    ..DecodeLimits::ENVELOPE
};

/// Messages the pre-scan refuses with (`bounds.rs`).
fn prescan_refusal(r: &Result<Proof, ZkError>) -> bool {
    match r {
        Err(ZkError::Encoding(m)) => {
            m.starts_with("decode bound")
                || m == "proof bytes end early"
                || m == "bad varint"
                || m == "bad option tag"
                || m == "trailing bytes"
                || m.contains("Merkle cap roots")
                || m.contains("hidden opening rounds")
        }
        _ => false,
    }
}

/// The caps, read independently from the verifier's rules, on a decoded struct.
fn within_caps(p: &Proof, l: &DecodeLimits) -> bool {
    let c = &p.commitments;
    let fri = &p.opening_proof.1;
    let one_root = [
        Some(&c.main),
        c.permutation.as_ref(),
        Some(&c.quotient_chunks),
        c.random.as_ref(),
    ]
    .into_iter()
    .flatten()
    .chain(&fri.commit_phase_commits)
    .all(|cap| cap.num_roots() == 1);
    if !one_root {
        return false;
    }
    let inst = &p.opened_values.instances;
    let n = inst.len();
    if n > l.max_instances {
        return false;
    }
    let w = l.max_opened_width;
    let mut widest = 0usize;
    let mut chunks = 0usize;
    for i in inst {
        let o = &i.base_opened_values;
        let mut vecs: Vec<(&Vec<Challenge>, usize)> = vec![
            (&o.trace_local, w),
            (&i.permutation_local, w),
            (&i.permutation_next, w),
        ];
        for v in [&o.trace_next, &o.preprocessed_local, &o.preprocessed_next]
            .into_iter()
            .flatten()
        {
            vecs.push((v, w));
        }
        if let Some(r) = &o.random {
            vecs.push((r, EXTENSION_DEGREE));
        }
        if o.quotient_chunks.len() > l.max_quotient_chunks {
            return false;
        }
        chunks += o.quotient_chunks.len();
        for q in &o.quotient_chunks {
            vecs.push((q, EXTENSION_DEGREE));
        }
        for (v, cap) in vecs {
            if v.len() > cap {
                return false;
            }
            widest = widest.max(v.len());
        }
    }
    let pre = inst
        .iter()
        .any(|i| i.base_opened_values.preprocessed_local.is_some());
    let rounds = usize::from(c.random.is_some())
        + 2
        + usize::from(pre)
        + usize::from(c.permutation.is_some());
    let hidden = &p.opening_proof.0;
    if hidden.len() != rounds {
        return false;
    }
    let q_round = usize::from(c.random.is_some()) + 1;
    for (r, round) in hidden.iter().enumerate() {
        let cap = if r == q_round { chunks } else { n };
        if round.len() > cap
            || round.iter().any(|m| {
                m.len() > OPENING_POINTS || m.iter().any(|pt| pt.len() > NUM_RANDOM_CODEWORDS)
            })
        {
            return false;
        }
    }
    let k = fri.commit_phase_commits.len();
    if k > MAX_FRI_ROUNDS || fri.commit_pow_witnesses.len() > k {
        return false;
    }
    if fri.input_openings.len() > rounds {
        return false;
    }
    let salts_ok = |s: &Vec<Vec<Vec<Val>>>, m: usize| {
        s.len() == NUM_QUERIES
            && s.iter()
                .all(|q| q.len() == m && q.iter().all(|x| x.len() == MERKLE_SALT_ELEMS))
    };
    for (b, io) in fri.input_openings.iter().enumerate() {
        let m = hidden[b].len();
        let ok = io.opened_values.len() == NUM_QUERIES
            && io.opened_values.iter().all(|q| {
                q.len() == m
                    && q.iter()
                        .all(|row| row.len() <= widest + NUM_RANDOM_CODEWORDS)
            })
            && salts_ok(&io.opening_proof.0, m)
            && io.opening_proof.1.sibling_hashes.len() <= MAX_PRUNED_SIBLINGS;
        if !ok {
            return false;
        }
    }
    if fri.commit_phase_openings.len() > k {
        return false;
    }
    for o in &fri.commit_phase_openings {
        let ok = o.sibling_values.len() == NUM_QUERIES
            && o.sibling_values
                .iter()
                .all(|s| s.len() < (1 << MAX_LOG_ARITY))
            && salts_ok(&o.opening_proof.0, 1)
            && o.opening_proof.1.sibling_hashes.len() <= MAX_PRUNED_SIBLINGS;
        if !ok {
            return false;
        }
    }
    fri.final_poly.len() <= 1 << LOG_FINAL_POLY_LEN
        && p.lookup_terminals.len() <= n
        && p.degree_bits.len() <= n
}

/// The canonical-form rules of `check_canonical_form`, re-read independently.
fn canonical(p: &Proof) -> bool {
    use p3_commit::Pcs;
    let c = &p.commitments;
    let fri = &p.opening_proof.1;
    let roots = [
        Some(&c.main),
        c.permutation.as_ref(),
        Some(&c.quotient_chunks),
        c.random.as_ref(),
    ]
    .into_iter()
    .flatten()
    .chain(&fri.commit_phase_commits)
    .all(|cap| cap.num_roots() == 1);
    let witnesses = fri.commit_pow_witnesses.iter().all(|w| *w == Val::ZERO);
    let empty = |v: &Option<Vec<Challenge>>| v.as_ref().is_some_and(Vec::is_empty);
    let options = p.opened_values.instances.iter().all(|i| {
        let o = &i.base_opened_values;
        !(empty(&o.trace_next)
            || empty(&o.preprocessed_local)
            || empty(&o.preprocessed_next)
            || empty(&o.random))
    });
    let pre = p
        .opened_values
        .instances
        .iter()
        .any(|i| i.base_opened_values.preprocessed_local.is_some());
    let rounds = usize::from(c.random.is_some())
        + 2
        + usize::from(pre)
        + usize::from(c.permutation.is_some());
    let pre_idx = <blacksilk_zk::config::Pcs as Pcs<
        Challenge,
        blacksilk_zk::config::Challenger,
    >>::PREPROCESSED_TRACE_IDX;
    let hidden = &p.opening_proof.0;
    let counts = hidden.len() == rounds
        && hidden.iter().enumerate().all(|(r, round)| {
            let want = if pre && r == pre_idx {
                0
            } else {
                NUM_RANDOM_CODEWORDS
            };
            round.iter().flatten().all(|pt| pt.len() == want)
        });
    roots && witnesses && options && counts
}

#[derive(Default, Debug)]
struct Tally {
    inputs: usize,
    postcard_ok: usize,
    beyond_caps: usize,
    valid: usize,
    prescan_accepts_postcard_range_error: usize,
}

/// Checks one input against every limit set.
fn check(bytes: &[u8], tally: &mut Tally, what: &str) {
    tally.inputs += 1;
    let body = match bytes.split_first() {
        Some((&v, body)) if v == PROOF_VERSION && bytes.len() <= MAX_PROOF_BYTES => body,
        _ => {
            for l in [TIGHT, PX, DecodeLimits::ENVELOPE] {
                assert!(decode_proof_with(bytes, &l).is_err(), "{what}");
            }
            return;
        }
    };
    let pc = catch_unwind(AssertUnwindSafe(|| {
        postcard::take_from_bytes::<Proof>(body)
    }))
    .unwrap_or_else(|_| panic!("{what}: postcard panicked"));
    if pc.is_ok() {
        tally.postcard_ok += 1;
    }
    for l in [TIGHT, PX, DecodeLimits::ENVELOPE] {
        let r = decode_proof_with(bytes, &l);
        let refused = prescan_refusal(&r);
        match &pc {
            Ok((p, rest)) => {
                let caps = within_caps(p, &l);
                if !caps {
                    tally.beyond_caps += 1;
                    assert!(
                        refused,
                        "{what}: beyond the caps {l:?} but not refused by the pre-scan: {}",
                        show(&r)
                    );
                    continue;
                }
                if !rest.is_empty() {
                    assert!(
                        refused,
                        "{what}: trailing bytes not refused by the pre-scan"
                    );
                    continue;
                }
                if canonical(p) {
                    assert!(
                        !refused,
                        "{what}: within the caps {l:?} and canonical, refused by the pre-scan: {}",
                        show(&r)
                    );
                    if encode_proof(p) == bytes {
                        tally.valid += 1;
                        assert!(r.is_ok(), "{what}: valid but refused: {}", show(&r));
                    } else {
                        assert!(r.is_err(), "{what}: non-canonical bytes accepted");
                    }
                } else {
                    assert!(r.is_err(), "{what}: non-canonical struct accepted");
                }
            }
            Err(e) => {
                assert!(
                    r.is_err(),
                    "{what}: postcard failed ({e}) but decode accepted"
                );
                if !refused {
                    // The pre-scan walked the whole body: postcard can only
                    // disagree on a value (a field element out of range).
                    assert_eq!(
                        *e,
                        postcard::Error::SerdeDeCustom,
                        "{what}: the pre-scan accepted a layout postcard reads differently: {}",
                        show(&r)
                    );
                    tally.prescan_accepts_postcard_range_error += 1;
                }
            }
        }
    }
}

fn below(rng: &mut ChaCha20Rng, n: usize) -> usize {
    (rng.next_u64() % n as u64) as usize
}

/// Varint-shaped byte strings that stress the reader.
fn special_varints() -> Vec<Vec<u8>> {
    vec![
        vec![0x80, 0x00],                                                 // overlong 0
        vec![0x81, 0x00],                                                 // overlong 1
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], // 10-byte 0
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], // u64::MAX
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02], // overflow
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], // overflow
        vec![0xff; 11],                                                   // unterminated
        vec![0xff, 0xff, 0xff, 0xff, 0x0f],                               // u32::MAX
        vec![0x80, 0x80, 0x80, 0x80, 0x10],                               // 2^32
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],             // 2^56 - 1
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], // 2^63
        vec![0xf8, 0x2e],                                                 // 6008
        vec![0xf0, 0x2e],                                                 // 6000
        vec![0xf1, 0x2e],                                                 // 6001
        vec![0x6c],                                                       // 108
        vec![0x6d],                                                       // 109
    ]
}

fn mutate(base: &[u8], rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut b = base.to_vec();
    let specials = special_varints();
    for _ in 0..1 + below(rng, 2) {
        let len = b.len().max(2);
        let at = 1 + below(rng, len - 1);
        let at = at.min(b.len());
        match below(rng, 8) {
            0 => {
                if at < b.len() {
                    b[at] ^= 1 << below(rng, 8);
                }
            }
            1 => {
                if at < b.len() {
                    b[at] = [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff, 0x6c, 0x6d][below(rng, 8)];
                }
            }
            2 => {
                let n = 1 + below(rng, 3);
                for _ in 0..n {
                    b.insert(at, rng.next_u32() as u8);
                }
            }
            3 => {
                let n = (1 + below(rng, 3)).min(b.len() - at);
                b.drain(at..at + n);
            }
            4 => b.truncate(at),
            5 => {
                // Replace one byte with a special varint.
                let s = &specials[below(rng, specials.len())];
                if at < b.len() {
                    b.splice(at..at + 1, s.iter().copied());
                }
            }
            6 => {
                // Make the varint at `at` overlong: add a continuation.
                if at < b.len() && b[at] & 0x80 == 0 {
                    let v = b[at];
                    b.splice(at..at + 1, [v | 0x80, 0x00]);
                }
            }
            _ => {
                // Insert a special varint.
                let s = specials[below(rng, specials.len())].clone();
                b.splice(at..at, s);
            }
        }
    }
    b
}

/// Structural edits with large lengths anywhere, then re-encoded.
fn edit(p: &mut Proof, rng: &mut ChaCha20Rng) {
    let big = [
        0usize, 1, 2, 3, 4, 5, 7, 8, 9, 12, 13, 15, 16, 17, 23, 24, 33, 34, 64, 65, 107, 108, 109,
        200, 3000,
    ];
    let n_ = big[below(rng, big.len())];
    let z = Challenge::ZERO;
    let n = p.opened_values.instances.len();
    let i = below(rng, n.max(1)).min(n.saturating_sub(1));
    let fri = &mut p.opening_proof.1;
    match below(rng, 22) {
        0 if n > 0 => p.opened_values.instances[i].base_opened_values.trace_local = vec![z; n_],
        1 if n > 0 => {
            p.opened_values.instances[i].base_opened_values.trace_next = if n_.is_multiple_of(3) {
                None
            } else {
                Some(vec![z; n_])
            }
        }
        2 if n > 0 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            o.preprocessed_local = if n_.is_multiple_of(3) {
                None
            } else {
                Some(vec![z; n_])
            };
        }
        3 if n > 0 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            o.quotient_chunks = vec![vec![z; EXTENSION_DEGREE]; n_.min(40)];
        }
        4 if n > 0 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            if let Some(q) = o.quotient_chunks.first_mut() {
                *q = vec![z; n_.min(20)];
            }
        }
        5 if n > 0 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            o.random = if n_.is_multiple_of(3) {
                None
            } else {
                Some(vec![z; n_.min(20)])
            };
        }
        6 if n > 0 => p.opened_values.instances[i].permutation_local = vec![z; n_],
        7 => {
            let r = below(rng, p.opening_proof.0.len().max(1));
            if let Some(round) = p.opening_proof.0.get_mut(r) {
                let m = round.first().cloned().unwrap_or_default();
                round.resize(n_.min(60), m);
            }
        }
        8 => {
            if let Some(m) = p.opening_proof.0.get_mut(0).and_then(|r| r.first_mut()) {
                let pt = m.first().cloned().unwrap_or_default();
                m.resize(n_.min(5), pt);
            }
        }
        9 => {
            if let Some(pt) = p
                .opening_proof
                .0
                .get_mut(1)
                .and_then(|r| r.first_mut())
                .and_then(|m| m.first_mut())
            {
                pt.resize(n_.min(20), z);
            }
        }
        10 => {
            let c = fri.commit_phase_commits.first().cloned();
            if let Some(c) = c {
                fri.commit_phase_commits.resize(n_.min(20), c);
            }
        }
        11 => fri.commit_pow_witnesses.resize(n_.min(20), Val::ZERO),
        12 => {
            if !fri.input_openings.is_empty() {
                let b = below(rng, fri.input_openings.len());
                let q = below(rng, NUM_QUERIES);
                let rows = &mut fri.input_openings[b].opened_values[q];
                let row = rows.first().cloned().unwrap_or_default();
                rows.resize(n_.min(80), row);
            }
        }
        13 => {
            if !fri.input_openings.is_empty() {
                let b = below(rng, fri.input_openings.len());
                if let Some(row) = fri.input_openings[b].opened_values[0].first_mut() {
                    row.resize(n_, Val::ZERO);
                }
            }
        }
        14 => {
            if !fri.input_openings.is_empty() {
                let b = below(rng, fri.input_openings.len());
                let v = &mut fri.input_openings[b].opened_values;
                let q = v[0].clone();
                v.resize(n_.min(120), q);
            }
        }
        15 => {
            if !fri.input_openings.is_empty() {
                let b = below(rng, fri.input_openings.len());
                let s = &mut fri.input_openings[b].opening_proof.0;
                let q = below(rng, s.len());
                if let Some(salt) = s[q].first_mut() {
                    salt.resize(n_.min(9), Val::ZERO);
                }
            }
        }
        16 => {
            if !fri.input_openings.is_empty() {
                let b = below(rng, fri.input_openings.len());
                let sib = &mut fri.input_openings[b].opening_proof.1.sibling_hashes;
                let extra = if below(rng, 2) == 0 {
                    MAX_PRUNED_SIBLINGS
                } else {
                    MAX_PRUNED_SIBLINGS + 1
                };
                sib.resize(extra, [Val::ZERO; 8]);
            }
        }
        17 => {
            if let Some(o) = fri.commit_phase_openings.first_mut() {
                let k = o.sibling_values.len().max(1);
                if let Some(s) = o.sibling_values.get_mut(below(rng, k)) {
                    *s = vec![z; n_.min(17)];
                }
            }
        }
        18 => {
            if let Some(o) = fri.commit_phase_openings.first_mut() {
                let s = o.sibling_values[0].clone();
                o.sibling_values.resize(n_.min(120), s);
            }
        }
        19 => fri.final_poly = vec![z; n_.min(70)],
        20 => p.degree_bits.resize(n_.min(40), 10),
        _ => {
            let t = p.lookup_terminals.first().cloned().flatten();
            p.lookup_terminals.resize(n_.min(40), t);
        }
    }
}

#[test]
fn prescan_and_postcard_agree_on_mutated_bytes() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x05ee_dd05);
    let mut tally = Tally::default();
    let bases: Vec<Vec<u8>> = [Spec::small(), Spec::transfer_like()]
        .iter()
        .map(|s| encode_proof(&synthetic::proof(s)))
        .chain([encode_proof(&synthetic::densest(3, 4, 5))])
        .collect();
    let iters: usize = std::env::var("RT_PXDOS_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    for it in 0..iters {
        let base = &bases[it % bases.len()];
        let b = mutate(base, &mut rng);
        check(&b, &mut tally, &format!("byte mutation {it}"));
    }
    println!("{tally:?}");
    assert!(tally.postcard_ok > 100);
}

#[test]
fn prescan_and_postcard_agree_on_structural_edits() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xed17);
    let mut tally = Tally::default();
    let iters: usize = std::env::var("RT_PXDOS_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    for it in 0..iters {
        let spec = match it % 3 {
            0 => Spec::small(),
            1 => Spec {
                chunks: vec![1, 2, 4],
                width: 12,
                perm_width: 0,
                preprocessed: false,
                fri_rounds: 3,
                siblings: 2,
            },
            _ => Spec {
                chunks: vec![4],
                width: 2,
                perm_width: 3,
                preprocessed: true,
                fri_rounds: 1,
                siblings: 0,
            },
        };
        let mut p = synthetic::proof(&spec);
        for _ in 0..1 + below(&mut rng, 3) {
            if catch_unwind(AssertUnwindSafe(|| edit(&mut p, &mut rng))).is_err() {
                continue;
            }
        }
        let b = encode_proof(&p);
        if b.len() > MAX_PROOF_BYTES {
            continue;
        }
        check(&b, &mut tally, &format!("structural edit {it}"));
        // And a byte mutation on top.
        let m = mutate(&b, &mut rng);
        check(&m, &mut tally, &format!("structural edit {it} + bytes"));
    }
    println!("{tally:?}");
    assert!(tally.beyond_caps > 100 && tally.valid > 100, "{tally:?}");
}

/// Every byte position of a tiny proof, replaced with every special varint
/// and overlong form: the positional sweep reaches every length prefix,
/// option tag and `log_arity` byte.
#[test]
fn prescan_and_postcard_agree_at_every_position() {
    let tiny = Spec {
        chunks: vec![1],
        width: 1,
        perm_width: 1,
        preprocessed: true,
        fri_rounds: 1,
        siblings: 1,
    };
    let base = encode_proof(&synthetic::proof(&tiny));
    let mut tally = Tally::default();
    let specials = special_varints();
    let stride: usize = std::env::var("RT_PXDOS_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(13);
    for at in (1..base.len()).step_by(stride) {
        for v in [0x00u8, 0x01, 0x02, 0x03, 0x7f, 0x80, 0xff] {
            let mut b = base.clone();
            b[at] = v;
            check(&b, &mut tally, &format!("at {at} = {v:#x}"));
        }
        for s in &specials {
            let mut b = base.clone();
            b.splice(at..at + 1, s.iter().copied());
            check(&b, &mut tally, &format!("at {at} = {s:x?}"));
        }
        if base[at] & 0x80 == 0 {
            let mut b = base.clone();
            b.splice(at..at + 1, [base[at] | 0x80, 0x00]);
            check(&b, &mut tally, &format!("at {at} overlong"));
        }
        let mut b = base.clone();
        b.truncate(at);
        check(&b, &mut tally, &format!("truncated at {at}"));
    }
    println!("{} bytes: {tally:?}", base.len());
}

/// Mutations of a real proof, if one is given.
#[test]
fn prescan_and_postcard_agree_on_a_real_proof() {
    let Ok(path) = std::env::var("RT_PXDOS_REAL") else {
        eprintln!("RT_PXDOS_REAL not set; skipped");
        return;
    };
    let real = std::fs::read(path).unwrap();
    let mut tally = Tally::default();
    check(&real, &mut tally, "the real proof");
    assert_eq!(
        tally.valid, 2,
        "the real proof decodes under PX and ENVELOPE: {tally:?}"
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0x7ea1);
    let iters: usize = std::env::var("RT_PXDOS_REAL_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let decoded = blacksilk_zk::decode_proof(&real).unwrap();
    for it in 0..iters {
        if it % 2 == 0 {
            let b = mutate(&real, &mut rng);
            check(&b, &mut tally, &format!("real byte mutation {it}"));
        } else {
            let mut p = blacksilk_zk::decode_proof(&encode_proof(&decoded)).unwrap();
            if catch_unwind(AssertUnwindSafe(|| edit(&mut p, &mut rng))).is_err() {
                continue;
            }
            let b = encode_proof(&p);
            if b.len() <= MAX_PROOF_BYTES {
                check(&b, &mut tally, &format!("real structural edit {it}"));
            }
        }
    }
    println!("{tally:?}");
}

fn show(r: &Result<Proof, ZkError>) -> String {
    match r {
        Ok(_) => "Ok".into(),
        Err(e) => format!("{e:?}"),
    }
}
