//! The proof decoder bounds every vector before allocating it (red team
//! RT-FUZZ-1; `blacksilk_zk::bounds`). No proving: the proofs are synthetic
//! (`support/synthetic.rs`), with an honest proof's structure. The real
//! transfer proof is decoded under the same bounds in `px/tests/proof.rs`.

#[path = "support/synthetic.rs"]
mod synthetic;

use blacksilk_zk::bounds::{MAX_FRI_ROUNDS, MAX_MERKLE_DEPTH, MAX_PRUNED_SIBLINGS};
use blacksilk_zk::config::{Challenge, Val};
use blacksilk_zk::params::{
    EXTENSION_DEGREE, LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_HEIGHT, MAX_PROOF_BYTES,
    MERKLE_SALT_ELEMS, MIN_LOG_HEIGHT, NUM_QUERIES, NUM_RANDOM_CODEWORDS, OPENING_POINTS,
};
use blacksilk_zk::{
    decode_proof, decode_proof_with, encode_proof, honest_fri_schedule, DecodeLimits, Proof,
    ZkError, PROOF_VERSION,
};
use p3_field::PrimeCharacteristicRing;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use synthetic::Spec;

/// The PX statements' limits (`blacksilk_px::prove::PROOF_LIMITS`: 23
/// tables); here only to show a narrower caller's limits apply.
const PX_LIKE: DecodeLimits = DecodeLimits {
    max_instances: 23,
    ..DecodeLimits::ENVELOPE
};

/// The message of a refusal by the decoder's bounds, if `r` is one.
fn bound_error(r: &Result<Proof, ZkError>) -> Option<&str> {
    match r {
        Err(ZkError::Encoding(m)) if m.starts_with("decode bound") => Some(m),
        _ => None,
    }
}

fn show(r: &Result<Proof, ZkError>) -> String {
    match r {
        Ok(_) => "Ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

/// The decoder before RT-FUZZ-1 without its canonical-form rules:
/// `postcard` over the whole body, and the bytes must re-encode identically.
fn postcard_decode(bytes: &[u8]) -> Option<Proof> {
    let (&v, body) = bytes.split_first()?;
    if v != PROOF_VERSION {
        return None;
    }
    let (p, rest) = postcard::take_from_bytes::<Proof>(body).ok()?;
    (rest.is_empty() && encode_proof(&p) == bytes).then_some(p)
}

/// Every cap of `blacksilk_zk::bounds::prescan`, on the decoded struct.
fn within_caps(p: &Proof, l: &DecodeLimits) -> bool {
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
    let inst = &p.opened_values.instances;
    let n = inst.len();
    let w = l.max_opened_width;
    let mut ok = roots && n <= l.max_instances;
    let mut widest = 0;
    let mut chunks = 0;
    let mut opened = |v: &Vec<Challenge>, cap: usize, ok: &mut bool| {
        *ok &= v.len() <= cap;
        widest = widest.max(v.len());
    };
    for i in inst {
        let o = &i.base_opened_values;
        opened(&o.trace_local, w, &mut ok);
        for v in [&o.trace_next, &o.preprocessed_local, &o.preprocessed_next]
            .into_iter()
            .flatten()
        {
            opened(v, w, &mut ok);
        }
        ok &= o.quotient_chunks.len() <= l.max_quotient_chunks;
        chunks += o.quotient_chunks.len();
        for q in &o.quotient_chunks {
            opened(q, EXTENSION_DEGREE, &mut ok);
        }
        if let Some(r) = &o.random {
            opened(r, EXTENSION_DEGREE, &mut ok);
        }
        opened(&i.permutation_local, w, &mut ok);
        opened(&i.permutation_next, w, &mut ok);
    }
    let preprocessed = inst
        .iter()
        .any(|i| i.base_opened_values.preprocessed_local.is_some());
    let rounds = usize::from(c.random.is_some())
        + 2
        + usize::from(preprocessed)
        + usize::from(c.permutation.is_some());
    let hidden = &p.opening_proof.0;
    ok &= hidden.len() == rounds;
    let quotient_round = usize::from(c.random.is_some()) + 1;
    for (r, round) in hidden.iter().enumerate() {
        ok &= round.len() <= if r == quotient_round { chunks } else { n };
        ok &= round.iter().all(|m| {
            m.len() <= OPENING_POINTS && m.iter().all(|pt| pt.len() <= NUM_RANDOM_CODEWORDS)
        });
    }
    let salts_ok = |salts: &Vec<Vec<Vec<Val>>>, m: usize| {
        salts.len() == NUM_QUERIES
            && salts
                .iter()
                .all(|s| s.len() == m && s.iter().all(|x| x.len() == MERKLE_SALT_ELEMS))
    };
    let k = fri.commit_phase_commits.len();
    ok &= k <= MAX_FRI_ROUNDS && fri.commit_pow_witnesses.len() <= k;
    ok &= fri.input_openings.len() <= hidden.len();
    for (b, io) in fri.input_openings.iter().enumerate() {
        let m = hidden.get(b).map_or(0, Vec::len);
        ok &= io.opened_values.len() == NUM_QUERIES
            && io.opened_values.iter().all(|q| {
                q.len() == m
                    && q.iter()
                        .all(|row| row.len() <= widest + NUM_RANDOM_CODEWORDS)
            })
            && salts_ok(&io.opening_proof.0, m)
            && io.opening_proof.1.sibling_hashes.len() <= MAX_PRUNED_SIBLINGS;
    }
    ok &= fri.commit_phase_openings.len() <= k;
    for o in &fri.commit_phase_openings {
        ok &= o.sibling_values.len() == NUM_QUERIES
            && o.sibling_values.iter().all(|s| s.len() < 16)
            && salts_ok(&o.opening_proof.0, 1)
            && o.opening_proof.1.sibling_hashes.len() <= MAX_PRUNED_SIBLINGS;
    }
    ok && fri.final_poly.len() <= 1 << LOG_FINAL_POLY_LEN
        && p.lookup_terminals.len() <= n
        && p.degree_bits.len() <= n
}

/// Heap bytes of the decoded vectors' elements (headers of nested vectors
/// included in their parent's elements), a proxy for the decoder's heap.
fn heap_estimate(p: &Proof) -> usize {
    use std::mem::size_of;
    let v = size_of::<Vec<u8>>();
    let e = size_of::<Challenge>();
    let f = size_of::<Val>();
    let mut s = 0;
    for i in &p.opened_values.instances {
        let o = &i.base_opened_values;
        s += size_of_val(i)
            + e * (o.trace_local.len() + i.permutation_local.len() + i.permutation_next.len());
        for x in [
            &o.trace_next,
            &o.preprocessed_local,
            &o.preprocessed_next,
            &o.random,
        ]
        .into_iter()
        .flatten()
        {
            s += e * x.len();
        }
        s += o
            .quotient_chunks
            .iter()
            .map(|q| v + e * q.len())
            .sum::<usize>();
    }
    for round in &p.opening_proof.0 {
        s += v;
        for m in round {
            s += v + m.iter().map(|pt| v + e * pt.len()).sum::<usize>();
        }
    }
    let fri = &p.opening_proof.1;
    let multi = |salts: &Vec<Vec<Vec<Val>>>, sib: usize| {
        salts
            .iter()
            .map(|q| v + q.iter().map(|x| v + f * x.len()).sum::<usize>())
            .sum::<usize>()
            + 32 * sib
    };
    for io in &fri.input_openings {
        s += size_of_val(io);
        s += io
            .opened_values
            .iter()
            .map(|q| v + q.iter().map(|r| v + f * r.len()).sum::<usize>())
            .sum::<usize>();
        s += multi(&io.opening_proof.0, io.opening_proof.1.sibling_hashes.len());
    }
    for o in &fri.commit_phase_openings {
        s += size_of_val(o)
            + o.sibling_values
                .iter()
                .map(|x| v + e * x.len())
                .sum::<usize>();
        s += multi(&o.opening_proof.0, o.opening_proof.1.sibling_hashes.len());
    }
    s + e * fri.final_poly.len() + 40 * fri.commit_phase_commits.len()
}

#[test]
fn synthetic_proofs_decode_under_both_limits() {
    for spec in [Spec::transfer_like(), Spec::small()] {
        let p = synthetic::proof(&spec);
        let bytes = encode_proof(&p);
        let d = decode_proof(&bytes).expect("an honest structure decodes");
        assert_eq!(encode_proof(&d), bytes);
        assert!(decode_proof_with(&bytes, &PX_LIKE).is_ok());
        assert!(within_caps(&p, &PX_LIKE));
    }
}

/// RT-FUZZ-1, reproduced on the synthetic transfer-shaped proof: one
/// instance padded with empty quotient chunks (one byte each on the wire, a
/// 24-byte vector header each in memory) up to `MAX_PROOF_BYTES`, with and
/// without the FRI openings. Before the fix both decoded (`Ok`, 18.7× and
/// 34× their size in heap on the real proof); now the length prefix is
/// refused before anything is allocated.
#[test]
fn rt_fuzz_1_padded_proofs_are_refused_before_allocation() {
    for strip in [false, true] {
        let mut p = synthetic::proof(&Spec::transfer_like());
        if strip {
            p.opening_proof.1.input_openings.clear();
            p.opening_proof.1.commit_phase_openings.clear();
        }
        let k = MAX_PROOF_BYTES - encode_proof(&p).len() - 8;
        let q = &mut p.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks;
        let chunks = q.len() + k;
        q.resize(chunks, vec![]);
        let bytes = encode_proof(&p);
        assert!(bytes.len() <= MAX_PROOF_BYTES);
        assert!(
            postcard_decode(&bytes).is_some(),
            "the padding is well formed"
        );
        let r = decode_proof(&bytes);
        assert_eq!(
            bound_error(&r),
            Some(
                format!("decode bound: quotient_chunks has {chunks} entries, more than 16")
                    .as_str()
            ),
            "strip {strip}: {}",
            show(&r)
        );
    }
}

/// The densest proofs the caps allow (every vector the caps admit, each
/// empty where it may be, or holding one value and filled to
/// `MAX_PROOF_BYTES`) hold a bounded heap per encoded byte. Measured with a
/// counting allocator (docs/reviews/v3-consensus-changes.md,
/// "px-proof-decode-bounds"): at most about 6 times their bytes, about 16 MB
/// at the 4 MiB limit.
#[test]
fn the_densest_proof_within_the_caps_has_a_bounded_heap() {
    // `usize::MAX`: the one-value fill (`densest_filled`).
    for (n, sib) in [
        (23, 0),
        (23, MAX_PRUNED_SIBLINGS),
        (33, 0),
        (33, MAX_PRUNED_SIBLINGS),
        (23, usize::MAX),
        (33, usize::MAX),
    ] {
        let p = if sib == usize::MAX {
            synthetic::densest_filled(n, 16)
        } else {
            synthetic::densest(n, 16, sib)
        };
        let bytes = encode_proof(&p);
        assert!(bytes.len() <= MAX_PROOF_BYTES);
        let r = decode_proof(&bytes);
        assert!(bound_error(&r).is_none(), "{}", show(&r));
        let d = postcard_decode(&bytes).expect("structurally well formed");
        assert!(within_caps(&d, &DecodeLimits::ENVELOPE));
        let heap = heap_estimate(&d);
        println!(
            "{n} instances, {sib} siblings: {} bytes, heap estimate {heap}",
            bytes.len()
        );
        assert!(
            heap <= 5 * bytes.len(),
            "{n} instances, {sib} siblings: {heap} heap bytes for {} bytes",
            bytes.len()
        );
    }
    // The same estimate shows the amplification the bounds remove.
    let base = synthetic::proof(&Spec::transfer_like());
    let mut p = synthetic::proof(&Spec::transfer_like());
    let q = &mut p.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks;
    q.resize(1_000_000, vec![]);
    let bytes = encode_proof(&p).len() - encode_proof(&base).len();
    assert!(heap_estimate(&p) - heap_estimate(&base) >= 20 * bytes);
}

type Edit = fn(&mut Proof);

/// One edit per cap, each exceeding it by one; `(name in the refusal, edit)`.
fn over_cap_edits() -> Vec<(&'static str, Edit)> {
    fn inst(p: &mut Proof) -> &mut p3_batch_stark::OpenedValues<Challenge> {
        &mut p.opened_values.instances[0].base_opened_values
    }
    vec![
        ("trace_local", |p| {
            inst(p).trace_local.resize(6_001, Challenge::ZERO)
        }),
        ("trace_next", |p| {
            inst(p).trace_next = Some(vec![Challenge::ZERO; 6_001])
        }),
        ("quotient_chunks", |p| {
            inst(p).quotient_chunks.resize(17, vec![Challenge::ZERO; 8])
        }),
        ("quotient chunk", |p| {
            inst(p).quotient_chunks[0].push(Challenge::ZERO)
        }),
        ("random opening", |p| {
            inst(p).random.as_mut().unwrap().push(Challenge::ZERO)
        }),
        ("permutation_next", |p| {
            p.opened_values.instances[1]
                .permutation_next
                .resize(6_001, Challenge::ZERO)
        }),
        ("hidden opening matrices", |p| {
            let m = p.opening_proof.0[1][0].clone();
            p.opening_proof.0[1].push(m)
        }),
        ("hidden opening points", |p| {
            let pt = p.opening_proof.0[1][0][0].clone();
            p.opening_proof.0[1][0].push(pt)
        }),
        ("hidden opening values", |p| {
            p.opening_proof.0[0][0][0].push(Challenge::ZERO)
        }),
        ("FRI commit-phase commitments", |p| {
            let c = p.opening_proof.1.commit_phase_commits[0].clone();
            p.opening_proof
                .1
                .commit_phase_commits
                .resize(MAX_FRI_ROUNDS + 1, c)
        }),
        ("commit-phase grinding witnesses", |p| {
            p.opening_proof.1.commit_pow_witnesses.push(Val::ZERO)
        }),
        ("FRI input batches", |p| {
            let b = p.opening_proof.1.input_openings[0].clone();
            p.opening_proof.1.input_openings.push(b)
        }),
        ("input opening queries", |p| {
            p.opening_proof.1.input_openings[0].opened_values.pop();
        }),
        ("input opening matrices", |p| {
            let r = p.opening_proof.1.input_openings[0].opened_values[5][0].clone();
            p.opening_proof.1.input_openings[0].opened_values[5].push(r)
        }),
        ("input opening row", |p| {
            p.opening_proof.1.input_openings[2].opened_values[0][0].resize(2 * 6_001, Val::ZERO)
        }),
        ("input opening multiproof", |p| {
            p.opening_proof.1.input_openings[1].opening_proof.0[3][0].push(Val::ZERO)
        }),
        ("input opening multiproof", |p| {
            p.opening_proof.1.input_openings[1].opening_proof.0.pop();
        }),
        ("input opening multiproof", |p| {
            p.opening_proof.1.input_openings[1]
                .opening_proof
                .1
                .sibling_hashes
                .resize(MAX_PRUNED_SIBLINGS + 1, [Val::ZERO; 8])
        }),
        ("commit-phase openings", |p| {
            let o = p.opening_proof.1.commit_phase_openings[0].clone();
            p.opening_proof.1.commit_phase_openings.push(o)
        }),
        ("commit-phase queries", |p| {
            let s = p.opening_proof.1.commit_phase_openings[0].sibling_values[0].clone();
            p.opening_proof.1.commit_phase_openings[0]
                .sibling_values
                .push(s)
        }),
        ("commit-phase sibling values", |p| {
            p.opening_proof.1.commit_phase_openings[0].sibling_values[7] = vec![Challenge::ZERO; 16]
        }),
        ("commit-phase multiproof", |p| {
            p.opening_proof.1.commit_phase_openings[0].opening_proof.0[9].push(vec![Val::ZERO; 4])
        }),
        ("final polynomial", |p| {
            p.opening_proof.1.final_poly.push(Challenge::ZERO)
        }),
        ("lookup terminals", |p| p.lookup_terminals.push(None)),
        ("degree bits", |p| p.degree_bits.push(10)),
    ]
}

#[test]
fn every_cap_refuses_one_more() {
    let base = synthetic::proof(&Spec::transfer_like());
    for (name, edit) in over_cap_edits() {
        let mut p = synthetic::proof(&Spec::transfer_like());
        edit(&mut p);
        assert_ne!(encode_proof(&p), encode_proof(&base), "{name}: no edit");
        assert!(!within_caps(&p, &DecodeLimits::ENVELOPE), "{name}");
        let bytes = encode_proof(&p);
        if bytes.len() > MAX_PROOF_BYTES {
            continue;
        }
        let r = decode_proof(&bytes);
        let msg = bound_error(&r).unwrap_or_else(|| panic!("{name}: {}", show(&r)));
        assert!(
            msg.starts_with(&format!("decode bound: {name} has ")),
            "{name}: {msg}"
        );
    }
    // Instances: 34 is one more than the envelope's 33, 24 one more than 23.
    let bytes = encode_proof(&synthetic::proof(&Spec {
        chunks: vec![2; 34],
        ..Spec::small()
    }));
    assert!(bound_error(&decode_proof(&bytes)).is_some_and(|m| m.contains("instances")));
    let bytes = encode_proof(&synthetic::proof(&Spec {
        chunks: vec![2; 24],
        ..Spec::small()
    }));
    assert!(bound_error(&decode_proof(&bytes)).is_none());
    assert!(
        bound_error(&decode_proof_with(&bytes, &PX_LIKE)).is_some_and(|m| m.contains("instances"))
    );
    // Two Merkle cap roots and an extra hidden round: the canonical-form
    // rules, now applied before allocation, with their messages.
    let mut p = synthetic::proof(&Spec::small());
    p.commitments.main = p3_merkle_tree::MerkleCap::new(vec![[Val::ZERO; 8]; 2]);
    assert!(matches!(decode_proof(&encode_proof(&p)),
        Err(ZkError::Encoding(m)) if m == "commitment 0 has 2 Merkle cap roots, not 1"));
    let mut p = synthetic::proof(&Spec::small());
    let r = p.opening_proof.0[0].clone();
    p.opening_proof.0.push(r);
    assert!(matches!(decode_proof(&encode_proof(&p)),
        Err(ZkError::Encoding(m)) if m.contains("hidden opening rounds")));
}

/// At every cap (not over it) the decoder's bounds refuse nothing.
#[test]
fn at_the_caps_nothing_is_refused_by_the_bounds() {
    // 33 instances (the envelope), one with the most quotient chunks.
    let mut chunks = vec![1; 33];
    chunks[0] = 16;
    let mut p = synthetic::proof(&Spec {
        chunks,
        ..Spec::small()
    });
    p.opened_values.instances[0].base_opened_values.trace_local = vec![Challenge::ZERO; 6_000];
    let fri = &mut p.opening_proof.1;
    let c = fri.commit_phase_commits[0].clone();
    fri.commit_phase_commits.resize(MAX_FRI_ROUNDS, c);
    fri.commit_pow_witnesses.resize(MAX_FRI_ROUNDS, Val::ZERO);
    fri.input_openings[0].opening_proof.1.sibling_hashes =
        vec![[Val::ZERO; 8]; MAX_PRUNED_SIBLINGS];
    fri.commit_phase_openings[0].sibling_values[0] = vec![Challenge::ZERO; 15];
    assert!(within_caps(&p, &DecodeLimits::ENVELOPE));
    let bytes = encode_proof(&p);
    assert!(bytes.len() <= MAX_PROOF_BYTES);
    let r = decode_proof(&bytes);
    assert!(r.is_ok(), "{}", show(&r));
}

fn below(rng: &mut ChaCha20Rng, n: usize) -> usize {
    rng.next_u32() as usize % n
}

/// The walk and `postcard` agree on the layout: over random structural
/// edits (vector lengths grown or shrunk anywhere, options toggled), a proof
/// `postcard` decodes is refused by the bounds exactly when it breaks a cap.
#[test]
fn the_bounds_agree_with_the_decoded_structure() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xb0d5);
    let limits = DecodeLimits {
        max_instances: 3,
        max_opened_width: 12,
        max_quotient_chunks: 4,
    };
    let (mut refused, mut accepted) = (0, 0);
    for _ in 0..400 {
        let mut p = synthetic::proof(&Spec::small());
        for _ in 0..1 + below(&mut rng, 3) {
            tweak(&mut p, &mut rng);
        }
        let bytes = encode_proof(&p);
        let Some(d) = postcard_decode(&bytes) else {
            continue;
        };
        let r = decode_proof_with(&bytes, &limits);
        let prescan_refusal = match &r {
            Err(ZkError::Encoding(m)) => {
                m.starts_with("decode bound")
                    || m.contains("Merkle cap roots")
                    || m.contains("hidden opening rounds")
            }
            _ => false,
        };
        if within_caps(&d, &limits) {
            accepted += 1;
            assert!(!prescan_refusal, "{}", show(&r));
        } else {
            refused += 1;
            assert!(r.is_err());
        }
    }
    assert!(refused > 50 && accepted > 50, "{refused} {accepted}");
}

/// Grows or shrinks one vector of `p` (or toggles an option) at random.
fn tweak(p: &mut Proof, rng: &mut ChaCha20Rng) {
    fn resize<T: Clone>(v: &mut Vec<T>, rng: &mut ChaCha20Rng, fill: T) {
        let n = v.len();
        let d = 1 + below(rng, 2);
        let m = if below(rng, 2) == 0 {
            n + d
        } else {
            n.saturating_sub(d)
        };
        v.resize(m, fill);
    }
    let z = Challenge::ZERO;
    let n = p.opened_values.instances.len();
    let i = below(rng, n);
    let fri = &mut p.opening_proof.1;
    match below(rng, 16) {
        0 => {
            if below(rng, 2) == 0 && n > 1 {
                p.opened_values.instances.pop();
            } else {
                let spec = Spec {
                    chunks: vec![2],
                    ..Spec::small()
                };
                let extra = synthetic::proof(&spec).opened_values.instances.remove(0);
                p.opened_values.instances.push(extra);
            }
        }
        1 => resize(
            &mut p.opened_values.instances[i].base_opened_values.trace_local,
            rng,
            z,
        ),
        2 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            o.trace_next = if o.trace_next.is_some() {
                None
            } else {
                Some(vec![z; 3])
            };
        }
        3 => resize(
            &mut p.opened_values.instances[i]
                .base_opened_values
                .quotient_chunks,
            rng,
            vec![z; 8],
        ),
        4 => {
            let o = &mut p.opened_values.instances[i].base_opened_values;
            if let Some(q) = o.quotient_chunks.first_mut() {
                resize(q, rng, z);
            }
        }
        5 => resize(&mut p.opened_values.instances[i].permutation_next, rng, z),
        6 => {
            let r = below(rng, p.opening_proof.0.len());
            let round = &mut p.opening_proof.0[r];
            if let Some(m) = round.first().cloned() {
                resize(round, rng, m);
            }
        }
        7 => {
            if let Some(pt) = p.opening_proof.0[1].first_mut().and_then(|m| m.first_mut()) {
                resize(pt, rng, z);
            }
        }
        8 => {
            let c = fri.commit_phase_commits[0].clone();
            resize(&mut fri.commit_phase_commits, rng, c);
        }
        9 => resize(&mut fri.commit_pow_witnesses, rng, Val::ZERO),
        10 => {
            let b = below(rng, fri.input_openings.len());
            let q = below(rng, NUM_QUERIES);
            let rows = &mut fri.input_openings[b].opened_values[q];
            if let Some(row) = rows.first().cloned() {
                resize(rows, rng, row);
            }
        }
        11 => {
            let b = below(rng, fri.input_openings.len());
            if let Some(row) = fri.input_openings[b].opened_values[0].first_mut() {
                resize(row, rng, Val::ZERO);
            }
        }
        12 => {
            let b = below(rng, fri.input_openings.len());
            let s = &mut fri.input_openings[b].opening_proof.0;
            let q = below(rng, s.len());
            if let Some(salt) = s[q].first_mut() {
                resize(salt, rng, Val::ZERO);
            }
        }
        13 => {
            let o = &mut fri.commit_phase_openings[0];
            let s = o.sibling_values[0].clone();
            resize(&mut o.sibling_values, rng, s);
        }
        14 => resize(&mut fri.final_poly, rng, z),
        _ => resize(&mut p.degree_bits, rng, 10),
    }
}

/// The size limit is inclusive (mutation run D): a proof of exactly
/// `MAX_PROOF_BYTES` within every cap decodes, and the same proof one byte
/// longer is refused for its size alone. The synthetic transfer-shaped proof
/// is filled with opened trace values (32 bytes each) to just below the
/// limit, and the last bytes come from the degree bits' varints (a value
/// of `k` bytes adds `k - 1`), which no cap reads.
#[test]
fn the_size_limit_is_inclusive() {
    /// The varint of `v` takes `k` bytes for `v = 1 << (7 * (k - 1))`.
    fn grow(p: &mut Proof, mut bytes: usize) {
        for b in p.degree_bits.iter_mut() {
            let k = 1 + bytes.min(8);
            *b = if k == 1 { 10 } else { 1 << (7 * (k - 1)) };
            bytes -= k - 1;
        }
        assert_eq!(bytes, 0, "the degree bits absorb the rest");
    }
    let mut p = synthetic::proof(&Spec::transfer_like());
    let ext = 4 * EXTENSION_DEGREE;
    let mut room = MAX_PROOF_BYTES - encode_proof(&p).len() - 64;
    for i in &mut p.opened_values.instances {
        let o = &mut i.base_opened_values;
        for v in [&mut o.trace_local, o.trace_next.as_mut().unwrap()] {
            let k = (v.len() + room / ext).min(DecodeLimits::ENVELOPE.max_opened_width);
            room -= (k - v.len()) * ext;
            v.resize(k, Challenge::ZERO);
        }
    }
    let deficit = MAX_PROOF_BYTES - encode_proof(&p).len();
    grow(&mut p, deficit);
    let bytes = encode_proof(&p);
    assert_eq!(bytes.len(), MAX_PROOF_BYTES);
    assert!(within_caps(&p, &DecodeLimits::ENVELOPE));
    let r = decode_proof(&bytes);
    assert!(r.is_ok(), "exactly MAX_PROOF_BYTES: {}", show(&r));
    assert!(decode_proof_with(&bytes, &PX_LIKE).is_ok());

    grow(&mut p, deficit + 1);
    let bytes = encode_proof(&p);
    assert_eq!(bytes.len(), MAX_PROOF_BYTES + 1);
    assert!(
        postcard_decode(&bytes).is_some_and(|d| within_caps(&d, &DecodeLimits::ENVELOPE)),
        "well formed and within the caps but for its size"
    );
    assert!(matches!(decode_proof(&bytes),
        Err(ZkError::Encoding(m)) if m == "proof too large"));
}

/// The FRI-round and Merkle caps, from what `verify` accepts (mutation run
/// D: the caps were used only symbolically, so a smaller or larger value went
/// unnoticed). `verify` accepts degree bits up to `MAX_LOG_HEIGHT + 1`, so the
/// tallest committed matrix has `2^(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP)` rows.
#[test]
fn the_fri_and_merkle_caps_follow_from_the_tallest_matrix() {
    let max_db = MAX_LOG_HEIGHT + 1;
    let tallest = max_db + LOG_BLOWUP;
    // FRI folds from the tallest height to the final polynomial's, at least
    // one bit per round (p3-fri `verify_fri`: arities in 1..=MAX_LOG_ARITY).
    assert_eq!(MAX_FRI_ROUNDS, tallest - (LOG_BLOWUP + LOG_FINAL_POLY_LEN));
    assert_eq!(MAX_FRI_ROUNDS, 17);
    // The canonical schedule (`check_fri_schedule`) of any degree bits
    // `verify` accepts stays within it; the most rounds come from a table at
    // every height.
    let every: Vec<usize> = (MIN_LOG_HEIGHT + 1..=max_db).collect();
    let most = honest_fri_schedule(&every).len();
    println!("most canonical FRI rounds: {most}");
    assert!(most <= MAX_FRI_ROUNDS);
    for db in MIN_LOG_HEIGHT + 1..=max_db {
        assert!(honest_fri_schedule(&[db]).len() <= most);
    }
    // Binary Merkle trees (cap height 0) over at most the tallest matrix's
    // rows: one sibling per level per queried leaf.
    assert_eq!(MAX_MERKLE_DEPTH, tallest);
    assert_eq!(MAX_MERKLE_DEPTH, 26);
    assert_eq!(MAX_PRUNED_SIBLINGS, NUM_QUERIES * tallest);
    assert_eq!(MAX_PRUNED_SIBLINGS, 2_808);
}

/// The walk reads a varint exactly as `postcard` reads a `usize` (mutation
/// run D): the degree bits, which no cap bounds, may take any `u64` value,
/// up to a tenth byte of 1; a tenth byte above 1 overflows and is refused by
/// the walk itself, before `postcard`. The last degree bit is the last
/// varint of the encoding.
#[test]
fn varints_are_read_as_postcard_reads_them() {
    let mut p = synthetic::proof(&Spec::small());
    *p.degree_bits.last_mut().unwrap() = usize::MAX;
    let bytes = encode_proof(&p);
    assert_eq!(
        bytes[bytes.len() - 10..],
        [0xff; 9].into_iter().chain([1]).collect::<Vec<_>>()
    );
    let r = decode_proof(&bytes);
    assert!(r.is_ok(), "a ten-byte varint ending in 1: {}", show(&r));
    assert_eq!(r.unwrap().degree_bits.last(), Some(&usize::MAX));

    let mut over = bytes.clone();
    *over.last_mut().unwrap() = 2;
    assert!(postcard_decode(&over).is_none(), "postcard refuses it too");
    assert!(matches!(decode_proof(&over),
        Err(ZkError::Encoding(m)) if m == "bad varint"));
    // Eleven bytes: the tenth still continues.
    let mut long = bytes.clone();
    *long.last_mut().unwrap() = 0x81;
    long.push(0);
    assert!(matches!(decode_proof(&long),
        Err(ZkError::Encoding(m)) if m == "bad varint"));
}

/// The walk names a commitment with more than one Merkle cap root by its
/// index in the canonical-form rule's order (main, permutation, quotient,
/// random, then the FRI commit-phase commitments), with or without the
/// optional ones (mutation run D: only the main commitment's index was
/// checked).
#[test]
fn a_commitment_with_two_roots_is_named_by_its_index() {
    fn two() -> p3_merkle_tree::MerkleCap<Val, [Val; 8]> {
        p3_merkle_tree::MerkleCap::new(vec![[Val::ZERO; 8]; 2])
    }
    // `Spec::small()` has a permutation and a random commitment, and two FRI
    // rounds; the same without lookups has no permutation commitment.
    let small = Spec::small();
    let no_lookups = Spec {
        perm_width: 0,
        ..Spec::small()
    };
    let cases: Vec<(&Spec, usize, Edit)> = vec![
        (&small, 0, |p| p.commitments.main = two()),
        (&small, 1, |p| p.commitments.permutation = Some(two())),
        (&small, 2, |p| p.commitments.quotient_chunks = two()),
        (&small, 3, |p| p.commitments.random = Some(two())),
        (&small, 4, |p| {
            p.opening_proof.1.commit_phase_commits[0] = two()
        }),
        (&small, 5, |p| {
            p.opening_proof.1.commit_phase_commits[1] = two()
        }),
        (&no_lookups, 1, |p| p.commitments.quotient_chunks = two()),
        (&no_lookups, 2, |p| p.commitments.random = Some(two())),
        (&no_lookups, 4, |p| {
            p.opening_proof.1.commit_phase_commits[1] = two()
        }),
    ];
    for (spec, index, edit) in cases {
        let mut p = synthetic::proof(spec);
        assert!(decode_proof(&encode_proof(&p)).is_ok(), "{index}: base");
        edit(&mut p);
        let want = format!("commitment {index} has 2 Merkle cap roots, not 1");
        let r = decode_proof(&encode_proof(&p));
        assert!(
            matches!(&r, Err(ZkError::Encoding(m)) if *m == want),
            "{want}: {}",
            show(&r)
        );
    }
}
