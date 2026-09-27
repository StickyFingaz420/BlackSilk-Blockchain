//! Pinned Bulletproofs+ vectors (spec §1.3, §7; dossier 16, item 1 / BPP-3).
//!
//! Three kinds of pins in `tests/vectors/bpp.txt`, kept apart on purpose:
//!
//! - `gen.*`: the generators `H`, `Gbp[i]`, `Hbp[i]` and a digest of all 2048
//!   vector generators. **Independently derived**: recomputed here from spec
//!   §1.3 with raw Blake2b and dalek, and compared with `generators`.
//! - `accept.k<k>.*`: consensus accept vectors for `k` = 1, 2, 3, 16. The
//!   commitments are independently derived (`Com(a, y)` from §1.4); the proof
//!   bytes were produced by the implementation's prover once and are read back
//!   from the file (they are a fixed input of the vector, not recomputed). The
//!   transcript values `t0`, `y`, `z`, the round challenges and the final `e`
//!   are **independently derived** from the proof bytes with the §7 formulas.
//!   `verify` must accept every accept vector; the reject vectors are single
//!   changes of them and must fail.
//! - `prover.k<k>.proof`: **regression pins** of the prover's output with a
//!   seeded ChaCha20 RNG. Wallet-side, not consensus: a legitimate prover change
//!   (for example to its hedged randomness) updates only these pins. At pinning
//!   time they equal the accept proofs.
//!
//! Proof encoding (spec §7): `A ‖ A1 ‖ B ‖ r1 ‖ s1 ‖ d1 ‖ L[0..r] ‖ R[0..r]`.
//! The generator digest is the untagged Blake2b-256 of
//! `Gbp[0] ‖ … ‖ Gbp[1023] ‖ Hbp[0] ‖ … ‖ Hbp[1023]` (compressed encodings).

mod common;

use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof, BITS, MAX_OUTPUTS};
use blacksilk_crypto::generators::{self, BP_MAX_GENERATORS};
use blacksilk_crypto::point::decode_scalar;
use blacksilk_crypto::Point;
use common::spec::{self, cat, enc};
use common::{wide, Pins};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const FILE: &str = "tests/vectors/bpp.txt";
const VECTORS: &str = include_str!("vectors/bpp.txt");

/// The proof sizes the vectors cover.
const KS: [usize; 4] = [1, 2, 3, 16];

/// Amounts of the `k`-output statement (include 0 and `2^64 − 1`).
fn amounts(k: usize) -> Vec<u64> {
    match k {
        1 => vec![u64::MAX],
        2 => vec![0, 1],
        3 => vec![1_000, u64::MAX, 12_345],
        16 => (0..16u64)
            .map(|j| match j {
                0 => 0,
                15 => u64::MAX,
                _ => (j + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15),
            })
            .collect(),
        _ => unreachable!(),
    }
}

/// Masks `wide(0x70 + j)`.
fn masks(k: usize) -> Vec<Scalar> {
    (0..k).map(|j| wide(0x70 + j as u8)).collect()
}

/// The prover's RNG for the `k`-output regression pin.
fn prover_rng(k: usize) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xb000 + k as u64)
}

/// Independently derived commitments `Com(a_j, y_j)`.
fn commitments(k: usize) -> Vec<RistrettoPoint> {
    amounts(k)
        .iter()
        .zip(masks(k))
        .map(|(a, y)| spec::com(*a, &y))
        .collect()
}

fn rounds_for(k: usize) -> usize {
    (BITS * k.next_power_of_two()).trailing_zeros() as usize
}

fn encode(p: &BppProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.encoded_len());
    for x in [&p.a, &p.a1, &p.b] {
        out.extend_from_slice(x.bytes());
    }
    for s in [&p.r1, &p.s1, &p.d1] {
        out.extend_from_slice(&s.to_bytes());
    }
    for x in p.l.iter().chain(&p.r) {
        out.extend_from_slice(x.bytes());
    }
    out
}

/// Strict decoding with the canonical decoders; the round count follows from `k`.
fn decode(bytes: &[u8], k: usize) -> BppProof {
    let r = rounds_for(k);
    assert_eq!(bytes.len(), 32 * (6 + 2 * r), "proof length for k = {k}");
    let field = |i: usize| -> [u8; 32] { bytes[32 * i..32 * (i + 1)].try_into().unwrap() };
    let point = |i: usize| Point::decode(&field(i)).expect("canonical point");
    let scalar = |i: usize| decode_scalar(&field(i)).expect("canonical scalar");
    BppProof {
        a: point(0),
        a1: point(1),
        b: point(2),
        r1: scalar(3),
        s1: scalar(4),
        d1: scalar(5),
        l: (0..r).map(|j| point(6 + j)).collect(),
        r: (0..r).map(|j| point(6 + r + j)).collect(),
    }
}

/// The spec §7 transcript, recomputed from the proof bytes.
struct Transcript {
    t0: [u8; 32],
    y: Scalar,
    z: Scalar,
    rounds: Vec<Scalar>,
    e: Scalar,
}

fn transcript(proof: &BppProof, v: &[Point]) -> Transcript {
    let k = v.len();
    let m = k.next_power_of_two();
    let mut init = vec![64u8, m as u8, k as u8];
    for p in v {
        init.extend_from_slice(p.bytes());
    }
    let t0 = spec::h32("bp+/init", &init);
    let y = spec::hs("bp+/y", &cat(&[&t0, proof.a.bytes()]));
    let z = spec::hs("bp+/z", &cat(&[&t0, proof.a.bytes(), &y.to_bytes()]));
    let mut t = z.to_bytes();
    let mut rounds = Vec::new();
    for (l, r) in proof.l.iter().zip(&proof.r) {
        let e = spec::hs("bp+/round", &cat(&[&t, l.bytes(), r.bytes()]));
        t = e.to_bytes();
        rounds.push(e);
    }
    let e = spec::hs("bp+/final", &cat(&[&t, proof.a1.bytes(), proof.b.bytes()]));
    Transcript {
        t0,
        y,
        z,
        rounds,
        e,
    }
}

/// The accept vector for `k`, read from the file.
fn accept_vector(k: usize) -> (BppProof, Vec<Point>) {
    let pins = Pins::new(FILE, VECTORS, &format!("accept.k{k}."));
    let v_bytes = pins.bytes("V");
    let v: Vec<Point> = v_bytes
        .chunks(32)
        .map(|c| Point::decode(c.try_into().unwrap()).expect("canonical V"))
        .collect();
    (decode(&pins.bytes("proof"), k), v)
}

// ---- generators (independently derived) ----

#[test]
fn generators() {
    assert_eq!(BP_MAX_GENERATORS, BITS * MAX_OUTPUTS);
    assert_eq!(BP_MAX_GENERATORS, 1024);
    let h = spec::h();
    assert_eq!(*generators::h(), h, "H");
    assert_eq!(generators::G, spec::g(), "G");

    let gens = generators::bp_generators();
    assert_eq!(gens.g.len(), BP_MAX_GENERATORS);
    assert_eq!(gens.h.len(), BP_MAX_GENERATORS);
    let mut all = Vec::with_capacity(64 * BP_MAX_GENERATORS);
    let mut derived_h = Vec::with_capacity(BP_MAX_GENERATORS);
    for i in 0..BP_MAX_GENERATORS as u32 {
        let g = spec::hp("generator/bp+/G", &i.to_le_bytes());
        assert_eq!(gens.g[i as usize], g, "Gbp[{i}]");
        all.extend_from_slice(&enc(&g));
        let h = spec::hp("generator/bp+/H", &i.to_le_bytes());
        assert_eq!(gens.h[i as usize], h, "Hbp[{i}]");
        derived_h.push(h);
    }
    for h in &derived_h {
        all.extend_from_slice(&enc(h));
    }

    let mut pins = Pins::new(FILE, VECTORS, "gen.");
    pins.check("G", enc(&spec::g()));
    pins.check("H", enc(&h));
    for i in [0usize, 1, 1023] {
        pins.check(&format!("Gbp.{i}"), enc(&gens.g[i]));
    }
    for i in [0usize, 1, 1023] {
        pins.check(&format!("Hbp.{i}"), enc(&gens.h[i]));
    }
    pins.check("digest", spec::blake2b256(&all));
    pins.finish();
}

// ---- consensus accept vectors ----

/// The pinned proofs verify against the independently derived commitments
/// (which must equal the pinned `V`), and the independently recomputed
/// transcript matches its pins.
#[test]
fn accept_vectors() {
    for k in KS {
        let mut pins = Pins::new(FILE, VECTORS, &format!("accept.k{k}."));
        let proof = decode(&pins.bytes("proof"), k);
        let v: Vec<Point> = commitments(k).into_iter().map(Point::from_point).collect();
        assert_eq!(proof.encoded_len(), bpp::proof_len(k).unwrap(), "k = {k}");
        assert_eq!(bpp::rounds(k), Some(rounds_for(k)), "k = {k}");
        assert!(bpp::verify(&proof, &v), "k = {k}: accept vector rejected");

        let t = transcript(&proof, &v);
        assert_eq!(t.rounds.len(), rounds_for(k));
        for x in t.rounds.iter().chain([&t.y, &t.z, &t.e]) {
            assert_ne!(*x, Scalar::ZERO, "k = {k}: zero challenge");
        }
        pins.check_str("proof_len", &proof.encoded_len().to_string());
        let v_bytes: Vec<u8> = v.iter().flat_map(|p| *p.bytes()).collect();
        pins.check("V", v_bytes);
        pins.check("proof", encode(&proof));
        pins.check("t0", t.t0);
        pins.check("y", t.y.to_bytes());
        pins.check("z", t.z.to_bytes());
        let rounds: Vec<u8> = t.rounds.iter().flat_map(|e| e.to_bytes()).collect();
        pins.check("e_rounds", rounds);
        pins.check("e", t.e.to_bytes());
        pins.finish();
    }
}

#[test]
fn accept_vectors_batch() {
    let vectors: Vec<(BppProof, Vec<Point>)> = KS.iter().map(|&k| accept_vector(k)).collect();
    let items: Vec<(&BppProof, &[Point])> =
        vectors.iter().map(|(p, v)| (p, v.as_slice())).collect();
    assert!(bpp::batch_verify(
        &items,
        &mut ChaCha20Rng::seed_from_u64(1)
    ));
    // One bad member fails the whole batch.
    let mut bad = vectors.clone();
    bad[2].0.d1 += Scalar::ONE;
    let items: Vec<(&BppProof, &[Point])> = bad.iter().map(|(p, v)| (p, v.as_slice())).collect();
    assert!(!bpp::batch_verify(
        &items,
        &mut ChaCha20Rng::seed_from_u64(1)
    ));
}

// ---- consensus reject vectors ----

fn plus_g(p: &Point) -> Point {
    Point::from_point(p.point() + spec::g())
}

/// Every single change of an accept vector (proof field, statement, shape) is
/// rejected. Run on `k` = 2 (no padding) and `k` = 3 (one padding slot).
#[test]
fn reject_vectors() {
    let mut rejected = 0;
    for k in [2usize, 3] {
        let (proof, v) = accept_vector(k);
        let mut reject = |p: &BppProof, v: &[Point], what: &str| {
            assert!(
                !bpp::verify(p, v),
                "k = {k}: reject vector accepted: {what}"
            );
            rejected += 1;
        };
        let with = |f: &dyn Fn(&mut BppProof)| {
            let mut p = proof.clone();
            f(&mut p);
            p
        };

        // Each proof element.
        reject(&with(&|p| p.a = plus_g(&p.a)), &v, "A + G");
        reject(&with(&|p| p.a1 = plus_g(&p.a1)), &v, "A1 + G");
        reject(&with(&|p| p.b = plus_g(&p.b)), &v, "B + G");
        reject(&with(&|p| p.r1 += Scalar::ONE), &v, "r1 + 1");
        reject(&with(&|p| p.s1 += Scalar::ONE), &v, "s1 + 1");
        reject(&with(&|p| p.d1 += Scalar::ONE), &v, "d1 + 1");
        for j in 0..proof.l.len() {
            reject(
                &with(&|p| p.l[j] = plus_g(&p.l[j])),
                &v,
                &format!("L[{j}] + G"),
            );
            reject(
                &with(&|p| p.r[j] = plus_g(&p.r[j])),
                &v,
                &format!("R[{j}] + G"),
            );
        }
        reject(&with(&|p| std::mem::swap(&mut p.l, &mut p.r)), &v, "L ↔ R");
        reject(&with(&|p| p.l.swap(0, 1)), &v, "L[0] ↔ L[1]");
        reject(
            &with(&|p| std::mem::swap(&mut p.r1, &mut p.s1)),
            &v,
            "r1 ↔ s1",
        );

        // Shape.
        reject(
            &with(&|p| {
                p.l.pop();
                p.r.pop();
            }),
            &v,
            "one round short",
        );
        reject(
            &with(&|p| {
                p.l.push(p.l[0]);
                p.r.push(p.r[0]);
            }),
            &v,
            "one round extra",
        );

        // Statement.
        let mut w = v.clone();
        w[0] = plus_g(&w[0]);
        reject(&proof, &w, "V[0] + G");
        let mut w = v.clone();
        w.swap(0, 1);
        reject(&proof, &w, "V[0] ↔ V[1]");
        reject(&proof, &v[..k - 1], "one commitment dropped");
        let mut w = v.clone();
        w.push(Point::decode(&[0; 32]).unwrap());
        // k = 3 → 4 keeps M = 4 (same shape), so only the transcript header
        // (and the statement) tells them apart.
        reject(&proof, &w, "identity commitment appended");
    }
    // A proof for one statement against another of a different size.
    let (p1, _) = accept_vector(1);
    let (_, v2) = accept_vector(2);
    assert!(!bpp::verify(&p1, &v2[..1]), "k = 1 proof, other commitment");
    assert!(!bpp::verify(&p1, &v2), "k = 1 proof, k = 2 statement");
    rejected += 2;
    // k = 2: 6 + 2·7 + 3 + 2 + 4 = 29; k = 3: 6 + 2·8 + 3 + 2 + 4 = 31.
    assert_eq!(rejected, 29 + 31 + 2);
}

// ---- prover determinism (regression pins, wallet-side) ----

/// The prover with a seeded RNG reproduces its pinned proofs, and returns the
/// independently derived commitments.
#[test]
fn prover_determinism_regression() {
    for k in KS {
        let (proof, v) = bpp::prove(&amounts(k), &masks(k), &mut prover_rng(k)).unwrap();
        let expected: Vec<Point> = commitments(k).into_iter().map(Point::from_point).collect();
        assert_eq!(v, expected, "k = {k}: prover commitments");
        assert!(bpp::verify(&proof, &v), "k = {k}");
        let mut pins = Pins::new(FILE, VECTORS, &format!("prover.k{k}."));
        pins.check("proof", encode(&proof));
        pins.finish();
    }
}
