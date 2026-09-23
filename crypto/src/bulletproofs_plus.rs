//! Aggregated Bulletproofs+ range proofs (spec §7).
//!
//! Chung, Han, Ju, Kim, Seo: "Bulletproofs+: Shorter Proofs for a
//! Privacy-Enhanced Distributed Ledger", IACR ePrint 2020/735, §4 (aggregate range
//! proof, Fig. 3) over the weighted inner-product argument (WIP, Fig. 1).
//!
//! Notation: value generator `H` (the paper's `g`), blinding generator `G` (the
//! paper's `h`), vectors `Gbp`, `Hbp`. Weighted inner product
//! `⟨a, b⟩_y = Σ_i a_i·b_i·y^(i+1)`. For `k` outputs, `M` = `k` rounded up to a
//! power of two, and `N = 64·M`.
//!
//! **Range proof.**
//!
//! ```text
//! a_L = bits of all amounts (padding slots: 0), a_R = a_L − 1
//! A   = <a_L, Gbp> + <a_R, Hbp> + α·G
//! y, z from the transcript
//! d_(64j+b) = z^(2(j+1))·2^b,   ←y_i = y^(N−i)
//! â_L = a_L − z·1,   â_R = a_R + d∘←y + z·1
//! α̂   = α + Σ_j z^(2(j+1))·y^(N+1)·γ_j
//! Â   = A − z·ΣGbp + Σ(d_i·y^(N−i) + z)·Hbp_i + Σ_j z^(2(j+1))·y^(N+1)·V_j
//!       + [(z − z²)·Σ_(i=1..N) y^i − z·y^(N+1)·⟨1, d⟩]·H
//! ```
//!
//! By construction `Â = <â_L, Gbp> + <â_R, Hbp> + ⟨â_L, â_R⟩_y·H + α̂·G`, and the
//! WIP proves knowledge of such an opening.
//!
//! **WIP rounds** (length `n`, half `h = n/2`):
//!
//! ```text
//! L = <a1·y^(−h), G2> + <b2, H1> + ⟨a1, b2⟩_y·H + d_L·G
//! R = <a2·y^h, G1> + <b1, H2> + ⟨a2·y^h, b1⟩_y·H + d_R·G
//! e from the transcript
//! G' = e^(−1)·G1 + e·y^(−h)·G2        H' = e·H1 + e^(−1)·H2
//! a' = e·a1 + e^(−1)·y^h·a2           b' = e^(−1)·b1 + e·b2
//! α' = α + e²·d_L + e^(−2)·d_R        P' = e²·L + P + e^(−2)·R
//! ```
//!
//! **Final step** (`n = 1`):
//!
//! ```text
//! A1 = r·G0 + s·H0 + (r·y·b + s·y·a)·H + δ·G
//! B  = r·y·s·H + η·G
//! e from the transcript
//! r1 = r + a·e,   s1 = s + b·e,   d1 = η + δ·e + α·e²
//! verifier: e²·P + e·A1 + B = e·r1·G0 + e·s1·H0 + r1·y·s1·H + d1·G
//! ```
//!
//! The verifier folds all of this into one multi-scalar multiplication
//! ([`verify`], [`batch_verify`]). A test checks it against a direct
//! round-by-round implementation of the equations above.

use crate::commitment::commit;
use crate::generators::{bp_generators, h, G};
use crate::hash::{h32, tags, Hasher64};
use crate::nonce::HedgedRng;
use crate::point::Point;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use std::iter::once;
use zeroize::Zeroize;

/// Bits per amount.
pub const BITS: usize = 64;
/// Maximum number of commitments in one proof.
pub const MAX_OUTPUTS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BppProof {
    pub a: Point,
    pub a1: Point,
    pub b: Point,
    pub r1: Scalar,
    pub s1: Scalar,
    pub d1: Scalar,
    pub l: Vec<Point>,
    pub r: Vec<Point>,
}

impl BppProof {
    pub fn encoded_len(&self) -> usize {
        32 * (6 + self.l.len() + self.r.len())
    }
}

/// Number of WIP rounds (`log2(64·M)`) for `outputs` commitments, if allowed.
pub fn rounds(outputs: usize) -> Option<usize> {
    if outputs == 0 || outputs > MAX_OUTPUTS {
        return None;
    }
    Some((BITS * outputs.next_power_of_two()).trailing_zeros() as usize)
}

/// Encoded proof size for `outputs` commitments.
pub fn proof_len(outputs: usize) -> Option<usize> {
    rounds(outputs).map(|r| 32 * (6 + 2 * r))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BppError {
    /// Zero or more than [`MAX_OUTPUTS`] amounts.
    OutputCount,
    /// `amounts` and `masks` have different lengths.
    MaskCount,
}

// ---- transcript (spec §7, normative) ----

fn transcript_init(commitments: &[Point], m: usize) -> [u8; 32] {
    let header = [BITS as u8, m as u8, commitments.len() as u8];
    let mut parts: Vec<&[u8]> = vec![&header];
    parts.extend(commitments.iter().map(|v| v.bytes().as_slice()));
    h32(tags::BPP_INIT, &parts)
}

fn challenge_y(t0: &[u8; 32], a: &Point) -> Scalar {
    Hasher64::new(tags::BPP_Y)
        .chain(t0)
        .chain(a.bytes())
        .to_scalar()
}

fn challenge_z(t0: &[u8; 32], a: &Point, y: &Scalar) -> Scalar {
    Hasher64::new(tags::BPP_Z)
        .chain(t0)
        .chain(a.bytes())
        .chain(y.as_bytes())
        .to_scalar()
}

fn challenge_round(t: &[u8; 32], l: &Point, r: &Point) -> Scalar {
    Hasher64::new(tags::BPP_ROUND)
        .chain(t)
        .chain(l.bytes())
        .chain(r.bytes())
        .to_scalar()
}

fn challenge_final(t: &[u8; 32], a1: &Point, b: &Point) -> Scalar {
    Hasher64::new(tags::BPP_FINAL)
        .chain(t)
        .chain(a1.bytes())
        .chain(b.bytes())
        .to_scalar()
}

// ---- helpers ----

/// `[1, x, x², …, x^(n−1)]`.
fn powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Scalar::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= x;
    }
    out
}

/// `⟨a, b⟩_y = Σ a_i·b_i·y^(i+1)`.
fn weighted_inner_product(a: &[Scalar], b: &[Scalar], y: &Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut w = *y;
    for (x, v) in a.iter().zip(b) {
        acc += x * v * w;
        w *= y;
    }
    acc
}

/// `z^(2(j+1))` for `j < m`.
fn z_even_powers(z: &Scalar, m: usize) -> Vec<Scalar> {
    let z2 = z * z;
    let mut out = Vec::with_capacity(m);
    let mut acc = z2;
    for _ in 0..m {
        out.push(acc);
        acc *= z2;
    }
    out
}

// ---- prover ----

/// Proves that each `amounts[j]` committed with `masks[j]` lies in `[0, 2^64)`.
/// Returns the proof and the commitments `masks[j]·G + amounts[j]·H`.
pub fn prove<R: RngCore + CryptoRng>(
    amounts: &[u64],
    masks: &[Scalar],
    rng: &mut R,
) -> Result<(BppProof, Vec<Point>), BppError> {
    let k = amounts.len();
    rounds(k).ok_or(BppError::OutputCount)?;
    if masks.len() != k {
        return Err(BppError::MaskCount);
    }
    let m = k.next_power_of_two();
    let commitments: Vec<Point> = amounts
        .iter()
        .zip(masks)
        .map(|(a, y)| Point::from_point(commit(*a, y)))
        .collect();

    let mut a_l = Vec::with_capacity(BITS * m);
    for j in 0..m {
        let v = amounts.get(j).copied().unwrap_or(0);
        for b in 0..BITS {
            a_l.push(Scalar::from((v >> b) & 1));
        }
    }

    let mut secret = Vec::with_capacity(40 * k);
    for (a, y) in amounts.iter().zip(masks) {
        secret.extend_from_slice(&a.to_le_bytes());
        secret.extend_from_slice(y.as_bytes());
    }
    let mut context: Vec<&[u8]> = vec![b"bp+"];
    context.extend(commitments.iter().map(|v| v.bytes().as_slice()));
    let mut hedge = HedgedRng::new(&[&secret], &context, rng);
    secret.zeroize();

    let proof = loop {
        // Retry only if a challenge is zero (probability ~2^-250 per challenge).
        if let Some(p) = prove_bits(&a_l, masks, &commitments, &mut hedge) {
            break p;
        }
    };
    a_l.zeroize();
    Ok((proof, commitments))
}

/// The protocol body. `a_l` is taken as given (normally the bit decomposition),
/// which lets the tests run a *malicious* prover with non-binary vectors.
fn prove_bits(
    a_l: &[Scalar],
    masks: &[Scalar],
    commitments: &[Point],
    hedge: &mut HedgedRng,
) -> Option<BppProof> {
    let n = a_l.len();
    let m = n / BITS;
    let gens = bp_generators();
    let hv = *h();

    let mut a_r: Vec<Scalar> = a_l.iter().map(|x| x - Scalar::ONE).collect();
    let mut alpha = hedge.scalar();
    let a = Point::from_point(RistrettoPoint::multiscalar_mul(
        a_l.iter().chain(&a_r).chain(once(&alpha)),
        gens.g[..n].iter().chain(&gens.h[..n]).chain(once(&G)),
    ));

    let t0 = transcript_init(commitments, m);
    let y = challenge_y(&t0, &a);
    let z = challenge_z(&t0, &a, &y);
    if y == Scalar::ZERO || z == Scalar::ZERO {
        return None;
    }
    let y_pows = powers(&y, n + 2);
    let y_inv = y.invert();
    let y_inv_pows = powers(&y_inv, n);
    let zpow = z_even_powers(&z, m);
    let two_pows = powers(&Scalar::from(2u64), BITS);

    let mut a_vec: Vec<Scalar> = a_l.iter().map(|x| x - z).collect();
    let mut b_vec: Vec<Scalar> = (0..n)
        .map(|i| a_r[i] + zpow[i / BITS] * two_pows[i % BITS] * y_pows[n - i] + z)
        .collect();
    a_r.zeroize();
    for (j, gamma) in masks.iter().enumerate() {
        alpha += zpow[j] * y_pows[n + 1] * gamma;
    }

    let mut g_vec: Vec<RistrettoPoint> = gens.g[..n].to_vec();
    let mut h_vec: Vec<RistrettoPoint> = gens.h[..n].to_vec();
    let mut l_out = Vec::new();
    let mut r_out = Vec::new();
    let mut transcript = z.to_bytes();

    while a_vec.len() > 1 {
        let half = a_vec.len() / 2;
        let (a1, a2) = a_vec.split_at(half);
        let (b1, b2) = b_vec.split_at(half);
        let (g1, g2) = g_vec.split_at(half);
        let (h1, h2) = h_vec.split_at(half);
        let (y_h, y_inv_h) = (y_pows[half], y_inv_pows[half]);

        let c_l = weighted_inner_product(a1, b2, &y);
        let c_r = weighted_inner_product(a2, b1, &y) * y_h;
        let d_l = hedge.scalar();
        let d_r = hedge.scalar();
        let l = Point::from_point(RistrettoPoint::multiscalar_mul(
            a1.iter()
                .map(|x| x * y_inv_h)
                .chain(b2.iter().copied())
                .chain([c_l, d_l]),
            g2.iter().chain(h1).chain([&hv, &G]),
        ));
        let r = Point::from_point(RistrettoPoint::multiscalar_mul(
            a2.iter()
                .map(|x| x * y_h)
                .chain(b1.iter().copied())
                .chain([c_r, d_r]),
            g1.iter().chain(h2).chain([&hv, &G]),
        ));

        let e = challenge_round(&transcript, &l, &r);
        if e == Scalar::ZERO {
            return None;
        }
        transcript = e.to_bytes();
        let e_inv = e.invert();

        // Generators and challenges are public: variable time is fine here.
        let new_g: Vec<RistrettoPoint> = (0..half)
            .map(|i| RistrettoPoint::vartime_multiscalar_mul([e_inv, e * y_inv_h], [g1[i], g2[i]]))
            .collect();
        let new_h: Vec<RistrettoPoint> = (0..half)
            .map(|i| RistrettoPoint::vartime_multiscalar_mul([e, e_inv], [h1[i], h2[i]]))
            .collect();
        let new_a: Vec<Scalar> = (0..half).map(|i| e * a1[i] + e_inv * y_h * a2[i]).collect();
        let new_b: Vec<Scalar> = (0..half).map(|i| e_inv * b1[i] + e * b2[i]).collect();
        alpha += e * e * d_l + e_inv * e_inv * d_r;

        a_vec.zeroize();
        b_vec.zeroize();
        a_vec = new_a;
        b_vec = new_b;
        g_vec = new_g;
        h_vec = new_h;
        l_out.push(l);
        r_out.push(r);
    }

    let (a0, b0) = (a_vec[0], b_vec[0]);
    let r_ = hedge.scalar();
    let s_ = hedge.scalar();
    let delta = hedge.scalar();
    let eta = hedge.scalar();
    let a1 = Point::from_point(RistrettoPoint::multiscalar_mul(
        [r_, s_, r_ * y * b0 + s_ * y * a0, delta],
        [g_vec[0], h_vec[0], hv, G],
    ));
    let b = Point::from_point(RistrettoPoint::multiscalar_mul([r_ * y * s_, eta], [hv, G]));
    let e = challenge_final(&transcript, &a1, &b);
    if e == Scalar::ZERO {
        return None;
    }
    let proof = BppProof {
        a,
        a1,
        b,
        r1: r_ + a0 * e,
        s1: s_ + b0 * e,
        d1: eta + delta * e + alpha * e * e,
        l: l_out,
        r: r_out,
    };
    a_vec.zeroize();
    b_vec.zeroize();
    alpha.zeroize();
    Some(proof)
}

// ---- verifier ----

struct Challenges {
    y: Scalar,
    z: Scalar,
    rounds: Vec<Scalar>,
    e: Scalar,
    n: usize,
    m: usize,
}

/// Recomputes the transcript. `None` if the proof shape is wrong for the number of
/// commitments or any challenge is zero.
fn challenges(proof: &BppProof, commitments: &[Point]) -> Option<Challenges> {
    let rounds = rounds(commitments.len())?;
    if proof.l.len() != rounds || proof.r.len() != rounds {
        return None;
    }
    let m = commitments.len().next_power_of_two();
    let t0 = transcript_init(commitments, m);
    let y = challenge_y(&t0, &proof.a);
    let z = challenge_z(&t0, &proof.a, &y);
    let mut t = z.to_bytes();
    let mut es = Vec::with_capacity(rounds);
    for (l, r) in proof.l.iter().zip(&proof.r) {
        let e = challenge_round(&t, l, r);
        t = e.to_bytes();
        es.push(e);
    }
    let e = challenge_final(&t, &proof.a1, &proof.b);
    if y == Scalar::ZERO || z == Scalar::ZERO || e == Scalar::ZERO || es.contains(&Scalar::ZERO) {
        return None;
    }
    Some(Challenges {
        y,
        z,
        rounds: es,
        e,
        n: BITS * m,
        m,
    })
}

/// Terms of one weighted proof in the combined verification equation.
struct Msm {
    g: Vec<Scalar>,
    h: Vec<Scalar>,
    value: Scalar,
    blind: Scalar,
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
}

impl Msm {
    fn new(n: usize) -> Self {
        Self {
            g: vec![Scalar::ZERO; n],
            h: vec![Scalar::ZERO; n],
            value: Scalar::ZERO,
            blind: Scalar::ZERO,
            scalars: Vec::new(),
            points: Vec::new(),
        }
    }

    /// Adds `w·(RHS − LHS)` of the final verification equation, expanded over the
    /// original generators (module docs).
    fn add(&mut self, proof: &BppProof, commitments: &[Point], c: &Challenges, w: Scalar) {
        let Challenges { y, z, e, n, m, .. } = *c;
        let es = &c.rounds;
        let rounds = es.len();
        let e2 = e * e;
        let mut es_inv = es.clone();
        Scalar::batch_invert(&mut es_inv);

        // Exponent of the folded generators: s_i = Π_t e_t^(±1), +1 where bit t of i
        // (most significant first) is set. The final G is Σ y^(−i)·s_i·Gbp_i and the
        // final H is Σ s_i^(−1)·Hbp_i = Σ s_(n−1−i)·Hbp_i.
        let mut s = vec![Scalar::ZERO; n];
        s[0] = es_inv.iter().product();
        for i in 1..n {
            let lg = (usize::BITS - 1 - i.leading_zeros()) as usize;
            let t = rounds - 1 - lg;
            s[i] = s[i - (1 << lg)] * es[t] * es[t];
        }

        let y_pows = powers(&y, n + 2);
        let zpow = z_even_powers(&z, m);
        let two_pows = powers(&Scalar::from(2u64), BITS);
        let y_inv = y.invert();
        let mut y_inv_i = Scalar::ONE;
        for i in 0..n {
            let d = zpow[i / BITS] * two_pows[i % BITS];
            self.g[i] += w * (e * proof.r1 * y_inv_i * s[i] + e2 * z);
            self.h[i] += w * (e * proof.s1 * s[n - 1 - i] - e2 * (d * y_pows[n - i] + z));
            y_inv_i *= y_inv;
        }

        let sum_y: Scalar = y_pows[1..=n].iter().sum();
        let sum_d = Scalar::from(u64::MAX) * zpow.iter().sum::<Scalar>();
        self.value +=
            w * (proof.r1 * y * proof.s1 - e2 * ((z - z * z) * sum_y - z * y_pows[n + 1] * sum_d));
        self.blind += w * proof.d1;

        let mut push = |s: Scalar, p: &Point| {
            self.scalars.push(s);
            self.points.push(*p.point());
        };
        push(-w * e2, &proof.a);
        push(-w * e, &proof.a1);
        push(-w, &proof.b);
        for t in 0..rounds {
            push(-w * e2 * es[t] * es[t], &proof.l[t]);
            push(-w * e2 * es_inv[t] * es_inv[t], &proof.r[t]);
        }
        for (j, v) in commitments.iter().enumerate() {
            push(-w * e2 * y_pows[n + 1] * zpow[j], v);
        }
    }

    fn check(self) -> bool {
        let gens = bp_generators();
        let n = self.g.len();
        RistrettoPoint::vartime_multiscalar_mul(
            self.g
                .iter()
                .chain(&self.h)
                .chain([&self.value, &self.blind])
                .chain(&self.scalars),
            gens.g[..n]
                .iter()
                .chain(&gens.h[..n])
                .chain([h(), &G])
                .chain(&self.points),
        )
        .is_identity()
    }
}

fn verify_weighted(items: &[(&BppProof, &[Point])], weights: &[Scalar]) -> bool {
    let mut parsed = Vec::with_capacity(items.len());
    for (proof, commitments) in items {
        match challenges(proof, commitments) {
            Some(c) => parsed.push(c),
            None => return false,
        }
    }
    let max_n = parsed.iter().map(|c| c.n).max().unwrap_or(0);
    let mut msm = Msm::new(max_n);
    for (((proof, commitments), c), w) in items.iter().zip(&parsed).zip(weights) {
        msm.add(proof, commitments, c, *w);
    }
    msm.check()
}

/// Verifies one proof for `commitments` (in order).
pub fn verify(proof: &BppProof, commitments: &[Point]) -> bool {
    verify_weighted(&[(proof, commitments)], &[Scalar::ONE])
}

/// Verifies many proofs at once. Each proof's equation is weighted with an
/// independent random 128-bit scalar, so an invalid proof makes the batch fail
/// except with probability about 2^-128. An empty batch is valid.
pub fn batch_verify<R: RngCore + CryptoRng>(items: &[(&BppProof, &[Point])], rng: &mut R) -> bool {
    let weights: Vec<Scalar> = items
        .iter()
        .map(|_| loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes[..16]);
            let w = Scalar::from_bytes_mod_order(bytes);
            if w != Scalar::ZERO {
                break w;
            }
        })
        .collect();
    verify_weighted(items, &weights)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::test_rng::{seeded, ChaCha20Rng};

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn random_point(rng: &mut impl RngCore) -> Point {
        Point::from_point(RistrettoPoint::mul_base(&random_scalar(rng)))
    }

    fn proof_for(amounts: &[u64], rng: &mut ChaCha20Rng) -> (BppProof, Vec<Point>) {
        let masks: Vec<Scalar> = amounts.iter().map(|_| random_scalar(rng)).collect();
        prove(amounts, &masks, rng).unwrap()
    }

    /// Direct, round-by-round verifier written from the module-level equations,
    /// used to cross-check the optimized single-MSM verifier.
    fn verify_naive(proof: &BppProof, commitments: &[Point]) -> bool {
        let Some(c) = challenges(proof, commitments) else {
            return false;
        };
        let Challenges { y, z, e, n, m, .. } = c;
        let gens = bp_generators();
        let hv = *h();
        let y_pows = powers(&y, n + 2);
        let zpow = z_even_powers(&z, m);
        let two_pows = powers(&Scalar::from(2u64), BITS);
        let d: Vec<Scalar> = (0..n)
            .map(|i| zpow[i / BITS] * two_pows[i % BITS])
            .collect();
        let sum_y: Scalar = y_pows[1..=n].iter().sum();
        let sum_d: Scalar = d.iter().sum();

        // Â
        let mut p = *proof.a.point();
        for i in 0..n {
            p += -z * gens.g[i] + (d[i] * y_pows[n - i] + z) * gens.h[i];
        }
        for (j, v) in commitments.iter().enumerate() {
            p += zpow[j] * y_pows[n + 1] * v.point();
        }
        p += ((z - z * z) * sum_y - z * y_pows[n + 1] * sum_d) * hv;

        // WIP folding.
        let mut g_vec: Vec<RistrettoPoint> = gens.g[..n].to_vec();
        let mut h_vec: Vec<RistrettoPoint> = gens.h[..n].to_vec();
        for (t, e_t) in c.rounds.iter().enumerate() {
            let half = g_vec.len() / 2;
            let e_inv = e_t.invert();
            let y_inv_h = y_pows[half].invert();
            g_vec = (0..half)
                .map(|i| e_inv * g_vec[i] + e_t * y_inv_h * g_vec[half + i])
                .collect();
            h_vec = (0..half)
                .map(|i| e_t * h_vec[i] + e_inv * h_vec[half + i])
                .collect();
            p = e_t * e_t * proof.l[t].point() + p + e_inv * e_inv * proof.r[t].point();
        }
        let lhs = e * e * p + e * proof.a1.point() + proof.b.point();
        let rhs = e * proof.r1 * g_vec[0]
            + e * proof.s1 * h_vec[0]
            + proof.r1 * y * proof.s1 * hv
            + proof.d1 * G;
        lhs == rhs
    }

    #[test]
    fn proves_and_verifies_every_output_count() {
        let mut rng = seeded(300);
        for k in 1..=MAX_OUTPUTS {
            let amounts: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
            let (proof, v) = proof_for(&amounts, &mut rng);
            assert_eq!(proof.l.len(), rounds(k).unwrap());
            assert_eq!(proof.encoded_len(), proof_len(k).unwrap());
            assert!(verify(&proof, &v), "k = {k}");
        }
    }

    #[test]
    fn boundary_amounts() {
        let mut rng = seeded(301);
        let (proof, v) = proof_for(&[0, u64::MAX, 1, 1 << 63], &mut rng);
        assert!(verify(&proof, &v));
        assert!(verify_naive(&proof, &v));
    }

    #[test]
    fn optimized_verifier_matches_naive_verifier() {
        let mut rng = seeded(302);
        for k in [1, 2, 3, 5, 8] {
            let amounts: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
            let (proof, v) = proof_for(&amounts, &mut rng);
            assert!(verify_naive(&proof, &v), "naive, k = {k}");
            assert!(verify(&proof, &v), "msm, k = {k}");
            // And on invalid proofs they agree too.
            let mut bad = proof.clone();
            bad.s1 += Scalar::ONE;
            assert!(!verify_naive(&bad, &v) && !verify(&bad, &v));
            let mut bad = proof.clone();
            bad.l[0] = random_point(&mut rng);
            assert!(!verify_naive(&bad, &v) && !verify(&bad, &v));
        }
    }

    #[test]
    fn every_single_element_mutation_is_rejected() {
        let mut rng = seeded(303);
        let (proof, v) = proof_for(&[5, 6, 7], &mut rng);
        assert!(verify(&proof, &v));
        let other = random_point(&mut rng);
        let mut cases: Vec<BppProof> = Vec::new();
        for f in 0..6 {
            let mut p = proof.clone();
            match f {
                0 => p.a = other,
                1 => p.a1 = other,
                2 => p.b = other,
                3 => p.r1 += Scalar::ONE,
                4 => p.s1 += Scalar::ONE,
                _ => p.d1 += Scalar::ONE,
            }
            cases.push(p);
        }
        for t in 0..proof.l.len() {
            let mut p = proof.clone();
            p.l[t] = other;
            cases.push(p);
            let mut p = proof.clone();
            p.r[t] = other;
            cases.push(p);
            let mut p = proof.clone();
            p.l.swap(t, (t + 1) % proof.l.len());
            cases.push(p);
        }
        let mut p = proof.clone();
        std::mem::swap(&mut p.l, &mut p.r);
        cases.push(p);
        for (i, p) in cases.iter().enumerate() {
            assert!(!verify(p, &v), "mutation {i}");
        }
    }

    #[test]
    fn statement_is_bound() {
        let mut rng = seeded(304);
        let (proof, v) = proof_for(&[10, 20], &mut rng);
        // Different amount in a commitment.
        let shifted = Point::from_point(v[0].point() + h());
        assert!(!verify(&proof, &[shifted, v[1]]));
        // Commitment order.
        assert!(!verify(&proof, &[v[1], v[0]]));
        // Missing or extra commitment (the shape still fits for 2 -> 1 is not
        // possible; 2 -> 3 pads to 4 and needs one more round).
        assert!(!verify(&proof, &v[..1]));
        assert!(!verify(&proof, &[v[0], v[1], v[0]]));
    }

    #[test]
    fn malformed_shapes_are_rejected_without_panicking() {
        let mut rng = seeded(305);
        let (proof, v) = proof_for(&[1], &mut rng);
        let mut p = proof.clone();
        p.l.pop();
        assert!(!verify(&p, &v));
        let mut p = proof.clone();
        p.r.push(v[0]);
        assert!(!verify(&p, &v));
        assert!(!verify(&proof, &[]));
        let many = vec![v[0]; MAX_OUTPUTS + 1];
        assert!(!verify(&proof, &many));
        assert_eq!(
            prove(&[], &[], &mut rng).unwrap_err(),
            BppError::OutputCount
        );
        assert_eq!(
            prove(&[1; 17], &[Scalar::ONE; 17], &mut rng).unwrap_err(),
            BppError::OutputCount
        );
        assert_eq!(
            prove(&[1, 2], &[Scalar::ONE], &mut rng).unwrap_err(),
            BppError::MaskCount
        );
    }

    /// A malicious prover that runs the protocol honestly except for its witness
    /// vector. It tries to prove amounts outside [0, 2^64), the core of an
    /// inflation attack.
    fn malicious_proof(
        a_l: Vec<Scalar>,
        value: Scalar,
        rng: &mut ChaCha20Rng,
    ) -> (BppProof, Vec<Point>) {
        let gamma = random_scalar(rng);
        let v = Point::from_point(RistrettoPoint::mul_base(&gamma) + value * h());
        let mut hedge = HedgedRng::new(&[b"evil"], &[], rng);
        let proof = prove_bits(&a_l, &[gamma], &[v], &mut hedge).unwrap();
        (proof, vec![v])
    }

    #[test]
    fn forged_out_of_range_proofs_fail() {
        let mut rng = seeded(306);
        // Control: the malicious code path produces valid proofs for honest witnesses.
        let bits =
            |x: u64| -> Vec<Scalar> { (0..64).map(|b| Scalar::from((x >> b) & 1)).collect() };
        let (p, v) = malicious_proof(bits(u64::MAX), Scalar::from(u64::MAX), &mut rng);
        assert!(verify(&p, &v));

        // 2^64 using a non-binary "bit" (a_L[63] = 2).
        let mut two = vec![Scalar::ZERO; 64];
        two[63] = Scalar::from(2u64);
        let two_64 = Scalar::from(1u128 << 64);
        let (p, v) = malicious_proof(two, two_64, &mut rng);
        assert!(!verify(&p, &v), "2^64 with a non-binary bit");

        // -1 (i.e. ℓ − 1): bits of 2^64 − 1 do not match a commitment to −1.
        let (p, v) = malicious_proof(bits(u64::MAX), -Scalar::ONE, &mut rng);
        assert!(!verify(&p, &v), "negative amount");

        // −5 represented with a negative "bit" (a_L[0] = −5).
        let mut neg = vec![Scalar::ZERO; 64];
        neg[0] = -Scalar::from(5u64);
        let (p, v) = malicious_proof(neg, -Scalar::from(5u64), &mut rng);
        assert!(!verify(&p, &v), "negative bit");
    }

    #[test]
    fn batch_verification() {
        let mut rng = seeded(307);
        let proofs: Vec<(BppProof, Vec<Point>)> = (1..=5)
            .map(|k| {
                let amounts: Vec<u64> = (0..k).map(|i| i as u64 * 1000).collect();
                proof_for(&amounts, &mut rng)
            })
            .collect();
        let items: Vec<(&BppProof, &[Point])> =
            proofs.iter().map(|(p, v)| (p, v.as_slice())).collect();
        assert!(batch_verify(&items, &mut rng));
        assert!(batch_verify(&[], &mut rng));
        // One bad proof among many fails the batch, wherever it is.
        for bad_index in 0..items.len() {
            let mut bad = proofs[bad_index].0.clone();
            bad.d1 += Scalar::ONE;
            let mut items2 = items.clone();
            items2[bad_index] = (&bad, items[bad_index].1);
            assert!(!batch_verify(&items2, &mut rng), "bad proof at {bad_index}");
        }
    }

    /// Two invalid proofs whose errors cancel pass an unweighted sum but not the
    /// randomly weighted batch.
    #[test]
    fn batch_weights_prevent_cancellation() {
        let mut rng = seeded(308);
        let (p1, v1) = proof_for(&[1], &mut rng);
        let (p2, v2) = proof_for(&[2], &mut rng);
        let mut b1 = p1.clone();
        let mut b2 = p2.clone();
        b1.d1 += Scalar::ONE; // adds +1·G to the equation
        b2.d1 -= Scalar::ONE; // adds −1·G
        let items: Vec<(&BppProof, &[Point])> = vec![(&b1, &v1), (&b2, &v2)];
        assert!(
            verify_weighted(&items, &[Scalar::ONE, Scalar::ONE]),
            "cancels when unweighted"
        );
        assert!(!batch_verify(&items, &mut rng));
    }

    /// Property test: random amounts and output counts.
    #[test]
    fn property_random_statements() {
        let mut rng = seeded(309);
        for _ in 0..12 {
            let k = 1 + (rng.next_u32() as usize % MAX_OUTPUTS);
            let amounts: Vec<u64> = (0..k)
                .map(|_| rng.next_u64() >> (rng.next_u32() % 64))
                .collect();
            let (proof, v) = proof_for(&amounts, &mut rng);
            assert!(verify(&proof, &v));
            let j = rng.next_u32() as usize % k;
            let mut v2 = v.clone();
            v2[j] = Point::from_point(v[j].point() + RistrettoPoint::mul_base(&Scalar::ONE));
            assert!(!verify(&proof, &v2));
        }
    }

    /// Zero-knowledge sanity: proofs for different amounts have the same shape and
    /// no repeated elements.
    #[test]
    fn proofs_do_not_repeat_elements() {
        let mut rng = seeded(310);
        let (p1, _) = proof_for(&[0], &mut rng);
        let (p2, _) = proof_for(&[0], &mut rng);
        assert_eq!(p1.encoded_len(), p2.encoded_len());
        assert_ne!(p1.a, p2.a);
        assert_ne!(p1.l[0], p2.l[0]);
        assert_ne!(p1.r1, p2.r1);
    }
}
