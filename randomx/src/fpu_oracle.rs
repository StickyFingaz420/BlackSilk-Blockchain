//! Differential test of `fpu.rs` against an independent IEEE 754 oracle
//! (dossier 05 C3; decisions "Agent 44": `rustc_apfloat` as a dev-dependency).
//!
//! The oracle is `rustc_apfloat`, a pure-Rust port of LLVM's APFloat, with the
//! rounding mode passed explicitly (it never touches the hardware mode):
//! - add, sub, mul, div: `ieee::Double` with the corresponding `Round`;
//! - sqrt (APFloat has none): the defining inequalities of each rounding
//!   mode, checked exactly in `ieee::Quad` (113-bit significand). For a double
//!   `r`, `r * r` needs at most 106 bits and a midpoint squared at most 108,
//!   so every comparison is exact. The hardware square root is only the
//!   starting guess of the search; a wrong guess cannot pass the inequalities.
//!
//! Results are compared bit for bit (the sign of zero included). How
//! independent the check is depends on the mode: in Nearest, `fpu.rs` returns
//! the hardware result, so those comparisons cross-check the oracle against
//! the hardware (and sqrt's search against both); in the directed modes the
//! expected value comes from `rustc_apfloat` alone (from its `Quad`
//! arithmetic for sqrt), with `oracle_matches_known_ieee_results` as the only
//! check of the oracle itself.
//!
//! Operands come from the domain RandomX can reach (spec 4.3 and 5.3; the
//! masks below repeat `vm.rs`), plus IEEE edge cases, plus a "wide" set of
//! random normal operands whose oracle result is normal, zero or an
//! overflow. `fpu.rs` documents that it is exact only where no subnormal
//! appears, so subnormal results are skipped and counted, never compared;
//! the RandomX samplers must produce none.
//! - f group (FADD_R/M, FSUB_R/M): reloaded every iteration from two i32
//!   (exact), then changed by a registers in [1, 2^32), by memory i32 and by
//!   FSCAL, which XORs the sign and the low 4 exponent bits. Sums of loaded
//!   values and a registers stay below about 2^34, but FSCAL maps the binade
//!   [2^33, 2^34) to [2^48, 2^49); a few FADD_R steps can cross 2^49, and a
//!   second FSCAL maps [2^49, 2^50) to [2^64, 2^65), so |f| reaches about
//!   2^64·(1 + 2^-9). Leaving that binade needs ~2^32 more additions. So the
//!   samplers cover |f| up to 2^65 (fpu.rs's own comment, "below ~3e14", is
//!   too low; a README follow-up), plus ±0 and ±2^-1008 (FSCAL of ∓0).
//! - e group (FMUL_R, FDIV_M, FSQRT_R): positive. Loaded through the e mask
//!   into [2^-255, 2), multiplied by a registers, divided by masked values in
//!   [2^-255, 2), so it can grow past `f64::MAX` (then ±MAX or +inf by mode)
//!   and +inf propagates.
//!
//! Quick mode (every `cargo test`): 10^5 RandomX-domain samples per op and
//! mode, plus a quarter as many wide samples. Full mode, opt-in:
//! `cargo test --release -p blacksilk-randomx fpu_oracle_full -- --ignored --nocapture --test-threads=1`
//! (10^7 per op and mode).

use crate::fpu::{self, Rounding};
use rustc_apfloat::ieee::{Double, Quad};
use rustc_apfloat::{Float, FloatConvert, Round, Status};
use std::cmp::Ordering;

const MODES: [Rounding; 4] = [
    Rounding::Nearest,
    Rounding::Down,
    Rounding::Up,
    Rounding::Zero,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
}

const OPS: [Op; 5] = [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Sqrt];

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

fn ap_round(mode: Rounding) -> Round {
    match mode {
        Rounding::Nearest => Round::NearestTiesToEven,
        Rounding::Down => Round::TowardNegative,
        Rounding::Up => Round::TowardPositive,
        Rounding::Zero => Round::TowardZero,
    }
}

fn to_ap(x: f64) -> Double {
    Double::from_bits(x.to_bits() as u128)
}

fn from_ap(x: Double) -> f64 {
    f64::from_bits(x.to_bits() as u64)
}

/// `x` as a binary128 value (exact: every double is a quad).
fn quad(x: f64) -> Quad {
    let mut loses_info = false;
    let q: Quad = to_ap(x).convert(&mut loses_info).value;
    assert!(!loses_info, "double -> quad must be exact");
    q
}

fn quad_mul_exact(a: Quad, b: Quad) -> Quad {
    let p = a.mul_r(b, Round::NearestTiesToEven);
    assert_eq!(p.status, Status::OK, "quad product must be exact");
    p.value
}

fn quad_cmp(a: Quad, b: Quad) -> Ordering {
    a.partial_cmp(&b).expect("no NaN in the oracle")
}

/// Correctly rounded square root under `mode`, from the defining inequalities.
fn sqrt_oracle(a: f64, mode: Rounding) -> f64 {
    // IEEE 754: sqrt(±0) = ±0, sqrt(+inf) = +inf.
    if a == 0.0 || a == f64::INFINITY {
        return a;
    }
    assert!(
        a > 0.0 && a.is_finite(),
        "sqrt operand out of domain: {a:e}"
    );
    let aq = quad(a);
    let sq = |r: f64| {
        let q = quad(r);
        quad_mul_exact(q, q)
    };
    // d = the largest double with d * d <= a.
    let mut d = a.sqrt();
    for _ in 0..4 {
        if quad_cmp(sq(d), aq) == Ordering::Greater {
            d = d.next_down();
        }
    }
    for _ in 0..4 {
        if quad_cmp(sq(d.next_up()), aq) != Ordering::Greater {
            d = d.next_up();
        }
    }
    assert!(
        quad_cmp(sq(d), aq) != Ordering::Greater
            && quad_cmp(sq(d.next_up()), aq) == Ordering::Greater,
        "sqrt oracle could not bracket sqrt({a:e})"
    );
    let exact = quad_cmp(sq(d), aq) == Ordering::Equal;
    match mode {
        _ if exact => d,
        Rounding::Down | Rounding::Zero => d,
        Rounding::Up => d.next_up(),
        Rounding::Nearest => {
            // The midpoint d + ulp/2 has 54 significant bits; its square, 108.
            let half_ulp = (d.next_up() - d) / 2.0;
            let mid = quad(d).add_r(quad(half_ulp), Round::NearestTiesToEven);
            assert_eq!(mid.status, Status::OK, "midpoint must be exact");
            match quad_cmp(aq, quad_mul_exact(mid.value, mid.value)) {
                Ordering::Less => d,
                Ordering::Greater => d.next_up(),
                // An odd 54-bit significand squared has more than 53 bits.
                Ordering::Equal => unreachable!("a square root cannot be a midpoint"),
            }
        }
    }
}

fn oracle(op: Op, a: f64, b: f64, mode: Rounding) -> f64 {
    let r = ap_round(mode);
    match op {
        Op::Add => from_ap(to_ap(a).add_r(to_ap(b), r).value),
        Op::Sub => from_ap(to_ap(a).sub_r(to_ap(b), r).value),
        Op::Mul => from_ap(to_ap(a).mul_r(to_ap(b), r).value),
        Op::Div => from_ap(to_ap(a).div_r(to_ap(b), r).value),
        Op::Sqrt => sqrt_oracle(a, mode),
    }
}

fn candidate(op: Op, a: f64, b: f64, mode: Rounding) -> f64 {
    match op {
        Op::Add => fpu::add(a, b, mode),
        Op::Sub => fpu::sub(a, b, mode),
        Op::Mul => fpu::mul(a, b, mode),
        Op::Div => fpu::div(a, b, mode),
        Op::Sqrt => fpu::sqrt(a, mode),
    }
}

// ---------------------------------------------------------------------------
// Operand samplers
// ---------------------------------------------------------------------------

/// SplitMix64: a fixed, dependency-free stream, so every run is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn sign(&mut self) -> bool {
        self.next() & 1 == 1
    }

    /// A uniform integer in `lo..=hi`.
    fn range(&mut self, lo: i32, hi: i32) -> i32 {
        lo + self.below((hi - lo + 1) as u64) as i32
    }
}

const MANTISSA_MASK: u64 = (1 << 52) - 1;
// vm.rs: the e-register mask and FSCAL.
const DYNAMIC_MANTISSA_MASK: u64 = (1 << (52 + 4)) - 1;
const CONST_EXPONENT_BITS: u64 = 0x300;
const FSCAL_MASK: u64 = 0x80F0_0000_0000_0000;

/// ±1.m × 2^exp, a normal double.
fn make(negative: bool, exp: i32, mantissa: u64) -> f64 {
    let biased = exp + 1023;
    assert!((1..=2046).contains(&biased));
    f64::from_bits(((negative as u64) << 63) | ((biased as u64) << 52) | (mantissa & MANTISSA_MASK))
}

/// A memory operand half: i32 converted to double (exact).
fn i32_value(rng: &mut Rng) -> f64 {
    rng.next() as u32 as i32 as f64
}

/// An a register (vm.rs `small_positive_float_bits`): [1, 2^32).
fn a_value(rng: &mut Rng) -> f64 {
    let entropy = rng.next();
    let mantissa = if rng.below(16) == 0 {
        0
    } else {
        entropy & MANTISSA_MASK
    };
    f64::from_bits((((entropy >> 59) + 1023) << 52) | mantissa)
}

/// A memory operand through the e mask (vm.rs `mask_e`/`float_mask`): [2^-255, 2).
fn e_masked(rng: &mut Rng) -> f64 {
    let x = i32_value(rng);
    let entropy = rng.next();
    let mask = (entropy & ((1 << 22) - 1)) | ((CONST_EXPONENT_BITS | ((entropy >> 60) << 4)) << 52);
    f64::from_bits((x.to_bits() & DYNAMIC_MANTISSA_MASK) | mask)
}

/// An f register value.
fn f_value(rng: &mut Rng) -> f64 {
    match rng.below(16) {
        0..=3 => i32_value(rng),
        4..=5 => a_value(rng),
        // Sums of i32 and a values, and their FSCAL images: |x| in [2^-80, 2^65).
        6..=11 => {
            let (s, e, m) = (rng.sign(), rng.range(-80, 64), rng.next());
            make(s, e, m)
        }
        // Integers up to 2^48 (exact sums of loaded values).
        12 => {
            let v = (rng.next() >> 16) as f64;
            if rng.sign() {
                -v
            } else {
                v
            }
        }
        13 => {
            let x = if rng.sign() {
                i32_value(rng)
            } else {
                a_value(rng)
            };
            f64::from_bits(x.to_bits() ^ FSCAL_MASK)
        }
        // ±0 and ±2^-1008 (FSCAL of ∓0).
        _ => {
            let z = [0.0, -0.0, 2f64.powi(-1008), -(2f64.powi(-1008))];
            z[rng.below(4) as usize]
        }
    }
}

/// An e register value (positive; +inf and the overflow boundary included).
fn e_value(rng: &mut Rng) -> f64 {
    match rng.below(32) {
        0..=11 => e_masked(rng),
        12..=25 => {
            let (e, m) = (rng.range(-520, 1023), rng.next());
            make(false, e, m)
        }
        26..=27 => f64::from_bits(f64::MAX.to_bits() - rng.below(1 << 20)),
        28..=29 => {
            let (e, m) = (rng.range(990, 1023), rng.next());
            make(false, e, m)
        }
        30 => f64::MAX,
        _ => f64::INFINITY,
    }
}

/// The ulp of a finite nonzero double below MAX.
fn ulp(x: f64) -> f64 {
    let x = x.abs();
    x.next_up() - x
}

/// An (f, operand) pair for FADD/FSUB, with constructed cancellations, ties and
/// exact sums. `op` is Add or Sub; ties and cancellations are built for it.
fn add_pair(rng: &mut Rng, op: Op) -> (f64, f64) {
    let sub = op == Op::Sub;
    // Returns (a, y) where the exact result is a + y; for Sub the operand is -y.
    let (a, y) = match rng.below(12) {
        0..=3 => (f_value(rng), f_value(rng)),
        4..=5 => (f_value(rng), a_value(rng)),
        6 => (f_value(rng), i32_value(rng)),
        7 => {
            let a = f_value(rng);
            (a, -a)
        }
        // Halfway cases: a ± ulp/2 and a ± 3ulp/2 (exact ties under Nearest).
        8..=9 => {
            let (s, e, m) = (rng.sign(), rng.range(-15, 64), rng.next());
            let a = make(s, e, m);
            let k = if rng.sign() { 0.5 } else { 1.5 };
            let y = k * ulp(a);
            (a, if rng.sign() { -y } else { y })
        }
        // Exact results: a ± k ulp, k < 2^20.
        _ => {
            let (s, e, m) = (rng.sign(), rng.range(-15, 64), rng.next());
            let a = make(s, e, m);
            let y = (1 + rng.below(1 << 20)) as f64 * ulp(a);
            (a, if rng.sign() { -y } else { y })
        }
    };
    let (a, y) = if rng.below(4) == 0 { (y, a) } else { (a, y) };
    if sub {
        (a, -y)
    } else {
        (a, y)
    }
}

/// A RandomX-domain operand pair for `op` (`b` is ignored for Sqrt).
fn randomx_pair(rng: &mut Rng, op: Op) -> (f64, f64) {
    match op {
        Op::Add | Op::Sub => add_pair(rng, op),
        Op::Mul => (e_value(rng), a_value(rng)),
        Op::Div => (e_value(rng), e_masked(rng)),
        Op::Sqrt => {
            if rng.below(16) == 0 {
                // A perfect square: a 26-bit significand squared is exact.
                let (e, m) = (rng.range(-300, 511), rng.next() & !((1 << 27) - 1));
                let r = make(false, e, m);
                (r * r, 0.0)
            } else {
                (e_value(rng), 0.0)
            }
        }
    }
}

/// Any normal double (positive for sqrt).
fn wide_value(rng: &mut Rng, positive: bool) -> f64 {
    let (s, e, m) = (!positive && rng.sign(), rng.range(-1022, 1023), rng.next());
    make(s, e, m)
}

fn wide_pair(rng: &mut Rng, op: Op) -> (f64, f64) {
    match op {
        Op::Sqrt => (wide_value(rng, true), 0.0),
        Op::Add | Op::Sub if rng.below(2) == 0 => {
            // Close exponents, so the operands interact.
            let (e, d) = (rng.range(-1000, 1023), rng.range(-60, 0));
            let a = make(rng.sign(), e, rng.next());
            let b = make(rng.sign(), (e + d).max(-1022), rng.next());
            (a, b)
        }
        _ => (wide_value(rng, false), wide_value(rng, false)),
    }
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

/// A case where fpu.rs and the oracle differ (all values as bit patterns).
struct Disagreement {
    op: Op,
    mode: Rounding,
    a: u64,
    b: u64,
    fpu: u64,
    oracle: u64,
}

impl std::fmt::Debug for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {:?}: a={:#018x} ({:e}) b={:#018x} ({:e}) fpu={:#018x} oracle={:#018x}",
            self.op,
            self.mode,
            self.a,
            f64::from_bits(self.a),
            self.b,
            f64::from_bits(self.b),
            self.fpu,
            self.oracle
        )
    }
}

#[derive(Default)]
struct Tally {
    compared: u64,
    skipped: u64,
    /// Every disagreement is counted ...
    mismatches: u64,
    /// ... but only the first `MAX_EXAMPLES` are kept as examples.
    examples: Vec<Disagreement>,
}

const MAX_EXAMPLES: usize = 64;

impl Tally {
    /// Compares one case; `wide` cases may be skipped (an exact result below
    /// the normal range, i.e. underflow), RandomX-domain cases must never
    /// need to be. Underflow is judged on the round-toward-zero result: for
    /// nonzero operands it is subnormal or zero exactly when |exact| < 2^-1022.
    fn check(&mut self, op: Op, a: f64, b: f64, mode: Rounding, wide: bool) {
        let want = oracle(op, a, b, mode);
        let toward_zero = oracle(op, a, b, Rounding::Zero);
        let nonzero_operands = a != 0.0 && (op == Op::Sqrt || b != 0.0);
        let underflow = toward_zero.is_subnormal()
            || (toward_zero == 0.0 && nonzero_operands && matches!(op, Op::Mul | Op::Div));
        if underflow {
            assert!(
                wide,
                "RandomX-domain sampler produced an out-of-domain result: {op:?} {mode:?} a={:#018x} b={:#018x}",
                a.to_bits(),
                b.to_bits()
            );
            self.skipped += 1;
            return;
        }
        let got = candidate(op, a, b, mode);
        self.compared += 1;
        if got.to_bits() == want.to_bits() {
            return;
        }
        self.mismatches += 1;
        if self.examples.len() < MAX_EXAMPLES {
            self.examples.push(Disagreement {
                op,
                mode,
                a: a.to_bits(),
                b: b.to_bits(),
                fpu: got.to_bits(),
                oracle: want.to_bits(),
            });
        }
    }
}

/// Runs `n` RandomX-domain and `n / 4` wide samples per op and mode; panics
/// with the total count of disagreements and, as examples, the first 64 per
/// op, mode and sample set with their exact operands.
fn run(n: u64, seed: u64) {
    let mut total = 0u64;
    let mut examples = Vec::new();
    println!("op   mode     randomx-domain   wide (skipped)   disagreements");
    for op in OPS {
        for (mi, mode) in MODES.into_iter().enumerate() {
            let mut rng = Rng(seed ^ ((op as u64) << 8) ^ mi as u64);
            let mut domain = Tally::default();
            for _ in 0..n {
                let (a, b) = randomx_pair(&mut rng, op);
                domain.check(op, a, b, mode, false);
            }
            let mut wide = Tally::default();
            for _ in 0..n / 4 {
                let (a, b) = wide_pair(&mut rng, op);
                wide.check(op, a, b, mode, true);
            }
            let bad = domain.mismatches + wide.mismatches;
            println!(
                "{:<4} {:<8} {:>14} {:>9} ({:>6}) {:>8}",
                format!("{op:?}"),
                format!("{mode:?}"),
                domain.compared,
                wide.compared,
                wide.skipped,
                bad
            );
            assert_eq!(domain.compared, n);
            total += bad;
            examples.extend(domain.examples);
            examples.extend(wide.examples);
        }
    }
    assert!(
        total == 0,
        "fpu.rs disagrees with the IEEE oracle in {total} case(s); {} examples:\n{:#?}",
        examples.len(),
        examples
    );
}

/// Hand-picked cases: exact results, ties, the largest finite value,
/// overflow, infinities and signed zeros, in every mode.
fn edge_cases() -> Vec<(Op, f64, f64)> {
    let max = f64::MAX;
    let inf = f64::INFINITY;
    let half_ulp_max = 2f64.powi(970);
    let quarter_ulp_max = 2f64.powi(969);
    let tiny = 2f64.powi(-1008);
    let mut v = vec![
        // Exact results.
        (Op::Add, 1.0, 1.0),
        (Op::Add, 3.0, -3.0),
        (Op::Add, -3.0, 3.0),
        (Op::Sub, 3.0, 3.0),
        (Op::Sub, -3.0, -3.0),
        (Op::Add, 0.0, 0.0),
        (Op::Add, 0.0, -0.0),
        (Op::Add, -0.0, 0.0),
        (Op::Add, -0.0, -0.0),
        (Op::Sub, 0.0, 0.0),
        (Op::Sub, -0.0, 0.0),
        (Op::Sub, 0.0, -0.0),
        (Op::Add, tiny, -tiny),
        (Op::Add, tiny, tiny),
        (Op::Add, -tiny, 1.0),
        (Op::Add, tiny, 4294967295.0),
        (Op::Sub, -tiny, 2147483648.0),
        (Op::Mul, 1.5, 2.0),
        (Op::Div, 6.0, 3.0),
        (Op::Div, 1.0, 4.0),
        (Op::Sqrt, 4.0, 0.0),
        (Op::Sqrt, 2f64.powi(-254), 0.0),
        (Op::Sqrt, 0.0, 0.0),
        (Op::Sqrt, -0.0, 0.0),
        // Ties: 1 + ulp/2 (to even: down), next_up(1) + ulp/2 (to even: up).
        (Op::Add, 1.0, f64::EPSILON / 2.0),
        (Op::Add, 1.0f64.next_up(), f64::EPSILON / 2.0),
        (Op::Add, -1.0, -f64::EPSILON / 2.0),
        (Op::Sub, 1.0f64.next_up(), -f64::EPSILON / 2.0),
        (Op::Add, 2f64.powi(48), 0.5 * ulp(2f64.powi(48))),
        (Op::Add, 4503599627370497.0, 0.5),
        // The top of the f range (|f| about 2^64 after two FSCALs): a tie and an a register.
        (Op::Add, 2f64.powi(64), 2048.0),
        (
            Op::Sub,
            -(2f64.powi(64) * (1.0 + 2f64.powi(-9))),
            4294967295.0,
        ),
        // Inexact.
        (Op::Div, 1.0, 3.0),
        (Op::Div, -1.0, 3.0),
        (Op::Sqrt, 2.0, 0.0),
        (Op::Mul, 1.0 + f64::EPSILON, 1.0 + f64::EPSILON),
        // The largest finite value and overflow.
        (Op::Add, max, 0.0),
        (Op::Add, max, quarter_ulp_max),
        (Op::Add, max, half_ulp_max),
        (Op::Add, -max, -quarter_ulp_max),
        (Op::Add, -max, -half_ulp_max),
        (Op::Add, max, max),
        (Op::Sub, -max, max),
        (Op::Mul, max, 1.0),
        (Op::Mul, max, 1.0 + f64::EPSILON),
        (Op::Mul, max, 4294967295.0),
        (Op::Mul, 2f64.powi(1000), 2f64.powi(24)),
        (Op::Mul, 2f64.powi(1023) * 1.5, 1.5),
        (Op::Div, max, 1.0),
        (Op::Div, max, 0.5),
        (Op::Div, max, 1.0f64.next_down()),
        (Op::Div, 2f64.powi(800), 2f64.powi(-255)),
        (Op::Div, max, 2f64.powi(-255)),
        (Op::Sqrt, max, 0.0),
        // Infinite operands.
        (Op::Add, inf, -3.5),
        (Op::Add, inf, 1.0),
        (Op::Mul, inf, 3.5),
        (Op::Div, inf, 2f64.powi(-255)),
        (Op::Sqrt, inf, 0.0),
    ];
    // a + 2^-52 a and similar near-overflow products for every binade near MAX.
    for e in 1015..=1023 {
        v.push((Op::Mul, make(false, e, MANTISSA_MASK), 2.0));
        v.push((Op::Mul, make(false, e, 1), 1.0 + f64::EPSILON));
    }
    v
}

#[test]
fn oracle_matches_known_ieee_results() {
    // The oracle itself, against values fixed by IEEE 754 (not by fpu.rs).
    let max = f64::MAX;
    let inf = f64::INFINITY;
    let q = 2f64.powi(969);
    assert_eq!(oracle(Op::Add, max, q, Rounding::Nearest), max);
    assert_eq!(oracle(Op::Add, max, q, Rounding::Up), inf);
    assert_eq!(oracle(Op::Add, max, q, Rounding::Down), max);
    assert_eq!(oracle(Op::Add, max, 2f64.powi(970), Rounding::Nearest), inf);
    assert_eq!(oracle(Op::Mul, -max, 3.0, Rounding::Up), -max);
    assert_eq!(oracle(Op::Mul, -max, 3.0, Rounding::Down), -inf);
    assert_eq!(oracle(Op::Mul, max, 3.0, Rounding::Zero), max);
    assert!(oracle(Op::Add, 3.0, -3.0, Rounding::Down).is_sign_negative());
    assert!(oracle(Op::Add, 3.0, -3.0, Rounding::Up).is_sign_positive());
    assert_eq!(
        oracle(Op::Add, 1.0, f64::EPSILON / 2.0, Rounding::Nearest),
        1.0
    );
    assert_eq!(
        oracle(Op::Add, 1.0, f64::EPSILON / 2.0, Rounding::Up),
        1.0f64.next_up()
    );
    let third_down = oracle(Op::Div, 1.0, 3.0, Rounding::Down);
    assert_eq!(
        oracle(Op::Div, 1.0, 3.0, Rounding::Up),
        third_down.next_up()
    );
    assert_eq!(oracle(Op::Div, 1.0, 3.0, Rounding::Nearest), 1.0 / 3.0);
    // sqrt(2) = 1.41421356237309504880...; 0x3FF6A09E667F3BCD = 1.41421356237309514547...
    // is above it and nearest, 0x3FF6A09E667F3BCC = 1.41421356237309492343... below it.
    assert_eq!(
        oracle(Op::Sqrt, 2.0, 0.0, Rounding::Nearest).to_bits(),
        0x3FF6_A09E_667F_3BCD
    );
    assert_eq!(
        oracle(Op::Sqrt, 2.0, 0.0, Rounding::Down).to_bits(),
        0x3FF6_A09E_667F_3BCC
    );
    assert_eq!(
        oracle(Op::Sqrt, 2.0, 0.0, Rounding::Zero).to_bits(),
        0x3FF6_A09E_667F_3BCC
    );
    assert_eq!(
        oracle(Op::Sqrt, 2.0, 0.0, Rounding::Up).to_bits(),
        0x3FF6_A09E_667F_3BCD
    );
    assert_eq!(oracle(Op::Sqrt, 4.0, 0.0, Rounding::Up), 2.0);
    assert_eq!(oracle(Op::Sqrt, max, 0.0, Rounding::Nearest), max.sqrt());
    // Every hardware (round-to-nearest) square root of a sample agrees.
    let mut rng = Rng(7);
    for _ in 0..10_000 {
        let x = wide_value(&mut rng, true);
        assert_eq!(
            oracle(Op::Sqrt, x, 0.0, Rounding::Nearest),
            x.sqrt(),
            "{x:e}"
        );
    }
}

#[test]
fn fpu_matches_oracle_on_edge_cases() {
    let mut tally = Tally::default();
    for (op, a, b) in edge_cases() {
        for mode in MODES {
            tally.check(op, a, b, mode, false);
        }
    }
    assert!(
        tally.mismatches == 0,
        "fpu.rs disagrees with the IEEE oracle in {} case(s):\n{:#?}",
        tally.mismatches,
        tally.examples
    );
    assert_eq!(tally.compared, edge_cases().len() as u64 * 4);
}

/// Quick mode: 10^5 RandomX-domain samples per op and mode.
#[test]
fn fpu_matches_oracle_quick() {
    run(100_000, 0x0B5F_0A2C_0001);
}

/// Full mode: 10^7 per op and mode (a different seed from quick mode).
#[test]
#[ignore = "about 10^8 oracle evaluations; run on demand"]
fn fpu_oracle_full() {
    run(10_000_000, 0x0B5F_0A2C_0002);
}
