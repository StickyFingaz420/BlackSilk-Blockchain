//! IEEE 754 arithmetic under the four RandomX rounding modes, in safe portable Rust.
//!
//! The reference implementation switches the hardware rounding mode (MXCSR).
//! Rust gives no sound way to do that (LLVM assumes round-to-nearest), so each
//! operation is computed with round-to-nearest and then corrected by one ulp
//! when the exact result lies on the other side of it. The sign of the exact
//! error comes from error-free transforms (TwoSum, Dekker's TwoProduct) applied
//! to operands rescaled by powers of two, so the transforms never overflow.
//!
//! Operand ranges (spec 4.3): f registers stay below ~3e14, a registers are in
//! [1, 2^32), and e registers are positive and normal. The e registers can
//! still grow past f64::MAX: FDIV_M divides by values as small as ~2^-255.
//! Overflow is therefore handled exactly as IEEE 754 prescribes (±MAX or ±inf
//! depending on the mode), and infinite operands propagate unchanged.
//! NaN and subnormal values never arise from RandomX arithmetic.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Rounding {
    Nearest = 0,
    Down = 1,
    Up = 2,
    Zero = 3,
}

impl Rounding {
    pub(crate) fn from_bits(bits: u64) -> Self {
        match bits & 3 {
            0 => Rounding::Nearest,
            1 => Rounding::Down,
            2 => Rounding::Up,
            _ => Rounding::Zero,
        }
    }
}

/// Result for finite operands whose exact result overflows (IEEE 754-2019, 7.4).
#[inline(always)]
fn overflow(negative: bool, mode: Rounding) -> f64 {
    let v = match (mode, negative) {
        (Rounding::Nearest, _) | (Rounding::Up, false) | (Rounding::Down, true) => f64::INFINITY,
        _ => f64::MAX,
    };
    if negative {
        -v
    } else {
        v
    }
}

/// `r` is the finite round-to-nearest result; `err` has the sign of (exact - r).
#[inline(always)]
fn correct(r: f64, err: f64, mode: Rounding) -> f64 {
    match mode {
        Rounding::Nearest => r,
        Rounding::Down if err < 0.0 => r.next_down(),
        Rounding::Up if err > 0.0 => r.next_up(),
        Rounding::Zero if r > 0.0 && err < 0.0 => r.next_down(),
        Rounding::Zero if r < 0.0 && err > 0.0 => r.next_up(),
        _ => r,
    }
}

/// Knuth's TwoSum: `s + e == a + b` exactly (for finite, non-overflowing `s`).
#[inline(always)]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    let e = (a - (s - bb)) + (b - bb);
    (s, e)
}

#[inline(always)]
fn split(a: f64) -> (f64, f64) {
    const SPLITTER: f64 = 134_217_729.0; // 2^27 + 1
    let c = SPLITTER * a;
    let hi = c - (c - a);
    (hi, a - hi)
}

/// Dekker's TwoProduct: `p + e == a * b` exactly (for operands of moderate magnitude).
#[inline(always)]
fn two_product(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    let (ah, al) = split(a);
    let (bh, bl) = split(b);
    let e = ((ah * bh - p) + ah * bl + al * bh) + al * bl;
    (p, e)
}

const EXP_MASK: u64 = 0x7FF << 52;

/// Rescales a normal number by a power of two so its biased exponent is `biased_exp`.
/// Exact, and preserves the rounding decision of any operation whose scaled
/// result is normal.
#[inline(always)]
fn with_exponent(x: f64, biased_exp: u64) -> f64 {
    f64::from_bits((x.to_bits() & !EXP_MASK) | (biased_exp << 52))
}

#[inline(always)]
fn biased_exponent(x: f64) -> u64 {
    (x.to_bits() & EXP_MASK) >> 52
}

#[inline]
pub(crate) fn add(a: f64, b: f64, mode: Rounding) -> f64 {
    let (s, e) = two_sum(a, b);
    if mode == Rounding::Nearest || !a.is_finite() || !b.is_finite() {
        return s;
    }
    if s.is_infinite() {
        return overflow(s < 0.0, mode);
    }
    if s == 0.0 && e == 0.0 {
        // Exact zero: -0 under roundTowardNegative unless both operands are +0.
        if mode == Rounding::Down && !(a.to_bits() == 0 && b.to_bits() == 0) {
            return -0.0;
        }
        return s;
    }
    correct(s, e, mode)
}

#[inline]
pub(crate) fn sub(a: f64, b: f64, mode: Rounding) -> f64 {
    add(a, -b, mode)
}

#[inline]
pub(crate) fn mul(a: f64, b: f64, mode: Rounding) -> f64 {
    let p = a * b;
    // Zero or infinite operands give exact results.
    if mode == Rounding::Nearest || !a.is_normal() || !b.is_normal() {
        return p;
    }
    if p.is_infinite() {
        return overflow(p < 0.0, mode);
    }
    let (_, e) = two_product(with_exponent(a, 1023), with_exponent(b, 1023));
    correct(p, e, mode)
}

#[inline]
pub(crate) fn div(a: f64, b: f64, mode: Rounding) -> f64 {
    let q = a / b;
    if mode == Rounding::Nearest || !a.is_normal() || !b.is_normal() {
        return q;
    }
    if q.is_infinite() {
        return overflow(q < 0.0, mode);
    }
    // With a', b' in [1, 2), q' = RN(a'/b') is q rescaled, and the remainder
    // a' - q'*b' is exactly representable and computed exactly.
    let (a1, b1) = (with_exponent(a, 1023), with_exponent(b, 1023));
    let q1 = a1 / b1;
    let (p, e) = two_product(q1, b1);
    let residual = (a1 - p) - e;
    // sign(a/b - q) = sign(residual) * sign(b)
    let err = if b < 0.0 { -residual } else { residual };
    correct(q, err, mode)
}

#[inline]
pub(crate) fn sqrt(a: f64, mode: Rounding) -> f64 {
    let s = a.sqrt();
    if mode == Rounding::Nearest || !a.is_normal() {
        return s;
    }
    // Rescale by an even power of two so that a' is in [1, 4).
    let a1 = with_exponent(a, 1023 + (biased_exponent(a) + 1) % 2);
    let s1 = a1.sqrt();
    let (p, e) = two_product(s1, s1);
    let residual = (a1 - p) - e; // sign(sqrt(a) - s)
    correct(s, residual, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_directed() {
        let a = 1.0;
        let b = f64::EPSILON / 4.0; // exact sum lies strictly between 1 and next_up(1)
        assert_eq!(add(a, b, Rounding::Nearest), 1.0);
        assert_eq!(add(a, b, Rounding::Down), 1.0);
        assert_eq!(add(a, b, Rounding::Up), 1.0f64.next_up());
        assert_eq!(add(a, b, Rounding::Zero), 1.0);
        assert_eq!(add(-a, -b, Rounding::Down), (-1.0f64).next_down());
        assert_eq!(add(-a, -b, Rounding::Up), -1.0);
        assert_eq!(add(-a, -b, Rounding::Zero), -1.0);
    }

    #[test]
    fn exact_zero_sign() {
        assert!(add(3.0, -3.0, Rounding::Down).is_sign_negative());
        assert!(add(3.0, -3.0, Rounding::Up).is_sign_positive());
        assert!(sub(3.0, 3.0, Rounding::Zero).is_sign_positive());
    }

    #[test]
    fn mul_div_sqrt_directed() {
        let down = div(1.0, 3.0, Rounding::Down);
        let up = div(1.0, 3.0, Rounding::Up);
        assert_eq!(up, down.next_up());
        assert!(down == 1.0 / 3.0 || up == 1.0 / 3.0);
        assert_eq!(div(1.0, 4.0, Rounding::Up), 0.25);

        let s_down = sqrt(2.0, Rounding::Down);
        let s_up = sqrt(2.0, Rounding::Up);
        assert_eq!(s_up, s_down.next_up());
        assert!(s_down == 2f64.sqrt() || s_up == 2f64.sqrt());
        assert_eq!(sqrt(4.0, Rounding::Down), 2.0);

        let x = 1.0 + f64::EPSILON;
        // (1+eps)^2 = 1 + 2eps + eps^2: the eps^2 tail separates the directed results.
        assert_eq!(mul(x, x, Rounding::Up), mul(x, x, Rounding::Down).next_up());
        assert_eq!(mul(x, x, Rounding::Zero), mul(x, x, Rounding::Down));
    }

    #[test]
    fn huge_magnitudes_use_scaled_residuals() {
        // Operands where an unscaled Dekker split (a * 2^27) would overflow.
        let a = 2f64.powi(1000) * 1.5;
        let b = 2f64.powi(20) * (1.0 + f64::EPSILON);
        let d = div(a, b, Rounding::Down);
        let u = div(a, b, Rounding::Up);
        assert!(d.is_finite() && u.is_finite());
        assert_eq!(u, d.next_up());
        let md = mul(a, 1.0 + f64::EPSILON, Rounding::Down);
        assert_eq!(mul(a, 1.0 + f64::EPSILON, Rounding::Up), md.next_up());
    }

    #[test]
    fn overflow_follows_ieee() {
        let big = f64::MAX;
        let tiny = 2f64.powi(-100);
        assert_eq!(div(big, tiny, Rounding::Nearest), f64::INFINITY);
        assert_eq!(div(big, tiny, Rounding::Up), f64::INFINITY);
        assert_eq!(div(big, tiny, Rounding::Down), f64::MAX);
        assert_eq!(div(big, tiny, Rounding::Zero), f64::MAX);
        assert_eq!(mul(big, 3.0, Rounding::Zero), f64::MAX);
        assert_eq!(mul(-big, 3.0, Rounding::Up), -f64::MAX);
        assert_eq!(mul(-big, 3.0, Rounding::Down), f64::NEG_INFINITY);
        // A quarter ulp above MAX: nearest rounds back to MAX, Up must still overflow.
        let quarter_ulp = 2f64.powi(969);
        assert_eq!(add(big, quarter_ulp, Rounding::Nearest), f64::MAX);
        assert_eq!(add(big, quarter_ulp, Rounding::Up), f64::INFINITY);
        assert_eq!(add(big, quarter_ulp, Rounding::Zero), f64::MAX);
    }

    #[test]
    fn infinities_propagate_exactly() {
        for mode in [
            Rounding::Nearest,
            Rounding::Down,
            Rounding::Up,
            Rounding::Zero,
        ] {
            assert_eq!(mul(f64::INFINITY, 3.5, mode), f64::INFINITY);
            assert_eq!(div(f64::INFINITY, 3.5, mode), f64::INFINITY);
            assert_eq!(sqrt(f64::INFINITY, mode), f64::INFINITY);
            assert_eq!(add(f64::INFINITY, -3.5, mode), f64::INFINITY);
        }
    }
}
