//! Generalised candidate rules for the selection study (W0-03b).
//!
//! These rules exist only in this harness. [`GenLwma`] is a parametrised LWMA-1 whose
//! default parameters reproduce the pre-v3 consensus rule exactly (pinned by a test
//! against its frozen copy `crate::rules::legacy_next`). Every rule is exact integer
//! arithmetic: `u128`/`i128` intermediates, truncating division, and (for the
//! exponential rules) the aserti3-2d fixed-point `2^x` polynomial.

use crate::rules::{Asert, DifficultyRule, Lwma, RiseCap};

/// How each solve time inside the LWMA window is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solve {
    /// `step = max(1, T * num / den)`; `this = max(ts[i], prev + step)`,
    /// `st = min(this - prev, 6T)`, `prev = this`.
    /// `num = 0` (step 1) is the consensus rule; a larger step is a "virtual-time" clamp:
    /// compressed stamps count `step` each, but the counted clock runs ahead of
    /// the stamps, so later stamps count less (no counted time is created).
    Monotone { step: (u64, u64) },
    /// `this = max(ts[i], prev + 1)`, `st = clamp(this - prev, T * num / den, 6T)`,
    /// `prev = this`.
    /// The literal per-solve-time clamp `[T/k, 6T]`.
    PerBlock { lo: (u64, u64) },
    /// `st = clamp(ts[i] - ts[i-1], -6T, 6T)`: signed solve times (zawy #13/#30:
    /// negative solve times keep manipulation symmetric).
    Signed,
}

/// Parametrised LWMA-1 with optional per-block output caps.
#[derive(Clone, Debug)]
pub struct GenLwma {
    pub label: String,
    pub window: usize,
    pub solve: Solve,
    /// Floor on the weighted sum: `L >= n^2 * T * floor.0 / floor.1`. The consensus
    /// value is `(1, 20)`; `(1, 2c)` bounds `next <= c * avg_D * (n+1)/n`.
    pub floor: (u64, u64),
    /// `next <= parent + max(1, parent * num / den)`.
    pub rise: Option<(u64, u64)>,
    /// `next >= max(1, parent * den / (den + num))` (the mirror of `rise`).
    pub fall: Option<(u64, u64)>,
}

impl GenLwma {
    pub fn current() -> Self {
        Self {
            label: "LWMA-60 (generalised, = current)".into(),
            window: 60,
            solve: Solve::Monotone { step: (0, 1) },
            floor: (1, 20),
            rise: None,
            fall: None,
        }
    }

    /// The raw (uncapped) LWMA value over the window ending at the parent.
    pub fn raw(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let take = ts.len().min(self.window + 1);
        let ts = &ts[ts.len() - take..];
        let cdw = &cd[cd.len() - take..];
        let n = take.saturating_sub(1) as i128;
        if n == 0 {
            return cd[0].min(u64::MAX as u128) as u64;
        }
        let t = target as i128;
        let mut prev = ts[0] as i128;
        let mut weighted: i128 = 0;
        let mut sum_d: u128 = 0;
        for i in 1..take {
            let st = match self.solve {
                Solve::Monotone { step: (num, den) } => {
                    let step = (t * num as i128 / den as i128).max(1);
                    let this = (ts[i] as i128).max(prev + step);
                    let st = (this - prev).min(6 * t);
                    prev = this;
                    st
                }
                Solve::PerBlock { lo: (num, den) } => {
                    let lo = t * num as i128 / den as i128;
                    let this = (ts[i] as i128).max(prev + 1);
                    let st = (this - prev).clamp(lo, 6 * t);
                    prev = this;
                    st
                }
                Solve::Signed => (ts[i] as i128 - ts[i - 1] as i128).clamp(-6 * t, 6 * t),
            };
            weighted += i as i128 * st;
            sum_d += cdw[i] - cdw[i - 1];
        }
        let floor = n * n * t * self.floor.0 as i128 / self.floor.1 as i128;
        let l = weighted.max(floor).max(1) as u128;
        let next = sum_d * target as u128 * (n as u128 + 1) / (2 * l);
        next.clamp(1, u64::MAX as u128) as u64
    }
}

impl DifficultyRule for GenLwma {
    fn name(&self) -> String {
        self.label.clone()
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let mut next = self.raw(ts, cd, target) as u128;
        let n = cd.len();
        if n >= 2 {
            let parent = cd[n - 1] - cd[n - 2];
            if let Some((num, den)) = self.rise {
                next = next.min(parent + (parent * num as u128 / den as u128).max(1));
            }
            if let Some((num, den)) = self.fall {
                let lo = (parent * den as u128 / (den + num) as u128).max(1);
                next = next.max(lo);
            }
        }
        next.clamp(1, u64::MAX as u128) as u64
    }
}

/// LWMA-60 with the rise cap applied to the weighted solve-time sum relative to the
/// parent's EFFECTIVE sum (derived from the parent's stored difficulty):
/// `L_eff(parent) = sumD_p * T * (n_p + 1) / (2 * D_parent)`, and
/// `L >= L_eff(parent) * den / (den + num)`.
#[derive(Clone, Debug)]
pub struct SumCap {
    pub num: u64,
    pub den: u64,
}

impl SumCap {
    fn window_sums(ts: &[u64], cd: &[u128], target: u64) -> (u128, u128, u128) {
        let take = ts.len().min(61);
        let ts = &ts[ts.len() - take..];
        let cd = &cd[cd.len() - take..];
        let n = take as u128 - 1;
        let t = target as u128;
        let mut prev = ts[0] as u128;
        let (mut w, mut s) = (0u128, 0u128);
        for i in 1..take {
            let this = (ts[i] as u128).max(prev + 1);
            w += i as u128 * (this - prev).min(6 * t);
            prev = this;
            s += cd[i] - cd[i - 1];
        }
        (n, w.max(n * n * t / 20).max(1), s)
    }
}

impl DifficultyRule for SumCap {
    fn name(&self) -> String {
        format!(
            "LWMA-60 + weighted-sum rise cap {}%",
            self.num as f64 * 100.0 / self.den as f64
        )
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let len = ts.len();
        if len < 3 {
            return Lwma { window: 60 }.next(ts, cd, target);
        }
        let t = target as u128;
        let (n, mut l, s) = Self::window_sums(ts, cd, target);
        let (np, _, sp) = Self::window_sums(&ts[..len - 1], &cd[..len - 1], target);
        let parent = cd[len - 1] - cd[len - 2];
        let l_eff_parent = sp * t * (np + 1) / (2 * parent.max(1));
        l = l
            .max(l_eff_parent * self.den as u128 / (self.den + self.num) as u128)
            .max(1);
        (s * t * (n + 1) / (2 * l)).clamp(1, u64::MAX as u128) as u64
    }
}

/// `d * 2^(num / den)` in exact integer arithmetic (the aserti3-2d radix-2^16
/// exponent, truncated towards minus infinity, and its cubic).
pub fn scale_pow2(d: u128, num: i128, den: i128) -> u128 {
    let exponent = (num * 65_536).div_euclid(den);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xffff) as u128;
    let factor = 65_536
        + ((195_766_423_245_049 * frac
            + 971_821_376 * frac * frac
            + 5_127 * frac * frac * frac
            + (1u128 << 47))
            >> 48);
    let base = (d * factor) >> 16;
    if shifts >= 0 {
        let s = shifts.min(100) as u32;
        if base > (u128::MAX >> s) {
            u128::MAX
        } else {
            base << s
        }
    } else {
        let s = (-shifts).min(127) as u32;
        base >> s
    }
}

/// Hybrid (harness only; zawy #61 is sceptical of LWMA/ASERT hybrids): LWMA-60 kept
/// inside a relative-ASERT band around the parent. With `st` the parent's solve time
/// (`clamp(ts_p - ts_pp, 0, 6T)`), `e = (T - st) / H`: after a fast block the
/// difficulty may rise by at most `2^e` and may not fall; after a slow block it may
/// fall by at most `2^e` and may not rise.
#[derive(Clone, Debug)]
pub struct Hybrid {
    pub half_life: u64,
}

impl DifficultyRule for Hybrid {
    fn name(&self) -> String {
        format!(
            "Hybrid LWMA-60 in relative-ASERT band (H = {} h)",
            self.half_life as f64 / 3600.0
        )
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let lwma = Lwma { window: 60 }.next(ts, cd, target) as u128;
        let len = ts.len();
        if len < 2 {
            return lwma as u64;
        }
        let parent = cd[len - 1] - cd[len - 2];
        let t = target as i128;
        let st = (ts[len - 1] as i128 - ts[len - 2] as i128).clamp(0, 6 * t);
        let bound = scale_pow2(parent, t - st, self.half_life as i128);
        let (lo, hi) = if st <= t {
            (parent, bound)
        } else {
            (bound, parent)
        };
        lwma.clamp(lo.max(1), hi.max(1)).clamp(1, u64::MAX as u128) as u64
    }
}

fn floor_rule(window: usize, c_num: u64, c_den: u64) -> GenLwma {
    // L >= n^2 T / (2c), c = c_num / c_den  =>  floor = (c_den, 2 c_num).
    let c = c_num as f64 / c_den as f64;
    GenLwma {
        label: format!("(c) LWMA-{window}, floor n^2 T/(2c), c = {c}"),
        window,
        solve: Solve::Monotone { step: (0, 1) },
        floor: (c_den, 2 * c_num),
        rise: None,
        fall: None,
    }
}

/// (a') LWMA-60 whose counted clock advances at least `max(1, T * num / den)` per block.
pub fn virtual_clock(num: u64, den: u64) -> GenLwma {
    GenLwma {
        label: format!(
            "(a') LWMA-60, virtual clock step {}T/{} ({} s at T = 120)",
            if num == 1 {
                String::new()
            } else {
                num.to_string()
            },
            den,
            120 * num / den
        ),
        solve: Solve::Monotone { step: (num, den) },
        ..GenLwma::current()
    }
}

/// The recommended rule of the selection study: the consensus LWMA-1 with the window
/// N = 75 (was 60) and the monotone step `prev + 1` replaced by `prev + max(1, T/2)`.
pub fn recommended() -> GenLwma {
    let mut r = GenLwma {
        window: 75,
        ..virtual_clock(1, 2)
    };
    r.label = "(a') LWMA-75, virtual clock step T/2 [RECOMMENDED]".into();
    r
}

/// Every candidate of the selection study, references first.
pub fn selection_candidates() -> Vec<Box<dyn DifficultyRule>> {
    let cur = GenLwma::current();
    let mut v: Vec<Box<dyn DifficultyRule>> = vec![
        Box::new(Lwma { window: 60 }),
        Box::new(RiseCap {
            base: Lwma { window: 60 },
            num: 2,
            den: 100,
        }),
        Box::new(Asert { half_life: 7_200 }),
    ];
    // (a) the literal symmetric solve-time clamp [T/k, 6T].
    for k in [2u64, 3, 4, 6] {
        v.push(Box::new(GenLwma {
            label: format!("(a) LWMA-60, st in [T/{k}, 6T]"),
            solve: Solve::PerBlock { lo: (1, k) },
            ..cur.clone()
        }));
    }
    // (a') the same lower bound as a virtual-time (monotone) clamp.
    for (num, den) in [(1u64, 3u64), (2, 5)] {
        v.push(Box::new(virtual_clock(num, den)));
    }
    v.push(Box::new(virtual_clock(1, 2)));
    for (num, den) in [(3u64, 5u64), (2, 3)] {
        v.push(Box::new(virtual_clock(num, den)));
    }
    v.push(Box::new(recommended()));
    v.push(Box::new(GenLwma {
        label: "(a') LWMA-90, virtual clock step T/2".into(),
        window: 90,
        ..virtual_clock(1, 2)
    }));
    // (b) matched rise and fall caps.
    for (num, den, pct) in [(2u64, 100u64, "2"), (5, 200, "2.5"), (3, 100, "3")] {
        v.push(Box::new(GenLwma {
            label: format!("(b) LWMA-60, rise and fall <= {pct}%"),
            rise: Some((num, den)),
            fall: Some((num, den)),
            ..cur.clone()
        }));
    }
    // (c) the rise bound on the weighted sum: an absolute floor (the consensus floor
    // tightened) and a parent-relative cap.
    v.push(Box::new(floor_rule(60, 3, 2)));
    v.push(Box::new(floor_rule(60, 7, 4)));
    v.push(Box::new(floor_rule(60, 2, 1)));
    v.push(Box::new(floor_rule(60, 5, 2)));
    v.push(Box::new(floor_rule(75, 2, 1)));
    v.push(Box::new(floor_rule(90, 2, 1)));
    v.push(Box::new(SumCap { num: 2, den: 100 }));
    // (d) ASERT with shorter half-lives, and the hybrid.
    v.push(Box::new(Asert { half_life: 3_600 }));
    v.push(Box::new(Asert { half_life: 2_700 }));
    v.push(Box::new(Hybrid { half_life: 3_600 }));
    // (e) signed solve times (zawy #13) with the c = 2 floor; and the c = 2 floor
    // plus a loose 5% output rise cap (for the genesis-era ramp, 03-F2).
    v.push(Box::new(GenLwma {
        label: "(e) LWMA-60, signed st in [-6T, 6T], floor c = 2".into(),
        solve: Solve::Signed,
        floor: (1, 4),
        ..cur.clone()
    }));
    v.push(Box::new(GenLwma {
        label: "(e) LWMA-60, floor c = 2, + rise <= 5%".into(),
        floor: (1, 4),
        rise: Some((5, 100)),
        ..cur.clone()
    }));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;
    use crate::rules::legacy_next;

    /// The generalised LWMA with default parameters IS the pre-v3 consensus rule
    /// (the frozen copy [`legacy_next`]), on random histories including
    /// out-of-order stamps and short windows.
    #[test]
    fn generalised_default_equals_the_pre_v3_rule() {
        let g = GenLwma::current();
        let mut rng = Rng::new(5);
        for len in [1usize, 2, 3, 10, 61, 62, 200] {
            for _ in 0..50 {
                let mut ts = vec![1_000_000u64];
                let mut cd = vec![1 + rng.below(1_000_000) as u128];
                for _ in 1..len {
                    let step = rng.below(1_500) as i64 - 300;
                    ts.push((*ts.last().unwrap() as i64 + step).max(1) as u64);
                    cd.push(cd.last().unwrap() + 1 + rng.below(2_000_000) as u128);
                }
                let from = len.saturating_sub(61);
                let want = legacy_next(&ts[from..], &cd[from..], 120, 60, cd[0] as u64);
                assert_eq!(g.next(&ts, &cd, 120), want);
            }
        }
    }

    #[test]
    fn floor_bounds_rise_to_c_times_average() {
        let r = floor_rule(60, 2, 1);
        // All stamps 1 s apart: L sits on the floor n^2 T / 4.
        let ts: Vec<u64> = (0..61).map(|i| 1_000 + i).collect();
        let cd: Vec<u128> = (0..61).map(|i| (i + 1) * 1_000_000).collect();
        // sumD = 60e6, n = 60: next = 60e6 * 120 * 61 / (2 * 3600 * 120 / 4 ... )
        let n = 60u128;
        let want = 60_000_000u128 * 120 * (n + 1) / (2 * (n * n * 120 / 4));
        assert_eq!(r.next(&ts, &cd, 120) as u128, want);
        assert_eq!(want, 2_033_333); // 2 * avg * 61/60
    }

    #[test]
    fn pow2_matches_asert() {
        assert_eq!(scale_pow2(1_000_000, 1, 1), 2_000_000);
        assert_eq!(scale_pow2(1_000_000, -1, 1), 500_000);
        let x = scale_pow2(1_000_000, 1, 4) as f64;
        assert!((x / 1e6 / 2f64.powf(0.25) - 1.0).abs() < 2e-4);
    }

    #[test]
    fn caps_hold_at_difficulty_one() {
        let r = GenLwma {
            rise: Some((2, 100)),
            fall: Some((2, 100)),
            ..GenLwma::current()
        };
        assert_eq!(r.next(&[0, 1, 2], &[1, 2, 3], 10), 2);
        assert_eq!(r.next(&[0, 60, 120], &[2, 4, 6], 10), 1);
    }
}
