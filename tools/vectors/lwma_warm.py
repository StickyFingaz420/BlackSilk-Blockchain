#!/usr/bin/env python3
"""Independent golden vectors for the v3 difficulty rule (test tooling, non-core).

Written from the rule text in docs/consensus.md section 4 (and the coordinator's
"DAA FINAL" decision), not from the Rust code. Python integers are unbounded, so
nothing here can wrap or saturate by accident; the clamp to [1, 2^64 - 1] is the
only bound, applied last as the spec says.

The rule, restated:
  inputs: ancestors oldest first ending with the parent: stamps t[], cumulative
          difficulties C[]; target T; window N; initial difficulty D0.
  window: the last N + 1 ancestors (fewer near genesis); n = size - 1.
          n == 0 -> D0.
  clock:  step = max(1, floor(T / 2)). The clock starts at the stamp 11 blocks
          before the window's oldest block (or the oldest ancestor given, if
          there are fewer), and every later block up to and including the
          window's oldest moves it to max(stamp, clock + step). That is the
          window's anchor.
  window: for the k-th window block after the anchor (k = 1..n):
          c = max(stamp, clock + step); solve = min(c - clock, 6T); clock = c;
          L += k * solve; S += C[k] - C[k-1].
  result: L = max(L, floor(n*n*T / 20), 1); next = floor(S*T*(n+1) / (2L));
          clamp to [1, 2^64 - 1].

Output: consensus/tests/data/lwma_vectors.txt (read by consensus/tests/lwma_warm.rs)
and, on stdout, the values pinned in consensus/tests/golden.rs.

Usage: python tools/vectors/lwma_warm.py [--check]
  --check: regenerate in memory and compare with the committed file.
Standard library only.
"""

import os
import sys

U64 = (1 << 64) - 1
WARM = 11


def lwma_v3(stamps, cumulative, target, window, d0):
    assert len(stamps) == len(cumulative) and stamps
    size = min(len(stamps), window + 1)
    n = size - 1
    if n == 0:
        return d0
    step = max(1, target // 2)
    oldest = len(stamps) - size  # index of the window's oldest block
    first = max(0, oldest - WARM)

    # The counted clock over the warm-up blocks and the window's oldest block.
    clock = stamps[first]
    for j in range(first + 1, oldest + 1):
        clock = max(stamps[j], clock + step)

    weighted_sum = 0
    difficulty_sum = 0
    for k in range(1, n + 1):
        idx = oldest + k
        counted = max(stamps[idx], clock + step)
        solve = min(counted - clock, 6 * target)
        clock = counted
        weighted_sum += k * solve
        difficulty_sum += cumulative[idx] - cumulative[idx - 1]

    weighted_sum = max(weighted_sum, (n * n * target) // 20, 1)
    result = (difficulty_sum * target * (n + 1)) // (2 * weighted_sum)
    return min(max(result, 1), U64)


# ----------------------------------------------------------------- PRNG
class SplitMix64:
    """Deterministic 64-bit generator (splitmix64), independent of Python's random."""

    def __init__(self, seed):
        self.state = seed & U64

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & U64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & U64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & U64
        return z ^ (z >> 31)

    def below(self, bound):
        return self.next() % bound


# ------------------------------------------------------------- histories
def from_blocks(t0, blocks):
    """blocks: (solve time, difficulty) pairs; the first entry is the anchor block
    at t0 with the first block's difficulty (only differences of C matter)."""
    ts = [t0]
    ds = [blocks[0][1] if blocks else 1]
    for st, d in blocks:
        ts.append(ts[-1] + st)
        ds.append(d)
    return ts, ds


def cumulative_of(ds):
    out = []
    acc = 0
    for d in ds:
        acc += d
        out.append(acc)
    return out


VECTORS = []


def add(name, target, window, d0, ts, ds, expect=None):
    assert all(0 <= t <= U64 for t in ts), name
    assert all(1 <= d <= U64 for d in ds), name
    assert len(ts) == len(ds), name
    got = lwma_v3(ts, cumulative_of(ds), target, window, d0)
    if expect is not None:
        assert got == expect, (name, got, expect)
    VECTORS.append((name, target, window, d0, ts, ds, got))
    return got


def build():
    T, N = 120, 75
    # ---- steady state (exact: every solve time T).
    for d in [1, 2, 100, 10_000, 1_000_000, 123_456_789, U64 // 100]:
        ts, ds = from_blocks(1_000_000, [(T, d)] * 120)
        add(f"steady_d{d}", T, N, 777, ts, ds, expect=d)
    for t in [10, 2, 3, 600]:
        ts, ds = from_blocks(1_700_000_000, [(t, 5_000)] * 90)
        add(f"steady_T{t}", t, N, 1, ts, ds, expect=5_000)

    # ---- hash rate x2, x10, /2, /10 (all solve times at the new rate).
    for label, st in [("x2", T // 2), ("half", 2 * T), ("x10", T // 10), ("tenth", 10 * T)]:
        ts, ds = from_blocks(1_000_000, [(st, 10_000)] * 100)
        add(f"rate_{label}", T, N, 777, ts, ds)
    # 2x = one step per block: exactly 20 000; 1/2: exactly 5 000.
    assert VECTORS[-4][6] == 20_000 and VECTORS[-3][6] == 5_000
    # ---- a step change inside the window (steady, then the new rate for k blocks).
    for label, st in [("up2", T // 2), ("up10", T // 10), ("down2", 2 * T), ("down10", 10 * T)]:
        for k in [1, 10, 38, 74, 75]:
            blocks = [(T, 10_000)] * 100 + [(st, 10_000)] * k
            ts, ds = from_blocks(1_000_000, blocks)
            add(f"jump_{label}_k{k}", T, N, 777, ts, ds)

    # ---- genesis-near short windows: every ancestor count around the boundaries.
    rng = SplitMix64(0x6E6E)
    for count in [1, 2, 3, 4, 11, 12, 13, 20, 75, 76, 77, 78, 86, 87, 88, 89]:
        ts = [1_790_380_800]
        ds = [100]
        for _ in range(count - 1):
            ts.append(ts[-1] + rng.below(400))
            ds.append(1 + rng.below(300))
        add(f"short_{count}", T, N, 100, ts, ds)

    # ---- the 1-second-block run (regtest: T = 10, D0 = 1) and at T = 120.
    for t, count in [(10, 2), (10, 3), (10, 12), (10, 40), (10, 100), (120, 5), (120, 100)]:
        ts = [1_700_000_000 + i for i in range(count)]
        ds = [1] * count
        add(f"one_second_T{t}_{count}", t, N, 1, ts, ds)
    # A chain grown block by block with 1-second blocks from D = 1 (regtest).
    ts, cd = [1_700_000_000], [1]
    ds = [1]
    for _ in range(150):
        d = lwma_v3(ts, cumulative_of(ds), 10, N, 1)
        ts.append(ts[-1] + 1)
        ds.append(d)
    add("one_second_grown_T10", 10, N, 1, ts, ds)

    # ---- the genesis gap: block 1 two hours after the genesis time.
    for gap in [7_200, 720, 721, 100_000]:
        ts, ds = [1_790_380_800, 1_790_380_800 + gap], [100, 100]
        add(f"genesis_gap_{gap}", T, N, 100, ts, ds)
    # ... and the recovery with on-target blocks after it (block 2 onwards).
    ts, ds = [1_790_380_800, 1_790_388_000], [100, 100]
    for _ in range(40):
        d = lwma_v3(ts, cumulative_of(ds), T, N, 100)
        ts.append(ts[-1] + T)
        ds.append(d)
    add("genesis_gap_recovery_40", T, N, 100, ts, ds)

    # ---- warm-up edge cases.
    base_ts, base_ds = from_blocks(1_000_000, [(T, 1_000_000)] * 86)  # 87 stamps
    assert len(base_ts) == 87
    # The red-team golden case: the window's oldest stamp (index 11) 1 300 s low.
    ts = list(base_ts)
    ts[11] -= 1_300
    add("redteam_lag_1300_warm", T, N, 1, ts, base_ds, expect=999_824)
    add("redteam_lag_1300_nowarm", T, N, 1, ts[11:], base_ds[11:], expect=998_248)
    add("redteam_steady", T, N, 1, base_ts, base_ds, expect=1_000_000)
    # A low stamp at each warm-up position, and just outside it (index 0 of 88).
    for pos in [0, 1, 5, 10, 11, 12, 20]:
        for low in [60, 1_300, 5_000]:
            ts = list(base_ts)
            ts[pos] -= low
            add(f"warm_low_at{pos}_by{low}", T, N, 1, ts, base_ds)
    ts = [999_000] + list(base_ts)
    ds = [1] + list(base_ds)
    add("warm_ignores_the_88th", T, N, 1, ts, ds, expect=1_000_000)
    # Forward stamps in the warm-up push the anchor ahead of the window.
    for pos, high in [(0, 360), (5, 720), (10, 3_000), (11, 3_000)]:
        ts = list(base_ts)
        ts[pos] += high
        add(f"warm_high_at{pos}_by{high}", T, N, 1, ts, base_ds)
    # A fast run inside the warm-up (7 s blocks) before a steady window.
    blocks = [(7, 999_999)] * 39 + [(T, 10_000)] * 75
    ts, ds = from_blocks(1_000_000, blocks)
    add("fast_run_just_before_window", T, N, 777, ts, ds)
    blocks = [(7, 999_999)] * 39 + [(T, 10_000)] * 86
    ts, ds = from_blocks(1_000_000, blocks)
    add("fast_run_before_warmup", T, N, 777, ts, ds, expect=10_000)
    # Partial warm-up (77..86 ancestors), with a low oldest window stamp.
    for count in [77, 78, 81, 86]:
        ts, ds = list(base_ts[-count:]), list(base_ds[-count:])
        ts[count - 76] -= 1_300
        add(f"partial_warm_{count}", T, N, 1, ts, ds)

    # ---- the 6T cap and the step at the boundaries (n = 2).
    for x in [0, 59, 60, 61, 719, 720, 721, 10_000]:
        add(f"cap_n2_x{x}", T, N, 777, [0, 120, 120 + x], [1000, 1000, 1000])

    # ---- u128 extremes.
    big = U64
    ts = [0] * 87
    ds = [big] * 87
    add("u64max_difficulty_equal_stamps", T, N, 1, ts, ds, expect=U64)
    ts, ds = from_blocks(1_000_000, [(T, big)] * 86)
    add("u64max_difficulty_on_target", T, N, 1, ts, ds, expect=U64)
    ts, ds = from_blocks(1_000_000, [(6 * T, big)] * 86)
    add("u64max_difficulty_slow", T, N, 1, ts, ds)
    ts = [U64 - 10 * (86 - i) for i in range(87)]
    ds = [1_000_000] * 87
    add("stamps_near_u64max", T, N, 1, ts, ds)
    ts = [U64 - 3] * 87
    add("stamps_at_u64max_equal", T, N, 1, ts, ds)
    t_big = (1 << 51) - 1
    ts, ds = from_blocks(0, [(t_big, big)] * 86)
    add("target_2pow51_minus1_steady", t_big, N, 1, ts, ds, expect=U64)
    ts = [0] * 87
    ds = [big] * 87
    add("target_2pow51_minus1_compressed", t_big, N, 1, ts, ds)
    ts, ds = from_blocks(0, [(1, 3)] * 86)
    add("target_1", 1, N, 1, ts, ds)
    add("target_2", 2, N, 1, ts, ds)
    add("target_3", 3, N, 1, ts, ds)
    ts, ds = from_blocks(0, [(0, 1)] * 86)
    add("difficulty_one_compressed", T, N, 1, ts, ds)
    ts, ds = from_blocks(0, [(6 * T, 1)] * 86)
    add("difficulty_one_slow", T, N, 1, ts, ds, expect=1)

    # ---- random adversarial histories: non-monotone stamps, MTP/FTL-edge jumps.
    rng = SplitMix64(0xADE5)
    for k in range(40):
        count = [2, 12, 50, 76, 80, 87, 87, 87, 100, 120][k % 10]
        t = [120, 10, 2, 7][k % 4]
        ts = [1_800_000_000]
        ds = [1 + rng.below(1 << (8 + 4 * (k % 13)))]
        for _ in range(count - 1):
            r = rng.below(10)
            if r == 0:
                step = -(rng.below(2_000))  # back towards the MTP
            elif r == 1:
                step = 360 + rng.below(360)  # an FTL-edge stamp
            else:
                step = rng.below(4 * t + 1)
            ts.append(max(0, ts[-1] + step))
            ds.append(1 + rng.below(1 << (8 + 4 * (k % 13))))
        add(f"random_{k}_T{t}_{count}", t, N, 1 + rng.below(1_000), ts, ds)
    return VECTORS


def render(vectors):
    lines = [
        "# Golden vectors for the v3 difficulty rule (docs/consensus.md section 4).",
        "# Generated by tools/vectors/lwma_warm.py (independent of the Rust code). Do not edit.",
        "# Fields: name T N D0 t0 dt diffs expected",
        "#   t0: the oldest stamp; dt: signed stamp differences (comma-separated, '-' if none);",
        "#   diffs: per-block difficulties (C[0] = diffs[0], C[i] = C[i-1] + diffs[i]).",
    ]
    for name, t, n, d0, ts, ds, want in vectors:
        dt = ",".join(str(ts[i] - ts[i - 1]) for i in range(1, len(ts))) or "-"
        lines.append(
            f"{name} {t} {n} {d0} {ts[0]} {dt} {','.join(map(str, ds))} {want}"
        )
    return "\n".join(lines) + "\n"


# ------------------------------------------------ values pinned in golden.rs
def golden_rs_values():
    T, N, D0 = 120, 75, 777
    out = []

    def lw(blocks):
        ts, ds = from_blocks(1_000_000, blocks)
        return lwma_v3(ts, cumulative_of(ds), T, N, D0)

    mixed10 = [(60 + (i * 37) % 200, 1000 + (i * 113) % 500) for i in range(1, 11)]
    mixed75 = [(60 + (i * 37) % 200, 1000 + (i * 113) % 500) for i in range(1, 76)]
    out.append(("lwma_window_fill_phase mixed n=10", lw(mixed10)))
    out.append(("lwma_mixed_window n=75", lw(mixed75)))
    ts = [10_000 - 3 * i for i in range(61)]
    cd = [i * 500 for i in range(61)]
    out.append(("lwma_out_of_order 3 s earlier (61)", lwma_v3(ts, cd, T, N, D0)))
    ts = [10_000 - 3 * i for i in range(87)]
    cd = [i * 500 for i in range(87)]
    out.append(("lwma_out_of_order 3 s earlier (87)", lwma_v3(ts, cd, T, N, D0)))
    wild = [(7, 999_999)] * 39 + [(T, 10_000)] * 75
    out.append(("lwma_only_the_last_window: fast run just before", lw(wild)))

    # Header chain on regtest (T = 10, N = 75), D0 = 1000, genesis 1 700 000 000.
    pattern = [10, 3, 25, -2, 1, 12, 10, 7, 70, -5, 4, 9]
    ts, ds = [1_700_000_000], [1000]
    diffs = []
    mtps = {}
    for h in range(1, 151):
        d = lwma_v3(ts, cumulative_of(ds), 10, N, 1000)
        diffs.append(d)
        last = sorted(ts[-11:])
        mtps[h] = last[(len(last) - 1) // 2]
        ts.append(ts[-1] + pattern[h % 12])
        ds.append(d)
    return out, diffs, sum(ds), mtps


def self_checks():
    # Hand derivations (docs/consensus.md section 4 examples).
    # n = 1, solve T: 100*120*2 / (2*120) = 100.
    assert lwma_v3([1000, 1120], [100, 200], 120, 75, 777) == 100
    # n = 1, stamps T/4 or equal apart: counted one step (60): 100*240/120 = 200.
    assert lwma_v3([1000, 1030], [100, 200], 120, 75, 777) == 200
    assert lwma_v3([1000, 1000], [100, 200], 120, 75, 777) == 200
    # [0, 50, 40, 400], d = 100, 200, 300: clock 60, 120, 400; solves 60, 60, 280;
    # L = 60 + 120 + 840 = 1020; 600*120*4 / 2040 = 141.
    assert lwma_v3([0, 50, 40, 400], [5, 105, 305, 605], 120, 75, 777) == 141
    # The red-team case: 75e6*120*76 / (2*342600) and / (2*342060).
    assert 75_000_000 * 120 * 76 // (2 * 342_600) == 998_248
    assert 75_000_000 * 120 * 76 // (2 * 342_060) == 999_824


def main():
    self_checks()
    vectors = build()
    text = render(vectors)
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "..", "consensus", "tests", "data", "lwma_vectors.txt")
    path = os.path.normpath(path)
    if "--check" in sys.argv:
        with open(path, encoding="utf-8") as f:
            if f.read() != text:
                print(f"MISMATCH: {path} differs from the generator output")
                return 1
        print(f"ok: {len(vectors)} vectors match {path}")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {len(vectors)} vectors to {path}")
    values, diffs, total, mtps = golden_rs_values()
    for name, v in values:
        print(f"golden.rs {name}: {v}")
    print("golden.rs CHAIN_DIFFICULTIES:", diffs)
    print("golden.rs total work:", total)
    print("golden.rs MTP before 1,2,3,6,11,12,21,150:",
          [mtps[h] for h in [1, 2, 3, 6, 11, 12, 21, 150]])
    return 0


if __name__ == "__main__":
    sys.exit(main())
