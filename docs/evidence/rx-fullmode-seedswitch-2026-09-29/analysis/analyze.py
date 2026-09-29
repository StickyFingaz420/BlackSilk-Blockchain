"""W4-RX: analysis of the full-mode seed-switch labnet run.

Usage: python analyze.py <run dir> <monitor csv> [switch height]
Prints a JSON document on stdout. Reads only the run's own logs.
"""
import csv
import json
import re
import sys
from datetime import datetime, timezone

run, monitor = sys.argv[1], sys.argv[2]
SWITCH = int(sys.argv[3]) if len(sys.argv) > 3 else 2113
KEY_HEIGHT = 2048
ANNOUNCE = KEY_HEIGHT + 1  # first template that can carry next_seed_id

TS = re.compile(r"^\[(\S+Z) (\w+)\s+(\S+)\] (.*)$")


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = TS.match(line.rstrip("\n"))
            if m:
                yield ts(m.group(1)), m.group(2), m.group(3), m.group(4)


out = {"switch_height": SWITCH}

# ---- miner0 (full mode) ----
m0 = f"{run}/miner0.log"
hashrate = []  # (t, H/s, mode)
rounds = []  # (t, hashes, secs, template height)
found = {}  # height -> (t, adopted)
submit_secs = {}  # height -> submission round trip
events = []
templates = []  # (t, height, difficulty)
cur_template = None
warn = []
for t, lvl, target, msg in lines(m0):
    if lvl in ("WARN", "ERROR"):
        warn.append((t, msg))
    if m := re.match(r"hash rate ([\d.]+) H/s \((\w+) mode\)", msg):
        hashrate.append((t, float(m.group(1)), m.group(2)))
    elif m := re.match(r"template (\d+) on \S+ \(difficulty (\d+)\)", msg):
        cur_template = int(m.group(1))
        templates.append((t, cur_template, int(m.group(2))))
    elif m := re.match(r"(\d+) hashes in ([\d.]+)(µs|ms|s) \(([\d.]+) H/s\)", msg):
        secs = float(m.group(2)) / {"ms": 1e3, "µs": 1e6}.get(m.group(3), 1)
        rounds.append((t, int(m.group(1)), secs, cur_template))
    elif m := re.match(r"found block (\d+)", msg):
        found[int(m.group(1))] = (t, "not on the node's best chain" not in msg)
        # The search's debug line comes just before the submission, this
        # line just after the node answered: the submission round trip,
        # which includes the node's validation (its PoW check included).
        if rounds:
            submit_secs[int(m.group(1))] = round(t - rounds[-1][0], 3)
    elif "RandomX" in msg or "prebuild" in msg or "dataset" in msg:
        events.append((t, msg))
out["miner0_events"] = [
    {"utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "msg": msg} for t, msg in events
]
out["miner0_warnings"] = [
    {"utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "msg": msg[:300]} for t, msg in warn
]

# Template heights over time -> when the miner first worked on each height.
first_template = {}
for t, h, d in templates:
    first_template.setdefault(h, (t, d))


def window_rate(pred):
    hs = sum(r[1] for r in rounds if pred(r))
    secs = sum(r[2] for r in rounds if pred(r))
    return {"hashes": hs, "search_secs": round(secs, 1), "hps": round(hs / secs, 2) if secs else None}


t_switch_tmpl = first_template.get(SWITCH, (None,))[0]
t_announce = first_template.get(ANNOUNCE, (None,))[0]
out["miner0_first_template_utc"] = {
    str(h): datetime.fromtimestamp(first_template[h][0], timezone.utc).isoformat()
    for h in (ANNOUNCE, SWITCH - 1, SWITCH, SWITCH + 1)
    if h in first_template
}
# Hash rate from the per-round debug lines, by template height band.
bands = {
    "heights 1500-2048 (old key, before the prebuild)": lambda r: r[3] and 1500 <= r[3] <= 2048,
    "heights 2049-2112 (old key, prebuild running or done)": lambda r: r[3] and 2049 <= r[3] <= 2112,
    "heights 2113-2176 (new key, first 64)": lambda r: r[3] and 2113 <= r[3] <= 2176,
    "heights 2177-2400 (new key)": lambda r: r[3] and 2177 <= r[3] <= 2400,
    f"heights 2401+ (new key)": lambda r: r[3] and r[3] >= 2401,
}
out["miner0_hashrate_by_band"] = {k: window_rate(p) for k, p in bands.items()}
out["miner0_hashrate_lines_around_switch"] = [
    {"utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "hps": v, "mode": mode}
    for t, v, mode in hashrate
    if t_switch_tmpl and abs(t - t_switch_tmpl) <= 20 * 60
]
out["miner0_modes_seen"] = sorted({mode for _, _, mode in hashrate})
out["miner0_light_mode_lines"] = sum(1 for _, _, mode in hashrate if mode == "light")

# Found blocks around the switch.
out["miner0_found_around_switch"] = [
    {"height": h, "utc": datetime.fromtimestamp(found[h][0], timezone.utc).isoformat(), "adopted_at_submission": found[h][1]}
    for h in sorted(found)
    if SWITCH - 5 <= h <= SWITCH + 10
]
out["miner0_submit_round_trip_secs_around_switch"] = {
    str(h): submit_secs[h] for h in sorted(submit_secs) if SWITCH - 10 <= h <= SWITCH + 10
}


def dist(vals):
    vals = sorted(vals)
    if not vals:
        return None
    return {"n": len(vals), "median": vals[len(vals) // 2], "p95": vals[int(len(vals) * 0.95)], "max": vals[-1]}


out["miner0_submit_round_trip_secs"] = {
    "all": dist(list(submit_secs.values())),
    "2113-2123": dist([v for h, v in submit_secs.items() if SWITCH <= h <= SWITCH + 10]),
}
first_new = min((h for h in found if h >= SWITCH), default=None)
out["miner0_first_found_at_or_after_switch"] = first_new
out["miner0_found_total"] = len(found)
out["miner0_found_at_or_after_switch"] = sum(1 for h in found if h >= SWITCH)

# ---- nodes: acceptance times per height ----
accepted = {}  # node -> height -> first t
reorgs = {}
for n in ["node0", "node1", "node2", "node3", "node-late"]:
    try:
        acc = {}
        rs = []
        for t, lvl, target, msg in lines(f"{run}/{n}.log"):
            # node0 and node2 log blocks submitted by their miner at info;
            # every node logs relayed headers (their PoW checked) at debug.
            if m := re.match(r"block (\w+) at height (\d+) accepted", msg):
                acc.setdefault(int(m.group(2)), t)
            elif m := re.match(r"peer \d+: (\d+) headers up to height (\d+) accepted \(new: true\)", msg):
                top, k = int(m.group(2)), int(m.group(1))
                for h in range(top - k + 1, top + 1):
                    acc.setdefault(h, t)
            elif m := re.match(r"reorganization: disconnecting (\d+) block\(s\) above height (\d+)", msg):
                rs.append((t, int(m.group(1)), int(m.group(2))))
        accepted[n] = acc
        reorgs[n] = rs
    except FileNotFoundError:
        pass

node0 = accepted.get("node0", {})
win = range(SWITCH - 10, SWITCH + 11)
out["node0_intervals_around_switch"] = [
    {"height": h, "accepted_utc": datetime.fromtimestamp(node0[h], timezone.utc).isoformat(),
     "secs_since_previous": round(node0[h] - node0[h - 1], 3) if h - 1 in node0 else None}
    for h in win if h in node0
]
# Relay: when each node first accepted the heights around the switch,
# relative to node0 (the full miner's node).
out["relay_delay_secs_around_switch"] = {
    n: {str(h): round(acc[h] - node0[h], 3) for h in win if h in acc and h in node0}
    for n, acc in accepted.items() if n not in ("node0", "node-late")
}


def interval_stats(lo, hi):
    ts_ = [node0[h] - node0[h - 1] for h in range(lo, hi + 1) if h in node0 and h - 1 in node0]
    if not ts_:
        return None
    ts_.sort()
    return {"blocks": len(ts_), "mean": round(sum(ts_) / len(ts_), 2), "median": round(ts_[len(ts_) // 2], 2), "max": round(ts_[-1], 2)}


out["node0_block_interval_secs"] = {
    "2049-2112": interval_stats(2049, 2112),
    "2113-2176": interval_stats(2113, 2176),
    "1985-2048": interval_stats(1985, 2048),
    "2177-2313": interval_stats(2177, 2313),
}
out["reorgs_touching_switch"] = {
    n: [{"utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "depth": d, "above": a} for t, d, a in rs if a - 5 <= SWITCH <= a + d + 5]
    for n, rs in reorgs.items()
}
out["reorg_count_per_node"] = {n: len(rs) for n, rs in reorgs.items()}
out["max_height_accepted"] = {n: max(acc) if acc else 0 for n, acc in accepted.items()}

# ---- monitor: full miner memory (prebuild window) ----
mem = []
free = []
with open(monitor, newline="") as f:
    for row in csv.reader(f):
        if len(row) < 8 or row[0] == "unix":
            continue
        try:
            t = int(row[0])
        except ValueError:
            continue
        free.append((t, int(row[1])))
        if row[2] == "miner-full":
            mem.append((t, int(row[4]), int(row[5]), float(row[6])))
out["min_free_mb"] = min(v for _, v in free) if free else None
out["min_free_mb_utc"] = datetime.fromtimestamp(min(free, key=lambda x: x[1])[0], timezone.utc).isoformat() if free else None
out["miner_full_peak_private_mb"] = max(p for _, _, p, _ in mem) if mem else None
out["miner_full_peak_ws_mb"] = max(w for _, w, _, _ in mem) if mem else None
# Prebuild, from the outside (the miner logs no line for a background
# build): the next key's cache (256 MiB) and dataset (2 GiB) are allocated
# at its start, so private bytes rise by about 2.3 GiB (the dataset
# allocation touches its pages at once, so the working set rises with it);
# the cache is freed when the dataset is built, so private bytes fall by
# about 256 MiB at its end. The CPU rate (cores busy) confirms: about 2
# (the mining threads) outside the build, 2 + build threads during it.
if mem:
    base = sorted(p for _, _, p, _ in mem)[len(mem) // 2]
    rise = next(((t, p) for t, _, p, _ in mem if p > base + 1500), None)
    out["private_mb_median"] = base
    if rise:
        t0, p0 = rise
        end = next(((t, p) for t, _, p, _ in mem if t > t0 and p0 - 400 < p < p0 - 150), None)
        out["prebuild_allocation_utc"] = datetime.fromtimestamp(t0, timezone.utc).isoformat()
        out["prebuild_private_mb"] = p0
        if end:
            t1 = end[0]
            out["prebuild_cache_freed_utc"] = datetime.fromtimestamp(t1, timezone.utc).isoformat()
            out["prebuild_private_mb_after"] = end[1]
            # Samples are about 10 s apart: the allocation happened after the
            # last sample before t0, the end after the last sample before t1.
            prev0 = max((t for t, *_ in mem if t < t0), default=t0)
            prev1 = max((t for t, *_ in mem if t < t1), default=t1)
            out["prebuild_duration_secs_bounds"] = [prev1 - t0, t1 - prev0]

            def by_time(lo, hi):
                return window_rate(lambda r: lo <= r[0] <= hi)

            out["miner0_hashrate_by_time"] = {
                "10 min before the prebuild": by_time(t0 - 600, t0),
                "during the prebuild": by_time(t0, prev1),
                "prebuild end to the switch": by_time(t1, t_switch_tmpl or t1),
                "first 10 min after the switch": by_time(t_switch_tmpl or t1, (t_switch_tmpl or t1) + 600),
            }

            def rate(lo, hi):
                s = [(t, c) for t, _, _, c in mem if lo <= t <= hi]
                return round((s[-1][1] - s[0][1]) / (s[-1][0] - s[0][0]), 2) if len(s) > 1 and s[-1][0] > s[0][0] else None

            out["miner_cores_busy"] = {
                "5 min before the allocation": rate(t0 - 310, t0 - 10),
                "during the prebuild": rate(t0, t1 - 11),
                "5 min after the prebuild": rate(t1, t1 + 300),
            }
            if SWITCH in node0:
                out["prebuild_end_before_block_2113_accepted_secs"] = round(node0[SWITCH] - t1, 1)
            if t_switch_tmpl:
                out["prebuild_end_before_first_2113_template_secs"] = round(t_switch_tmpl - t1, 1)
        rel = next(((t, p) for t, _, p, _ in mem if t > t0 and p < base + 500), None)
        out["previous_dataset_released_utc"] = datetime.fromtimestamp(rel[0], timezone.utc).isoformat() if rel else None
        if t_announce:
            out["announce_template_to_allocation_secs"] = round(t0 - t_announce, 1)
    out["miner_full_memory_samples_around_prebuild"] = [
        {"utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "ws_mb": w, "private_mb": p, "cpu_s": c}
        for t, w, p, c in mem
        if t_announce and t_announce - 60 <= t <= (t_switch_tmpl or t_announce) + 120
    ][::3]

print(json.dumps(out, indent=1))
