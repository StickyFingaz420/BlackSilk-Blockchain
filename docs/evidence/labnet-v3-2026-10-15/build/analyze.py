"""Acceptance analysis of one labnet run (reads the run's own files; writes
<run>/acceptance.json and prints a summary). Usage: analyze.py RUN SHA256SUMS
"""
import json, os, re, sys, glob, statistics
from datetime import datetime, timezone

run, sums = sys.argv[1], sys.argv[2]
S = json.load(open(os.path.join(run, "summary.json")))
R = json.load(open(os.path.join(run, "report.json")))
n = S["nodes"]
out = {}

def ts(line):
    m = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z", line)
    if not m:
        return None
    return datetime.strptime(m.group(1)[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()

# --- binaries
expected = {}
for l in open(sums):
    h, p = l.split()
    expected[os.path.basename(p.lstrip("*")).replace(".exe", "")] = h
b = {}
for k, rec in S["binaries"].items():
    exe = {"labnet": "blacksilk-labnet", "node": "blacksilk-node", "miner": "blacksilk-miner"}[k]
    v = rec["version"]
    b[k] = {
        "commit_66f12f0": "66f12f0761c80f13c493f2c752d2f511511f3303" in v,
        "no_dirty": "-dirty" not in v,
        "build_flags_none": "build flags: none" in v,
        "sha256_matches": rec["sha256"] == expected.get(exe),
    }
out["binaries"] = b

# --- summary fields
keys = ["checks_passed", "evidence", "evidence_notes", "crashes", "stuck_incidents",
        "misbehavior_disconnects", "converged_at_end", "mempools_drained_at_end",
        "late_joiner_synced", "late_joiner_peers", "late_joiner_required_peers",
        "late_joiner_secs_to_required", "late_joiner_max_peers", "fresh_wallet_balances_match",
        "fresh_wallet_px_balances_match", "supply_conserved", "generated", "wallet_total",
        "final_height", "duration_secs", "measured_secs", "warmup", "reorganizations",
        "max_reorg_depth", "reorg_depths", "reorgs_by_phase", "blocks_found_by_phase",
        "relay_discovery", "tx_attempts", "tx_submitted", "tx_failures", "partitions",
        "partition_split", "max_rss_mb", "all_equal_samples", "samples", "miner_modes"]
out["summary"] = {k: S.get(k) for k in keys}

# --- logs
logs = {os.path.basename(p): open(p, encoding="utf-8", errors="replace").read().splitlines()
        for p in glob.glob(os.path.join(run, "*.log")) if not os.path.basename(p) == "journal.log"}
node_logs = [f"node{i}.log" for i in range(n)]
all_proc_logs = [k for k in logs if k.startswith("node") or k.startswith("miner")]
out["selftest_missing"] = [k for k in sorted(logs) if k.startswith("node") and
                           not any("RandomX self-test passed" in l for l in logs[k])]
pats = {"is_invalid": r"is invalid", "misbehaved": r"misbehaved \(\+",
        "inbound_limit": r"inbound limit reached", "panic": r"panick", "ERROR": r"\bERROR\b",
        "halt": r"(?i)\bhalt"}
hits = {}
for name, pat in pats.items():
    rx = re.compile(pat)
    hits[name] = [f"{k}: {l[:240]}" for k in sorted(all_proc_logs) for l in logs[k] if rx.search(l)]
out["grep_hits"] = {k: {"count": len(v), "first": v[:10]} for k, v in hits.items()}
warn = [f"{k}: {l[:240]}" for k in sorted(all_proc_logs) for l in logs[k] if " WARN " in l]
out["warn_lines"] = {"count": len(warn), "first": warn[:30]}

# --- final chain coverage: every final-chain block (height >= 1) in every lab node's log
final = [l.split() for l in open(os.path.join(run, "final-chain.txt")) if l.strip()]
seen = []
for i in range(n):
    ids = set()
    for l in logs[f"node{i}.log"]:
        m = re.search(r"block ([0-9a-f]{12})[0-9a-f]* at height \d+ (accepted \(tip|received)", l)
        if m:
            ids.add(m.group(1))
    seen.append(ids)
missing = {}
for h, bid in final:
    if int(h) == 0:
        continue
    miss = [i for i in range(n) if bid[:12] not in seen[i]]
    if miss:
        missing[h] = miss
out["final_chain_blocks"] = len(final) - 1
out["final_chain_blocks_not_logged_by_every_node"] = {"count": len(missing), "first": dict(list(missing.items())[:20])}

# --- per-hop arrivals (connected phase): origin accept -> receiver first sighting
journal = open(os.path.join(run, "journal.log"), encoding="utf-8").read().splitlines()
def jt(sub):
    for l in journal:
        if sub in l:
            return int(l[1:l.index("]")])
    return None
warm_end = jt("warm-up done") or jt("warm-up ended")
traffic_end = jt("traffic phase over")
parts = [(int(l[1:l.index("]")]), "start" if "started" in l else "heal") for l in journal
         if "partition #" in l or "partition healed" in l]
def connected(t):
    if warm_end is None or t < warm_end or (traffic_end and t > traffic_end):
        return False
    state, last_heal = "conn", None
    for pt, kind in parts:
        if pt > t:
            break
        state = "part" if kind == "start" else "conn"
        if kind == "heal":
            last_heal = pt
    if state == "part":
        return False
    if last_heal is not None and t < last_heal + 60:
        return False  # heal window
    return True
origin = {}
first = [dict() for _ in range(n)]
for i in range(n):
    for l in logs[f"node{i}.log"]:
        m = re.search(r"block ([0-9a-f]{12})[0-9a-f]* at height (\d+) (accepted \(tip|received)", l)
        if not m:
            continue
        t = ts(l)
        bid = m.group(1)
        if m.group(3).startswith("accepted") and bid not in origin and "blacksilk_node]" in l:
            origin[bid] = (i, t)
        if bid not in first[i]:
            first[i][bid] = t
final_ids = {bid[:12] for h, bid in final}
def ringdist(a, c):
    d = abs(a - c) % n
    return min(d, n - d)
byhop = {}
byhop_final = {}
for bid, (o, t0) in origin.items():
    if not connected(t0):
        continue
    for i in range(n):
        if i == o or bid not in first[i]:
            continue
        d = first[i][bid] - t0
        h = ringdist(o, i) if S["topology"] == "ring" else None
        key = h if h is not None else "n/a"
        byhop.setdefault(key, []).append(d * 1000)
        if bid in final_ids:
            byhop_final.setdefault(key, []).append(d * 1000)
def stats(v):
    v = sorted(v)
    if not v:
        return None
    return {"n": len(v), "median_ms": round(statistics.median(v)), "p90_ms": round(v[int(0.9 * (len(v) - 1))]), "max_ms": round(v[-1])}
out["arrivals_by_hop_all"] = {str(k): stats(v) for k, v in sorted(byhop.items(), key=lambda x: str(x[0]))}
out["arrivals_by_hop_final_chain"] = {str(k): stats(v) for k, v in sorted(byhop_final.items(), key=lambda x: str(x[0]))}
out["connected_origin_blocks"] = sum(1 for b_, (o, t) in origin.items() if connected(t))

# --- side branches vs final chain (node 0's store)
sb = R.get("side_branches") or []
heavier = [x for x in sb if x["work"] and x["final_chain_work"] and x["work"][-1][1] > x["final_chain_work"][-1][1]]
equal = [x for x in sb if x["work"] and x["final_chain_work"] and x["work"][-1][1] == x["final_chain_work"][-1][1]]
out["side_branches"] = {"count": len(sb), "heavier_than_final_over_same_heights": len(heavier),
                        "equal_work_ties": len(equal), "max_len": max((x["tip_height"] - x["fork_height"] for x in sb), default=0)}
out["report"] = {k: R.get(k) for k in ["late_joiner_getaddr_answer", "propagation", "propagation_with_contested",
                                       "found_by_phase", "stale_after_warmup", "refused_at_rpc", "heals",
                                       "difficulty_min", "difficulty_max", "difficulty_first_third",
                                       "difficulty_last_third", "templates_abandoned_after_warmup"]}
out["report"]["arrivals_receivers"] = [{"node": x["node"], "never_seen": x["never_seen"], **(x["arrival"] or {})}
                                       for x in R["arrivals"]["receivers"]]
out["report"]["arrivals_all"] = R["arrivals"]["all"]
out["phase_marks_unix"] = {"warmup_end": warm_end, "traffic_end": traffic_end, "partitions": parts}
json.dump(out, open(os.path.join(run, "acceptance.json"), "w"), indent=1)
print(json.dumps({k: out[k] for k in ["binaries", "selftest_missing", "grep_hits", "final_chain_blocks",
                                      "final_chain_blocks_not_logged_by_every_node", "arrivals_by_hop_all",
                                      "arrivals_by_hop_final_chain", "side_branches"]}, indent=1))
