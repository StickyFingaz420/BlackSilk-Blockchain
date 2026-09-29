"""W4-RX: which miner produced each final-chain block in the checked windows.

Usage: python attribute.py <rx-verify.json> <run dir>
A block is miner0's (full mode) if node0 logged its id as accepted from its
miner's RPC submission, miner1's (light mode) if node2 did.
"""
import json
import re
import sys

d = json.load(open(sys.argv[1]))
run = sys.argv[2]
rec = {r["height"]: r["id"][:16] for r in d["records"]}


def submitted(path):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"block (\w{16}) at height (\d+) accepted", line)
        if m:
            out.setdefault(int(m.group(2)), set()).add(m.group(1))
    return out


m0 = submitted(f"{run}/node0.log")
m1 = submitted(f"{run}/node2.log")
res = {}
for lo, hi in ((2040, 2112), (2113, 2140), (2300, 2313), (2820, 2835)):
    hs = [h for h in range(lo, hi + 1) if h in rec]
    a = [h for h in hs if rec[h] in m0.get(h, ())]
    b = [h for h in hs if rec[h] in m1.get(h, ())]
    res[f"{lo}-{hi}"] = {
        "blocks": len(hs),
        "miner0_full": len(a),
        "miner1_light": b,
        "unattributed": [h for h in hs if h not in a and h not in b],
    }
print(json.dumps(res, indent=1))
