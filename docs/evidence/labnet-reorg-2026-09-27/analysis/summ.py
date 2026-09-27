import json, re, sys, glob, collections

# Per-run summary: reorg depth buckets (per node log line), found vs final height.
for d in sys.argv[1:]:
    s = json.load(open(d + '/summary.json'))
    depths = []
    for f in sorted(glob.glob(d + '/node[0-9].log')):
        for l in open(f, encoding='utf-8', errors='replace'):
            m = re.search(r'disconnecting (\d+) block\(s\) above height (\d+)', l)
            if m:
                depths.append(int(m.group(1)))
    fd = []
    for f in ('miner0', 'miner1'):
        fd.append(sum(1 for l in open(d + f'/{f}.log', encoding='utf-8', errors='replace') if 'found block' in l))
    buckets = {'1': 0, '2-3': 0, '4-9': 0, '10-29': 0, '>=30': 0}
    for x in depths:
        k = '1' if x == 1 else '2-3' if x <= 3 else '4-9' if x <= 9 else '10-29' if x <= 29 else '>=30'
        buckets[k] += 1
    found = sum(fd)
    h = s['final_height']
    print(f"{d:10s} height {h:4d} reorgs {s['reorganizations']:3d} max {s['max_reorg_depth']:3d} "
          f"depths {buckets} found {found} not-in-final-chain {found - h} ({100 * (found - h) / found:.0f}%) "
          f"stuck {s['stuck_incidents']} passed {s['checks_passed']}")
