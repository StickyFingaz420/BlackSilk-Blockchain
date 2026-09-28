"""Not-adopted fraction of connected-phase found blocks, by tip difficulty.

Usage: python stratify.py <run dir> [<run dir> ...]
A run dir holds metrics.csv and the miner logs (in logs/ or beside it). Each
`found block` line is attributed to the latest earlier metrics sample (15 s
grid): its phase and the highest tip difficulty over the nodes. Only
`connected` samples are counted. Output per bucket: (found, not adopted, %).
The phase attribution is by timestamp, so totals differ slightly from
summary.json, which attributes by log position.
"""
import csv
import datetime
import os
import sys

for run in sys.argv[1:]:
    rows = list(csv.reader(open(os.path.join(run, 'metrics.csv'))))
    h = rows[0]
    ui, di, pi = h.index('unix'), h.index('difficulties'), h.index('phase')
    samples = [(int(x[ui]), max(int(d) for d in x[di].split('/') if d), x[pi]) for x in rows[1:]]
    buckets = {}
    for m in ['miner0.log', 'miner1.log']:
        path = os.path.join(run, 'logs', m)
        if not os.path.exists(path):
            path = os.path.join(run, m)
        for line in open(path, encoding='utf-8', errors='replace'):
            if 'found block ' not in line:
                continue
            ts = datetime.datetime.strptime(line[1:24], '%Y-%m-%dT%H:%M:%S.%f')
            ts = ts.replace(tzinfo=datetime.timezone.utc).timestamp()
            prev = [s for s in samples if s[0] <= ts]
            if not prev or prev[-1][2] != 'connected':
                continue
            d = prev[-1][1]
            b = '<=12' if d <= 12 else '13-16' if d <= 16 else '>=17'
            f, n = buckets.get(b, (0, 0))
            buckets[b] = (f + 1, n + ('not on the node' in line))
    print(run, {k: (v[0], v[1], round(100 * v[1] / v[0], 1)) for k, v in sorted(buckets.items())})
