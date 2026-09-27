import re,sys,datetime,statistics
d=sys.argv[1]
def ts(line):
    m=re.match(r'\[(\S+)Z',line); return datetime.datetime.fromisoformat(m.group(1)).timestamp()
def found(f):
    out={}
    for l in open(f,encoding='utf-8',errors='replace'):
        m=re.search(r'found block (\d+)',l)
        if m: out.setdefault(int(m.group(1)),ts(l))
    return out
def hdr(f):
    out={}
    for l in open(f,encoding='utf-8',errors='replace'):
        m=re.search(r'headers up to height (\d+) accepted \(new: true\)',l)
        if m: out.setdefault(int(m.group(1)),[]).append(ts(l))
    return out
a=found(d+'/miner0.log'); b=found(d+'/miner1.log')
h2=hdr(d+'/node2.log'); h0=hdr(d+'/node0.log')
def deltas(src,dst,lo,hi):
    r=[]
    for h in range(lo,hi+1):
        if h in src and h in dst:
            # first new-header accept at dst at/after the rival's find
            c=[t-src[h] for t in dst[h] if t>=src[h]-0.05]
            if c: r.append(min(c))
    return r
for lo,hi,lab in [(2,76,'D=1 phase'),(77,200,'D>=2')]:
    x=deltas(a,h2,lo,hi); y=deltas(b,h0,lo,hi)
    off=[abs(a[h]-b[h]) for h in range(lo,hi+1) if h in a and h in b]
    q=lambda v: 'n=%d median %.3f p10 %.3f p90 %.3f'%(len(v),statistics.median(v),sorted(v)[len(v)//10],sorted(v)[len(v)*9//10]) if v else 'n=0'
    print(lab,'| A found->node2 header:',q(x),'| B found->node0 header:',q(y),'| |tA-tB| same height:',q(off))
