import json,sys,struct
bs=[]
for f in sys.argv[1:]:
    bs+=json.load(open(f))['blocks']
prev=None
out=[]
for b in bs:
    h=bytes.fromhex(b['hex'][:200])
    ver,=struct.unpack_from('<I',h,0); ht,=struct.unpack_from('<Q',h,4); ts,=struct.unpack_from('<Q',h,44); d,=struct.unpack_from('<Q',h,52)
    out.append((ht,ts,d))
for i,(ht,ts,d) in enumerate(out):
    dt = ts-out[i-1][1] if i else 0
    print(ht,ts,dt,d)
