import random,sys
def v3(ts,cd,T,N=75,init=1,WARM=11):
    L=len(ts); take=min(L,N+1); n=take-1
    if n==0: return init
    step=max(1,T//2); w0=L-take; frm=max(0,w0-WARM); prev=ts[frm]
    for x in ts[frm+1:w0+1]: prev=max(x,prev+step)
    W=0;S=0
    for i in range(1,take):
        this=max(ts[w0+i],prev+step); st=min(this-prev,6*T); prev=this
        W+=i*st; S+=cd[w0+i]-cd[w0+i-1]
    W=max(W,n*n*T//20,1)
    return max(1,S*T*(n+1)//(2*W))
def old(ts,cd,T,N=60,init=1):
    L=len(ts); take=min(L,N+1); n=take-1
    if n==0: return init
    t=ts[L-take:]; c=cd[L-take:]; prev=t[0]; W=0;S=0
    for i in range(1,take):
        this=t[i] if t[i]>prev else prev+1
        st=min(this-prev,6*T); prev=this; W+=i*st; S+=c[i]-c[i-1]
    W=max(W,n*n*T//20,1)
    return max(1,S*T*(n+1)//(2*W))
def run(rule,H,T=10,init=1,blocks=600,seed=1,gen_gap=90_000_000):
    rng=random.Random(seed)
    ts=[1_700_000_000]; cd=[init]; now=float(ts[0]+gen_gap); ds=[]
    for h in range(1,blocks+1):
        d=rule(ts,cd,T,init=init)
        now+=rng.expovariate(H/d)+0.0
        ts.append(max(int(now),ts[-1])) ; cd.append(cd[-1]+d); ds.append((h,d,now))
    return ds
for name,rule in [('v3',v3),('old',old)]:
    for H in [1.2,4.0]:
        ds=run(rule,H)
        t0=ds[0][2]
        eq=H*10
        reach=next((h for h,d,t in ds if d>=0.8*eq),None)
        tr = next((t-t0 for h,d,t in ds if d>=0.8*eq),None)
        print(name,'H=%.1f eqD=%.0f'%(H,eq),'reach80%% at block',reach,'after %.0fs'%(tr or -1),'D@50,100,150,300:',[ds[i-1][1] for i in (50,100,150,300)])
print('--- no genesis gap')
for H in [4.0]:
    ds=run(v3,H,gen_gap=0)
    print('v3 nogap D@10,30,50,76,100,150:',[ds[i-1][1] for i in (10,30,50,76,100,150)])
    ds=run(v3,H)
    print('v3 gap   D@10,30,50,76,100,150:',[ds[i-1][1] for i in (10,30,50,76,100,150)])
