exec(open('ramp.py').read().split("for name,rule")[0])
for H,label in [(100/120,'eq=D0'),(1000/120,'eq=10xD0'),(10000/120,'eq=100xD0')]:
  for name,rule in [('v3',v3),('old',old)]:
    res=[]
    for seed in range(5):
      ds=run(rule,H,T=120,init=100,blocks=800,seed=seed,gen_gap=7200)
      eq=H*120
      reach=next((h for h,d,t in ds if d>=0.8*eq),None)
      res.append(reach)
    print(label,name,'blocks to 80% of eq D:',res, 'D@2..5', [ds[i][1] for i in range(1,5)])
