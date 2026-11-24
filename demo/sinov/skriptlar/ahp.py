import numpy as np, json, itertools
C=['K1','K2','K3','K4','K5','K6','K7']
names={'K1':'Funksional qamrov','K2':'Aniqlash sifati','K3':'CI/CD integratsiyasi','K4':'Moslashuvchanlik va me’yoriy xaritalash','K5':'Iqtisodiy samaradorlik','K6':'Ta’minot zanjiri xavfsizligi','K7':'Normativ muvofiqlik va ma’lumotlar mahalliyligi'}
up={('K1','K2'):1/2,('K1','K3'):3,('K1','K4'):3,('K1','K5'):2,('K1','K6'):1,('K1','K7'):1,
('K2','K3'):4,('K2','K4'):4,('K2','K5'):3,('K2','K6'):2,('K2','K7'):2,
('K3','K4'):1,('K3','K5'):1/2,('K3','K6'):1/3,('K3','K7'):1/3,
('K4','K5'):1/2,('K4','K6'):1/3,('K4','K7'):1/3,
('K5','K6'):1/2,('K5','K7'):1/2,('K6','K7'):1}
n=len(C); A=np.ones((n,n))
for (a,b),v in up.items():
    i,j=C.index(a),C.index(b); A[i,j]=v; A[j,i]=1/v
# geometric mean method + eigenvector
gm=np.prod(A,axis=1)**(1/n); w=gm/gm.sum()
ev,vec=np.linalg.eig(A); k=np.argmax(ev.real); lam=ev.real[k]; we=np.abs(vec[:,k].real); we/=we.sum()
CI=(lam-n)/(n-1); RI={3:0.58,4:0.9,5:1.12,6:1.24,7:1.32,8:1.41}[n]; CR=CI/RI
print('lambda',round(lam,4),'CI',round(CI,4),'CR',round(CR,4))
for c,a,b in zip(C,w,we): print(c,round(a,4),round(b,4))
T=['Trivy','Grype','Checkov','KICS','Prowler','Wiz','Cortex Cloud','MS Defender for Cloud']
S={ # K1..K7
'Trivy':[4,4,5,4,5,2,4],
'Grype':[2,4,5,2,5,4,4],
'Checkov':[3,3,5,5,5,3,4],
'KICS':[3,3,5,4,5,1,4],
'Prowler':[3,3,4,5,5,3,4],
'Wiz':[5,3,4,5,1,3,2],
'Cortex Cloud':[5,3,4,5,1,3,2],
'MS Defender for Cloud':[4,3,3,4,3,3,2]}
M=np.array([S[t] for t in T],float)
score=M@we; norm=score/5
order=np.argsort(-score)
print()
for r,i in enumerate(order,1): print(r,T[i],round(score[i],3),round(norm[i],3))
# sensitivity: each weight +/-20%, +/-50%
res=[]
base_rank=[T[i] for i in order]
def rank(wv):
    s=M@wv; return [T[i] for i in np.argsort(-s)], s
changes={}
for j,c in enumerate(C):
    for f in [0.5,0.8,1.2,1.5]:
        wv=we.copy(); wv[j]*=f; wv/=wv.sum(); rk,s=rank(wv)
        changes[(c,f)]=(rk[:3], rk==base_rank)
for k,v in changes.items(): print(k, 'top3:',v[0], 'same order' if v[1] else 'ORDER CHANGED')
# scenarios
sc={'Davlat tashkiloti (K7 va K6 ustuvor)':{'K6':2.0,'K7':2.0},'Yirik korporativ (K1 va K2 ustuvor, K5 past)':{'K1':2.0,'K2':1.5,'K5':0.3},'Kichik tashkilot (K5 ustuvor)':{'K5':3.0}}
scen={}
for name,mult in sc.items():
    wv=we.copy()
    for c,f in mult.items(): wv[C.index(c)]*=f
    wv/=wv.sum(); rk,s=rank(wv); scen[name]={'w':[round(x,3) for x in wv],'rank':[(T[i],round(s[i],3)) for i in np.argsort(-s)]}
    print(name, scen[name]['rank'][:4])
json.dump({'C':C,'names':names,'A':A.tolist(),'w':we.tolist(),'w_gm':w.tolist(),'lam':lam,'CI':CI,'CR':CR,'T':T,'S':S,'score':score.tolist(),'order':[int(i) for i in order],'scen':scen,
 'sens':{f'{k[0]}x{k[1]}':{'top3':v[0],'same':v[1]} for k,v in changes.items()}},open('/home/claude/diss/calc/ahp.json','w'),ensure_ascii=False,indent=1)
