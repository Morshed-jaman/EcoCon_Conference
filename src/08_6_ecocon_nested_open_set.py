"""Final experiment: nested open-set detector selection (EcoCon-NOS)."""
from __future__ import annotations
import hashlib,json,time
from pathlib import Path
import joblib,numpy as np,pandas as pd
from scipy.stats import wilcoxon
from sklearn.covariance import LedoitWolf
from sklearn.metrics import roc_auc_score,average_precision_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

ROOT=Path(__file__).resolve().parent.parent;R=ROOT/'results';P=ROOT/'processed';LM=ROOT/'models'/'loafo';MM=ROOT/'models'/'ecocon_md';NM=ROOT/'models'/'ecocon_nos';LP=R/'predictions'/'loafo';MP=R/'predictions'/'ecocon_md'
FOLDS=['DDoS','DoS','Mirai','Recon','Spoofing','BruteForce','Web'];CANDS=['MSP','Entropy','MD-Pred','Min-MD','MDS','ClassConditionalKNN','GlobalKNN'];COST={x:i for i,x in enumerate(CANDS)}
ALPHA=.05;MAXINNER=12;MAXCLASS=20000;MAXGLOBAL=100000;K=10
def req(x,m):
 if not x:raise RuntimeError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def rng_for(seed,text):return np.random.default_rng(seed+int(hashlib.sha256(text.encode()).hexdigest()[:8],16))
def grouped_split(d,seed):
 g=d.groupby('feature_hash',sort=False).agg(family=('family','first'),n=('family','size')).reset_index();parts=[]
 for fam,x in g.groupby('family',sort=True):
  x=x.sort_values('feature_hash').copy();x=x.iloc[rng_for(seed,str(fam)).permutation(len(x))];target=.8*x.n.sum();cur=0;s=[]
  for n in x.n:s.append('reference' if cur<target else 'valid');cur+=n
  x['inner_split']=s;parts.append(x)
 return pd.concat(parts,ignore_index=True)
def choose_holdouts(train):
 c=train.groupby(['family','fine_label']).size().rename('n').reset_index();eligible=[]
 for fam,g in c.groupby('family'):
  if len(g)>=2:eligible.extend(g[g.n>=1000].sort_values('fine_label').to_dict('records'))
 by={f:sorted([r for r in eligible if r['family']==f],key=lambda z:z['fine_label']) for f in sorted({r['family'] for r in eligible})};out=[]
 while len(out)<MAXINNER and any(by.values()):
  for f in sorted(by):
   if by[f] and len(out)<MAXINNER:out.append(by[f].pop(0))
 return out
def sample_idx(labels,classes,cap,seed):
 rng=np.random.default_rng(seed);idx=[];base=cap//len(classes);extra=cap%len(classes)
 for i,c in enumerate(classes):
  z=np.flatnonzero(labels==c);n=min(len(z),base+(i<extra));idx.extend(rng.choice(z,n,replace=False))
 if len(idx)<min(cap,len(labels)):
  rem=np.setdiff1d(np.arange(len(labels)),np.array(idx));n=min(len(rem),min(cap,len(labels))-len(idx));idx.extend(rng.choice(rem,n,replace=False))
 return np.array(idx,dtype=int)
def fit_context(ref,features,classes,seed):
 sc=StandardScaler().fit(ref[features].to_numpy(float));Z=sc.transform(ref[features].to_numpy(float)).astype('float32');y=ref.family.to_numpy();means={c:Z[y==c].mean(0).astype(float) for c in classes};res=np.empty_like(Z,dtype=float)
 for c in classes:m=y==c;res[m]=Z[m]-means[c]
 lw=LedoitWolf(assume_centered=True).fit(res);prec=lw.precision_;class_knn={};class_rows=0
 for c in classes:
  z=Z[y==c];rr=rng_for(seed,c);sel=rr.choice(len(z),min(len(z),MAXCLASS),replace=False);bank=z[sel];class_knn[c]=NearestNeighbors(n_neighbors=min(K,len(bank)),n_jobs=-1).fit(bank);class_rows+=len(bank)
 gi=sample_idx(y,classes,MAXGLOBAL,seed+991);global_knn=NearestNeighbors(n_neighbors=min(K,len(gi)),n_jobs=-1).fit(Z[gi])
 return {'features':features,'classes':classes,'scaler':sc,'means':means,'precision':prec,'class_knn':class_knn,'global_knn':global_knn,'class_reference_rows':class_rows,'global_reference_rows':len(gi)}
def score_all(d,ctx):
 fs=ctx['features'];Z=ctx['scaler'].transform(d[fs].to_numpy(float)).astype('float32');classes=ctx['classes'];pred=d.predicted_family.to_numpy();D=np.empty((len(d),len(classes)))
 for j,c in enumerate(classes):r=Z-ctx['means'][c];D[:,j]=np.maximum(np.einsum('ij,jk,ik->i',r,ctx['precision'],r,optimize=True),0)
 order=np.sort(D,axis=1);var=D.var(1);codes=pd.Categorical(pred,categories=classes).codes;req((codes>=0).all(),'unknown predicted class');mdpred=D[np.arange(len(D)),codes];cc=np.empty(len(d))
 for c in classes:
  m=pred==c
  if m.any():cc[m]=ctx['class_knn'][c].kneighbors(Z[m],return_distance=True)[0].mean(1)
 glob=ctx['global_knn'].kneighbors(Z,return_distance=True)[0].mean(1);probs=d[[c for c in d if c.startswith('prob_')]].to_numpy();ent=-(probs*np.log(probs+1e-12)).sum(1)
 return {'MSP':1-probs.max(1),'Entropy':ent,'MD-Pred':mdpred,'Min-MD':order[:,0],'MDS':np.log1p(order[:,0])-np.log1p(var),'ClassConditionalKNN':cc,'GlobalKNN':glob}
def score_selected(d,ctx,candidate):
 if candidate in ['MSP','Entropy']:
  probs=d[[c for c in d if c.startswith('prob_')]].to_numpy();return 1-probs.max(1) if candidate=='MSP' else -(probs*np.log(probs+1e-12)).sum(1)
 Z=ctx['scaler'].transform(d[ctx['features']].to_numpy(float)).astype('float32');pred=d.predicted_family.to_numpy()
 if candidate=='ClassConditionalKNN':
  out=np.empty(len(d))
  for c in ctx['classes']:
   m=pred==c
   if m.any():out[m]=ctx['class_knn'][c].kneighbors(Z[m],return_distance=True)[0].mean(1)
  return out
 if candidate=='GlobalKNN':return ctx['global_knn'].kneighbors(Z,return_distance=True)[0].mean(1)
 D=np.empty((len(d),len(ctx['classes'])))
 for j,c in enumerate(ctx['classes']):r=Z-ctx['means'][c];D[:,j]=np.maximum(np.einsum('ij,jk,ik->i',r,ctx['precision'],r,optimize=True),0)
 if candidate=='Min-MD':return D.min(1)
 if candidate=='MDS':return np.log1p(D.min(1))-np.log1p(D.var(1))
 codes=pd.Categorical(pred,categories=ctx['classes']).codes;return D[np.arange(len(D)),codes]
def attach_predictions(d,model,features,classes):
 p=model.predict_proba(d[features].astype('float32'));out=d.copy();out['predicted_family']=np.array(classes)[p.argmax(1)]
 for i,c in enumerate(classes):out[f'prob_{c}']=p[:,i]
 return out
def threshold(s):return float(np.quantile(s,.95,method='higher'))
def inner_metric(cand,sk,su,known):
 t=threshold(sk);rk=sk>=t;ru=su>=t;correct=known.predicted_family.to_numpy()==known.family.to_numpy();ak=~rk;au=~ru;accepted=ak.sum()+au.sum();risk=((ak&~correct).sum()+au.sum())/accepted;lab=np.r_[np.zeros(len(sk)),np.ones(len(su))];scores=np.r_[sk,su]
 return {'known_rejection':rk.mean(),'UADR':ru.mean(),'overall_risk':risk,'AUROC':roc_auc_score(lab,scores),'AUPRC':average_precision_score(lab,scores)}
def select_candidate(summary):
 best=summary.mean_UADR.max();q=summary[summary.mean_UADR>=best-.01].copy();r=q.mean_overall_risk.min();q=q[q.mean_overall_risk==r]
 if len(q)>1:q=q[q.worst_UADR==q.worst_UADR.max()]
 chosen=sorted(q.candidate,key=lambda x:COST[x])[0];row=summary[summary.candidate==chosen].iloc[0]
 return chosen,f"{chosen} selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order.",row
def pv(cal,s):
 a=np.sort(cal);return (1+len(a)-np.searchsorted(a,s,side='left'))/(len(a)+1)
def outer_metric(h,method,k,u,scorek,scoreu,pcal):
 pk=pv(pcal,scorek);pu=pv(pcal,scoreu);rk=pk<=ALPHA;ru=pu<=ALPHA;correct=k.predicted_family.to_numpy()==k.true_family.to_numpy();ak=~rk;au=~ru;acc=ak.sum()+au.sum();wrong=(ak&~correct).sum()+au.sum();lab=np.r_[np.zeros(len(k)),np.ones(len(u))];ss=np.r_[scorek,scoreu]
 return {'held_out_family':h,'method':method,'known_rejection_rate':rk.mean(),'known_acceptance_rate':ak.mean(),'known_selective_risk':(~correct[ak]).mean(),'UADR':ru.mean(),'unknown_acceptance_rate':au.mean(),'coverage':acc/(len(k)+len(u)),'review_rate':1-acc/(len(k)+len(u)),'overall_selective_risk':wrong/acc,'AUROC':roc_auc_score(lab,ss),'AUPRC':average_precision_score(lab,ss),'known_count':len(k),'unknown_count':len(u),'known_rejected':rk.sum(),'unknown_rejected':ru.sum(),'accepted_known':ak.sum(),'accepted_unknown':au.sum(),'wrong_known_accepted':int((ak&~correct).sum())},rk,ru,pk,pu
def load_outer(h,split,pool,features):
 p=pd.read_parquet(LP/h/f'{split}.parquet');lookup=pool[['feature_hash',*features]].drop_duplicates('feature_hash');return p.merge(lookup,on='feature_hash',validate='many_to_one')
def bootstrap_ci(row,rk,ru,k,u,seed):
 rng=np.random.default_rng(seed);nu=len(u);uadr=rng.binomial(nu,ru.mean(),1000)/nu;correct=k.predicted_family.to_numpy()==k.true_family.to_numpy();cats=np.array([((~rk)&(~correct)).sum(),((~rk)&correct).sum(),(~ru).sum(),rk.sum()+ru.sum()]);draw=rng.multinomial(len(k)+len(u),cats/cats.sum(),size=1000);risk=(draw[:,0]+draw[:,2])/np.maximum(draw[:,:3].sum(1),1)
 return [('UADR',*np.quantile(uadr,[.025,.975])),('overall_selective_risk',*np.quantile(risk,[.025,.975]))]
def main():
 NM.mkdir(parents=True,exist_ok=True);success={'primary':['macro NOS UADR > macro MD UADR','macro NOS risk < macro MD risk','macro known rejection in [0.04,0.06]'],'strong_robustness':'within 0.02 of best existing on >=6/7 and strictly best on >=4/7','best_paper_target':{'macro_UADR':.35,'macro_risk':.44,'folds_beat_MD':5},'alpha':ALPHA};(R/'ecocon_nos_success_criteria.json').write_text(json.dumps(success,indent=2)+'\n')
 pool=pd.read_parquet(P/'modeling_pool.parquet');manifest=pd.read_parquet(R/'loafo_split_manifest.parquet');meta=json.loads((LM/'metadata.json').read_text());before={str(p):sha(p) for root in [LM,MM] for p in root.glob('holdout_*.joblib')};holdouts={};inner_rows=[];summaries=[];selections={};cache={}
 # Freeze every diversity-selected pseudo-OOD label before evaluating any candidate.
 for h in FOLDS:
  fm=manifest[manifest.held_out_family==h];train0=pool[pool.feature_hash.isin(set(fm.loc[fm.loafo_split=='train','feature_hash']))];chosen0=choose_holdouts(train0);holdouts[h]=[{'fine_label':x['fine_label'],'family':x['family'],'rows':int(x['n'])} for x in chosen0]
 (R/'ecocon_nos_inner_holdouts.json').write_text(json.dumps(holdouts,indent=2)+'\n');req(len(json.loads((R/'ecocon_nos_inner_holdouts.json').read_text()))==7,'inner holdout freeze')
 for oi,h in enumerate(FOLDS):
  print(f'[Outer {h}]\nConstructing inner pseudo-OOD folds...',flush=True);cfg=meta[h];fs=cfg['selected_features'];classes=cfg['known_classes'];fm=manifest[manifest.held_out_family==h];th=set(fm.loc[fm.loafo_split=='train','feature_hash']);train=pool[pool.feature_hash.isin(th)].copy();model=joblib.load(LM/f'holdout_{h}.joblib');train=attach_predictions(train,model,fs,classes);chosen=holdouts[h]
  fold_results=[]
  for ii,item in enumerate(chosen):
   label=item['fine_label'];print(f'Inner {label}...',flush=True);pseudo=train[train.fine_label==label];knownpool=train[train.fine_label!=label];im=grouped_split(knownpool,10000+oi*100+ii);ref=knownpool[knownpool.feature_hash.isin(set(im.loc[im.inner_split=='reference','feature_hash']))];valid=knownpool[knownpool.feature_hash.isin(set(im.loc[im.inner_split=='valid','feature_hash']))];req(label not in set(ref.fine_label) and not(set(ref.feature_hash)&set(valid.feature_hash)),'inner leakage');ctx=fit_context(ref,fs,classes,42000+oi*100+ii);sv=score_all(valid,ctx);su=score_all(pseudo,ctx)
   vals=[]
   for c in CANDS:
    z=inner_metric(c,sv[c],su[c],valid);row={'outer_held_out_family':h,'inner_held_out_fine_label':label,'candidate':c,**z};inner_rows.append(row);fold_results.append(row);vals.append((c,z['UADR']))
   print(' '.join(f'{c}={v:.3f}' for c,v in vals),flush=True)
  fdf=pd.DataFrame(fold_results);win=fdf.loc[fdf.groupby('inner_held_out_fine_label').UADR.transform('max')==fdf.UADR].candidate.value_counts()
  s=fdf.groupby('candidate').agg(mean_UADR=('UADR','mean'),median_UADR=('UADR','median'),std_UADR=('UADR','std'),worst_UADR=('UADR','min'),mean_overall_risk=('overall_risk','mean')).reset_index();s['inner_fold_wins']=s.candidate.map(win).fillna(0).astype(int);s.insert(0,'outer_held_out_family',h);summaries.append(s);det,reason,srow=select_candidate(s);selections[h]={'selected_detector':det,'mean_inner_UADR':float(srow.mean_UADR),'mean_inner_risk':float(srow.mean_overall_risk),'inner_folds_used':len(chosen),'selection_reason':reason};print(f'Selected detector: {det}',flush=True)
 pd.DataFrame(inner_rows).to_csv(R/'ecocon_nos_inner_results.csv',index=False,float_format='%.10f');pd.concat(summaries).to_csv(R/'ecocon_nos_candidate_summary.csv',index=False,float_format='%.10f');(R/'ecocon_nos_outer_detector_selection.json').write_text(json.dumps(selections,indent=2)+'\n');req(len(json.loads((R/'ecocon_nos_outer_detector_selection.json').read_text()))==7,'selection freeze')
 # Fit only selected outer detector references and calibrate before opening either test partition.
 outer_ctx={};cal_scores={}
 for oi,h in enumerate(FOLDS):
  cfg=meta[h];fs=cfg['selected_features'];classes=cfg['known_classes'];fm=manifest[manifest.held_out_family==h];train=pool[pool.feature_hash.isin(set(fm.loc[fm.loafo_split=='train','feature_hash']))].copy();model=joblib.load(LM/f'holdout_{h}.joblib');train=attach_predictions(train,model,fs,classes);det=selections[h]['selected_detector']
  ctx=fit_context(train,fs,classes,52000+oi) if det not in ['MSP','Entropy','MD-Pred'] else None;cal=load_outer(h,'calibration',pool,fs);scores=None
  if det in ['MSP','Entropy']:
   probs=cal[[c for c in cal if c.startswith('prob_')]].to_numpy();scores=1-probs.max(1) if det=='MSP' else -(probs*np.log(probs+1e-12)).sum(1)
  elif det=='MD-Pred':scores=pd.read_parquet(MP/h/'calibration.parquet').mahalanobis_pred.to_numpy()
  else:scores=score_all(cal,ctx)[det]
  outer_ctx[h]=ctx;cal_scores[h]=scores;joblib.dump({'selected_detector':det,'context':ctx,'calibration_scores':scores,'alpha':ALPHA},NM/f'holdout_{h}.joblib',compress=3)
 (NM/'metadata.json').write_text(json.dumps(selections,indent=2)+'\n')
 # Selection, criteria, calibration and alpha are now frozen; outer tests may be opened.
 nos_rows=[];rescue=[];eff=[];boot=[];decisions={}
 for oi,h in enumerate(FOLDS):
  print(f'[Outer {h}] SELECTION FROZEN.\nOuter calibration complete.\nOpening outer unknown test...',flush=True);cfg=meta[h];fs=cfg['selected_features'];det=selections[h]['selected_detector'];ctx=outer_ctx[h];k=load_outer(h,'test_known',pool,fs);u=load_outer(h,'test_unknown',pool,fs)
  if det in ['MSP','Entropy']:
   def ps(d):
    p=d[[c for c in d if c.startswith('prob_')]].to_numpy();return 1-p.max(1) if det=='MSP' else -(p*np.log(p+1e-12)).sum(1)
   sk,su=ps(k),ps(u)
  elif det=='MD-Pred':sk=pd.read_parquet(MP/h/'test_known.parquet').mahalanobis_pred.to_numpy();su=pd.read_parquet(MP/h/'test_unknown.parquet').mahalanobis_pred.to_numpy()
  else:sk=score_selected(k,ctx,det);su=score_selected(u,ctx,det)
  row,rk,ru,pk,pu=outer_metric(h,'EcoConNOS',k,u,sk,su,cal_scores[h]);nos_rows.append(row);decisions[h]=(rk,ru,k,u)
  high=u.max_probability.to_numpy()>=.95;oldres=pd.read_csv(R/'overconfident_unknown_rescue.csv').set_index('held_out_family').loc[h,'ecocon_rescue_rate'];
  # frozen MSP/Entropy decisions use Step-8 per-row files
  oldm={m:pd.read_parquet(R/'predictions'/'step8'/h/f'{m}.parquet') for m in ['MSP','Entropy']};rescue.append({'held_out_family':h,'high_confidence_unknown_rows':int(high.sum()),'MSP_rescue_rate':oldm['MSP'].loc[oldm['MSP'].is_unknown,'rejected'].to_numpy()[high].mean(),'Entropy_rescue_rate':oldm['Entropy'].loc[oldm['Entropy'].is_unknown,'rejected'].to_numpy()[high].mean(),'EcoConMD_rescue_rate':oldres,'EcoConNOS_rescue_rate':ru[high].mean()})
  for metric,lo,hi in bootstrap_ci(row,rk,ru,k,u,20260811+oi):boot.append({'held_out_family':h,'metric':metric,'estimate':row[metric if metric=='UADR' else 'overall_selective_risk'],'ci_lower':lo,'ci_upper':hi,'bootstrap_resamples':1000})
  # selected auxiliary timing only; identical known-test rows, 10 repeats
  oldeff=pd.read_csv(R/'ecocon_efficiency.csv').set_index('held_out_family').loc[h];base=float(oldeff.xgboost_ms_per_sample);ts=[]
  for _ in range(10):
   s=time.perf_counter()
   if det=='MSP':_ = 1-k[[c for c in k if c.startswith('prob_')]].to_numpy().max(1)
   elif det=='Entropy':
    p=k[[c for c in k if c.startswith('prob_')]].to_numpy();_=-(p*np.log(p+1e-12)).sum(1)
   elif det=='MD-Pred':
    obj=joblib.load(MM/f'holdout_{h}.joblib');Z=obj['scaler'].transform(k[fs].to_numpy(float));pred=k.predicted_family.to_numpy();res=np.empty_like(Z)
    for c in cfg['known_classes']:m=pred==c;res[m]=Z[m]-obj['class_means'][c]
    _=np.maximum(np.einsum('ij,jk,ik->i',res,obj['shared_precision_matrix'],res,optimize=True),0)
   else:_=score_selected(k,ctx,det)
   ts.append(time.perf_counter()-s)
  aux=np.median(ts)*1000/len(k);mem=(NM/f'holdout_{h}.joblib').stat().st_size/2**20;eff.append({'held_out_family':h,'selected_detector':det,'xgboost_ms_per_sample':base,'auxiliary_ms_per_sample':aux,'combined_ms_per_sample':base+aux,'overhead_percent':aux/base*100,'class_reference_rows':0 if ctx is None else ctx['class_reference_rows'],'global_reference_rows':0 if ctx is None else ctx['global_reference_rows'],'detector_object_size_mib':mem});print(f'Final UADR={row["UADR"]:.4f}',flush=True)
 pd.DataFrame(nos_rows).to_csv(R/'ecocon_nos_outer_results.csv',index=False,float_format='%.10f');pd.DataFrame(rescue).to_csv(R/'ecocon_nos_overconfident_rescue.csv',index=False,float_format='%.10f');pd.DataFrame(eff).to_csv(R/'ecocon_nos_efficiency.csv',index=False,float_format='%.10f');pd.DataFrame(boot).to_csv(R/'ecocon_nos_bootstrap_ci.csv',index=False,float_format='%.10f')
 # Frozen baseline comparison and summaries.
 old=pd.read_csv(R/'selective_metrics_by_fold.csv');base=old[(old.alpha==ALPHA)&old.method.isin(['ForcedXGBoost','MSP','Entropy','EcoConMD'])].copy();fuse=pd.read_csv(R/'step8_5_selective_by_fold.csv');fuse=fuse[(fuse.alpha==ALPHA)&(fuse.method=='EcoConFuse')].copy();allrows=pd.concat([base,fuse,pd.DataFrame(nos_rows)],ignore_index=True,sort=False);allrows.to_csv(R/'ecocon_nos_outer_results.csv',index=False,float_format='%.10f')
 macro=[]
 for method,g in allrows.groupby('method'):macro.append({'method':method,'known_rejection_rate':g.known_rejection_rate.mean(),'UADR':g.UADR.mean(),'coverage':g.coverage.mean(),'review_rate':g.review_rate.mean(),'overall_selective_risk':g.overall_selective_risk.mean()})
 macro=pd.DataFrame(macro);macro.to_csv(R/'ecocon_nos_macro_summary.csv',index=False,float_format='%.10f');piv=allrows.pivot(index='held_out_family',columns='method',values='UADR');fam=piv[['MSP','Entropy','EcoConMD','EcoConNOS']].reset_index();fam['best_existing']=fam[['MSP','Entropy','EcoConMD']].max(axis=1);fam['NOS_regret']=fam.EcoConNOS-fam.best_existing;fam.to_csv(R/'ecocon_nos_family_comparison.csv',index=False,float_format='%.10f')
 stats=[]
 for outcome in ['UADR','overall_selective_risk']:
  q=allrows.pivot(index='held_out_family',columns='method',values=outcome)
  for b in ['EcoConMD','Entropy','MSP']:
   d=q.EcoConNOS-q[b];st,p=wilcoxon(q.EcoConNOS,q[b]);win=d>0 if outcome=='UADR' else d<0;stats.append({'outcome':outcome,'comparison':f'EcoConNOS vs {b}','mean_paired_difference':d.mean(),'median_paired_difference':np.median(d),'wins':int(win.sum()),'losses':int((~win&(d!=0)).sum()),'ties':int((d==0).sum()),'wilcoxon_statistic':st,'p_value':p})
 pd.DataFrame(stats).to_csv(R/'ecocon_nos_statistics.csv',index=False,float_format='%.10f')
 # Fresh confirmation uses already-selected detector and calibration.
 fresh=pd.read_parquet(P/'fresh_confirmation_unknown.parquet');freshout=[]
 prior=pd.read_csv(R/'step8_5_fresh_confirmation.csv').set_index('held_out_family')
 for h in FOLDS[:5]:
  d=fresh[fresh.family==h].copy();cfg=meta[h];fs=cfg['selected_features'];classes=cfg['known_classes'];model=joblib.load(LM/f'holdout_{h}.joblib');d=attach_predictions(d,model,fs,classes);det=selections[h]['selected_detector'];ctx=outer_ctx[h]
  if det=='MSP':s=1-d[[c for c in d if c.startswith('prob_')]].to_numpy().max(1)
  elif det=='Entropy':
   p=d[[c for c in d if c.startswith('prob_')]].to_numpy();s=-(p*np.log(p+1e-12)).sum(1)
  elif det=='MD-Pred':
   obj=joblib.load(MM/f'holdout_{h}.joblib');Z=obj['scaler'].transform(d[fs].to_numpy(float));pred=d.predicted_family.to_numpy();res=np.empty_like(Z)
   for c in classes:m=pred==c;res[m]=Z[m]-obj['class_means'][c]
   s=np.maximum(np.einsum('ij,jk,ik->i',res,obj['shared_precision_matrix'],res,optimize=True),0)
  else:s=score_all(d,ctx)[det]
  nos=(pv(cal_scores[h],s)<=ALPHA).mean();q=prior.loc[h];freshout.append({'held_out_family':h,'selected_detector':det,'fresh_rows':len(d),'MSP_UADR':q.MSP_UADR,'Entropy_UADR':q.Entropy_UADR,'EcoConMD_UADR':q.EcoConMD_UADR,'EcoConNOS_UADR':nos})
 pd.DataFrame(freshout).to_csv(R/'ecocon_nos_fresh_confirmation.csv',index=False,float_format='%.10f')
 req({str(p):sha(p) for root in [LM,MM] for p in root.glob('holdout_*.joblib')}==before,'frozen model changed');mm=macro.set_index('method');primary=mm.loc['EcoConNOS','UADR']>mm.loc['EcoConMD','UADR'] and mm.loc['EcoConNOS','overall_selective_risk']<mm.loc['EcoConMD','overall_selective_risk'] and .04<=mm.loc['EcoConNOS','known_rejection_rate']<=.06;within=(fam.NOS_regret>=-.02).sum();strict=(fam.NOS_regret>0).sum();strong=within>=6 and strict>=4;beatmd=(fam.EcoConNOS>fam.EcoConMD).sum();target=mm.loc['EcoConNOS','UADR']>=.35 and mm.loc['EcoConNOS','overall_selective_risk']<=.44 and beatmd>=5;outcome='A' if primary else 'B' if strong else 'C';final='EcoCon-NOS' if outcome=='A' else 'EcoCon-MD'
 novelty='EcoCon-NOS does not assume that one uncertainty score is universally optimal. It performs nested open-set validation using fine-grained attack types available within the known training distribution to select an uncertainty channel before encountering the outer unseen attack family.';lim='This does not guarantee selection of the optimal detector for arbitrary future zero-day attacks.';audit=[novelty,lim,'',f'PRIMARY SUCCESS: {primary}',f'STRONG ROBUSTNESS: {strong}',f'OUTCOME: {outcome}',f'FINAL METHOD: {final}',f'BEST-PAPER TARGET: {target}','',json.dumps(selections,indent=2),'',macro.to_string(index=False),'',fam.to_string(index=False),'','Outer unknown used for candidate design: NO','Outer unknown used for candidate selection: NO','Outer unknown used for threshold selection: NO','Outer test-known used for detector selection: NO','Outer calibration used for detector selection: NO','Outer calibration used for threshold calibration: YES','Inner pseudo-OOD generated only from outer training: YES','XGBoost retrained: NO','Feature budget changed: NO','Alpha changed: NO','VALIDATION: PASS'];(R/'ecocon_nos_method_audit.txt').write_text('\n'.join(audit)+'\n');config={'candidates':CANDS,'max_inner_folds':MAXINNER,'known_rejection_target':ALPHA,'max_reference_per_class':MAXCLASS,'max_global_reference':MAXGLOBAL,'n_neighbors':K,'bootstrap_resamples':1000,'bootstrap_seed':20260811};(R/'ecocon_nos_config.json').write_text(json.dumps(config,indent=2)+'\n');print(f'PRIMARY SUCCESS: {primary}\nFINAL METHOD: {final}\nVALIDATION: PASS',flush=True)
if __name__=='__main__':main()
