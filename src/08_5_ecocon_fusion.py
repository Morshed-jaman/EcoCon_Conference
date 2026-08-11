"""Step 8.5: final frozen EcoCon-Fuse experiment and fresh-sample confirmation."""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
import joblib, numpy as np, pandas as pd
import pyarrow.parquet as pq
from scipy.stats import wilcoxon

ROOT=Path(__file__).resolve().parent.parent; R=ROOT/"results"; PROC=ROOT/"processed"; CSVROOT=ROOT/"CSV"
LP=R/"predictions"/"loafo"; MP=R/"predictions"/"ecocon_md"; OP=R/"predictions"/"step8_5"
LM=ROOT/"models"/"loafo"; MM=ROOT/"models"/"ecocon_md"; FM=ROOT/"models"/"ecocon_fuse"
FOLDS=["DDoS","DoS","Mirai","Recon","Spoofing","BruteForce","Web"]; ELIGIBLE=FOLDS[:5]
ALPHAS=[.01,.025,.05,.10,.15,.20]; PRIMARY=.05; MINREF=200
FEATURES=["Header_Length","Protocol Type","Time_To_Live","Rate","fin_flag_number","syn_flag_number","rst_flag_number","psh_flag_number","ack_flag_number","ece_flag_number","cwr_flag_number","ack_count","syn_count","fin_count","rst_count","HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC","TCP","UDP","DHCP","ARP","ICMP","IGMP","IPv","LLC","Tot sum","Min","Max","AVG","Std","Tot size","IAT","Number","Variance"]
def req(x,m):
 if not x: raise RuntimeError(m)
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def pv(ref,s):
 a=np.sort(np.asarray(ref)); return (1+len(a)-np.searchsorted(a,s,side='left'))/(len(a)+1)
def conditional(ref_scores,ref_pred,scores,pred,classes,minref=MINREF):
 out=np.empty(len(scores)); log={}
 for c in classes:
  g=ref_scores[ref_pred==c]; fallback=len(g)<minref; base=ref_scores if fallback else g; mask=pred==c; out[mask]=pv(base,scores[mask]);log[c]={"size":int(len(g)),"global_fallback":fallback}
 req(np.isfinite(out).all() and (out>0).all() and (out<=1).all(),"bad p-values");return out,log
def split_calibration(d,held,seed):
 g=d.groupby('feature_hash',sort=False).agg(true_family=('true_family','first'),predicted_family=('predicted_family','first'),group_row_count=('true_family','size')).reset_index();parts=[]
 for _,x in g.groupby(['predicted_family','true_family'],sort=True):
  x=x.sort_values('feature_hash').copy(); rng=np.random.default_rng(seed+int(hashlib.sha256(str(x.iloc[0][['predicted_family','true_family']].tolist()).encode()).hexdigest()[:8],16));x=x.iloc[rng.permutation(len(x))]
  target=.6*x.group_row_count.sum();cur=0;stage=[]
  for n in x.group_row_count: stage.append('CAL-A' if cur<target else 'CAL-B');cur+=n
  x['calibration_stage']=stage;parts.append(x)
 g=pd.concat(parts,ignore_index=True);g.insert(0,'held_out_family',held);return g
def load_scores(held,split):
 p=pd.read_parquet(LP/held/f'{split}.parquet');m=pd.read_parquet(MP/held/f'{split}.parquet')
 req(len(p)==len(m) and p.feature_hash.equals(m.feature_hash),f'{held}/{split} alignment')
 p['mahalanobis_pred']=m.mahalanobis_pred.to_numpy();return p
def build_refs(cal,manifest,classes):
 d=cal.merge(manifest[['feature_hash','calibration_stage']],on='feature_hash',validate='many_to_one');a=d[d.calibration_stage=='CAL-A'].copy();b=d[d.calibration_stage=='CAL-B'].copy()
 for x in [a,b]: req(len(x)>0,'empty calibration stage')
 for x in [a,b]:
  x['p_md'],mdlog=conditional(a.mahalanobis_pred.to_numpy(),a.predicted_family.to_numpy(),x.mahalanobis_pred.to_numpy(),x.predicted_family.to_numpy(),classes)
  x['p_ent'],entlog=conditional(a.prediction_entropy.to_numpy(),a.predicted_family.to_numpy(),x.prediction_entropy.to_numpy(),x.predicted_family.to_numpy(),classes)
  x['s_md']=-np.log(np.maximum(x.p_md,1e-12));x['s_ent']=-np.log(np.maximum(x.p_ent,1e-12));x['s_fuse']=np.maximum(x.s_md,x.s_ent)
 refs={"classes":classes,"cal_a_md":{},"cal_a_ent":{},"cal_b_md":{},"cal_b_ent":{},"cal_b_fuse":{},"global":{}}
 for c in classes:
  refs['cal_a_md'][c]=a.loc[a.predicted_family==c,'mahalanobis_pred'].to_numpy();refs['cal_a_ent'][c]=a.loc[a.predicted_family==c,'prediction_entropy'].to_numpy()
  refs['cal_b_md'][c]=b.loc[b.predicted_family==c,'s_md'].to_numpy();refs['cal_b_ent'][c]=b.loc[b.predicted_family==c,'s_ent'].to_numpy();refs['cal_b_fuse'][c]=b.loc[b.predicted_family==c,'s_fuse'].to_numpy()
 for k,col in [('cal_a_md','mahalanobis_pred'),('cal_a_ent','prediction_entropy'),('cal_b_md','s_md'),('cal_b_ent','s_ent'),('cal_b_fuse','s_fuse')]:refs['global'][k]=(a if k.startswith('cal_a') else b)[col].to_numpy()
 return a,b,refs,{"stage1_md":mdlog,"stage1_entropy":entlog}
def apply_refs(d,refs):
 classes=refs['classes'];pred=d.predicted_family.to_numpy();out=d.copy()
 def cp(key,vals):
  z=np.empty(len(vals))
  for c in classes:
   g=refs[key][c];base=refs['global'][key] if len(g)<MINREF else g;mask=pred==c;z[mask]=pv(base,vals[mask])
  return z
 out['p_md_stage1']=cp('cal_a_md',out.mahalanobis_pred.to_numpy());out['p_entropy_stage1']=cp('cal_a_ent',out.prediction_entropy.to_numpy())
 out['s_md']=-np.log(np.maximum(out.p_md_stage1,1e-12));out['s_ent']=-np.log(np.maximum(out.p_entropy_stage1,1e-12));out['fusion_score']=np.maximum(out.s_md,out.s_ent)
 out['p_nested_md']=cp('cal_b_md',out.s_md.to_numpy());out['p_nested_entropy']=cp('cal_b_ent',out.s_ent.to_numpy());out['p_fuse']=cp('cal_b_fuse',out.fusion_score.to_numpy())
 req(np.isfinite(out[['p_md_stage1','p_entropy_stage1','fusion_score','p_nested_md','p_nested_entropy','p_fuse']]).all().all(),"nonfinite fusion")
 return out
def component_arrays(md,entropy,pred,refs):
 classes=refs['classes']
 def cp(key,vals):
  z=np.empty(len(vals))
  for c in classes:
   g=refs[key][c];base=refs['global'][key] if len(g)<MINREF else g;mask=pred==c;z[mask]=pv(base,vals[mask])
  return z
 pmd=cp('cal_a_md',md);pent=cp('cal_a_ent',entropy);sf=np.maximum(-np.log(np.maximum(pmd,1e-12)),-np.log(np.maximum(pent,1e-12)));pf=cp('cal_b_fuse',sf)
 return pf
def met(held,method,alpha,k,u,pcol):
 rk=k[pcol].to_numpy()<=alpha;ru=u[pcol].to_numpy()<=alpha;correct=k.predicted_family.to_numpy()==k.true_family.to_numpy();ak=~rk;au=~ru;accepted=ak.sum()+au.sum();wrong=(ak&~correct).sum()+au.sum()
 return {"held_out_family":held,"method":method,"alpha":alpha,"known_rejection_rate":rk.mean(),"known_acceptance_rate":ak.mean(),"known_accepted_accuracy":correct[ak].mean(),"known_selective_risk":(~correct[ak]).mean(),"UADR":ru.mean(),"unknown_acceptance_rate":au.mean(),"coverage":accepted/(len(k)+len(u)),"review_rate":1-accepted/(len(k)+len(u)),"overall_selective_risk":wrong/accepted,"known_count":len(k),"unknown_count":len(u),"known_rejected":rk.sum(),"unknown_rejected":ru.sum(),"accepted_known":ak.sum(),"accepted_unknown":au.sum(),"wrong_known_accepted":int((ak&~correct).sum())}
def external_rows():
 x=pd.read_csv(R/'step8_family_comparison.csv');return x[(x.alpha if 'alpha' in x else pd.Series(PRIMARY,index=x.index))==PRIMARY] if 'alpha'in x else x
def md_score(X,pred,obj):
 Z=obj['scaler'].transform(X);means=obj['class_means'];P=obj['shared_precision_matrix'];res=np.empty_like(Z)
 for c in np.unique(pred):m=pred==c;res[m]=Z[m]-means[c]
 return np.maximum(np.einsum('ij,jk,ik->i',res,P,res,optimize=True),0)
def scan_fresh(old_hashes,mapping,counts,feature_dtypes):
 rng=np.random.default_rng(314159);rows=[];used=set(old_hashes)
 for fam in ELIGIBLE:
  print(f'[Fresh Confirmation] Scanning unused {fam} data...',flush=True);labels=sorted(mapping.loc[mapping.family==fam,'fine_label']);base=5000//len(labels);extra=5000%len(labels)
  for li,label in enumerate(labels):
   need=base+(li<extra);files=counts[counts.attack_folder==label].sample(frac=1,random_state=int(rng.integers(2**31-1)))
   reservoir=pd.DataFrame();seen=0
   for fr in files.itertuples():
    path=CSVROOT/Path(fr.relative_path);offset=0
    for chunk in pd.read_csv(path,chunksize=100000,encoding='utf-8-sig',on_bad_lines='skip'):
     n=len(chunk);num=chunk.reindex(columns=FEATURES).apply(pd.to_numeric,errors='coerce');valid=np.isfinite(num.to_numpy(float)).all(1);num=num.loc[valid].copy();src=np.arange(offset+1,offset+n+1)[valid];offset+=n
     if num.empty:continue
     num=num.astype(feature_dtypes);hs=pd.util.hash_pandas_object(num[FEATURES],index=False).astype('uint64');keep=~hs.isin(used);num=num.loc[keep].copy();hs=hs.loc[keep];src=src[keep.to_numpy()]
     if num.empty:continue
     num['feature_hash']=hs.to_numpy();num['source_row']=src;num=num.drop_duplicates('feature_hash');num['fine_label']=label;num['family']=fam;num['source_file']=fr.relative_path;num['_priority']=rng.random(len(num));reservoir=pd.concat([reservoir,num],ignore_index=True).sort_values('_priority').drop_duplicates('feature_hash').nsmallest(need,'_priority');seen+=len(num)
    if len(reservoir)>=need:break
   req(len(reservoir)>=need,f'fresh {fam}/{label} insufficient');used.update(reservoir.feature_hash.astype('uint64'));rows.append(reservoir)
  print(f'Selected 5000 unique fresh hashes for {fam}.',flush=True)
 out=pd.concat(rows,ignore_index=True).drop(columns='_priority');req(len(out)==25000 and out.feature_hash.is_unique,'fresh pool invalid');return out
def main():
 for p in [FM,OP]:p.mkdir(parents=True,exist_ok=True)
 freeze={"method_name":"EcoCon-Fuse","fusion_type":"nested_dual_view_conformal_max_nonconformity","signals":["class_conditional_mahalanobis","predictive_entropy"],"primary_alpha":PRIMARY,"alpha_levels":ALPHAS,"calibration_split_ratio":{"stage1":.60,"stage2":.40},"calibration_split_seed_base":420,"fusion_formula":"max(-log(p_md), -log(p_entropy))","equivalent_interpretation":"smallest of the two first-stage conformity p-values represents the strongest anomaly evidence","threshold_source":"known calibration only","unknown_used_for_tuning":False,"test_known_used_for_tuning":False,"xgboost_retrained":False,"feature_budget_changed":False}
 criteria={"primary":["macro fuse UADR > macro MD UADR","macro fuse UADR > macro entropy UADR","macro fuse risk <= macro MD risk","macro known rejection in [0.04,0.06]"],"robustness":"beats best existing UADR >=5/7 OR within 0.02 on >=6/7 with better macro UADR","overconfidence":"DDoS and Mirai rescue remains strong; assess DoS improvement"}
 (R/'step8_5_method_freeze.json').write_text(json.dumps(freeze,indent=2)+'\n');(R/'step8_5_success_criteria.json').write_text(json.dumps(criteria,indent=2)+'\n');print('[Freeze]\nMethod definition frozen.\nSuccess criteria frozen.',flush=True)
 before={str(p):digest(p) for root in [LM,MM] for p in root.glob('holdout_*.joblib')};meta=json.loads((LM/'metadata.json').read_text());manifests=[];rows=[];refs_all={};rescue=[];eff=[]
 external=pd.read_csv(R/'selective_metrics_by_fold.csv');external=external[(external.alpha==PRIMARY)&external.method.isin(['MSP','Entropy','EcoConMD'])].copy();ext=external
 for i,h in enumerate(FOLDS):
  print(f'[Holdout {h}]\nCreating CAL-A/CAL-B...',flush=True);cal=load_scores(h,'calibration');cm=split_calibration(cal,h,420+i);manifests.append(cm);classes=meta[h]['known_classes'];a,b,refs,logs=build_refs(cal,cm,classes);refs_all[h]=refs
  obj={"held_out_family":h,"refs":refs,"fallback_log":logs,"min_class_reference":MINREF,"calibration_seed":420+i};joblib.dump(obj,FM/f'holdout_{h}.joblib',compress=3)
  print('Computing MD conformity...\nComputing entropy conformity...\nBuilding fusion calibration...',flush=True);k=apply_refs(load_scores(h,'test_known'),refs);u=apply_refs(load_scores(h,'test_unknown'),refs)
  for alpha in ALPHAS:
   for method,col in [('NestedEntropy','p_nested_entropy'),('NestedMD','p_nested_md'),('EcoConFuse','p_fuse')]:rows.append(met(h,method,alpha,k,u,col))
  out=OP/h;out.mkdir(parents=True,exist_ok=True)
  for name,d,unk in [('test_known',k,False),('test_unknown',u,True)]:
   q=d[['feature_hash','true_family','predicted_family','max_probability','prediction_entropy','mahalanobis_pred','p_md_stage1','p_entropy_stage1','fusion_score','p_fuse']].copy();q=q.rename(columns={'prediction_entropy':'entropy'});q['accepted']=q.p_fuse>PRIMARY;q['rejected']=~q.accepted;q['is_unknown']=unk;q.to_parquet(out/f'{name}.parquet',index=False)
  high=u.max_probability>=.95;mdrate=float(ext[(ext.held_out_family==h)&(ext.method=='EcoConMD')].UADR.iloc[0]);frate=float((u.p_fuse<=PRIMARY)[high].mean());rescue.append({"held_out_family":h,"unknown_rows":len(u),"high_confidence_unknown_rows":int(high.sum()),"high_confidence_percentage":high.mean()*100,"EcoConMD_rescue_rate":float(pd.read_csv(R/'overconfident_unknown_rescue.csv').set_index('held_out_family').loc[h,'ecocon_rescue_rate']),"EcoConFuse_rescue_rate":frate,"absolute_rescue_improvement":frate-float(pd.read_csv(R/'overconfident_unknown_rescue.csv').set_index('held_out_family').loc[h,'ecocon_rescue_rate'])})
  # Lightweight lookup/fusion timing, 10 identical known-test repetitions.
  pred=k.predicted_family.to_numpy();mdvals=k.mahalanobis_pred.to_numpy();probcols=[c for c in k if c.startswith('prob_')];probs=k[probcols].to_numpy();component_arrays(mdvals[:4096],k.prediction_entropy.to_numpy()[:4096],pred[:4096],refs)
  ent_t=[];first_t=[];fuse_t=[];second_t=[]
  for _ in range(10):
   s=time.perf_counter();entropy=-(probs*np.log(probs+1e-12)).sum(1);ent_t.append(time.perf_counter()-s)
   s=time.perf_counter();pmd=np.empty(len(k));pent=np.empty(len(k))
   for c in refs['classes']:
    mask=pred==c
    for key,vals,outv in [('cal_a_md',mdvals,pmd),('cal_a_ent',entropy,pent)]:g=refs[key][c];outv[mask]=pv(refs['global'][key] if len(g)<MINREF else g,vals[mask])
   first_t.append(time.perf_counter()-s)
   s=time.perf_counter();sf=np.maximum(-np.log(np.maximum(pmd,1e-12)),-np.log(np.maximum(pent,1e-12)));fuse_t.append(time.perf_counter()-s)
   s=time.perf_counter();pf=np.empty(len(k))
   for c in refs['classes']:
    mask=pred==c;g=refs['cal_b_fuse'][c];pf[mask]=pv(refs['global']['cal_b_fuse'] if len(g)<MINREF else g,sf[mask])
   second_t.append(time.perf_counter()-s)
  n=len(k);entms=np.median(ent_t)*1000/n;firstms=np.median(first_t)*1000/n;fusems=np.median(fuse_t)*1000/n;secondms=np.median(second_t)*1000/n;extra=entms+firstms+fusems+secondms
  oldeff=pd.read_csv(R/'ecocon_efficiency.csv').set_index('held_out_family').loc[h];base=float(oldeff.xgboost_ms_per_sample);mdcomb=float(oldeff.combined_ms_per_sample);mdcore=float(oldeff.scaler_ms_per_sample+oldeff.mahalanobis_ms_per_sample);totalaux=mdcore+extra;combined_time=base+totalaux
  eff.append({"held_out_family":h,"xgboost_ms_per_sample":base,"ecocon_md_combined_ms_per_sample":mdcomb,"entropy_ms_per_sample":entms,"first_stage_lookup_ms_per_sample":firstms,"fusion_ms_per_sample":fusems,"second_stage_lookup_ms_per_sample":secondms,"ecocon_fuse_auxiliary_ms_per_sample":totalaux,"ecocon_fuse_combined_ms_per_sample":combined_time,"overhead_vs_xgboost_percent":totalaux/base*100,"additional_overhead_vs_ecocon_md_percent":(combined_time/mdcomb-1)*100})
  print('Evaluating known test...\nEvaluating unknown test...\nDone.',flush=True)
 pd.concat(manifests,ignore_index=True).to_parquet(R/'step8_5_calibration_manifest.parquet',index=False);new=pd.DataFrame(rows);new.to_csv(R/'step8_5_selective_by_fold.csv',index=False,float_format='%.10f');pd.DataFrame(rescue).to_csv(R/'step8_5_overconfident_rescue.csv',index=False,float_format='%.10f');pd.DataFrame(eff).to_csv(R/'step8_5_efficiency.csv',index=False,float_format='%.10f');(FM/'metadata.json').write_text(json.dumps({h:{"file":f'holdout_{h}.joblib'} for h in FOLDS},indent=2)+'\n')
 # Combine new alpha=.05 with frozen Step-8 external methods.
 n05=new[new.alpha==PRIMARY];e05=external[external.method.isin(['MSP','Entropy','EcoConMD'])].copy();e05['alpha']=PRIMARY
 combined=pd.concat([n05,e05],ignore_index=True,sort=False);mac=[];mic=[]
 for method,g in combined.groupby('method'):
  mac.append({"method":method,"known_rejection_rate":g.known_rejection_rate.mean(),"UADR":g.UADR.mean(),"coverage":g.coverage.mean(),"review_rate":g.review_rate.mean(),"overall_selective_risk":g.overall_selective_risk.mean(),"known_selective_risk":g.known_selective_risk.mean() if 'known_selective_risk'in g else np.nan})
  if method in n05.method.unique():
   kr=g.known_rejected.sum()/g.known_count.sum();ur=g.unknown_rejected.sum()/g.unknown_count.sum();ak=g.accepted_known.sum();au=g.accepted_unknown.sum();w=g.wrong_known_accepted.sum();cov=(ak+au)/(g.known_count.sum()+g.unknown_count.sum());mic.append({"method":method,"known_rejection_rate":kr,"UADR":ur,"coverage":cov,"review_rate":1-cov,"overall_selective_risk":(w+au)/(ak+au),"known_selective_risk":w/ak})
  else:
   old=pd.read_csv(R/'selective_metrics_summary.csv');q=old[(old.method==method)&(old.alpha==PRIMARY)&(old.aggregation=='micro')].iloc[0];mic.append({"method":method,"known_rejection_rate":q.mean_or_aggregate_known_rejection,"UADR":q.UADR,"coverage":q.coverage,"review_rate":1-q.coverage,"overall_selective_risk":q.overall_selective_risk,"known_selective_risk":q.known_selective_risk})
 macro=pd.DataFrame(mac);micro=pd.DataFrame(mic);macro.to_csv(R/'step8_5_macro_summary.csv',index=False,float_format='%.10f');micro.to_csv(R/'step8_5_micro_summary.csv',index=False,float_format='%.10f')
 piv=combined.pivot(index='held_out_family',columns='method',values='UADR');fam=pd.DataFrame({"held_out_family":piv.index,"MSP":piv.MSP,"Entropy":piv.Entropy,"EcoConMD":piv.EcoConMD,"EcoConFuse":piv.EcoConFuse});fam['best_existing_uadr']=fam[['MSP','Entropy','EcoConMD']].max(axis=1);fam['fusion_regret']=fam.EcoConFuse-fam.best_existing_uadr;fam['best_method']=fam[['MSP','Entropy','EcoConMD','EcoConFuse']].idxmax(axis=1);fam.to_csv(R/'step8_5_family_comparison.csv',index=False,float_format='%.10f')
 # Alpha-point curves and AURC.
 curves=new[['held_out_family','method','alpha','coverage','overall_selective_risk','known_rejection_rate','UADR']];curves[['held_out_family','method','alpha','coverage','overall_selective_risk']].to_csv(R/'step8_5_risk_coverage.csv',index=False,float_format='%.10f');curves[['held_out_family','method','alpha','known_rejection_rate','UADR']].to_csv(R/'step8_5_uadr_vs_known_rejection.csv',index=False,float_format='%.10f');aur=[]
 for (h,m),g in curves.groupby(['held_out_family','method']):g=g.sort_values('coverage');aur.append({"held_out_family":h,"method":m,"AURC":np.trapezoid(g.overall_selective_risk,g.coverage)})
 pd.DataFrame(aur).to_csv(R/'step8_5_aurc.csv',index=False,float_format='%.10f')
 stats=[]
 for outcome in ['UADR','overall_selective_risk']:
  q=combined.pivot(index='held_out_family',columns='method',values=outcome)
  for base in ['EcoConMD','Entropy','MSP']:
   diff=q.EcoConFuse-q[base];st,p=wilcoxon(q.EcoConFuse,q[base]);winmask=diff>0 if outcome=='UADR' else diff<0;losemask=diff<0 if outcome=='UADR' else diff>0;stats.append({"outcome":outcome,"comparison":f'EcoConFuse vs {base}',"median_paired_difference":np.median(diff),"mean_paired_difference":diff.mean(),"wins":int(winmask.sum()),"losses":int(losemask.sum()),"ties":int((diff==0).sum()),"wilcoxon_statistic":st,"p_value":p})
 pd.DataFrame(stats).to_csv(R/'step8_5_statistics.csv',index=False,float_format='%.10f')
 # Fresh subtype-aware reservoir sampling from randomly ordered raw files.
 schema=pq.read_schema(PROC/'research_pool.parquet');feature_dtypes={f:('int64' if str(schema.field(f).type).startswith('int') else 'float64') for f in FEATURES};pool=pd.read_parquet(PROC/'research_pool.parquet',columns=['feature_hash']);old=set(pool.feature_hash.astype('uint64'));mapping=pd.read_csv(R/'attack_family_mapping.csv');counts=pd.read_csv(R/'file_record_counts.csv');fresh=scan_fresh(old,mapping,counts,feature_dtypes);fresh=fresh[FEATURES+['fine_label','family','source_file','source_row','feature_hash']];fresh.to_parquet(PROC/'fresh_confirmation_unknown.parquet',index=False)
 fresh_rows=[]
 for h in ELIGIBLE:
  d=fresh[fresh.family==h];model=joblib.load(LM/f'holdout_{h}.joblib');mdobj=joblib.load(MM/f'holdout_{h}.joblib');refs=refs_all[h];fs=meta[h]['selected_features'];pro=model.predict_proba(d[fs].astype(np.float32));pred=np.array(meta[h]['known_classes'])[pro.argmax(1)];ent=-(pro*np.log(pro+1e-12)).sum(1);maxp=pro.max(1);md=md_score(d[fs].to_numpy(float),pred,mdobj);z=pd.DataFrame({'predicted_family':pred,'prediction_entropy':ent,'mahalanobis_pred':md,'max_probability':maxp});z=apply_refs(z,refs)
  cal=load_scores(h,'calibration');msp_t=np.quantile(1-cal.max_probability,1-PRIMARY,method='higher');ent_t=np.quantile(cal.prediction_entropy,1-PRIMARY,method='higher');mdp,_=conditional(cal.mahalanobis_pred.to_numpy(),cal.predicted_family.to_numpy(),md,pred,meta[h]['known_classes'],100)
  high=maxp>=.95;fresh_rows.append({"held_out_family":h,"fresh_rows":len(z),"MSP_UADR":np.mean(1-maxp>=msp_t),"Entropy_UADR":np.mean(ent>=ent_t),"EcoConMD_UADR":np.mean(mdp<=PRIMARY),"EcoConFuse_UADR":np.mean(z.p_fuse<=PRIMARY),"fraction_maxprob_ge_095":high.mean(),"EcoConFuse_rescue_rate_ge_095":np.mean((z.p_fuse<=PRIMARY)[high])})
 pd.DataFrame(fresh_rows).to_csv(R/'step8_5_fresh_confirmation.csv',index=False,float_format='%.10f')
 req(not(set(fresh.feature_hash.astype('uint64'))&old),'fresh overlap');req({str(p):digest(p) for root in [LM,MM] for p in root.glob('holdout_*.joblib')}==before,'frozen model changed')
 mm=macro.set_index('method');primary=(mm.loc['EcoConFuse','UADR']>mm.loc['EcoConMD','UADR'] and mm.loc['EcoConFuse','UADR']>mm.loc['Entropy','UADR'] and mm.loc['EcoConFuse','overall_selective_risk']<=mm.loc['EcoConMD','overall_selective_risk'] and .04<=mm.loc['EcoConFuse','known_rejection_rate']<=.06)
 within=(fam.fusion_regret>=-.02).sum();beats_all=(fam.fusion_regret>0).sum();robust=beats_all>=5 or (within>=6 and mm.loc['EcoConFuse','UADR']>max(mm.loc['EcoConMD','UADR'],mm.loc['Entropy','UADR']));outcome='OUTCOME A — STRONG IMPROVEMENT' if primary and robust else 'OUTCOME B — PARTIAL IMPROVEMENT' if primary else 'OUTCOME C — NO IMPROVEMENT';decision='EcoCon-Fuse' if outcome.startswith('OUTCOME A') else 'EcoCon-MD'
 # Final comparison includes frozen Step-8 references.
 oldsum=pd.read_csv(R/'selective_metrics_summary.csv');base=oldsum[(oldsum.alpha==PRIMARY)&(oldsum.aggregation=='macro')&oldsum.method.isin(['ForcedXGBoost','MSP','Entropy','ProbabilityConformal','EcoConMD'])].copy();base=base.rename(columns={'mean_or_aggregate_known_rejection':'macro_known_rejection','UADR':'macro_UADR','coverage':'macro_coverage','overall_selective_risk':'macro_overall_selective_risk','known_selective_risk':'macro_known_selective_risk'});base['macro_review_rate']=1-base.macro_coverage
 fuse=macro[macro.method=='EcoConFuse'].rename(columns={'known_rejection_rate':'macro_known_rejection','UADR':'macro_UADR','coverage':'macro_coverage','review_rate':'macro_review_rate','overall_selective_risk':'macro_overall_selective_risk','known_selective_risk':'macro_known_selective_risk'});final=pd.concat([base[['method','macro_known_rejection','macro_UADR','macro_coverage','macro_review_rate','macro_overall_selective_risk','macro_known_selective_risk']],fuse],ignore_index=True);final['mean_auxiliary_overhead_percent']=final.method.map({'EcoConMD':pd.read_csv(R/'ecocon_efficiency.csv').overhead_percentage.mean(),'EcoConFuse':pd.DataFrame(eff).overhead_vs_xgboost_percent.mean()}).fillna(0);rank=piv[['MSP','Entropy','EcoConMD','EcoConFuse']].rank(axis=1,ascending=False,method='min');final['folds_best_UADR']=final.method.map((rank==1).sum()).fillna(0).astype(int);final['folds_second_best_UADR']=final.method.map((rank==2).sum()).fillna(0).astype(int);final.to_csv(R/'step8_5_final_comparison.csv',index=False,float_format='%.10f')
 config={**freeze,"min_class_reference":MINREF,"fresh_seed":314159,"fresh_target_per_family":5000};(R/'step8_5_config.json').write_text(json.dumps(config,indent=2)+'\n')
 note='EcoCon-Fuse was developed after observing that predictive uncertainty and Mahalanobis atypicality exhibited complementary family-level failure modes. Consequently, the original seven-fold fusion evaluation should be interpreted as a final methodological enhancement rather than a fully independent confirmatory experiment. A separate fresh-sample CICIoT2023 confirmation was therefore added where unused raw samples were available.'
 audit=[note,'',f'PRIMARY SUCCESS: {"PASS" if primary else "FAIL"}',f'ROBUSTNESS SUCCESS: {"PASS" if robust else "FAIL"}',f'FINAL OUTCOME: {outcome}',f'FINAL METHOD: {decision}',f'FUSION BEATS ALL: {beats_all}/7',f'WITHIN 0.02 OF BEST: {within}/7','MACRO SUMMARY',macro.to_string(index=False),'MICRO SUMMARY',micro.to_string(index=False),'FAMILY COMPARISON',fam.to_string(index=False),'OVERCONFIDENT RESCUE',pd.DataFrame(rescue).to_string(index=False),'AURC',pd.DataFrame(aur).to_string(index=False),'STATISTICAL TESTS',pd.DataFrame(stats).to_string(index=False),'EFFICIENCY',pd.DataFrame(eff).to_string(index=False),'FRESH CONFIRMATION',pd.DataFrame(fresh_rows).to_string(index=False),'','UNKNOWN USED FOR TRAINING: NO','UNKNOWN USED FOR CALIBRATION: NO','UNKNOWN USED FOR FUSION WEIGHTING: NO','TEST-KNOWN USED FOR CALIBRATION: NO','XGBOOST RETRAINED: NO','FEATURE BUDGET CHANGED: NO','ALPHA CHANGED: NO','STEP 8.5 VALIDATION: PASS'];(R/'step8_5_final_audit.txt').write_text('\n'.join(audit)+'\n')
 print(f'PRIMARY SUCCESS: {"PASS" if primary else "FAIL"}\n{outcome}\nFINAL METHOD: {decision}\nSTEP 8.5 VALIDATION: PASS',flush=True)
if __name__=='__main__':main()
