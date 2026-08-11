"""Step 8: selective LOAFO evaluation with probability and EcoCon-MD scores."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from sklearn.covariance import LedoitWolf
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
POOL_PATH = ROOT / "processed" / "modeling_pool.parquet"
MANIFEST_PATH = RESULTS / "loafo_split_manifest.parquet"
STEP7_PRED = RESULTS / "predictions" / "loafo"
OUT_PRED = RESULTS / "predictions" / "ecocon_md"
DECISION_DIR = RESULTS / "predictions" / "step8"
LOAFO_MODELS = ROOT / "models" / "loafo"
MODEL_DIR = ROOT / "models" / "ecocon_md"
FOLDS = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]
ALPHAS = [0.01, 0.025, 0.05, 0.10, 0.15, 0.20]
PRIMARY_ALPHA = 0.05
METHODS = ["ForcedXGBoost", "MSP", "Entropy", "InverseMargin", "ProbabilityConformal", "EcoConMD"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()


def attach_features(pred: pd.DataFrame, feature_lookup: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    # Identical hashes have identical features; many-to-one preserves every prediction row without Cartesian duplication.
    out = pred.merge(feature_lookup[["feature_hash", *features]], on="feature_hash", how="left", validate="many_to_one")
    require(len(out) == len(pred) and out[features].notna().all().all(), "Feature-hash join failed")
    return out


def md_scores(X: np.ndarray, predicted: np.ndarray, means: dict[str, np.ndarray], precision: np.ndarray) -> np.ndarray:
    residual = np.empty_like(X, dtype=np.float64)
    for family in np.unique(predicted):
        mask = predicted == family; residual[mask] = X[mask] - means[str(family)]
    result = np.einsum("ij,jk,ik->i", residual, precision, residual, optimize=True)
    require(np.isfinite(result).all() and result.min() >= -1e-7, "Invalid squared Mahalanobis distance")
    return np.maximum(result, 0.0)


def pvalue_global(calibration: np.ndarray, scores: np.ndarray) -> np.ndarray:
    ordered = np.sort(calibration)
    ge = len(ordered) - np.searchsorted(ordered, scores, side="left")
    return (1.0 + ge) / (len(ordered) + 1.0)


def mondrian_pvalues(cal_md: np.ndarray, cal_pred: np.ndarray, scores: np.ndarray, pred: np.ndarray,
                     known: list[str]) -> tuple[np.ndarray, dict[str, dict]]:
    result = np.empty(len(scores), dtype=float); groups = {}
    for family in known:
        group = cal_md[cal_pred == family]; fallback = len(group) < 100
        target = cal_md if fallback else group; mask = pred == family
        result[mask] = pvalue_global(target, scores[mask])
        groups[family] = {"calibration_group_size": int(len(group)), "global_fallback": fallback}
    require(np.isfinite(result).all() and (result > 0).all() and (result <= 1).all(), "Invalid conformal p-values")
    return result, groups


def threshold(scores: np.ndarray, alpha: float) -> float:
    return float(np.quantile(scores, 1.0 - alpha, method="higher"))


def decisions_for(method: str, alpha: float, cal: pd.DataFrame, known: pd.DataFrame, unknown: pd.DataFrame):
    if method == "ForcedXGBoost":
        return np.zeros(len(cal), bool), np.zeros(len(known), bool), np.zeros(len(unknown), bool), np.nan
    if method in {"MSP", "Entropy", "InverseMargin"}:
        col = {"MSP": "score_msp", "Entropy": "score_entropy", "InverseMargin": "score_margin"}[method]
        t = threshold(cal[col].to_numpy(), alpha)
        return cal[col].to_numpy() >= t, known[col].to_numpy() >= t, unknown[col].to_numpy() >= t, t
    col = "p_prob" if method == "ProbabilityConformal" else "p_ecocon"
    return cal[col].to_numpy() <= alpha, known[col].to_numpy() <= alpha, unknown[col].to_numpy() <= alpha, alpha


def fold_metrics(held: str, method: str, alpha: float, cal: pd.DataFrame, known: pd.DataFrame, unknown: pd.DataFrame,
                 rc: np.ndarray, rk: np.ndarray, ru: np.ndarray) -> dict:
    known_correct = known.predicted_family.to_numpy() == known.true_family.to_numpy(); ak = ~rk; au = ~ru
    wrong_known_accepted = int((ak & ~known_correct).sum()); accepted_known = int(ak.sum()); accepted_unknown = int(au.sum())
    accepted_total = accepted_known + accepted_unknown; total = len(known) + len(unknown)
    return {"held_out_family": held, "method": method, "alpha": alpha,
            "calibration_rejection_rate": float(rc.mean()), "known_rejection_rate": float(rk.mean()),
            "known_acceptance_rate": float(ak.mean()),
            "known_accepted_accuracy": float(known_correct[ak].mean()) if accepted_known else np.nan,
            "known_selective_risk": wrong_known_accepted / accepted_known if accepted_known else np.nan,
            "UADR": float(ru.mean()), "unknown_acceptance_rate": float(au.mean()),
            "coverage": accepted_total / total, "review_rate": 1 - accepted_total / total,
            "overall_selective_risk": (wrong_known_accepted + accepted_unknown) / accepted_total if accepted_total else np.nan,
            "calibration_count": len(cal), "known_count": len(known), "unknown_count": len(unknown),
            "known_rejected_count": int(rk.sum()), "unknown_rejected_count": int(ru.sum()),
            "accepted_known_count": accepted_known, "accepted_unknown_count": accepted_unknown,
            "wrong_known_accepted_count": wrong_known_accepted}


def curve_points(held: str, method: str, known: pd.DataFrame, unknown: pd.DataFrame) -> list[dict]:
    if method == "ForcedXGBoost":
        anomaly_k = np.zeros(len(known)); anomaly_u = np.zeros(len(unknown))
    elif method == "MSP": anomaly_k, anomaly_u = known.score_msp.to_numpy(), unknown.score_msp.to_numpy()
    elif method == "Entropy": anomaly_k, anomaly_u = known.score_entropy.to_numpy(), unknown.score_entropy.to_numpy()
    elif method == "InverseMargin": anomaly_k, anomaly_u = known.score_margin.to_numpy(), unknown.score_margin.to_numpy()
    elif method == "ProbabilityConformal": anomaly_k, anomaly_u = 1-known.p_prob.to_numpy(), 1-unknown.p_prob.to_numpy()
    else: anomaly_k, anomaly_u = 1-known.p_ecocon.to_numpy(), 1-unknown.p_ecocon.to_numpy()
    combined = np.r_[anomaly_k, anomaly_u]
    thresholds = np.unique(np.r_[-np.inf, np.quantile(combined, np.linspace(0, 1, 201), method="linear"), np.inf])
    correct = known.predicted_family.to_numpy() == known.true_family.to_numpy(); rows=[]
    for t in thresholds:
        rk, ru = anomaly_k >= t, anomaly_u >= t; ak, au = ~rk, ~ru
        accepted = int(ak.sum()+au.sum()); wrong = int((ak & ~correct).sum()+au.sum())
        rows.append({"held_out_family": held, "method": method, "threshold": t,
                     "known_rejection_rate": float(rk.mean()), "UADR": float(ru.mean()),
                     "coverage": accepted/(len(known)+len(unknown)), "overall_selective_risk": wrong/accepted if accepted else 0.0})
    return rows


def decision_file(base: pd.DataFrame, held: str, method: str, score: np.ndarray, threshold_or_p: np.ndarray,
                  rejected: np.ndarray, is_unknown: bool) -> pd.DataFrame:
    correct = base.predicted_family.to_numpy() == base.true_family.to_numpy()
    return pd.DataFrame({"feature_hash": base.feature_hash.to_numpy(), "true_family": base.true_family.to_numpy(),
                         "predicted_family": base.predicted_family.to_numpy(), "is_unknown": is_unknown,
                         "score": score, "threshold_or_pvalue": threshold_or_p, "accepted": ~rejected,
                         "rejected": rejected, "correct_if_known": False if is_unknown else correct})


def main() -> int:
    MODEL_DIR.mkdir(parents=True, exist_ok=True); OUT_PRED.mkdir(parents=True, exist_ok=True); DECISION_DIR.mkdir(parents=True, exist_ok=True)
    criteria = {"frozen_before_unknown_scoring": True, "primary_alpha": PRIMARY_ALPHA,
                "primary_success": "EcoConMD macro overall selective risk lower than MSP and Entropy AND macro UADR higher than both",
                "secondary_success": "EcoConMD UADR exceeds both MSP and Entropy in at least 4 of 7 folds with comparable known rejection",
                "comparable_known_rejection_definition": "absolute macro known-rejection difference versus the mean of MSP and Entropy <= 0.02",
                "strong_success": "descriptive improvement for one or more of DDoS, DoS, Mirai"}
    criteria_path = RESULTS / "step8_success_criteria.json"; criteria_path.write_text(json.dumps(criteria, indent=2)+"\n")
    require(json.loads(criteria_path.read_text())["primary_alpha"] == PRIMARY_ALPHA, "Success criteria freeze failed")
    metadata = json.loads((LOAFO_MODELS/"metadata.json").read_text()); selections=json.loads((RESULTS/"loafo_budget_selection.json").read_text())
    manifest = pd.read_parquet(MANIFEST_PATH); pool = pd.read_parquet(POOL_PATH)
    all_features = list(dict.fromkeys(f for h in FOLDS for f in metadata[h]["selected_features"]))
    feature_lookup = pool[["feature_hash", *all_features]].drop_duplicates("feature_hash", keep="first")
    require(feature_lookup.feature_hash.is_unique, "Feature lookup not unique")
    before_hashes = {h: sha256(LOAFO_MODELS/f"holdout_{h}.joblib") for h in FOLDS}
    md_auc_rows=[]; metric_rows=[]; curve_rows=[]; fairness_rows=[]; rescue_rows=[]; dist_rows=[]; efficiency_rows=[]; md_metadata={}; group_log={}
    fold_counts={}
    for held in FOLDS:
        print(f"[Holdout {held}]\nLoading frozen model...\nFitting train-only Mahalanobis reference...", flush=True)
        cfg=metadata[held]; features=cfg["selected_features"]; known=cfg["known_classes"]
        require(features == selections[held]["selected_features"], f"{held}: frozen features changed")
        fm=manifest[manifest.held_out_family==held]; train_hashes=set(fm.loc[fm.loafo_split=="train","feature_hash"])
        train=pool[pool.feature_hash.isin(train_hashes)]; require(held not in set(train.family), f"{held}: held-out scaler leakage")
        scaler=StandardScaler().fit(train[features].to_numpy(np.float64)); Xtrain=scaler.transform(train[features].to_numpy(np.float64))
        means={c:Xtrain[train.family.to_numpy()==c].mean(axis=0) for c in known}
        residual=np.empty_like(Xtrain)
        for c in known:
            mask=train.family.to_numpy()==c; residual[mask]=Xtrain[mask]-means[c]
        lw=LedoitWolf(assume_centered=True).fit(residual); precision=lw.precision_
        require(np.isfinite(lw.covariance_).all() and np.isfinite(precision).all(), f"{held}: covariance failure")
        auxiliary={"held_out_family":held,"selected_features":features,"scaler":scaler,"class_means":means,
                   "shared_precision_matrix":precision,"known_classes":known,"covariance_shrinkage":float(lw.shrinkage_)}
        path=MODEL_DIR/f"holdout_{held}.joblib"; joblib.dump(auxiliary,path,compress=3)
        md_metadata[held]={"selected_features":features,"known_classes":known,"train_rows":len(train),"model_size_bytes":path.stat().st_size,
                           "covariance":"LedoitWolf_shared","distance_target":"xgboost_predicted_class","tiny_negative_clip_tolerance":1e-7}
        del Xtrain,residual,lw
        frames={}
        print("Generating calibration scores...\nGenerating test scores...", flush=True)
        for split in ["calibration","test_known","test_unknown"]:
            pred=pd.read_parquet(STEP7_PRED/held/f"{split}.parquet")
            joined=attach_features(pred,feature_lookup,features); X=scaler.transform(joined[features].to_numpy(np.float64))
            joined["mahalanobis_pred"]=md_scores(X,joined.predicted_family.to_numpy(),means,precision)
            joined["score_msp"]=1-joined.max_probability; joined["score_entropy"]=joined.prediction_entropy
            joined["score_margin"]=1-joined.probability_margin
            frames[split]=joined.drop(columns=features)
        cal,kt,ut=frames["calibration"],frames["test_known"],frames["test_unknown"]
        for frame in [cal,kt,ut]: frame["p_prob"]=pvalue_global(cal.score_msp.to_numpy(),frame.score_msp.to_numpy())
        for frame in [cal,kt,ut]:
            frame["p_ecocon"],groups=mondrian_pvalues(cal.mahalanobis_pred.to_numpy(),cal.predicted_family.to_numpy(),
                                                       frame.mahalanobis_pred.to_numpy(),frame.predicted_family.to_numpy(),known)
        group_log[held]=groups
        folder=OUT_PRED/held; folder.mkdir(parents=True,exist_ok=True)
        keep=["feature_hash","true_family","predicted_family","max_probability","prediction_entropy","probability_margin","mahalanobis_pred"]
        for split,frame in frames.items(): frame[keep].to_parquet(folder/f"{split}.parquet",index=False)
        labels=np.r_[np.zeros(len(kt),int),np.ones(len(ut),int)]; raw=np.r_[kt.mahalanobis_pred,ut.mahalanobis_pred]
        md_auc_rows.append({"held_out_family":held,"auroc":roc_auc_score(labels,raw),"auprc":average_precision_score(labels,raw),
                            "known_count":len(kt),"unknown_count":len(ut)})
        for split,frame in frames.items():
            x=frame.mahalanobis_pred.to_numpy()
            for stat,value in [("mean",x.mean()),("median",np.median(x)),("p25",np.quantile(x,.25)),("p75",np.quantile(x,.75)),
                               ("p90",np.quantile(x,.90)),("p95",np.quantile(x,.95))]:
                dist_rows.append({"held_out_family":held,"split":split,"statistic":stat,"value":value})
        for alpha in ALPHAS:
            print(f"Evaluating alpha={alpha}...",flush=True)
            for method in METHODS:
                rc,rk,ru,t=decisions_for(method,alpha,cal,kt,ut); metric_rows.append(fold_metrics(held,method,alpha,cal,kt,ut,rc,rk,ru))
                if alpha==PRIMARY_ALPHA and method!="ForcedXGBoost":
                    if method=="MSP": sk,su=kt.score_msp.to_numpy(),ut.score_msp.to_numpy(); vk=np.full(len(kt),t);vu=np.full(len(ut),t)
                    elif method=="Entropy": sk,su=kt.score_entropy.to_numpy(),ut.score_entropy.to_numpy();vk=np.full(len(kt),t);vu=np.full(len(ut),t)
                    elif method=="InverseMargin": sk,su=kt.score_margin.to_numpy(),ut.score_margin.to_numpy();vk=np.full(len(kt),t);vu=np.full(len(ut),t)
                    elif method=="ProbabilityConformal": sk,su=kt.score_msp.to_numpy(),ut.score_msp.to_numpy();vk=kt.p_prob.to_numpy();vu=ut.p_prob.to_numpy()
                    else: sk,su=kt.mahalanobis_pred.to_numpy(),ut.mahalanobis_pred.to_numpy();vk=kt.p_ecocon.to_numpy();vu=ut.p_ecocon.to_numpy()
                    d=pd.concat([decision_file(kt,held,method,sk,vk,rk,False),decision_file(ut,held,method,su,vu,ru,True)],ignore_index=True)
                    out=DECISION_DIR/held;out.mkdir(parents=True,exist_ok=True);d.to_parquet(out/f"{method}.parquet",index=False)
        _,rk_md,ru_md,_=decisions_for("EcoConMD",PRIMARY_ALPHA,cal,kt,ut)
        for family in known:
            mask=kt.true_family.to_numpy()==family; fairness_rows.append({"held_out_family":held,"known_true_family":family,
                                                                          "row_count":int(mask.sum()),"rejection_rate":float(rk_md[mask].mean())})
        high=ut.max_probability.to_numpy()>=.95
        rescue_rows.append({"held_out_family":held,"unknown_ge_095_count":int(high.sum()),"unknown_ge_095_percentage":high.mean()*100,
                            "ecocon_rejected_count":int((ru_md&high).sum()),"ecocon_rescue_rate":float(ru_md[high].mean()) if high.any() else np.nan})
        for method in METHODS: curve_rows.extend(curve_points(held,method,kt,ut))
        fold_counts[held]=(len(cal),len(kt),len(ut))
        # Identical known-test benchmark inputs; 10 repeats after warm-up.
        frozen=joblib.load(LOAFO_MODELS/f"holdout_{held}.joblib"); joined=attach_features(pd.read_parquet(STEP7_PRED/held/"test_known.parquet"),feature_lookup,features)
        Xraw=joined[features].to_numpy(np.float64); Xfloat=pd.DataFrame(Xraw.astype(np.float32),columns=features)
        frozen.predict_proba(Xfloat.iloc[:4096]); scaler.transform(Xraw[:4096]); Xwarm=scaler.transform(Xraw[:4096]); md_scores(Xwarm,joined.predicted_family.to_numpy()[:4096],means,precision)
        sorted_groups={c:np.sort(cal.loc[cal.predicted_family==c,"mahalanobis_pred"].to_numpy()) for c in known}
        timings={k:[] for k in ["xgb","scale","md","lookup","total"]}
        for _ in range(10):
            s=time.perf_counter(); frozen.predict_proba(Xfloat); timings["xgb"].append(time.perf_counter()-s)
            s=time.perf_counter(); Xs=scaler.transform(Xraw); timings["scale"].append(time.perf_counter()-s)
            s=time.perf_counter(); mds=md_scores(Xs,joined.predicted_family.to_numpy(),means,precision); timings["md"].append(time.perf_counter()-s)
            s=time.perf_counter(); mondrian_pvalues(cal.mahalanobis_pred.to_numpy(),cal.predicted_family.to_numpy(),mds,joined.predicted_family.to_numpy(),known); timings["lookup"].append(time.perf_counter()-s)
            s=time.perf_counter(); Xs=scaler.transform(Xraw); mds=md_scores(Xs,joined.predicted_family.to_numpy(),means,precision); mondrian_pvalues(cal.mahalanobis_pred.to_numpy(),cal.predicted_family.to_numpy(),mds,joined.predicted_family.to_numpy(),known); timings["total"].append(time.perf_counter()-s)
        n=len(joined); xgb=np.median(timings["xgb"])*1000/n; aux=np.median(timings["total"])*1000/n
        efficiency_rows.append({"held_out_family":held,"test_known_rows":n,"xgboost_ms_per_sample":xgb,
                                "scaler_ms_per_sample":np.median(timings["scale"])*1000/n,"mahalanobis_ms_per_sample":np.median(timings["md"])*1000/n,
                                "conformal_lookup_ms_per_sample":np.median(timings["lookup"])*1000/n,"ecocon_auxiliary_ms_per_sample":aux,
                                "combined_ms_per_sample":xgb+aux,"overhead_percentage":aux/xgb*100,"auxiliary_model_size_mib":path.stat().st_size/2**20})
        print("Done.",flush=True)
    require({h:sha256(LOAFO_MODELS/f"holdout_{h}.joblib") for h in FOLDS}==before_hashes,"Frozen XGBoost model changed")
    (MODEL_DIR/"metadata.json").write_text(json.dumps({"folds":md_metadata,"calibration_groups":group_log},indent=2)+"\n")
    metrics=pd.DataFrame(metric_rows); metrics.to_csv(RESULTS/"selective_metrics_by_fold.csv",index=False,float_format="%.10f")
    pd.DataFrame(md_auc_rows).to_csv(RESULTS/"ecocon_md_raw_auc.csv",index=False,float_format="%.10f")
    pd.DataFrame(fairness_rows).to_csv(RESULTS/"ecocon_known_family_rejection.csv",index=False,float_format="%.10f")
    pd.DataFrame(rescue_rows).to_csv(RESULTS/"overconfident_unknown_rescue.csv",index=False,float_format="%.10f")
    pd.DataFrame(dist_rows).to_csv(RESULTS/"mahalanobis_distribution_summary.csv",index=False,float_format="%.10f")
    pd.DataFrame(efficiency_rows).to_csv(RESULTS/"ecocon_efficiency.csv",index=False,float_format="%.10f")
    curves=pd.DataFrame(curve_rows); curves.to_csv(RESULTS/"risk_coverage_points.csv",index=False,float_format="%.10f")
    curves[["held_out_family","method","threshold","known_rejection_rate","UADR"]].to_csv(RESULTS/"uadr_vs_known_rejection.csv",index=False,float_format="%.10f")
    aurc=[]
    for (held,method),g in curves.groupby(["held_out_family","method"]):
        g=g.sort_values("coverage"); aurc.append({"held_out_family":held,"method":method,"AURC":np.trapezoid(g.overall_selective_risk,g.coverage)})
    pd.DataFrame(aurc).to_csv(RESULTS/"risk_coverage_auc.csv",index=False,float_format="%.10f")
    summaries=[]
    for (method,alpha),g in metrics.groupby(["method","alpha"]):
        summaries.append({"method":method,"alpha":alpha,"aggregation":"macro","mean_or_aggregate_known_rejection":g.known_rejection_rate.mean(),
                          "UADR":g.UADR.mean(),"coverage":g.coverage.mean(),"overall_selective_risk":g.overall_selective_risk.mean(),
                          "known_selective_risk":g.known_selective_risk.mean()})
        kr=g.known_rejected_count.sum()/g.known_count.sum(); ur=g.unknown_rejected_count.sum()/g.unknown_count.sum()
        ak=g.accepted_known_count.sum();au=g.accepted_unknown_count.sum();wrong=g.wrong_known_accepted_count.sum();total=g.known_count.sum()+g.unknown_count.sum()
        summaries.append({"method":method,"alpha":alpha,"aggregation":"micro","mean_or_aggregate_known_rejection":kr,"UADR":ur,
                          "coverage":(ak+au)/total,"overall_selective_risk":(wrong+au)/(ak+au),"known_selective_risk":wrong/ak})
    summary=pd.DataFrame(summaries);summary.to_csv(RESULTS/"selective_metrics_summary.csv",index=False,float_format="%.10f")
    primary=metrics[metrics.alpha==PRIMARY_ALPHA]; primary[["held_out_family","method","known_rejection_rate","UADR","coverage","overall_selective_risk","review_rate"]].to_csv(RESULTS/"step8_family_comparison.csv",index=False,float_format="%.10f")
    tests=[]
    for outcome in ["UADR","overall_selective_risk"]:
        pivot=primary.pivot(index="held_out_family",columns="method",values=outcome)
        for baseline in ["MSP","Entropy"]:
            diff=pivot.EcoConMD-pivot[baseline]
            try: stat,p=wilcoxon(pivot.EcoConMD,pivot[baseline],alternative="two-sided");note="n=7; interpret cautiously"
            except ValueError as e: stat,p=np.nan,np.nan;note=str(e)
            tests.append({"outcome":outcome,"comparison":f"EcoConMD vs {baseline}","median_paired_difference":np.median(diff),
                          "effect_direction":"EcoConMD higher" if np.median(diff)>0 else "EcoConMD lower" if np.median(diff)<0 else "tie",
                          "wilcoxon_statistic":stat,"p_value":p,"note":note})
    tests_df=pd.DataFrame(tests);tests_df.to_csv(RESULTS/"step8_statistical_tests.csv",index=False,float_format="%.10f")
    macro=summary[(summary.alpha==PRIMARY_ALPHA)&(summary.aggregation=="macro")].set_index("method")
    primary_success=(macro.loc["EcoConMD","overall_selective_risk"]<macro.loc["MSP","overall_selective_risk"] and
                     macro.loc["EcoConMD","overall_selective_risk"]<macro.loc["Entropy","overall_selective_risk"] and
                     macro.loc["EcoConMD","UADR"]>macro.loc["MSP","UADR"] and macro.loc["EcoConMD","UADR"]>macro.loc["Entropy","UADR"])
    piv=primary.pivot(index="held_out_family",columns="method",values="UADR"); wins=((piv.EcoConMD>piv.MSP)&(piv.EcoConMD>piv.Entropy)).sum()
    mdkr=primary[primary.method=="EcoConMD"].known_rejection_rate.mean(); basekr=primary[primary.method.isin(["MSP","Entropy"])].known_rejection_rate.mean()
    secondary_success=bool(wins>=4 and abs(mdkr-basekr)<=0.02)
    config={"methods":METHODS,"alpha_levels":ALPHAS,"primary_alpha":PRIMARY_ALPHA,"distance":"class_conditional_mahalanobis",
            "covariance":"LedoitWolf_shared","distance_target":"xgboost_predicted_class","conformal_calibration":"predicted_class_conditional",
            "feature_budgets":"frozen_from_step7","threshold_source":"calibration_only","empirical_quantile":"numpy method=higher; reject score >= threshold",
            "unknown_used_for_tuning":False,"test_known_used_for_tuning":False}
    (RESULTS/"step8_config.json").write_text(json.dumps(config,indent=2)+"\n")
    audit=["METHODS: "+", ".join(METHODS),"ALPHA LEVELS: "+str(ALPHAS),"PRIMARY ALPHA = 0.05",
           "Conformal limitation: calibration controls known-data false rejection only under relevant exchangeability assumptions; it does not guarantee unseen-family/OOD detection.",""]
    rawdf=pd.DataFrame(md_auc_rows); rescuedf=pd.DataFrame(rescue_rows); effdf=pd.DataFrame(efficiency_rows)
    for held in FOLDS:
        cfg=metadata[held];audit += [f"HELD OUT: {held}",f"SELECTED FEATURES: {len(cfg['selected_features'])}",
          f"CALIBRATION/KNOWN/UNKNOWN: {fold_counts[held][0]}/{fold_counts[held][1]}/{fold_counts[held][2]}",
          "RAW MD AUROC/AUPRC: "+str(rawdf.loc[rawdf.held_out_family==held,["auroc","auprc"]].iloc[0].to_dict())]
        for _,r in primary[primary.held_out_family==held].iterrows(): audit.append(f"{r.method}: known_rejection={r.known_rejection_rate}, UADR={r.UADR}, coverage={r.coverage}, overall_risk={r.overall_selective_risk}, known_risk={r.known_selective_risk}")
        audit += ["OVERCONFIDENT RESCUE: "+str(rescuedf[rescuedf.held_out_family==held].iloc[0].to_dict()),""]
    audit += ["MACRO SUMMARY",macro.to_string(),"","MICRO SUMMARY",summary[(summary.alpha==PRIMARY_ALPHA)&(summary.aggregation=="micro")].to_string(index=False),
              "","AURC SUMMARY",pd.DataFrame(aurc).to_string(index=False),"","STATISTICAL TESTS",tests_df.to_string(index=False),
              "","ECOCON COMPUTATIONAL OVERHEAD",effdf.to_string(index=False),"",f"PRIMARY SUCCESS = {'PASS' if primary_success else 'FAIL'}",
              f"SECONDARY SUCCESS = {'PASS' if secondary_success else 'FAIL'}",f"SECONDARY UADR WINS = {wins}/7",
              "STRONG SUCCESS = descriptive; see DDoS/DoS/Mirai fold results","","UNKNOWN DATA USED FOR THRESHOLD SELECTION: NO",
              "TEST-KNOWN USED FOR THRESHOLD SELECTION: NO","XGBOOST RETRAINED: NO","FEATURE RANKING CHANGED: NO","","STEP 8 VALIDATION: PASS"]
    (RESULTS/"step8_selective_audit.txt").write_text("\n".join(audit)+"\n")
    print(f"PRIMARY SUCCESS = {'PASS' if primary_success else 'FAIL'}\nSECONDARY SUCCESS = {'PASS' if secondary_success else 'FAIL'}\nSTEP 8 VALIDATION: PASS",flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
