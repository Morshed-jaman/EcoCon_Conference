"""Step 7: leakage-safe fold-specific LOAFO models and raw uncertainty outputs."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             log_loss, precision_recall_fscore_support, roc_auc_score)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parent.parent
POOL_PATH = ROOT / "processed" / "modeling_pool.parquet"
MANIFEST_PATH = ROOT / "results" / "loafo_split_manifest.parquet"
COUNTS_PATH = ROOT / "results" / "loafo_fold_counts.csv"
MAPPING_PATH = ROOT / "results" / "class_mapping.json"
RESULTS = ROOT / "results"
MODEL_DIR = ROOT / "models" / "loafo"
PRED_DIR = RESULTS / "predictions" / "loafo"
FOLDS = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]
BUDGETS = [39, 30, 20, 15, 10, 5]
EPSILON = 0.005
BASE_SEED = 42
FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP",
    "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max",
    "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]
METADATA = {"fine_label", "family", "source_file", "source_folder", "source_row", "feature_hash"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def model_for(seed: int, classes: int, estimators: int = 2000, early: bool = True) -> XGBClassifier:
    return XGBClassifier(
        objective="multi:softprob", num_class=classes, n_estimators=estimators,
        learning_rate=0.05, max_depth=8, subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", eval_metric="mlogloss", random_state=seed, n_jobs=-1,
        early_stopping_rounds=100 if early else None,
    )


def stable_rng(seed: int, family: str) -> np.random.Generator:
    digest = hashlib.sha256(f"{seed}|{family}".encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "little"))


def make_internal_manifest(train: pd.DataFrame, held: str, seed: int) -> pd.DataFrame:
    groups = train.groupby("feature_hash", sort=False).agg(family=("family", "first"), group_row_count=("family", "size")).reset_index()
    require(train.groupby("feature_hash")["family"].nunique().max() == 1, f"{held}: conflicting hash")
    parts = []
    for family in sorted(train.family.unique()):
        g = groups.loc[groups.family == family].sort_values("feature_hash", kind="stable").reset_index(drop=True)
        g = g.iloc[stable_rng(seed, family).permutation(len(g))].reset_index(drop=True)
        total = int(g.group_row_count.sum()); targets = {"train": total * .85, "dev": total * .15}; counts = {"train": 0, "dev": 0}
        allocations = []
        for size in g.group_row_count.astype(int):
            split = max(["train", "dev"], key=lambda s: ((targets[s] - counts[s]) / targets[s], s == "train"))
            allocations.append(split); counts[split] += size
        g["internal_split"] = allocations; parts.append(g)
    result = pd.concat(parts, ignore_index=True)
    memberships = train[["feature_hash", "fine_label"]].drop_duplicates()
    for fine in sorted(train.fine_label.unique()):
        hashes = set(memberships.loc[memberships.fine_label == fine, "feature_hash"])
        for destination in ["train", "dev"]:
            if result.loc[result.feature_hash.isin(hashes) & result.internal_split.eq(destination)].empty:
                source = "dev" if destination == "train" else "train"
                candidates = result.loc[result.feature_hash.isin(hashes) & result.internal_split.eq(source)].sort_values(["group_row_count", "feature_hash"])
                require(not candidates.empty, f"{held}: cannot repair {fine} into {destination}")
                result.loc[result.feature_hash == candidates.iloc[0].feature_hash, "internal_split"] = destination
    result.insert(0, "held_out_family", held)
    return result[["held_out_family", "feature_hash", "family", "internal_split", "group_row_count"]].sort_values("feature_hash")


def metric_dict(y, pred, prob) -> dict[str, float]:
    p, r, f, _ = precision_recall_fscore_support(y, pred, labels=np.arange(prob.shape[1]), zero_division=0)
    _, _, wf, _ = precision_recall_fscore_support(y, pred, average="weighted", zero_division=0)
    return {"accuracy": accuracy_score(y, pred), "balanced_accuracy": balanced_accuracy_score(y, pred),
            "macro_precision": float(p.mean()), "macro_recall": float(r.mean()), "macro_f1": float(f.mean()),
            "weighted_f1": float(wf), "log_loss": log_loss(y, prob, labels=np.arange(prob.shape[1]))}


def ranking_from(model: XGBClassifier) -> pd.DataFrame:
    raw = model.get_booster().get_score(importance_type="gain")
    rank = pd.DataFrame({"feature": FEATURES, "gain": [float(raw.get(f, 0)) for f in FEATURES]})
    rank = rank.sort_values(["gain", "feature"], ascending=[False, True], kind="stable").reset_index(drop=True)
    rank.insert(0, "rank", np.arange(1, 40)); total = rank.gain.sum(); rank["normalized_gain"] = rank.gain / total if total else 0
    return rank


def check_prob(prob: np.ndarray, expected_classes: int, context: str) -> None:
    require(prob.shape[1] == expected_classes and np.isfinite(prob).all(), f"{context}: invalid probabilities")
    require(np.allclose(prob.sum(axis=1), 1, atol=1e-5), f"{context}: probability sum")


def probability_frame(frame: pd.DataFrame, prob: np.ndarray, known: list[str], held: str, split: str) -> pd.DataFrame:
    check_prob(prob, len(known), f"{held}/{split}")
    order = np.sort(prob, axis=1)
    maxp = order[:, -1]; margin = order[:, -1] - order[:, -2]
    entropy = -(prob * np.log(prob + 1e-12)).sum(axis=1)
    out = pd.DataFrame({"feature_hash": frame.feature_hash.to_numpy(), "true_family": frame.family.to_numpy(),
                        "fine_label": frame.fine_label.to_numpy(), "split": split, "held_out_family": held,
                        "predicted_family": np.array(known, dtype=object)[np.argmax(prob, axis=1)]})
    for i, family in enumerate(known): out[f"prob_{family}"] = prob[:, i]
    out["max_probability"] = maxp; out["prediction_entropy"] = entropy; out["probability_margin"] = margin
    return out


def benchmark(model, X: pd.DataFrame) -> float:
    model.predict_proba(X.iloc[:min(4096, len(X))]); times = []
    for _ in range(5):
        start = time.perf_counter(); model.predict_proba(X); times.append(time.perf_counter() - start)
    return float(np.median(times) * 1000 / len(X))


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True); MODEL_DIR.mkdir(parents=True, exist_ok=True); PRED_DIR.mkdir(parents=True, exist_ok=True)
    global_mapping = json.loads(MAPPING_PATH.read_text()); global_order = [k for k, v in sorted(global_mapping.items(), key=lambda x: x[1])]
    require(len(FEATURES) == 39 and not (set(FEATURES) & METADATA), "Feature contract failed")
    pool = pd.read_parquet(POOL_PATH)
    require(len(pool) == 612_115 and np.isfinite(pool[FEATURES].to_numpy(dtype=np.float64, copy=False)).all(), "Modeling pool validation failed")
    manifest = pd.read_parquet(MANIFEST_PATH)
    require(set(manifest.held_out_family) == set(FOLDS), "LOAFO fold manifest mismatch")
    require(COUNTS_PATH.is_file(), "LOAFO count audit missing")

    class_maps, internal_manifests, rankings, budget_rows, selections, frozen = {}, [], [], [], {}, {}
    fold_train_cache = {}
    for fold_index, held in enumerate(FOLDS):
        seed = BASE_SEED + fold_index; print(f"[LOAFO {held}]\nCreating internal split...", flush=True)
        known = [x for x in global_order if x != held]; local = {x: i for i, x in enumerate(known)}; class_maps[held] = local
        fm = manifest.loc[manifest.held_out_family == held]
        require(fm.feature_hash.is_unique, f"{held}: duplicate manifest hash")
        hash_sets = {s: set(fm.loc[fm.loafo_split == s, "feature_hash"]) for s in ["train", "calibration", "test_known", "test_unknown"]}
        for i, a in enumerate(hash_sets):
            for b in list(hash_sets)[i+1:]: require(not (hash_sets[a] & hash_sets[b]), f"{held}: {a}/{b} hash overlap")
        train = pool.loc[pool.feature_hash.isin(hash_sets["train"])].copy(); fold_train_cache[held] = train
        require(held not in set(train.family) and set(train.family) == set(known), f"{held}: train class leakage")
        im = make_internal_manifest(train, held, seed); internal_manifests.append(im)
        assigned = train.merge(im[["feature_hash", "internal_split"]], on="feature_hash", validate="many_to_one")
        itr, idev = assigned.loc[assigned.internal_split == "train"], assigned.loc[assigned.internal_split == "dev"]
        require(not (set(itr.feature_hash) & set(idev.feature_hash)), f"{held}: internal overlap")
        require(set(itr.family) == set(idev.family) == set(known), f"{held}: internal family coverage")
        ytr = itr.family.map(local).to_numpy(np.int32); yd = idev.family.map(local).to_numpy(np.int32)
        weights = compute_sample_weight("balanced", ytr)
        print("Ranking 39 features...", flush=True)
        ranking_model = model_for(seed, 7); ranking_model.fit(itr[FEATURES].astype(np.float32), ytr, sample_weight=weights,
                                                               eval_set=[(idev[FEATURES].astype(np.float32), yd)], verbose=False)
        rank = ranking_from(ranking_model); rank.insert(0, "held_out_family", held); rankings.append(rank); del ranking_model
        ranked_features = rank.feature.tolist(); sets = {39: FEATURES.copy(), **{b: ranked_features[:b] for b in BUDGETS if b < 39}}
        fold_results, fold_best = {}, {}
        for budget in BUDGETS:
            print(f"Budget {budget}...", flush=True); fs = sets[budget]; model = model_for(seed, 7)
            model.fit(itr[fs].astype(np.float32), ytr, sample_weight=weights, eval_set=[(idev[fs].astype(np.float32), yd)], verbose=False)
            prob = model.predict_proba(idev[fs].astype(np.float32)); check_prob(prob, 7, f"{held}/dev/{budget}")
            met = metric_dict(yd, np.argmax(prob, axis=1), prob); best = int(model.best_iteration)
            budget_rows.append({"held_out_family": held, "feature_count": budget, "macro_f1": met["macro_f1"],
                                "balanced_accuracy": met["balanced_accuracy"], "weighted_f1": met["weighted_f1"], "best_iteration": best})
            fold_results[budget] = met["macro_f1"]; fold_best[budget] = best; del model, prob
        reference = fold_results[39]; threshold = reference - EPSILON; eligible = sorted(b for b in BUDGETS if fold_results[b] >= threshold); selected = min(eligible)
        reason = f"Budget {selected} is the smallest budget with fold internal-dev Macro-F1 >= F1_39 - 0.005 ({threshold:.10f}); calibration and tests were not used."
        selections[held] = {"reference_dev_macro_f1": reference, "eligibility_threshold": threshold,
                            "budget_dev_macro_f1": {str(b): fold_results[b] for b in BUDGETS}, "eligible_budgets": eligible,
                            "selected_budget": selected, "selected_features": sets[selected], "selection_reason": reason}
        frozen[held] = {"held_out_family": held, "known_classes": known, "selected_budget": selected,
                        "selected_features": sets[selected], "best_iteration": fold_best[selected], "class_mapping": local,
                        "class_weights_policy": "balanced sample weights from fold fitting labels only", "random_seed": seed,
                        "train_rows": len(train), "internal_train_rows": len(itr), "internal_dev_rows": len(idev)}
        print(f"Selected budget = {selected}", flush=True)

    pd.concat(internal_manifests, ignore_index=True).to_parquet(RESULTS / "loafo_internal_dev_manifest.parquet", index=False)
    pd.concat(rankings, ignore_index=True).to_csv(RESULTS / "loafo_feature_rankings.csv", index=False, float_format="%.12g")
    pd.DataFrame(budget_rows).to_csv(RESULTS / "loafo_budget_dev_metrics.csv", index=False, float_format="%.10f")
    (RESULTS / "loafo_class_mappings.json").write_text(json.dumps(class_maps, indent=2) + "\n")
    (RESULTS / "loafo_budget_selection.json").write_text(json.dumps(selections, indent=2) + "\n")
    frozen_path = RESULTS / "loafo_frozen_fold_configs.json"; frozen_path.write_text(json.dumps(frozen, indent=2) + "\n")
    require(len(json.loads(frozen_path.read_text())) == 7, "Frozen fold configuration write failed")

    known_metrics, known_pc, unknown_summaries, forced_rows, auc_rows, efficiency, selected_rows, model_metadata = [], [], [], [], [], [], [], {}
    audit = []
    for held in FOLDS:
        print(f"[LOAFO {held}] Refitting final model...", flush=True)
        cfg = frozen[held]; known = cfg["known_classes"]; local = cfg["class_mapping"]; fs = cfg["selected_features"]
        fm = manifest.loc[manifest.held_out_family == held]
        hashes = {s: set(fm.loc[fm.loafo_split == s, "feature_hash"]) for s in ["train", "calibration", "test_known", "test_unknown"]}
        train = fold_train_cache.pop(held); ytr = train.family.map(local).to_numpy(np.int32); weights = compute_sample_weight("balanced", ytr)
        model = model_for(cfg["random_seed"], 7, cfg["best_iteration"] + 1, early=False)
        start = time.perf_counter(); model.fit(train[fs].astype(np.float32), ytr, sample_weight=weights); training_seconds = time.perf_counter() - start
        model_path = MODEL_DIR / f"holdout_{held}.joblib"; joblib.dump(model, model_path, compress=3); size_mib = model_path.stat().st_size / 2**20
        model_metadata[held] = {**cfg, "final_estimators": cfg["best_iteration"] + 1, "training_rows": len(train), "model_size_bytes": model_path.stat().st_size}

        # These three partitions are first materialized for model evaluation only after all fold decisions were frozen.
        calibration = pool.loc[pool.feature_hash.isin(hashes["calibration"])].copy()
        test_known = pool.loc[pool.feature_hash.isin(hashes["test_known"])].copy()
        test_unknown = pool.loc[pool.feature_hash.isin(hashes["test_unknown"])].copy()
        require(held not in set(calibration.family) | set(test_known.family) and set(test_unknown.family) == {held}, f"{held}: held-out partition leakage")
        print("Generating calibration probabilities...", flush=True)
        outputs = {}
        for split, frame in [("calibration", calibration), ("test_known", test_known), ("test_unknown", test_unknown)]:
            prob = model.predict_proba(frame[fs].astype(np.float32)); outputs[split] = probability_frame(frame, prob, known, held, split)
            folder = PRED_DIR / held; folder.mkdir(parents=True, exist_ok=True); outputs[split].to_parquet(folder / f"{split}.parquet", index=False)
        kt = outputs["test_known"]; yk = test_known.family.map(local).to_numpy(np.int32); pk = np.array([local[x] for x in kt.predicted_family], dtype=np.int32)
        known_prob = kt[[f"prob_{x}" for x in known]].to_numpy(); met = metric_dict(yk, pk, known_prob)
        known_metrics.append({"held_out_family": held, **met})
        p, r, f, s = precision_recall_fscore_support(yk, pk, labels=np.arange(7), zero_division=0)
        known_pc += [{"held_out_family": held, "family": known[i], "precision": p[i], "recall": r[i], "f1": f[i], "support": int(s[i])} for i in range(7)]
        unk = outputs["test_unknown"]; maxp = unk.max_probability.to_numpy(); entropy = unk.prediction_entropy.to_numpy()
        unknown_summaries.append({"held_out_family": held, "unknown_rows": len(unk), "mean_max_probability": maxp.mean(),
                                  "median_max_probability": np.median(maxp), "p90_max_probability": np.quantile(maxp, .90),
                                  "p95_max_probability": np.quantile(maxp, .95), "fraction_maxprob_ge_090": np.mean(maxp >= .90),
                                  "fraction_maxprob_ge_095": np.mean(maxp >= .95), "mean_entropy": entropy.mean(), "median_entropy": np.median(entropy)})
        forced = unk.predicted_family.value_counts().reindex(known, fill_value=0)
        forced_rows += [{"held_out_family": held, "predicted_known_family": family, "count": int(count), "percentage": count / len(unk) * 100} for family, count in forced.items()]
        labels = np.r_[np.zeros(len(kt), dtype=int), np.ones(len(unk), dtype=int)]
        score_pairs = {"MSP": np.r_[1-kt.max_probability, 1-unk.max_probability],
                       "entropy": np.r_[kt.prediction_entropy, unk.prediction_entropy],
                       "inverse_margin": np.r_[1-kt.probability_margin, 1-unk.probability_margin]}
        for score_name, scores in score_pairs.items():
            auc_rows.append({"held_out_family": held, "score": score_name, "auroc": roc_auc_score(labels, scores),
                             "auprc": average_precision_score(labels, scores), "known_count": len(kt), "unknown_count": len(unk)})
        latency = benchmark(model, test_known[fs].astype(np.float32))
        efficiency.append({"held_out_family": held, "selected_feature_count": len(fs), "training_seconds": training_seconds,
                           "median_test_known_ms_per_sample": latency, "model_size_mib": size_mib})
        selected_rows.append({"held_out_family": held, "selected_budget": len(fs), "known_class_count": 7, "train_rows": len(train),
                              "calibration_rows": len(calibration), "known_test_rows": len(test_known), "unknown_test_rows": len(test_unknown),
                              "known_test_macro_f1": met["macro_f1"], "known_test_balanced_accuracy": met["balanced_accuracy"], "model_size_mib": size_mib})
        rank = next(x for x in rankings if x.held_out_family.iloc[0] == held); sel = selections[held]
        fold_auc = pd.DataFrame(auc_rows); fold_auc = fold_auc.loc[fold_auc.held_out_family == held].set_index("score")
        us = unknown_summaries[-1]
        audit += [f"HELD OUT: {held}", f"TRAIN: {len(train)}", f"INTERNAL TRAIN: {cfg['internal_train_rows']}", f"INTERNAL DEV: {cfg['internal_dev_rows']}",
                  f"CALIBRATION: {len(calibration)}", f"KNOWN TEST: {len(test_known)}", f"UNKNOWN TEST: {len(test_unknown)}",
                  f"FEATURE RANKING top 10: {rank.feature.head(10).tolist()}", f"39-feature dev Macro-F1: {sel['reference_dev_macro_f1']}",
                  f"eligibility threshold: {sel['eligibility_threshold']}", f"selected budget: {len(fs)}", f"selected features: {fs}",
                  f"KNOWN TEST accuracy: {met['accuracy']}", f"KNOWN TEST balanced accuracy: {met['balanced_accuracy']}",
                  f"KNOWN TEST Macro-F1: {met['macro_f1']}", f"KNOWN TEST weighted F1: {met['weighted_f1']}",
                  f"UNKNOWN mean max probability: {us['mean_max_probability']}", f"UNKNOWN median max probability: {us['median_max_probability']}",
                  f"UNKNOWN fraction >= 0.90: {us['fraction_maxprob_ge_090']}", f"UNKNOWN fraction >= 0.95: {us['fraction_maxprob_ge_095']}",
                  *[f"RAW {score} AUROC/AUPRC: {fold_auc.loc[score,'auroc']} / {fold_auc.loc[score,'auprc']}" for score in ["MSP", "entropy", "inverse_margin"]],
                  "LEAKAGE CHECKS: all PASS", ""]
        print("Done.", flush=True)

    pd.DataFrame(known_metrics).to_csv(RESULTS / "loafo_known_test_metrics.csv", index=False, float_format="%.10f")
    pd.DataFrame(known_pc).to_csv(RESULTS / "loafo_known_test_per_class.csv", index=False, float_format="%.10f")
    pd.DataFrame(unknown_summaries).to_csv(RESULTS / "loafo_unknown_confidence_summary.csv", index=False, float_format="%.10f")
    pd.DataFrame(forced_rows).to_csv(RESULTS / "loafo_unknown_forced_predictions.csv", index=False, float_format="%.10f")
    pd.DataFrame(auc_rows).to_csv(RESULTS / "loafo_raw_uncertainty_auc.csv", index=False, float_format="%.10f")
    pd.DataFrame(efficiency).to_csv(RESULTS / "loafo_model_efficiency.csv", index=False, float_format="%.10f")
    pd.DataFrame(selected_rows).to_csv(RESULTS / "loafo_selected_models.csv", index=False, float_format="%.10f")
    (MODEL_DIR / "metadata.json").write_text(json.dumps(model_metadata, indent=2) + "\n")
    config = {"model": "xgboost", "feature_budgets": BUDGETS, "epsilon_macro_f1": EPSILON,
              "ranking": "fold_specific_xgboost_gain", "random_seed_base": BASE_SEED, "group_key": "feature_hash",
              "calibration_used_for_model_selection": False, "test_known_used_for_selection": False,
              "test_unknown_used_for_selection": False, "thresholding_performed": False, "conformal_performed": False}
    (RESULTS / "step7_config.json").write_text(json.dumps(config, indent=2) + "\n")
    audit += ["HELD-OUT FAMILY USED FOR RANKING: NO", "HELD-OUT FAMILY USED FOR BUDGET SELECTION: NO",
              "CALIBRATION USED FOR MODEL SELECTION: NO", "TEST_KNOWN USED FOR MODEL SELECTION: NO",
              "TEST_UNKNOWN USED FOR MODEL SELECTION: NO", "THRESHOLDING PERFORMED: NO", "CONFORMAL PERFORMED: NO", "", "STEP 7 VALIDATION: PASS"]
    (RESULTS / "step7_loafo_audit.txt").write_text("\n".join(audit) + "\n")
    print("STEP 7 VALIDATION: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
