"""Step 6: closed-set XGBoost feature-budget experiment (no LOAFO/calibration)."""

from __future__ import annotations

import io
import json
import shutil
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, log_loss,
                             precision_recall_fscore_support)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parent.parent
TRAIN_PATH = ROOT / "processed" / "closed_set" / "train.parquet"
TEST_PATH = ROOT / "processed" / "closed_set" / "test.parquet"
MANIFEST_PATH = ROOT / "results" / "step5_internal_dev_manifest.parquet"
CLASS_MAPPING_PATH = ROOT / "results" / "class_mapping.json"
RESULTS = ROOT / "results"
MODEL_DIR = ROOT / "models" / "resource_budget"
PRED_DIR = RESULTS / "predictions" / "resource_budget"
SEED = 42
BUDGETS = [39, 30, 20, 15, 10, 5]
EPSILON = 0.005
DEV_REPS = 5
TEST_REPS = 10
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


def new_model(n_estimators: int = 2000, early_stopping: bool = True) -> XGBClassifier:
    return XGBClassifier(
        objective="multi:softprob", num_class=8, n_estimators=n_estimators,
        learning_rate=0.05, max_depth=8, subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", eval_metric="mlogloss", random_state=SEED, n_jobs=-1,
        early_stopping_rounds=100 if early_stopping else None,
    )


def validate_train(frame: pd.DataFrame, mapping: dict[str, int]) -> None:
    require(len(frame) == 428_477, "Official train row-count drift")
    require(len(FEATURES) == 39 and len(set(FEATURES)) == 39, "Expected 39 unique features")
    require(all(f in frame for f in FEATURES), "Feature schema mismatch")
    require(not (set(FEATURES) & METADATA), "Metadata included in feature list")
    require(mapping == {"Benign": 0, "BruteForce": 1, "DDoS": 2, "DoS": 3, "Mirai": 4, "Recon": 5, "Spoofing": 6, "Web": 7}, "Class mapping drift")
    require(set(frame.family) == set(mapping), "Official train family mismatch")
    require(np.isfinite(frame[FEATURES].to_numpy(dtype=np.float64, copy=False)).all(), "Nonfinite train feature")


def xy(frame: pd.DataFrame, features: list[str], mapping: dict[str, int]) -> tuple[pd.DataFrame, np.ndarray]:
    return frame[features].astype(np.float32, copy=True), frame.family.map(mapping).to_numpy(dtype=np.int32)


def calculate_metrics(y: np.ndarray, pred: np.ndarray, prob: np.ndarray) -> dict[str, float]:
    p, r, f, _ = precision_recall_fscore_support(y, pred, labels=np.arange(8), zero_division=0)
    _, _, wf, _ = precision_recall_fscore_support(y, pred, average="weighted", zero_division=0)
    return {"accuracy": accuracy_score(y, pred), "balanced_accuracy": balanced_accuracy_score(y, pred),
            "macro_precision": float(p.mean()), "macro_recall": float(r.mean()),
            "macro_f1": float(f.mean()), "weighted_f1": float(wf),
            "log_loss": log_loss(y, prob, labels=np.arange(8))}


def validate_probabilities(prob: np.ndarray, budget: int) -> None:
    require(prob.ndim == 2 and prob.shape[1] == 8, f"Budget {budget}: probability shape")
    require(np.isfinite(prob).all(), f"Budget {budget}: nonfinite probabilities")
    require(np.allclose(prob.sum(axis=1), 1.0, atol=1e-5), f"Budget {budget}: probability sums")


def per_class_rows(y: np.ndarray, pred: np.ndarray, budget: int, class_order: list[str]) -> list[dict]:
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=np.arange(8), zero_division=0)
    return [{"feature_count": budget, "family": class_order[i], "precision": p[i], "recall": r[i], "f1": f[i], "support": int(s[i])} for i in range(8)]


def benchmark(model: XGBClassifier, X: pd.DataFrame, repetitions: int) -> dict[str, float]:
    model.predict_proba(X.iloc[: min(4096, len(X))])
    elapsed = []
    for _ in range(repetitions):
        start = time.perf_counter(); model.predict_proba(X); elapsed.append(time.perf_counter() - start)
    median = float(np.median(elapsed))
    return {"median_total_inference_ms": median * 1000, "median_ms_per_sample": median * 1000 / len(X),
            "samples_per_second": len(X) / median}


def serialized_size(model: XGBClassifier) -> int:
    buffer = io.BytesIO(); joblib.dump(model, buffer, compress=3); return buffer.tell()


def fit_dev(X_train, y_train, X_dev, y_dev, weights) -> tuple[XGBClassifier, float]:
    model = new_model(); start = time.perf_counter()
    model.fit(X_train, y_train, sample_weight=weights, eval_set=[(X_dev, y_dev)], verbose=False)
    return model, time.perf_counter() - start


def create_ranking(model: XGBClassifier) -> pd.DataFrame:
    raw = model.get_booster().get_score(importance_type="gain")
    ranking = pd.DataFrame({"feature": FEATURES, "gain": [float(raw.get(f, 0.0)) for f in FEATURES]})
    ranking = ranking.sort_values(["gain", "feature"], ascending=[False, True], kind="stable").reset_index(drop=True)
    ranking.insert(0, "rank", np.arange(1, len(ranking) + 1))
    total = ranking.gain.sum(); ranking["normalized_gain"] = ranking.gain / total if total else 0.0
    require(len(ranking) == 39 and set(ranking.feature) == set(FEATURES), "Incomplete feature ranking")
    return ranking


def pareto_table(dev: pd.DataFrame, efficiency: pd.DataFrame) -> pd.DataFrame:
    table = dev[["feature_count", "macro_f1"]].merge(
        efficiency[["feature_count", "median_ms_per_sample", "model_size_mib"]], on="feature_count")
    efficient = []
    for a in table.itertuples(index=False):
        dominated = False
        for b in table.itertuples(index=False):
            if a.feature_count == b.feature_count:
                continue
            no_worse = (b.macro_f1 >= a.macro_f1 and b.feature_count <= a.feature_count and
                        b.median_ms_per_sample <= a.median_ms_per_sample and b.model_size_mib <= a.model_size_mib)
            strict = (b.macro_f1 > a.macro_f1 or b.feature_count < a.feature_count or
                      b.median_ms_per_sample < a.median_ms_per_sample or b.model_size_mib < a.model_size_mib)
            if no_worse and strict:
                dominated = True; break
        efficient.append(not dominated)
    table["pareto_efficient"] = efficient
    return table.sort_values("feature_count", ascending=False)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True); MODEL_DIR.mkdir(parents=True, exist_ok=True); PRED_DIR.mkdir(parents=True, exist_ok=True)
    mapping = json.loads(CLASS_MAPPING_PATH.read_text(encoding="utf-8")); class_order = [k for k, _ in sorted(mapping.items(), key=lambda item: item[1])]
    train = pd.read_parquet(TRAIN_PATH)
    validate_train(train, mapping)
    manifest = pd.read_parquet(MANIFEST_PATH)
    require(list(manifest.columns) == ["feature_hash", "family", "group_row_count", "internal_split"], "Step-5 manifest schema drift")
    require(manifest.feature_hash.is_unique and set(manifest.internal_split) == {"train", "dev"}, "Invalid Step-5 manifest")
    assigned = train.merge(manifest[["feature_hash", "internal_split"]], on="feature_hash", validate="many_to_one")
    internal_train = assigned.loc[assigned.internal_split == "train"].copy()
    internal_dev = assigned.loc[assigned.internal_split == "dev"].copy()
    require((len(internal_train), len(internal_dev)) == (364_204, 64_273), "Step-5 internal split was not exactly reused")
    require(not (set(internal_train.feature_hash) & set(internal_dev.feature_hash)), "Internal hash overlap")
    require(set(internal_train.family) == set(internal_dev.family) == set(class_order), "Internal family coverage")
    y_internal = internal_train.family.map(mapping).to_numpy(dtype=np.int32)
    y_dev = internal_dev.family.map(mapping).to_numpy(dtype=np.int32)
    internal_weights = compute_sample_weight("balanced", y_internal)

    print("[Ranking] training full-feature model...", flush=True)
    ranking_model, _ = fit_dev(internal_train[FEATURES].astype(np.float32), y_internal,
                               internal_dev[FEATURES].astype(np.float32), y_dev, internal_weights)
    ranking = create_ranking(ranking_model)
    ranking.to_csv(RESULTS / "feature_ranking_closed_set.csv", index=False, float_format="%.12g")
    del ranking_model
    ranked = ranking.feature.tolist()
    sets = {39: FEATURES.copy(), **{k: ranked[:k] for k in BUDGETS if k < 39}}
    for small, large in zip([5, 10, 15, 20, 30], [10, 15, 20, 30, 39]):
        require(set(sets[small]).issubset(sets[large]), f"Budgets {small}/{large} not nested")
    (RESULTS / "feature_budget_sets.json").write_text(json.dumps({str(k): sets[k] for k in BUDGETS}, indent=2) + "\n", encoding="utf-8")

    dev_rows, dev_pc_rows, dev_eff_rows, best_iterations = [], [], [], {}
    for budget in BUDGETS:
        print(f"[Budget {budget}] training...", flush=True)
        features = sets[budget]
        X_i, X_d = internal_train[features].astype(np.float32), internal_dev[features].astype(np.float32)
        model, seconds = fit_dev(X_i, y_internal, X_d, y_dev, internal_weights)
        prob = model.predict_proba(X_d); validate_probabilities(prob, budget); pred = np.argmax(prob, axis=1)
        require(np.isin(pred, np.arange(8)).all(), f"Budget {budget}: invalid prediction")
        best = int(model.best_iteration); best_iterations[budget] = best
        dev_rows.append({"feature_count": budget, **calculate_metrics(y_dev, pred, prob), "best_iteration": best})
        dev_pc_rows.extend(per_class_rows(y_dev, pred, budget, class_order))
        timing = benchmark(model, X_d, DEV_REPS); size = serialized_size(model)
        dev_eff_rows.append({"feature_count": budget, "training_seconds": seconds, **timing,
                             "model_size_bytes": size, "model_size_mib": size / 2**20})
        del model, X_i, X_d, prob
    dev = pd.DataFrame(dev_rows); dev_pc = pd.DataFrame(dev_pc_rows); dev_eff = pd.DataFrame(dev_eff_rows)
    dev.to_csv(RESULTS / "feature_budget_dev_metrics.csv", index=False, float_format="%.10f")
    dev_pc.to_csv(RESULTS / "feature_budget_dev_per_class.csv", index=False, float_format="%.10f")
    dev_eff.to_csv(RESULTS / "feature_budget_dev_efficiency.csv", index=False, float_format="%.10f")

    reference = float(dev.loc[dev.feature_count == 39, "macro_f1"].iloc[0]); threshold = reference - EPSILON
    eligible = sorted(dev.loc[dev.macro_f1 >= threshold, "feature_count"].astype(int).tolist())
    selected = min(eligible) if eligible else 39
    reason = (f"Budget {selected} is the smallest predeclared budget with internal-dev Macro-F1 >= "
              f"F1_39 - 0.005 ({threshold:.10f}); official test and calibration were not used.")
    selection = {"reference_budget": 39, "reference_dev_macro_f1": reference, "epsilon": EPSILON,
                 "eligibility_threshold": threshold,
                 "all_budget_dev_macro_f1": {str(int(r.feature_count)): float(r.macro_f1) for r in dev.itertuples()},
                 "eligible_budgets": eligible, "selected_budget": selected, "selected_features": sets[selected],
                 "selection_reason": reason, "test_loaded": False}
    selection_path = RESULTS / "feature_budget_selection.json"
    selection_path.write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
    frozen = json.loads(selection_path.read_text(encoding="utf-8"))
    require(frozen["selected_budget"] == selected and frozen["test_loaded"] is False, "Selection freeze verification failed")
    print(f"[Selection frozen] selected budget = {selected}", flush=True)
    pareto = pareto_table(dev, dev_eff); pareto.to_csv(RESULTS / "feature_budget_pareto.csv", index=False, float_format="%.10f")

    y_train = train.family.map(mapping).to_numpy(dtype=np.int32)
    official_weights = compute_sample_weight("balanced", y_train)
    final_models, final_seconds, metadata = {}, {}, {}
    for budget in BUDGETS:
        print(f"[Final budget {budget}] fitting official train...", flush=True)
        model = new_model(best_iterations[budget] + 1, early_stopping=False)
        X = train[sets[budget]].astype(np.float32); start = time.perf_counter(); model.fit(X, y_train, sample_weight=official_weights)
        final_seconds[budget] = time.perf_counter() - start
        path = MODEL_DIR / f"xgboost_{budget}_features.joblib"; joblib.dump(model, path, compress=3)
        size = path.stat().st_size
        metadata[str(budget)] = {"feature_count": budget, "feature_names": sets[budget], "best_iteration": best_iterations[budget],
                                 "final_estimators": best_iterations[budget] + 1, "training_rows": len(train),
                                 "class_order": class_order, "random_seed": SEED, "model_size": size}
        final_models[budget] = model
    shutil.copyfile(MODEL_DIR / f"xgboost_{selected}_features.joblib", MODEL_DIR / "selected_budget_model.joblib")
    (MODEL_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    # Official test remains unopened until ranking, development, selection, Pareto, and final fits are frozen.
    print("[Official test now unlocked]", flush=True)
    test = pd.read_parquet(TEST_PATH)
    require(len(test) == 91_819 and set(test.family) == set(class_order), "Official test validation failed")
    require(not (set(train.feature_hash) & set(test.feature_hash)), "Official train/test hash overlap")
    require(np.isfinite(test[FEATURES].to_numpy(dtype=np.float64, copy=False)).all(), "Nonfinite test feature")
    y_test = test.family.map(mapping).to_numpy(dtype=np.int32)
    test_rows, test_pc_rows, test_eff_rows = [], [], []
    for budget in BUDGETS:
        print(f"[Official test budget {budget}] evaluating...", flush=True)
        X = test[sets[budget]].astype(np.float32); model = final_models[budget]
        prob = model.predict_proba(X); validate_probabilities(prob, budget); pred = np.argmax(prob, axis=1)
        require(np.isin(pred, np.arange(8)).all(), f"Budget {budget}: invalid test predictions")
        test_rows.append({"feature_count": budget, **calculate_metrics(y_test, pred, prob)})
        test_pc_rows.extend(per_class_rows(y_test, pred, budget, class_order))
        timing = benchmark(model, X, TEST_REPS); path = MODEL_DIR / f"xgboost_{budget}_features.joblib"; size = path.stat().st_size
        test_eff_rows.append({"feature_count": budget, "final_training_seconds": final_seconds[budget], **timing,
                              "model_size_bytes": size, "model_size_mib": size / 2**20})
        prediction = pd.DataFrame({"feature_hash": test.feature_hash.to_numpy(), "true_family": test.family.to_numpy(),
                                   "predicted_family": np.array(class_order, dtype=object)[pred]})
        for i, family in enumerate(class_order): prediction[f"prob_{family}"] = prob[:, i]
        prediction.to_parquet(PRED_DIR / f"xgboost_{budget}_test.parquet", index=False)
    test_metrics = pd.DataFrame(test_rows); test_pc = pd.DataFrame(test_pc_rows); test_eff = pd.DataFrame(test_eff_rows)
    test_metrics.to_csv(RESULTS / "feature_budget_test_metrics.csv", index=False, float_format="%.10f")
    test_pc.to_csv(RESULTS / "feature_budget_test_per_class.csv", index=False, float_format="%.10f")
    test_eff.to_csv(RESULTS / "feature_budget_test_efficiency.csv", index=False, float_format="%.10f")

    combined = test_metrics.merge(test_eff, on="feature_count")
    full = combined.loc[combined.feature_count == 39].iloc[0]; chosen = combined.loc[combined.feature_count == selected].iloc[0]
    compare_metrics = ["feature_count", "macro_f1", "balanced_accuracy", "weighted_f1", "median_ms_per_sample",
                       "samples_per_second", "model_size_mib", "final_training_seconds"]
    comparison = []
    for metric in compare_metrics:
        fv, sv = float(full[metric]), float(chosen[metric])
        comparison.append({"metric": "training_seconds" if metric == "final_training_seconds" else metric,
                           "full_39": fv, "selected_budget": sv, "absolute_change": sv - fv,
                           "relative_change_percent": (sv - fv) / fv * 100 if fv else np.nan})
    comparison.append({"metric": "feature_reduction_percent", "full_39": 0.0,
                       "selected_budget": (39 - selected) / 39 * 100, "absolute_change": (39 - selected) / 39 * 100,
                       "relative_change_percent": np.nan})
    comparison_df = pd.DataFrame(comparison)
    comparison_df.to_csv(RESULTS / "selected_budget_vs_full.csv", index=False, float_format="%.10f")

    config = {"model": "xgboost", "random_seed": SEED, "feature_budgets": BUDGETS,
              "ranking_method": "xgboost_gain", "epsilon_macro_f1": EPSILON,
              "selection_rule": "smallest budget with dev Macro-F1 >= 39-feature dev Macro-F1 - 0.005",
              "class_weight_policy": "balanced sample weights computed from fitting labels only",
              "internal_split_reused_from_step5": True, "calibration_used": False, "loafo_used": False,
              "test_used_for_selection": False, "development_latency_repetitions": DEV_REPS,
              "test_latency_repetitions": TEST_REPS}
    (RESULTS / "step6_config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    pc_lookup = dev_pc.set_index(["feature_count", "family"])
    audit = ["FEATURE RANKING SOURCE: internal train only", "", "RANKED FEATURES: rank | feature | gain"]
    audit += [f"{r.rank} | {r.feature} | {r.gain}" for r in ranking.itertuples(index=False)]
    audit += ["", "DEVELOPMENT RESULTS"]
    for row in dev.merge(dev_eff, on="feature_count").itertuples(index=False):
        audit += [f"FEATURES: {row.feature_count}", f"best_iteration: {row.best_iteration}", f"macro_f1: {row.macro_f1}",
                  f"balanced_accuracy: {row.balanced_accuracy}", f"weighted_f1: {row.weighted_f1}",
                  f"BruteForce_f1: {pc_lookup.loc[(row.feature_count, 'BruteForce'), 'f1']}",
                  f"Web_f1: {pc_lookup.loc[(row.feature_count, 'Web'), 'f1']}", f"training_seconds: {row.training_seconds}",
                  f"median_ms_per_sample: {row.median_ms_per_sample}", f"model_size_mib: {row.model_size_mib}", ""]
    audit += [f"REFERENCE DEV MACRO-F1: {reference}", f"EPSILON: {EPSILON}", f"ELIGIBILITY THRESHOLD: {threshold}",
              f"ELIGIBLE BUDGETS: {eligible}", f"SELECTED BUDGET: {selected}", f"SELECTED FEATURES: {sets[selected]}",
              f"SELECTION REASON: {reason}", "", "TEST LOADED AFTER SELECTION: YES", "", "OFFICIAL TEST RESULTS"]
    for row in test_metrics.merge(test_eff, on="feature_count").itertuples(index=False):
        audit += [f"FEATURES: {row.feature_count}; accuracy={row.accuracy}; balanced_accuracy={row.balanced_accuracy}; "
                  f"macro_f1={row.macro_f1}; weighted_f1={row.weighted_f1}; log_loss={row.log_loss}; "
                  f"median_ms_per_sample={row.median_ms_per_sample}; model_size_mib={row.model_size_mib}"]
    audit += ["", "SELECTED VS FULL (computational-efficiency proxy; not energy consumption)", comparison_df.to_string(index=False), "",
              "LOAFO NOTE: This closed-set ranking MUST NOT be reused directly for LOAFO. Every Step-7 fold must learn its own ranking from that fold's TRAIN data only.", "",
              "CALIBRATION USED: NO", "TEST USED FOR FEATURE RANKING: NO", "TEST USED FOR BUDGET SELECTION: NO",
              "LOAFO PERFORMED: NO", "CONFORMAL PERFORMED: NO", "", "STEP 6 VALIDATION: PASS"]
    (RESULTS / "step6_resource_budget_audit.txt").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print("CALIBRATION USED: NO\nTEST USED FOR FEATURE RANKING: NO\nTEST USED FOR BUDGET SELECTION: NO\nLOAFO PERFORMED: NO\nCONFORMAL PERFORMED: NO\nSTEP 6 VALIDATION: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
