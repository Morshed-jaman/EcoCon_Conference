"""Step 5: train and audit three all-feature closed-set baselines only."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import psutil
import pyarrow
import sklearn
import xgboost
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                             log_loss, precision_recall_fscore_support)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parent.parent
TRAIN_PATH = ROOT / "processed" / "closed_set" / "train.parquet"
TEST_PATH = ROOT / "processed" / "closed_set" / "test.parquet"
RESULTS = ROOT / "results"
MODELS = ROOT / "models" / "baselines"
PREDICTIONS = RESULTS / "predictions"
SEED = 42
DEV_RATIO = 0.15
LATENCY_DEV_REPS = 5
LATENCY_TEST_REPS = 10
CLASS_ORDER = ["Benign", "BruteForce", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web"]
CLASS_TO_ID = {name: i for i, name in enumerate(CLASS_ORDER)}
FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP",
    "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max",
    "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]
METADATA = ["fine_label", "family", "source_file", "source_folder", "source_row", "feature_hash"]
MODEL_KEYS = ["random_forest", "xgboost", "lightgbm"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_frame(frame: pd.DataFrame, expected_rows: int, label: str) -> None:
    require(len(frame) == expected_rows, f"{label} rows {len(frame)} != {expected_rows}")
    require(len(FEATURES) == 39 and all(c in frame for c in FEATURES), f"{label}: feature schema mismatch")
    require(all(c in frame for c in METADATA), f"{label}: metadata schema mismatch")
    require(set(frame["family"]) == set(CLASS_ORDER), f"{label}: not all fixed classes present")
    require(np.isfinite(frame[FEATURES].to_numpy(dtype=np.float64, copy=False)).all(), f"{label}: nonfinite features")


def family_rng(family: str) -> np.random.Generator:
    digest = hashlib.sha256(f"{SEED}|step5|{family}".encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "little"))


def internal_manifest(train: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    groups = train.groupby("feature_hash", sort=False).agg(
        family=("family", "first"), group_row_count=("family", "size")
    ).reset_index()
    require(train.groupby("feature_hash")["family"].nunique().max() == 1, "Official train contains conflicting hash labels")
    pieces = []
    for family in CLASS_ORDER:
        g = groups.loc[groups.family == family].sort_values("feature_hash", kind="stable").reset_index(drop=True)
        g = g.iloc[family_rng(family).permutation(len(g))].reset_index(drop=True)
        total = int(g.group_row_count.sum())
        targets = {"train": (1 - DEV_RATIO) * total, "dev": DEV_RATIO * total}
        counts = {"train": 0, "dev": 0}
        assignments = []
        for size in g.group_row_count.astype(int):
            split = max(["train", "dev"], key=lambda s: ((targets[s] - counts[s]) / targets[s], s == "train"))
            assignments.append(split)
            counts[split] += size
        g["internal_split"] = assignments
        pieces.append(g)
    manifest = pd.concat(pieces, ignore_index=True)
    memberships = train[["feature_hash", "fine_label"]].drop_duplicates()
    repairs = []
    coverage = memberships.merge(manifest[["feature_hash", "internal_split"]], on="feature_hash")
    present = coverage.groupby(["fine_label", "internal_split"]).size()
    for fine_label in sorted(train.fine_label.unique()):
        for destination in ["train", "dev"]:
            if present.get((fine_label, destination), 0):
                continue
            source = "dev" if destination == "train" else "train"
            candidate_hashes = memberships.loc[memberships.fine_label == fine_label, "feature_hash"]
            candidates = manifest.loc[manifest.feature_hash.isin(candidate_hashes) & manifest.internal_split.eq(source)]
            candidates = candidates.sort_values(["group_row_count", "feature_hash"], kind="stable")
            require(not candidates.empty, f"Cannot repair {fine_label} into internal {destination}")
            chosen = candidates.iloc[0]
            manifest.loc[manifest.feature_hash == chosen.feature_hash, "internal_split"] = destination
            repairs.append(f"Moved hash {chosen.feature_hash} ({chosen.group_row_count} rows, {fine_label}) {source}->{destination}")
    manifest = manifest.sort_values("feature_hash", kind="stable").reset_index(drop=True)
    return manifest, repairs


def class_weights(y: np.ndarray) -> dict[str, float]:
    counts = np.bincount(y, minlength=len(CLASS_ORDER))
    require((counts > 0).all(), "Class missing while calculating weights")
    return {CLASS_ORDER[i]: float(len(y) / (len(CLASS_ORDER) * counts[i])) for i in range(len(CLASS_ORDER))}


def encode(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    return frame[FEATURES].to_numpy(dtype=np.float32, copy=True), frame.family.map(CLASS_TO_ID).to_numpy(dtype=np.int32)


def metrics(y: np.ndarray, pred: np.ndarray, prob: np.ndarray) -> dict[str, float]:
    precision, recall, f1, _ = precision_recall_fscore_support(y, pred, labels=np.arange(8), zero_division=0)
    _, _, weighted_f1, _ = precision_recall_fscore_support(y, pred, average="weighted", zero_division=0)
    return {
        "accuracy": accuracy_score(y, pred), "balanced_accuracy": balanced_accuracy_score(y, pred),
        "macro_precision": float(precision.mean()), "macro_recall": float(recall.mean()),
        "macro_f1": float(f1.mean()), "weighted_f1": float(weighted_f1),
        "log_loss": log_loss(y, prob, labels=np.arange(8)),
    }


def benchmark(model, X: np.ndarray, repetitions: int) -> dict[str, float]:
    model.predict_proba(X[: min(4096, len(X))])
    elapsed = []
    for _ in range(repetitions):
        start = time.perf_counter()
        model.predict_proba(X)
        elapsed.append(time.perf_counter() - start)
    median_s = float(np.median(elapsed))
    return {"median_total_inference_ms": median_s * 1000, "median_ms_per_sample": median_s * 1000 / len(X),
            "samples_per_second": len(X) / median_s}


def in_memory_size(model) -> int:
    buffer = io.BytesIO()
    joblib.dump(model, buffer, compress=3)
    return buffer.tell()


def make_models(xgb_estimators: int = 2000, lgb_estimators: int = 2000, development: bool = True):
    return {
        "random_forest": RandomForestClassifier(n_estimators=300, max_features="sqrt", class_weight="balanced_subsample", random_state=SEED, n_jobs=-1),
        "xgboost": XGBClassifier(objective="multi:softprob", num_class=8, n_estimators=xgb_estimators,
                                 learning_rate=0.05, max_depth=8, subsample=0.8, colsample_bytree=0.8,
                                 tree_method="hist", eval_metric="mlogloss", random_state=SEED, n_jobs=-1,
                                 early_stopping_rounds=100 if development else None),
        "lightgbm": LGBMClassifier(objective="multiclass", num_class=8, n_estimators=lgb_estimators,
                                    learning_rate=0.05, num_leaves=31, subsample=0.8, colsample_bytree=0.8,
                                    random_state=SEED, n_jobs=-1, verbosity=-1),
    }


def fit_development(X_train, y_train, X_dev, y_dev):
    models = make_models()
    rows = []
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    for key in MODEL_KEYS:
        print(f"[DEV] Training {key}", flush=True)
        model = models[key]
        start = time.perf_counter()
        if key == "xgboost":
            model.fit(X_train, y_train, sample_weight=sample_weights, eval_set=[(X_dev, y_dev)], verbose=False)
        elif key == "lightgbm":
            model.fit(X_train, y_train, sample_weight=sample_weights, eval_set=[(X_dev, y_dev)],
                      callbacks=[lgb.early_stopping(100, verbose=False)])
        else:
            model.fit(X_train, y_train)
        training_seconds = time.perf_counter() - start
        prob = model.predict_proba(X_dev)
        pred = np.argmax(prob, axis=1)
        row = {"model": key, "feature_count": 39, **metrics(y_dev, pred, prob), "training_seconds": training_seconds}
        if key == "xgboost":
            row["best_iteration"] = int(model.best_iteration)
        elif key == "lightgbm":
            row["best_iteration"] = int(model.best_iteration_)
        else:
            row["best_iteration"] = None
        row.update(benchmark(model, X_dev, LATENCY_DEV_REPS))
        size = in_memory_size(model)
        row.update({"serialized_model_size_bytes": size, "serialized_model_size_mib": size / 2**20})
        rows.append(row)
        print(f"[DEV] {key} macro_f1={row['macro_f1']:.6f}, best_iteration={row['best_iteration']}", flush=True)
    return models, pd.DataFrame(rows)


def select_model(dev: pd.DataFrame) -> tuple[str, str]:
    best = float(dev.macro_f1.max())
    eligible = dev.loc[dev.macro_f1 >= best - 0.002].copy()
    if len(eligible) == 1:
        selected = eligible.iloc[0]
        reason = f"{selected.model} had the highest internal-dev Macro-F1 ({selected.macro_f1:.10f}); no other model was within 0.002."
    else:
        min_latency = float(eligible.median_ms_per_sample.min())
        latency_tied = eligible.loc[eligible.median_ms_per_sample <= min_latency * 1.01]
        if len(latency_tied) == 1:
            selected = latency_tied.iloc[0]
            reason = (f"Models within 0.002 of best Macro-F1: {', '.join(eligible.model)}. "
                      f"{selected.model} had the lowest median prediction latency ({selected.median_ms_per_sample:.10f} ms/sample).")
        else:
            selected = latency_tied.sort_values(["serialized_model_size_bytes", "model"]).iloc[0]
            reason = (f"Models within 0.002 of best Macro-F1 also had effectively tied latency (within 1%): "
                      f"{', '.join(latency_tied.model)}. {selected.model} had the smallest serialized development model.")
    return str(selected.model), reason


def fit_final(X, y, xgb_count: int, lgb_count: int):
    models = make_models(xgb_count, lgb_count, development=False)
    weights = compute_sample_weight(class_weight="balanced", y=y)
    seconds = {}
    for key in MODEL_KEYS:
        print(f"[FINAL] Training {key}", flush=True)
        start = time.perf_counter()
        if key in {"xgboost", "lightgbm"}:
            models[key].fit(X, y, sample_weight=weights)
        else:
            models[key].fit(X, y)
        seconds[key] = time.perf_counter() - start
    return models, seconds


def environment_text() -> str:
    gpu = "Not detected"
    try:
        gpu = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True, timeout=5).stdout.strip() or gpu
    except (OSError, subprocess.SubprocessError):
        pass
    cpu = platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "Unknown")
    return "\n".join([
        f"OS: {platform.platform()}", f"Python: {platform.python_version()}", f"CPU: {cpu}",
        f"Logical CPU count: {psutil.cpu_count(logical=True)}", f"Physical CPU count: {psutil.cpu_count(logical=False)}",
        f"Total RAM bytes: {psutil.virtual_memory().total}", f"GPU: {gpu}", f"pandas: {pd.__version__}",
        f"numpy: {np.__version__}", f"scikit-learn: {sklearn.__version__}", f"xgboost: {xgboost.__version__}",
        f"lightgbm: {lgb.__version__}", f"pyarrow: {pyarrow.__version__}",
    ]) + "\n"


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True); MODELS.mkdir(parents=True, exist_ok=True); PREDICTIONS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "class_mapping.json").write_text(json.dumps(CLASS_TO_ID, indent=2) + "\n", encoding="utf-8")
    (RESULTS / "experiment_environment.txt").write_text(environment_text(), encoding="utf-8")
    official_train = pd.read_parquet(TRAIN_PATH)
    validate_frame(official_train, 428_477, "official train")
    manifest, repairs = internal_manifest(official_train)
    require(manifest.feature_hash.is_unique, "Internal manifest hash duplication")
    manifest.to_parquet(RESULTS / "step5_internal_dev_manifest.parquet", index=False)
    assigned = official_train.merge(manifest[["feature_hash", "internal_split"]], on="feature_hash", validate="many_to_one")
    internal_train = assigned.loc[assigned.internal_split == "train"]
    internal_dev = assigned.loc[assigned.internal_split == "dev"]
    overlap = len(set(internal_train.feature_hash) & set(internal_dev.feature_hash))
    require(overlap == 0, f"Internal hash overlap: {overlap}")
    coverage = assigned.groupby(["fine_label", "internal_split"]).size().unstack(fill_value=0)
    require(len(coverage) == 34 and (coverage[["train", "dev"]] > 0).all().all(), "Fine-label internal coverage failed")
    require(set(internal_train.family) == set(internal_dev.family) == set(CLASS_ORDER), "Internal family coverage failed")
    X_internal, y_internal = encode(internal_train)
    X_dev, y_dev = encode(internal_dev)
    internal_weights = class_weights(y_internal)
    development_models, dev = fit_development(X_internal, y_internal, X_dev, y_dev)
    dev.to_csv(RESULTS / "baseline_dev_metrics.csv", index=False, float_format="%.10f")
    selected, reason = select_model(dev)
    selection = {"primary_metric": "macro_f1", "macro_f1_tolerance": 0.002,
                 "tie_breaker_1": "inference_latency", "tie_breaker_2": "serialized_model_size",
                 "selected_model": selected, "reason": reason,
                 # DataFrame.to_json converts non-applicable RF best_iteration to
                 # standards-compliant JSON null rather than Python's NaN token.
                 "dev_metrics_used": json.loads(dev.to_json(orient="records"))}
    # This write is intentionally completed before the official test file is loaded.
    (RESULTS / "baseline_selection.json").write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
    del development_models, X_internal, y_internal, X_dev, y_dev

    X_train, y_train = encode(official_train)
    official_weights = class_weights(y_train)
    weight_payload = {"formula": "n_samples / (n_classes * class_count)", "internal_train_only": internal_weights,
                      "official_train_only": official_weights,
                      "random_forest": "class_weight=balanced_subsample", "xgboost_and_lightgbm": "equivalent per-row balanced sample weights"}
    (RESULTS / "step5_class_weights.json").write_text(json.dumps(weight_payload, indent=2) + "\n", encoding="utf-8")
    xgb_best = int(dev.loc[dev.model == "xgboost", "best_iteration"].iloc[0])
    lgb_best = int(dev.loc[dev.model == "lightgbm", "best_iteration"].iloc[0])
    final_models, final_training_seconds = fit_final(X_train, y_train, xgb_best + 1, lgb_best)
    model_sizes = {}
    for key, model in final_models.items():
        path = MODELS / f"{key}.joblib"
        joblib.dump(model, path, compress=3)
        model_sizes[key] = path.stat().st_size
    shutil.copyfile(MODELS / f"{selected}.joblib", MODELS / "primary_model.joblib")
    metadata = {key: {"model": key, "feature_count": 39, "feature_names": FEATURES, "class_order": CLASS_ORDER,
                      "best_iteration": (xgb_best if key == "xgboost" else lgb_best if key == "lightgbm" else None),
                      "random_seed": SEED, "class_weight_policy": "balanced from official TRAIN only",
                      "training_rows": len(official_train)} for key in MODEL_KEYS}
    (MODELS / "model_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    # The official test is first loaded here, after selection and final refits are frozen.
    official_test = pd.read_parquet(TEST_PATH)
    validate_frame(official_test, 91_819, "official test")
    require(len(set(official_train.feature_hash) & set(official_test.feature_hash)) == 0, "Official train/test hash overlap")
    X_test, y_test = encode(official_test)
    test_rows, per_class_rows, efficiency_rows = [], [], []
    for key in MODEL_KEYS:
        model = final_models[key]
        prob = model.predict_proba(X_test)
        require(prob.shape == (len(X_test), 8) and np.isfinite(prob).all(), f"{key}: invalid probabilities")
        require(np.allclose(prob.sum(axis=1), 1.0, atol=1e-5), f"{key}: probability rows do not sum to one")
        pred = np.argmax(prob, axis=1)
        require(np.isin(pred, np.arange(8)).all(), f"{key}: unexpected prediction")
        test_rows.append({"model": key, "feature_count": 39, **metrics(y_test, pred, prob)})
        precision, recall, f1, support = precision_recall_fscore_support(y_test, pred, labels=np.arange(8), zero_division=0)
        per_class_rows += [{"model": key, "family": CLASS_ORDER[i], "precision": precision[i], "recall": recall[i], "f1": f1[i], "support": int(support[i])} for i in range(8)]
        cm = confusion_matrix(y_test, pred, labels=np.arange(8))
        pd.DataFrame(cm, index=CLASS_ORDER, columns=CLASS_ORDER).rename_axis("true_family").to_csv(RESULTS / f"confusion_matrix_{key}.csv")
        pred_frame = pd.DataFrame({"feature_hash": official_test.feature_hash.to_numpy(), "true_family": official_test.family.to_numpy(),
                                   "predicted_family": np.array(CLASS_ORDER, dtype=object)[pred]})
        for i, family in enumerate(CLASS_ORDER): pred_frame[f"prob_{family}"] = prob[:, i]
        pred_frame.to_parquet(PREDICTIONS / f"{key}_test.parquet", index=False)
        timing = benchmark(model, X_test, LATENCY_TEST_REPS)
        efficiency_rows.append({"model": key, "test_samples": len(X_test), **timing,
                                "training_seconds": final_training_seconds[key], "serialized_model_size_bytes": model_sizes[key],
                                "serialized_model_size_mib": model_sizes[key] / 2**20})
    test = pd.DataFrame(test_rows); per_class = pd.DataFrame(per_class_rows); efficiency = pd.DataFrame(efficiency_rows)
    test.to_csv(RESULTS / "baseline_test_metrics.csv", index=False, float_format="%.10f")
    per_class.to_csv(RESULTS / "baseline_per_class_metrics.csv", index=False, float_format="%.10f")
    efficiency.to_csv(RESULTS / "baseline_efficiency.csv", index=False, float_format="%.10f")

    config = {"random_seed": SEED, "feature_count": 39, "features": FEATURES, "primary_metric": "macro_f1",
              "selection_tolerance": 0.002, "class_weight_policy": "balanced; weights learned from fitting partition labels only",
              "internal_dev_ratio": DEV_RATIO, "number_of_latency_repetitions": {"dev": LATENCY_DEV_REPS, "test": LATENCY_TEST_REPS},
              "calibration_used": False,
              "models": {"random_forest": {"n_estimators": 300, "max_features": "sqrt", "class_weight": "balanced_subsample"},
                         "xgboost": {"development_n_estimators": 2000, "final_n_estimators": xgb_best + 1, "learning_rate": 0.05, "max_depth": 8, "subsample": 0.8, "colsample_bytree": 0.8, "tree_method": "hist", "early_stopping_rounds": 100},
                         "lightgbm": {"development_n_estimators": 2000, "final_n_estimators": lgb_best, "learning_rate": 0.05, "num_leaves": 31, "subsample": 0.8, "colsample_bytree": 0.8, "early_stopping_rounds": 100}}}
    (RESULTS / "step5_config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    lines = [f"FEATURE COUNT: 39", f"TRAIN ROWS: {len(official_train)}", f"INTERNAL TRAIN ROWS: {len(internal_train)}",
             f"INTERNAL DEV ROWS: {len(internal_dev)}", f"INTERNAL HASH OVERLAP: {overlap}", f"INTERNAL REPAIRS: {len(repairs)}", *repairs,
             "", "CLASS WEIGHTS", json.dumps(weight_payload, indent=2), ""]
    for row in dev.to_dict("records"):
        lines += [f"DEV MODEL: {row['model']}", *[f"{k}: {row[k]}" for k in ["accuracy", "balanced_accuracy", "macro_f1", "weighted_f1", "log_loss", "training_seconds", "best_iteration", "median_ms_per_sample"]], ""]
    lines += [f"PREDECLARED PRIMARY MODEL: {selected}", f"SELECTION REASON: {reason}", ""]
    for row in test.to_dict("records"):
        lines += [f"OFFICIAL TEST MODEL: {row['model']}", *[f"{k}: {row[k]}" for k in ["accuracy", "balanced_accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1", "log_loss"]]]
        for pc in per_class.loc[per_class.model == row["model"]].itertuples(): lines.append(f"per-class F1 {pc.family}: {pc.f1}")
        eff = efficiency.loc[efficiency.model == row["model"]].iloc[0]
        lines += [f"median ms/sample: {eff.median_ms_per_sample}", f"samples/sec: {eff.samples_per_second}", f"model size bytes: {eff.serialized_model_size_bytes}", ""]
    lines += ["CALIBRATION SET USED: NO", "FEATURE SELECTION USED: NO", "TEST USED FOR MODEL SELECTION: NO", "", "STEP 5 VALIDATION: PASS"]
    (RESULTS / "step5_baseline_audit.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("CALIBRATION SET USED: NO\nFEATURE SELECTION USED: NO\nTEST USED FOR MODEL SELECTION: NO\nSTEP 5 VALIDATION: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
