"""Refresh EcoCon-NOS efficiency measurements from frozen Step 8.6 artifacts."""
from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ecocon_nos", ROOT / "src" / "08_6_ecocon_nested_open_set.py")
nos = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(nos)

pool = pd.read_parquet(nos.P / "modeling_pool.parquet")
metadata = json.loads((nos.LM / "metadata.json").read_text())
selections = json.loads((nos.R / "ecocon_nos_outer_detector_selection.json").read_text())
baseline = pd.read_csv(nos.R / "ecocon_efficiency.csv").set_index("held_out_family")
rows = []

for held_out in nos.FOLDS:
    cfg = metadata[held_out]
    features = cfg["selected_features"]
    classes = cfg["known_classes"]
    detector = selections[held_out]["selected_detector"]
    frozen = joblib.load(nos.NM / f"holdout_{held_out}.joblib")
    context = frozen["context"]
    known = nos.load_outer(held_out, "test_known", pool, features)
    md_object = joblib.load(nos.MM / f"holdout_{held_out}.joblib") if detector == "MD-Pred" else None
    timings = []
    for _ in range(10):
        started = time.perf_counter()
        if detector == "MD-Pred":
            z = md_object["scaler"].transform(known[features].to_numpy(float))
            predicted = known.predicted_family.to_numpy()
            residuals = np.empty_like(z)
            for family in classes:
                mask = predicted == family
                residuals[mask] = z[mask] - md_object["class_means"][family]
            _ = np.maximum(
                np.einsum(
                    "ij,jk,ik->i",
                    residuals,
                    md_object["shared_precision_matrix"],
                    residuals,
                    optimize=True,
                ),
                0,
            )
        else:
            _ = nos.score_selected(known, context, detector)
        timings.append(time.perf_counter() - started)
    xgb_ms = float(baseline.loc[held_out, "xgboost_ms_per_sample"])
    auxiliary_ms = float(np.median(timings) * 1000 / len(known))
    rows.append(
        {
            "held_out_family": held_out,
            "selected_detector": detector,
            "xgboost_ms_per_sample": xgb_ms,
            "auxiliary_ms_per_sample": auxiliary_ms,
            "combined_ms_per_sample": xgb_ms + auxiliary_ms,
            "overhead_percent": auxiliary_ms / xgb_ms * 100,
            "class_reference_rows": 0 if context is None else context["class_reference_rows"],
            "global_reference_rows": 0 if context is None else context["global_reference_rows"],
            "detector_object_size_mib": (nos.NM / f"holdout_{held_out}.joblib").stat().st_size / 2**20,
        }
    )

pd.DataFrame(rows).to_csv(nos.R / "ecocon_nos_efficiency.csv", index=False, float_format="%.10f")
print(pd.DataFrame(rows).to_string(index=False))
