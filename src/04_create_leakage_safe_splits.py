"""Step 4: create conflict-free, feature-hash-grouped evaluation splits.

This script performs data partitioning and audits only.  It deliberately does
not fit, transform, rank, resample, or otherwise learn from feature values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "processed"
RESULTS = ROOT / "results"
INPUT = PROCESSED / "research_pool.parquet"
AMBIGUOUS = PROCESSED / "ambiguous_conflict_pool.parquet"
MODELING = PROCESSED / "modeling_pool.parquet"
CLOSED_DIR = PROCESSED / "closed_set"

SEED = 42
RATIOS = {"train": 0.70, "calibration": 0.15, "test": 0.15}
SPLITS = list(RATIOS)
EXPECTED_ROWS = 637_892
EXPECTED_FAMILIES = {"Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"}
LOAFO_FAMILIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]
FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum",
    "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_pool(pool: pd.DataFrame) -> None:
    require(len(pool) == EXPECTED_ROWS, f"Research-pool row count changed: {len(pool)} != {EXPECTED_ROWS}")
    require(len(FEATURES) == 39 and all(c in pool for c in FEATURES), "The 39 expected feature columns are not present")
    require(all(c in pool for c in ["fine_label", "family", "feature_hash"]), "Required label/hash columns are missing")
    require(pool["feature_hash"].notna().all(), "Null feature_hash values found")
    require(set(pool["family"].unique()) == EXPECTED_FAMILIES and pool["family"].nunique() == 8, "Expected exactly 8 verified families")
    require(pool["fine_label"].nunique() == 34, "Expected exactly 34 fine labels")
    values = pool[FEATURES].to_numpy(dtype=np.float64, copy=False)
    require(np.isfinite(values).all(), "NaN or infinite feature value found")


def seeded_rng(family: str) -> np.random.Generator:
    digest = hashlib.sha256(f"{SEED}|{family}".encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "little"))


def create_group_split(groups: pd.DataFrame) -> pd.DataFrame:
    """Greedily allocate whole groups against per-family row-count targets."""
    parts = []
    for family in sorted(EXPECTED_FAMILIES):
        g = groups.loc[groups["family"] == family].copy().sort_values("feature_hash", kind="stable").reset_index(drop=True)
        g = g.iloc[seeded_rng(family).permutation(len(g))].reset_index(drop=True)
        total = int(g["group_row_count"].sum())
        targets = {s: RATIOS[s] * total for s in SPLITS}
        current = {s: 0 for s in SPLITS}
        assigned = []
        for size in g["group_row_count"].astype(int):
            # Largest normalized target deficit; fixed SPLITS order breaks ties.
            split = max(SPLITS, key=lambda s: ((targets[s] - current[s]) / targets[s], -SPLITS.index(s)))
            assigned.append(split)
            current[split] += size
        g["split"] = assigned
        parts.append(g)
    return pd.concat(parts, ignore_index=True)


def repair_fine_label_coverage(manifest: pd.DataFrame, pool: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Move entire groups deterministically when a fine label is absent in a split."""
    manifest = manifest.copy()
    memberships = pool[["feature_hash", "fine_label"]].drop_duplicates()
    repairs: list[str] = []
    for _ in range(100):
        coverage = memberships.merge(manifest[["feature_hash", "split"]], on="feature_hash").groupby(["fine_label", "split"]).size()
        missing = [(label, split) for label in sorted(pool["fine_label"].unique()) for split in SPLITS if coverage.get((label, split), 0) == 0]
        if not missing:
            return manifest, repairs
        changed = False
        for label, destination in missing:
            candidates = memberships.loc[memberships["fine_label"] == label, "feature_hash"].drop_duplicates().to_frame()
            candidates = candidates.merge(manifest, on="feature_hash")
            viable = []
            for row in candidates.sort_values(["group_row_count", "feature_hash"], kind="stable").itertuples(index=False):
                source = row.split
                if source == destination:
                    continue
                source_label_groups = memberships.loc[memberships["fine_label"] == label, "feature_hash"].isin(
                    manifest.loc[manifest["split"] == source, "feature_hash"]
                ).sum()
                if source == "train" and source_label_groups <= 1:
                    continue
                viable.append(row)
            if viable:
                chosen = viable[0]
                manifest.loc[manifest["feature_hash"] == chosen.feature_hash, "split"] = destination
                repairs.append(f"Moved hash {chosen.feature_hash} ({chosen.group_row_count} rows, {label}) from {chosen.split} to {destination}")
                changed = True
        if not changed:
            break
    return manifest, repairs


def overlap_counts(manifest: pd.DataFrame) -> dict[str, int]:
    sets = {s: set(manifest.loc[manifest["split"] == s, "feature_hash"]) for s in SPLITS}
    return {
        "train/calibration": len(sets["train"] & sets["calibration"]),
        "train/test": len(sets["train"] & sets["test"]),
        "calibration/test": len(sets["calibration"] & sets["test"]),
    }


def fine_counts(pool_with_split: pd.DataFrame) -> pd.DataFrame:
    table = pool_with_split.groupby(["fine_label", "family", "split"]).size().unstack(fill_value=0)
    for split in SPLITS:
        if split not in table:
            table[split] = 0
    table = table.rename(columns={s: f"{s}_count" for s in SPLITS}).reset_index()
    table["total_count"] = table[[f"{s}_count" for s in SPLITS]].sum(axis=1)
    return table[["fine_label", "family", "train_count", "calibration_count", "test_count", "total_count"]].sort_values(["family", "fine_label"])


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    CLOSED_DIR.mkdir(parents=True, exist_ok=True)
    require(INPUT.is_file(), f"Missing Step-3 input: {INPUT}")
    pool = pd.read_parquet(INPUT)
    validate_pool(pool)

    family_nunique = pool.groupby("feature_hash", sort=False)["family"].nunique()
    conflict_hashes = family_nunique[family_nunique > 1].index
    ambiguous = pool.loc[pool["feature_hash"].isin(conflict_hashes)].copy()
    modeling = pool.loc[~pool["feature_hash"].isin(conflict_hashes)].copy()
    require(modeling.groupby("feature_hash")["family"].nunique().max() == 1, "Conflict remained in modeling pool")
    require(len(ambiguous) + len(modeling) == len(pool), "Conflict partition did not preserve all rows")
    ambiguous.to_parquet(AMBIGUOUS, index=False, engine="pyarrow", compression="snappy")
    modeling.to_parquet(MODELING, index=False, engine="pyarrow", compression="snappy")
    print("CONFLICT-FREE MODELING POOL: PASS")

    groups = modeling.groupby("feature_hash", sort=False).agg(family=("family", "first"), group_row_count=("family", "size")).reset_index()
    manifest = create_group_split(groups)
    manifest, repairs = repair_fine_label_coverage(manifest, modeling)
    manifest = manifest.sort_values("feature_hash", kind="stable").reset_index(drop=True)
    require(manifest["feature_hash"].is_unique and len(manifest) == modeling["feature_hash"].nunique(), "Closed-set manifest is not one-row-per-hash")
    overlaps = overlap_counts(manifest)
    for key, value in overlaps.items():
        require(value == 0, f"Hash leakage in {key}: {value}")

    assigned = modeling.merge(manifest[["feature_hash", "split"]], on="feature_hash", validate="many_to_one")
    require(len(assigned) == len(modeling), "Rows lost while applying manifest")
    for split in SPLITS:
        frame = assigned.loc[assigned["split"] == split, modeling.columns]
        frame.to_parquet(CLOSED_DIR / f"{split}.parquet", index=False, engine="pyarrow", compression="snappy")

    manifest.to_parquet(RESULTS / "closed_set_split_manifest.parquet", index=False, engine="pyarrow", compression="snappy")
    split_counts = assigned.groupby(["split", "family"], as_index=False).size().rename(columns={"size": "row_count"})
    family_totals = split_counts.groupby("family")["row_count"].transform("sum")
    split_totals = split_counts.groupby("split")["row_count"].transform("sum")
    split_counts["percentage_within_family"] = split_counts["row_count"] / family_totals * 100
    split_counts["percentage_of_split"] = split_counts["row_count"] / split_totals * 100
    split_counts.to_csv(RESULTS / "closed_set_split_counts.csv", index=False, float_format="%.10f")
    fine = fine_counts(assigned)
    fine.to_csv(RESULTS / "closed_set_fine_label_counts.csv", index=False)
    require((fine["train_count"] > 0).all(), "A fine label is absent from train")
    require((fine[["calibration_count", "test_count"]] > 0).all().all(), "Fine-label repair could not cover calibration/test")
    family_coverage = assigned.groupby(["family", "split"]).size().unstack(fill_value=0)
    require((family_coverage[SPLITS] > 0).all().all(), "A family is absent from a closed-set split")

    loafo_parts = []
    for held_out in LOAFO_FAMILIES:
        fold = manifest.copy()
        fold.insert(0, "held_out_family", held_out)
        fold = fold.rename(columns={"split": "base_split"})
        fold["loafo_split"] = np.where(
            fold["family"].eq(held_out), "test_unknown",
            fold["base_split"].replace({"test": "test_known"}),
        )
        loafo_parts.append(fold[["held_out_family", "feature_hash", "family", "base_split", "loafo_split", "group_row_count"]])
    loafo = pd.concat(loafo_parts, ignore_index=True)
    loafo.to_parquet(RESULTS / "loafo_split_manifest.parquet", index=False, engine="pyarrow", compression="snappy")
    loafo_counts = loafo.groupby(["held_out_family", "loafo_split", "family"], as_index=False)["group_row_count"].sum().rename(columns={"group_row_count": "row_count"})
    loafo_counts.to_csv(RESULTS / "loafo_fold_counts.csv", index=False)

    fold_summary = []
    for held_out in LOAFO_FAMILIES:
        fold = loafo.loc[loafo["held_out_family"] == held_out]
        counts = fold.groupby("loafo_split")["group_row_count"].sum().to_dict()
        held_leak = fold.loc[fold["family"] == held_out].groupby("loafo_split")["group_row_count"].sum().to_dict()
        require(held_leak.get("train", 0) == held_leak.get("calibration", 0) == held_leak.get("test_known", 0) == 0, f"Held-out leakage in {held_out}")
        require(held_leak.get("test_unknown", 0) > 0, f"No unknown rows for {held_out}")
        require(fold["feature_hash"].is_unique, f"Duplicate hash assignment within {held_out} fold")
        fold_summary.append({"held_out_family": held_out, **{s: int(counts.get(s, 0)) for s in ["train", "calibration", "test_known", "test_unknown"]}})
        print(f"LOAFO {held_out}: PASS")

    config = {
        "random_seed": SEED, "train_ratio": 0.70, "calibration_ratio": 0.15, "test_ratio": 0.15,
        "group_key": "feature_hash", "conflict_policy": "exclude_entire_conflicting_hash_group",
        "loafo_families": LOAFO_FAMILIES,
    }
    (RESULTS / "step4_config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    global_counts = assigned["split"].value_counts().to_dict()
    family_counts = modeling["family"].value_counts().sort_index()
    lines = [
        f"ORIGINAL RESEARCH POOL ROWS: {len(pool)}", f"CONFLICT HASH COUNT: {len(conflict_hashes)}",
        f"CONFLICT ROW COUNT: {len(ambiguous)}", f"MODELING POOL ROW COUNT: {len(modeling)}", "",
        "MODELING POOL FAMILY COUNTS", *[f"{k}: {v}" for k, v in family_counts.items()], "", "CLOSED SET",
        *[f"{s.upper()} ROWS: {global_counts[s]} ({global_counts[s] / len(modeling) * 100:.10f}%)" for s in SPLITS], "",
        "HASH OVERLAP", *[f"{k}: {v}" for k, v in overlaps.items()], "", "FINE-LABEL REPRESENTATION",
        f"All 34 labels in train: {'PASS' if (fine.train_count > 0).all() else 'FAIL'}",
        f"All 34 labels in calibration: {'PASS' if (fine.calibration_count > 0).all() else 'FAIL'}",
        f"All 34 labels in test: {'PASS' if (fine.test_count > 0).all() else 'FAIL'}",
        f"Repairs performed: {len(repairs)}", *repairs, "",
        "CALIBRATION RESERVATION: Calibration is reserved only for conformal and uncertainty/rejection calibration; it must not be used for feature ranking, base-classifier fitting, or hyperparameter optimization. Hyperparameter tuning must use TRAIN-only internal CV.", "",
        "LOAFO FUTURE-LEAKAGE POLICY: In every LOAFO experiment, feature selection/ranking and hyperparameters must be learned using that fold's TRAIN data only. A global ranking across all eight families is prohibited. Conformal calibration uses CALIBRATION only, and the unknown test family is never used for threshold selection.", "",
    ]
    for row in fold_summary:
        held = row["held_out_family"]
        lines += [f"LOAFO HELD OUT FAMILY: {held}", f"TRAIN ROWS: {row['train']}", f"CALIBRATION ROWS: {row['calibration']}",
                  f"KNOWN TEST ROWS: {row['test_known']}", f"UNKNOWN TEST ROWS: {row['test_unknown']}",
                  "UNKNOWN FAMILY LEAKAGE INTO TRAIN: 0", "UNKNOWN FAMILY LEAKAGE INTO CALIBRATION: 0", "HASH LEAKAGE: 0", ""]
    lines += ["STEP 4 VALIDATION: PASS"]
    (RESULTS / "step4_split_audit.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"TRAIN-CALIBRATION HASH OVERLAP: {overlaps['train/calibration']}")
    print(f"TRAIN-TEST HASH OVERLAP: {overlaps['train/test']}")
    print(f"CALIBRATION-TEST HASH OVERLAP: {overlaps['calibration/test']}")
    print("STEP 4 VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
