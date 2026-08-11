"""Step 3: build a deterministic, subtype-aware CICIoT2023 research pool."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_ROOT = PROJECT_ROOT / "CSV"
RESULTS_DIR = PROJECT_ROOT / "results"
PROCESSED_DIR = PROJECT_ROOT / "processed"
MAPPING_PATH = RESULTS_DIR / "attack_family_mapping.csv"
FINE_COUNTS_PATH = RESULTS_DIR / "fine_label_counts.csv"
FILE_COUNTS_PATH = RESULTS_DIR / "file_record_counts.csv"

POOL_PATH = PROCESSED_DIR / "research_pool.parquet"
PLAN_PATH = RESULTS_DIR / "sampling_plan.csv"
POOL_COUNTS_PATH = RESULTS_DIR / "research_pool_counts.csv"
FAMILY_COUNTS_PATH = RESULTS_DIR / "research_pool_family_counts.csv"
CLEANING_AUDIT_PATH = RESULTS_DIR / "step3_cleaning_audit.csv"
DUPLICATE_AUDIT_PATH = RESULTS_DIR / "duplicate_audit.txt"
CONFLICTS_PATH = RESULTS_DIR / "label_conflicts.parquet"
CONFIG_PATH = RESULTS_DIR / "step3_config.json"

RANDOM_SEED = 42
FAMILY_CAP = 100_000
FINE_LABEL_MINIMUM = 1_000
CHUNK_SIZE = 100_000
EXPECTED_FAMILIES = {"Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"}
FEATURE_COLUMNS = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum",
    "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]


def stable_sort(frame: pd.DataFrame, columns: list[str], ascending: list[bool] | None = None) -> pd.DataFrame:
    return frame.sort_values(columns, ascending=ascending or [True] * len(columns), kind="stable").reset_index(drop=True)


def load_and_validate_inputs() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, str]]:
    for path in (MAPPING_PATH, FINE_COUNTS_PATH, FILE_COUNTS_PATH):
        if not path.is_file():
            raise FileNotFoundError(f"Required Step-2 artifact is missing: {path}")
    mapping = pd.read_csv(MAPPING_PATH)
    fine_counts = pd.read_csv(FINE_COUNTS_PATH)
    file_counts = pd.read_csv(FILE_COUNTS_PATH)
    if list(mapping.columns) != ["fine_label", "family"]:
        raise RuntimeError("Unexpected attack_family_mapping.csv schema")
    if len(mapping) != 34 or mapping["fine_label"].nunique() != 34:
        raise RuntimeError("Mapping must contain exactly 34 unique fine labels")
    if set(mapping["family"]) != EXPECTED_FAMILIES:
        raise RuntimeError(f"Unexpected mapped families: {sorted(set(mapping['family']) - EXPECTED_FAMILIES)}")
    disk_folders = {path.name for path in DATASET_ROOT.iterdir() if path.is_dir()}
    mapped_folders = set(mapping["fine_label"])
    if disk_folders != mapped_folders:
        raise RuntimeError(
            f"Mapping/disk mismatch. Unmapped on disk={sorted(disk_folders - mapped_folders)}, "
            f"absent from disk={sorted(mapped_folders - disk_folders)}"
        )
    if set(fine_counts["fine_label"]) != mapped_folders:
        raise RuntimeError("fine_label_counts.csv does not cover the verified mapping exactly")
    lookup = dict(zip(mapping["fine_label"], mapping["family"]))
    if any(fine_counts.set_index("fine_label").loc[label, "family"] != family for label, family in lookup.items()):
        raise RuntimeError("Family disagreement between mapping and fine-label count audit")
    if int(file_counts["row_count"].sum()) != int(fine_counts["record_count"].sum()):
        raise RuntimeError("Step-2 file and fine-label record totals disagree")
    return mapping, fine_counts, file_counts, lookup


def allocate_capped_quotas(group: pd.DataFrame) -> dict[str, tuple[int, int]]:
    available = {row.fine_label: int(row.record_count) for row in group.itertuples(index=False)}
    base = {label: min(FINE_LABEL_MINIMUM, count) for label, count in available.items()}
    quota = dict(base)
    remaining = FAMILY_CAP - sum(base.values())
    residual = {label: available[label] - base[label] for label in available}
    residual_total = sum(residual.values())
    if remaining < 0 or residual_total < remaining:
        raise RuntimeError("Capped quota is infeasible")
    exact = {label: remaining * residual[label] / residual_total for label in available}
    floors = {label: math.floor(value) for label, value in exact.items()}
    for label in quota:
        quota[label] += floors[label]
    left = FAMILY_CAP - sum(quota.values())
    remainder_order = sorted(available, key=lambda label: (-(exact[label] - floors[label]), label.casefold(), label))
    for label in remainder_order:
        if left == 0:
            break
        if quota[label] < available[label]:
            quota[label] += 1
            left -= 1
    while left:
        candidates = sorted((label for label in available if quota[label] < available[label]), key=lambda x: (x.casefold(), x))
        if not candidates:
            raise RuntimeError("Unable to redistribute unused capped quota")
        for label in candidates:
            if left == 0:
                break
            quota[label] += 1
            left -= 1
    return {label: (base[label], quota[label]) for label in available}


def create_sampling_plan(fine_counts: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for family in sorted(EXPECTED_FAMILIES):
        group = fine_counts.loc[fine_counts["family"] == family, ["fine_label", "record_count"]].copy()
        family_raw = int(group["record_count"].sum())
        if family_raw > FAMILY_CAP:
            allocations = allocate_capped_quotas(group)
        else:
            allocations = {
                row.fine_label: (min(FINE_LABEL_MINIMUM, int(row.record_count)), int(row.record_count))
                for row in group.itertuples(index=False)
            }
        for row in group.itertuples(index=False):
            raw = int(row.record_count)
            base, target = allocations[row.fine_label]
            rows.append({
                "family": family,
                "fine_label": row.fine_label,
                "raw_record_count": raw,
                "family_raw_count": family_raw,
                "family_cap": FAMILY_CAP,
                "base_minimum": base,
                "target_sample_count": target,
                "sampling_fraction": target / raw,
            })
    plan = stable_sort(pd.DataFrame(rows), ["family", "fine_label"])
    for family, group in plan.groupby("family"):
        raw = int(group["family_raw_count"].iloc[0])
        target = int(group["target_sample_count"].sum())
        expected = FAMILY_CAP if raw > FAMILY_CAP else raw
        if target != expected or (group["target_sample_count"] > group["raw_record_count"]).any():
            raise RuntimeError(f"Invalid sampling allocation for {family}: {target} != {expected}")
    return plan


def rng_for_label(label: str) -> np.random.Generator:
    digest = hashlib.sha256(f"{RANDOM_SEED}|{label}".encode("utf-8")).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "little"))


def find_malformed_rows(path: Path) -> set[int]:
    malformed: set[int] = set()
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise RuntimeError(f"Empty CSV: {path}") from exc
            if header != FEATURE_COLUMNS:
                raise RuntimeError(f"Schema mismatch while scanning {path}")
            for source_row, row in enumerate(reader, start=1):
                if len(row) != len(FEATURE_COLUMNS):
                    malformed.add(source_row)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise RuntimeError(f"Could not structurally scan {path}: {type(exc).__name__}: {exc}") from exc
    return malformed


def classify_and_clean(raw: pd.DataFrame, source_rows: np.ndarray, malformed_rows: set[int]) -> tuple[pd.DataFrame, dict[str, int]]:
    numeric = raw.apply(pd.to_numeric, errors="coerce")
    malformed = pd.Series(np.isin(source_rows, list(malformed_rows)), index=raw.index)
    original_missing = raw.isna().any(axis=1)
    conversion_failed = numeric.isna().any(axis=1) & ~original_missing
    positive_inf_any = numeric.eq(np.inf).any(axis=1)
    negative_inf_any = numeric.eq(-np.inf).any(axis=1)

    remaining = ~malformed
    nonnumeric = remaining & conversion_failed
    remaining &= ~nonnumeric
    nan = remaining & numeric.isna().any(axis=1)
    remaining &= ~nan
    positive_inf = remaining & positive_inf_any
    remaining &= ~positive_inf
    negative_inf = remaining & negative_inf_any
    valid = remaining & ~negative_inf
    counts = {
        "malformed_rows": int(malformed.sum()),
        "nan_rows": int(nan.sum()),
        "positive_inf_rows": int(positive_inf.sum()),
        "negative_inf_rows": int(negative_inf.sum()),
        "non_numeric_rows": int(nonnumeric.sum()),
        "total_invalid_rows": int((~valid).sum()),
    }
    cleaned = numeric.loc[valid].copy()
    cleaned["source_row"] = source_rows[valid.to_numpy()]
    return cleaned, counts


def update_reservoir(current: pd.DataFrame | None, candidates: pd.DataFrame, target: int) -> pd.DataFrame:
    if current is None or current.empty:
        combined = candidates
    elif candidates.empty:
        return current
    else:
        combined = pd.concat([current, candidates], ignore_index=True)
    if len(combined) > target:
        combined = combined.nsmallest(target, "_random_priority", keep="first")
    return combined.reset_index(drop=True)


def stream_sample(plan: pd.DataFrame, file_counts: pd.DataFrame, lookup: dict[str, str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    targets = dict(zip(plan["fine_label"], plan["target_sample_count"].astype(int)))
    reservoirs: dict[str, pd.DataFrame] = {}
    audit_rows: list[dict[str, object]] = []
    started = time.perf_counter()
    for family in sorted(EXPECTED_FAMILIES):
        print(f"\n[Family {family}]")
        labels = sorted(plan.loc[plan["family"] == family, "fine_label"], key=lambda x: (x.casefold(), x))
        for label in labels:
            print(f"[Fine label {label}] target={targets[label]}")
            label_files = file_counts.loc[file_counts["attack_folder"] == label].copy()
            label_files = stable_sort(label_files, ["relative_path"])
            rng = rng_for_label(label)
            reservoir: pd.DataFrame | None = None
            for file_index, file_row in enumerate(label_files.itertuples(index=False), start=1):
                path = DATASET_ROOT / Path(file_row.relative_path)
                malformed_positions = find_malformed_rows(path)
                totals = {key: 0 for key in ("malformed_rows", "nan_rows", "positive_inf_rows", "negative_inf_rows", "non_numeric_rows", "total_invalid_rows")}
                rows_processed = 0
                valid_considered = 0
                try:
                    reader = pd.read_csv(
                        path, usecols=FEATURE_COLUMNS, dtype=str, chunksize=CHUNK_SIZE,
                        encoding="utf-8-sig", on_bad_lines="error",
                    )
                    for raw_chunk in reader:
                        chunk_start = rows_processed + 1
                        source_rows = np.arange(chunk_start, chunk_start + len(raw_chunk), dtype=np.int64)
                        cleaned, rejected = classify_and_clean(raw_chunk, source_rows, malformed_positions)
                        rows_processed += len(raw_chunk)
                        valid_considered += len(cleaned)
                        for key in totals:
                            totals[key] += rejected[key]
                        if not cleaned.empty:
                            cleaned["fine_label"] = label
                            cleaned["family"] = lookup[label]
                            cleaned["source_file"] = file_row.relative_path
                            cleaned["source_folder"] = label
                            cleaned["_random_priority"] = rng.random(len(cleaned))
                            reservoir = update_reservoir(reservoir, cleaned, targets[label])
                except Exception as exc:
                    raise RuntimeError(f"Failed while sampling {file_row.relative_path}: {type(exc).__name__}: {exc}") from exc
                expected_rows = int(file_row.row_count)
                if rows_processed != expected_rows:
                    raise RuntimeError(f"Row-count drift for {file_row.relative_path}: processed {rows_processed}, expected {expected_rows}")
                if totals["malformed_rows"] != len(malformed_positions):
                    raise RuntimeError(f"Malformed-row accounting drift for {file_row.relative_path}")
                audit_rows.append({
                    "relative_path": file_row.relative_path,
                    "fine_label": label,
                    "family": lookup[label],
                    "rows_processed": rows_processed,
                    **totals,
                    "valid_rows_considered": valid_considered,
                    "rows_selected": 0,
                })
                if file_index % 5 == 0 or file_index == len(label_files):
                    selected = 0 if reservoir is None else len(reservoir)
                    print(f"  Processed {file_index}/{len(label_files)} files; reservoir {selected}/{targets[label]}")
            if reservoir is None or len(reservoir) < targets[label]:
                valid_total = 0 if reservoir is None else len(reservoir)
                raw_total = int(plan.loc[plan["fine_label"] == label, "raw_record_count"].iloc[0])
                if raw_total > FAMILY_CAP:
                    raise RuntimeError(f"Capped label {label} could not meet target: {valid_total}/{targets[label]}")
                print(f"  NOTE: {label} retained {valid_total}/{targets[label]} after invalid-row cleaning")
            reservoirs[label] = reservoir if reservoir is not None else pd.DataFrame()
    print(f"\nStreaming sampling elapsed: {(time.perf_counter() - started) / 60:.2f} minutes")
    pool = pd.concat([reservoirs[label] for label in sorted(reservoirs)], ignore_index=True)
    pool = pool.drop(columns=["_random_priority"])
    audit = pd.DataFrame(audit_rows)
    selected_by_file = pool["source_file"].value_counts()
    audit["rows_selected"] = audit["relative_path"].map(selected_by_file).fillna(0).astype(int)
    return pool, audit


def add_feature_hashes(pool: pd.DataFrame) -> pd.DataFrame:
    pool = pool.copy()
    pool["feature_hash"] = pd.util.hash_pandas_object(pool[FEATURE_COLUMNS], index=False).astype("uint64")
    return pool


def duplicate_statistics(pool: pd.DataFrame) -> tuple[dict[str, object], pd.DataFrame]:
    sizes = pool.groupby("feature_hash", sort=False).size()
    duplicate_sizes = sizes[sizes > 1]
    family_counts = pool.groupby("feature_hash", sort=False)["family"].nunique()
    conflict_hashes = family_counts[family_counts > 1].index
    conflicts = pool.loc[pool["feature_hash"].isin(conflict_hashes)].copy()
    families = sorted(conflicts["family"].unique().tolist()) if not conflicts.empty else []
    stats = {
        "total_rows": len(pool),
        "unique_hashes": int(len(sizes)),
        "rows_in_duplicate_groups": int(duplicate_sizes.sum()),
        "duplicate_groups": int(len(duplicate_sizes)),
        "max_duplicate_group_size": int(sizes.max()) if len(sizes) else 0,
        "conflicting_hashes": int(len(conflict_hashes)),
        "rows_in_conflict_groups": int(len(conflicts)),
        "families_involved": families,
    }
    return stats, conflicts


def build_count_reports(plan: pd.DataFrame, pool: pd.DataFrame, audit: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    final_counts = pool.groupby(["family", "fine_label"], as_index=False).size().rename(columns={"size": "final_count"})
    rejected = audit.groupby(["family", "fine_label"], as_index=False)["total_invalid_rows"].sum().rename(columns={"total_invalid_rows": "rejected_invalid_count"})
    counts = plan[["family", "fine_label", "target_sample_count"]].merge(rejected, on=["family", "fine_label"], how="left").merge(final_counts, on=["family", "fine_label"], how="left")
    counts["rejected_invalid_count"] = counts["rejected_invalid_count"].fillna(0).astype(int)
    counts["final_count"] = counts["final_count"].fillna(0).astype(int)
    counts.insert(3, "valid_sampled_count", counts["final_count"])
    counts = counts[["family", "fine_label", "target_sample_count", "valid_sampled_count", "rejected_invalid_count", "final_count"]]
    counts = stable_sort(counts, ["family", "fine_label"])

    raw_family = plan.groupby("family", as_index=False)["raw_record_count"].sum()
    target_family = plan.groupby("family", as_index=False)["target_sample_count"].sum().rename(columns={"target_sample_count": "target_record_count"})
    final_family = pool.groupby("family", as_index=False).size().rename(columns={"size": "final_valid_count"})
    family = raw_family.merge(target_family, on="family").merge(final_family, on="family", how="left")
    family["final_valid_count"] = family["final_valid_count"].fillna(0).astype(int)
    family["percentage_of_research_pool"] = family["final_valid_count"] / len(pool) * 100
    family = stable_sort(family, ["family"])
    return counts, family


def validate_reloaded_pool(expected_rows: int, mapping: pd.DataFrame) -> tuple[bool, list[str], pd.DataFrame]:
    reloaded = pd.read_parquet(POOL_PATH)
    errors: list[str] = []
    required = FEATURE_COLUMNS + ["fine_label", "family", "source_file", "source_folder", "source_row", "feature_hash"]
    if len(reloaded) != expected_rows:
        errors.append(f"row count {len(reloaded)} != {expected_rows}")
    if list(reloaded.columns) != required:
        errors.append("column names/order do not match the required 45-column pool schema")
    if reloaded[FEATURE_COLUMNS].isna().any().any():
        errors.append("NaN feature values found")
    values = reloaded[FEATURE_COLUMNS].to_numpy(dtype=float, copy=False)
    if np.isposinf(values).any() or np.isneginf(values).any():
        errors.append("infinite feature values found")
    if set(reloaded["family"]) != EXPECTED_FAMILIES:
        errors.append("family labels differ from the expected 8 families")
    if set(reloaded["fine_label"]) != set(mapping["fine_label"]):
        errors.append("fine labels differ from the expected 34 labels")
    expected_pairs = set(map(tuple, mapping[["fine_label", "family"]].itertuples(index=False, name=None)))
    observed_pairs = set(map(tuple, reloaded[["fine_label", "family"]].drop_duplicates().itertuples(index=False, name=None)))
    if observed_pairs != expected_pairs:
        errors.append("fine-label/family pairs differ from the verified mapping")
    return not errors, errors, reloaded


def save_duplicate_audit(stats: dict[str, object]) -> None:
    text = "\n".join([
        f"TOTAL RESEARCH POOL ROWS: {stats['total_rows']}",
        f"UNIQUE FEATURE HASHES: {stats['unique_hashes']}",
        f"ROWS IN DUPLICATE GROUPS: {stats['rows_in_duplicate_groups']}",
        f"NUMBER OF DUPLICATE GROUPS: {stats['duplicate_groups']}",
        f"MAX DUPLICATE GROUP SIZE: {stats['max_duplicate_group_size']}",
        f"CONFLICTING FEATURE HASHES: {stats['conflicting_hashes']}",
        f"ROWS IN LABEL-CONFLICT GROUPS: {stats['rows_in_conflict_groups']}",
        f"FAMILIES INVOLVED: {', '.join(stats['families_involved']) if stats['families_involved'] else 'None'}",
    ]) + "\n"
    DUPLICATE_AUDIT_PATH.write_text(text, encoding="utf-8")


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    mapping, fine_counts, file_counts, lookup = load_and_validate_inputs()
    plan = create_sampling_plan(fine_counts)
    plan.to_csv(PLAN_PATH, index=False, encoding="utf-8", float_format="%.10f")
    print("SAMPLING PLAN (finalized before raw feature sampling)")
    print(plan.to_string(index=False))
    config = {
        "random_seed": RANDOM_SEED,
        "family_cap": FAMILY_CAP,
        "fine_label_minimum": FINE_LABEL_MINIMUM,
        "chunk_size": CHUNK_SIZE,
        "feature_count": len(FEATURE_COLUMNS),
        "sampling_algorithm": "deterministic per-fine-label seeded random-priority streaming reservoir with largest-remainder quotas",
        "run_datetime_utc": datetime.now(timezone.utc).isoformat(),
        "input_dataset_path": str(DATASET_ROOT),
        "invalid_rejection_priority": ["malformed", "non_numeric", "nan", "positive_inf", "negative_inf"],
    }
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")

    pool, audit = stream_sample(plan, file_counts, lookup)
    pool = add_feature_hashes(pool)
    required_order = FEATURE_COLUMNS + ["fine_label", "family", "source_file", "source_folder", "source_row", "feature_hash"]
    pool = pool[required_order]
    counts, family_counts = build_count_reports(plan, pool, audit)
    stats, conflicts = duplicate_statistics(pool)

    pool.to_parquet(POOL_PATH, index=False, engine="pyarrow", compression="snappy")
    audit.to_csv(CLEANING_AUDIT_PATH, index=False, encoding="utf-8")
    counts.to_csv(POOL_COUNTS_PATH, index=False, encoding="utf-8")
    family_counts.to_csv(FAMILY_COUNTS_PATH, index=False, encoding="utf-8", float_format="%.6f")
    save_duplicate_audit(stats)
    if conflicts.empty:
        if CONFLICTS_PATH.exists():
            CONFLICTS_PATH.unlink()
    else:
        conflicts.to_parquet(CONFLICTS_PATH, index=False, engine="pyarrow", compression="snappy")

    passed, errors, reloaded = validate_reloaded_pool(len(pool), mapping)
    print(f"\nRESEARCH POOL VALIDATION: {'PASS' if passed else 'FAIL'}")
    for error in errors:
        print(f"- {error}")
    print(f"FINAL RESEARCH POOL ROWS: {len(reloaded)}")
    print("\nFINAL FAMILY COUNTS")
    print(family_counts.to_string(index=False))
    print("\nFINAL FINE-LABEL COUNTS")
    print(counts[["family", "fine_label", "final_count"]].to_string(index=False))
    print("\nDUPLICATE STATISTICS")
    print(json.dumps(stats, indent=2))
    print(f"TOTAL INVALID ROWS EXCLUDED: {int(audit['total_invalid_rows'].sum())}")
    print(f"PARQUET FILE SIZE: {POOL_PATH.stat().st_size / (1024 ** 2):.3f} MB")
    if not passed:
        raise RuntimeError("Research pool validation failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
