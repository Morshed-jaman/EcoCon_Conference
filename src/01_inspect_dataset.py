"""Safely inspect the extracted CICIoT2023 CSV dataset and create inventories."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_ROOT = PROJECT_ROOT / "CSV"
RESULTS_DIR = PROJECT_ROOT / "results"
INVENTORY_PATH = RESULTS_DIR / "dataset_inventory.csv"
FOLDER_SUMMARY_PATH = RESULTS_DIR / "folder_summary.csv"
SCHEMA_PATH = RESULTS_DIR / "dataset_schema.csv"
SAMPLE_ROWS = 20
LABEL_CANDIDATES = (
    "label",
    "Label",
    "class",
    "Class",
    "attack",
    "Attack",
    "category",
    "Category",
)


def sorted_top_level_folders(root: Path) -> list[Path]:
    """Return immediate child directories in a reproducible order."""
    return sorted(
        (path for path in root.iterdir() if path.is_dir()),
        key=lambda path: (path.name.casefold(), path.name),
    )


def sorted_csv_files(root: Path) -> list[Path]:
    """Return CSV files recursively, sorted by their dataset-relative paths."""
    files = (path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".csv")
    return sorted(
        files,
        key=lambda path: (path.relative_to(root).as_posix().casefold(), path.relative_to(root).as_posix()),
    )


def safe_size_bytes(path: Path) -> int:
    """Read a file size, returning zero with a warning if metadata is unreadable."""
    try:
        return path.stat().st_size
    except OSError as exc:
        print(f"WARNING: Could not read size for {path}: {exc}")
        return 0


def build_inventory(root: Path, folders: Iterable[Path], csv_files: list[Path]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Build per-file inventory and per-top-level-folder summary dataframes."""
    records: list[dict[str, object]] = []
    folder_totals = {folder.name: {"count": 0, "bytes": 0} for folder in folders}

    for path in csv_files:
        relative = path.relative_to(root)
        attack_folder = relative.parts[0] if len(relative.parts) > 1 else ""
        size_bytes = safe_size_bytes(path)
        records.append(
            {
                "attack_folder": attack_folder,
                "relative_path": relative.as_posix(),
                "filename": path.name,
                "size_mb": size_bytes / (1024**2),
            }
        )
        if attack_folder in folder_totals:
            folder_totals[attack_folder]["count"] += 1
            folder_totals[attack_folder]["bytes"] += size_bytes

    inventory = pd.DataFrame.from_records(
        records,
        columns=["attack_folder", "relative_path", "filename", "size_mb"],
    )
    summary = pd.DataFrame.from_records(
        [
            {
                "attack_folder": folder.name,
                "csv_file_count": folder_totals[folder.name]["count"],
                "total_size_mb": folder_totals[folder.name]["bytes"] / (1024**2),
            }
            for folder in folders
        ],
        columns=["attack_folder", "csv_file_count", "total_size_mb"],
    )
    return inventory, summary


def read_first_valid_csv(csv_files: Iterable[Path]) -> tuple[Path | None, pd.DataFrame | None]:
    """Read only SAMPLE_ROWS from the first alphabetically ordered readable CSV."""
    for path in csv_files:
        try:
            sample = pd.read_csv(path, nrows=SAMPLE_ROWS)
            if len(sample.columns) == 0:
                print(f"WARNING: Skipping CSV with no columns: {path}")
                continue
            return path, sample
        except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError, OSError, ValueError) as exc:
            print(f"WARNING: Could not inspect {path}: {type(exc).__name__}: {exc}")
        except Exception as exc:  # Keep one corrupt file from stopping inventory creation.
            print(f"WARNING: Unexpected error while inspecting {path}: {type(exc).__name__}: {exc}")
    return None, None


def find_label_column(columns: Iterable[object]) -> object | None:
    """Find the first candidate label name in the specified priority order."""
    column_list = list(columns)
    for candidate in LABEL_CANDIDATES:
        if candidate in column_list:
            return candidate
    return None


def print_sample_report(path: Path, sample: pd.DataFrame) -> None:
    """Print schema, label evidence, preview, and concise data-quality checks."""
    print("\nFIRST VALID CSV SAMPLE")
    print(f"Complete file path: {path.resolve()}")
    print(f"Sampled dataframe shape: {sample.shape}")
    print(f"Total number of columns: {len(sample.columns)}")
    print(f"Complete ordered column list: {list(sample.columns)}")

    print("\nPANDAS DTYPES")
    for column, dtype in sample.dtypes.items():
        print(f"- {column}: {dtype}")

    print("\nFIRST 5 ROWS")
    print(sample.head(5).to_string(index=False))

    label_column = find_label_column(sample.columns)
    print("\nLABEL COLUMN CHECK")
    if label_column is None:
        print("No explicit label column found in the inspected CSV. Folder names may represent the attack labels.")
    else:
        print(f"Label column found: {label_column}")
        print("Sample value counts (including NaN):")
        print(sample[label_column].value_counts(dropna=False).to_string())

    missing_by_column = sample.isna().sum()
    missing_by_column = missing_by_column[missing_by_column > 0]
    numeric = sample.select_dtypes(include="number")
    numeric_values = numeric.to_numpy().ravel()
    positive_inf = sum(1 for value in numeric_values if math.isinf(value) and value > 0)
    negative_inf = sum(1 for value in numeric_values if math.isinf(value) and value < 0)
    duplicate_rows = int(sample.duplicated().sum())

    print("\nSAMPLE DATA QUALITY SUMMARY")
    print(f"Missing/NaN cells: {int(sample.isna().sum().sum())}")
    print(f"Columns with missing/NaN values: {missing_by_column.to_dict()}")
    print(f"Positive infinity values (numeric columns only): {positive_inf}")
    print(f"Negative infinity values (numeric columns only): {negative_inf}")
    print(f"Duplicate rows: {duplicate_rows}")


def save_schema(sample: pd.DataFrame | None) -> None:
    """Save the sampled schema, or a header-only report when no CSV is readable."""
    if sample is None:
        schema = pd.DataFrame(columns=["column_index", "column_name", "dtype"])
    else:
        schema = pd.DataFrame(
            {
                "column_index": range(len(sample.columns)),
                "column_name": [str(column) for column in sample.columns],
                "dtype": [str(dtype) for dtype in sample.dtypes],
            }
        )
    schema.to_csv(SCHEMA_PATH, index=False, encoding="utf-8")


def main() -> int:
    """Inspect the dataset without modifying any source file."""
    if not DATASET_ROOT.is_dir():
        print(f"ERROR: Dataset directory does not exist: {DATASET_ROOT}")
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    folders = sorted_top_level_folders(DATASET_ROOT)
    csv_files = sorted_csv_files(DATASET_ROOT)
    inventory, folder_summary = build_inventory(DATASET_ROOT, folders, csv_files)

    print("TOP-LEVEL DATASET FOLDERS")
    for index, row in enumerate(folder_summary.itertuples(index=False), start=1):
        print(
            f"{index:02d}. {row.attack_folder:<35} "
            f"CSV files: {row.csv_file_count:<5} Size: {row.total_size_mb:.2f} MB"
        )

    total_bytes = sum(safe_size_bytes(path) for path in csv_files)
    print("\nDATASET TOTALS")
    print(f"Total number of attack/label folders: {len(folders)}")
    print(f"Total number of CSV files: {len(csv_files)}")
    print(f"Total dataset CSV size: {total_bytes / (1024**3):.3f} GB")

    inspected_path, sample = read_first_valid_csv(csv_files)
    if inspected_path is None or sample is None:
        print("\nERROR: No readable, non-empty CSV file was found for schema inspection.")
    else:
        print_sample_report(inspected_path, sample)

    inventory.to_csv(INVENTORY_PATH, index=False, encoding="utf-8", float_format="%.6f")
    folder_summary.to_csv(FOLDER_SUMMARY_PATH, index=False, encoding="utf-8", float_format="%.6f")
    save_schema(sample)

    print("\nGENERATED REPORTS")
    print(f"- {INVENTORY_PATH.resolve()}")
    print(f"- {FOLDER_SUMMARY_PATH.resolve()}")
    print(f"- {SCHEMA_PATH.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
