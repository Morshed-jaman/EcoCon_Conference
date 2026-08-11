"""Step 2: validate labels, stream record counts, and audit CICIoT2023 schemas."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Iterable

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_ROOT = PROJECT_ROOT / "CSV"
RESULTS_DIR = PROJECT_ROOT / "results"

FAMILY_MAPPING: dict[str, tuple[str, ...]] = {
    "Benign": ("Benign_Final",),
    "DDoS": (
        "DDoS-ACK_Fragmentation", "DDoS-HTTP_Flood", "DDoS-ICMP_Flood",
        "DDoS-ICMP_Fragmentation", "DDoS-PSHACK_FLOOD", "DDoS-RSTFINFLOOD",
        "DDoS-SlowLoris", "DDoS-SYN_Flood", "DDoS-SynonymousIP_Flood",
        "DDoS-TCP_Flood", "DDoS-UDP_Flood", "DDoS-UDP_Fragmentation",
    ),
    "DoS": ("DoS-HTTP_Flood", "DoS-SYN_Flood", "DoS-TCP_Flood", "DoS-UDP_Flood"),
    "Mirai": ("Mirai-greeth_flood", "Mirai-greip_flood", "Mirai-udpplain"),
    "Recon": (
        "Recon-HostDiscovery", "Recon-OSScan", "Recon-PingSweep",
        "Recon-PortScan", "VulnerabilityScan",
    ),
    "Spoofing": ("DNS_Spoofing", "MITM-ArpSpoofing"),
    "BruteForce": ("DictionaryBruteForce",),
    "Web": (
        "Backdoor_Malware", "BrowserHijacking", "CommandInjection",
        "SqlInjection", "Uploading_Attack", "XSS",
    ),
}

REFERENCE_COLUMNS = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum",
    "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]

STEP2_FILES = {
    "mapping": RESULTS_DIR / "attack_family_mapping.csv",
    "file_counts": RESULTS_DIR / "file_record_counts.csv",
    "fine_counts": RESULTS_DIR / "fine_label_counts.csv",
    "family_counts": RESULTS_DIR / "family_counts.csv",
    "schema_audit": RESULTS_DIR / "schema_audit.csv",
    "summary": RESULTS_DIR / "step2_dataset_audit.txt",
}


def sort_key(value: str | Path) -> tuple[str, str]:
    text = value.as_posix() if isinstance(value, Path) else value
    return text.casefold(), text


def discover_folders() -> list[str]:
    if not DATASET_ROOT.is_dir():
        raise FileNotFoundError(f"Dataset root does not exist: {DATASET_ROOT}")
    return sorted((path.name for path in DATASET_ROOT.iterdir() if path.is_dir()), key=sort_key)


def validate_mapping(discovered: list[str]) -> dict[str, str]:
    mapped_labels = [label for labels in FAMILY_MAPPING.values() for label in labels]
    duplicates = sorted((label for label, count in Counter(mapped_labels).items() if count > 1), key=sort_key)
    unmapped = sorted(set(discovered) - set(mapped_labels), key=sort_key)
    missing_on_disk = sorted(set(mapped_labels) - set(discovered), key=sort_key)
    errors = []
    if duplicates:
        errors.append(f"Folders mapped more than once: {duplicates}")
    if unmapped:
        errors.append(f"Real folders not mapped: {unmapped}")
    if missing_on_disk:
        errors.append(f"Mapping entries absent from disk: {missing_on_disk}")
    if errors:
        raise RuntimeError("MAPPING VALIDATION: FAIL\n" + "\n".join(errors))

    lookup = {label: family for family, labels in FAMILY_MAPPING.items() for label in labels}
    print("MAPPING VALIDATION: PASS")
    print(f"Mapped folders: {len(mapped_labels)}/{len(discovered)}")
    print(f"Families: {len(FAMILY_MAPPING)}")
    for family, labels in FAMILY_MAPPING.items():
        print(f"- {family}: {len(labels)} fine-grained class(es)")
    return lookup


def discover_csv_files(folders: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for folder in folders:
        files.extend(
            path for path in (DATASET_ROOT / folder).rglob("*")
            if path.is_file() and path.suffix.lower() == ".csv"
        )
    return sorted(files, key=lambda path: sort_key(path.relative_to(DATASET_ROOT)))


def read_header(path: Path) -> tuple[list[str], str]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            try:
                return next(csv.reader(handle, strict=True)), ""
            except StopIteration:
                return [], "Empty file"
    except (OSError, UnicodeError, csv.Error) as exc:
        return [], f"{type(exc).__name__}: {exc}"


def audit_schema(path: Path) -> dict[str, object]:
    header, error = read_header(path)
    missing = [column for column in REFERENCE_COLUMNS if column not in header]
    extra = [column for column in header if column not in REFERENCE_COLUMNS]
    return {
        "relative_path": path.relative_to(DATASET_ROOT).as_posix(),
        "column_count": len(header),
        "schema_matches_reference": not error and header == REFERENCE_COLUMNS,
        "missing_columns": "|".join(missing),
        "extra_columns": "|".join(extra),
        "order_matches": not error and header == REFERENCE_COLUMNS,
        "read_error": error,
    }


def count_records(path: Path, expected_columns: int) -> tuple[int, list[str], str]:
    """Stream logical CSV records and validate every record's field count."""
    count = 0
    warnings: list[str] = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                next(reader)
            except StopIteration:
                return 0, warnings, "Empty file"
            for line_number, row in enumerate(reader, start=2):
                if len(row) != expected_columns:
                    warnings.append(
                        f"Malformed record at logical row {line_number}: "
                        f"expected {expected_columns} fields, found {len(row)}"
                    )
                count += 1
    except (OSError, UnicodeError, csv.Error) as exc:
        return count, warnings, f"{type(exc).__name__}: {exc}"
    return count, warnings, ""


def audit_files(csv_files: list[Path], lookup: dict[str, str]) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    file_rows = []
    schema_rows = []
    count_errors: list[str] = []
    print(f"\nAuditing {len(csv_files)} CSV files by streaming records...")
    for index, path in enumerate(csv_files, start=1):
        relative = path.relative_to(DATASET_ROOT)
        fine_label = relative.parts[0]
        schema_row = audit_schema(path)
        schema_rows.append(schema_row)
        row_count, row_warnings, count_error = count_records(path, len(REFERENCE_COLUMNS))
        count_errors.extend(f"{relative.as_posix()}: {warning}" for warning in row_warnings)
        if count_error:
            count_errors.append(f"{relative.as_posix()}: {count_error}")
        try:
            size_mb = path.stat().st_size / (1024 ** 2)
        except OSError as exc:
            size_mb = 0.0
            count_errors.append(f"{relative.as_posix()}: size read failed: {exc}")
        file_rows.append({
            "attack_folder": fine_label,
            "family": lookup[fine_label],
            "relative_path": relative.as_posix(),
            "filename": path.name,
            "row_count": row_count,
            "size_mb": size_mb,
        })
        if index % 25 == 0 or index == len(csv_files):
            print(f"  Processed {index}/{len(csv_files)} files")

    fatal_errors = [error for error in count_errors if "Malformed record" not in error]
    if fatal_errors:
        raise RuntimeError("RECORD COUNTING: FAIL\n" + "\n".join(fatal_errors))
    if count_errors:
        print("\nRECORD STRUCTURE WARNINGS (records retained in exact counts):")
        for error in count_errors:
            print(f"- {error}")
    return (
        pd.DataFrame(file_rows),
        pd.DataFrame(schema_rows, columns=[
            "relative_path", "column_count", "schema_matches_reference",
            "missing_columns", "extra_columns", "order_matches", "read_error",
        ]),
        count_errors,
    )


def validate_schema_audit(schema_df: pd.DataFrame) -> bool:
    inconsistent = schema_df.loc[~schema_df["schema_matches_reference"]]
    if inconsistent.empty:
        print("\nSCHEMA CONSISTENCY: PASS")
        return True
    print("\nSCHEMA CONSISTENCY: FAIL")
    for row in inconsistent.itertuples(index=False):
        print(f"- {row.relative_path}: columns={row.column_count}, missing={row.missing_columns}, "
              f"extra={row.extra_columns}, order_matches={row.order_matches}, error={row.read_error}")
    return False


def aggregate_counts(file_df: pd.DataFrame, folders: list[str], lookup: dict[str, str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    total_records = int(file_df["row_count"].sum())
    fine = file_df.groupby("attack_folder", as_index=False, sort=False).agg(
        csv_file_count=("relative_path", "count"),
        record_count=("row_count", "sum"),
        total_size_mb=("size_mb", "sum"),
    ).rename(columns={"attack_folder": "fine_label"})
    missing_counts = sorted(set(folders) - set(fine["fine_label"]), key=sort_key)
    if missing_counts:
        raise RuntimeError(f"Folders containing no CSV files: {missing_counts}")
    fine.insert(1, "family", fine["fine_label"].map(lookup))
    fine["percentage_of_dataset"] = fine["record_count"] / total_records * 100
    fine = fine.sort_values(["record_count", "fine_label"], ascending=[False, True], kind="stable").reset_index(drop=True)

    family = fine.groupby("family", as_index=False, sort=False).agg(
        fine_label_count=("fine_label", "count"),
        csv_file_count=("csv_file_count", "sum"),
        record_count=("record_count", "sum"),
        total_size_mb=("total_size_mb", "sum"),
    )
    family["percentage_of_dataset"] = family["record_count"] / total_records * 100
    family = family[["family", "fine_label_count", "csv_file_count", "record_count", "percentage_of_dataset", "total_size_mb"]]
    family = family.sort_values(["record_count", "family"], ascending=[False, True], kind="stable").reset_index(drop=True)
    return fine, family


def mapping_dataframe() -> pd.DataFrame:
    return pd.DataFrame(
        [(label, family) for family, labels in FAMILY_MAPPING.items() for label in labels],
        columns=["fine_label", "family"],
    )


def format_report(folders: list[str], file_df: pd.DataFrame, fine_df: pd.DataFrame,
                  family_df: pd.DataFrame, mapping_pass: bool, schema_pass: bool,
                  record_warnings: list[str]) -> str:
    total_records = int(file_df["row_count"].sum())
    total_size_mb = float(file_df["size_mb"].sum())
    smallest_family = family_df.sort_values(["record_count", "family"], ascending=[True, True]).iloc[0]
    largest_family = family_df.sort_values(["record_count", "family"], ascending=[False, True]).iloc[0]
    ratio = float(largest_family["record_count"] / smallest_family["record_count"])
    smallest_fine = fine_df.sort_values(["record_count", "fine_label"], ascending=[True, True]).head(10)

    lines = [
        "EcoCon-IDS CICIoT2023 Step 2 Dataset Audit",
        "=" * 48,
        f"Total top-level folders: {len(folders)}",
        f"Total fine-grained attacks: {len(folders) - 1}",
        f"Benign class count: {len(FAMILY_MAPPING['Benign'])}",
        f"Total CSV files: {len(file_df)}",
        f"Total records: {total_records}",
        f"Total size: {total_size_mb / 1024:.3f} GB ({total_size_mb:.3f} MB)",
        f"Number of feature columns: {len(REFERENCE_COLUMNS)}",
        "Explicit label column present? No",
        f"Mapping validation result: {'PASS' if mapping_pass else 'FAIL'}",
        f"Schema validation result: {'PASS' if schema_pass else 'FAIL'}",
        "",
        "FINE-LABEL COUNTS",
        "fine_label | family | records",
    ]
    lines.extend(f"{row.fine_label} | {row.family} | {int(row.record_count)}" for row in fine_df.itertuples(index=False))
    lines.extend(["", "FAMILY COUNTS", "family | fine-label count | records | percentage"])
    lines.extend(
        f"{row.family} | {int(row.fine_label_count)} | {int(row.record_count)} | {row.percentage_of_dataset:.6f}%"
        for row in family_df.itertuples(index=False)
    )
    lines.extend([
        "", "SMALLEST FAMILY:", f"{smallest_family['family']}, {int(smallest_family['record_count'])}",
        "", "LARGEST FAMILY:", f"{largest_family['family']}, {int(largest_family['record_count'])}",
        "", "IMBALANCE RATIO:", f"{ratio:.6f}",
        "", "10 SMALLEST FINE-GRAINED CLASSES", "fine_label | family | records",
    ])
    lines.extend(f"{row.fine_label} | {row.family} | {int(row.record_count)}" for row in smallest_fine.itertuples(index=False))
    lines.extend(["", "RECORD STRUCTURE WARNINGS"])
    if record_warnings:
        lines.extend(record_warnings)
    else:
        lines.append("None")
    return "\n".join(lines) + "\n"


def save_outputs(file_df: pd.DataFrame, fine_df: pd.DataFrame, family_df: pd.DataFrame,
                 schema_df: pd.DataFrame, report: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    mapping_dataframe().to_csv(STEP2_FILES["mapping"], index=False, encoding="utf-8")
    file_df.to_csv(STEP2_FILES["file_counts"], index=False, encoding="utf-8", float_format="%.6f")
    fine_df.to_csv(STEP2_FILES["fine_counts"], index=False, encoding="utf-8", float_format="%.6f")
    family_df.to_csv(STEP2_FILES["family_counts"], index=False, encoding="utf-8", float_format="%.6f")
    schema_df.to_csv(STEP2_FILES["schema_audit"], index=False, encoding="utf-8")
    STEP2_FILES["summary"].write_text(report, encoding="utf-8")


def main() -> int:
    folders = discover_folders()
    lookup = validate_mapping(folders)
    csv_files = discover_csv_files(folders)
    if not csv_files:
        raise RuntimeError("No CSV files found.")
    file_df, schema_df, record_warnings = audit_files(csv_files, lookup)
    schema_pass = validate_schema_audit(schema_df)
    fine_df, family_df = aggregate_counts(file_df, folders, lookup)
    report = format_report(folders, file_df, fine_df, family_df, True, schema_pass, record_warnings)
    save_outputs(file_df, fine_df, family_df, schema_df, report)
    print(f"\nTOTAL RECORDS: {int(file_df['row_count'].sum())}")
    print("\n" + report)
    print("GENERATED STEP-2 REPORTS")
    for path in STEP2_FILES.values():
        print(f"- {path.resolve()}")
    if not schema_pass:
        raise RuntimeError("Schema inconsistencies were found; see schema_audit.csv.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
