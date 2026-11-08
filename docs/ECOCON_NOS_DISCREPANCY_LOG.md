# EcoCon-NOS Discrepancy Log

| Files involved | Conflict | Likely reason | Publication decision |
|---|---|---|---|
| `paper_assets/data/key_numbers.json`; `processed/modeling_pool.parquet`; `results/closed_set_split_counts.csv`; `results/duplicate_audit.txt` | Historical derivative reported `modeling_pool_rows: 0`; corrected to 612,115 in checklist fixes 11–18. Verified lineage is 637,892 - 25,777 = 612,115 and split counts sum to 612,115. | Step-9 zero-column Parquet read lost the row count; now reads feature_hash. | Use 612,115; never publish 0. |
| `results/ecocon_nos_efficiency.csv`; `tools/refresh_ecocon_nos_efficiency.py`; `paper_assets/audit/efficiency_status.txt` | A NOS timing CSV exists, but the corrected refresh did not complete and timing accounting is declared inconsistent. | Historical benchmark mixed timing scopes; correction timed out. | Do not quote NOS efficiency values; status is not publication-safe. |
| Prompt wording; `results/ecocon_nos_success_criteria.json` | Prompt says expected selections/results approximately; artifacts provide exact values. | Prompt intentionally contains rounded expectations. | Use exact artifacts throughout. |

No frozen result artifact was modified to resolve a discrepancy. Checklist fixes update derived tables, summaries and their generators only.
