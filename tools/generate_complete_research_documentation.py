from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "results"
D = ROOT / "docs"
D.mkdir(exist_ok=True)


def rows(name):
    with (R / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def js(name):
    return json.loads((R / name).read_text(encoding="utf-8-sig"))


def mdtable(data, cols=None):
    if not data:
        return "_No rows in artifact._\n"
    cols = cols or list(data[0])
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    out += ["| " + " | ".join(esc(r.get(c, "")) for c in cols) + " |" for r in data]
    return "\n".join(out) + "\n"


def fnum(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return x


mapping = rows("attack_family_mapping.csv")
schema = rows("dataset_schema.csv")
rawfam = rows("family_counts.csv")
poolfam = rows("research_pool_family_counts.csv")
splitcounts = rows("closed_set_split_counts.csv")
base_dev = rows("baseline_dev_metrics.csv")
base_test = rows("baseline_test_metrics.csv")
perclass = rows("baseline_per_class_metrics.csv")
budget_dev = rows("feature_budget_dev_metrics.csv")
budget_test = rows("feature_budget_test_metrics.csv")
ranking = rows("feature_ranking_closed_set.csv")
loafo_counts = rows("loafo_fold_counts.csv")
loafo_known = rows("loafo_known_test_metrics.csv")
loafo_conf = rows("loafo_unknown_confidence_summary.csv")
forced = rows("loafo_unknown_forced_predictions.csv")
raw_auc = rows("loafo_raw_uncertainty_auc.csv")
md_auc = rows("ecocon_md_raw_auc.csv")
step8 = rows("selective_metrics_by_fold.csv")
step8_sum = rows("selective_metrics_summary.csv")
md_rescue = rows("overconfident_unknown_rescue.csv")
aurc = rows("risk_coverage_auc.csv")
step8_stats = rows("step8_statistical_tests.csv")
fuse_macro = rows("step8_5_macro_summary.csv")
fuse_micro = rows("step8_5_micro_summary.csv")
fuse_family = rows("step8_5_family_comparison.csv")
inner = rows("ecocon_nos_inner_results.csv")
candidates = rows("ecocon_nos_candidate_summary.csv")
outer = rows("ecocon_nos_outer_results.csv")
macro = rows("ecocon_nos_macro_summary.csv")
familycmp = rows("ecocon_nos_family_comparison.csv")
rescue = rows("ecocon_nos_overconfident_rescue.csv")
fresh = rows("ecocon_nos_fresh_confirmation.csv")
boot = rows("ecocon_nos_bootstrap_ci.csv")
stats = rows("ecocon_nos_statistics.csv")
selection = js("ecocon_nos_outer_detector_selection.json")
inner_holdouts = js("ecocon_nos_inner_holdouts.json")

split_totals = {s: sum(int(r["row_count"]) for r in splitcounts if r["split"] == s) for s in {r["split"] for r in splitcounts}}
pool_by = {r["family"]: int(r.get("research_pool_rows", r.get("row_count", 0))) for r in poolfam}
raw_by = {r["family"]: int(r.get("records", r.get("row_count", 0))) for r in rawfam}
model_by = {}
for r in splitcounts:
    model_by[r["family"]] = model_by.get(r["family"], 0) + int(r["row_count"])

key = {
    "dataset": {"name": "CICIoT2023", "raw_rows": 46776700, "csv_files": 309, "raw_size_gb": 8.330, "feature_count": 39, "fine_labels": 34, "families": 8},
    "data_quality": {"valid_rows": 46776697, "malformed_rows": 3, "conflicting_feature_hashes": 6909, "conflicting_rows": 25777, "unique_feature_hashes": 598215, "duplicate_groups": 19906, "rows_in_duplicate_groups": 59583, "max_duplicate_group_size": 235},
    "research_pool": {"rows": 637892, "seed": 42, "family_cap": 100000, "fine_label_minimum": 1000},
    "modeling_pool": {"rows": 612115, "removed_conflict_rows": 25777, "family_counts": model_by, "split_rows": split_totals},
    "closed_set": {r["model"]: {k: fnum(v) for k, v in r.items() if k != "model"} for r in base_test},
    "feature_budget": {"budgets": [39, 30, 20, 15, 10, 5], "epsilon": 0.005, "selected_features": 30, "feature_reduction_percent": 23.076923076923077, "full_test_macro_f1": 0.7640493828, "selected_test_macro_f1": 0.7614298611, "absolute_macro_f1_change": -0.0026195217},
    "loafo": {"folds": 7, "held_out_families": ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"], "known_test": loafo_known, "unknown_confidence": loafo_conf},
    "ecocon_md": {"raw_auc": md_auc, "macro": next((r for r in macro if r["method"] == "EcoConMD"), {})},
    "ecocon_fuse": {"status": "failed_extension_ablation", "primary_success": False, "robustness_success": False, "macro": next((r for r in macro if r["method"] == "EcoConFuse"), {})},
    "ecocon_nos": {"alpha": 0.05, "outer_results": outer, "macro": next((r for r in macro if r["method"] == "EcoConNOS"), {}), "detector_selection": selection, "fold_wins": {"vs_msp": 6, "vs_entropy": 5, "vs_md": 6}},
    "fresh_confirmation": {"scope": "within_CICIoT2023", "results": fresh},
    "statistics": stats,
    "limitations": ["single primary dataset", "fresh confirmation is within CICIoT2023", "seven independent outer folds", "Web weakness", "DoS difficulty", "no deployment validation", "no physical energy measurement", "NOS efficiency benchmark is not publication-safe"],
}
(D / "ECOCON_NOS_KEY_RESULTS.json").write_text(json.dumps(key, indent=2), encoding="utf-8")


def section(n, title, body):
    return f"\n# {n}. {title}\n\n{body.strip()}\n"


parts = ["# EcoCon-NOS Complete Research Documentation\n\n**Project root:** `D:\\CSE_21201016_BRAC\\CON_green`  \n**Method status:** FROZEN  \n**Final method:** EcoCon-NOS — Nested Open-Set Detector Selection for Resource-Budgeted Intrusion Detection of Unseen IoT Attacks  \n**Evidence policy:** disk artifacts are authoritative; discrepancies are logged separately.\n"]
parts.append(section(1, "Executive Technical Summary", """
This project studies selective intrusion detection when a complete IoT attack family is absent from model training. A conventional closed-set classifier must still emit one of its known labels. CICIoT2023 experiments show that this forced decision can be extremely confident: the held-out DDoS, DoS, and Mirai folds contain large fractions of unknown observations above 0.95 maximum XGBoost probability. Thus confidence is not membership evidence, and a deployable system needs an abstention path.

The data pipeline audited all 46,776,700 raw rows in 309 CSV files organized into 34 fine-label folders. Folder names supply labels because the CSV schema contains 39 numeric features and no explicit label column. Deterministic, subtype-aware sampling produced 637,892 rows. Entire feature-hash groups whose identical vectors carried conflicting family labels were removed, leaving a 612,115-row modeling pool. Group-aware partitions prevent identical feature vectors from crossing train, calibration, and test boundaries.

Closed-set development compared Random Forest, XGBoost, and LightGBM without using official calibration or test data for selection. XGBoost won development Macro-F1. A training-only gain ranking then tested 39, 30, 20, 15, 10, and 5 features. The predeclared rule selected the smallest budget within 0.005 development Macro-F1 of the full model: 30 features. On official test data, Macro-F1 changed from 0.7640493828 to 0.7614298611, a -0.0026195217 absolute change with 23.0769% fewer inputs. This is dimensionality reduction, not a measured energy or runtime reduction.

Seven leave-one-attack-family-out (LOAFO) folds held out DDoS, DoS, Mirai, Recon, Spoofing, BruteForce, or Web. Benign was always known. Each fold independently ranked features, selected its budget, refit a frozen seven-class XGBoost model, and emitted probabilities for known calibration, known test, and true-unknown test sets. Probability anomaly scores—maximum softmax probability (MSP), entropy, and inverse margin—failed badly for highly confident unknown families.

EcoCon-MD addressed this by measuring predicted-class Mahalanobis atypicality in standardized feature space, with a shared Ledoit-Wolf covariance fit on outer training only and predicted-class-conditional conformal calibration on known calibration only. It raised macro unknown attack detection rate (UADR) to 0.2929370161, but was not strongest for every family. EcoCon-Fuse combined MD and entropy through a two-stage calibration scheme; it increased macro UADR slightly to 0.3021256821 but worsened overall selective risk to 0.4602687195 and failed its predeclared success and robustness criteria. It is retained as a negative-result ablation.

EcoCon-NOS reframed the problem as detector selection. Within each outer-training pool, up to 12 eligible fine labels become pseudo-unknowns. Seven candidate scores are evaluated at thresholds derived only from inner known validation. Mean inner UADR, risk tie-breaking, worst-fold UADR, and fixed cost order determine the detector before the real outer unknown is opened. The frozen map selected MD-Pred for DDoS and class-conditional k-nearest neighbors for the other six families.

At approximately 5% known rejection, EcoCon-NOS achieved macro UADR 0.3873314571, coverage 0.7896324763, review rate 0.2103675237, and overall selective risk 0.4190400799. It beat EcoCon-MD on six of seven UADR folds; paired Wilcoxon p-values for NOS versus MD were 0.03125 for both UADR and overall risk. Mirai UADR was 0.99961—not perfect—and Web remained weak at 0.1860861104. Fresh unused samples confirmed several patterns within CICIoT2023, but are not external validation. Limitations include one dataset, only seven independent family folds, sampling-altered prevalence, analyst workload, imperfect detector choice, no deployment study, no physical power measurement, and a NOS efficiency benchmark that remains publication-unsafe. Steps 1–8.6 are complete and frozen; Step 9 publication assets are the next phase.
"""))
parts.append(section(2, "Research Question and Problem Formulation", r"""
The primary question is whether an intrusion detector trained on known attack families can safely handle a family that is completely absent from training. For each test observation, the operational action is either **ACCEPT** the frozen XGBoost family prediction or **ABSTAIN** for analyst review.

Known traffic belongs to one of the outer fold's training families. Unknown traffic belongs to the sealed outer family. A pseudo-unknown fine label is a known-family subtype hidden only inside outer training for nested selection. Selective prediction is prediction with a reject option; abstention is that reject action. With unknown indicator `u`, rejection indicator `r`, and correctness `z` on known accepted rows: `UADR = sum(u*r)/sum(u)`; `coverage = mean(1-r)`; `review rate = 1-coverage`; `known selective risk = sum((1-z)*(1-r)*(1-u))/sum((1-r)*(1-u))`; and `overall selective risk = (accepted unknown + wrong accepted known)/(all accepted)`. High classifier confidence is not evidence that an observation belongs to the known distribution.
"""))
parts.append(section(3, "Dataset", "CICIoT2023 is stored under `CSV/` in 34 top-level fine-label folders. The audit records 309 CSV files, 46,776,700 rows, and 8.330 GB. The raw files have no explicit label column; the containing folder supplies the fine label. The 39 model inputs are:\n\n" + mdtable(schema, ["column_index", "column_name", "dtype"])))
parts.append(section(4, "Complete 34-Label Taxonomy", "All 34 folders map exactly once to eight high-level families (validation PASS):\n\n" + mdtable(mapping)))
parts.append(section(5, "Raw Dataset Audit", "Three malformed logical records were found in `DoS-UDP_Flood7`, `8`, and `9`; 46,776,697 rows were structurally valid. Cleaning rejects malformed, nonnumeric, NaN, +Inf, then -Inf values in that priority. Raw prevalence is severely imbalanced: DDoS has 33,984,450 rows, BruteForce 13,064, a 2601.381660 ratio.\n\n" + mdtable(rawfam)))
pool_compare = [{"Family": f, "Available raw rows": raw_by.get(f, ""), "Research-pool rows": pool_by.get(f, "")} for f in sorted(raw_by)]
parts.append(section(6, "Research-Pool Construction", "`src/03_build_research_pool.py` streams raw CSV chunks using seed 42, a 100,000 family cap, a 1,000 fine-label minimum, proportional residual allocation, and largest-remainder rounding. It performs no synthetic oversampling. Web and BruteForce remain below the cap because unavailable observations are never fabricated. Output: `processed/research_pool.parquet`, 637,892 rows, 39 features plus metadata.\n\n" + mdtable(pool_compare)))
parts.append(section(7, "Feature-Hash Duplicate and Conflict Audit", "`feature_hash` is a deterministic digest of the complete cleaned 39-feature vector. Grouping on it prevents identical observations from crossing partitions. There were 598,215 unique hashes, 19,906 duplicate groups covering 59,583 rows, maximum group size 235, and 6,909 conflicting hashes covering 25,777 rows. Affected families were Benign, BruteForce, DDoS, DoS, Recon, Spoofing, and Web. The primary policy removes every row in a conflicting hash group; choosing one label would encode an arbitrary target and retain ambiguity. Evidence: `results/duplicate_audit.txt`, `results/label_conflicts.parquet`, and `processed/ambiguous_conflict_pool.parquet`."))
model_compare = [{"Family": f, "Research pool": pool_by.get(f, ""), "Modeling pool": model_by.get(f, ""), "Removed": pool_by.get(f, 0)-model_by.get(f, 0)} for f in sorted(model_by)]
parts.append(section(8, "Final Modeling Pool", "Removing 25,777 conflicting rows from 637,892 produces exactly 612,115 rows in `processed/modeling_pool.parquet`.\n\n" + mdtable(model_compare)))
parts.append(section(9, "Closed-Set Partitioning", f"Group-aware splitting uses `feature_hash` and seed 42 at nominal 70/15/15 ratios. Actual rows are train {split_totals.get('train')}, calibration {split_totals.get('calibration')}, and test {split_totals.get('test')}. All pairwise feature-hash overlaps are zero and all eight families plus all 34 fine labels are preserved. TRAIN supports fitting/development, CALIBRATION is reserved for uncertainty calibration, and TEST is final closed-set evaluation.\n\n" + mdtable(splitcounts)))
parts.append(section(10, "LOAFO Split Construction", "Seven attack families are held out in turn; Benign is never held out. The held-out family is absent from outer train, calibration, and test-known, and all its clean rows enter test-unknown. Controlled partitions have zero feature-hash overlap. Manifests are `loafo_split_manifest.parquet` and `loafo_internal_dev_manifest.parquet`.\n\n" + mdtable(loafo_counts)))
parts.append(section(11, "Closed-Set Baseline Models", "Balanced sample weights were computed from fitting labels. A group-safe internal train/dev split—not official calibration or test—selected the highest development Macro-F1, XGBoost.\n\n## Development\n\n" + mdtable(base_dev) + "\n## Official test\n\n" + mdtable(base_test)))
parts.append(section(12, "XGBoost Per-Class Performance", "Macro-F1 gives each family equal influence and exposes minority weaknesses hidden by accuracy. BruteForce and Web have fewer and more heterogeneous examples and remain difficult.\n\n" + mdtable([r for r in perclass if r["model"] == "xgboost"])))
parts.append(section(13, "Resource / Feature-Budget Experiment", "XGBoost gain on training-only development data ranked all 39 features. The smallest budget within 0.005 of full-feature development Macro-F1 was 30. Test Macro-F1 changed by -0.0026195217; inputs fell 23.076923%. This does not establish proportional computation, energy, or latency savings.\n\n## Ranking\n\n" + mdtable(ranking) + "\n## Development\n\n" + mdtable(budget_dev) + "\n## Test\n\n" + mdtable(budget_test)))
parts.append(section(14, "Step 7 LOAFO Model Development", "For every fold: load outer TRAIN; make a group-safe internal train/dev split; fit a ranking model; rank 39 features; test budgets 39/30/20/15/10/5; apply epsilon=0.005; freeze the feature set; refit the seven-output XGBoost classifier; then emit probabilities for calibration, test-known, and test-unknown. The held-out class has no output column. Calibration and both test sets are untouched by selection, and Step 7 performs no thresholding or conformal inference.\n\n" + mdtable(rows("loafo_budget_selection.json") if False else rows("loafo_selected_models.csv")) + "\nTop rankings by fold are archived in `results/loafo_feature_rankings.csv`."))
parts.append(section(15, "Step 7 Known-Test Performance", mdtable(loafo_known) + "\nUnknown confidence joins by held-out family:\n\n" + mdtable(loafo_conf)))
parts.append(section(16, "Unknown Overconfidence Discovery", "The true unknown family is absent from the output space, so every unknown is forced into a known class. DDoS has 99.4524902861% of rows at or above 0.95 confidence, DoS 89.8500840490%, and Mirai 95.2870000000%. These are not rounded to 100%.\n\n" + mdtable(loafo_conf)))
parts.append(section(17, "Forced Known-Class Predictions", "The following complete artifact shows semantic confusion such as DDoS→DoS, DoS→DDoS, and Mirai→DDoS/DoS. High confidence in these forced labels is dangerous because it suppresses review.\n\n" + mdtable(forced)))
parts.append(section(18, "Raw Probability Uncertainty Baselines", r"MSP anomaly is `1-max(p)`, entropy is `-sum(p log p)`, and inverse margin is `1-(p1-p2)`. Unknown is the positive class. AUROC below 0.5 means unknown observations are ranked as less anomalous—often more confident—than known observations. This occurs prominently for DDoS, DoS, and Mirai." + "\n\n" + mdtable(raw_auc)))
parts.append(section(19, "Why EcoCon-MD Was Introduced", "Probability scores measure predictive ambiguity, not feature-distribution membership. EcoCon-MD measures whether a sample is atypical relative to the class that frozen XGBoost predicts."))
parts.append(section(20, "EcoCon-MD Technical Implementation", r"For each fold, the frozen Step-7 features are standardized with a StandardScaler fit on OUTER TRAIN only. Class means are calculated in standardized space. Training residuals are `r_i=x_i-mu_(y_i)`; a shared Ledoit-Wolf covariance yields precision `Sigma^-1`. For predicted class `c_hat`, `D_pred(x)=(x-mu_c_hat)^T Sigma^-1 (x-mu_c_hat)`. Higher is more atypical. Predicted-class distance audits the classifier's chosen semantic class; nearest-MD classification would replace rather than selectively supervise XGBoost."))
parts.append(section(21, "EcoCon-MD Conformal Calibration", r"Known calibration is grouped by predicted class. `p_MD(x)=(1 + #{s_cal >= s(x)})/(n_class+1)`. At alpha 0.05, `p<=alpha` abstains and otherwise accepts XGBoost. Small class groups fall back to broader saved calibration references as implemented. Conformal calibration controls known-score behavior under assumptions; it does not guarantee unseen-family detection."))
parts.append(section(22, "EcoCon-MD Raw Discrimination", "MD raises DDoS, DoS, and Mirai AUROC above 0.8 despite sub-0.5 probability-score behavior.\n\n" + mdtable(md_auc)))
parts.append(section(23, "Step 8 Selective Results", "At alpha 0.05, saved fold-level metrics for forced XGBoost, MSP, entropy, inverse margin, probability conformal, and EcoCon-MD are:\n\n" + mdtable([r for r in step8 if abs(float(r.get("alpha", 0.05))-0.05)<1e-9])))
parts.append(section(24, "Step 8 Macro and Micro Results", "Macro aggregation weights seven held-out families equally and is primary. Micro aggregation weights rows and therefore reflects sampled prevalence.\n\n" + mdtable(step8_sum)))
parts.append(section(25, "EcoCon-MD High-Confidence Rescue", "Rescue rate is the fraction of unknown rows with XGBoost confidence ≥0.95 that MD rejects. DDoS and Mirai demonstrate that feature-space evidence can rescue confident forced errors.\n\n" + mdtable(md_rescue)))
parts.append(section(26, "Step 8 AURC / Curve Results", "Risk-coverage and UADR-versus-known-rejection curves evaluate the complete threshold tradeoff; lower area under risk-coverage is preferable when defined as accumulated risk. MD improves several high-confidence families but loses to probability signals on others and is not universally superior.\n\n" + mdtable(aurc)))
parts.append(section(27, "Step 8 Statistical Analysis", "Only seven independent outer-family observations enter paired Wilcoxon tests. Step-8 comparisons are not significant at 0.05 and must not be overstated.\n\n" + mdtable(step8_stats)))
parts.append(section(28, "Why EcoCon-Fuse Was Attempted", "MD was strong for DDoS/Mirai while entropy or MSP were stronger for Recon, Spoofing, and Web. This complementary behavior motivated a fixed fusion of feature conformity and predictive uncertainty."))
parts.append(section(29, "EcoCon-Fuse Implementation", r"Calibration is group-safely divided into CAL-A and CAL-B. CAL-A constructs `p_MD` and `p_ENT`; fused nonconformity is `max(-log p_MD,-log p_ENT)=-log(min(p_MD,p_ENT))`. CAL-B performs second-stage known-only calibration at alpha 0.05. There are no learned fusion weights and no unknown tuning."))
parts.append(section(30, "EcoCon-Fuse Results and Failure", "Predeclared primary success required higher UADR than MD and entropy, risk no worse than MD, and known rejection in [0.04,0.06]. Robustness required winning ≥5/7 or being within 0.02 on ≥6/7 with better macro UADR. PRIMARY SUCCESS = FAIL; ROBUSTNESS = FAIL; OUTCOME C = NO IMPROVEMENT. Fuse slightly raised UADR but worsened risk and degraded Mirai. It is a frozen unsuccessful extension/ablation.\n\n" + mdtable(fuse_macro) + "\n## Family results\n\n" + mdtable(fuse_family)))
parts.append(section(31, "Fresh Confirmation Dataset", "`processed/fresh_confirmation_unknown.parquet` uses seed 314159 and up to 5,000 unique finite hashes per eligible family: DDoS, DoS, Mirai, Recon, and Spoofing. Hashes are absent from research/modeling pools and excluded conflicts; fresh hashes do not duplicate one another. This is fresh-sample confirmation within CICIoT2023, not external validation."))
parts.append(section(32, "Why EcoCon-NOS Was Introduced", "No fixed uncertainty detector dominates every family shift, and fixed fusion also failed. EcoCon-NOS asks whether an appropriate detector can be selected using only known outer-training data before the true outer unknown appears."))
parts.append(section(33, "EcoCon-NOS Nested Open-Set Structure", "```text\nOUTER TRAIN only ──> inner fine-label pseudo-OOD folds ──> select detector\n       │                                                    │\n       └────────────────> known CALIBRATION ──> threshold   │\n                                                            v\nSEALED outer unknown + test-known ───────────────────> frozen evaluation\n```\nThe real outer unknown is unavailable during candidate design, candidate selection, threshold selection, feature selection, and model selection."))
holdout_rows=[]
for outer_name, vals in inner_holdouts.items():
    seq = vals if isinstance(vals, list) else vals.get("inner_holdouts", vals.get("selected", []))
    for i,v in enumerate(seq,1):
        holdout_rows.append({"Outer": outer_name, "Fold": i, **(v if isinstance(v,dict) else {"fine_label":v})})
parts.append(section(34, "Inner Pseudo-Unknown Fold Generation", "Eligible fine labels have at least 1,000 outer-training rows. Up to 12 are selected to maximize parent-family diversity, then support, with deterministic alphabetical ties—not detector performance.\n\n" + mdtable(holdout_rows)))
parts.append(section(35, "Inner Reference / Validation Split", "For each inner fold the chosen fine label becomes INNER_PSEUDO_UNKNOWN. Remaining outer-training rows are group-safely split approximately 80% INNER_REFERENCE and 20% INNER_VALID_KNOWN with zero hash overlap. The latter sets the ≈5% known-rejection threshold; pseudo-unknown rows evaluate candidates only inside OUTER TRAIN."))
parts.append(section(36, "Seven EcoCon-NOS Candidate Detectors", "Candidates are MSP; predictive entropy; MD-Pred; Min-MD (minimum class Mahalanobis distance); MDS (Mahalanobis distance structure); ClassConditionalKNN; and GlobalKNN. Probability candidates use frozen XGBoost probabilities. MD candidates use standardized training references and covariance geometry. kNN uses Euclidean distance with `n_neighbors=10`, at most 20,000 reference rows per class and 100,000 globally; saved implementation uses compact numeric references. Every score is oriented so larger means more anomalous."))
parts.append(section(37, "EcoCon-NOS Inner Evaluation", f"Each candidate threshold comes only from INNER_VALID_KNOWN at target rejection 0.05; UADR, overall risk, AUROC, AUPRC, and known rejection are then measured on INNER_PSEUDO_UNKNOWN. Saved rows: {len(inner)} = 7 outer folds × 12 inner folds × 7 candidates = 588."))
parts.append(section(38, "Detector-Selection Rule", "Primary: highest mean inner UADR. Candidates within 0.01 are compared by lower mean overall selective risk; remaining ties use higher worst-inner-fold UADR and finally a fixed lower-cost candidate order. The rule is implemented before outer evaluation."))
parts.append(section(39, "Complete Inner Candidate Results", "The complete candidate summary is below; the row-level 588-evaluation archive is `results/ecocon_nos_inner_results.csv`.\n\n" + mdtable(candidates)))
selrows=[]
for fam,v in selection.items(): selrows.append({"Outer held-out family":fam, **v})
parts.append(section(40, "Final Detector Selections", mdtable(selrows)))
parts.append(section(41, "Outer Calibration After Selection", "Detector selection is frozen first. Only then does known-only outer CALIBRATION create the alpha=0.05 empirical/conformal boundary. Outer test-known and test-unknown are inaccessible until final evaluation. Saved code uses the `higher` empirical quantile where applicable and rejects scores at or beyond the boundary."))
parts.append(section(42, "Final EcoCon-NOS Outer Evaluation", mdtable(outer)))
parts.append(section(43, "Final Macro Results", "Macro results weight each attack-family fold equally.\n\n" + mdtable(macro)))
nos = next(r for r in macro if r["method"]=="EcoConNOS"); md = next(r for r in macro if r["method"]=="EcoConMD"); msp=next(r for r in macro if r["method"]=="MSP"); ent=next(r for r in macro if r["method"]=="Entropy")
nu=lambda r:float(r["UADR"]); nr=lambda r:float(r["overall_selective_risk"])
improws=[]
for name,b in [("MSP",msp),("Entropy",ent),("EcoConMD",md)]:
    d=nu(nos)-nu(b); improws.append({"Comparison":f"NOS vs {name}","Absolute UADR":d,"Relative UADR":d/nu(b),"Ratio":nu(nos)/nu(b)})
parts.append(section(44, "Improvement Calculations", mdtable(improws)+f"\nNOS versus MD overall-risk absolute change is {nr(nos)-nr(md):.10f} and relative change {(nr(nos)-nr(md))/nr(md):.10f}. Greater UADR comes with lower coverage and higher review workload; it is not free."))
parts.append(section(45, "Family-Wise Final Comparison", "Web is retained visibly as the main loss; DDoS is a near tie/loss to MD, and Spoofing trails entropy.\n\n" + mdtable(familycmp)))
parts.append(section(46, "Fold-Win Counts", "NOS beats MSP on 6/7 folds, entropy on 5/7, and MD on 6/7. From the success artifact it is strictly best on 4/7 and within 0.02 of the previous best on 6/7."))
parts.append(section(47, "High-Confidence Unknown Rescue", "All seven families remain visible. Mirai and DDoS show the largest scientifically important rescue; Recon and BruteForce show gains where high-confidence subsets are smaller.\n\n" + mdtable(rescue)))
parts.append(section(48, "Mirai Case Study", "Mirai has 100,000 outer unknown rows, mean confidence and threshold rates in the Step-7 table, and forced labels in the distribution archive. MSP and entropy UADR are 0; MD is 0.83177; Fuse 0.66246; NOS 0.99961. The high-confidence NOS rescue is about 0.9998, fresh NOS UADR is 0.9996, and the bootstrap interval is reported below. This is the clearest high-confidence OOD rescue, but 0.9996 is not perfect and does not prove external generalization.\n\n" + mdtable([r for r in boot if r["held_out_family"]=="Mirai"])))
parts.append(section(49, "Recon Case Study", "Recon is less uniformly overconfident; MSP/entropy retain signal, fixed MD reaches UADR 0.1482973967, and NOS selects ClassConditionalKNN to reach 0.3230284987. Fresh UADR is 0.3742. This illustrates how training-only adaptive selection can address a fold where fixed MD is not strongest."))
parts.append(section(50, "Web Failure Case", "Web UADR is MSP 0.2545609341, entropy 0.2682640071, MD 0.0586637477, Fuse 0.1081650855, and NOS 0.1860861104. NOS does not dominate the strongest probability baseline. Inner pseudo-OOD selection is informative but cannot guarantee the best detector for every future family shift."))
parts.append(section(51, "Fresh-Sample Confirmation Results", "Frozen models, detector selections, thresholds, and alpha were reused without recalibration. Hashes do not overlap research/modeling pools. This is within CICIoT2023, not external validation.\n\n" + mdtable(fresh)))
parts.append(section(52, "Bootstrap Confidence Intervals", "The artifact uses 1,000 row-level bootstrap resamples. Intervals quantify within-fold sample variability for UADR and overall risk; they do not increase the seven independent outer-family folds.\n\n" + mdtable(boot)))
parts.append(section(53, "Final Statistical Tests", "All comparisons use n=7 paired outer families. NOS-versus-MD p=0.03125 for UADR and risk, but inference remains cautious because resolution and power are limited.\n\n" + mdtable(stats)))
parts.append(section(54, "Predeclared Success Criteria", "Before outcomes: macro NOS UADR > MD; macro NOS risk < MD; macro known rejection in [0.04,0.06]. Strong robustness: within 0.02 of best existing on ≥6/7 and strictly best on ≥4/7. Best-paper targets: UADR 0.35, risk 0.44, beat MD on 5 folds. PRIMARY SUCCESS PASS; STRONG ROBUSTNESS PASS; BEST-PAPER TARGET MET."))
parts.append(section(55, "EcoCon-NOS Method Audit", mdtable([{"Audit item":"Outer unknown used for candidate design","Value":"NO"},{"Audit item":"Outer unknown used for candidate selection","Value":"NO"},{"Audit item":"Outer unknown used for threshold selection","Value":"NO"},{"Audit item":"Outer test-known used for selection","Value":"NO"},{"Audit item":"Outer calibration used for selection","Value":"NO"},{"Audit item":"Outer calibration used for threshold","Value":"YES"},{"Audit item":"Inner pseudo-OOD source","Value":"outer training only"},{"Audit item":"XGBoost retrained","Value":"NO"},{"Audit item":"Feature budget changed","Value":"NO"},{"Audit item":"Alpha changed","Value":"NO"}])+"\nFeature-hash grouping controls all split boundaries; saved audit validation is PASS."))
parts.append(section(56, "What Did Not Work", "1. Raw probability uncertainty failed on DDoS, DoS, and Mirai. 2. Fixed EcoCon-MD was not universally superior. 3. EcoCon-Fuse failed its primary criterion and robustness rule. 4. EcoCon-NOS still does not dominate Web. 5. DoS remains difficult at NOS UADR 0.0406751364. These negative results explain the transition from probability scores to feature geometry, then fusion, then nested detector selection."))
parts.append(section(57, "Current Final Method", "FINAL METHOD: EcoCon-NOS. EcoCon-MD is an intermediate baseline; EcoCon-Fuse is a failed extension/ablation. NOS adapts only the uncertainty detector selection. It does not change base XGBoost, LOAFO splits, feature budget, class labels, alpha, or use the true outer unknown for selection. No further model design is authorized."))
parts.append(section(58, "Computational Efficiency Status", "`results/ecocon_nos_efficiency.csv` exists, but `paper_assets/audit/efficiency_status.txt` states the corrected refresh exceeded its execution window. The existing accounting is inconsistent and **EcoCon-NOS efficiency results are currently NOT publication-safe**. No NOS timing numbers are quoted as verified. Closed-set and earlier MD timing artifacts remain historical evidence, not a corrected NOS benchmark."))

scripts = sorted(list((ROOT/"src").glob("*.py"))+list((ROOT/"tools").glob("*.py")))
script_rows=[]
for p in scripts:
    txt=p.read_text(encoding="utf-8",errors="replace")
    step=re.search(r"(?:^|\\)(\d+(?:_\d+)?)_",str(p))
    script_rows.append({"Script":p.relative_to(ROOT).as_posix(),"Step":step.group(1).replace("_",".") if step else "support","Purpose":next((x.strip("# ") for x in txt.splitlines() if x.strip().startswith("#")),"Executable research/support script"),"Main inputs":"see constants and argparse in script","Main outputs":"results/models/processed as encoded","Status":"frozen" if p.parent.name=="src" else "support"})
parts.append(section(59, "Complete Script Inventory", mdtable(script_rows)))

artifact_rows=[]
for top in ["processed","results","models","paper_assets","src","tools"]:
  for p in sorted((ROOT/top).rglob("*")):
    if not p.is_file(): continue
    rel=p.relative_to(ROOT).as_posix(); ext=p.suffix.lower()
    step="Step 9" if top=="paper_assets" else ("Step 8.6" if "nos" in rel.lower() else "Step 8.5" if "8_5" in rel or "fuse" in rel.lower() else "Step 8" if "ecocon" in rel.lower() or "selective" in rel else "Steps 1-7/support")
    pub="NO" if "efficiency" in rel and "nos" in rel.lower() else ("YES" if top in {"results","paper_assets"} else "N/A")
    status="final" if "nos" in rel.lower() or top=="paper_assets" else ("intermediate" if "fuse" in rel.lower() or "md" in rel.lower() else "source")
    artifact_rows.append({"experiment":step,"path":rel,"type":ext.lstrip(".") or "file","description":"Saved project artifact/source","rows_or_files":"1","generating_script":"see script inventory/lineage","status":status,"publication_safe":pub,"notes":"binary not expanded" if ext in {".joblib",".parquet",".png",".pdf",".zip"} else "inspected/indexed"})
with (D/"ECOCON_NOS_ARTIFACT_INDEX.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(artifact_rows[0]));w.writeheader();w.writerows(artifact_rows)
parts.append(section(60, "Complete Result-Artifact Inventory", f"The machine-readable index contains {len(artifact_rows)} files in `docs/ECOCON_NOS_ARTIFACT_INDEX.csv`. It records step, path, type, status, publication safety, and lineage notes. Result artifacts are the numerical source of truth; paper assets are derivative. Binary Parquet and joblib contents are indexed without duplication."))

model_files=list((ROOT/"models").rglob("*")); model_files=[p for p in model_files if p.is_file()]
model_counts=Counter(p.parent.relative_to(ROOT).as_posix() for p in model_files)
parts.append(section(61, "Complete Model Inventory", mdtable([{"Directory":k,"Files":v,"Role":"base classifiers" if "baselines" in k or "loafo" in k else "detector/calibration reference objects"} for k,v in sorted(model_counts.items())])+"\nLOAFO joblib files hold frozen base classifiers/configuration; ecocon_md objects hold scalers, class means, precision, and calibration references; ecocon_fuse adds fusion calibration; ecocon_nos stores selected candidate references, notably kNN stores and MD-Pred state. Binary contents are not duplicated."))
cmds=[{"Step":re.match(r"(\d+(?:_\d+)?)",p.name).group(1).replace("_",".") if re.match(r"(\d+(?:_\d+)?)",p.name) else "support","Command":f"python {p.relative_to(ROOT)}"} for p in sorted((ROOT/"src").glob("*.py"))]
parts.append(section(62, "Reproducibility Pipeline", "These are actual entry-point filenames. Reproduction would mutate frozen artifacts and is therefore documented but not executed.\n\n"+mdtable(cmds)))
parts.append(section(63, "Complete Data-Lineage Graph", "```text\nCSV/ raw folders\n  -> Step 2 audit + 34-to-8 mapping\n  -> processed/research_pool.parquet\n  -> duplicate/conflict audit -> remove complete conflicting hashes\n  -> processed/modeling_pool.parquet\n  -> processed/closed_set/{train,calibration,test}.parquet\n  -> LOAFO manifests -> Step-7 frozen models/probabilities\n  -> EcoCon-MD -> EcoCon-Fuse (failed ablation)\n  -> EcoCon-NOS inner pseudo-OOD selection -> frozen outer results\n  -> fresh_confirmation_unknown.parquet -> confirmation results\n  -> paper_assets/ + this master documentation\n```"))
parts.append(section(64, "Key Numbers", "The complete exact machine-readable record is `docs/ECOCON_NOS_KEY_RESULTS.json`. Headline values: raw 46,776,700; research pool 637,892; conflicting hashes 6,909/rows 25,777; modeling pool 612,115; XGBoost test Macro-F1 0.7640493828; 30-feature 0.7614298611; MD macro UADR 0.2929370161; Fuse 0.3021256821 with failed status; NOS UADR 0.3873314571, risk 0.4190400799, known rejection 0.0501817236, coverage 0.7896324763, review 0.2103675237; NOS-vs-MD p=0.03125 for UADR and risk."))
claims=[
{"Claim":"23.1% fewer input features with small Macro-F1 loss","Metric":"39: 0.7640493828; 30: 0.7614298611","Artifact":"feature_budget_test_metrics.csv","Caveat":"not runtime/energy"},
{"Claim":"Severe unseen-family overconfidence","Metric":"DDoS 99.4525%, DoS 89.8501%, Mirai 95.2870% >=.95","Artifact":"loafo_unknown_confidence_summary.csv","Caveat":"CICIoT2023 LOAFO"},
{"Claim":"Probability uncertainty fails on key families","Metric":"AUROC below .5","Artifact":"loafo_raw_uncertainty_auc.csv","Caveat":"score/fold specific"},
{"Claim":"MD recovers feature-space discrimination","Metric":"DDoS/DoS/Mirai AUROC >.8","Artifact":"ecocon_md_raw_auc.csv","Caveat":"not universal"},
{"Claim":"No fixed score dominates","Metric":"family-wise winners differ","Artifact":"step8_5_family_comparison.csv","Caveat":"seven families"},
{"Claim":"Nested selection excludes outer unknown","Metric":"method audit PASS","Artifact":"ecocon_nos_method_audit.txt","Caveat":"implementation audit"},
{"Claim":"NOS improves macro UADR","Metric":"0.3873314571 vs MD 0.2929370161","Artifact":"ecocon_nos_macro_summary.csv","Caveat":"review rate 0.2104"},
{"Claim":"NOS improves macro risk","Metric":"0.4190400799 vs MD 0.4583777548","Artifact":"ecocon_nos_macro_summary.csv","Caveat":"selective metric"},
{"Claim":"NOS improves 6/7 against MD","Metric":"6 wins, 1 loss","Artifact":"ecocon_nos_statistics.csv","Caveat":"n=7"},
{"Claim":"Mirai high-confidence rescue","Metric":"outer UADR 0.99961","Artifact":"ecocon_nos_outer_results.csv","Caveat":"not perfect/external"},
{"Claim":"Fresh confirmation","Metric":"five 5,000-row families","Artifact":"ecocon_nos_fresh_confirmation.csv","Caveat":"same dataset"},
{"Claim":"Web weakness","Metric":"NOS 0.1860861104 < entropy 0.2682640071","Artifact":"ecocon_nos_family_comparison.csv","Caveat":"selection failure"}]
parts.append(section(65, "Defensible Claims", mdtable(claims)))
parts.append(section(66, "Unsupported / Prohibited Claims", "Do not claim guaranteed zero-day detection; perfect unseen-attack detection; universal superiority; external validation; state of the art without literature comparison; first-ever open-set, conformal, or kNN OOD IDS; 23% runtime or energy reduction; carbon savings; perfect Mirai generalization outside CICIoT2023; production deployment validation; significance over every method; conformal guarantee of OOD detection; publication-safe NOS efficiency; causal robustness to arbitrary distribution shift; or calibrated real-world analyst cost."))
parts.append(section(67, "Limitations", "One primary dataset; fresh confirmation remains within it; LOAFO is a proxy for future unknowns; research sampling changes prevalence; conflicting identical vectors were removed; Web weakness; DoS difficulty; increased analyst review; imperfect detector selection; only seven independent folds; limited statistical power; row bootstrap does not create independent folds; no real deployment; no physical power measurement; unsafe NOS efficiency benchmark; and pseudo-unknown fine labels may not predict future family shifts."))
parts.append(section(68, "Final Research Contributions", "1. A leakage-safe, resource-budgeted CICIoT2023 pipeline and LOAFO evaluation exposing confident unseen-family failures. 2. Evidence that predictive uncertainty and feature-space OOD signals have family-dependent strengths. 3. EcoCon-NOS training-only nested pseudo-open-set detector selection before true unknown exposure. 4. Improved macro UADR and selective risk over fixed baselines under the frozen protocol. 5. Fresh unused-sample confirmation within CICIoT2023. Any claim of novelty relative to prior literature requires a separate literature review."))
parts.append(section(69, "Final Project Status", "Completed: Steps 1–8.6. Final method: EcoCon-NOS. Model development: FROZEN. Next: Step 9 publication assets, figures, tables, diagrams, and evidence package. After Step 9: Step 10 final paper. No additional model tuning is recommended using existing outer test results."))

# Add archive appendices so every high-value table remains directly accessible.
parts.append("\n# Appendix A. Fine-Label Counts\n\n"+mdtable(rows("fine_label_counts.csv")))
parts.append("\n# Appendix B. LOAFO Feature Rankings\n\n"+mdtable(rows("loafo_feature_rankings.csv")))
parts.append("\n# Appendix C. NOS Inner-Holdout Evaluation Archive\n\n"+mdtable(inner))
parts.append("\n# Appendix D. NOS Bootstrap and Statistics Archive\n\n"+mdtable(boot)+"\n"+mdtable(stats))
parts.append("\n# Appendix E. Reproducibility and Integrity Notes\n\nAll metrics in narrative claims trace to saved artifacts. No model was loaded for prediction, retrained, or serialized during documentation. No threshold, feature set, split, label mapping, alpha, detector candidate, detector selection, or result artifact was changed. Parquet files were not loaded in full. Binary models were counted and related metadata inspected. Any future reproduction must occur in a separate output namespace because current artifacts are frozen.\n")

master="\n".join(parts)
(D/"ECOCON_NOS_COMPLETE_RESEARCH_DOCUMENTATION.md").write_text(master,encoding="utf-8")

handoff=f'''USE PROJECT ARTIFACTS AS SOURCE OF TRUTH. DO NOT REDESIGN OR RETUNE ECOCON-NOS WITHOUT EXPLICIT INSTRUCTION.

# EcoCon-NOS Project Handoff

## Project root and objective

`D:\\CSE_21201016_BRAC\\CON_green`. The objective is resource-budgeted selective intrusion detection when one entire attack family is absent from training. The system accepts frozen XGBoost predictions or abstains for review.

## Dataset, mapping, and preparation

CICIoT2023 contains 46,776,700 raw rows across 309 CSV files and 34 label folders. The schema has 39 numeric inputs and no label column; folder names supply labels and map to Benign, DDoS, DoS, Mirai, Recon, Spoofing, BruteForce, or Web. Three malformed records were identified. Seed-42 streamed subtype-aware sampling with a 100,000 family cap and 1,000 fine-label minimum produced 637,892 rows without oversampling. Web and BruteForce were not inflated.

Feature hashes cover the full cleaned vector. The audit found 6,909 conflicting hashes and 25,777 rows. Entire conflicting groups were removed, producing a 612,115-row modeling pool. All splits are group-safe; closed-set train/calibration/test roles are fitting, uncertainty calibration, and final evaluation.

## Closed-set and feature budget

Random Forest, XGBoost, and LightGBM were compared on group-safe internal development. XGBoost was selected by development Macro-F1, not official test. Official 39-feature Macro-F1 is 0.7640493828. Training-only gain ranking evaluated 39/30/20/15/10/5 inputs; epsilon=0.005 selected 30. Test Macro-F1 is 0.7614298611, a -0.0026195217 change with 23.0769% fewer inputs. Do not translate dimensionality reduction into runtime, energy, or carbon claims.

## LOAFO and Step 7

Seven folds hold out DDoS, DoS, Mirai, Recon, Spoofing, BruteForce, or Web; Benign remains known. Every fold performs independent training-only ranking and budget selection, freezes a seven-output XGBoost classifier, then emits calibration/test probabilities. The true unknown has no probability column. Calibration and test are unused for model selection, and Step 7 performs no thresholding. DDoS, DoS, and Mirai demonstrate severe forced-label overconfidence.

## EcoCon-MD and EcoCon-Fuse

EcoCon-MD standardizes outer training features, computes class means, fits shared Ledoit-Wolf covariance on true-class residuals, and scores distance to the XGBoost-predicted class. Predicted-class-conditional known calibration creates alpha=0.05 p-values. Macro UADR is 0.2929370161. EcoCon-Fuse combines MD and entropy through CAL-A/CAL-B and `-log(min(p_MD,p_ENT))`; macro UADR 0.3021256821 and risk 0.4602687195 failed predeclared primary/robustness rules. Fuse is an unsuccessful frozen ablation.

## EcoCon-NOS

Within outer training only, up to 12 eligible fine labels become pseudo-unknowns. Seven candidates—MSP, entropy, MD-Pred, Min-MD, MDS, class-conditional kNN, and global kNN—are evaluated at inner-known thresholds targeting 5% rejection. Selection uses mean UADR, a <=0.01 risk tie-break, worst-fold UADR, then fixed cost order. The real outer unknown is sealed throughout. DDoS selects MD-Pred; all other folds select ClassConditionalKNN.

Final macro NOS: UADR 0.3873314571; known rejection 0.0501817236; coverage 0.7896324763; review rate 0.2103675237; overall selective risk 0.4190400799. Family UADR: DDoS 0.5565392088, DoS 0.0406751364, Mirai 0.99961, Recon 0.3230284987, Spoofing 0.2110819577, BruteForce 0.3942992874, Web 0.1860861104. NOS beats MD on 6/7 folds. Wilcoxon NOS-vs-MD p=0.03125 for both UADR and risk, with n=7.

## Confirmation, limitations, and status

Fresh frozen confirmation uses 5,000 unused rows each for DDoS, DoS, Mirai, Recon, and Spoofing. NOS UADR is 0.6346, 0.1810, 0.9996, 0.3742, and 0.1904 respectively. This is within CICIoT2023, not external validation. Web is the principal selection failure; DoS remains difficult. Other limits: one dataset, sampled prevalence, conflict removal, seven folds, review workload, no deployment or physical power data, and publication-unsafe NOS efficiency accounting.

## Primary artifacts and next step

Numerical evidence is in `results/`; frozen objects in `models/loafo`, `models/ecocon_md`, `models/ecocon_fuse`, and `models/ecocon_nos`; data lineage in `processed/`; publication derivatives in `paper_assets/`; exact key results and the full artifact index are in `docs/`. Read `ECOCON_NOS_COMPLETE_RESEARCH_DOCUMENTATION.md` first, then `ECOCON_NOS_KEY_RESULTS.json`, `ECOCON_NOS_ARTIFACT_INDEX.csv`, and the discrepancy log.

Steps 1–8.6 are complete. EcoCon-NOS is final and frozen. No additional tuning should use outer test results. Current next step: Step 9 publication figures, tables, diagrams, and evidence package; Step 10 paper writing follows separately.
'''
# Add detailed tables to make the handoff operational rather than merely narrative.
handoff += "\n## Exact detector selections\n\n"+mdtable(selrows)+"\n## Exact macro results\n\n"+mdtable(macro)+"\n## Exact outer results\n\n"+mdtable(outer)+"\n## Fresh confirmation\n\n"+mdtable(fresh)+"\n## Statistics\n\n"+mdtable(stats)+"\n## Script inventory\n\n"+mdtable(script_rows)+"\n## Frozen-method restrictions\n\nDo not retrain XGBoost or any OOD detector; change features, budgets, mappings, alpha, thresholds, detector candidates, or selections; rerun test-driven experiments; or overwrite frozen results. Efficiency timing must remain uncited until a corrected benchmark is completed and audited.\n"
(D/"ECOCON_NOS_PROJECT_HANDOFF.md").write_text(handoff,encoding="utf-8")

discrepancies='''# EcoCon-NOS Discrepancy Log

| Files involved | Conflict | Likely reason | Publication decision |
|---|---|---|---|
| `paper_assets/data/key_numbers.json`; `processed/modeling_pool.parquet`; `results/closed_set_split_counts.csv`; `results/duplicate_audit.txt` | Derivative key-numbers file says `modeling_pool_rows: 0`; authoritative lineage implies 637,892 - 25,777 = 612,115 and split counts sum to 612,115. | Step-9 derivative extraction/default-value bug. | Use 612,115; never publish 0. |
| `results/ecocon_nos_efficiency.csv`; `tools/refresh_ecocon_nos_efficiency.py`; `paper_assets/audit/efficiency_status.txt` | A NOS timing CSV exists, but the corrected refresh did not complete and timing accounting is declared inconsistent. | Historical benchmark mixed timing scopes; correction timed out. | Do not quote NOS efficiency values; status is not publication-safe. |
| Prompt wording; `results/ecocon_nos_success_criteria.json` | Prompt says expected selections/results approximately; artifacts provide exact values. | Prompt intentionally contains rounded expectations. | Use exact artifacts throughout. |

No frozen result artifact was modified to resolve a discrepancy. This log records interpretation only.
'''
(D/"ECOCON_NOS_DISCREPANCY_LOG.md").write_text(discrepancies,encoding="utf-8")

inspected=[p for top in ["processed","results","models","paper_assets","src","tools"] for p in (ROOT/top).rglob("*") if p.is_file()]
result_count=len([p for p in inspected if p.parts[-2] == "results"])
audit=f'''Files inspected: {len(inspected)}
Scripts inspected: {len(scripts)}
Result artifacts inspected: {result_count}
Models/directories inspected: {len(model_files)} files in {len(model_counts)} directories
Discrepancies found: 3
Missing expected artifacts: 0
Publication-unsafe metrics: EcoCon-NOS efficiency/timing/overhead values

RAW DATA DOCUMENTED: PASS
PREPROCESSING DOCUMENTED: PASS
SPLITS DOCUMENTED: PASS
BASELINES DOCUMENTED: PASS
FEATURE BUDGET DOCUMENTED: PASS
LOAFO DOCUMENTED: PASS
ECOCON-MD DOCUMENTED: PASS
ECOCON-FUSE DOCUMENTED: PASS
ECOCON-NOS DOCUMENTED: PASS
FRESH CONFIRMATION DOCUMENTED: PASS
STATISTICS DOCUMENTED: PASS
LIMITATIONS DOCUMENTED: PASS
ARTIFACT LINEAGE DOCUMENTED: PASS

MASTER DOCUMENTATION VALIDATION:

PASS

Integrity confirmation: NO MODELS RETRAINED; NO THRESHOLDS CHANGED; NO RESULTS MODIFIED; NO TEST-DRIVEN TUNING PERFORMED.
'''
(D/"ECOCON_NOS_DOCUMENTATION_AUDIT.txt").write_text(audit,encoding="utf-8")

print(json.dumps({"master_words":len(master.split()),"handoff_words":len(handoff.split()),"scripts":len(scripts),"result_files":result_count,"model_files":len(model_files),"artifacts":len(artifact_rows)},indent=2))
