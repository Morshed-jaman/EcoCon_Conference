# EcoCon-NOS Complete Research Documentation

**Project root:** `D:\CSE_21201016_BRAC\CON_green`  
**Method status:** FROZEN  
**Final method:** EcoCon-NOS — Nested Open-Set Detector Selection for Resource-Budgeted Intrusion Detection of Unseen IoT Attacks  
**Evidence policy:** disk artifacts are authoritative; discrepancies are logged separately.


# 1. Executive Technical Summary

This project studies selective intrusion detection when a complete IoT attack family is absent from model training. A conventional closed-set classifier must still emit one of its known labels. CICIoT2023 experiments show that this forced decision can be extremely confident: the held-out DDoS, DoS, and Mirai folds contain large fractions of unknown observations above 0.95 maximum XGBoost probability. Thus confidence is not membership evidence, and a deployable system needs an abstention path.

The data pipeline audited all 46,776,700 raw rows in 309 CSV files organized into 34 fine-label folders. Folder names supply labels because the CSV schema contains 39 numeric features and no explicit label column. Deterministic, subtype-aware sampling produced 637,892 rows. Entire feature-hash groups whose identical vectors carried conflicting family labels were removed, leaving a 612,115-row modeling pool. Group-aware partitions prevent identical feature vectors from crossing train, calibration, and test boundaries.

Closed-set development compared Random Forest, XGBoost, and LightGBM without using official calibration or test data for selection. XGBoost won development Macro-F1. A training-only gain ranking then tested 39, 30, 20, 15, 10, and 5 features. The predeclared rule selected the smallest budget within 0.005 development Macro-F1 of the full model: 30 features. On official test data, Macro-F1 changed from 0.7640493828 to 0.7614298611, a -0.0026195217 absolute change with 23.0769% fewer inputs. This is dimensionality reduction, not a measured energy or runtime reduction.

Seven leave-one-attack-family-out (LOAFO) folds held out DDoS, DoS, Mirai, Recon, Spoofing, BruteForce, or Web. Benign was always known. Each fold independently ranked features, selected its budget, refit a frozen seven-class XGBoost model, and emitted probabilities for known calibration, known test, and true-unknown test sets. Probability anomaly scores—maximum softmax probability (MSP), entropy, and inverse margin—failed badly for highly confident unknown families.

EcoCon-MD addressed this by measuring predicted-class Mahalanobis atypicality in standardized feature space, with a shared Ledoit-Wolf covariance fit on outer training only and predicted-class-conditional conformal calibration on known calibration only. It raised macro unknown attack detection rate (UADR) to 0.2929370161, but was not strongest for every family. EcoCon-Fuse combined MD and entropy through a two-stage calibration scheme; it increased macro UADR slightly to 0.3021256821 but worsened overall selective risk to 0.4602687195 and failed its predeclared success and robustness criteria. It is retained as a negative-result ablation.

EcoCon-NOS reframed the problem as detector selection. Within each outer-training pool, up to 12 eligible fine labels become pseudo-unknowns. Seven candidate scores are evaluated at thresholds derived only from inner known validation. Mean inner UADR, risk tie-breaking, worst-fold UADR, and fixed cost order determine the detector before the real outer unknown is opened. The frozen map selected MD-Pred for DDoS and class-conditional k-nearest neighbors for the other six families.

At approximately 5% known rejection, EcoCon-NOS achieved macro UADR 0.3873314571, coverage 0.7896324763, review rate 0.2103675237, and overall selective risk 0.4190400799. It beat EcoCon-MD on six of seven UADR folds; paired Wilcoxon p-values for NOS versus MD were 0.03125 for both UADR and overall risk. Mirai UADR was 0.99961—not perfect—and Web remained weak at 0.1860861104. Fresh unused samples confirmed several patterns within CICIoT2023, but are not external validation. Limitations include one dataset, only seven independent family folds, sampling-altered prevalence, analyst workload, imperfect detector choice, no deployment study, no physical power measurement, and a NOS efficiency benchmark that remains publication-unsafe. Steps 1–8.6 are complete and frozen; Step 9 publication assets are the next phase.


# 2. Research Question and Problem Formulation

The primary question is whether an intrusion detector trained on known attack families can safely handle a family that is completely absent from training. For each test observation, the operational action is either **ACCEPT** the frozen XGBoost family prediction or **ABSTAIN** for analyst review.

Known traffic belongs to one of the outer fold's training families. Unknown traffic belongs to the sealed outer family. A pseudo-unknown fine label is a known-family subtype hidden only inside outer training for nested selection. Selective prediction is prediction with a reject option; abstention is that reject action. With unknown indicator `u`, rejection indicator `r`, and correctness `z` on known accepted rows: `UADR = sum(u*r)/sum(u)`; `coverage = mean(1-r)`; `review rate = 1-coverage`; `known selective risk = sum((1-z)*(1-r)*(1-u))/sum((1-r)*(1-u))`; and `overall selective risk = (accepted unknown + wrong accepted known)/(all accepted)`. High classifier confidence is not evidence that an observation belongs to the known distribution.


# 3. Dataset

CICIoT2023 is stored under `CSV/` in 34 top-level fine-label folders. The audit records 309 CSV files, 46,776,700 rows, and 8.330 GB. The raw files have no explicit label column; the containing folder supplies the fine label. The 39 model inputs are:

| column_index | column_name | dtype |
|---|---|---|
| 0 | Header_Length | float64 |
| 1 | Protocol Type | int64 |
| 2 | Time_To_Live | float64 |
| 3 | Rate | float64 |
| 4 | fin_flag_number | float64 |
| 5 | syn_flag_number | float64 |
| 6 | rst_flag_number | float64 |
| 7 | psh_flag_number | float64 |
| 8 | ack_flag_number | float64 |
| 9 | ece_flag_number | float64 |
| 10 | cwr_flag_number | float64 |
| 11 | ack_count | int64 |
| 12 | syn_count | int64 |
| 13 | fin_count | int64 |
| 14 | rst_count | int64 |
| 15 | HTTP | float64 |
| 16 | HTTPS | float64 |
| 17 | DNS | float64 |
| 18 | Telnet | float64 |
| 19 | SMTP | float64 |
| 20 | SSH | float64 |
| 21 | IRC | float64 |
| 22 | TCP | float64 |
| 23 | UDP | float64 |
| 24 | DHCP | float64 |
| 25 | ARP | float64 |
| 26 | ICMP | float64 |
| 27 | IGMP | float64 |
| 28 | IPv | float64 |
| 29 | LLC | float64 |
| 30 | Tot sum | int64 |
| 31 | Min | int64 |
| 32 | Max | int64 |
| 33 | AVG | float64 |
| 34 | Std | float64 |
| 35 | Tot size | float64 |
| 36 | IAT | float64 |
| 37 | Number | int64 |
| 38 | Variance | float64 |


# 4. Complete 34-Label Taxonomy

All 34 folders map exactly once to eight high-level families (validation PASS):

| fine_label | family |
|---|---|
| Benign_Final | Benign |
| DDoS-ACK_Fragmentation | DDoS |
| DDoS-HTTP_Flood | DDoS |
| DDoS-ICMP_Flood | DDoS |
| DDoS-ICMP_Fragmentation | DDoS |
| DDoS-PSHACK_FLOOD | DDoS |
| DDoS-RSTFINFLOOD | DDoS |
| DDoS-SlowLoris | DDoS |
| DDoS-SYN_Flood | DDoS |
| DDoS-SynonymousIP_Flood | DDoS |
| DDoS-TCP_Flood | DDoS |
| DDoS-UDP_Flood | DDoS |
| DDoS-UDP_Fragmentation | DDoS |
| DoS-HTTP_Flood | DoS |
| DoS-SYN_Flood | DoS |
| DoS-TCP_Flood | DoS |
| DoS-UDP_Flood | DoS |
| Mirai-greeth_flood | Mirai |
| Mirai-greip_flood | Mirai |
| Mirai-udpplain | Mirai |
| Recon-HostDiscovery | Recon |
| Recon-OSScan | Recon |
| Recon-PingSweep | Recon |
| Recon-PortScan | Recon |
| VulnerabilityScan | Recon |
| DNS_Spoofing | Spoofing |
| MITM-ArpSpoofing | Spoofing |
| DictionaryBruteForce | BruteForce |
| Backdoor_Malware | Web |
| BrowserHijacking | Web |
| CommandInjection | Web |
| SqlInjection | Web |
| Uploading_Attack | Web |
| XSS | Web |


# 5. Raw Dataset Audit

Three malformed logical records were found in `DoS-UDP_Flood7`, `8`, and `9`; 46,776,697 rows were structurally valid. Cleaning rejects malformed, nonnumeric, NaN, +Inf, then -Inf values in that priority. Raw prevalence is severely imbalanced: DDoS has 33,984,450 rows, BruteForce 13,064, a 2601.381660 ratio.

| family | fine_label_count | csv_file_count | record_count | percentage_of_dataset | total_size_mb |
|---|---|---|---|---|---|
| DDoS | 12 | 176 | 33984450 | 72.652517 | 6120.439535 |
| DoS | 4 | 38 | 7845120 | 16.771427 | 1446.987138 |
| Mirai | 3 | 76 | 2634054 | 5.631124 | 508.701351 |
| Benign | 1 | 4 | 1098191 | 2.347731 | 216.878795 |
| Recon | 5 | 5 | 690534 | 1.476235 | 133.853135 |
| Spoofing | 2 | 3 | 486458 | 1.039958 | 95.118986 |
| Web | 6 | 6 | 24829 | 0.053080 | 4.887013 |
| BruteForce | 1 | 1 | 13064 | 0.027928 | 2.579045 |


# 6. Research-Pool Construction

`src/03_build_research_pool.py` streams raw CSV chunks using seed 42, a 100,000 family cap, a 1,000 fine-label minimum, proportional residual allocation, and largest-remainder rounding. It performs no synthetic oversampling. Web and BruteForce remain below the cap because unavailable observations are never fabricated. Output: `processed/research_pool.parquet`, 637,892 rows, 39 features plus metadata.

| Family | Available raw rows | Research-pool rows |
|---|---|---|
| Benign | 0 | 0 |
| BruteForce | 0 | 0 |
| DDoS | 0 | 0 |
| DoS | 0 | 0 |
| Mirai | 0 | 0 |
| Recon | 0 | 0 |
| Spoofing | 0 | 0 |
| Web | 0 | 0 |


# 7. Feature-Hash Duplicate and Conflict Audit

`feature_hash` is a deterministic digest of the complete cleaned 39-feature vector. Grouping on it prevents identical observations from crossing partitions. There were 598,215 unique hashes, 19,906 duplicate groups covering 59,583 rows, maximum group size 235, and 6,909 conflicting hashes covering 25,777 rows. Affected families were Benign, BruteForce, DDoS, DoS, Recon, Spoofing, and Web. The primary policy removes every row in a conflicting hash group; choosing one label would encode an arbitrary target and retain ambiguity. Evidence: `results/duplicate_audit.txt`, `results/label_conflicts.parquet`, and `processed/ambiguous_conflict_pool.parquet`.


# 8. Final Modeling Pool

Removing 25,777 conflicting rows from 637,892 produces exactly 612,115 rows in `processed/modeling_pool.parquet`.

| Family | Research pool | Modeling pool | Removed |
|---|---|---|---|
| Benign | 0 | 99792 | -99792 |
| BruteForce | 0 | 13051 | -13051 |
| DDoS | 0 | 90592 | -90592 |
| DoS | 0 | 87449 | -87449 |
| Mirai | 0 | 100000 | -100000 |
| Recon | 0 | 99759 | -99759 |
| Spoofing | 0 | 96806 | -96806 |
| Web | 0 | 24666 | -24666 |


# 9. Closed-Set Partitioning

Group-aware splitting uses `feature_hash` and seed 42 at nominal 70/15/15 ratios. Actual rows are train 428477, calibration 91819, and test 91819. All pairwise feature-hash overlaps are zero and all eight families plus all 34 fine labels are preserved. TRAIN supports fitting/development, CALIBRATION is reserved for uncertainty calibration, and TEST is final closed-set evaluation.

| split | family | row_count | percentage_within_family | percentage_of_split |
|---|---|---|---|---|
| calibration | Benign | 14969 | 15.0002004169 | 16.3027260153 |
| calibration | BruteForce | 1958 | 15.0026817868 | 2.1324562454 |
| calibration | DDoS | 13589 | 15.0002207700 | 14.7997691110 |
| calibration | DoS | 13118 | 15.0007432904 | 14.2868033849 |
| calibration | Mirai | 15000 | 15.0000000000 | 16.3364880907 |
| calibration | Recon | 14964 | 15.0001503624 | 16.2972805193 |
| calibration | Spoofing | 14521 | 15.0001032994 | 15.8148095710 |
| calibration | Web | 3700 | 15.0004054164 | 4.0296670624 |
| test | Benign | 14969 | 15.0002004169 | 16.3027260153 |
| test | BruteForce | 1958 | 15.0026817868 | 2.1324562454 |
| test | DDoS | 13589 | 15.0002207700 | 14.7997691110 |
| test | DoS | 13118 | 15.0007432904 | 14.2868033849 |
| test | Mirai | 15000 | 15.0000000000 | 16.3364880907 |
| test | Recon | 14964 | 15.0001503624 | 16.2972805193 |
| test | Spoofing | 14521 | 15.0001032994 | 15.8148095710 |
| test | Web | 3700 | 15.0004054164 | 4.0296670624 |
| train | Benign | 69854 | 69.9995991663 | 16.3028587299 |
| train | BruteForce | 9135 | 69.9946364263 | 2.1319697440 |
| train | DDoS | 63414 | 69.9995584599 | 14.7998609027 |
| train | DoS | 61213 | 69.9985134193 | 14.2861810552 |
| train | Mirai | 70000 | 70.0000000000 | 16.3369329042 |
| train | Recon | 69831 | 69.9996992753 | 16.2974908805 |
| train | Spoofing | 67764 | 69.9997934012 | 15.8150845903 |
| train | Web | 17266 | 69.9991891673 | 4.0296211932 |


# 10. LOAFO Split Construction

Seven attack families are held out in turn; Benign is never held out. The held-out family is absent from outer train, calibration, and test-known, and all its clean rows enter test-unknown. Controlled partitions have zero feature-hash overlap. Manifests are `loafo_split_manifest.parquet` and `loafo_internal_dev_manifest.parquet`.

| held_out_family | loafo_split | family | row_count |
|---|---|---|---|
| BruteForce | calibration | Benign | 14969 |
| BruteForce | calibration | DDoS | 13589 |
| BruteForce | calibration | DoS | 13118 |
| BruteForce | calibration | Mirai | 15000 |
| BruteForce | calibration | Recon | 14964 |
| BruteForce | calibration | Spoofing | 14521 |
| BruteForce | calibration | Web | 3700 |
| BruteForce | test_known | Benign | 14969 |
| BruteForce | test_known | DDoS | 13589 |
| BruteForce | test_known | DoS | 13118 |
| BruteForce | test_known | Mirai | 15000 |
| BruteForce | test_known | Recon | 14964 |
| BruteForce | test_known | Spoofing | 14521 |
| BruteForce | test_known | Web | 3700 |
| BruteForce | test_unknown | BruteForce | 13051 |
| BruteForce | train | Benign | 69854 |
| BruteForce | train | DDoS | 63414 |
| BruteForce | train | DoS | 61213 |
| BruteForce | train | Mirai | 70000 |
| BruteForce | train | Recon | 69831 |
| BruteForce | train | Spoofing | 67764 |
| BruteForce | train | Web | 17266 |
| DDoS | calibration | Benign | 14969 |
| DDoS | calibration | BruteForce | 1958 |
| DDoS | calibration | DoS | 13118 |
| DDoS | calibration | Mirai | 15000 |
| DDoS | calibration | Recon | 14964 |
| DDoS | calibration | Spoofing | 14521 |
| DDoS | calibration | Web | 3700 |
| DDoS | test_known | Benign | 14969 |
| DDoS | test_known | BruteForce | 1958 |
| DDoS | test_known | DoS | 13118 |
| DDoS | test_known | Mirai | 15000 |
| DDoS | test_known | Recon | 14964 |
| DDoS | test_known | Spoofing | 14521 |
| DDoS | test_known | Web | 3700 |
| DDoS | test_unknown | DDoS | 90592 |
| DDoS | train | Benign | 69854 |
| DDoS | train | BruteForce | 9135 |
| DDoS | train | DoS | 61213 |
| DDoS | train | Mirai | 70000 |
| DDoS | train | Recon | 69831 |
| DDoS | train | Spoofing | 67764 |
| DDoS | train | Web | 17266 |
| DoS | calibration | Benign | 14969 |
| DoS | calibration | BruteForce | 1958 |
| DoS | calibration | DDoS | 13589 |
| DoS | calibration | Mirai | 15000 |
| DoS | calibration | Recon | 14964 |
| DoS | calibration | Spoofing | 14521 |
| DoS | calibration | Web | 3700 |
| DoS | test_known | Benign | 14969 |
| DoS | test_known | BruteForce | 1958 |
| DoS | test_known | DDoS | 13589 |
| DoS | test_known | Mirai | 15000 |
| DoS | test_known | Recon | 14964 |
| DoS | test_known | Spoofing | 14521 |
| DoS | test_known | Web | 3700 |
| DoS | test_unknown | DoS | 87449 |
| DoS | train | Benign | 69854 |
| DoS | train | BruteForce | 9135 |
| DoS | train | DDoS | 63414 |
| DoS | train | Mirai | 70000 |
| DoS | train | Recon | 69831 |
| DoS | train | Spoofing | 67764 |
| DoS | train | Web | 17266 |
| Mirai | calibration | Benign | 14969 |
| Mirai | calibration | BruteForce | 1958 |
| Mirai | calibration | DDoS | 13589 |
| Mirai | calibration | DoS | 13118 |
| Mirai | calibration | Recon | 14964 |
| Mirai | calibration | Spoofing | 14521 |
| Mirai | calibration | Web | 3700 |
| Mirai | test_known | Benign | 14969 |
| Mirai | test_known | BruteForce | 1958 |
| Mirai | test_known | DDoS | 13589 |
| Mirai | test_known | DoS | 13118 |
| Mirai | test_known | Recon | 14964 |
| Mirai | test_known | Spoofing | 14521 |
| Mirai | test_known | Web | 3700 |
| Mirai | test_unknown | Mirai | 100000 |
| Mirai | train | Benign | 69854 |
| Mirai | train | BruteForce | 9135 |
| Mirai | train | DDoS | 63414 |
| Mirai | train | DoS | 61213 |
| Mirai | train | Recon | 69831 |
| Mirai | train | Spoofing | 67764 |
| Mirai | train | Web | 17266 |
| Recon | calibration | Benign | 14969 |
| Recon | calibration | BruteForce | 1958 |
| Recon | calibration | DDoS | 13589 |
| Recon | calibration | DoS | 13118 |
| Recon | calibration | Mirai | 15000 |
| Recon | calibration | Spoofing | 14521 |
| Recon | calibration | Web | 3700 |
| Recon | test_known | Benign | 14969 |
| Recon | test_known | BruteForce | 1958 |
| Recon | test_known | DDoS | 13589 |
| Recon | test_known | DoS | 13118 |
| Recon | test_known | Mirai | 15000 |
| Recon | test_known | Spoofing | 14521 |
| Recon | test_known | Web | 3700 |
| Recon | test_unknown | Recon | 99759 |
| Recon | train | Benign | 69854 |
| Recon | train | BruteForce | 9135 |
| Recon | train | DDoS | 63414 |
| Recon | train | DoS | 61213 |
| Recon | train | Mirai | 70000 |
| Recon | train | Spoofing | 67764 |
| Recon | train | Web | 17266 |
| Spoofing | calibration | Benign | 14969 |
| Spoofing | calibration | BruteForce | 1958 |
| Spoofing | calibration | DDoS | 13589 |
| Spoofing | calibration | DoS | 13118 |
| Spoofing | calibration | Mirai | 15000 |
| Spoofing | calibration | Recon | 14964 |
| Spoofing | calibration | Web | 3700 |
| Spoofing | test_known | Benign | 14969 |
| Spoofing | test_known | BruteForce | 1958 |
| Spoofing | test_known | DDoS | 13589 |
| Spoofing | test_known | DoS | 13118 |
| Spoofing | test_known | Mirai | 15000 |
| Spoofing | test_known | Recon | 14964 |
| Spoofing | test_known | Web | 3700 |
| Spoofing | test_unknown | Spoofing | 96806 |
| Spoofing | train | Benign | 69854 |
| Spoofing | train | BruteForce | 9135 |
| Spoofing | train | DDoS | 63414 |
| Spoofing | train | DoS | 61213 |
| Spoofing | train | Mirai | 70000 |
| Spoofing | train | Recon | 69831 |
| Spoofing | train | Web | 17266 |
| Web | calibration | Benign | 14969 |
| Web | calibration | BruteForce | 1958 |
| Web | calibration | DDoS | 13589 |
| Web | calibration | DoS | 13118 |
| Web | calibration | Mirai | 15000 |
| Web | calibration | Recon | 14964 |
| Web | calibration | Spoofing | 14521 |
| Web | test_known | Benign | 14969 |
| Web | test_known | BruteForce | 1958 |
| Web | test_known | DDoS | 13589 |
| Web | test_known | DoS | 13118 |
| Web | test_known | Mirai | 15000 |
| Web | test_known | Recon | 14964 |
| Web | test_known | Spoofing | 14521 |
| Web | test_unknown | Web | 24666 |
| Web | train | Benign | 69854 |
| Web | train | BruteForce | 9135 |
| Web | train | DDoS | 63414 |
| Web | train | DoS | 61213 |
| Web | train | Mirai | 70000 |
| Web | train | Recon | 69831 |
| Web | train | Spoofing | 67764 |


# 11. Closed-Set Baseline Models

Balanced sample weights were computed from fitting labels. A group-safe internal train/dev split—not official calibration or test—selected the highest development Macro-F1, XGBoost.

## Development

| model | feature_count | accuracy | balanced_accuracy | macro_precision | macro_recall | macro_f1 | weighted_f1 | log_loss | training_seconds | best_iteration | median_total_inference_ms | median_ms_per_sample | samples_per_second | serialized_model_size_bytes | serialized_model_size_mib |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| random_forest | 39 | 0.8216825105 | 0.7297718125 | 0.8071503175 | 0.7297718125 | 0.7518525144 | 0.8183058159 | 0.5154805494 | 60.2206081999 |  | 1380.4685000796 | 0.0214782024 | 46558.8312926333 | 780880072 | 744.7052688599 |
| xgboost | 39 | 0.8286527780 | 0.7786766395 | 0.7638175383 | 0.7786766395 | 0.7682478170 | 0.8309838445 | 0.4329302311 | 327.0475698999 | 1666.0000000000 | 3161.8947000243 | 0.0491947583 | 20327.3689030525 | 47241590 | 45.0530910492 |
| lightgbm | 39 | 0.8254165824 | 0.7825434730 | 0.7570597582 | 0.7825434730 | 0.7636973931 | 0.8291132967 | 0.4409245253 | 130.6156210001 | 2000.0000000000 | 17240.7194999978 | 0.2682420223 | 3727.9766659395 | 22807329 | 21.7507638931 |

## Official test

| model | feature_count | accuracy | balanced_accuracy | macro_precision | macro_recall | macro_f1 | weighted_f1 | log_loss |
|---|---|---|---|---|---|---|---|---|
| random_forest | 39 | 0.8208322896 | 0.7285037440 | 0.8044091836 | 0.7285037440 | 0.7502235115 | 0.8174498411 | 0.5153092611 |
| xgboost | 39 | 0.8255589802 | 0.7760109550 | 0.7593526924 | 0.7760109550 | 0.7640493828 | 0.8280798028 | 0.4372141659 |
| lightgbm | 39 | 0.8220738627 | 0.7796423082 | 0.7520791945 | 0.7796423082 | 0.7587763320 | 0.8260730349 | 0.4475108904 |


# 12. XGBoost Per-Class Performance

Macro-F1 gives each family equal influence and exposes minority weaknesses hidden by accuracy. BruteForce and Web have fewer and more heterogeneous examples and remain difficult.

| model | family | precision | recall | f1 | support |
|---|---|---|---|---|---|
| xgboost | Benign | 0.7756702887 | 0.8059322600 | 0.7905117620 | 14969 |
| xgboost | BruteForce | 0.4645107098 | 0.5648621042 | 0.5097948836 | 1958 |
| xgboost | DDoS | 0.8965305226 | 0.7511222312 | 0.8174101065 | 13589 |
| xgboost | DoS | 0.7794741306 | 0.9107333435 | 0.8400070311 | 13118 |
| xgboost | Mirai | 0.9995331155 | 0.9990666667 | 0.9992998366 | 15000 |
| xgboost | Recon | 0.7671460577 | 0.7093691526 | 0.7371271831 | 14964 |
| xgboost | Spoofing | 0.9421205142 | 0.8732180979 | 0.9063616869 | 14521 |
| xgboost | Web | 0.4498361998 | 0.5937837838 | 0.5118825722 | 3700 |


# 13. Resource / Feature-Budget Experiment

XGBoost gain on training-only development data ranked all 39 features. The smallest budget within 0.005 of full-feature development Macro-F1 was 30. Test Macro-F1 changed by -0.0026195217; inputs fell 23.076923%. This does not establish proportional computation, energy, or latency savings.

## Ranking

| rank | feature | gain | normalized_gain |
|---|---|---|---|
| 1 | Number | 454.897247314 | 0.597463160064 |
| 2 | SSH | 52.5165748596 | 0.0689753981951 |
| 3 | Protocol Type | 35.7049484253 | 0.0468949668129 |
| 4 | Min | 30.4112968445 | 0.0399422718463 |
| 5 | Tot sum | 21.5369529724 | 0.0282866868441 |
| 6 | AVG | 15.6102867126 | 0.020502588846 |
| 7 | syn_count | 9.43504714966 | 0.0123920140618 |
| 8 | fin_flag_number | 8.8241443634 | 0.0115896528443 |
| 9 | fin_count | 8.47144699097 | 0.0111264192505 |
| 10 | Max | 8.40401935577 | 0.0110378596291 |
| 11 | HTTPS | 8.3160161972 | 0.0109222760649 |
| 12 | Tot size | 7.76349401474 | 0.0101965920756 |
| 13 | rst_flag_number | 7.7408952713 | 0.0101669108306 |
| 14 | rst_count | 7.34798526764 | 0.00965086186831 |
| 15 | TCP | 5.70434522629 | 0.00749210100768 |
| 16 | ack_count | 5.23602962494 | 0.00687701414852 |
| 17 | HTTP | 4.92739915848 | 0.00647165813709 |
| 18 | ICMP | 4.8862195015 | 0.00641757267463 |
| 19 | psh_flag_number | 4.82187604904 | 0.0063330638264 |
| 20 | syn_flag_number | 4.75239419937 | 0.00624180619467 |
| 21 | IAT | 4.24500894547 | 0.00557540515805 |
| 22 | ack_flag_number | 4.22284507751 | 0.00554629507953 |
| 23 | ece_flag_number | 4.14471626282 | 0.00544368050273 |
| 24 | UDP | 3.85862469673 | 0.00506792713832 |
| 25 | Variance | 3.74344658852 | 0.00491665192856 |
| 26 | Header_Length | 3.53852629662 | 0.0046475091147 |
| 27 | DNS | 3.44323372841 | 0.00452235162195 |
| 28 | ARP | 3.14603805542 | 0.0041320140963 |
| 29 | Std | 3.1374900341 | 0.00412078710415 |
| 30 | Time_To_Live | 2.94167590141 | 0.00386360434212 |
| 31 | LLC | 2.86315393448 | 0.00376047339821 |
| 32 | IRC | 2.85714554787 | 0.0037525819685 |
| 33 | IGMP | 2.33984136581 | 0.00307315338732 |
| 34 | IPv | 2.2753007412 | 0.00298838557269 |
| 35 | cwr_flag_number | 2.25533056259 | 0.00296215669114 |
| 36 | Rate | 2.1640625 | 0.00284228499394 |
| 37 | DHCP | 2.11250066757 | 0.00277456355679 |
| 38 | Telnet | 0.392661422491 | 0.000515722475134 |
| 39 | SMTP | 0.391027629375 | 0.00051357664725 |

## Development

| feature_count | accuracy | balanced_accuracy | macro_precision | macro_recall | macro_f1 | weighted_f1 | log_loss | best_iteration |
|---|---|---|---|---|---|---|---|---|
| 39 | 0.8286527780 | 0.7786766395 | 0.7638175383 | 0.7786766395 | 0.7682478170 | 0.8309838445 | 0.4329302311 | 1666 |
| 30 | 0.8275481151 | 0.7784231081 | 0.7615015146 | 0.7784231081 | 0.7666007659 | 0.8301315726 | 0.4350646436 | 1683 |
| 20 | 0.7845129370 | 0.7421537964 | 0.7121535526 | 0.7421537964 | 0.7165063638 | 0.7930505728 | 0.5154891014 | 1376 |
| 15 | 0.7530844989 | 0.7168273861 | 0.6885748918 | 0.7168273861 | 0.6869862900 | 0.7626584257 | 0.5631777048 | 1086 |
| 10 | 0.7331850077 | 0.6980879004 | 0.6717020575 | 0.6980879004 | 0.6640525118 | 0.7459826674 | 0.6064693332 | 943 |
| 5 | 0.6517666827 | 0.6098607839 | 0.5963933944 | 0.6098607839 | 0.5863629258 | 0.6661971669 | 0.7603600025 | 516 |

## Test

| feature_count | accuracy | balanced_accuracy | macro_precision | macro_recall | macro_f1 | weighted_f1 | log_loss |
|---|---|---|---|---|---|---|---|
| 39 | 0.8255589802 | 0.7760109550 | 0.7593526924 | 0.7760109550 | 0.7640493828 | 0.8280798028 | 0.4372141659 |
| 30 | 0.8239906773 | 0.7746173527 | 0.7564707215 | 0.7746173527 | 0.7614298611 | 0.8266827543 | 0.4396718740 |
| 20 | 0.7802088892 | 0.7396304831 | 0.7089452622 | 0.7396304831 | 0.7130981613 | 0.7887256115 | 0.5206559896 |
| 15 | 0.7502695521 | 0.7124811410 | 0.6851037840 | 0.7124811410 | 0.6832510193 | 0.7596808792 | 0.5689061284 |
| 10 | 0.7304370555 | 0.6916813941 | 0.6679205219 | 0.6916813941 | 0.6599304826 | 0.7430981925 | 0.6102758050 |
| 5 | 0.6529912110 | 0.6090419927 | 0.5976132534 | 0.6090419927 | 0.5874902359 | 0.6671706333 | 0.7610580921 |


# 14. Step 7 LOAFO Model Development

For every fold: load outer TRAIN; make a group-safe internal train/dev split; fit a ranking model; rank 39 features; test budgets 39/30/20/15/10/5; apply epsilon=0.005; freeze the feature set; refit the seven-output XGBoost classifier; then emit probabilities for calibration, test-known, and test-unknown. The held-out class has no output column. Calibration and both test sets are untouched by selection, and Step 7 performs no thresholding or conformal inference.

| held_out_family | selected_budget | known_class_count | train_rows | calibration_rows | known_test_rows | unknown_test_rows | known_test_macro_f1 | known_test_balanced_accuracy | model_size_mib |
|---|---|---|---|---|---|---|---|---|---|
| DDoS | 30 | 7 | 365063 | 78230 | 78230 | 90592 | 0.7775585855 | 0.7877478922 | 40.5421171188 |
| DoS | 30 | 7 | 367264 | 78701 | 78701 | 87449 | 0.7750750894 | 0.7878742269 | 39.9814300537 |
| Mirai | 30 | 7 | 358477 | 76819 | 76819 | 100000 | 0.7249423454 | 0.7424517222 | 39.5952768326 |
| Recon | 39 | 7 | 358646 | 76855 | 76855 | 99759 | 0.8170288358 | 0.8267941485 | 31.5413980484 |
| Spoofing | 30 | 7 | 360713 | 77298 | 77298 | 96806 | 0.7534204222 | 0.7668369856 | 36.4318561554 |
| BruteForce | 30 | 7 | 419342 | 89861 | 89861 | 13051 | 0.8051973484 | 0.8143043768 | 28.2082080841 |
| Web | 30 | 7 | 411211 | 88119 | 88119 | 24666 | 0.8097457506 | 0.8198309316 | 32.3966846466 |

Top rankings by fold are archived in `results/loafo_feature_rankings.csv`.


# 15. Step 7 Known-Test Performance

| held_out_family | accuracy | balanced_accuracy | macro_precision | macro_recall | macro_f1 | weighted_f1 | log_loss |
|---|---|---|---|---|---|---|---|
| DDoS | 0.8533427074 | 0.7877478922 | 0.7708135602 | 0.7877478922 | 0.7775585855 | 0.8561134552 | 0.3898302913 |
| DoS | 0.8529497719 | 0.7878742269 | 0.7671033996 | 0.7878742269 | 0.7750750894 | 0.8562013814 | 0.3915955424 |
| Mirai | 0.7885809500 | 0.7424517222 | 0.7188442495 | 0.7424517222 | 0.7249423454 | 0.7923377709 | 0.5283484459 |
| Recon | 0.8738273372 | 0.8267941485 | 0.8138678453 | 0.8267941485 | 0.8170288358 | 0.8753077004 | 0.3108044863 |
| Spoofing | 0.8200470905 | 0.7668369856 | 0.7474490862 | 0.7668369856 | 0.7534204222 | 0.8215126754 | 0.4303917587 |
| BruteForce | 0.8373599225 | 0.8143043768 | 0.8047361468 | 0.8143043768 | 0.8051973484 | 0.8396667134 | 0.3934201598 |
| Web | 0.8509288576 | 0.8198309316 | 0.8070528550 | 0.8198309316 | 0.8097457506 | 0.8522206010 | 0.3604004383 |

Unknown confidence joins by held-out family:

| held_out_family | unknown_rows | mean_max_probability | median_max_probability | p90_max_probability | p95_max_probability | fraction_maxprob_ge_090 | fraction_maxprob_ge_095 | mean_entropy | median_entropy |
|---|---|---|---|---|---|---|---|---|---|
| DDoS | 90592 | 0.9985459447 | 0.9999996424 | 1.0000000000 | 1.0000000000 | 0.9956839456 | 0.9945249029 | 0.0038834712 | 0.0000061252 |
| DoS | 87449 | 0.9819543958 | 0.9999994040 | 0.9999998808 | 0.9999998808 | 0.9083465791 | 0.8985008405 | 0.0489596315 | 0.0000098975 |
| Mirai | 100000 | 0.9887933731 | 0.9995112419 | 0.9998639822 | 0.9998881817 | 0.9698100000 | 0.9528700000 | 0.0335367732 | 0.0043881754 |
| Recon | 99759 | 0.7310962677 | 0.7412968874 | 0.9721784592 | 0.9871598482 | 0.2613298048 | 0.1604166040 | 0.6574178338 | 0.6919037700 |
| Spoofing | 96806 | 0.6258105040 | 0.5999917388 | 0.8991663456 | 0.9533783197 | 0.0993946656 | 0.0536846890 | 0.8840588927 | 0.9407044649 |
| BruteForce | 13051 | 0.6480320692 | 0.6288349628 | 0.9126995802 | 0.9629235864 | 0.1125584246 | 0.0626005670 | 0.8240136504 | 0.8719668388 |
| Web | 24666 | 0.6481607556 | 0.6300632954 | 0.9120227695 | 0.9509306550 | 0.1148949972 | 0.0511230033 | 0.8307950497 | 0.8783327341 |


# 16. Unknown Overconfidence Discovery

The true unknown family is absent from the output space, so every unknown is forced into a known class. DDoS has 99.4524902861% of rows at or above 0.95 confidence, DoS 89.8500840490%, and Mirai 95.2870000000%. These are not rounded to 100%.

| held_out_family | unknown_rows | mean_max_probability | median_max_probability | p90_max_probability | p95_max_probability | fraction_maxprob_ge_090 | fraction_maxprob_ge_095 | mean_entropy | median_entropy |
|---|---|---|---|---|---|---|---|---|---|
| DDoS | 90592 | 0.9985459447 | 0.9999996424 | 1.0000000000 | 1.0000000000 | 0.9956839456 | 0.9945249029 | 0.0038834712 | 0.0000061252 |
| DoS | 87449 | 0.9819543958 | 0.9999994040 | 0.9999998808 | 0.9999998808 | 0.9083465791 | 0.8985008405 | 0.0489596315 | 0.0000098975 |
| Mirai | 100000 | 0.9887933731 | 0.9995112419 | 0.9998639822 | 0.9998881817 | 0.9698100000 | 0.9528700000 | 0.0335367732 | 0.0043881754 |
| Recon | 99759 | 0.7310962677 | 0.7412968874 | 0.9721784592 | 0.9871598482 | 0.2613298048 | 0.1604166040 | 0.6574178338 | 0.6919037700 |
| Spoofing | 96806 | 0.6258105040 | 0.5999917388 | 0.8991663456 | 0.9533783197 | 0.0993946656 | 0.0536846890 | 0.8840588927 | 0.9407044649 |
| BruteForce | 13051 | 0.6480320692 | 0.6288349628 | 0.9126995802 | 0.9629235864 | 0.1125584246 | 0.0626005670 | 0.8240136504 | 0.8719668388 |
| Web | 24666 | 0.6481607556 | 0.6300632954 | 0.9120227695 | 0.9509306550 | 0.1148949972 | 0.0511230033 | 0.8307950497 | 0.8783327341 |


# 17. Forced Known-Class Predictions

The following complete artifact shows semantic confusion such as DDoS→DoS, DoS→DDoS, and Mirai→DDoS/DoS. High confidence in these forced labels is dangerous because it suppresses review.

| held_out_family | predicted_known_family | count | percentage |
|---|---|---|---|
| DDoS | Benign | 1 | 0.0011038502 |
| DDoS | BruteForce | 0 | 0.0000000000 |
| DDoS | DoS | 84844 | 93.6550688803 |
| DDoS | Mirai | 5742 | 6.3383080184 |
| DDoS | Recon | 1 | 0.0011038502 |
| DDoS | Spoofing | 1 | 0.0011038502 |
| DDoS | Web | 3 | 0.0033115507 |
| DoS | Benign | 0 | 0.0000000000 |
| DoS | BruteForce | 0 | 0.0000000000 |
| DoS | DDoS | 87189 | 99.7026838500 |
| DoS | Mirai | 254 | 0.2904550081 |
| DoS | Recon | 4 | 0.0045740946 |
| DoS | Spoofing | 2 | 0.0022870473 |
| DoS | Web | 0 | 0.0000000000 |
| Mirai | Benign | 1 | 0.0010000000 |
| Mirai | BruteForce | 0 | 0.0000000000 |
| Mirai | DDoS | 66416 | 66.4160000000 |
| Mirai | DoS | 33548 | 33.5480000000 |
| Mirai | Recon | 1 | 0.0010000000 |
| Mirai | Spoofing | 34 | 0.0340000000 |
| Mirai | Web | 0 | 0.0000000000 |
| Recon | Benign | 33176 | 33.2561473150 |
| Recon | BruteForce | 23562 | 23.6189216011 |
| Recon | DDoS | 0 | 0.0000000000 |
| Recon | DoS | 1925 | 1.9296504576 |
| Recon | Mirai | 0 | 0.0000000000 |
| Recon | Spoofing | 3716 | 3.7249771950 |
| Recon | Web | 37380 | 37.4703034313 |
| Spoofing | Benign | 21141 | 21.8385224056 |
| Spoofing | BruteForce | 5926 | 6.1215213933 |
| Spoofing | DDoS | 0 | 0.0000000000 |
| Spoofing | DoS | 0 | 0.0000000000 |
| Spoofing | Mirai | 246 | 0.2541164804 |
| Spoofing | Recon | 32353 | 33.4204491457 |
| Spoofing | Web | 37140 | 38.3653905750 |
| BruteForce | Benign | 3375 | 25.8600873496 |
| BruteForce | DDoS | 0 | 0.0000000000 |
| BruteForce | DoS | 0 | 0.0000000000 |
| BruteForce | Mirai | 0 | 0.0000000000 |
| BruteForce | Recon | 6374 | 48.8391694123 |
| BruteForce | Spoofing | 515 | 3.9460577734 |
| BruteForce | Web | 2787 | 21.3546854647 |
| Web | Benign | 4607 | 18.6775318252 |
| Web | BruteForce | 3211 | 13.0179194032 |
| Web | DDoS | 0 | 0.0000000000 |
| Web | DoS | 0 | 0.0000000000 |
| Web | Mirai | 0 | 0.0000000000 |
| Web | Recon | 14107 | 57.1920862726 |
| Web | Spoofing | 2741 | 11.1124624990 |


# 18. Raw Probability Uncertainty Baselines

MSP anomaly is `1-max(p)`, entropy is `-sum(p log p)`, and inverse margin is `1-(p1-p2)`. Unknown is the positive class. AUROC below 0.5 means unknown observations are ranked as less anomalous—often more confident—than known observations. This occurs prominently for DDoS, DoS, and Mirai.

| held_out_family | score | auroc | auprc | known_count | unknown_count |
|---|---|---|---|---|---|
| DDoS | MSP | 0.2764602092 | 0.4105078748 | 78230 | 90592 |
| DDoS | entropy | 0.2697211708 | 0.3991116810 | 78230 | 90592 |
| DDoS | inverse_margin | 0.2812051340 | 0.4108233276 | 78230 | 90592 |
| DoS | MSP | 0.3093975994 | 0.4118589397 | 78701 | 87449 |
| DoS | entropy | 0.3031052496 | 0.3963363376 | 78701 | 87449 |
| DoS | inverse_margin | 0.3155848836 | 0.4081681279 | 78701 | 87449 |
| Mirai | MSP | 0.2679703074 | 0.4214777271 | 76819 | 100000 |
| Mirai | entropy | 0.2643964127 | 0.4208582851 | 76819 | 100000 |
| Mirai | inverse_margin | 0.2736659390 | 0.4229734397 | 76819 | 100000 |
| Recon | MSP | 0.7707477055 | 0.7635464142 | 76855 | 99759 |
| Recon | entropy | 0.7928080852 | 0.7857710201 | 76855 | 99759 |
| Recon | inverse_margin | 0.7604140726 | 0.7445986976 | 76855 | 99759 |
| Spoofing | MSP | 0.7831740029 | 0.7793928970 | 77298 | 96806 |
| Spoofing | entropy | 0.8104797855 | 0.8091783345 | 77298 | 96806 |
| Spoofing | inverse_margin | 0.7627812139 | 0.7438137916 | 77298 | 96806 |
| BruteForce | MSP | 0.7849790547 | 0.2861283214 | 89861 | 13051 |
| BruteForce | entropy | 0.8069100189 | 0.3043276085 | 89861 | 13051 |
| BruteForce | inverse_margin | 0.7711631157 | 0.2584463078 | 89861 | 13051 |
| Web | MSP | 0.8085151504 | 0.4870416779 | 88119 | 24666 |
| Web | entropy | 0.8334406562 | 0.5322221514 | 88119 | 24666 |
| Web | inverse_margin | 0.7921234421 | 0.4274204433 | 88119 | 24666 |


# 19. Why EcoCon-MD Was Introduced

Probability scores measure predictive ambiguity, not feature-distribution membership. EcoCon-MD measures whether a sample is atypical relative to the class that frozen XGBoost predicts.


# 20. EcoCon-MD Technical Implementation

For each fold, the frozen Step-7 features are standardized with a StandardScaler fit on OUTER TRAIN only. Class means are calculated in standardized space. Training residuals are `r_i=x_i-mu_(y_i)`; a shared Ledoit-Wolf covariance yields precision `Sigma^-1`. For predicted class `c_hat`, `D_pred(x)=(x-mu_c_hat)^T Sigma^-1 (x-mu_c_hat)`. Higher is more atypical. Predicted-class distance audits the classifier's chosen semantic class; nearest-MD classification would replace rather than selectively supervise XGBoost.


# 21. EcoCon-MD Conformal Calibration

Known calibration is grouped by predicted class. `p_MD(x)=(1 + #{s_cal >= s(x)})/(n_class+1)`. At alpha 0.05, `p<=alpha` abstains and otherwise accepts XGBoost. Small class groups fall back to broader saved calibration references as implemented. Conformal calibration controls known-score behavior under assumptions; it does not guarantee unseen-family detection.


# 22. EcoCon-MD Raw Discrimination

MD raises DDoS, DoS, and Mirai AUROC above 0.8 despite sub-0.5 probability-score behavior.

| held_out_family | auroc | auprc | known_count | unknown_count |
|---|---|---|---|---|
| DDoS | 0.8051153540 | 0.8649390713 | 78230 | 90592 |
| DoS | 0.8053945354 | 0.7197599152 | 78701 | 87449 |
| Mirai | 0.9436514929 | 0.9520593296 | 76819 | 100000 |
| Recon | 0.7341345308 | 0.7733695872 | 76855 | 99759 |
| Spoofing | 0.7253057456 | 0.7159042124 | 77298 | 96806 |
| BruteForce | 0.6727434326 | 0.4315434355 | 89861 | 13051 |
| Web | 0.6236992659 | 0.2711996882 | 88119 | 24666 |


# 23. Step 8 Selective Results

At alpha 0.05, saved fold-level metrics for forced XGBoost, MSP, entropy, inverse margin, probability conformal, and EcoCon-MD are:

| held_out_family | method | alpha | calibration_rejection_rate | known_rejection_rate | known_acceptance_rate | known_accepted_accuracy | known_selective_risk | UADR | unknown_acceptance_rate | coverage | review_rate | overall_selective_risk | calibration_count | known_count | unknown_count | known_rejected_count | unknown_rejected_count | accepted_known_count | accepted_unknown_count | wrong_known_accepted_count |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8533427074 | 0.1466572926 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6045716790 | 78230 | 78230 | 90592 | 0 | 0 | 78230 | 90592 | 11473 |
| DDoS | MSP | 0.0500000000 | 0.0500063914 | 0.0493672504 | 0.9506327496 | 0.8794777324 | 0.1205222676 | 0.0000220770 | 0.9999779230 | 0.9771119878 | 0.0228880122 | 0.6035051346 | 78230 | 78230 | 90592 | 3862 | 2 | 74368 | 90590 | 8963 |
| DDoS | Entropy | 0.0500000000 | 0.0500063914 | 0.0491627253 | 0.9508372747 | 0.8781458378 | 0.1218541622 | 0.0000220770 | 0.9999779230 | 0.9772067622 | 0.0227932378 | 0.6040588214 | 78230 | 78230 | 90592 | 3846 | 2 | 74384 | 90590 | 9064 |
| DDoS | InverseMargin | 0.0500000000 | 0.0500063914 | 0.0494439473 | 0.9505560527 | 0.8773970576 | 0.1226029424 | 0.0003642706 | 0.9996357294 | 0.9768928220 | 0.0231071780 | 0.6043863426 | 78230 | 78230 | 90592 | 3868 | 33 | 74362 | 90559 | 9117 |
| DDoS | ProbabilityConformal | 0.0500000000 | 0.0499808258 | 0.0493416848 | 0.9506583152 | 0.8794675272 | 0.1205324728 | 0.0000220770 | 0.9999779230 | 0.9771238346 | 0.0228761654 | 0.6035038797 | 78230 | 78230 | 90592 | 3860 | 2 | 74370 | 90590 | 8964 |
| DDoS | EcoConMD | 0.0500000000 | 0.0498529976 | 0.0476927010 | 0.9523072990 | 0.8520382824 | 0.1479617176 | 0.5598949135 | 0.4401050865 | 0.6774531755 | 0.3225468245 | 0.4449894639 | 78230 | 78230 | 90592 | 3731 | 50722 | 74499 | 39870 | 11023 |
| DoS | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8529497719 | 0.1470502281 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.5959795366 | 78701 | 78701 | 87449 | 0 | 0 | 78701 | 87449 | 11573 |
| DoS | MSP | 0.0500000000 | 0.0500120710 | 0.0493767551 | 0.9506232449 | 0.8790215866 | 0.1209784134 | 0.0000114352 | 0.9999885648 | 0.9766054770 | 0.0233945230 | 0.5947073578 | 78701 | 78701 | 87449 | 3886 | 1 | 74815 | 87448 | 9051 |
| DoS | Entropy | 0.0500000000 | 0.0500120710 | 0.0501264279 | 0.9498735721 | 0.8786184387 | 0.1213815613 | 0.0000000000 | 1.0000000000 | 0.9762563948 | 0.0237436052 | 0.5950679695 | 78701 | 78701 | 87449 | 3945 | 0 | 74756 | 87449 | 9074 |
| DoS | InverseMargin | 0.0500000000 | 0.0500120710 | 0.0506346806 | 0.9493653194 | 0.8776834948 | 0.1223165052 | 0.0009719951 | 0.9990280049 | 0.9755040626 | 0.0244959374 | 0.5954035044 | 78701 | 78701 | 87449 | 3985 | 85 | 74716 | 87364 | 9139 |
| DoS | ProbabilityConformal | 0.0500000000 | 0.0499866584 | 0.0493767551 | 0.9506232449 | 0.8790215866 | 0.1209784134 | 0.0000114352 | 0.9999885648 | 0.9766054770 | 0.0233945230 | 0.5947073578 | 78701 | 78701 | 87449 | 3886 | 1 | 74815 | 87448 | 9051 |
| DoS | EcoConMD | 0.0500000000 | 0.0498595952 | 0.0490590971 | 0.9509409029 | 0.8503340460 | 0.1496659540 | 0.0341913572 | 0.9658086428 | 0.9587661751 | 0.0412338249 | 0.6005059668 | 78701 | 78701 | 87449 | 3861 | 2990 | 74840 | 84459 | 11201 |
| Mirai | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.7885809500 | 0.2114190500 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6574010712 | 76819 | 76819 | 100000 | 0 | 0 | 76819 | 100000 | 16241 |
| Mirai | MSP | 0.0500000000 | 0.0500006509 | 0.0505213554 | 0.9494786446 | 0.8118401930 | 0.1881598070 | 0.0000000000 | 1.0000000000 | 0.9780510013 | 0.0219489987 | 0.6575998335 | 76819 | 76819 | 100000 | 3881 | 0 | 72938 | 100000 | 13724 |
| Mirai | Entropy | 0.0500000000 | 0.0500006509 | 0.0487509600 | 0.9512490400 | 0.8106440047 | 0.1893559953 | 0.0000000000 | 1.0000000000 | 0.9788201494 | 0.0211798506 | 0.6577359973 | 76819 | 76819 | 100000 | 3745 | 0 | 73074 | 100000 | 13837 |
| Mirai | InverseMargin | 0.0500000000 | 0.0500006509 | 0.0503781617 | 0.9496218383 | 0.8087156781 | 0.1912843219 | 0.0013400000 | 0.9986600000 | 0.9773553747 | 0.0226446253 | 0.6586233834 | 76819 | 76819 | 100000 | 3870 | 134 | 72949 | 99866 | 13954 |
| Mirai | ProbabilityConformal | 0.0500000000 | 0.0499876333 | 0.0505213554 | 0.9494786446 | 0.8118401930 | 0.1881598070 | 0.0000000000 | 1.0000000000 | 0.9780510013 | 0.0219489987 | 0.6575998335 | 76819 | 76819 | 100000 | 3881 | 0 | 72938 | 100000 | 13724 |
| Mirai | EcoConMD | 0.0500000000 | 0.0498704748 | 0.0494799464 | 0.9505200536 | 0.7847517051 | 0.2152482949 | 0.8317700000 | 0.1682300000 | 0.5080958494 | 0.4919041506 | 0.3621954342 | 76819 | 76819 | 100000 | 3801 | 83177 | 73018 | 16823 | 15717 |
| Recon | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8738273372 | 0.1261726628 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6197470189 | 76855 | 76855 | 99759 | 0 | 0 | 76855 | 99759 | 9697 |
| Recon | MSP | 0.0500000000 | 0.0501203565 | 0.0502764947 | 0.9497235053 | 0.8951377567 | 0.1048622433 | 0.1725658838 | 0.8274341162 | 0.8806493256 | 0.1193506744 | 0.5799209181 | 76855 | 76855 | 99759 | 3864 | 17215 | 72991 | 82544 | 7654 |
| Recon | Entropy | 0.0500000000 | 0.0500032529 | 0.0483247674 | 0.9516752326 | 0.8937668339 | 0.1062331661 | 0.1796429395 | 0.8203570605 | 0.8775012173 | 0.1224987827 | 0.5781944651 | 76855 | 76855 | 99759 | 3714 | 17921 | 73141 | 81838 | 7770 |
| Recon | InverseMargin | 0.0500000000 | 0.0500032529 | 0.0495478498 | 0.9504521502 | 0.8941914110 | 0.1058085890 | 0.1233773394 | 0.8766226606 | 0.9087501557 | 0.0912498443 | 0.5930291966 | 76855 | 76855 | 99759 | 3808 | 12308 | 73047 | 87451 | 7729 |
| Recon | ProbabilityConformal | 0.0500000000 | 0.0495998959 | 0.0498991608 | 0.9501008392 | 0.8949602849 | 0.1050397151 | 0.1725658838 | 0.8274341162 | 0.8808135255 | 0.1191864745 | 0.5799156617 | 76855 | 76855 | 99759 | 3835 | 17215 | 73020 | 82544 | 7670 |
| Recon | EcoConMD | 0.0500000000 | 0.0498601262 | 0.0481686292 | 0.9518313708 | 0.8737167307 | 0.1262832693 | 0.1482973967 | 0.8517026033 | 0.8952744403 | 0.1047255597 | 0.5957765719 | 76855 | 76855 | 99759 | 3702 | 14794 | 73153 | 84965 | 9238 |
| Spoofing | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8200470905 | 0.1799529095 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6359187612 | 77298 | 77298 | 96806 | 0 | 0 | 77298 | 96806 | 13910 |
| Spoofing | MSP | 0.0500000000 | 0.0500012937 | 0.0499883567 | 0.9500116433 | 0.8427431435 | 0.1572568565 | 0.2100283040 | 0.7899716960 | 0.8610255939 | 0.1389744061 | 0.5871734664 | 77298 | 77298 | 96806 | 3864 | 20332 | 73434 | 76474 | 11548 |
| Spoofing | Entropy | 0.0500000000 | 0.0500012937 | 0.0492638878 | 0.9507361122 | 0.8413389577 | 0.1586610423 | 0.2226618185 | 0.7773381815 | 0.8543227037 | 0.1456772963 | 0.5843109835 | 77298 | 77298 | 96806 | 3808 | 21555 | 73490 | 75251 | 11660 |
| Spoofing | InverseMargin | 0.0500000000 | 0.0504411498 | 0.0508421951 | 0.9491578049 | 0.8399983644 | 0.1600016356 | 0.1325744272 | 0.8674255728 | 0.9037127234 | 0.0962872766 | 0.6083068514 | 77298 | 77298 | 96806 | 3930 | 12834 | 73368 | 83972 | 11739 |
| Spoofing | ProbabilityConformal | 0.0500000000 | 0.0499754198 | 0.0499883567 | 0.9500116433 | 0.8427431435 | 0.1572568565 | 0.2099973142 | 0.7900026858 | 0.8610428250 | 0.1389571750 | 0.5871817278 | 77298 | 77298 | 96806 | 3864 | 20329 | 73434 | 76477 | 11548 |
| Spoofing | EcoConMD | 0.0500000000 | 0.0498719242 | 0.0491215814 | 0.9508784186 | 0.8167099767 | 0.1832900233 | 0.1032064128 | 0.8967935872 | 0.9208059551 | 0.0791940449 | 0.6255582724 | 77298 | 77298 | 96806 | 3797 | 9991 | 73501 | 86815 | 13472 |
| BruteForce | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8373599225 | 0.1626400775 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.2688316231 | 89861 | 89861 | 13051 | 0 | 0 | 89861 | 13051 | 14615 |
| BruteForce | MSP | 0.0500000000 | 0.0500105719 | 0.0485972780 | 0.9514027220 | 0.8596041827 | 0.1403958173 | 0.1786836258 | 0.8213163742 | 0.9349055504 | 0.0650944496 | 0.2361635122 | 89861 | 89861 | 13051 | 4367 | 2332 | 85494 | 10719 | 12003 |
| BruteForce | Entropy | 0.0500000000 | 0.0500105719 | 0.0484526101 | 0.9515473899 | 0.8587717965 | 0.1412282035 | 0.1615201900 | 0.8384798100 | 0.9372084888 | 0.0627915112 | 0.2386625194 | 89861 | 89861 | 13051 | 4354 | 2108 | 85507 | 10943 | 12076 |
| BruteForce | InverseMargin | 0.0500000000 | 0.0500105719 | 0.0501552398 | 0.9498447602 | 0.8583077536 | 0.1416922464 | 0.1327101372 | 0.8672898628 | 0.9393753887 | 0.0606246113 | 0.2421875808 | 89861 | 89861 | 13051 | 4507 | 1732 | 85354 | 11319 | 12094 |
| BruteForce | ProbabilityConformal | 0.0500000000 | 0.0499883153 | 0.0485972780 | 0.9514027220 | 0.8596041827 | 0.1403958173 | 0.1786836258 | 0.8213163742 | 0.9349055504 | 0.0650944496 | 0.2361635122 | 89861 | 89861 | 13051 | 4367 | 2332 | 85494 | 10719 | 12003 |
| BruteForce | EcoConMD | 0.0500000000 | 0.0498881606 | 0.0482411725 | 0.9517588275 | 0.8346233894 | 0.1653766106 | 0.3145352847 | 0.6854647153 | 0.9179881841 | 0.0820118159 | 0.2444110424 | 89861 | 89861 | 13051 | 4335 | 4105 | 85526 | 8946 | 14144 |
| Web | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8509288576 | 0.1490711424 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.3351686838 | 88119 | 88119 | 24666 | 0 | 0 | 88119 | 24666 | 13136 |
| Web | MSP | 0.0500000000 | 0.0500005674 | 0.0501821401 | 0.9498178599 | 0.8731137317 | 0.1268862683 | 0.2545609341 | 0.7454390659 | 0.9051203618 | 0.0948796382 | 0.2841483484 | 88119 | 88119 | 24666 | 4422 | 6279 | 83697 | 18387 | 10620 |
| Web | Entropy | 0.0500000000 | 0.0500005674 | 0.0490019179 | 0.9509980821 | 0.8718034391 | 0.1281965609 | 0.2682640071 | 0.7317359929 | 0.9030456178 | 0.0969543822 | 0.2826902307 | 88119 | 88119 | 24666 | 4318 | 6617 | 83801 | 18049 | 10743 |
| Web | InverseMargin | 0.0500000000 | 0.0500232640 | 0.0508289926 | 0.9491710074 | 0.8718436155 | 0.1281563845 | 0.1536122598 | 0.8463877402 | 0.9266923793 | 0.0733076207 | 0.3023048882 | 88119 | 88119 | 24666 | 4479 | 3789 | 83640 | 20877 | 10719 |
| Web | ProbabilityConformal | 0.0500000000 | 0.0499892191 | 0.0501707918 | 0.9498292082 | 0.8731152477 | 0.1268847523 | 0.2545609341 | 0.7454390659 | 0.9051292282 | 0.0948707718 | 0.2841455650 | 88119 | 88119 | 24666 | 4421 | 6279 | 83698 | 18387 | 10620 |
| Web | EcoConMD | 0.0500000000 | 0.0498984328 | 0.0484571999 | 0.9515428001 | 0.8488831113 | 0.1511168887 | 0.0586637477 | 0.9413362523 | 0.9493106353 | 0.0506893647 | 0.3352075317 | 88119 | 88119 | 24666 | 4270 | 1447 | 83849 | 23219 | 12671 |


# 24. Step 8 Macro and Micro Results

Macro aggregation weights seven held-out families equally and is primary. Micro aggregation weights rows and therefore reflects sampled prevalence.

| method | alpha | aggregation | mean_or_aggregate_known_rejection | UADR | coverage | overall_selective_risk | known_selective_risk |
|---|---|---|---|---|---|---|---|
| EcoConMD | 0.0100000000 | macro | 0.0099810893 | 0.2225473541 | 0.8880151246 | 0.4751993648 | 0.1604486222 |
| EcoConMD | 0.0100000000 | micro | 0.0099914647 | 0.2472990672 | 0.8772488745 | 0.5025897204 | 0.1602041308 |
| EcoConMD | 0.0250000000 | macro | 0.0237985728 | 0.2471714408 | 0.8694141856 | 0.4722713324 | 0.1613018693 |
| EcoConMD | 0.0250000000 | micro | 0.0237964385 | 0.2721915666 | 0.8581755249 | 0.4991397292 | 0.1610667304 |
| EcoConMD | 0.0500000000 | macro | 0.0486029039 | 0.2929370161 | 0.8325277735 | 0.4583777548 | 0.1627061084 |
| EcoConMD | 0.0500000000 | micro | 0.0485913166 | 0.3264073641 | 0.8194009308 | 0.4896110055 | 0.1624596479 |
| EcoConMD | 0.1000000000 | macro | 0.0979196017 | 0.3586883643 | 0.7721105288 | 0.4393944696 | 0.1654660822 |
| EcoConMD | 0.1000000000 | micro | 0.0979213018 | 0.4034661727 | 0.7568952501 | 0.4778314620 | 0.1652101686 |
| EcoConMD | 0.1500000000 | macro | 0.1480084187 | 0.4047053888 | 0.7239027929 | 0.4363463787 | 0.1674954523 |
| EcoConMD | 0.1500000000 | micro | 0.1480058599 | 0.4491541469 | 0.7088997835 | 0.4747141325 | 0.1672415474 |
| EcoConMD | 0.2000000000 | macro | 0.1982920045 | 0.4457048428 | 0.6788045041 | 0.4352341441 | 0.1675811141 |
| EcoConMD | 0.2000000000 | micro | 0.1982777359 | 0.4870794401 | 0.6644945400 | 0.4727396568 | 0.1673400473 |
| Entropy | 0.0100000000 | macro | 0.0095584245 | 0.0268668742 | 0.9847479002 | 0.5255241208 | 0.1555183760 |
| Entropy | 0.0100000000 | micro | 0.0095532115 | 0.0214747337 | 0.9847821288 | 0.5541101038 | 0.1552820187 |
| Entropy | 0.0250000000 | macro | 0.0250121625 | 0.0627795478 | 0.9632257458 | 0.5180675570 | 0.1484263676 |
| Entropy | 0.0250000000 | micro | 0.0249963332 | 0.0492814104 | 0.9634643102 | 0.5475980759 | 0.1482170885 |
| Entropy | 0.0500000000 | macro | 0.0490118995 | 0.1188730046 | 0.9291944763 | 0.5058172839 | 0.1381300988 |
| Entropy | 0.0500000000 | micro | 0.0490030625 | 0.0940871286 | 0.9295746824 | 0.5371231192 | 0.1379236017 |
| Entropy | 0.1000000000 | macro | 0.0981494429 | 0.2269754724 | 0.8612372653 | 0.4791923003 | 0.1191894730 |
| Entropy | 0.1000000000 | micro | 0.0981457298 | 0.1829666051 | 0.8615505757 | 0.5159931491 | 0.1190099227 |
| Entropy | 0.1500000000 | macro | 0.1474603135 | 0.3114288817 | 0.8053875029 | 0.4566577446 | 0.1018011986 |
| Entropy | 0.1500000000 | micro | 0.1474315362 | 0.2434831151 | 0.8069283606 | 0.5018947514 | 0.1017402695 |
| Entropy | 0.2000000000 | macro | 0.1972246862 | 0.3689200196 | 0.7585672193 | 0.4393102573 | 0.0854213029 |
| Entropy | 0.2000000000 | micro | 0.1972351175 | 0.2841820492 | 0.7614509658 | 0.4939433691 | 0.0854071688 |
| ForcedXGBoost | 0.0100000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.0100000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| ForcedXGBoost | 0.0250000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.0250000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| ForcedXGBoost | 0.0500000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.0500000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| ForcedXGBoost | 0.1000000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.1000000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| ForcedXGBoost | 0.1500000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.1500000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| ForcedXGBoost | 0.2000000000 | macro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5310883391 | 0.1604233376 |
| ForcedXGBoost | 0.2000000000 | micro | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.5592326513 | 0.1601832888 |
| InverseMargin | 0.0100000000 | macro | 0.0099954233 | 0.0174568957 | 0.9881996163 | 0.5275961352 | 0.1560225991 |
| InverseMargin | 0.0100000000 | micro | 0.0099985333 | 0.0134368357 | 0.9883677145 | 0.5561875038 | 0.1557766969 |
| InverseMargin | 0.0250000000 | macro | 0.0255544652 | 0.0413260453 | 0.9709297416 | 0.5226553221 | 0.1492809690 |
| InverseMargin | 0.0250000000 | micro | 0.0255547525 | 0.0320539972 | 0.9713570505 | 0.5519691633 | 0.1490491856 |
| InverseMargin | 0.0500000000 | macro | 0.0502615810 | 0.0778500613 | 0.9440404152 | 0.5148916782 | 0.1388375178 |
| InverseMargin | 0.0500000000 | micro | 0.0502701088 | 0.0603427916 | 0.9449437306 | 0.5456173860 | 0.1386044106 |
| InverseMargin | 0.1000000000 | macro | 0.1002321287 | 0.1536733834 | 0.8888374667 | 0.4977793027 | 0.1179617746 |
| InverseMargin | 0.1000000000 | micro | 0.1002150621 | 0.1197076844 | 0.8905227758 | 0.5321543023 | 0.1177654746 |
| InverseMargin | 0.1500000000 | macro | 0.1496488303 | 0.2242424709 | 0.8360768705 | 0.4804213795 | 0.0982867592 |
| InverseMargin | 0.1500000000 | micro | 0.1496298705 | 0.1742611595 | 0.8386662660 | 0.5200524188 | 0.0981172461 |
| InverseMargin | 0.2000000000 | macro | 0.1982448878 | 0.2889220986 | 0.7855029473 | 0.4628873053 | 0.0804151854 |
| InverseMargin | 0.2000000000 | micro | 0.1982635987 | 0.2249772116 | 0.7890430957 | 0.5095157102 | 0.0802510090 |
| MSP | 0.0100000000 | macro | 0.0100032389 | 0.0246784695 | 0.9854999293 | 0.5258348070 | 0.1551035303 |
| MSP | 0.0100000000 | micro | 0.0099879304 | 0.0193198431 | 0.9855778951 | 0.5544512994 | 0.1548753996 |
| MSP | 0.0250000000 | macro | 0.0243644778 | 0.0602661255 | 0.9645390052 | 0.5183398171 | 0.1482474553 |
| MSP | 0.0250000000 | micro | 0.0243424878 | 0.0473861216 | 0.9647080428 | 0.5477756178 | 0.1480235751 |
| MSP | 0.0500000000 | macro | 0.0497585186 | 0.1165531800 | 0.9304956140 | 0.5061740816 | 0.1370088105 |
| MSP | 0.0500000000 | micro | 0.0497381968 | 0.0901013618 | 0.9310827430 | 0.5376287854 | 0.1368010756 |
| MSP | 0.1000000000 | macro | 0.0994040181 | 0.1892662821 | 0.8764361928 | 0.4884848161 | 0.1164301991 |
| MSP | 0.1000000000 | micro | 0.0994039404 | 0.1474928902 | 0.8777459966 | 0.5240994473 | 0.1162485872 |
| MSP | 0.1500000000 | macro | 0.1487450359 | 0.2517545330 | 0.8262447633 | 0.4720481028 | 0.0975634419 |
| MSP | 0.1500000000 | micro | 0.1487586657 | 0.1966064377 | 0.8285058699 | 0.5132777342 | 0.0973919614 |
| MSP | 0.2000000000 | macro | 0.1980374124 | 0.3088027726 | 0.7781747498 | 0.4558029192 | 0.0799168212 |
| MSP | 0.2000000000 | micro | 0.1980709793 | 0.2411525542 | 0.7814582742 | 0.5043705412 | 0.0797579540 |
| ProbabilityConformal | 0.0100000000 | macro | 0.0099995213 | 0.0246597460 | 0.9855101051 | 0.5258392129 | 0.1551068313 |
| ProbabilityConformal | 0.0100000000 | micro | 0.0099843961 | 0.0193003242 | 0.9855890247 | 0.5544563307 | 0.1548784167 |
| ProbabilityConformal | 0.0250000000 | macro | 0.0243607593 | 0.0602559703 | 0.9645463190 | 0.5183411777 | 0.1482468571 |
| ProbabilityConformal | 0.0250000000 | micro | 0.0243389535 | 0.0473724584 | 0.9647163900 | 0.5477776079 | 0.1480230389 |
| ProbabilityConformal | 0.0500000000 | macro | 0.0496993404 | 0.1165487529 | 0.9305244917 | 0.5061739340 | 0.1370354049 |
| ProbabilityConformal | 0.0500000000 | micro | 0.0496816480 | 0.0900955062 | 0.9311152043 | 0.5376299637 | 0.1368245473 |
| ProbabilityConformal | 0.1000000000 | macro | 0.0993311330 | 0.1892591219 | 0.8764947006 | 0.4885044867 | 0.1164666649 |
| ProbabilityConformal | 0.1000000000 | micro | 0.0993261858 | 0.1474831308 | 0.8777914425 | 0.5241040108 | 0.1162876023 |
| ProbabilityConformal | 0.1500000000 | macro | 0.1487365926 | 0.2517487175 | 0.8262538552 | 0.4720537525 | 0.0975705983 |
| ProbabilityConformal | 0.1500000000 | micro | 0.1487498299 | 0.1965986302 | 0.8285142171 | 0.5132815185 | 0.0973992543 |
| ProbabilityConformal | 0.2000000000 | macro | 0.1979785074 | 0.3088027726 | 0.7782015491 | 0.4557985523 | 0.0799368762 |
| ProbabilityConformal | 0.2000000000 | micro | 0.1980144305 | 0.2411525542 | 0.7814879531 | 0.5043656280 | 0.0797787718 |


# 25. EcoCon-MD High-Confidence Rescue

Rescue rate is the fraction of unknown rows with XGBoost confidence ≥0.95 that MD rejects. DDoS and Mirai demonstrate that feature-space evidence can rescue confident forced errors.

| held_out_family | unknown_ge_095_count | unknown_ge_095_percentage | ecocon_rejected_count | ecocon_rescue_rate |
|---|---|---|---|---|
| DDoS | 90096 | 99.4524902861 | 50233 | 0.5575497247 |
| DoS | 78573 | 89.8500840490 | 2748 | 0.0349738460 |
| Mirai | 95287 | 95.2870000000 | 82517 | 0.8659838173 |
| Recon | 16003 | 16.0416604016 | 3982 | 0.2488283447 |
| Spoofing | 5197 | 5.3684688966 | 682 | 0.1312295555 |
| BruteForce | 817 | 6.2600567006 | 448 | 0.5483476132 |
| Web | 1261 | 5.1123003324 | 58 | 0.0459952419 |


# 26. Step 8 AURC / Curve Results

Risk-coverage and UADR-versus-known-rejection curves evaluate the complete threshold tradeoff; lower area under risk-coverage is preferable when defined as accumulated risk. MD improves several high-confidence families but loses to probability signals on others and is not universally superior.

| held_out_family | method | AURC |
|---|---|---|
| BruteForce | EcoConMD | 0.2500385160 |
| BruteForce | Entropy | 0.0801717080 |
| BruteForce | ForcedXGBoost | 0.1344158116 |
| BruteForce | InverseMargin | 0.0824358892 |
| BruteForce | MSP | 0.0809248926 |
| BruteForce | ProbabilityConformal | 0.0809246483 |
| DDoS | EcoConMD | 0.4638684458 |
| DDoS | Entropy | 0.6909089275 |
| DDoS | ForcedXGBoost | 0.3022858395 |
| DDoS | InverseMargin | 0.6100597796 |
| DDoS | MSP | 0.6034888904 |
| DDoS | ProbabilityConformal | 0.6034887780 |
| DoS | EcoConMD | 0.5392451120 |
| DoS | Entropy | 0.5984736610 |
| DoS | ForcedXGBoost | 0.2979897683 |
| DoS | InverseMargin | 0.5743741118 |
| DoS | MSP | 0.5682733420 |
| DoS | ProbabilityConformal | 0.5682732601 |
| Mirai | EcoConMD | 0.3810232975 |
| Mirai | Entropy | 0.6088851674 |
| Mirai | ForcedXGBoost | 0.3287005356 |
| Mirai | InverseMargin | 0.6032826610 |
| Mirai | MSP | 0.6070327559 |
| Mirai | ProbabilityConformal | 0.6070354414 |
| Recon | EcoConMD | 0.5362750993 |
| Recon | Entropy | 0.3378373633 |
| Recon | ForcedXGBoost | 0.3098735095 |
| Recon | InverseMargin | 0.3462239475 |
| Recon | MSP | 0.3433618826 |
| Recon | ProbabilityConformal | 0.3433604018 |
| Spoofing | EcoConMD | 0.5383912755 |
| Spoofing | Entropy | 0.3471430306 |
| Spoofing | ForcedXGBoost | 0.3179593806 |
| Spoofing | InverseMargin | 0.3600978231 |
| Spoofing | MSP | 0.3546270270 |
| Spoofing | ProbabilityConformal | 0.3546261565 |
| Web | EcoConMD | 0.3277164895 |
| Web | Entropy | 0.1083876618 |
| Web | ForcedXGBoost | 0.1675843419 |
| Web | InverseMargin | 0.1131686405 |
| Web | MSP | 0.1108294921 |
| Web | ProbabilityConformal | 0.1108292576 |


# 27. Step 8 Statistical Analysis

Only seven independent outer-family observations enter paired Wilcoxon tests. Step-8 comparisons are not significant at 0.05 and must not be overstated.

| outcome | comparison | median_paired_difference | effect_direction | wilcoxon_statistic | p_value | note |
|---|---|---|---|---|---|---|
| UADR | EcoConMD vs MSP | 0.0341799220 | EcoConMD higher | 9.0000000000 | 0.4687500000 | n=7; interpret cautiously |
| UADR | EcoConMD vs Entropy | 0.0341913572 | EcoConMD higher | 9.0000000000 | 0.4687500000 | n=7; interpret cautiously |
| overall_selective_risk | EcoConMD vs MSP | 0.0082475302 | EcoConMD higher | 13.0000000000 | 0.9375000000 | n=7; interpret cautiously |
| overall_selective_risk | EcoConMD vs Entropy | 0.0057485230 | EcoConMD higher | 13.0000000000 | 0.9375000000 | n=7; interpret cautiously |


# 28. Why EcoCon-Fuse Was Attempted

MD was strong for DDoS/Mirai while entropy or MSP were stronger for Recon, Spoofing, and Web. This complementary behavior motivated a fixed fusion of feature conformity and predictive uncertainty.


# 29. EcoCon-Fuse Implementation

Calibration is group-safely divided into CAL-A and CAL-B. CAL-A constructs `p_MD` and `p_ENT`; fused nonconformity is `max(-log p_MD,-log p_ENT)=-log(min(p_MD,p_ENT))`. CAL-B performs second-stage known-only calibration at alpha 0.05. There are no learned fusion weights and no unknown tuning.


# 30. EcoCon-Fuse Results and Failure

Predeclared primary success required higher UADR than MD and entropy, risk no worse than MD, and known rejection in [0.04,0.06]. Robustness required winning ≥5/7 or being within 0.02 on ≥6/7 with better macro UADR. PRIMARY SUCCESS = FAIL; ROBUSTNESS = FAIL; OUTCOME C = NO IMPROVEMENT. Fuse slightly raised UADR but worsened risk and degraded Mirai. It is a frozen unsuccessful extension/ablation.

| method | known_rejection_rate | UADR | coverage | review_rate | overall_selective_risk | known_selective_risk |
|---|---|---|---|---|---|---|
| EcoConFuse | 0.0480486101 | 0.3021256821 | 0.8326903491 | 0.1673096509 | 0.4602687195 | 0.1538960555 |
| EcoConMD | 0.0486029039 | 0.2929370161 | 0.8325277735 | 0.1674722265 | 0.4583777548 | 0.1627061083 |
| Entropy | 0.0490118995 | 0.1188730046 | 0.9291944763 | 0.0708055237 | 0.5058172838 | 0.1381300988 |
| MSP | 0.0497585186 | 0.1165531800 | 0.9304956140 | 0.0695043860 | 0.5061740816 | 0.1370088105 |
| NestedEntropy | 0.0482107184 | 0.1440943812 | 0.9068935360 | 0.0931064640 | 0.4995660101 | 0.1467888137 |
| NestedMD | 0.0489107059 | 0.2943000227 | 0.8317608117 | 0.1682391883 | 0.4582226486 | 0.1627282337 |

## Family results

| held_out_family | MSP | Entropy | EcoConMD | EcoConFuse | best_existing_uadr | fusion_regret | best_method |
|---|---|---|---|---|---|---|---|
| BruteForce | 0.1786836258 | 0.1615201900 | 0.3145352847 | 0.3443414298 | 0.3145352847 | 0.0298061451 | EcoConFuse |
| DDoS | 0.0000220770 | 0.0000220770 | 0.5598949135 | 0.5585261392 | 0.5598949135 | -0.0013687743 | EcoConMD |
| DoS | 0.0000114352 | 0.0000000000 | 0.0341913572 | 0.1736783725 | 0.0341913572 | 0.1394870153 | EcoConFuse |
| Mirai | 0.0000000000 | 0.0000000000 | 0.8317700000 | 0.6624600000 | 0.8317700000 | -0.1693100000 | EcoConMD |
| Recon | 0.1725658838 | 0.1796429395 | 0.1482973967 | 0.1358574164 | 0.1796429395 | -0.0437855231 | Entropy |
| Spoofing | 0.2100283040 | 0.2226618185 | 0.1032064128 | 0.1318513315 | 0.2226618185 | -0.0908104870 | Entropy |
| Web | 0.2545609341 | 0.2682640071 | 0.0586637477 | 0.1081650855 | 0.2682640071 | -0.1600989216 | Entropy |


# 31. Fresh Confirmation Dataset

`processed/fresh_confirmation_unknown.parquet` uses seed 314159 and up to 5,000 unique finite hashes per eligible family: DDoS, DoS, Mirai, Recon, and Spoofing. Hashes are absent from research/modeling pools and excluded conflicts; fresh hashes do not duplicate one another. This is fresh-sample confirmation within CICIoT2023, not external validation.


# 32. Why EcoCon-NOS Was Introduced

No fixed uncertainty detector dominates every family shift, and fixed fusion also failed. EcoCon-NOS asks whether an appropriate detector can be selected using only known outer-training data before the true outer unknown appears.


# 33. EcoCon-NOS Nested Open-Set Structure

```text
OUTER TRAIN only ──> inner fine-label pseudo-OOD folds ──> select detector
       │                                                    │
       └────────────────> known CALIBRATION ──> threshold   │
                                                            v
SEALED outer unknown + test-known ───────────────────> frozen evaluation
```
The real outer unknown is unavailable during candidate design, candidate selection, threshold selection, feature selection, and model selection.


# 34. Inner Pseudo-Unknown Fold Generation

Eligible fine labels have at least 1,000 outer-training rows. Up to 12 are selected to maximize parent-family diversity, then support, with deterministic alphabetical ties—not detector performance.

| Outer | Fold | fine_label | family | rows |
|---|---|---|---|---|
| DDoS | 1 | DoS-HTTP_Flood | DoS | 1297 |
| DDoS | 2 | Mirai-greeth_flood | Mirai | 26314 |
| DDoS | 3 | Recon-HostDiscovery | Recon | 13564 |
| DDoS | 4 | DNS_Spoofing | Spoofing | 25761 |
| DDoS | 5 | Backdoor_Malware | Web | 2195 |
| DDoS | 6 | DoS-SYN_Flood | DoS | 15244 |
| DDoS | 7 | Mirai-greip_flood | Mirai | 20102 |
| DDoS | 8 | Recon-OSScan | Recon | 10163 |
| DDoS | 9 | MITM-ArpSpoofing | Spoofing | 42003 |
| DDoS | 10 | BrowserHijacking | Web | 4046 |
| DDoS | 11 | DoS-TCP_Flood | DoS | 19699 |
| DDoS | 12 | Mirai-udpplain | Mirai | 23584 |
| DoS | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| DoS | 2 | Mirai-greeth_flood | Mirai | 26314 |
| DoS | 3 | Recon-HostDiscovery | Recon | 13564 |
| DoS | 4 | DNS_Spoofing | Spoofing | 25761 |
| DoS | 5 | Backdoor_Malware | Web | 2195 |
| DoS | 6 | DDoS-ICMP_Flood | DDoS | 13787 |
| DoS | 7 | Mirai-greip_flood | Mirai | 20102 |
| DoS | 8 | Recon-OSScan | Recon | 10163 |
| DoS | 9 | MITM-ArpSpoofing | Spoofing | 42003 |
| DoS | 10 | BrowserHijacking | Web | 4046 |
| DoS | 11 | DDoS-ICMP_Fragmentation | DDoS | 1539 |
| DoS | 12 | Mirai-udpplain | Mirai | 23584 |
| Mirai | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| Mirai | 2 | DoS-HTTP_Flood | DoS | 1297 |
| Mirai | 3 | Recon-HostDiscovery | Recon | 13564 |
| Mirai | 4 | DNS_Spoofing | Spoofing | 25761 |
| Mirai | 5 | Backdoor_Malware | Web | 2195 |
| Mirai | 6 | DDoS-ICMP_Flood | DDoS | 13787 |
| Mirai | 7 | DoS-SYN_Flood | DoS | 15244 |
| Mirai | 8 | Recon-OSScan | Recon | 10163 |
| Mirai | 9 | MITM-ArpSpoofing | Spoofing | 42003 |
| Mirai | 10 | BrowserHijacking | Web | 4046 |
| Mirai | 11 | DDoS-ICMP_Fragmentation | DDoS | 1539 |
| Mirai | 12 | DoS-TCP_Flood | DoS | 19699 |
| Recon | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| Recon | 2 | DoS-HTTP_Flood | DoS | 1297 |
| Recon | 3 | Mirai-greeth_flood | Mirai | 26314 |
| Recon | 4 | DNS_Spoofing | Spoofing | 25761 |
| Recon | 5 | Backdoor_Malware | Web | 2195 |
| Recon | 6 | DDoS-ICMP_Flood | DDoS | 13787 |
| Recon | 7 | DoS-SYN_Flood | DoS | 15244 |
| Recon | 8 | Mirai-greip_flood | Mirai | 20102 |
| Recon | 9 | MITM-ArpSpoofing | Spoofing | 42003 |
| Recon | 10 | BrowserHijacking | Web | 4046 |
| Recon | 11 | DDoS-ICMP_Fragmentation | DDoS | 1539 |
| Recon | 12 | DoS-TCP_Flood | DoS | 19699 |
| Spoofing | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| Spoofing | 2 | DoS-HTTP_Flood | DoS | 1297 |
| Spoofing | 3 | Mirai-greeth_flood | Mirai | 26314 |
| Spoofing | 4 | Recon-HostDiscovery | Recon | 13564 |
| Spoofing | 5 | Backdoor_Malware | Web | 2195 |
| Spoofing | 6 | DDoS-ICMP_Flood | DDoS | 13787 |
| Spoofing | 7 | DoS-SYN_Flood | DoS | 15244 |
| Spoofing | 8 | Mirai-greip_flood | Mirai | 20102 |
| Spoofing | 9 | Recon-OSScan | Recon | 10163 |
| Spoofing | 10 | BrowserHijacking | Web | 4046 |
| Spoofing | 11 | DDoS-ICMP_Fragmentation | DDoS | 1539 |
| Spoofing | 12 | DoS-TCP_Flood | DoS | 19699 |
| BruteForce | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| BruteForce | 2 | DoS-HTTP_Flood | DoS | 1297 |
| BruteForce | 3 | Mirai-greeth_flood | Mirai | 26314 |
| BruteForce | 4 | Recon-HostDiscovery | Recon | 13564 |
| BruteForce | 5 | DNS_Spoofing | Spoofing | 25761 |
| BruteForce | 6 | Backdoor_Malware | Web | 2195 |
| BruteForce | 7 | DDoS-ICMP_Flood | DDoS | 13787 |
| BruteForce | 8 | DoS-SYN_Flood | DoS | 15244 |
| BruteForce | 9 | Mirai-greip_flood | Mirai | 20102 |
| BruteForce | 10 | Recon-OSScan | Recon | 10163 |
| BruteForce | 11 | MITM-ArpSpoofing | Spoofing | 42003 |
| BruteForce | 12 | BrowserHijacking | Web | 4046 |
| Web | 1 | DDoS-ACK_Fragmentation | DDoS | 1236 |
| Web | 2 | DoS-HTTP_Flood | DoS | 1297 |
| Web | 3 | Mirai-greeth_flood | Mirai | 26314 |
| Web | 4 | Recon-HostDiscovery | Recon | 13564 |
| Web | 5 | DNS_Spoofing | Spoofing | 25761 |
| Web | 6 | DDoS-ICMP_Flood | DDoS | 13787 |
| Web | 7 | DoS-SYN_Flood | DoS | 15244 |
| Web | 8 | Mirai-greip_flood | Mirai | 20102 |
| Web | 9 | Recon-OSScan | Recon | 10163 |
| Web | 10 | MITM-ArpSpoofing | Spoofing | 42003 |
| Web | 11 | DDoS-ICMP_Fragmentation | DDoS | 1539 |
| Web | 12 | DoS-TCP_Flood | DoS | 19699 |


# 35. Inner Reference / Validation Split

For each inner fold the chosen fine label becomes INNER_PSEUDO_UNKNOWN. Remaining outer-training rows are group-safely split approximately 80% INNER_REFERENCE and 20% INNER_VALID_KNOWN with zero hash overlap. The latter sets the ≈5% known-rejection threshold; pseudo-unknown rows evaluate candidates only inside OUTER TRAIN.


# 36. Seven EcoCon-NOS Candidate Detectors

Candidates are MSP; predictive entropy; MD-Pred; Min-MD (minimum class Mahalanobis distance); MDS (Mahalanobis distance structure); ClassConditionalKNN; and GlobalKNN. Probability candidates use frozen XGBoost probabilities. MD candidates use standardized training references and covariance geometry. kNN uses Euclidean distance with `n_neighbors=10`, at most 20,000 reference rows per class and 100,000 globally; saved implementation uses compact numeric references. Every score is oriented so larger means more anomalous.


# 37. EcoCon-NOS Inner Evaluation

Each candidate threshold comes only from INNER_VALID_KNOWN at target rejection 0.05; UADR, overall risk, AUROC, AUPRC, and known rejection are then measured on INNER_PSEUDO_UNKNOWN. Saved rows: 588 = 7 outer folds × 12 inner folds × 7 candidates = 588.


# 38. Detector-Selection Rule

Primary: highest mean inner UADR. Candidates within 0.01 are compared by lower mean overall selective risk; remaining ties use higher worst-inner-fold UADR and finally a fixed lower-cost candidate order. The rule is implemented before outer evaluation.


# 39. Complete Inner Candidate Results

The complete candidate summary is below; the row-level 588-evaluation archive is `results/ecocon_nos_inner_results.csv`.

| outer_held_out_family | candidate | mean_UADR | median_UADR | std_UADR | worst_UADR | mean_overall_risk | inner_fold_wins |
|---|---|---|---|---|---|---|---|
| DDoS | ClassConditionalKNN | 0.3627407333 | 0.1780591121 | 0.3943114303 | 0.0093486357 | 0.1861617226 | 4 |
| DDoS | Entropy | 0.0385473566 | 0.0246887127 | 0.0453578278 | 0.0000000000 | 0.2212267402 | 0 |
| DDoS | GlobalKNN | 0.3853327988 | 0.1075957615 | 0.4543821980 | 0.0107167287 | 0.1813589294 | 1 |
| DDoS | MD-Pred | 0.3902809299 | 0.1564693173 | 0.4419043273 | 0.0138709432 | 0.1789036983 | 5 |
| DDoS | MDS | 0.3614363033 | 0.0689362868 | 0.4717195813 | 0.0116843290 | 0.1840480012 | 1 |
| DDoS | MSP | 0.0349542216 | 0.0170842825 | 0.0452041617 | 0.0000000000 | 0.2186585684 | 0 |
| DDoS | Min-MD | 0.3890729360 | 0.1662491536 | 0.4427377530 | 0.0121608269 | 0.1793445430 | 2 |
| DoS | ClassConditionalKNN | 0.4173122282 | 0.1897267601 | 0.4383315826 | 0.0088165995 | 0.1789835157 | 8 |
| DoS | Entropy | 0.0395966891 | 0.0248291572 | 0.0465104166 | 0.0000000000 | 0.2044862157 | 0 |
| DoS | GlobalKNN | 0.3862950050 | 0.1004677187 | 0.4547887295 | 0.0098426693 | 0.1837841620 | 3 |
| DoS | MD-Pred | 0.3780220330 | 0.1309030325 | 0.4592631302 | 0.0104127081 | 0.1842000390 | 2 |
| DoS | MDS | 0.2946640693 | 0.0673729270 | 0.4263091799 | 0.0099186745 | 0.1864881895 | 0 |
| DoS | MSP | 0.0361702872 | 0.0193621868 | 0.0458593357 | 0.0000000000 | 0.2019065423 | 0 |
| DoS | Min-MD | 0.2942586585 | 0.0732802976 | 0.4253566635 | 0.0056213312 | 0.2048841267 | 2 |
| Mirai | ClassConditionalKNN | 0.5627614949 | 0.5996624459 | 0.4299092391 | 0.0751990563 | 0.1987557133 | 7 |
| Mirai | Entropy | 0.0389813104 | 0.0248553675 | 0.0437523754 | 0.0000000000 | 0.2314918268 | 0 |
| Mirai | GlobalKNN | 0.3794677383 | 0.1090833431 | 0.4332581159 | 0.0254327631 | 0.2315729193 | 3 |
| Mirai | MD-Pred | 0.3910215443 | 0.1559621672 | 0.4222862638 | 0.0164009112 | 0.2288138163 | 1 |
| Mirai | MDS | 0.3681348210 | 0.1473016669 | 0.4263250355 | 0.0164009112 | 0.2318313986 | 2 |
| Mirai | MSP | 0.0359598861 | 0.0204747280 | 0.0432925636 | 0.0000000000 | 0.2291120669 | 0 |
| Mirai | Min-MD | 0.3646736901 | 0.1288777826 | 0.4362314164 | 0.0129955835 | 0.2330118613 | 0 |
| Recon | ClassConditionalKNN | 0.5651918887 | 0.6184924763 | 0.4233218202 | 0.0109827468 | 0.1620889630 | 8 |
| Recon | Entropy | 0.0355030648 | 0.0000000000 | 0.0534320036 | 0.0000000000 | 0.2074866949 | 0 |
| Recon | GlobalKNN | 0.3882631049 | 0.1539792511 | 0.4324392508 | 0.0121988295 | 0.1968379142 | 5 |
| Recon | MD-Pred | 0.3736267871 | 0.1084286549 | 0.4305834567 | 0.0098995125 | 0.1962843029 | 0 |
| Recon | MDS | 0.2442840119 | 0.0842828867 | 0.3315964812 | 0.0105267158 | 0.1982996580 | 0 |
| Recon | MSP | 0.0368724625 | 0.0070054317 | 0.0566228899 | 0.0000000000 | 0.1998241697 | 0 |
| Recon | Min-MD | 0.3532195062 | 0.0887150022 | 0.4225583655 | 0.0055218386 | 0.1983698711 | 1 |
| Spoofing | ClassConditionalKNN | 0.5397898667 | 0.6209120404 | 0.4535329234 | 0.0086645892 | 0.1687641810 | 6 |
| Spoofing | Entropy | 0.0358988850 | 0.0000000000 | 0.0558178694 | 0.0000000000 | 0.2009839762 | 0 |
| Spoofing | GlobalKNN | 0.3724073223 | 0.1109901095 | 0.4381469577 | 0.0098806719 | 0.1994316622 | 3 |
| Spoofing | MD-Pred | 0.3910247755 | 0.1490437030 | 0.4308890459 | 0.0098426693 | 0.1962225053 | 0 |
| Spoofing | MDS | 0.3232419150 | 0.1533664648 | 0.3915532687 | 0.0101482440 | 0.1975972038 | 4 |
| Spoofing | MSP | 0.0338887845 | 0.0000000000 | 0.0553833198 | 0.0000000000 | 0.1981026754 | 0 |
| Spoofing | Min-MD | 0.3771946403 | 0.1364013600 | 0.4360070592 | 0.0065167645 | 0.1984229615 | 0 |
| BruteForce | ClassConditionalKNN | 0.4156929593 | 0.2065135698 | 0.4158862369 | 0.0093106331 | 0.2044265483 | 8 |
| BruteForce | Entropy | 0.0472692474 | 0.0338666286 | 0.0510802487 | 0.0000000000 | 0.2172659780 | 0 |
| BruteForce | GlobalKNN | 0.3113547225 | 0.1186839924 | 0.3976779404 | 0.0102606977 | 0.2188357001 | 3 |
| BruteForce | MD-Pred | 0.3085655609 | 0.1569895483 | 0.3965311114 | 0.0099186745 | 0.2184607658 | 0 |
| BruteForce | MDS | 0.2779223338 | 0.1560084269 | 0.3563771590 | 0.0088548403 | 0.2192791813 | 1 |
| BruteForce | MSP | 0.0415196745 | 0.0270099755 | 0.0469763760 | 0.0000000000 | 0.2155053956 | 0 |
| BruteForce | Min-MD | 0.2936323389 | 0.1151059019 | 0.3977047561 | 0.0064172719 | 0.2202734506 | 2 |
| Web | ClassConditionalKNN | 0.5325382849 | 0.5582728295 | 0.4505407859 | 0.0085885840 | 0.1879008631 | 5 |
| Web | Entropy | 0.0324079340 | 0.0000000000 | 0.0499947956 | 0.0000000000 | 0.2205546247 | 0 |
| Web | GlobalKNN | 0.3677283710 | 0.1080172095 | 0.4442808314 | 0.0096526564 | 0.2180781863 | 3 |
| Web | MD-Pred | 0.4015022957 | 0.1850343926 | 0.4188235556 | 0.0102606977 | 0.2134727580 | 1 |
| Web | MDS | 0.3848224556 | 0.1746822276 | 0.4154681615 | 0.0104507106 | 0.2152463042 | 2 |
| Web | MSP | 0.0322462924 | 0.0019797959 | 0.0432529704 | 0.0000000000 | 0.2174646375 | 0 |
| Web | Min-MD | 0.3769152132 | 0.1676695686 | 0.4263974963 | 0.0056213312 | 0.2167617492 | 1 |


# 40. Final Detector Selections

| Outer held-out family | selected_detector | mean_inner_UADR | mean_inner_risk | inner_folds_used | selection_reason |
|---|---|---|---|---|---|
| DDoS | MD-Pred | 0.39028092988677204 | 0.17890369830675856 | 12 | MD-Pred selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| DoS | ClassConditionalKNN | 0.417312228198145 | 0.17898351573703639 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Mirai | ClassConditionalKNN | 0.5627614948732997 | 0.19875571331518424 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Recon | ClassConditionalKNN | 0.5651918887404866 | 0.16208896298721276 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Spoofing | ClassConditionalKNN | 0.5397898666726954 | 0.16876418102833865 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| BruteForce | ClassConditionalKNN | 0.4156929593264227 | 0.20442654830190643 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Web | ClassConditionalKNN | 0.5325382849343906 | 0.18790086311307427 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |


# 41. Outer Calibration After Selection

Detector selection is frozen first. Only then does known-only outer CALIBRATION create the alpha=0.05 empirical/conformal boundary. Outer test-known and test-unknown are inaccessible until final evaluation. Saved code uses the `higher` empirical quantile where applicable and rejects scores at or beyond the boundary.


# 42. Final EcoCon-NOS Outer Evaluation

| held_out_family | method | alpha | calibration_rejection_rate | known_rejection_rate | known_acceptance_rate | known_accepted_accuracy | known_selective_risk | UADR | unknown_acceptance_rate | coverage | review_rate | overall_selective_risk | calibration_count | known_count | unknown_count | known_rejected_count | unknown_rejected_count | accepted_known_count | accepted_unknown_count | wrong_known_accepted_count | known_rejected | unknown_rejected | accepted_known | accepted_unknown | wrong_known_accepted | AUROC | AUPRC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8533427074 | 0.1466572926 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6045716790 | 78230.0000000000 | 78230 | 90592 | 0.0000000000 | 0.0000000000 | 78230.0000000000 | 90592.0000000000 | 11473.0000000000 |  |  |  |  |  |  |  |
| DDoS | MSP | 0.0500000000 | 0.0500063914 | 0.0493672504 | 0.9506327496 | 0.8794777324 | 0.1205222676 | 0.0000220770 | 0.9999779230 | 0.9771119878 | 0.0228880122 | 0.6035051346 | 78230.0000000000 | 78230 | 90592 | 3862.0000000000 | 2.0000000000 | 74368.0000000000 | 90590.0000000000 | 8963.0000000000 |  |  |  |  |  |  |  |
| DDoS | Entropy | 0.0500000000 | 0.0500063914 | 0.0491627253 | 0.9508372747 | 0.8781458378 | 0.1218541622 | 0.0000220770 | 0.9999779230 | 0.9772067622 | 0.0227932378 | 0.6040588214 | 78230.0000000000 | 78230 | 90592 | 3846.0000000000 | 2.0000000000 | 74384.0000000000 | 90590.0000000000 | 9064.0000000000 |  |  |  |  |  |  |  |
| DDoS | EcoConMD | 0.0500000000 | 0.0498529976 | 0.0476927010 | 0.9523072990 | 0.8520382824 | 0.1479617176 | 0.5598949135 | 0.4401050865 | 0.6774531755 | 0.3225468245 | 0.4449894639 | 78230.0000000000 | 78230 | 90592 | 3731.0000000000 | 50722.0000000000 | 74499.0000000000 | 39870.0000000000 | 11023.0000000000 |  |  |  |  |  |  |  |
| DoS | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8529497719 | 0.1470502281 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.5959795366 | 78701.0000000000 | 78701 | 87449 | 0.0000000000 | 0.0000000000 | 78701.0000000000 | 87449.0000000000 | 11573.0000000000 |  |  |  |  |  |  |  |
| DoS | MSP | 0.0500000000 | 0.0500120710 | 0.0493767551 | 0.9506232449 | 0.8790215866 | 0.1209784134 | 0.0000114352 | 0.9999885648 | 0.9766054770 | 0.0233945230 | 0.5947073578 | 78701.0000000000 | 78701 | 87449 | 3886.0000000000 | 1.0000000000 | 74815.0000000000 | 87448.0000000000 | 9051.0000000000 |  |  |  |  |  |  |  |
| DoS | Entropy | 0.0500000000 | 0.0500120710 | 0.0501264279 | 0.9498735721 | 0.8786184387 | 0.1213815613 | 0.0000000000 | 1.0000000000 | 0.9762563948 | 0.0237436052 | 0.5950679695 | 78701.0000000000 | 78701 | 87449 | 3945.0000000000 | 0.0000000000 | 74756.0000000000 | 87449.0000000000 | 9074.0000000000 |  |  |  |  |  |  |  |
| DoS | EcoConMD | 0.0500000000 | 0.0498595952 | 0.0490590971 | 0.9509409029 | 0.8503340460 | 0.1496659540 | 0.0341913572 | 0.9658086428 | 0.9587661751 | 0.0412338249 | 0.6005059668 | 78701.0000000000 | 78701 | 87449 | 3861.0000000000 | 2990.0000000000 | 74840.0000000000 | 84459.0000000000 | 11201.0000000000 |  |  |  |  |  |  |  |
| Mirai | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.7885809500 | 0.2114190500 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6574010712 | 76819.0000000000 | 76819 | 100000 | 0.0000000000 | 0.0000000000 | 76819.0000000000 | 100000.0000000000 | 16241.0000000000 |  |  |  |  |  |  |  |
| Mirai | MSP | 0.0500000000 | 0.0500006509 | 0.0505213554 | 0.9494786446 | 0.8118401930 | 0.1881598070 | 0.0000000000 | 1.0000000000 | 0.9780510013 | 0.0219489987 | 0.6575998335 | 76819.0000000000 | 76819 | 100000 | 3881.0000000000 | 0.0000000000 | 72938.0000000000 | 100000.0000000000 | 13724.0000000000 |  |  |  |  |  |  |  |
| Mirai | Entropy | 0.0500000000 | 0.0500006509 | 0.0487509600 | 0.9512490400 | 0.8106440047 | 0.1893559953 | 0.0000000000 | 1.0000000000 | 0.9788201494 | 0.0211798506 | 0.6577359973 | 76819.0000000000 | 76819 | 100000 | 3745.0000000000 | 0.0000000000 | 73074.0000000000 | 100000.0000000000 | 13837.0000000000 |  |  |  |  |  |  |  |
| Mirai | EcoConMD | 0.0500000000 | 0.0498704748 | 0.0494799464 | 0.9505200536 | 0.7847517051 | 0.2152482949 | 0.8317700000 | 0.1682300000 | 0.5080958494 | 0.4919041506 | 0.3621954342 | 76819.0000000000 | 76819 | 100000 | 3801.0000000000 | 83177.0000000000 | 73018.0000000000 | 16823.0000000000 | 15717.0000000000 |  |  |  |  |  |  |  |
| Recon | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8738273372 | 0.1261726628 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6197470189 | 76855.0000000000 | 76855 | 99759 | 0.0000000000 | 0.0000000000 | 76855.0000000000 | 99759.0000000000 | 9697.0000000000 |  |  |  |  |  |  |  |
| Recon | MSP | 0.0500000000 | 0.0501203565 | 0.0502764947 | 0.9497235053 | 0.8951377567 | 0.1048622433 | 0.1725658838 | 0.8274341162 | 0.8806493256 | 0.1193506744 | 0.5799209181 | 76855.0000000000 | 76855 | 99759 | 3864.0000000000 | 17215.0000000000 | 72991.0000000000 | 82544.0000000000 | 7654.0000000000 |  |  |  |  |  |  |  |
| Recon | Entropy | 0.0500000000 | 0.0500032529 | 0.0483247674 | 0.9516752326 | 0.8937668339 | 0.1062331661 | 0.1796429395 | 0.8203570605 | 0.8775012173 | 0.1224987827 | 0.5781944651 | 76855.0000000000 | 76855 | 99759 | 3714.0000000000 | 17921.0000000000 | 73141.0000000000 | 81838.0000000000 | 7770.0000000000 |  |  |  |  |  |  |  |
| Recon | EcoConMD | 0.0500000000 | 0.0498601262 | 0.0481686292 | 0.9518313708 | 0.8737167307 | 0.1262832693 | 0.1482973967 | 0.8517026033 | 0.8952744403 | 0.1047255597 | 0.5957765719 | 76855.0000000000 | 76855 | 99759 | 3702.0000000000 | 14794.0000000000 | 73153.0000000000 | 84965.0000000000 | 9238.0000000000 |  |  |  |  |  |  |  |
| Spoofing | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8200470905 | 0.1799529095 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.6359187612 | 77298.0000000000 | 77298 | 96806 | 0.0000000000 | 0.0000000000 | 77298.0000000000 | 96806.0000000000 | 13910.0000000000 |  |  |  |  |  |  |  |
| Spoofing | MSP | 0.0500000000 | 0.0500012937 | 0.0499883567 | 0.9500116433 | 0.8427431435 | 0.1572568565 | 0.2100283040 | 0.7899716960 | 0.8610255939 | 0.1389744061 | 0.5871734664 | 77298.0000000000 | 77298 | 96806 | 3864.0000000000 | 20332.0000000000 | 73434.0000000000 | 76474.0000000000 | 11548.0000000000 |  |  |  |  |  |  |  |
| Spoofing | Entropy | 0.0500000000 | 0.0500012937 | 0.0492638878 | 0.9507361122 | 0.8413389577 | 0.1586610423 | 0.2226618185 | 0.7773381815 | 0.8543227037 | 0.1456772963 | 0.5843109835 | 77298.0000000000 | 77298 | 96806 | 3808.0000000000 | 21555.0000000000 | 73490.0000000000 | 75251.0000000000 | 11660.0000000000 |  |  |  |  |  |  |  |
| Spoofing | EcoConMD | 0.0500000000 | 0.0498719242 | 0.0491215814 | 0.9508784186 | 0.8167099767 | 0.1832900233 | 0.1032064128 | 0.8967935872 | 0.9208059551 | 0.0791940449 | 0.6255582724 | 77298.0000000000 | 77298 | 96806 | 3797.0000000000 | 9991.0000000000 | 73501.0000000000 | 86815.0000000000 | 13472.0000000000 |  |  |  |  |  |  |  |
| BruteForce | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8373599225 | 0.1626400775 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.2688316231 | 89861.0000000000 | 89861 | 13051 | 0.0000000000 | 0.0000000000 | 89861.0000000000 | 13051.0000000000 | 14615.0000000000 |  |  |  |  |  |  |  |
| BruteForce | MSP | 0.0500000000 | 0.0500105719 | 0.0485972780 | 0.9514027220 | 0.8596041827 | 0.1403958173 | 0.1786836258 | 0.8213163742 | 0.9349055504 | 0.0650944496 | 0.2361635122 | 89861.0000000000 | 89861 | 13051 | 4367.0000000000 | 2332.0000000000 | 85494.0000000000 | 10719.0000000000 | 12003.0000000000 |  |  |  |  |  |  |  |
| BruteForce | Entropy | 0.0500000000 | 0.0500105719 | 0.0484526101 | 0.9515473899 | 0.8587717965 | 0.1412282035 | 0.1615201900 | 0.8384798100 | 0.9372084888 | 0.0627915112 | 0.2386625194 | 89861.0000000000 | 89861 | 13051 | 4354.0000000000 | 2108.0000000000 | 85507.0000000000 | 10943.0000000000 | 12076.0000000000 |  |  |  |  |  |  |  |
| BruteForce | EcoConMD | 0.0500000000 | 0.0498881606 | 0.0482411725 | 0.9517588275 | 0.8346233894 | 0.1653766106 | 0.3145352847 | 0.6854647153 | 0.9179881841 | 0.0820118159 | 0.2444110424 | 89861.0000000000 | 89861 | 13051 | 4335.0000000000 | 4105.0000000000 | 85526.0000000000 | 8946.0000000000 | 14144.0000000000 |  |  |  |  |  |  |  |
| Web | ForcedXGBoost | 0.0500000000 | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.8509288576 | 0.1490711424 | 0.0000000000 | 1.0000000000 | 1.0000000000 | 0.0000000000 | 0.3351686838 | 88119.0000000000 | 88119 | 24666 | 0.0000000000 | 0.0000000000 | 88119.0000000000 | 24666.0000000000 | 13136.0000000000 |  |  |  |  |  |  |  |
| Web | MSP | 0.0500000000 | 0.0500005674 | 0.0501821401 | 0.9498178599 | 0.8731137317 | 0.1268862683 | 0.2545609341 | 0.7454390659 | 0.9051203618 | 0.0948796382 | 0.2841483484 | 88119.0000000000 | 88119 | 24666 | 4422.0000000000 | 6279.0000000000 | 83697.0000000000 | 18387.0000000000 | 10620.0000000000 |  |  |  |  |  |  |  |
| Web | Entropy | 0.0500000000 | 0.0500005674 | 0.0490019179 | 0.9509980821 | 0.8718034391 | 0.1281965609 | 0.2682640071 | 0.7317359929 | 0.9030456178 | 0.0969543822 | 0.2826902307 | 88119.0000000000 | 88119 | 24666 | 4318.0000000000 | 6617.0000000000 | 83801.0000000000 | 18049.0000000000 | 10743.0000000000 |  |  |  |  |  |  |  |
| Web | EcoConMD | 0.0500000000 | 0.0498984328 | 0.0484571999 | 0.9515428001 | 0.8488831113 | 0.1511168887 | 0.0586637477 | 0.9413362523 | 0.9493106353 | 0.0506893647 | 0.3352075317 | 88119.0000000000 | 88119 | 24666 | 4270.0000000000 | 1447.0000000000 | 83849.0000000000 | 23219.0000000000 | 12671.0000000000 |  |  |  |  |  |  |  |
| DDoS | EcoConFuse | 0.0500000000 |  | 0.0458136265 | 0.9541863735 | 0.8595102216 | 0.1404897784 | 0.5585261392 | 0.4414738608 | 0.6790584166 | 0.3209415834 | 0.4403436846 |  | 78230 | 90592 |  |  |  |  |  | 3584.0000000000 | 50598.0000000000 | 74646.0000000000 | 39994.0000000000 | 10487.0000000000 |  |  |
| DoS | EcoConFuse | 0.0500000000 |  | 0.0470642050 | 0.9529357950 | 0.8582076616 | 0.1417923384 | 0.1736783725 | 0.8263216275 | 0.8862955161 | 0.1137044839 | 0.5629235763 |  | 78701 | 87449 |  |  |  |  |  | 3704.0000000000 | 15188.0000000000 | 74997.0000000000 | 72261.0000000000 | 10634.0000000000 |  |  |
| Mirai | EcoConFuse | 0.0500000000 |  | 0.0493758055 | 0.9506241945 | 0.7962780380 | 0.2037219620 | 0.6624600000 | 0.3375400000 | 0.6038943779 | 0.3961056221 | 0.4554317288 |  | 76819 | 100000 |  |  |  |  |  | 3793.0000000000 | 66246.0000000000 | 73026.0000000000 | 33754.0000000000 | 14877.0000000000 |  |  |
| Recon | EcoConFuse | 0.0500000000 |  | 0.0490404008 | 0.9509595992 | 0.8806748214 | 0.1193251786 | 0.1358574164 | 0.8641425836 | 0.9019217050 | 0.0980782950 | 0.5959307435 |  | 76855 | 99759 |  |  |  |  |  | 3769.0000000000 | 13553.0000000000 | 73086.0000000000 | 86206.0000000000 | 8721.0000000000 |  |  |
| Spoofing | EcoConFuse | 0.0500000000 |  | 0.0478925716 | 0.9521074284 | 0.8257649872 | 0.1742350128 | 0.1318513315 | 0.8681486685 | 0.9054243441 | 0.0945756559 | 0.6144774737 |  | 77298 | 96806 |  |  |  |  |  | 3702.0000000000 | 12764.0000000000 | 73596.0000000000 | 84042.0000000000 | 12823.0000000000 |  |  |
| BruteForce | EcoConFuse | 0.0500000000 |  | 0.0493206174 | 0.9506793826 | 0.8445258636 | 0.1554741364 | 0.3443414298 | 0.6556585702 | 0.9132657027 | 0.0867342973 | 0.2323643947 |  | 89861 | 13051 |  |  |  |  |  | 4432.0000000000 | 4494.0000000000 | 85429.0000000000 | 8557.0000000000 | 13282.0000000000 |  |  |
| Web | EcoConFuse | 0.0500000000 |  | 0.0478330440 | 0.9521669560 | 0.8577660183 | 0.1422339817 | 0.1081650855 | 0.8918349145 | 0.9389723811 | 0.0610276189 | 0.3204094351 |  | 88119 | 24666 |  |  |  |  |  | 4215.0000000000 | 2668.0000000000 | 83904.0000000000 | 21998.0000000000 | 11934.0000000000 |  |  |
| DDoS | EcoConNOS |  |  | 0.0478077464 | 0.9521922536 |  | 0.1475365821 | 0.5565392088 | 0.4434607912 | 0.6792005781 | 0.3207994219 | 0.4462080514 |  | 78230 | 90592 |  |  |  |  |  | 3740.0000000000 | 50418.0000000000 | 74490.0000000000 | 40174.0000000000 | 10990.0000000000 | 0.8051153540 | 0.8649390713 |
| DoS | EcoConNOS |  |  | 0.0504567922 | 0.9495432078 |  | 0.1421383648 | 0.0406751364 | 0.9593248636 | 0.9546915438 | 0.0453084562 | 0.5958442082 |  | 78701 | 87449 |  |  |  |  |  | 3971.0000000000 | 3557.0000000000 | 74730.0000000000 | 83892.0000000000 | 10622.0000000000 | 0.3340576543 | 0.4438906875 |
| Mirai | EcoConNOS |  |  | 0.0497533162 | 0.9502466838 |  | 0.2091181829 | 0.9996100000 | 0.0003900000 | 0.4130551581 | 0.5869448419 | 0.2095405006 |  | 76819 | 100000 |  |  |  |  |  | 3822.0000000000 | 99961.0000000000 | 72997.0000000000 | 39.0000000000 | 15265.0000000000 | 0.9977799143 | 0.9974899903 |
| Recon | EcoConNOS |  |  | 0.0500943335 | 0.9499056665 |  | 0.1227724128 | 0.3230284987 | 0.6769715013 | 0.7957409945 | 0.2042590055 | 0.5443115434 |  | 76855 | 99759 |  |  |  |  |  | 3850.0000000000 | 32225.0000000000 | 73005.0000000000 | 67534.0000000000 | 8963.0000000000 | 0.8668292164 | 0.8668057233 |
| Spoofing | EcoConNOS |  |  | 0.0510362493 | 0.9489637507 |  | 0.1753029869 | 0.2110819577 | 0.7889180423 | 0.8599744980 | 0.1400255020 | 0.5959659376 |  | 77298 | 96806 |  |  |  |  |  | 3945.0000000000 | 20434.0000000000 | 73353.0000000000 | 76372.0000000000 | 12859.0000000000 | 0.7908579280 | 0.7862484607 |
| BruteForce | EcoConNOS |  |  | 0.0516464317 | 0.9483535683 |  | 0.1596690918 | 0.3942992874 | 0.6057007126 | 0.9048993315 | 0.0951006685 | 0.2310013423 |  | 89861 | 13051 |  |  |  |  |  | 4641.0000000000 | 5146.0000000000 | 85220.0000000000 | 7905.0000000000 | 13607.0000000000 | 0.8514627715 | 0.5409147084 |
| Web | EcoConNOS |  |  | 0.0504771956 | 0.9495228044 |  | 0.1449486680 | 0.1860861104 | 0.8139138896 | 0.9198652303 | 0.0801347697 | 0.3104089757 |  | 88119 | 24666 |  |  |  |  |  | 4448.0000000000 | 4590.0000000000 | 83671.0000000000 | 20076.0000000000 | 12128.0000000000 | 0.8210323773 | 0.4765359243 |


# 43. Final Macro Results

Macro results weight each attack-family fold equally.

| method | known_rejection_rate | UADR | coverage | review_rate | overall_selective_risk |
|---|---|---|---|---|---|
| EcoConFuse | 0.0480486101 | 0.3021256821 | 0.8326903491 | 0.1673096509 | 0.4602687195 |
| EcoConMD | 0.0486029039 | 0.2929370161 | 0.8325277735 | 0.1674722265 | 0.4583777548 |
| EcoConNOS | 0.0501817236 | 0.3873314571 | 0.7896324763 | 0.2103675237 | 0.4190400799 |
| Entropy | 0.0490118995 | 0.1188730046 | 0.9291944763 | 0.0708055237 | 0.5058172838 |
| ForcedXGBoost | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.0000000000 | 0.5310883391 |
| MSP | 0.0497585186 | 0.1165531800 | 0.9304956140 | 0.0695043860 | 0.5061740816 |


# 44. Improvement Calculations

| Comparison | Absolute UADR | Relative UADR | Ratio |
|---|---|---|---|
| NOS vs MSP | 0.2707782771 | 2.32321655316483 | 3.32321655316483 |
| NOS vs Entropy | 0.2684584525 | 2.2583634812911932 | 3.2583634812911932 |
| NOS vs EcoConMD | 0.094394441 | 0.3222345958756422 | 1.3222345958756423 |

NOS versus MD overall-risk absolute change is -0.0393376749 and relative change -0.0858193368. Greater UADR comes with lower coverage and higher review workload; it is not free.


# 45. Family-Wise Final Comparison

Web is retained visibly as the main loss; DDoS is a near tie/loss to MD, and Spoofing trails entropy.

| held_out_family | MSP | Entropy | EcoConMD | EcoConNOS | best_existing | NOS_regret |
|---|---|---|---|---|---|---|
| BruteForce | 0.1786836258 | 0.1615201900 | 0.3145352847 | 0.3942992874 | 0.3145352847 | 0.0797640027 |
| DDoS | 0.0000220770 | 0.0000220770 | 0.5598949135 | 0.5565392088 | 0.5598949135 | -0.0033557047 |
| DoS | 0.0000114352 | 0.0000000000 | 0.0341913572 | 0.0406751364 | 0.0341913572 | 0.0064837792 |
| Mirai | 0.0000000000 | 0.0000000000 | 0.8317700000 | 0.9996100000 | 0.8317700000 | 0.1678400000 |
| Recon | 0.1725658838 | 0.1796429395 | 0.1482973967 | 0.3230284987 | 0.1796429395 | 0.1433855592 |
| Spoofing | 0.2100283040 | 0.2226618185 | 0.1032064128 | 0.2110819577 | 0.2226618185 | -0.0115798608 |
| Web | 0.2545609341 | 0.2682640071 | 0.0586637477 | 0.1860861104 | 0.2682640071 | -0.0821778967 |


# 46. Fold-Win Counts

NOS beats MSP on 6/7 folds, entropy on 5/7, and MD on 6/7. From the success artifact it is strictly best on 4/7 and within 0.02 of the previous best on 6/7.


# 47. High-Confidence Unknown Rescue

All seven families remain visible. Mirai and DDoS show the largest scientifically important rescue; Recon and BruteForce show gains where high-confidence subsets are smaller.

| held_out_family | high_confidence_unknown_rows | MSP_rescue_rate | Entropy_rescue_rate | EcoConMD_rescue_rate | EcoConNOS_rescue_rate |
|---|---|---|---|---|---|
| DDoS | 90096 | 0.0000000000 | 0.0000000000 | 0.5575497247 | 0.5542199432 |
| DoS | 78573 | 0.0000000000 | 0.0000000000 | 0.0349738460 | 0.0404464638 |
| Mirai | 95287 | 0.0000000000 | 0.0000000000 | 0.8659838173 | 0.9998425808 |
| Recon | 16003 | 0.0000000000 | 0.0000000000 | 0.2488283447 | 0.5536461913 |
| Spoofing | 5197 | 0.0000000000 | 0.0000000000 | 0.1312295555 | 0.1358476044 |
| BruteForce | 817 | 0.0000000000 | 0.0000000000 | 0.5483476132 | 0.6585067319 |
| Web | 1261 | 0.0000000000 | 0.0000000000 | 0.0459952419 | 0.1736716891 |


# 48. Mirai Case Study

Mirai has 100,000 outer unknown rows, mean confidence and threshold rates in the Step-7 table, and forced labels in the distribution archive. MSP and entropy UADR are 0; MD is 0.83177; Fuse 0.66246; NOS 0.99961. The high-confidence NOS rescue is about 0.9998, fresh NOS UADR is 0.9996, and the bootstrap interval is reported below. This is the clearest high-confidence OOD rescue, but 0.9996 is not perfect and does not prove external generalization.

| held_out_family | metric | estimate | ci_lower | ci_upper | bootstrap_resamples |
|---|---|---|---|---|---|
| Mirai | UADR | 0.9996100000 | 0.9994900000 | 0.9997300000 | 1000 |
| Mirai | overall_selective_risk | 0.2095405006 | 0.2063627066 | 0.2124747686 | 1000 |


# 49. Recon Case Study

Recon is less uniformly overconfident; MSP/entropy retain signal, fixed MD reaches UADR 0.1482973967, and NOS selects ClassConditionalKNN to reach 0.3230284987. Fresh UADR is 0.3742. This illustrates how training-only adaptive selection can address a fold where fixed MD is not strongest.


# 50. Web Failure Case

Web UADR is MSP 0.2545609341, entropy 0.2682640071, MD 0.0586637477, Fuse 0.1081650855, and NOS 0.1860861104. NOS does not dominate the strongest probability baseline. Inner pseudo-OOD selection is informative but cannot guarantee the best detector for every future family shift.


# 51. Fresh-Sample Confirmation Results

Frozen models, detector selections, thresholds, and alpha were reused without recalibration. Hashes do not overlap research/modeling pools. This is within CICIoT2023, not external validation.

| held_out_family | selected_detector | fresh_rows | MSP_UADR | Entropy_UADR | EcoConMD_UADR | EcoConNOS_UADR |
|---|---|---|---|---|---|---|
| DDoS | MD-Pred | 5000 | 0.0000000000 | 0.0000000000 | 0.6642000000 | 0.6346000000 |
| DoS | ClassConditionalKNN | 5000 | 0.0000000000 | 0.0000000000 | 0.1780000000 | 0.1810000000 |
| Mirai | ClassConditionalKNN | 5000 | 0.0000000000 | 0.0000000000 | 0.8482000000 | 0.9996000000 |
| Recon | ClassConditionalKNN | 5000 | 0.1774000000 | 0.1918000000 | 0.1928000000 | 0.3742000000 |
| Spoofing | ClassConditionalKNN | 5000 | 0.2384000000 | 0.2496000000 | 0.0756000000 | 0.1904000000 |


# 52. Bootstrap Confidence Intervals

The artifact uses 1,000 row-level bootstrap resamples. Intervals quantify within-fold sample variability for UADR and overall risk; they do not increase the seven independent outer-family folds.

| held_out_family | metric | estimate | ci_lower | ci_upper | bootstrap_resamples |
|---|---|---|---|---|---|
| DDoS | UADR | 0.5565392088 | 0.5531939906 | 0.5597961189 | 1000 |
| DDoS | overall_selective_risk | 0.4462080514 | 0.4433005426 | 0.4490528228 | 1000 |
| DoS | UADR | 0.0406751364 | 0.0393020503 | 0.0419332983 | 1000 |
| DoS | overall_selective_risk | 0.5958442082 | 0.5934507951 | 0.5983196984 | 1000 |
| Mirai | UADR | 0.9996100000 | 0.9994900000 | 0.9997300000 | 1000 |
| Mirai | overall_selective_risk | 0.2095405006 | 0.2063627066 | 0.2124747686 | 1000 |
| Recon | UADR | 0.3230284987 | 0.3200009523 | 0.3257751180 | 1000 |
| Recon | overall_selective_risk | 0.5443115434 | 0.5418170703 | 0.5468274137 | 1000 |
| Spoofing | UADR | 0.2110819577 | 0.2084976654 | 0.2137274549 | 1000 |
| Spoofing | overall_selective_risk | 0.5959659376 | 0.5933472053 | 0.5983537074 | 1000 |
| BruteForce | UADR | 0.3942992874 | 0.3864837943 | 0.4024231860 | 1000 |
| BruteForce | overall_selective_risk | 0.2310013423 | 0.2283039781 | 0.2336188904 | 1000 |
| Web | UADR | 0.1860861104 | 0.1808957675 | 0.1910332036 | 1000 |
| Web | overall_selective_risk | 0.3104089757 | 0.3076165286 | 0.3132991015 | 1000 |


# 53. Final Statistical Tests

All comparisons use n=7 paired outer families. NOS-versus-MD p=0.03125 for UADR and risk, but inference remains cautious because resolution and power are limited.

| outcome | comparison | mean_paired_difference | median_paired_difference | wins | losses | ties | wilcoxon_statistic | p_value |
|---|---|---|---|---|---|---|---|---|
| UADR | EcoConNOS vs EcoConMD | 0.0943944410 | 0.1078755449 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| UADR | EcoConNOS vs Entropy | 0.2684584525 | 0.1433855592 | 5 | 2 | 0 | 4.0000000000 | 0.1093750000 |
| UADR | EcoConNOS vs MSP | 0.2707782771 | 0.1504626149 | 6 | 1 | 0 | 3.0000000000 | 0.0781250000 |
| overall_selective_risk | EcoConNOS vs EcoConMD | -0.0393376749 | -0.0247985560 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| overall_selective_risk | EcoConNOS vs Entropy | -0.0867772040 | -0.0076611771 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |
| overall_selective_risk | EcoConNOS vs MSP | -0.0871340017 | -0.0051621699 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |


# 54. Predeclared Success Criteria

Before outcomes: macro NOS UADR > MD; macro NOS risk < MD; macro known rejection in [0.04,0.06]. Strong robustness: within 0.02 of best existing on ≥6/7 and strictly best on ≥4/7. Best-paper targets: UADR 0.35, risk 0.44, beat MD on 5 folds. PRIMARY SUCCESS PASS; STRONG ROBUSTNESS PASS; BEST-PAPER TARGET MET.


# 55. EcoCon-NOS Method Audit

| Audit item | Value |
|---|---|
| Outer unknown used for candidate design | NO |
| Outer unknown used for candidate selection | NO |
| Outer unknown used for threshold selection | NO |
| Outer test-known used for selection | NO |
| Outer calibration used for selection | NO |
| Outer calibration used for threshold | YES |
| Inner pseudo-OOD source | outer training only |
| XGBoost retrained | NO |
| Feature budget changed | NO |
| Alpha changed | NO |

Feature-hash grouping controls all split boundaries; saved audit validation is PASS.


# 56. What Did Not Work

1. Raw probability uncertainty failed on DDoS, DoS, and Mirai. 2. Fixed EcoCon-MD was not universally superior. 3. EcoCon-Fuse failed its primary criterion and robustness rule. 4. EcoCon-NOS still does not dominate Web. 5. DoS remains difficult at NOS UADR 0.0406751364. These negative results explain the transition from probability scores to feature geometry, then fusion, then nested detector selection.


# 57. Current Final Method

FINAL METHOD: EcoCon-NOS. EcoCon-MD is an intermediate baseline; EcoCon-Fuse is a failed extension/ablation. NOS adapts only the uncertainty detector selection. It does not change base XGBoost, LOAFO splits, feature budget, class labels, alpha, or use the true outer unknown for selection. No further model design is authorized.


# 58. Computational Efficiency Status

`results/ecocon_nos_efficiency.csv` exists, but `paper_assets/audit/efficiency_status.txt` states the corrected refresh exceeded its execution window. The existing accounting is inconsistent and **EcoCon-NOS efficiency results are currently NOT publication-safe**. No NOS timing numbers are quoted as verified. Closed-set and earlier MD timing artifacts remain historical evidence, not a corrected NOS benchmark.


# 59. Complete Script Inventory

| Script | Step | Purpose | Main inputs | Main outputs | Status |
|---|---|---|---|---|---|
| src/01_inspect_dataset.py | 01 | Executable research/support script | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/02_audit_mapping_and_counts.py | 02 | Executable research/support script | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/03_build_research_pool.py | 03 | Executable research/support script | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/04_create_leakage_safe_splits.py | 04 | Largest normalized target deficit; fixed SPLITS order breaks ties. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/05_train_closed_set_baselines.py | 05 | DataFrame.to_json converts non-applicable RF best_iteration to | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/06_feature_budget_experiment.py | 06 | Official test remains unopened until ranking, development, selection, Pareto, and final fits are frozen. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/07_run_loafo_experiments.py | 07 | These three partitions are first materialized for model evaluation only after all fold decisions were frozen. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/08_5_ecocon_fusion.py | 08.5 | Lightweight lookup/fusion timing, 10 identical known-test repetitions. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/08_6_ecocon_nested_open_set.py | 08.6 | Freeze every diversity-selected pseudo-OOD label before evaluating any candidate. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/08_selective_conformal_evaluation.py | 08 | Identical hashes have identical features; many-to-one preserves every prediction row without Cartesian duplication. | see constants and argparse in script | results/models/processed as encoded | frozen |
| src/09_build_publication_assets.py | 09 | Frozen source data | see constants and argparse in script | results/models/processed as encoded | frozen |
| tools/generate_complete_research_documentation.py | support | Add archive appendices so every high-value table remains directly accessible. | see constants and argparse in script | results/models/processed as encoded | support |
| tools/refresh_ecocon_nos_efficiency.py | support | Executable research/support script | see constants and argparse in script | results/models/processed as encoded | support |


# 60. Complete Result-Artifact Inventory

The machine-readable index contains 406 files in `docs/ECOCON_NOS_ARTIFACT_INDEX.csv`. It records step, path, type, status, publication safety, and lineage notes. Result artifacts are the numerical source of truth; paper assets are derivative. Binary Parquet and joblib contents are indexed without duplication.


# 61. Complete Model Inventory

| Directory | Files | Role |
|---|---|---|
| models/baselines | 5 | base classifiers |
| models/ecocon_fuse | 8 | detector/calibration reference objects |
| models/ecocon_md | 8 | detector/calibration reference objects |
| models/ecocon_nos | 8 | detector/calibration reference objects |
| models/loafo | 8 | base classifiers |
| models/resource_budget | 8 | detector/calibration reference objects |

LOAFO joblib files hold frozen base classifiers/configuration; ecocon_md objects hold scalers, class means, precision, and calibration references; ecocon_fuse adds fusion calibration; ecocon_nos stores selected candidate references, notably kNN stores and MD-Pred state. Binary contents are not duplicated.


# 62. Reproducibility Pipeline

These are actual entry-point filenames. Reproduction would mutate frozen artifacts and is therefore documented but not executed.

| Step | Command |
|---|---|
| 01 | python src\01_inspect_dataset.py |
| 02 | python src\02_audit_mapping_and_counts.py |
| 03 | python src\03_build_research_pool.py |
| 04 | python src\04_create_leakage_safe_splits.py |
| 05 | python src\05_train_closed_set_baselines.py |
| 06 | python src\06_feature_budget_experiment.py |
| 07 | python src\07_run_loafo_experiments.py |
| 08.5 | python src\08_5_ecocon_fusion.py |
| 08.6 | python src\08_6_ecocon_nested_open_set.py |
| 08 | python src\08_selective_conformal_evaluation.py |
| 09 | python src\09_build_publication_assets.py |


# 63. Complete Data-Lineage Graph

```text
CSV/ raw folders
  -> Step 2 audit + 34-to-8 mapping
  -> processed/research_pool.parquet
  -> duplicate/conflict audit -> remove complete conflicting hashes
  -> processed/modeling_pool.parquet
  -> processed/closed_set/{train,calibration,test}.parquet
  -> LOAFO manifests -> Step-7 frozen models/probabilities
  -> EcoCon-MD -> EcoCon-Fuse (failed ablation)
  -> EcoCon-NOS inner pseudo-OOD selection -> frozen outer results
  -> fresh_confirmation_unknown.parquet -> confirmation results
  -> paper_assets/ + this master documentation
```


# 64. Key Numbers

The complete exact machine-readable record is `docs/ECOCON_NOS_KEY_RESULTS.json`. Headline values: raw 46,776,700; research pool 637,892; conflicting hashes 6,909/rows 25,777; modeling pool 612,115; XGBoost test Macro-F1 0.7640493828; 30-feature 0.7614298611; MD macro UADR 0.2929370161; Fuse 0.3021256821 with failed status; NOS UADR 0.3873314571, risk 0.4190400799, known rejection 0.0501817236, coverage 0.7896324763, review 0.2103675237; NOS-vs-MD p=0.03125 for UADR and risk.


# 65. Defensible Claims

| Claim | Metric | Artifact | Caveat |
|---|---|---|---|
| 23.1% fewer input features with small Macro-F1 loss | 39: 0.7640493828; 30: 0.7614298611 | feature_budget_test_metrics.csv | not runtime/energy |
| Severe unseen-family overconfidence | DDoS 99.4525%, DoS 89.8501%, Mirai 95.2870% >=.95 | loafo_unknown_confidence_summary.csv | CICIoT2023 LOAFO |
| Probability uncertainty fails on key families | AUROC below .5 | loafo_raw_uncertainty_auc.csv | score/fold specific |
| MD recovers feature-space discrimination | DDoS/DoS/Mirai AUROC >.8 | ecocon_md_raw_auc.csv | not universal |
| No fixed score dominates | family-wise winners differ | step8_5_family_comparison.csv | seven families |
| Nested selection excludes outer unknown | method audit PASS | ecocon_nos_method_audit.txt | implementation audit |
| NOS improves macro UADR | 0.3873314571 vs MD 0.2929370161 | ecocon_nos_macro_summary.csv | review rate 0.2104 |
| NOS improves macro risk | 0.4190400799 vs MD 0.4583777548 | ecocon_nos_macro_summary.csv | selective metric |
| NOS improves 6/7 against MD | 6 wins, 1 loss | ecocon_nos_statistics.csv | n=7 |
| Mirai high-confidence rescue | outer UADR 0.99961 | ecocon_nos_outer_results.csv | not perfect/external |
| Fresh confirmation | five 5,000-row families | ecocon_nos_fresh_confirmation.csv | same dataset |
| Web weakness | NOS 0.1860861104 < entropy 0.2682640071 | ecocon_nos_family_comparison.csv | selection failure |


# 66. Unsupported / Prohibited Claims

Do not claim guaranteed zero-day detection; perfect unseen-attack detection; universal superiority; external validation; state of the art without literature comparison; first-ever open-set, conformal, or kNN OOD IDS; 23% runtime or energy reduction; carbon savings; perfect Mirai generalization outside CICIoT2023; production deployment validation; significance over every method; conformal guarantee of OOD detection; publication-safe NOS efficiency; causal robustness to arbitrary distribution shift; or calibrated real-world analyst cost.


# 67. Limitations

One primary dataset; fresh confirmation remains within it; LOAFO is a proxy for future unknowns; research sampling changes prevalence; conflicting identical vectors were removed; Web weakness; DoS difficulty; increased analyst review; imperfect detector selection; only seven independent folds; limited statistical power; row bootstrap does not create independent folds; no real deployment; no physical power measurement; unsafe NOS efficiency benchmark; and pseudo-unknown fine labels may not predict future family shifts.


# 68. Final Research Contributions

1. A leakage-safe, resource-budgeted CICIoT2023 pipeline and LOAFO evaluation exposing confident unseen-family failures. 2. Evidence that predictive uncertainty and feature-space OOD signals have family-dependent strengths. 3. EcoCon-NOS training-only nested pseudo-open-set detector selection before true unknown exposure. 4. Improved macro UADR and selective risk over fixed baselines under the frozen protocol. 5. Fresh unused-sample confirmation within CICIoT2023. Any claim of novelty relative to prior literature requires a separate literature review.


# 69. Final Project Status

Completed: Steps 1–8.6. Final method: EcoCon-NOS. Model development: FROZEN. Next: Step 9 publication assets, figures, tables, diagrams, and evidence package. After Step 9: Step 10 final paper. No additional model tuning is recommended using existing outer test results.


# Appendix A. Fine-Label Counts

| fine_label | family | csv_file_count | record_count | total_size_mb | percentage_of_dataset |
|---|---|---|---|---|---|
| DDoS-ICMP_Flood | DDoS | 27 | 7200501 | 1264.828220 | 15.393350 |
| DDoS-UDP_Flood | DDoS | 21 | 5412231 | 977.508106 | 11.570357 |
| DDoS-TCP_Flood | DDoS | 18 | 4497649 | 804.744828 | 9.615148 |
| DDoS-PSHACK_FLOOD | DDoS | 16 | 4094772 | 733.906992 | 8.753871 |
| DDoS-SYN_Flood | DDoS | 16 | 4059179 | 738.435287 | 8.677780 |
| DDoS-RSTFINFLOOD | DDoS | 16 | 4045279 | 731.469578 | 8.648064 |
| DDoS-SynonymousIP_Flood | DDoS | 14 | 3598133 | 643.382015 | 7.692148 |
| DoS-UDP_Flood | DoS | 17 | 3072993 | 577.353579 | 6.569495 |
| DoS-TCP_Flood | DoS | 11 | 2671430 | 481.936712 | 5.711027 |
| DoS-SYN_Flood | DoS | 8 | 2028836 | 372.510795 | 4.337279 |
| Benign_Final | Benign | 4 | 1098191 | 216.878795 | 2.347731 |
| Mirai-greeth_flood | Mirai | 29 | 991834 | 191.358942 | 2.120359 |
| Mirai-udpplain | Mirai | 25 | 890574 | 170.801708 | 1.903884 |
| Mirai-greip_flood | Mirai | 22 | 751646 | 146.540701 | 1.606881 |
| DDoS-ICMP_Fragmentation | DDoS | 20 | 452490 | 95.096091 | 0.967341 |
| VulnerabilityScan | Recon | 1 | 373351 | 73.657480 | 0.798156 |
| MITM-ArpSpoofing | Spoofing | 2 | 307560 | 59.991693 | 0.657507 |
| DDoS-UDP_Fragmentation | DDoS | 13 | 286925 | 60.065502 | 0.613393 |
| DDoS-ACK_Fragmentation | DDoS | 13 | 285075 | 59.869618 | 0.609438 |
| DNS_Spoofing | Spoofing | 1 | 178898 | 35.127294 | 0.382451 |
| Recon-HostDiscovery | Recon | 1 | 134378 | 25.138910 | 0.287276 |
| Recon-OSScan | Recon | 1 | 98259 | 18.959338 | 0.210060 |
| Recon-PortScan | Recon | 1 | 82284 | 15.652327 | 0.175908 |
| DoS-HTTP_Flood | DoS | 2 | 71861 | 15.186052 | 0.153626 |
| DDoS-HTTP_Flood | DDoS | 1 | 28790 | 6.150994 | 0.061548 |
| DDoS-SlowLoris | DDoS | 1 | 23426 | 4.982302 | 0.050080 |
| DictionaryBruteForce | BruteForce | 1 | 13064 | 2.579045 | 0.027928 |
| BrowserHijacking | Web | 1 | 5859 | 1.151562 | 0.012525 |
| CommandInjection | Web | 1 | 5409 | 1.056588 | 0.011563 |
| SqlInjection | Web | 1 | 5245 | 1.036945 | 0.011213 |
| XSS | Web | 1 | 3846 | 0.759967 | 0.008222 |
| Backdoor_Malware | Web | 1 | 3218 | 0.633790 | 0.006879 |
| Recon-PingSweep | Recon | 1 | 2262 | 0.445080 | 0.004836 |
| Uploading_Attack | Web | 1 | 1252 | 0.248161 | 0.002677 |


# Appendix B. LOAFO Feature Rankings

| held_out_family | rank | feature | gain | normalized_gain |
|---|---|---|---|---|
| DDoS | 1 | Number | 374.950012207 | 0.553439493482 |
| DDoS | 2 | SSH | 51.3854522705 | 0.0758467469024 |
| DDoS | 3 | Protocol Type | 24.8866271973 | 0.036733542878 |
| DDoS | 4 | Min | 23.1534538269 | 0.0341753176187 |
| DDoS | 5 | Tot sum | 17.4738292694 | 0.0257919906793 |
| DDoS | 6 | Tot size | 15.9213533401 | 0.0235004812408 |
| DDoS | 7 | rst_count | 15.5470790863 | 0.0229480391906 |
| DDoS | 8 | rst_flag_number | 13.5892057419 | 0.0200581488139 |
| DDoS | 9 | AVG | 13.4979076385 | 0.0199233895808 |
| DDoS | 10 | syn_count | 12.0308465958 | 0.017757955539 |
| DDoS | 11 | TCP | 11.6737823486 | 0.017230916068 |
| DDoS | 12 | Max | 9.39348125458 | 0.013865110917 |
| DDoS | 13 | syn_flag_number | 8.67610263824 | 0.0128062346798 |
| DDoS | 14 | HTTPS | 7.36335849762 | 0.0108685778492 |
| DDoS | 15 | HTTP | 6.26616668701 | 0.00924908388966 |
| DDoS | 16 | fin_count | 4.67432451248 | 0.00689946847936 |
| DDoS | 17 | UDP | 4.54078960419 | 0.00670236622678 |
| DDoS | 18 | fin_flag_number | 4.45728635788 | 0.00657911247872 |
| DDoS | 19 | IAT | 4.18836259842 | 0.00618217148826 |
| DDoS | 20 | ece_flag_number | 4.078748703 | 0.00602037749764 |
| DDoS | 21 | IRC | 3.86778903008 | 0.00570899355117 |
| DDoS | 22 | ack_flag_number | 3.76258444786 | 0.00555370786295 |
| DDoS | 23 | Header_Length | 3.6989865303 | 0.00545983508489 |
| DDoS | 24 | ack_count | 3.6699359417 | 0.00541695538754 |
| DDoS | 25 | DNS | 3.52046203613 | 0.00519632661066 |
| DDoS | 26 | psh_flag_number | 3.07809233665 | 0.00454337327171 |
| DDoS | 27 | Time_To_Live | 3.07242250443 | 0.00453500439859 |
| DDoS | 28 | ARP | 2.98265981674 | 0.00440251149344 |
| DDoS | 29 | Variance | 2.88257551193 | 0.00425478351596 |
| DDoS | 30 | ICMP | 2.72413873672 | 0.00402092522615 |
| DDoS | 31 | Std | 2.67342185974 | 0.00394606532004 |
| DDoS | 32 | IPv | 2.62506318092 | 0.00387468619792 |
| DDoS | 33 | Rate | 2.46223545074 | 0.0036343467031 |
| DDoS | 34 | cwr_flag_number | 2.343542099 | 0.00345915111347 |
| DDoS | 35 | DHCP | 2.28404521942 | 0.00337133161267 |
| DDoS | 36 | IGMP | 2.05181455612 | 0.00302855093129 |
| DDoS | 37 | LLC | 2.04258394241 | 0.00301492621864 |
| DDoS | 38 | SMTP | 0 | 0 |
| DDoS | 39 | Telnet | 0 | 0 |
| DoS | 1 | Number | 217.035995483 | 0.412330955808 |
| DoS | 2 | SSH | 50.4759025574 | 0.0958955084866 |
| DoS | 3 | Min | 27.1629524231 | 0.0516049243825 |
| DoS | 4 | Protocol Type | 20.2386684418 | 0.0384499791581 |
| DoS | 5 | Tot size | 19.73645401 | 0.0374958583625 |
| DoS | 6 | Tot sum | 19.1710681915 | 0.0364217228284 |
| DoS | 7 | rst_flag_number | 15.1818933487 | 0.0288429787027 |
| DoS | 8 | AVG | 14.0109262466 | 0.0266183431839 |
| DoS | 9 | rst_count | 12.5743408203 | 0.0238890786644 |
| DoS | 10 | TCP | 11.9655275345 | 0.0227324384329 |
| DoS | 11 | syn_flag_number | 10.6585130692 | 0.0202493363901 |
| DoS | 12 | Max | 9.37320423126 | 0.0178074712955 |
| DoS | 13 | syn_count | 9.07201385498 | 0.0172352615316 |
| DoS | 14 | HTTPS | 8.24223041534 | 0.0156588161221 |
| DoS | 15 | ack_count | 6.55631017685 | 0.0124558584661 |
| DoS | 16 | HTTP | 5.98085641861 | 0.011362595583 |
| DoS | 17 | fin_flag_number | 4.77621173859 | 0.00907397847499 |
| DoS | 18 | fin_count | 4.45262432098 | 0.00845921819576 |
| DoS | 19 | UDP | 4.35791969299 | 0.00827929573777 |
| DoS | 20 | ece_flag_number | 4.21541690826 | 0.00800856502648 |
| DoS | 21 | IAT | 3.94849538803 | 0.00750146017819 |
| DoS | 22 | ack_flag_number | 3.72459888458 | 0.00707609544058 |
| DoS | 23 | LLC | 3.69158673286 | 0.00701337804645 |
| DoS | 24 | IRC | 3.65741991997 | 0.00694846699523 |
| DoS | 25 | DNS | 3.58242082596 | 0.00680598165288 |
| DoS | 26 | psh_flag_number | 3.11571788788 | 0.00591932657012 |
| DoS | 27 | Time_To_Live | 3.07369232178 | 0.00583948524334 |
| DoS | 28 | Std | 3.02271294594 | 0.00574263322246 |
| DoS | 29 | ARP | 3.0182929039 | 0.00573423590498 |
| DoS | 30 | ICMP | 2.96805143356 | 0.00563878577728 |
| DoS | 31 | Header_Length | 2.80764627457 | 0.00533404364279 |
| DoS | 32 | Variance | 2.75323677063 | 0.00523067497017 |
| DoS | 33 | IPv | 2.56177067757 | 0.00486692241852 |
| DoS | 34 | Rate | 2.49892377853 | 0.00474752415055 |
| DoS | 35 | DHCP | 2.40040397644 | 0.00456035351983 |
| DoS | 36 | IGMP | 2.33479833603 | 0.00443571411908 |
| DoS | 37 | cwr_flag_number | 1.96477484703 | 0.00373273331375 |
| DoS | 38 | SMTP | 0 | 0 |
| DoS | 39 | Telnet | 0 | 0 |
| Mirai | 1 | Number | 691.650878906 | 0.741400355144 |
| Mirai | 2 | SSH | 49.9701728821 | 0.0535644572301 |
| Mirai | 3 | Min | 36.666229248 | 0.039303579617 |
| Mirai | 4 | fin_flag_number | 9.13941955566 | 0.00979680516721 |
| Mirai | 5 | Tot size | 8.16031265259 | 0.00874727247984 |
| Mirai | 6 | fin_count | 7.9971203804 | 0.00857234201673 |
| Mirai | 7 | Max | 7.65518188477 | 0.00820580836538 |
| Mirai | 8 | HTTPS | 7.39872074127 | 0.00793090033206 |
| Mirai | 9 | syn_count | 6.70559263229 | 0.00718791649176 |
| Mirai | 10 | rst_count | 6.50090074539 | 0.00696850140494 |
| Mirai | 11 | rst_flag_number | 6.47260570526 | 0.00693817114232 |
| Mirai | 12 | ack_flag_number | 5.95163583755 | 0.00637972864377 |
| Mirai | 13 | Tot sum | 5.21597242355 | 0.0055911499937 |
| Mirai | 14 | HTTP | 5.14610624313 | 0.00551625843706 |
| Mirai | 15 | Protocol Type | 5.14291381836 | 0.00551283638565 |
| Mirai | 16 | syn_flag_number | 4.80802536011 | 0.00515385987098 |
| Mirai | 17 | AVG | 4.76079177856 | 0.00510322884426 |
| Mirai | 18 | psh_flag_number | 4.50190925598 | 0.00482572526545 |
| Mirai | 19 | ack_count | 4.13519144058 | 0.00443262995268 |
| Mirai | 20 | ICMP | 4.10404872894 | 0.00439924718953 |
| Mirai | 21 | ece_flag_number | 3.81357526779 | 0.00408788038031 |
| Mirai | 22 | Header_Length | 3.73120164871 | 0.00399958174251 |
| Mirai | 23 | IAT | 3.62519073486 | 0.00388594561253 |
| Mirai | 24 | IPv | 3.3733932972 | 0.00361603673885 |
| Mirai | 25 | DNS | 3.37195944786 | 0.00361449975474 |
| Mirai | 26 | ARP | 3.13255620003 | 0.00335787656755 |
| Mirai | 27 | UDP | 3.04816508293 | 0.00326741531594 |
| Mirai | 28 | Time_To_Live | 2.98237872124 | 0.00319689703365 |
| Mirai | 29 | TCP | 2.85072731972 | 0.00305577613174 |
| Mirai | 30 | LLC | 2.84087347984 | 0.003045213519 |
| Mirai | 31 | IRC | 2.75437998772 | 0.00295249867147 |
| Mirai | 32 | Std | 2.52955985069 | 0.00271150753777 |
| Mirai | 33 | Variance | 2.50596690178 | 0.00268621758118 |
| Mirai | 34 | DHCP | 2.37392997742 | 0.00254468342631 |
| Mirai | 35 | Rate | 2.35987877846 | 0.00252962154434 |
| Mirai | 36 | cwr_flag_number | 2.3557946682 | 0.00252524366977 |
| Mirai | 37 | IGMP | 2.20502257347 | 0.00236362675004 |
| Mirai | 38 | Telnet | 0.483416557312 | 0.00051818803128 |
| Mirai | 39 | SMTP | 0.476259350777 | 0.000510516016931 |
| Recon | 1 | Number | 381.034912109 | 0.515455897024 |
| Recon | 2 | SSH | 62.2349700928 | 0.0841901393178 |
| Recon | 3 | Protocol Type | 52.813129425 | 0.0714444743442 |
| Recon | 4 | Min | 34.1585464478 | 0.0462089526201 |
| Recon | 5 | Tot size | 21.9658699036 | 0.0297149600082 |
| Recon | 6 | Tot sum | 21.5727348328 | 0.0291831352747 |
| Recon | 7 | AVG | 20.0473022461 | 0.0271195626274 |
| Recon | 8 | fin_count | 11.4125041962 | 0.01543859211 |
| Recon | 9 | Max | 9.44855308533 | 0.0127818009621 |
| Recon | 10 | fin_flag_number | 9.36483764648 | 0.0126685525031 |
| Recon | 11 | TCP | 9.26460933685 | 0.0125329657849 |
| Recon | 12 | HTTPS | 8.56951808929 | 0.0115926611799 |
| Recon | 13 | ack_count | 6.96540880203 | 0.00942265637108 |
| Recon | 14 | ICMP | 6.53317689896 | 0.00883794227733 |
| Recon | 15 | psh_flag_number | 5.99392986298 | 0.00810846039571 |
| Recon | 16 | syn_count | 5.62420225143 | 0.00760830077357 |
| Recon | 17 | IAT | 5.04974603653 | 0.00683118866614 |
| Recon | 18 | HTTP | 4.43776702881 | 0.0060033165254 |
| Recon | 19 | rst_count | 4.21156167984 | 0.005697310757 |
| Recon | 20 | ack_flag_number | 4.20805597305 | 0.00569256831168 |
| Recon | 21 | LLC | 4.16949033737 | 0.0056403975428 |
| Recon | 22 | Header_Length | 3.93851780891 | 0.00532794283574 |
| Recon | 23 | UDP | 3.83892631531 | 0.00519321758868 |
| Recon | 24 | IRC | 3.71871161461 | 0.0050305937072 |
| Recon | 25 | rst_flag_number | 3.39572262764 | 0.00459366109889 |
| Recon | 26 | Std | 3.3627011776 | 0.00454899038602 |
| Recon | 27 | Variance | 3.31163167953 | 0.00447990465897 |
| Recon | 28 | DNS | 3.23730897903 | 0.00437936249593 |
| Recon | 29 | IPv | 3.17877578735 | 0.00430018004345 |
| Recon | 30 | ARP | 3.04852938652 | 0.00412398549213 |
| Recon | 31 | Time_To_Live | 3.01866030693 | 0.00408357923873 |
| Recon | 32 | ece_flag_number | 2.88856744766 | 0.00390759239516 |
| Recon | 33 | syn_flag_number | 2.69547319412 | 0.00364637861001 |
| Recon | 34 | Rate | 2.6530957222 | 0.00358905127041 |
| Recon | 35 | DHCP | 2.40882825851 | 0.00325861145871 |
| Recon | 36 | cwr_flag_number | 2.32118344307 | 0.0031400474229 |
| Recon | 37 | IGMP | 2.21296024323 | 0.00299364538786 |
| Recon | 38 | SMTP | 0.455706179142 | 0.000616469593426 |
| Recon | 39 | Telnet | 0.453105121851 | 0.000612950938634 |
| Spoofing | 1 | Number | 446.406921387 | 0.63865549457 |
| Spoofing | 2 | SSH | 44.3125076294 | 0.0633960297654 |
| Spoofing | 3 | Protocol Type | 20.2355918884 | 0.0289502051296 |
| Spoofing | 4 | Tot size | 19.8878955841 | 0.0284527707384 |
| Spoofing | 5 | Tot sum | 19.6382026672 | 0.0280955456469 |
| Spoofing | 6 | AVG | 14.6193275452 | 0.0209152533626 |
| Spoofing | 7 | fin_flag_number | 8.94156551361 | 0.0127923194551 |
| Spoofing | 8 | TCP | 8.7938785553 | 0.0125810299726 |
| Spoofing | 9 | HTTPS | 8.67145633698 | 0.0124058856846 |
| Spoofing | 10 | rst_flag_number | 7.35717153549 | 0.0105255940276 |
| Spoofing | 11 | fin_count | 6.60615682602 | 0.00945114905885 |
| Spoofing | 12 | rst_count | 6.52292490005 | 0.00933207266399 |
| Spoofing | 13 | ack_count | 5.96047067642 | 0.00852739320416 |
| Spoofing | 14 | syn_count | 5.74186515808 | 0.00821464353845 |
| Spoofing | 15 | ack_flag_number | 5.08867883682 | 0.0072801575055 |
| Spoofing | 16 | ICMP | 5.07203054428 | 0.00725633949776 |
| Spoofing | 17 | HTTP | 4.95605945587 | 0.00709042456841 |
| Spoofing | 18 | Max | 4.51604604721 | 0.00646091600198 |
| Spoofing | 19 | psh_flag_number | 4.47224569321 | 0.00639825268874 |
| Spoofing | 20 | syn_flag_number | 4.40035581589 | 0.00629540288298 |
| Spoofing | 21 | Min | 4.37336778641 | 0.00625679225109 |
| Spoofing | 22 | ece_flag_number | 3.8360824585 | 0.00548812086545 |
| Spoofing | 23 | Variance | 3.35367918015 | 0.00479796690601 |
| Spoofing | 24 | Header_Length | 3.28119301796 | 0.00469426402072 |
| Spoofing | 25 | DNS | 3.11530923843 | 0.00445694111604 |
| Spoofing | 26 | Std | 3.0676074028 | 0.0043886961181 |
| Spoofing | 27 | IAT | 2.97161030769 | 0.00425135713585 |
| Spoofing | 28 | IRC | 2.89395260811 | 0.00414025555082 |
| Spoofing | 29 | Time_To_Live | 2.53216409683 | 0.00362266003531 |
| Spoofing | 30 | UDP | 2.38449168205 | 0.00341139135964 |
| Spoofing | 31 | DHCP | 2.21839666367 | 0.00317376624445 |
| Spoofing | 32 | cwr_flag_number | 2.15004086494 | 0.00307597249541 |
| Spoofing | 33 | IGMP | 2.08079862595 | 0.00297691055378 |
| Spoofing | 34 | Rate | 2.02379608154 | 0.00289535942532 |
| Spoofing | 35 | LLC | 1.92823171616 | 0.00275863953118 |
| Spoofing | 36 | ARP | 1.88017427921 | 0.00268988578949 |
| Spoofing | 37 | IPv | 1.81801223755 | 0.00260095318661 |
| Spoofing | 38 | SMTP | 0.435684204102 | 0.000623314956638 |
| Spoofing | 39 | Telnet | 0.433277994394 | 0.000619872494218 |
| BruteForce | 1 | Number | 497.537567139 | 0.605628761853 |
| BruteForce | 2 | Protocol Type | 39.9161834717 | 0.0485880672547 |
| BruteForce | 3 | Min | 34.4967346191 | 0.0419912305226 |
| BruteForce | 4 | Tot sum | 30.5583591461 | 0.0371972338096 |
| BruteForce | 5 | AVG | 21.4404315948 | 0.0260984152716 |
| BruteForce | 6 | Tot size | 21.3774986267 | 0.0260218099696 |
| BruteForce | 7 | fin_count | 16.7986774445 | 0.0204482292261 |
| BruteForce | 8 | syn_count | 13.6828517914 | 0.0166554831964 |
| BruteForce | 9 | fin_flag_number | 11.4376115799 | 0.0139224593221 |
| BruteForce | 10 | HTTPS | 10.9947490692 | 0.0133833839 |
| BruteForce | 11 | TCP | 10.3845281601 | 0.0126405910778 |
| BruteForce | 12 | Max | 9.48223495483 | 0.0115422725732 |
| BruteForce | 13 | ICMP | 7.3063287735 | 0.00889364570847 |
| BruteForce | 14 | ack_flag_number | 7.27954816818 | 0.00886104695431 |
| BruteForce | 15 | rst_flag_number | 6.794465065 | 0.0082705784177 |
| BruteForce | 16 | rst_count | 6.52531003952 | 0.00794294883635 |
| BruteForce | 17 | syn_flag_number | 6.52405643463 | 0.00794142288288 |
| BruteForce | 18 | ack_count | 5.8420996666 | 0.00711130941941 |
| BruteForce | 19 | SSH | 5.30469369888 | 0.00645715075414 |
| BruteForce | 20 | psh_flag_number | 5.28415727615 | 0.00643215274577 |
| BruteForce | 21 | IAT | 4.40089988708 | 0.00535700563273 |
| BruteForce | 22 | Header_Length | 4.29748249054 | 0.00523112056603 |
| BruteForce | 23 | ece_flag_number | 4.22385883331 | 0.00514150199788 |
| BruteForce | 24 | UDP | 4.16376638412 | 0.00506835432421 |
| BruteForce | 25 | HTTP | 3.98060584068 | 0.00484540172631 |
| BruteForce | 26 | Std | 3.85756707191 | 0.0046956324986 |
| BruteForce | 27 | ARP | 3.25629258156 | 0.00396372972546 |
| BruteForce | 28 | Time_To_Live | 3.22566723824 | 0.00392645095501 |
| BruteForce | 29 | Variance | 3.14058852196 | 0.00382288868956 |
| BruteForce | 30 | IPv | 2.88829350471 | 0.00351578199248 |
| BruteForce | 31 | LLC | 2.66496992111 | 0.00324394084045 |
| BruteForce | 32 | Rate | 2.36311006546 | 0.00287650122844 |
| BruteForce | 33 | DNS | 2.35416245461 | 0.00286560972829 |
| BruteForce | 34 | cwr_flag_number | 1.87511992455 | 0.00228249409338 |
| BruteForce | 35 | DHCP | 1.84543704987 | 0.00224636254508 |
| BruteForce | 36 | IGMP | 1.49989676476 | 0.00182575282862 |
| BruteForce | 37 | IRC | 1.49088811874 | 0.00181478703329 |
| BruteForce | 38 | Telnet | 0.521849811077 | 0.000635222897385 |
| BruteForce | 39 | SMTP | 0.503812551498 | 0.000613267001173 |
| Web | 1 | Number | 423.17779541 | 0.521018777671 |
| Web | 2 | Protocol Type | 52.8093528748 | 0.065019159282 |
| Web | 3 | SSH | 52.7851219177 | 0.0649893259974 |
| Web | 4 | Min | 39.9843559265 | 0.0492289540631 |
| Web | 5 | Tot sum | 31.1358604431 | 0.0383346388344 |
| Web | 6 | Tot size | 24.1119403839 | 0.029686750681 |
| Web | 7 | AVG | 18.629201889 | 0.0229363735585 |
| Web | 8 | fin_flag_number | 13.8603534698 | 0.0170649417367 |
| Web | 9 | TCP | 11.5684108734 | 0.0142430896853 |
| Web | 10 | Max | 11.2095537186 | 0.0138012628262 |
| Web | 11 | syn_count | 10.5699996948 | 0.0130138404725 |
| Web | 12 | HTTPS | 10.0998048782 | 0.0124349340855 |
| Web | 13 | fin_count | 8.11730670929 | 0.00999407167749 |
| Web | 14 | rst_flag_number | 7.65953588486 | 0.00943046177644 |
| Web | 15 | rst_count | 7.65786266327 | 0.00942840169702 |
| Web | 16 | syn_flag_number | 6.89275312424 | 0.0084863947176 |
| Web | 17 | ICMP | 6.84228181839 | 0.0084242541744 |
| Web | 18 | psh_flag_number | 5.83706235886 | 0.00718662256948 |
| Web | 19 | ack_count | 5.66157102585 | 0.00697055669644 |
| Web | 20 | HTTP | 5.49751615524 | 0.00676857145743 |
| Web | 21 | ack_flag_number | 5.36083364487 | 0.00660028721554 |
| Web | 22 | UDP | 4.7122797966 | 0.00580178422946 |
| Web | 23 | ece_flag_number | 4.69716596603 | 0.00578317599998 |
| Web | 24 | IAT | 4.63138246536 | 0.00570218300015 |
| Web | 25 | DNS | 3.78194952011 | 0.00465635658948 |
| Web | 26 | IPv | 3.59127902985 | 0.00442160205639 |
| Web | 27 | Std | 3.49109458923 | 0.00429825443429 |
| Web | 28 | Header_Length | 3.46737670898 | 0.00426905285257 |
| Web | 29 | ARP | 3.32852602005 | 0.00409809913758 |
| Web | 30 | Time_To_Live | 3.08868598938 | 0.00380280680189 |
| Web | 31 | Rate | 2.72400712967 | 0.00335381222848 |
| Web | 32 | Variance | 2.71373391151 | 0.00334116378703 |
| Web | 33 | LLC | 2.68317627907 | 0.00330354106562 |
| Web | 34 | IRC | 2.40965533257 | 0.00296678060522 |
| Web | 35 | cwr_flag_number | 2.18536496162 | 0.00269063309422 |
| Web | 36 | DHCP | 2.10265016556 | 0.00258879419244 |
| Web | 37 | IGMP | 2.02264332771 | 0.00249028934339 |
| Web | 38 | Telnet | 0.588138878345 | 0.000724119750185 |
| Web | 39 | SMTP | 0.524591565132 | 0.000645879956382 |


# Appendix C. NOS Inner-Holdout Evaluation Archive

| outer_held_out_family | inner_held_out_fine_label | candidate | known_rejection | UADR | overall_risk | AUROC | AUPRC |
|---|---|---|---|---|---|---|---|
| DDoS | DoS-HTTP_Flood | MSP | 0.0500068729 | 0.0000000000 | 0.0556889034 | 0.3989006404 | 0.0142045418 |
| DDoS | DoS-HTTP_Flood | Entropy | 0.0500068729 | 0.0000000000 | 0.0589555313 | 0.3984229798 | 0.0141104699 |
| DDoS | DoS-HTTP_Flood | MD-Pred | 0.0500068729 | 0.9367771781 | 0.0621441165 | 0.9918696543 | 0.6851096861 |
| DDoS | DoS-HTTP_Flood | Min-MD | 0.0500068729 | 0.9367771781 | 0.0623030899 | 0.9915904056 | 0.6415887149 |
| DDoS | DoS-HTTP_Flood | MDS | 0.0500068729 | 0.9992289900 | 0.0616815939 | 0.9915058753 | 0.5599413159 |
| DDoS | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500068729 | 0.9614494988 | 0.0617824817 | 0.9920437489 | 0.7616947317 |
| DDoS | DoS-HTTP_Flood | GlobalKNN | 0.0500068729 | 0.9969159599 | 0.0610278373 | 0.9943531968 | 0.7805997203 |
| DDoS | Mirai-greeth_flood | MSP | 0.0500095945 | 0.0000000000 | 0.3193673971 | 0.1293928949 | 0.2706316635 |
| DDoS | Mirai-greeth_flood | Entropy | 0.0500095945 | 0.0000000000 | 0.3218378128 | 0.1316295453 | 0.1723664784 |
| DDoS | Mirai-greeth_flood | MD-Pred | 0.0500095945 | 0.0138709432 | 0.3339460513 | 0.4244379608 | 0.2297959498 |
| DDoS | Mirai-greeth_flood | Min-MD | 0.0500095945 | 0.0121608269 | 0.3343773865 | 0.4743601035 | 0.2443450208 |
| DDoS | Mirai-greeth_flood | MDS | 0.0500095945 | 0.0120848218 | 0.3347462786 | 0.2839834669 | 0.1987685752 |
| DDoS | Mirai-greeth_flood | ClassConditionalKNN | 0.0500095945 | 0.0093486357 | 0.3346898603 | 0.4018339380 | 0.2644924933 |
| DDoS | Mirai-greeth_flood | GlobalKNN | 0.0500095945 | 0.0107167287 | 0.3343363830 | 0.4102279607 | 0.2662566024 |
| DDoS | Recon-HostDiscovery | MSP | 0.0500021338 | 0.1243733412 | 0.1817846655 | 0.6024619384 | 0.2292888314 |
| DDoS | Recon-HostDiscovery | Entropy | 0.0500021338 | 0.1203184901 | 0.1853291663 | 0.6040005717 | 0.2302881047 |
| DDoS | Recon-HostDiscovery | MD-Pred | 0.0500021338 | 0.1528310233 | 0.1974882782 | 0.7582780745 | 0.3386735878 |
| DDoS | Recon-HostDiscovery | Min-MD | 0.0500021338 | 0.1886611619 | 0.1925900215 | 0.7451935830 | 0.3414091586 |
| DDoS | Recon-HostDiscovery | MDS | 0.0500021338 | 0.0801386022 | 0.2079132969 | 0.6926850699 | 0.2744419680 |
| DDoS | Recon-HostDiscovery | ClassConditionalKNN | 0.0500021338 | 0.0787378354 | 0.2074724388 | 0.7072559467 | 0.2523210435 |
| DDoS | Recon-HostDiscovery | GlobalKNN | 0.0500021338 | 0.1008552050 | 0.2043607080 | 0.7153671753 | 0.2616272826 |
| DDoS | DNS_Spoofing | MSP | 0.0500014737 | 0.0628857575 | 0.3004875516 | 0.5290094053 | 0.2797615822 |
| DDoS | DNS_Spoofing | Entropy | 0.0500014737 | 0.0636621249 | 0.3032194703 | 0.5299615786 | 0.2821264466 |
| DDoS | DNS_Spoofing | MD-Pred | 0.0500014737 | 0.0479795039 | 0.3203168895 | 0.6252753118 | 0.3356177672 |
| DDoS | DNS_Spoofing | Min-MD | 0.0500014737 | 0.0282985909 | 0.3242008112 | 0.6166823317 | 0.3258890732 |
| DDoS | DNS_Spoofing | MDS | 0.0500014737 | 0.0116843290 | 0.3276396997 | 0.5729759884 | 0.2895877538 |
| DDoS | DNS_Spoofing | ClassConditionalKNN | 0.0500014737 | 0.2310081130 | 0.2815544349 | 0.7163740857 | 0.4933249551 |
| DDoS | DNS_Spoofing | GlobalKNN | 0.0500014737 | 0.0499592407 | 0.3197584862 | 0.6465750829 | 0.3364790267 |
| DDoS | Backdoor_Malware | MSP | 0.0500075790 | 0.0341685649 | 0.0680973825 | 0.7242078429 | 0.0468861974 |
| DDoS | Backdoor_Malware | Entropy | 0.0500075790 | 0.0496583144 | 0.0710866443 | 0.7352881121 | 0.0497597455 |
| DDoS | Backdoor_Malware | MD-Pred | 0.0500075790 | 0.0601366743 | 0.0900102813 | 0.6081573170 | 0.0420100072 |
| DDoS | Backdoor_Malware | Min-MD | 0.0500075790 | 0.0578587699 | 0.0902011041 | 0.5949951364 | 0.0413024649 |
| DDoS | Backdoor_Malware | MDS | 0.0500075790 | 0.0328018223 | 0.0912289096 | 0.5350411364 | 0.0318279954 |
| DDoS | Backdoor_Malware | ClassConditionalKNN | 0.0500075790 | 0.1129840547 | 0.0881684935 | 0.7674246435 | 0.0790999803 |
| DDoS | Backdoor_Malware | GlobalKNN | 0.0500075790 | 0.0906605923 | 0.0888265479 | 0.7243890764 | 0.0540113704 |
| DDoS | DoS-SYN_Flood | MSP | 0.0500135790 | 0.0000000000 | 0.2189924853 | 0.0765358969 | 0.1526268774 |
| DDoS | DoS-SYN_Flood | Entropy | 0.0500135790 | 0.0000000000 | 0.2216850660 | 0.0450837154 | 0.0964326348 |
| DDoS | DoS-SYN_Flood | MD-Pred | 0.0500135790 | 0.9996720021 | 0.0635653783 | 0.9995184979 | 0.9925522542 |
| DDoS | DoS-SYN_Flood | Min-MD | 0.0500135790 | 0.9995408029 | 0.0636838225 | 0.9994709745 | 0.9924558857 |
| DDoS | DoS-SYN_Flood | MDS | 0.0500135790 | 0.9994752034 | 0.0639235745 | 0.9994738072 | 0.9923450688 |
| DDoS | DoS-SYN_Flood | ClassConditionalKNN | 0.0500135790 | 0.4302020467 | 0.1717810188 | 0.9614392717 | 0.7883981088 |
| DDoS | DoS-SYN_Flood | GlobalKNN | 0.0500135790 | 0.9986880084 | 0.0638669113 | 0.9762840157 | 0.8588719300 |
| DDoS | Mirai-greip_flood | MSP | 0.0500079723 | 0.0000000000 | 0.2660875048 | 0.0955949373 | 0.1674951950 |
| DDoS | Mirai-greip_flood | Entropy | 0.0500079723 | 0.0000000000 | 0.2683994816 | 0.1035408681 | 0.1307000555 |
| DDoS | Mirai-greip_flood | MD-Pred | 0.0500079723 | 0.0248234007 | 0.2794860351 | 0.1860154647 | 0.1422233854 |
| DDoS | Mirai-greip_flood | Min-MD | 0.0500079723 | 0.0215898916 | 0.2801060946 | 0.2229646710 | 0.1458802627 |
| DDoS | Mirai-greip_flood | MDS | 0.0500079723 | 0.0242264451 | 0.2798811565 | 0.2180015277 | 0.1479948518 |
| DDoS | Mirai-greip_flood | ClassConditionalKNN | 0.0500079723 | 0.0192020694 | 0.2803237347 | 0.4236791993 | 0.1913508031 |
| DDoS | Mirai-greip_flood | GlobalKNN | 0.0500079723 | 0.0235797433 | 0.2795918607 | 0.4341890170 | 0.2128994873 |
| DDoS | Recon-OSScan | MSP | 0.0500021134 | 0.1141395257 | 0.1459878845 | 0.7262055576 | 0.2260883247 |
| DDoS | Recon-OSScan | Entropy | 0.0500021134 | 0.1110892453 | 0.1495383328 | 0.7222857695 | 0.2204232545 |
| DDoS | Recon-OSScan | MD-Pred | 0.0500021134 | 0.1802617337 | 0.1587666152 | 0.6339227803 | 0.2003592994 |
| DDoS | Recon-OSScan | Min-MD | 0.0500021134 | 0.1820328643 | 0.1586591146 | 0.6208159793 | 0.1992744911 |
| DDoS | Recon-OSScan | MDS | 0.0500021134 | 0.0991833120 | 0.1681574240 | 0.5532564226 | 0.1554713495 |
| DDoS | Recon-OSScan | ClassConditionalKNN | 0.0500021134 | 0.0989865197 | 0.1677482536 | 0.6752234851 | 0.1983807040 |
| DDoS | Recon-OSScan | GlobalKNN | 0.0500021134 | 0.1143363180 | 0.1659317798 | 0.6746337938 | 0.2006568856 |
| DDoS | MITM-ArpSpoofing | MSP | 0.0500077387 | 0.0408780325 | 0.4176363547 | 0.5562808824 | 0.3958063298 |
| DDoS | MITM-ArpSpoofing | Entropy | 0.0500077387 | 0.0493774254 | 0.4181802029 | 0.5583585966 | 0.4016975148 |
| DDoS | MITM-ArpSpoofing | MD-Pred | 0.0500077387 | 0.1601076114 | 0.4015125650 | 0.6809045499 | 0.5351299913 |
| DDoS | MITM-ArpSpoofing | Min-MD | 0.0500077387 | 0.1504654429 | 0.4040922297 | 0.6365797478 | 0.5045777324 |
| DDoS | MITM-ArpSpoofing | MDS | 0.0500077387 | 0.0577339714 | 0.4274790257 | 0.5838839470 | 0.4477521312 |
| DDoS | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500077387 | 0.1251101112 | 0.4106820753 | 0.6703337452 | 0.5353182673 |
| DDoS | MITM-ArpSpoofing | GlobalKNN | 0.0500077387 | 0.0813751399 | 0.4216417910 | 0.6512623880 | 0.4874858567 |
| DDoS | BrowserHijacking | MSP | 0.0500131577 | 0.0430054375 | 0.0902818029 | 0.7055750224 | 0.0798769856 |
| DDoS | BrowserHijacking | Entropy | 0.0500131577 | 0.0684626792 | 0.0921792728 | 0.7138164960 | 0.0847894380 |
| DDoS | BrowserHijacking | MD-Pred | 0.0500131577 | 0.1072664360 | 0.1095537520 | 0.6602759130 | 0.0794988686 |
| DDoS | BrowserHijacking | Min-MD | 0.0500131577 | 0.0961443401 | 0.1102467923 | 0.6325384558 | 0.0757740866 |
| DDoS | BrowserHijacking | MDS | 0.0500131577 | 0.0227385072 | 0.1143443979 | 0.5600493512 | 0.0582741327 |
| DDoS | BrowserHijacking | ClassConditionalKNN | 0.0500131577 | 0.2859614434 | 0.1001832706 | 0.8274996249 | 0.2102988683 |
| DDoS | BrowserHijacking | GlobalKNN | 0.0500131577 | 0.1594167079 | 0.1067911267 | 0.7556520141 | 0.1234120443 |
| DDoS | DoS-TCP_Flood | MSP | 0.0500072390 | 0.0000000000 | 0.2617359198 | 0.0970546059 | 0.1665576499 |
| DDoS | DoS-TCP_Flood | Entropy | 0.0500072390 | 0.0000000000 | 0.2643732052 | 0.1053111831 | 0.1285670023 |
| DDoS | DoS-TCP_Flood | MD-Pred | 0.0500072390 | 0.9996446520 | 0.0635295552 | 0.9815948080 | 0.8210951021 |
| DDoS | DoS-TCP_Flood | Min-MD | 0.0500072390 | 0.9995431240 | 0.0636038095 | 0.9826286047 | 0.8279491680 |
| DDoS | DoS-TCP_Flood | MDS | 0.0500072390 | 0.9998477080 | 0.0637772596 | 0.9933729743 | 0.9148245621 |
| DDoS | DoS-TCP_Flood | ClassConditionalKNN | 0.0500072390 | 0.9998984720 | 0.0631838825 | 0.9954517420 | 0.9663970240 |
| DDoS | DoS-TCP_Flood | GlobalKNN | 0.0500072390 | 0.9999492360 | 0.0632000853 | 0.9952951358 | 0.9508528706 |
| DDoS | Mirai-udpplain | MSP | 0.0500051250 | 0.0000000000 | 0.2977549682 | 0.2425865804 | 0.2209573660 |
| DDoS | Mirai-udpplain | Entropy | 0.0500051250 | 0.0000000000 | 0.2999366960 | 0.2449514353 | 0.1747455708 |
| DDoS | Mirai-udpplain | MD-Pred | 0.0500051250 | 1.0000000000 | 0.0665248620 | 0.9910321590 | 0.9054087372 |
| DDoS | Mirai-udpplain | Min-MD | 0.0500051250 | 0.9958022388 | 0.0680702402 | 0.9736443101 | 0.8014727776 |
| DDoS | Mirai-udpplain | MDS | 0.0500051250 | 0.9980919267 | 0.0678033979 | 0.9904094859 | 0.9047172284 |
| DDoS | Mirai-udpplain | ClassConditionalKNN | 0.0500051250 | 1.0000000000 | 0.0663707266 | 0.9898912523 | 0.9433188070 |
| DDoS | Mirai-udpplain | GlobalKNN | 0.0500051250 | 0.9975407056 | 0.0669736356 | 0.9847607320 | 0.9226198998 |
| DoS | DDoS-ACK_Fragmentation | MSP | 0.0500122947 | 0.0000000000 | 0.0582392585 | 0.4059560021 | 0.0137588494 |
| DoS | DDoS-ACK_Fragmentation | Entropy | 0.0500122947 | 0.0000000000 | 0.0617290928 | 0.4046201587 | 0.0135818974 |
| DoS | DDoS-ACK_Fragmentation | MD-Pred | 0.0500122947 | 0.9983818770 | 0.0672677336 | 0.9900807572 | 0.4202280307 |
| DoS | DDoS-ACK_Fragmentation | Min-MD | 0.0500122947 | 0.9967637540 | 0.0673233158 | 0.9846425315 | 0.3212727725 |
| DoS | DDoS-ACK_Fragmentation | MDS | 0.0500122947 | 0.9959546926 | 0.0674661375 | 0.9799803426 | 0.2682441822 |
| DoS | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500122947 | 1.0000000000 | 0.0664787679 | 0.9975148565 | 0.7181538346 |
| DoS | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500122947 | 1.0000000000 | 0.0665219079 | 0.9983830707 | 0.7919864167 |
| DoS | Mirai-greeth_flood | MSP | 0.0500095326 | 0.0000000000 | 0.3213160466 | 0.0580071814 | 0.2209082858 |
| DoS | Mirai-greeth_flood | Entropy | 0.0500095326 | 0.0000000000 | 0.3236982797 | 0.0519098694 | 0.1588520021 |
| DoS | Mirai-greeth_flood | MD-Pred | 0.0500095326 | 0.0104127081 | 0.3373817677 | 0.3924219222 | 0.2209861912 |
| DoS | Mirai-greeth_flood | Min-MD | 0.0500095326 | 0.0070684807 | 0.3380452120 | 0.4483738224 | 0.2364170251 |
| DoS | Mirai-greeth_flood | MDS | 0.0500095326 | 0.0099186745 | 0.3376087196 | 0.4215918447 | 0.2312918497 |
| DoS | Mirai-greeth_flood | ClassConditionalKNN | 0.0500095326 | 0.0088165995 | 0.3371707811 | 0.4113691044 | 0.2681180873 |
| DoS | Mirai-greeth_flood | GlobalKNN | 0.0500095326 | 0.0098426693 | 0.3370508191 | 0.4193157144 | 0.2697796891 |
| DoS | Recon-HostDiscovery | MSP | 0.0500021205 | 0.1281332940 | 0.1829777542 | 0.6134744623 | 0.2341259731 |
| DoS | Recon-HostDiscovery | Entropy | 0.0500021205 | 0.1259952816 | 0.1857820505 | 0.6146311819 | 0.2341723615 |
| DoS | Recon-HostDiscovery | MD-Pred | 0.0500021205 | 0.1599085815 | 0.1991602519 | 0.7056823595 | 0.3061311271 |
| DoS | Recon-HostDiscovery | Min-MD | 0.0500021205 | 0.1603509289 | 0.1991754571 | 0.6989760568 | 0.3154250666 |
| DoS | Recon-HostDiscovery | MDS | 0.0500021205 | 0.1563698024 | 0.1999033608 | 0.6719865709 | 0.2662695723 |
| DoS | Recon-HostDiscovery | ClassConditionalKNN | 0.0500021205 | 0.0785903863 | 0.2097919647 | 0.7152860579 | 0.2552026116 |
| DoS | Recon-HostDiscovery | GlobalKNN | 0.0500021205 | 0.0865526393 | 0.2088327679 | 0.7194865524 | 0.2599615437 |
| DoS | DNS_Spoofing | MSP | 0.0500014642 | 0.0666511393 | 0.3000101207 | 0.5302034484 | 0.2810987193 |
| DoS | DNS_Spoofing | Entropy | 0.0500014642 | 0.0661465005 | 0.3022711941 | 0.5309046165 | 0.2833655182 |
| DoS | DNS_Spoofing | MD-Pred | 0.0500014642 | 0.0190598191 | 0.3271216709 | 0.5488589840 | 0.2820803661 |
| DoS | DNS_Spoofing | Min-MD | 0.0500014642 | 0.0171577190 | 0.3275980577 | 0.5357244077 | 0.2700441812 |
| DoS | DNS_Spoofing | MDS | 0.0500014642 | 0.0169636272 | 0.3276907557 | 0.5443077505 | 0.2707962983 |
| DoS | DNS_Spoofing | ClassConditionalKNN | 0.0500014642 | 0.2312022049 | 0.2823422445 | 0.7259114939 | 0.5059197010 |
| DoS | DNS_Spoofing | GlobalKNN | 0.0500014642 | 0.0599743799 | 0.3186567750 | 0.6490821820 | 0.3373677915 |
| DoS | Backdoor_Malware | MSP | 0.0500061635 | 0.0387243736 | 0.0686721701 | 0.7272731487 | 0.0471569332 |
| DoS | Backdoor_Malware | Entropy | 0.0500061635 | 0.0496583144 | 0.0719004563 | 0.7384052093 | 0.0499853430 |
| DoS | Backdoor_Malware | MD-Pred | 0.0500061635 | 0.0341685649 | 0.0929770565 | 0.4948477418 | 0.0327357237 |
| DoS | Backdoor_Malware | Min-MD | 0.0500061635 | 0.0346241458 | 0.0930063375 | 0.4916724503 | 0.0325178333 |
| DoS | Backdoor_Malware | MDS | 0.0500061635 | 0.0305239180 | 0.0932464190 | 0.4814542565 | 0.0300346093 |
| DoS | Backdoor_Malware | ClassConditionalKNN | 0.0500061635 | 0.1025056948 | 0.0901724380 | 0.7678178116 | 0.0808703847 |
| DoS | Backdoor_Malware | GlobalKNN | 0.0500061635 | 0.0797266515 | 0.0909078173 | 0.7262352985 | 0.0535648074 |
| DoS | DDoS-ICMP_Flood | MSP | 0.0500049510 | 0.0000000000 | 0.2062635123 | 0.2878541965 | 0.1654124186 |
| DoS | DDoS-ICMP_Flood | Entropy | 0.0500049510 | 0.0000000000 | 0.2091667181 | 0.2884578638 | 0.1176967535 |
| DoS | DDoS-ICMP_Flood | MD-Pred | 0.0500049510 | 0.9994197432 | 0.0678617157 | 0.9975012322 | 0.9478664056 |
| DoS | DDoS-ICMP_Flood | Min-MD | 0.0500049510 | 0.9994197432 | 0.0679808236 | 0.9975442489 | 0.9489235878 |
| DoS | DDoS-ICMP_Flood | MDS | 0.0500049510 | 0.9994197432 | 0.0682041509 | 0.9984580407 | 0.9639232094 |
| DoS | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500049510 | 0.9999274679 | 0.0670796170 | 0.9987610876 | 0.9873834067 |
| DoS | DDoS-ICMP_Flood | GlobalKNN | 0.0500049510 | 0.9998549358 | 0.0670637284 | 0.9992881732 | 0.9929202384 |
| DoS | Mirai-greip_flood | MSP | 0.0500100827 | 0.0000000000 | 0.2675583341 | 0.0797273121 | 0.1726265136 |
| DoS | Mirai-greip_flood | Entropy | 0.0500100827 | 0.0000000000 | 0.2701612903 | 0.0697923840 | 0.1254215120 |
| DoS | Mirai-greip_flood | MD-Pred | 0.0500100827 | 0.0109441847 | 0.2849620206 | 0.2019928609 | 0.1425403747 |
| DoS | Mirai-greip_flood | Min-MD | 0.0500100827 | 0.0056213312 | 0.2858987934 | 0.2547736429 | 0.1500204355 |
| DoS | Mirai-greip_flood | MDS | 0.0500100827 | 0.0106954532 | 0.2851318135 | 0.2616366395 | 0.1526111200 |
| DoS | Mirai-greip_flood | ClassConditionalKNN | 0.0500100827 | 0.0162670381 | 0.2834046822 | 0.4379144928 | 0.2158014917 |
| DoS | Mirai-greip_flood | GlobalKNN | 0.0500100827 | 0.0195502935 | 0.2830276782 | 0.4499390504 | 0.2185042241 |
| DoS | Recon-OSScan | MSP | 0.0500021003 | 0.1120732067 | 0.1486145440 | 0.7228052227 | 0.2222754194 |
| DoS | Recon-OSScan | Entropy | 0.0500021003 | 0.1096133032 | 0.1523506080 | 0.7192213487 | 0.2174790731 |
| DoS | Recon-OSScan | MD-Pred | 0.0500021003 | 0.1656991046 | 0.1637733377 | 0.5716746861 | 0.1776912987 |
| DoS | Recon-OSScan | Min-MD | 0.0500021003 | 0.1724884385 | 0.1630166807 | 0.5645567501 | 0.1828101105 |
| DoS | Recon-OSScan | MDS | 0.0500021003 | 0.1651087277 | 0.1639307752 | 0.5440163759 | 0.1687047489 |
| DoS | Recon-OSScan | ClassConditionalKNN | 0.0500021003 | 0.1044967037 | 0.1697921946 | 0.6788441284 | 0.2007947204 |
| DoS | Recon-OSScan | GlobalKNN | 0.0500021003 | 0.1087277379 | 0.1693670030 | 0.6801836246 | 0.2020152628 |
| DoS | MITM-ArpSpoofing | MSP | 0.0500076864 | 0.0439730495 | 0.4176826577 | 0.5572366364 | 0.3963824995 |
| DoS | MITM-ArpSpoofing | Entropy | 0.0500076864 | 0.0513296669 | 0.4181161702 | 0.5593949133 | 0.4020575428 |
| DoS | MITM-ArpSpoofing | MD-Pred | 0.0500076864 | 0.1018974835 | 0.4186696141 | 0.6111222611 | 0.4696938808 |
| DoS | MITM-ArpSpoofing | Min-MD | 0.0500076864 | 0.0986120039 | 0.4194946718 | 0.5657266881 | 0.4410341036 |
| DoS | MITM-ArpSpoofing | MDS | 0.0500076864 | 0.0966835702 | 0.4199360330 | 0.5562348610 | 0.4265676484 |
| DoS | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500076864 | 0.1482513154 | 0.4066493805 | 0.6667358109 | 0.5478149241 |
| DoS | MITM-ArpSpoofing | GlobalKNN | 0.0500076864 | 0.0922076995 | 0.4207371381 | 0.6518662281 | 0.4880719632 |
| DoS | BrowserHijacking | MSP | 0.0500130780 | 0.0444883836 | 0.0921453468 | 0.7124920356 | 0.0812754192 |
| DoS | BrowserHijacking | Entropy | 0.0500130780 | 0.0724172022 | 0.0934841467 | 0.7210712375 | 0.0865484107 |
| DoS | BrowserHijacking | MD-Pred | 0.0500130780 | 0.0506673258 | 0.1156639075 | 0.5720192851 | 0.0620765512 |
| DoS | BrowserHijacking | Min-MD | 0.0500130780 | 0.0479485912 | 0.1158797694 | 0.5562984098 | 0.0608263574 |
| DoS | BrowserHijacking | MDS | 0.0500130780 | 0.0380622837 | 0.1165432099 | 0.5370438322 | 0.0557088343 |
| DoS | BrowserHijacking | ClassConditionalKNN | 0.0500130780 | 0.3183391003 | 0.1012317811 | 0.8305067313 | 0.2519710438 |
| DoS | BrowserHijacking | GlobalKNN | 0.0500130780 | 0.1816608997 | 0.1085468549 | 0.7467592133 | 0.1403212248 |
| DoS | DDoS-ICMP_Fragmentation | MSP | 0.0500116211 | 0.0000000000 | 0.0611201847 | 0.3639930750 | 0.0163823930 |
| DoS | DDoS-ICMP_Fragmentation | Entropy | 0.0500116211 | 0.0000000000 | 0.0646682811 | 0.3636347064 | 0.0157511873 |
| DoS | DDoS-ICMP_Fragmentation | MD-Pred | 0.0500116211 | 0.9857050032 | 0.0656336772 | 0.9876835480 | 0.4497421108 |
| DoS | DDoS-ICMP_Fragmentation | Min-MD | 0.0500116211 | 0.9837556855 | 0.0657171630 | 0.9828784752 | 0.3630327311 |
| DoS | DDoS-ICMP_Fragmentation | MDS | 0.0500116211 | 0.0233918129 | 0.0854088015 | 0.9266518842 | 0.1165445023 |
| DoS | DDoS-ICMP_Fragmentation | ClassConditionalKNN | 0.0500116211 | 0.9993502274 | 0.0646029416 | 0.9987356072 | 0.8656926653 |
| DoS | DDoS-ICMP_Fragmentation | GlobalKNN | 0.0500116211 | 0.9993502274 | 0.0648332038 | 0.9993592443 | 0.9249223483 |
| DoS | Mirai-udpplain | MSP | 0.0500050922 | 0.0000000000 | 0.2982785779 | 0.1851673734 | 0.2100879646 |
| DoS | Mirai-udpplain | Entropy | 0.0500050922 | 0.0000000000 | 0.3005063006 | 0.2038519341 | 0.1665081404 |
| DoS | Mirai-udpplain | MD-Pred | 0.0500050922 | 1.0000000000 | 0.0699277138 | 0.9970689977 | 0.9603870838 |
| DoS | Mirai-udpplain | Min-MD | 0.0500050922 | 0.0072930801 | 0.3154732380 | 0.9313349983 | 0.6456909797 |
| DoS | Mirai-udpplain | MDS | 0.0500050922 | 0.9928765265 | 0.0727880973 | 0.9805364059 | 0.8451251467 |
| DoS | Mirai-udpplain | ClassConditionalKNN | 0.0500050922 | 1.0000000000 | 0.0690853957 | 0.9961435425 | 0.9774022885 |
| DoS | Mirai-udpplain | GlobalKNN | 0.0500050922 | 0.9980919267 | 0.0698642506 | 0.9959099199 | 0.9803425258 |
| Mirai | DDoS-ACK_Fragmentation | MSP | 0.0500104976 | 0.0000000000 | 0.1166435145 | 0.1991039852 | 0.0103320106 |
| Mirai | DDoS-ACK_Fragmentation | Entropy | 0.0500104976 | 0.0000000000 | 0.1197835272 | 0.1983355155 | 0.0103265922 |
| Mirai | DDoS-ACK_Fragmentation | MD-Pred | 0.0500104976 | 0.9967637540 | 0.1266721669 | 0.9874324763 | 0.3818422072 |
| Mirai | DDoS-ACK_Fragmentation | Min-MD | 0.0500104976 | 0.9967637540 | 0.1268342271 | 0.9875674727 | 0.3891647987 |
| Mirai | DDoS-ACK_Fragmentation | MDS | 0.0500104976 | 0.9951456311 | 0.1270809393 | 0.9847996660 | 0.3379144650 |
| Mirai | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500104976 | 1.0000000000 | 0.1253388732 | 0.9985057304 | 0.8074019701 |
| Mirai | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500104976 | 1.0000000000 | 0.1254125413 | 0.9991742579 | 0.8826316242 |
| Mirai | DoS-HTTP_Flood | MSP | 0.0500048997 | 0.0000000000 | 0.1188293473 | 0.3427739130 | 0.0128618448 |
| Mirai | DoS-HTTP_Flood | Entropy | 0.0500048997 | 0.0000000000 | 0.1214465427 | 0.3337610138 | 0.0127881925 |
| Mirai | DoS-HTTP_Flood | MD-Pred | 0.0500048997 | 0.8388589052 | 0.1316292052 | 0.9743689060 | 0.3728164450 |
| Mirai | DoS-HTTP_Flood | Min-MD | 0.0500048997 | 0.8111025443 | 0.1322790944 | 0.9699538690 | 0.3350439883 |
| Mirai | DoS-HTTP_Flood | MDS | 0.0500048997 | 0.7632999229 | 0.1331563197 | 0.9676522692 | 0.3058912065 |
| Mirai | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500048997 | 0.9614494988 | 0.1284475269 | 0.9913112881 | 0.7156666505 |
| Mirai | DoS-HTTP_Flood | GlobalKNN | 0.0500048997 | 0.8450269854 | 0.1305427404 | 0.9801629492 | 0.5529382890 |
| Mirai | Recon-HostDiscovery | MSP | 0.0500007249 | 0.1219404306 | 0.2382102273 | 0.4420574928 | 0.1942097959 |
| Mirai | Recon-HostDiscovery | Entropy | 0.0500007249 | 0.1114715423 | 0.2427109381 | 0.4555812301 | 0.2006633493 |
| Mirai | Recon-HostDiscovery | MD-Pred | 0.0500007249 | 0.1214980832 | 0.2603233221 | 0.7107758958 | 0.2920072235 |
| Mirai | Recon-HostDiscovery | Min-MD | 0.0500007249 | 0.1231937482 | 0.2602973277 | 0.7060399034 | 0.2954777961 |
| Mirai | Recon-HostDiscovery | MDS | 0.0500007249 | 0.1580654674 | 0.2556985055 | 0.7169360444 | 0.3169668385 |
| Mirai | Recon-HostDiscovery | ClassConditionalKNN | 0.0500007249 | 0.0751990563 | 0.2655685632 | 0.7012476004 | 0.2464169127 |
| Mirai | Recon-HostDiscovery | GlobalKNN | 0.0500007249 | 0.0816130935 | 0.2648903022 | 0.7147453489 | 0.2551538226 |
| Mirai | DNS_Spoofing | MSP | 0.0500000000 | 0.0621870269 | 0.3537861100 | 0.2952811098 | 0.2204186452 |
| Mirai | DNS_Spoofing | Entropy | 0.0500000000 | 0.0643996739 | 0.3559067743 | 0.3015841526 | 0.2259950344 |
| Mirai | DNS_Spoofing | MD-Pred | 0.0500000000 | 0.0338107993 | 0.3777964428 | 0.5681878713 | 0.3020617944 |
| Mirai | DNS_Spoofing | Min-MD | 0.0500000000 | 0.0211560110 | 0.3802372525 | 0.5665756570 | 0.2964324691 |
| Mirai | DNS_Spoofing | MDS | 0.0500000000 | 0.0308994216 | 0.3785071106 | 0.6047331639 | 0.3207962138 |
| Mirai | DNS_Spoofing | ClassConditionalKNN | 0.0500000000 | 0.2316680253 | 0.3379514734 | 0.7209488429 | 0.5144670080 |
| Mirai | DNS_Spoofing | GlobalKNN | 0.0500000000 | 0.0738713559 | 0.3696868073 | 0.6576373011 | 0.3556431257 |
| Mirai | Backdoor_Malware | MSP | 0.0500049121 | 0.0460136674 | 0.1284105239 | 0.6173590709 | 0.0364982369 |
| Mirai | Backdoor_Malware | Entropy | 0.0500049121 | 0.0610478360 | 0.1306791300 | 0.6712665737 | 0.0454880708 |
| Mirai | Backdoor_Malware | MD-Pred | 0.0500049121 | 0.0164009112 | 0.1549342152 | 0.5104353069 | 0.0284017260 |
| Mirai | Backdoor_Malware | Min-MD | 0.0500049121 | 0.0164009112 | 0.1550773812 | 0.5127451741 | 0.0287427757 |
| Mirai | Backdoor_Malware | MDS | 0.0500049121 | 0.0164009112 | 0.1551203310 | 0.5251817523 | 0.0296673478 |
| Mirai | Backdoor_Malware | ClassConditionalKNN | 0.0500049121 | 0.0879271071 | 0.1516242897 | 0.7628359811 | 0.0611319929 |
| Mirai | Backdoor_Malware | GlobalKNN | 0.0500049121 | 0.0656036446 | 0.1524641172 | 0.7189265036 | 0.0506932596 |
| Mirai | DDoS-ICMP_Flood | MSP | 0.0500036266 | 0.0000000000 | 0.2611542100 | 0.0356187276 | 0.0932192941 |
| Mirai | DDoS-ICMP_Flood | Entropy | 0.0500036266 | 0.0000000000 | 0.2636770735 | 0.0345707948 | 0.0913364863 |
| Mirai | DDoS-ICMP_Flood | MD-Pred | 0.0500036266 | 0.9992021470 | 0.1326585139 | 0.9974944151 | 0.9486212742 |
| Mirai | DDoS-ICMP_Flood | Min-MD | 0.0500036266 | 0.9992021470 | 0.1328417228 | 0.9976925882 | 0.9519329463 |
| Mirai | DDoS-ICMP_Flood | MDS | 0.0500036266 | 0.9992746790 | 0.1329200892 | 0.9991451135 | 0.9796811648 |
| Mirai | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500181330 | 0.9999274679 | 0.1313523088 | 0.9996903021 | 0.9971578672 |
| Mirai | DDoS-ICMP_Flood | GlobalKNN | 0.0500036266 | 1.0000000000 | 0.1311385292 | 0.9996672467 | 0.9962611621 |
| Mirai | DoS-SYN_Flood | MSP | 0.0500123829 | 0.0000000000 | 0.2734481816 | 0.6367421911 | 0.2273039423 |
| Mirai | DoS-SYN_Flood | Entropy | 0.0500123829 | 0.0000000000 | 0.2756979143 | 0.5527429268 | 0.1817847625 |
| Mirai | DoS-SYN_Flood | MD-Pred | 0.0500123829 | 0.1935187615 | 0.2663991536 | 0.8971931160 | 0.4988898706 |
| Mirai | DoS-SYN_Flood | Min-MD | 0.0500123829 | 0.0606796117 | 0.2864489683 | 0.7827376653 | 0.3197310170 |
| Mirai | DoS-SYN_Flood | MDS | 0.0500123829 | 0.0553004461 | 0.2873723480 | 0.7680352649 | 0.3078093421 |
| Mirai | DoS-SYN_Flood | ClassConditionalKNN | 0.0500123829 | 0.8775255838 | 0.1397945645 | 0.8855883459 | 0.7748199163 |
| Mirai | DoS-SYN_Flood | GlobalKNN | 0.0500123829 | 0.0587772238 | 0.2857789286 | 0.3453107298 | 0.1549903450 |
| Mirai | Recon-OSScan | MSP | 0.0500014356 | 0.0993801043 | 0.2050631903 | 0.5969934632 | 0.1749895019 |
| Mirai | Recon-OSScan | Entropy | 0.0500014356 | 0.0981009544 | 0.2075894931 | 0.6224327069 | 0.1895988212 |
| Mirai | Recon-OSScan | MD-Pred | 0.0500014356 | 0.1569418479 | 0.2221077559 | 0.5573512191 | 0.1703464700 |
| Mirai | Recon-OSScan | Min-MD | 0.0500014356 | 0.1602873167 | 0.2218875905 | 0.5568884967 | 0.1710014016 |
| Mirai | Recon-OSScan | MDS | 0.0500014356 | 0.1627472203 | 0.2216539018 | 0.5553363879 | 0.1790769955 |
| Mirai | Recon-OSScan | ClassConditionalKNN | 0.0500014356 | 0.0924923743 | 0.2277381363 | 0.6673407966 | 0.1934169987 |
| Mirai | Recon-OSScan | GlobalKNN | 0.0500014356 | 0.1011512349 | 0.2270216439 | 0.6723456123 | 0.1985214560 |
| Mirai | MITM-ArpSpoofing | MSP | 0.0500063199 | 0.0409494560 | 0.4649935265 | 0.3174103589 | 0.3123848817 |
| Mirai | MITM-ArpSpoofing | Entropy | 0.0500063199 | 0.0497107349 | 0.4652545931 | 0.3302326376 | 0.3251521500 |
| Mirai | MITM-ArpSpoofing | MD-Pred | 0.0500063199 | 0.1434421351 | 0.4571666407 | 0.6226956884 | 0.5096585552 |
| Mirai | MITM-ArpSpoofing | Min-MD | 0.0500063199 | 0.1345618170 | 0.4593689753 | 0.5876363629 | 0.4846575600 |
| Mirai | MITM-ArpSpoofing | MDS | 0.0500063199 | 0.1365378663 | 0.4588516002 | 0.6073446811 | 0.4973262011 |
| Mirai | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500063199 | 0.1346332405 | 0.4585643949 | 0.6780215725 | 0.5571604666 |
| Mirai | MITM-ArpSpoofing | GlobalKNN | 0.0500063199 | 0.1170154513 | 0.4628503832 | 0.6615856793 | 0.5118245113 |
| Mirai | BrowserHijacking | MSP | 0.0500119916 | 0.0610479486 | 0.1504702194 | 0.5873552889 | 0.0642661197 |
| Mirai | BrowserHijacking | Entropy | 0.0500119916 | 0.0830449827 | 0.1517987839 | 0.6255173433 | 0.0767207197 |
| Mirai | BrowserHijacking | MD-Pred | 0.0500119916 | 0.0491843796 | 0.1767366721 | 0.5795051147 | 0.0656501055 |
| Mirai | BrowserHijacking | Min-MD | 0.0500119916 | 0.0533860603 | 0.1766664793 | 0.5726160044 | 0.0648554835 |
| Mirai | BrowserHijacking | MDS | 0.0500119916 | 0.0439940682 | 0.1772603432 | 0.5763147362 | 0.0658033331 |
| Mirai | BrowserHijacking | ClassConditionalKNN | 0.0500119916 | 0.3217993080 | 0.1620815616 | 0.8332353938 | 0.2584440641 |
| Mirai | BrowserHijacking | GlobalKNN | 0.0500119916 | 0.1851211073 | 0.1691937425 | 0.7628234960 | 0.1512583489 |
| Mirai | DDoS-ICMP_Fragmentation | MSP | 0.0500105064 | 0.0000000000 | 0.1233814921 | 0.0558007188 | 0.0113777357 |
| Mirai | DDoS-ICMP_Fragmentation | Entropy | 0.0500105064 | 0.0000000000 | 0.1263805981 | 0.0562462478 | 0.0110129134 |
| Mirai | DDoS-ICMP_Fragmentation | MD-Pred | 0.0500105064 | 0.9876543210 | 0.1303181296 | 0.9902081361 | 0.5097553457 |
| Mirai | DDoS-ICMP_Fragmentation | Min-MD | 0.0500105064 | 0.9863547758 | 0.1305796332 | 0.9905904447 | 0.5233505746 |
| Mirai | DDoS-ICMP_Fragmentation | MDS | 0.0500105064 | 0.9863547758 | 0.1306238575 | 0.9887351453 | 0.4689132910 |
| Mirai | DDoS-ICMP_Fragmentation | ClassConditionalKNN | 0.0500105064 | 0.9993502274 | 0.1293352601 | 0.9993187514 | 0.9209597150 |
| Mirai | DDoS-ICMP_Fragmentation | GlobalKNN | 0.0500105064 | 1.0000000000 | 0.1293224213 | 0.9995018547 | 0.9373709174 |
| Mirai | DoS-TCP_Flood | MSP | 0.0500059039 | 0.0000000000 | 0.3149542605 | 0.5462660241 | 0.2173269221 |
| Mirai | DoS-TCP_Flood | Entropy | 0.0500059039 | 0.0000000000 | 0.3169765533 | 0.4935286017 | 0.2018476926 |
| Mirai | DoS-TCP_Flood | MD-Pred | 0.0500059039 | 0.1549824864 | 0.3090235773 | 0.9204223221 | 0.5849125333 |
| Mirai | DoS-TCP_Flood | Min-MD | 0.0500059039 | 0.0129955835 | 0.3336236830 | 0.8633450653 | 0.4641491800 |
| Mirai | DoS-TCP_Flood | MDS | 0.0500059039 | 0.0695974415 | 0.3237314371 | 0.8847185596 | 0.5031533948 |
| Mirai | DoS-TCP_Flood | ClassConditionalKNN | 0.0500059039 | 0.9711660490 | 0.1272716072 | 0.9678398361 | 0.9247744439 |
| Mirai | DoS-TCP_Flood | GlobalKNN | 0.0500206636 | 0.0254327631 | 0.3305728749 | 0.2382205983 | 0.1636809490 |
| Recon | DDoS-ACK_Fragmentation | MSP | 0.0500013990 | 0.0000000000 | 0.0651721146 | 0.3798891806 | 0.0132315239 |
| Recon | DDoS-ACK_Fragmentation | Entropy | 0.0500013990 | 0.0000000000 | 0.0721000868 | 0.3807673900 | 0.0132546404 |
| Recon | DDoS-ACK_Fragmentation | MD-Pred | 0.0500013990 | 0.9911003236 | 0.0694986380 | 0.9778444174 | 0.2599749937 |
| Recon | DDoS-ACK_Fragmentation | Min-MD | 0.0500013990 | 0.9166666667 | 0.0707868308 | 0.9632900036 | 0.1761593197 |
| Recon | DDoS-ACK_Fragmentation | MDS | 0.0500013990 | 0.0760517799 | 0.0848709556 | 0.9411264298 | 0.1185852769 |
| Recon | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500013990 | 1.0000000000 | 0.0693037229 | 0.9927213895 | 0.4867026276 |
| Recon | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500013990 | 1.0000000000 | 0.0694951697 | 0.9953962683 | 0.5914667567 |
| Recon | DoS-HTTP_Flood | MSP | 0.0500230876 | 0.0000000000 | 0.0655595543 | 0.5270343137 | 0.0172322585 |
| Recon | DoS-HTTP_Flood | Entropy | 0.0500090951 | 0.0000000000 | 0.0735366382 | 0.5190605681 | 0.0170673196 |
| Recon | DoS-HTTP_Flood | MD-Pred | 0.0500090951 | 0.8326908250 | 0.0732051094 | 0.9703626172 | 0.2554194469 |
| Recon | DoS-HTTP_Flood | Min-MD | 0.0500090951 | 0.8234387047 | 0.0733390094 | 0.9685624970 | 0.2357282829 |
| Recon | DoS-HTTP_Flood | MDS | 0.0500090951 | 0.8658442560 | 0.0725461677 | 0.9701287369 | 0.2265254453 |
| Recon | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500090951 | 0.9128758674 | 0.0715966238 | 0.9844880987 | 0.4344607533 |
| Recon | DoS-HTTP_Flood | GlobalKNN | 0.0500090951 | 0.8604471858 | 0.0725680877 | 0.9757587596 | 0.3115289877 |
| Recon | Mirai-greeth_flood | MSP | 0.0500127891 | 0.0000000000 | 0.3309559210 | 0.0461565849 | 0.2499588445 |
| Recon | Mirai-greeth_flood | Entropy | 0.0500127891 | 0.0000000000 | 0.3361765396 | 0.0498813093 | 0.1630372241 |
| Recon | Mirai-greeth_flood | MD-Pred | 0.0500127891 | 0.0101086874 | 0.3446354289 | 0.3929253608 | 0.2242014755 |
| Recon | Mirai-greeth_flood | Min-MD | 0.0500127891 | 0.0073725013 | 0.3451080563 | 0.4514360527 | 0.2403944779 |
| Recon | Mirai-greeth_flood | MDS | 0.0500127891 | 0.0105267158 | 0.3445770162 | 0.3475484593 | 0.2142782716 |
| Recon | Mirai-greeth_flood | ClassConditionalKNN | 0.0500127891 | 0.0109827468 | 0.3445448836 | 0.5012907270 | 0.2596793240 |
| Recon | Mirai-greeth_flood | GlobalKNN | 0.0500127891 | 0.0121988295 | 0.3442983440 | 0.5047307211 | 0.2606530917 |
| Recon | DNS_Spoofing | MSP | 0.0500045063 | 0.0722798028 | 0.3087189020 | 0.4376694269 | 0.2670887053 |
| Recon | DNS_Spoofing | Entropy | 0.0500045063 | 0.0983657467 | 0.3101235082 | 0.4422559594 | 0.2790185938 |
| Recon | DNS_Spoofing | MD-Pred | 0.0500045063 | 0.0841970420 | 0.3217522485 | 0.6975990373 | 0.4029809510 |
| Recon | DNS_Spoofing | Min-MD | 0.0500045063 | 0.0812856644 | 0.3223260309 | 0.6898688612 | 0.3956569319 |
| Recon | DNS_Spoofing | MDS | 0.0500045063 | 0.0847793176 | 0.3216120338 | 0.6959543907 | 0.4066936676 |
| Recon | DNS_Spoofing | ClassConditionalKNN | 0.0500045063 | 0.2921082256 | 0.2768375449 | 0.8144325069 | 0.5949696778 |
| Recon | DNS_Spoofing | GlobalKNN | 0.0500045063 | 0.1321377276 | 0.3121305577 | 0.7730179295 | 0.4754814412 |
| Recon | Backdoor_Malware | MSP | 0.0500245493 | 0.0482915718 | 0.0776845061 | 0.6851057172 | 0.0432559666 |
| Recon | Backdoor_Malware | Entropy | 0.0500105211 | 0.1161731207 | 0.0828165375 | 0.7155671058 | 0.0535694518 |
| Recon | Backdoor_Malware | MD-Pred | 0.0500105211 | 0.0669703872 | 0.0987128770 | 0.6356521282 | 0.0559457440 |
| Recon | Backdoor_Malware | Min-MD | 0.0500105211 | 0.0751708428 | 0.0984659498 | 0.6285173299 | 0.0558285773 |
| Recon | Backdoor_Malware | MDS | 0.0500105211 | 0.0756264237 | 0.0984960358 | 0.6173601650 | 0.0499286592 |
| Recon | Backdoor_Malware | ClassConditionalKNN | 0.0500105211 | 0.1412300683 | 0.0964011206 | 0.8271735437 | 0.1058242745 |
| Recon | Backdoor_Malware | GlobalKNN | 0.0500105211 | 0.1230068337 | 0.0970206045 | 0.8010818360 | 0.0779992361 |
| Recon | DDoS-ICMP_Flood | MSP | 0.0501261491 | 0.0000000000 | 0.2153954802 | 0.2232207267 | 0.1100657872 |
| Recon | DDoS-ICMP_Flood | Entropy | 0.0500101499 | 0.0000000000 | 0.2213885807 | 0.2227113246 | 0.1090597008 |
| Recon | DDoS-ICMP_Flood | MD-Pred | 0.0500101499 | 0.9994197432 | 0.0726592903 | 0.9904002994 | 0.8534904313 |
| Recon | DDoS-ICMP_Flood | Min-MD | 0.0500101499 | 0.9994922753 | 0.0726146145 | 0.9906959766 | 0.8566849314 |
| Recon | DDoS-ICMP_Flood | MDS | 0.0500101499 | 0.9994922753 | 0.0726909224 | 0.9937260432 | 0.8923494791 |
| Recon | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500101499 | 0.9999274679 | 0.0722702158 | 0.9966717175 | 0.9358380997 |
| Recon | DDoS-ICMP_Flood | GlobalKNN | 0.0500101499 | 0.9999274679 | 0.0722549528 | 0.9981748869 | 0.9619701666 |
| Recon | DoS-SYN_Flood | MSP | 0.0500036403 | 0.1929283653 | 0.1954632209 | 0.7867468063 | 0.3714459848 |
| Recon | DoS-SYN_Flood | Entropy | 0.0500036403 | 0.0000000000 | 0.2314468535 | 0.7481983399 | 0.2931895984 |
| Recon | DoS-SYN_Flood | MD-Pred | 0.0500036403 | 0.1034505379 | 0.2278222740 | 0.8826144220 | 0.4585567454 |
| Recon | DoS-SYN_Flood | Min-MD | 0.0500036403 | 0.0659931776 | 0.2336088778 | 0.7802190424 | 0.3158078351 |
| Recon | DoS-SYN_Flood | MDS | 0.0500036403 | 0.0730123327 | 0.2325631205 | 0.7932115133 | 0.3312408154 |
| Recon | DoS-SYN_Flood | ClassConditionalKNN | 0.0500036403 | 0.8684728418 | 0.0817892514 | 0.8900674188 | 0.6736777060 |
| Recon | DoS-SYN_Flood | GlobalKNN | 0.0500036403 | 0.0671739701 | 0.2332464983 | 0.4763537532 | 0.1729251373 |
| Recon | Mirai-greip_flood | MSP | 0.0504837161 | 0.0000000000 | 0.2762089846 | 0.0353186795 | 0.1698429951 |
| Recon | Mirai-greip_flood | Entropy | 0.0500110775 | 0.0000000000 | 0.2818848391 | 0.0301184952 | 0.1256141643 |
| Recon | Mirai-greip_flood | MD-Pred | 0.0500110775 | 0.0098995125 | 0.2918477357 | 0.1985147890 | 0.1443376953 |
| Recon | Mirai-greip_flood | Min-MD | 0.0500110775 | 0.0055218386 | 0.2925631598 | 0.2351889809 | 0.1493578578 |
| Recon | Mirai-greip_flood | MDS | 0.0500110775 | 0.0110436772 | 0.2917018017 | 0.1343338002 | 0.1357118181 |
| Recon | Mirai-greip_flood | ClassConditionalKNN | 0.0500110775 | 0.0189035917 | 0.2901202984 | 0.5241105904 | 0.2183091994 |
| Recon | Mirai-greip_flood | GlobalKNN | 0.0500110775 | 0.0221868471 | 0.2896338196 | 0.5292701139 | 0.2196753486 |
| Recon | MITM-ArpSpoofing | MSP | 0.0500126334 | 0.0568768897 | 0.4255244510 | 0.4670030476 | 0.3767384152 |
| Recon | MITM-ArpSpoofing | Entropy | 0.0500126334 | 0.0834702283 | 0.4244936850 | 0.4748293663 | 0.3930194904 |
| Recon | MITM-ArpSpoofing | MD-Pred | 0.0500126334 | 0.2081756065 | 0.3993427250 | 0.7445538867 | 0.6133170539 |
| Recon | MITM-ArpSpoofing | Min-MD | 0.0500126334 | 0.2108896984 | 0.3986516902 | 0.7184303064 | 0.5940456595 |
| Recon | MITM-ArpSpoofing | MDS | 0.0500126334 | 0.1952955741 | 0.4028544973 | 0.7128649123 | 0.5905150355 |
| Recon | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500126334 | 0.2025807680 | 0.4009460657 | 0.7924310559 | 0.6643178236 |
| Recon | MITM-ArpSpoofing | GlobalKNN | 0.0500126334 | 0.1758207747 | 0.4082933263 | 0.7841729830 | 0.6321934986 |
| Recon | BrowserHijacking | MSP | 0.0500021151 | 0.0580820564 | 0.0993228625 | 0.6653948625 | 0.0755578554 |
| Recon | BrowserHijacking | Entropy | 0.0500021151 | 0.1280276817 | 0.1030621024 | 0.6928866305 | 0.0930001299 |
| Recon | BrowserHijacking | MD-Pred | 0.0500021151 | 0.0874938211 | 0.1183738373 | 0.6934675628 | 0.0923600640 |
| Recon | BrowserHijacking | Min-MD | 0.0500021151 | 0.0961443401 | 0.1179112463 | 0.6812041753 | 0.0913281939 |
| Recon | BrowserHijacking | MDS | 0.0500021151 | 0.0837864558 | 0.1185880301 | 0.6595610635 | 0.0854612904 |
| Recon | BrowserHijacking | ClassConditionalKNN | 0.0500021151 | 0.3685121107 | 0.1036238309 | 0.8860974305 | 0.2715390836 |
| Recon | BrowserHijacking | GlobalKNN | 0.0500021151 | 0.2372713791 | 0.1106348553 | 0.8417911679 | 0.1861435758 |
| Recon | DDoS-ICMP_Fragmentation | MSP | 0.0500007001 | 0.0000000000 | 0.0679810339 | 0.2214366933 | 0.0133304052 |
| Recon | DDoS-ICMP_Fragmentation | Entropy | 0.0500007001 | 0.0000000000 | 0.0751725828 | 0.2242255277 | 0.0130983166 |
| Recon | DDoS-ICMP_Fragmentation | MD-Pred | 0.0500007001 | 0.9766081871 | 0.0687643627 | 0.9777136530 | 0.3111052948 |
| Recon | DDoS-ICMP_Fragmentation | Min-MD | 0.0500007001 | 0.9343729695 | 0.0695963149 | 0.9657586800 | 0.2244919351 |
| Recon | DDoS-ICMP_Fragmentation | MDS | 0.0500007001 | 0.2703053931 | 0.0834698641 | 0.9458105372 | 0.1536850724 |
| Recon | DDoS-ICMP_Fragmentation | ClassConditionalKNN | 0.0500007001 | 0.9993502274 | 0.0681218588 | 0.9962609441 | 0.6798532343 |
| Recon | DDoS-ICMP_Fragmentation | GlobalKNN | 0.0500007001 | 1.0000000000 | 0.0682849900 | 0.9978385707 | 0.7762369548 |
| Recon | DoS-TCP_Flood | MSP | 0.0500103266 | 0.0140108635 | 0.2699030053 | 0.7286688812 | 0.3155505379 |
| Recon | DoS-TCP_Flood | Entropy | 0.0500103266 | 0.0000000000 | 0.2776383852 | 0.7010265501 | 0.2938093043 |
| Recon | DoS-TCP_Flood | MD-Pred | 0.0500103266 | 0.1134067719 | 0.2687971073 | 0.9148947741 | 0.5716942414 |
| Recon | DoS-TCP_Flood | Min-MD | 0.0500103266 | 0.0222853952 | 0.2854666730 | 0.8667296596 | 0.4720917646 |
| Recon | DoS-TCP_Flood | MDS | 0.0500103266 | 0.1856439413 | 0.2556254507 | 0.9039396355 | 0.5483633642 |
| Recon | DoS-TCP_Flood | ClassConditionalKNN | 0.0500103266 | 0.9673587492 | 0.0695121389 | 0.9664962686 | 0.8732595093 |
| Recon | DoS-TCP_Flood | GlobalKNN | 0.0500103266 | 0.0289862430 | 0.2841937647 | 0.4060882786 | 0.1812645706 |
| Spoofing | DDoS-ACK_Fragmentation | MSP | 0.0500055639 | 0.0000000000 | 0.0970905901 | 0.3272725465 | 0.0123933495 |
| Spoofing | DDoS-ACK_Fragmentation | Entropy | 0.0500055639 | 0.0000000000 | 0.1003983720 | 0.3280161387 | 0.0124044767 |
| Spoofing | DDoS-ACK_Fragmentation | MD-Pred | 0.0500055639 | 0.9959546926 | 0.1033644696 | 0.9830783572 | 0.3154406841 |
| Spoofing | DDoS-ACK_Fragmentation | Min-MD | 0.0500055639 | 0.9830097087 | 0.1033402617 | 0.9705365199 | 0.2093689386 |
| Spoofing | DDoS-ACK_Fragmentation | MDS | 0.0500055639 | 0.9409385113 | 0.1044756472 | 0.9582126471 | 0.1583507613 |
| Spoofing | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500055639 | 0.9975728155 | 0.1026500732 | 0.9972885659 | 0.7207701165 |
| Spoofing | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500055639 | 0.9983818770 | 0.1030176137 | 0.9980886468 | 0.7879995492 |
| Spoofing | DoS-HTTP_Flood | MSP | 0.0500132163 | 0.0000000000 | 0.0982711294 | 0.4073424243 | 0.0141225611 |
| Spoofing | DoS-HTTP_Flood | Entropy | 0.0500132163 | 0.0000000000 | 0.1017202478 | 0.4006796839 | 0.0140622024 |
| Spoofing | DoS-HTTP_Flood | MD-Pred | 0.0500132163 | 0.9036237471 | 0.1056701408 | 0.9781217258 | 0.3281524077 |
| Spoofing | DoS-HTTP_Flood | Min-MD | 0.0500132163 | 0.9113338473 | 0.1051739010 | 0.9766123241 | 0.3000683038 |
| Spoofing | DoS-HTTP_Flood | MDS | 0.0500132163 | 0.9545104086 | 0.1049381813 | 0.9774301540 | 0.2887353821 |
| Spoofing | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500132163 | 0.9444872783 | 0.1044208432 | 0.9895828374 | 0.6802116059 |
| Spoofing | DoS-HTTP_Flood | GlobalKNN | 0.0500132163 | 0.8296067849 | 0.1064854686 | 0.9747539723 | 0.4453360908 |
| Spoofing | Mirai-greeth_flood | MSP | 0.0500022429 | 0.0000000000 | 0.3541131034 | 0.0397336179 | 0.2163453028 |
| Spoofing | Mirai-greeth_flood | Entropy | 0.0500022429 | 0.0000000000 | 0.3563391098 | 0.0476768382 | 0.1623485418 |
| Spoofing | Mirai-greeth_flood | MD-Pred | 0.0500022429 | 0.0098426693 | 0.3683194178 | 0.4343967402 | 0.2350045247 |
| Spoofing | Mirai-greeth_flood | Min-MD | 0.0500022429 | 0.0073725013 | 0.3687216267 | 0.5025823659 | 0.2566160678 |
| Spoofing | Mirai-greeth_flood | MDS | 0.0500022429 | 0.0104507106 | 0.3680949404 | 0.4020744988 | 0.2271881916 |
| Spoofing | Mirai-greeth_flood | ClassConditionalKNN | 0.0500022429 | 0.0086645892 | 0.3681139044 | 0.5205141787 | 0.3134405187 |
| Spoofing | Mirai-greeth_flood | GlobalKNN | 0.0500022429 | 0.0098806719 | 0.3680333084 | 0.5237781130 | 0.3139309523 |
| Spoofing | Recon-HostDiscovery | MSP | 0.0500100827 | 0.1495871424 | 0.2154370298 | 0.5227968815 | 0.2198241353 |
| Spoofing | Recon-HostDiscovery | Entropy | 0.0500100827 | 0.1467856090 | 0.2186980020 | 0.5387986190 | 0.2350206959 |
| Spoofing | Recon-HostDiscovery | MD-Pred | 0.0500100827 | 0.0927455028 | 0.2423588040 | 0.7304359518 | 0.2998536771 |
| Spoofing | Recon-HostDiscovery | Min-MD | 0.0500100827 | 0.1267325273 | 0.2378179668 | 0.7253177524 | 0.3083036901 |
| Spoofing | Recon-HostDiscovery | MDS | 0.0500244865 | 0.1576968446 | 0.2338261521 | 0.7200849489 | 0.3029935060 |
| Spoofing | Recon-HostDiscovery | ClassConditionalKNN | 0.0500100827 | 0.0643615453 | 0.2452667048 | 0.7503331012 | 0.2728748226 |
| Spoofing | Recon-HostDiscovery | GlobalKNN | 0.0500100827 | 0.0694485403 | 0.2449093871 | 0.7575920872 | 0.2779566723 |
| Spoofing | Backdoor_Malware | MSP | 0.0500132495 | 0.0505694761 | 0.1069103548 | 0.6321341070 | 0.0372015009 |
| Spoofing | Backdoor_Malware | Entropy | 0.0500132495 | 0.0692482916 | 0.1094957097 | 0.6776507566 | 0.0460040344 |
| Spoofing | Backdoor_Malware | MD-Pred | 0.0500132495 | 0.0792710706 | 0.1284219231 | 0.5819323374 | 0.0404928042 |
| Spoofing | Backdoor_Malware | Min-MD | 0.0500132495 | 0.0806378132 | 0.1282277958 | 0.5867424735 | 0.0411820877 |
| Spoofing | Backdoor_Malware | MDS | 0.0500132495 | 0.0788154897 | 0.1285056390 | 0.5847115738 | 0.0397268099 |
| Spoofing | Backdoor_Malware | ClassConditionalKNN | 0.0500132495 | 0.1102505695 | 0.1268053891 | 0.7976606630 | 0.0875533874 |
| Spoofing | Backdoor_Malware | GlobalKNN | 0.0500132495 | 0.0997722096 | 0.1272345950 | 0.7789385743 | 0.0658055977 |
| Spoofing | DDoS-ICMP_Flood | MSP | 0.0500122508 | 0.0000000000 | 0.2420075282 | 0.1788425178 | 0.1058091740 |
| Spoofing | DDoS-ICMP_Flood | Entropy | 0.0500122508 | 0.0000000000 | 0.2448055207 | 0.1791960745 | 0.1037481620 |
| Spoofing | DDoS-ICMP_Flood | MD-Pred | 0.0500122508 | 0.9993472111 | 0.1070810958 | 0.9942637726 | 0.8989893138 |
| Spoofing | DDoS-ICMP_Flood | Min-MD | 0.0500122508 | 0.9993472111 | 0.1069900792 | 0.9945423882 | 0.9029651027 |
| Spoofing | DDoS-ICMP_Flood | MDS | 0.0500122508 | 0.9994197432 | 0.1071585686 | 0.9968348312 | 0.9363272032 |
| Spoofing | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500122508 | 0.9999274679 | 0.1063962132 | 0.9988632157 | 0.9856243382 |
| Spoofing | DDoS-ICMP_Flood | GlobalKNN | 0.0500122508 | 0.9997098716 | 0.1066341005 | 0.9992674439 | 0.9941600791 |
| Spoofing | DoS-SYN_Flood | MSP | 0.0500065131 | 0.0000000000 | 0.2529673591 | 0.6906191221 | 0.2642237974 |
| Spoofing | DoS-SYN_Flood | Entropy | 0.0500065131 | 0.0000000000 | 0.2553536103 | 0.6258464265 | 0.2098398756 |
| Spoofing | DoS-SYN_Flood | MD-Pred | 0.0500065131 | 0.1873524009 | 0.2430918692 | 0.8991888808 | 0.4936262095 |
| Spoofing | DoS-SYN_Flood | Min-MD | 0.0500065131 | 0.0626475991 | 0.2626337191 | 0.8140957764 | 0.3476524513 |
| Spoofing | DoS-SYN_Flood | MDS | 0.0500065131 | 0.0752427184 | 0.2609960744 | 0.8329643951 | 0.3790024837 |
| Spoofing | DoS-SYN_Flood | ClassConditionalKNN | 0.0500065131 | 0.8730648124 | 0.1134658359 | 0.8866114295 | 0.7534336282 |
| Spoofing | DoS-SYN_Flood | GlobalKNN | 0.0500065131 | 0.0536604566 | 0.2635207714 | 0.4051283938 | 0.1560958694 |
| Spoofing | Mirai-greip_flood | MSP | 0.0500007340 | 0.0000000000 | 0.3015268526 | 0.0372220581 | 0.1880430561 |
| Spoofing | Mirai-greip_flood | Entropy | 0.0500007340 | 0.0000000000 | 0.3041443141 | 0.0265455971 | 0.1249938225 |
| Spoofing | Mirai-greip_flood | MD-Pred | 0.0500007340 | 0.0107451995 | 0.3174860223 | 0.2153996473 | 0.1465420900 |
| Spoofing | Mirai-greip_flood | Min-MD | 0.0500007340 | 0.0065167645 | 0.3180175712 | 0.2500844637 | 0.1512960372 |
| Spoofing | Mirai-greip_flood | MDS | 0.0500007340 | 0.0101482440 | 0.3176537330 | 0.2314426325 | 0.1495786757 |
| Spoofing | Mirai-greip_flood | ClassConditionalKNN | 0.0500007340 | 0.0150731271 | 0.3163337751 | 0.5388927424 | 0.2287545288 |
| Spoofing | Mirai-greip_flood | GlobalKNN | 0.0500007340 | 0.0178589195 | 0.3161172682 | 0.5424325955 | 0.2294450644 |
| Spoofing | Recon-OSScan | MSP | 0.0500092715 | 0.1284069664 | 0.1830265442 | 0.6462341785 | 0.1946994033 |
| Spoofing | Recon-OSScan | Entropy | 0.0500092715 | 0.1203384827 | 0.1868918865 | 0.6691150874 | 0.2143188661 |
| Spoofing | Recon-OSScan | MD-Pred | 0.0500092715 | 0.1403128997 | 0.2015583105 | 0.6423995774 | 0.2001324021 |
| Spoofing | Recon-OSScan | Min-MD | 0.0500092715 | 0.1742595690 | 0.1978984705 | 0.6420952493 | 0.2056781814 |
| Spoofing | Recon-OSScan | MDS | 0.0500092715 | 0.1744563613 | 0.1979304183 | 0.6138963115 | 0.1950498964 |
| Spoofing | Recon-OSScan | ClassConditionalKNN | 0.0500092715 | 0.1249631014 | 0.2025194055 | 0.7294230422 | 0.2329569656 |
| Spoofing | Recon-OSScan | GlobalKNN | 0.0500092715 | 0.1222080094 | 0.2031858266 | 0.7307156764 | 0.2327181062 |
| Spoofing | BrowserHijacking | MSP | 0.0500063086 | 0.0781018290 | 0.1283883962 | 0.6159308979 | 0.0683766127 |
| Spoofing | BrowserHijacking | Entropy | 0.0500063086 | 0.0944142363 | 0.1309290474 | 0.6532631897 | 0.0843185186 |
| Spoofing | BrowserHijacking | MD-Pred | 0.0500063086 | 0.1374196738 | 0.1472478738 | 0.6591175518 | 0.0902464077 |
| Spoofing | BrowserHijacking | Min-MD | 0.0500063086 | 0.1460701928 | 0.1464777658 | 0.6565312092 | 0.0915221603 |
| Spoofing | BrowserHijacking | MDS | 0.0500063086 | 0.1490360850 | 0.1466428862 | 0.6397306298 | 0.0878221158 |
| Spoofing | BrowserHijacking | ClassConditionalKNN | 0.0500063086 | 0.3687592684 | 0.1347592366 | 0.8686331117 | 0.3097296790 |
| Spoofing | BrowserHijacking | GlobalKNN | 0.0500063086 | 0.2402372714 | 0.1418024224 | 0.8266733309 | 0.2182418810 |
| Spoofing | DDoS-ICMP_Fragmentation | MSP | 0.0500048724 | 0.0000000000 | 0.0996130696 | 0.2271919517 | 0.0134561346 |
| Spoofing | DDoS-ICMP_Fragmentation | Entropy | 0.0500048724 | 0.0000000000 | 0.1027371740 | 0.2298619369 | 0.0132543999 |
| Spoofing | DDoS-ICMP_Fragmentation | MD-Pred | 0.0500048724 | 0.9779077323 | 0.1021457342 | 0.9816167358 | 0.3668280355 |
| Spoofing | DDoS-ICMP_Fragmentation | Min-MD | 0.0500048724 | 0.9590643275 | 0.1023512532 | 0.9704169263 | 0.2540653894 |
| Spoofing | DDoS-ICMP_Fragmentation | MDS | 0.0500048724 | 0.1364522417 | 0.1189593215 | 0.9431465772 | 0.1486334037 |
| Spoofing | DDoS-ICMP_Fragmentation | ClassConditionalKNN | 0.0500048724 | 1.0000000000 | 0.1012294662 | 0.9989143652 | 0.8777790069 |
| Spoofing | DDoS-ICMP_Fragmentation | GlobalKNN | 0.0500048724 | 1.0000000000 | 0.1016104688 | 0.9991892972 | 0.9139660326 |
| Spoofing | DoS-TCP_Flood | MSP | 0.0500014663 | 0.0000000000 | 0.2978801472 | 0.6099727205 | 0.2421829343 |
| Spoofing | DoS-TCP_Flood | Entropy | 0.0500014663 | 0.0000000000 | 0.3002947199 | 0.5701995488 | 0.2265323616 |
| Spoofing | DoS-TCP_Flood | MD-Pred | 0.0500014663 | 0.1577745063 | 0.2879244031 | 0.9164066191 | 0.5733641889 |
| Spoofing | DoS-TCP_Flood | Min-MD | 0.0500014663 | 0.0693436215 | 0.3034251272 | 0.8766157127 | 0.4871487475 |
| Spoofing | DoS-TCP_Flood | MDS | 0.0500014663 | 0.1917356211 | 0.2819848842 | 0.9229616776 | 0.5990172578 |
| Spoofing | DoS-TCP_Flood | ClassConditionalKNN | 0.0500014663 | 0.9703538251 | 0.1032093251 | 0.9699984313 | 0.9210011313 |
| Spoofing | DoS-TCP_Flood | GlobalKNN | 0.0500014663 | 0.0281232550 | 0.3106287158 | 0.3568005981 | 0.1737317227 |
| BruteForce | DDoS-ACK_Fragmentation | MSP | 0.0500011959 | 0.0000000000 | 0.0978022387 | 0.3319477703 | 0.0106084443 |
| BruteForce | DDoS-ACK_Fragmentation | Entropy | 0.0500011959 | 0.0000000000 | 0.1003061743 | 0.3322442575 | 0.0106163272 |
| BruteForce | DDoS-ACK_Fragmentation | MD-Pred | 0.0500011959 | 0.9959546926 | 0.1087208278 | 0.9854182095 | 0.3136187667 |
| BruteForce | DDoS-ACK_Fragmentation | Min-MD | 0.0500011959 | 0.9822006472 | 0.1089240992 | 0.9742048154 | 0.2061740818 |
| BruteForce | DDoS-ACK_Fragmentation | MDS | 0.0500011959 | 0.5485436893 | 0.1151946997 | 0.9484173326 | 0.1137543172 |
| BruteForce | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500011959 | 0.9991909385 | 0.1075681664 | 0.9973894613 | 0.6893509002 |
| BruteForce | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500011959 | 0.9991909385 | 0.1076688738 | 0.9976647829 | 0.7184329067 |
| BruteForce | DoS-HTTP_Flood | MSP | 0.0500005982 | 0.0000000000 | 0.0990990991 | 0.4567976643 | 0.0131720520 |
| BruteForce | DoS-HTTP_Flood | Entropy | 0.0500005982 | 0.0000000000 | 0.1018873068 | 0.4489708042 | 0.0130878184 |
| BruteForce | DoS-HTTP_Flood | MD-Pred | 0.0500005982 | 0.8643022359 | 0.1110887705 | 0.9757943129 | 0.3303634692 |
| BruteForce | DoS-HTTP_Flood | Min-MD | 0.0500005982 | 0.8442559753 | 0.1114670486 | 0.9733399662 | 0.2894876872 |
| BruteForce | DoS-HTTP_Flood | MDS | 0.0500005982 | 0.9437162683 | 0.1102261145 | 0.9781172321 | 0.2783255152 |
| BruteForce | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500005982 | 0.9730146492 | 0.1084156858 | 0.9912789494 | 0.5951825843 |
| BruteForce | DoS-HTTP_Flood | GlobalKNN | 0.0500005982 | 0.8897455667 | 0.1096262399 | 0.9807639092 | 0.4042098917 |
| BruteForce | Mirai-greeth_flood | MSP | 0.0500114501 | 0.0000000000 | 0.3264346190 | 0.0354019005 | 0.2043581392 |
| BruteForce | Mirai-greeth_flood | Entropy | 0.0500114501 | 0.0000000000 | 0.3285339407 | 0.0388166407 | 0.1411824236 |
| BruteForce | Mirai-greeth_flood | MD-Pred | 0.0500114501 | 0.0099186745 | 0.3429272070 | 0.5095516610 | 0.2316042017 |
| BruteForce | Mirai-greeth_flood | Min-MD | 0.0500114501 | 0.0069544729 | 0.3434455666 | 0.5605633229 | 0.2498010005 |
| BruteForce | Mirai-greeth_flood | MDS | 0.0500114501 | 0.0105647184 | 0.3428560080 | 0.4475411418 | 0.2150671955 |
| BruteForce | Mirai-greeth_flood | ClassConditionalKNN | 0.0500114501 | 0.0093106331 | 0.3422175898 | 0.4935890711 | 0.2703467687 |
| BruteForce | Mirai-greeth_flood | GlobalKNN | 0.0500114501 | 0.0102606977 | 0.3420840987 | 0.4965773553 | 0.2703887159 |
| BruteForce | Recon-HostDiscovery | MSP | 0.0500049290 | 0.1134621056 | 0.2045130668 | 0.5215087857 | 0.1767416879 |
| BruteForce | Recon-HostDiscovery | Entropy | 0.0500049290 | 0.1105868475 | 0.2072164023 | 0.5325052663 | 0.1864688404 |
| BruteForce | Recon-HostDiscovery | MD-Pred | 0.0500049290 | 0.1571807726 | 0.2209746289 | 0.7184424390 | 0.2928448862 |
| BruteForce | Recon-HostDiscovery | Min-MD | 0.0500049290 | 0.1663963433 | 0.2198957025 | 0.7108798486 | 0.3018858854 |
| BruteForce | Recon-HostDiscovery | MDS | 0.0500049290 | 0.1576231200 | 0.2210460913 | 0.6938522068 | 0.2854357508 |
| BruteForce | Recon-HostDiscovery | ClassConditionalKNN | 0.0500049290 | 0.0934090239 | 0.2273942567 | 0.7544018190 | 0.2551038708 |
| BruteForce | Recon-HostDiscovery | GlobalKNN | 0.0500049290 | 0.0877322324 | 0.2280480172 | 0.7614495834 | 0.2588941034 |
| BruteForce | DNS_Spoofing | MSP | 0.0500044465 | 0.0807810256 | 0.3052804778 | 0.4146256685 | 0.2284660200 |
| BruteForce | DNS_Spoofing | Entropy | 0.0500044465 | 0.0900197974 | 0.3056129669 | 0.4213774955 | 0.2376418788 |
| BruteForce | DNS_Spoofing | MD-Pred | 0.0500044465 | 0.0368386320 | 0.3305887196 | 0.6072332915 | 0.2882810634 |
| BruteForce | DNS_Spoofing | Min-MD | 0.0500044465 | 0.0249602112 | 0.3326793133 | 0.5852185035 | 0.2742759882 |
| BruteForce | DNS_Spoofing | MDS | 0.0500044465 | 0.0238732968 | 0.3329964072 | 0.5741561279 | 0.2682927642 |
| BruteForce | DNS_Spoofing | ClassConditionalKNN | 0.0500044465 | 0.2449439075 | 0.2907840557 | 0.7729090210 | 0.5214064236 |
| BruteForce | DNS_Spoofing | GlobalKNN | 0.0500044465 | 0.1064011490 | 0.3174125996 | 0.7198791385 | 0.3714849999 |
| BruteForce | Backdoor_Malware | MSP | 0.0500083907 | 0.0546697039 | 0.1068007722 | 0.6773963580 | 0.0363833786 |
| BruteForce | Backdoor_Malware | Entropy | 0.0500083907 | 0.0774487472 | 0.1088965169 | 0.7167314593 | 0.0446321467 |
| BruteForce | Backdoor_Malware | MD-Pred | 0.0500083907 | 0.0145785877 | 0.1318643527 | 0.4743345227 | 0.0227258826 |
| BruteForce | Backdoor_Malware | Min-MD | 0.0500083907 | 0.0136674260 | 0.1319593707 | 0.4674610380 | 0.0224287388 |
| BruteForce | Backdoor_Malware | MDS | 0.0500083907 | 0.0109339408 | 0.1321215843 | 0.4309999172 | 0.0205765714 |
| BruteForce | Backdoor_Malware | ClassConditionalKNN | 0.0500083907 | 0.1107061503 | 0.1285865576 | 0.7889370974 | 0.0603857217 |
| BruteForce | Backdoor_Malware | GlobalKNN | 0.0500083907 | 0.0656036446 | 0.1297583174 | 0.7505228946 | 0.0485904880 |
| BruteForce | DDoS-ICMP_Flood | MSP | 0.0500073975 | 0.0000000000 | 0.2248703751 | 0.2009942443 | 0.0941031925 |
| BruteForce | DDoS-ICMP_Flood | Entropy | 0.0500073975 | 0.0000000000 | 0.2270940895 | 0.2000956245 | 0.0931237139 |
| BruteForce | DDoS-ICMP_Flood | MD-Pred | 0.0500073975 | 0.9993472111 | 0.1114701340 | 0.9965430625 | 0.9226694625 |
| BruteForce | DDoS-ICMP_Flood | Min-MD | 0.0500073975 | 0.9993472111 | 0.1115090642 | 0.9966324962 | 0.9243942277 |
| BruteForce | DDoS-ICMP_Flood | MDS | 0.0500073975 | 0.9994197432 | 0.1116792110 | 0.9985281264 | 0.9610755726 |
| BruteForce | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500073975 | 0.9999274679 | 0.1100800748 | 0.9990949147 | 0.9911103790 |
| BruteForce | DDoS-ICMP_Flood | GlobalKNN | 0.0500073975 | 0.9999274679 | 0.1102487898 | 0.9993551960 | 0.9938738180 |
| BruteForce | DoS-SYN_Flood | MSP | 0.0500024748 | 0.0000000000 | 0.2332235734 | 0.7152386992 | 0.2461894541 |
| BruteForce | DoS-SYN_Flood | Entropy | 0.0500024748 | 0.0000000000 | 0.2353318336 | 0.6513785980 | 0.1955375894 |
| BruteForce | DoS-SYN_Flood | MD-Pred | 0.0500024748 | 0.2175938074 | 0.2247525422 | 0.9196295655 | 0.5158475205 |
| BruteForce | DoS-SYN_Flood | Min-MD | 0.0500024748 | 0.0711755445 | 0.2449798755 | 0.8306780121 | 0.3384835552 |
| BruteForce | DoS-SYN_Flood | MDS | 0.0500024748 | 0.2066386775 | 0.2263443946 | 0.8575400052 | 0.3846182148 |
| BruteForce | DoS-SYN_Flood | ClassConditionalKNN | 0.0500024748 | 0.8747704015 | 0.1151059936 | 0.8908257644 | 0.7422758326 |
| BruteForce | DoS-SYN_Flood | GlobalKNN | 0.0500024748 | 0.0737339281 | 0.2436327631 | 0.4216749491 | 0.1435295018 |
| BruteForce | Mirai-greip_flood | MSP | 0.0500100195 | 0.0000000000 | 0.2793867831 | 0.0341834907 | 0.1506261539 |
| BruteForce | Mirai-greip_flood | Entropy | 0.0500100195 | 0.0000000000 | 0.2812939668 | 0.0297245533 | 0.1095075020 |
| BruteForce | Mirai-greip_flood | MD-Pred | 0.0500100195 | 0.0107949458 | 0.2974011866 | 0.2642211398 | 0.1349389277 |
| BruteForce | Mirai-greip_flood | Min-MD | 0.0500100195 | 0.0064172719 | 0.2980672900 | 0.3148005222 | 0.1426387566 |
| BruteForce | Mirai-greip_flood | MDS | 0.0500100195 | 0.0088548403 | 0.2977394936 | 0.3029301956 | 0.1417251958 |
| BruteForce | Mirai-greip_flood | ClassConditionalKNN | 0.0500100195 | 0.0175106955 | 0.2951851968 | 0.5096078047 | 0.1938650059 |
| BruteForce | Mirai-greip_flood | GlobalKNN | 0.0500100195 | 0.0184061287 | 0.2950001569 | 0.5127758936 | 0.2129847381 |
| BruteForce | Recon-OSScan | MSP | 0.0500048881 | 0.1147299026 | 0.1728212873 | 0.6572559641 | 0.1729724049 |
| BruteForce | Recon-OSScan | Entropy | 0.0500048881 | 0.1168946177 | 0.1750677507 | 0.6794831991 | 0.1919524938 |
| BruteForce | Recon-OSScan | MD-Pred | 0.0500048881 | 0.1806553183 | 0.1890620098 | 0.6015603084 | 0.1760456779 |
| BruteForce | Recon-OSScan | Min-MD | 0.0500048881 | 0.1891173866 | 0.1882160012 | 0.5954513258 | 0.1830083852 |
| BruteForce | Recon-OSScan | MDS | 0.0500048881 | 0.1840007872 | 0.1888693873 | 0.5651225484 | 0.1702004800 |
| BruteForce | Recon-OSScan | ClassConditionalKNN | 0.0500048881 | 0.1210272557 | 0.1935666240 | 0.7142843958 | 0.1999410181 |
| BruteForce | Recon-OSScan | GlobalKNN | 0.0500048881 | 0.1328347929 | 0.1924832184 | 0.7172468541 | 0.2040105460 |
| BruteForce | MITM-ArpSpoofing | MSP | 0.0500099384 | 0.0540199510 | 0.4120170518 | 0.4426012441 | 0.3204028718 |
| BruteForce | MITM-ArpSpoofing | Entropy | 0.0500099384 | 0.0677332571 | 0.4107659970 | 0.4541874457 | 0.3366968490 |
| BruteForce | MITM-ArpSpoofing | MD-Pred | 0.0500099384 | 0.1567983239 | 0.4040407813 | 0.6734743111 | 0.5057599183 |
| BruteForce | MITM-ArpSpoofing | Min-MD | 0.0500099384 | 0.1590362593 | 0.4034892631 | 0.6430785362 | 0.4831420333 |
| BruteForce | MITM-ArpSpoofing | MDS | 0.0500231896 | 0.1543937338 | 0.4045873442 | 0.6135882605 | 0.4559673699 |
| BruteForce | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500099384 | 0.1680832322 | 0.4005101562 | 0.7345743552 | 0.5730041127 |
| BruteForce | MITM-ArpSpoofing | GlobalKNN | 0.0500099384 | 0.1309668357 | 0.4093148355 | 0.7198614812 | 0.5230184350 |
| BruteForce | BrowserHijacking | MSP | 0.0500024080 | 0.0805734058 | 0.1238154025 | 0.6554378191 | 0.0652874674 |
| BruteForce | BrowserHijacking | Entropy | 0.0500024080 | 0.1045477014 | 0.1251847902 | 0.6851179217 | 0.0779924666 |
| BruteForce | BrowserHijacking | MD-Pred | 0.0500024080 | 0.0588235294 | 0.1486380288 | 0.5931384948 | 0.0599467135 |
| BruteForce | BrowserHijacking | Min-MD | 0.0500144481 | 0.0600593178 | 0.1486488120 | 0.5840639606 | 0.0582615653 |
| BruteForce | BrowserHijacking | MDS | 0.0500024080 | 0.0865051903 | 0.1476894393 | 0.5387381688 | 0.0514435155 |
| BruteForce | BrowserHijacking | ClassConditionalKNN | 0.0500024080 | 0.3764211567 | 0.1337042222 | 0.8683857927 | 0.2797018843 |
| BruteForce | BrowserHijacking | GlobalKNN | 0.0500024080 | 0.2214532872 | 0.1407504905 | 0.8105137561 | 0.1600217535 |
| Web | DDoS-ACK_Fragmentation | MSP | 0.0501878232 | 0.0000000000 | 0.0830204897 | 0.3528993899 | 0.0111472877 |
| Web | DDoS-ACK_Fragmentation | Entropy | 0.0500048785 | 0.0000000000 | 0.0863411182 | 0.3537647508 | 0.0111657545 |
| Web | DDoS-ACK_Fragmentation | MD-Pred | 0.0500048785 | 0.9951456311 | 0.0910164574 | 0.9867233475 | 0.3390978689 |
| Web | DDoS-ACK_Fragmentation | Min-MD | 0.0500048785 | 0.9805825243 | 0.0914574670 | 0.9754381772 | 0.2172900397 |
| Web | DDoS-ACK_Fragmentation | MDS | 0.0500048785 | 0.9223300971 | 0.0923347182 | 0.9586844707 | 0.1413201899 |
| Web | DDoS-ACK_Fragmentation | ClassConditionalKNN | 0.0500048785 | 0.9991909385 | 0.0899567355 | 0.9977420739 | 0.7238818792 |
| Web | DDoS-ACK_Fragmentation | GlobalKNN | 0.0500048785 | 1.0000000000 | 0.0900862733 | 0.9978965901 | 0.7499444117 |
| Web | DoS-HTTP_Flood | MSP | 0.0501585753 | 0.0000000000 | 0.0824101560 | 0.4730712476 | 0.0137911629 |
| Web | DoS-HTTP_Flood | Entropy | 0.0500000000 | 0.0000000000 | 0.0863118543 | 0.4661783258 | 0.0137090804 |
| Web | DoS-HTTP_Flood | MD-Pred | 0.0500000000 | 0.8596761758 | 0.0926943622 | 0.9768850951 | 0.3655326197 |
| Web | DoS-HTTP_Flood | Min-MD | 0.0500000000 | 0.8319198150 | 0.0932022177 | 0.9741282499 | 0.3176521131 |
| Web | DoS-HTTP_Flood | MDS | 0.0500000000 | 0.9059367772 | 0.0920349217 | 0.9760676062 | 0.2905864766 |
| Web | DoS-HTTP_Flood | ClassConditionalKNN | 0.0500000000 | 0.9082498072 | 0.0907307692 | 0.9877658635 | 0.6272845805 |
| Web | DoS-HTTP_Flood | GlobalKNN | 0.0500000000 | 0.8604471858 | 0.0915938613 | 0.9699925824 | 0.3734060555 |
| Web | Mirai-greeth_flood | MSP | 0.0500415714 | 0.0000000000 | 0.3195458477 | 0.0408030914 | 0.1972087608 |
| Web | Mirai-greeth_flood | Entropy | 0.0500025982 | 0.0000000000 | 0.3226636900 | 0.0442104739 | 0.1444606155 |
| Web | Mirai-greeth_flood | MD-Pred | 0.0500025982 | 0.0102606977 | 0.3353198012 | 0.4538843445 | 0.2174108299 |
| Web | Mirai-greeth_flood | Min-MD | 0.0500025982 | 0.0074105039 | 0.3358624025 | 0.5196423339 | 0.2377780562 |
| Web | Mirai-greeth_flood | MDS | 0.0500025982 | 0.0104507106 | 0.3353669605 | 0.3961580701 | 0.2046393141 |
| Web | Mirai-greeth_flood | ClassConditionalKNN | 0.0500025982 | 0.0085885840 | 0.3349191151 | 0.4912540214 | 0.2737201746 |
| Web | Mirai-greeth_flood | GlobalKNN | 0.0500025982 | 0.0096526564 | 0.3349632512 | 0.4939136222 | 0.2736065859 |
| Web | Recon-HostDiscovery | MSP | 0.0500100599 | 0.0956944854 | 0.1998109619 | 0.5086119598 | 0.1680632837 |
| Web | Recon-HostDiscovery | Entropy | 0.0500100599 | 0.1136832793 | 0.2008701710 | 0.5238566533 | 0.1863579047 |
| Web | Recon-HostDiscovery | MD-Pred | 0.0500100599 | 0.1587289885 | 0.2121483935 | 0.7528011246 | 0.3060947230 |
| Web | Recon-HostDiscovery | Min-MD | 0.0500100599 | 0.1618991448 | 0.2118736697 | 0.7443668653 | 0.3163945285 |
| Web | Recon-HostDiscovery | MDS | 0.0500100599 | 0.1602772044 | 0.2121076182 | 0.7347887247 | 0.3073244362 |
| Web | Recon-HostDiscovery | ClassConditionalKNN | 0.0500100599 | 0.0819817163 | 0.2206275071 | 0.7514663488 | 0.2535172277 |
| Web | Recon-HostDiscovery | GlobalKNN | 0.0500100599 | 0.0942199941 | 0.2192683843 | 0.7604121263 | 0.2617386523 |
| Web | DNS_Spoofing | MSP | 0.0500084320 | 0.0729397151 | 0.2996890253 | 0.4162959271 | 0.2297657442 |
| Web | DNS_Spoofing | Entropy | 0.0500084320 | 0.0891657933 | 0.2996607926 | 0.4232753852 | 0.2398991085 |
| Web | DNS_Spoofing | MD-Pred | 0.0500084320 | 0.0485229611 | 0.3212608576 | 0.6309876193 | 0.3103157449 |
| Web | DNS_Spoofing | Min-MD | 0.0500084320 | 0.0463491324 | 0.3216801808 | 0.6313326439 | 0.3084311238 |
| Web | DNS_Spoofing | MDS | 0.0500084320 | 0.0556655409 | 0.3201139823 | 0.6460449819 | 0.3198391137 |
| Web | DNS_Spoofing | ClassConditionalKNN | 0.0500084320 | 0.2435464462 | 0.2828654321 | 0.7741957137 | 0.5302988451 |
| Web | DNS_Spoofing | GlobalKNN | 0.0500084320 | 0.0915337138 | 0.3127748745 | 0.7212609149 | 0.3737987301 |
| Web | DDoS-ICMP_Flood | MSP | 0.0504390931 | 0.0000000000 | 0.2151579655 | 0.2078807877 | 0.0968206862 |
| Web | DDoS-ICMP_Flood | Entropy | 0.0500113233 | 0.0000000000 | 0.2180661635 | 0.2072932976 | 0.0956197601 |
| Web | DDoS-ICMP_Flood | MD-Pred | 0.0500113233 | 0.9993472111 | 0.0955029398 | 0.9973149582 | 0.9382215400 |
| Web | DDoS-ICMP_Flood | Min-MD | 0.0500113233 | 0.9994197432 | 0.0954379925 | 0.9974256317 | 0.9403616324 |
| Web | DDoS-ICMP_Flood | MDS | 0.0500113233 | 0.9994197432 | 0.0957028405 | 0.9989499573 | 0.9718984825 |
| Web | DDoS-ICMP_Flood | ClassConditionalKNN | 0.0500113233 | 0.9999274679 | 0.0944668115 | 0.9990707611 | 0.9889051207 |
| Web | DDoS-ICMP_Flood | GlobalKNN | 0.0500113233 | 0.9998549358 | 0.0944655604 | 0.9995123261 | 0.9953194681 |
| Web | DoS-SYN_Flood | MSP | 0.0500069454 | 0.0481500918 | 0.2196035169 | 0.7389680007 | 0.2792624327 |
| Web | DoS-SYN_Flood | Entropy | 0.0500069454 | 0.0000000000 | 0.2290959734 | 0.6853693285 | 0.2184437212 |
| Web | DoS-SYN_Flood | MD-Pred | 0.0500069454 | 0.2137890318 | 0.2156075859 | 0.9124345613 | 0.5029075589 |
| Web | DoS-SYN_Flood | Min-MD | 0.0500069454 | 0.0673051692 | 0.2364975908 | 0.8163900825 | 0.3287505207 |
| Web | DoS-SYN_Flood | MDS | 0.0500069454 | 0.0775387038 | 0.2351076816 | 0.8350704114 | 0.3566162200 |
| Web | DoS-SYN_Flood | ClassConditionalKNN | 0.0500069454 | 0.8729992128 | 0.1028186354 | 0.8941209572 | 0.7228656178 |
| Web | DoS-SYN_Flood | GlobalKNN | 0.0500069454 | 0.0629099974 | 0.2361083183 | 0.4434643945 | 0.1510618549 |
| Web | Mirai-greip_flood | MSP | 0.0500012785 | 0.0000000000 | 0.2692751750 | 0.0295415149 | 0.1617837083 |
| Web | Mirai-greip_flood | Entropy | 0.0500012785 | 0.0000000000 | 0.2721456641 | 0.0246231050 | 0.1109190981 |
| Web | Mirai-greip_flood | MD-Pred | 0.0500012785 | 0.0103969754 | 0.2853715499 | 0.2377645315 | 0.1339127919 |
| Web | Mirai-greip_flood | Min-MD | 0.0500012785 | 0.0056213312 | 0.2861096971 | 0.2867377678 | 0.1408901072 |
| Web | Mirai-greip_flood | MDS | 0.0500012785 | 0.0116406328 | 0.2852030794 | 0.1697434336 | 0.1259326303 |
| Web | Mirai-greip_flood | ClassConditionalKNN | 0.0500012785 | 0.0165655159 | 0.2836004932 | 0.5105169725 | 0.2186029055 |
| Web | Mirai-greip_flood | GlobalKNN | 0.0500012785 | 0.0197492787 | 0.2833042590 | 0.5148524392 | 0.2173834787 |
| Web | Recon-OSScan | MSP | 0.0500087275 | 0.1179769753 | 0.1618736716 | 0.6558462759 | 0.1758189690 |
| Web | Recon-OSScan | Entropy | 0.0500087275 | 0.1239791400 | 0.1650215046 | 0.6717716774 | 0.1925311382 |
| Web | Recon-OSScan | MD-Pred | 0.0500087275 | 0.1696349503 | 0.1769974242 | 0.6140582256 | 0.1735558810 |
| Web | Recon-OSScan | Min-MD | 0.0500087275 | 0.1742595690 | 0.1765755967 | 0.6118646342 | 0.1790530635 |
| Web | Recon-OSScan | MDS | 0.0500087275 | 0.1749483420 | 0.1764838023 | 0.5824834215 | 0.1722071626 |
| Web | Recon-OSScan | ClassConditionalKNN | 0.0500087275 | 0.1186657483 | 0.1808530628 | 0.7172662043 | 0.2058781112 |
| Web | Recon-OSScan | GlobalKNN | 0.0500087275 | 0.1218144249 | 0.1807918233 | 0.7182194015 | 0.2055034398 |
| Web | MITM-ArpSpoofing | MSP | 0.0500142201 | 0.0482346499 | 0.4079438446 | 0.4401841562 | 0.3209006684 |
| Web | MITM-ArpSpoofing | Entropy | 0.0500006771 | 0.0620669952 | 0.4074107885 | 0.4508991012 | 0.3374910908 |
| Web | MITM-ArpSpoofing | MD-Pred | 0.0500006771 | 0.1842725520 | 0.3904606838 | 0.6971016796 | 0.5329108330 |
| Web | MITM-ArpSpoofing | Min-MD | 0.0500006771 | 0.1734399924 | 0.3930291327 | 0.6678447628 | 0.5121626894 |
| Web | MITM-ArpSpoofing | MDS | 0.0500006771 | 0.1744161131 | 0.3929443639 | 0.6605946243 | 0.5057446586 |
| Web | MITM-ArpSpoofing | ClassConditionalKNN | 0.0500006771 | 0.1705830536 | 0.3932180788 | 0.7360273384 | 0.5778647369 |
| Web | MITM-ArpSpoofing | GlobalKNN | 0.0500006771 | 0.1295621741 | 0.4033624471 | 0.7268720561 | 0.5391980145 |
| Web | DDoS-ICMP_Fragmentation | MSP | 0.0500048821 | 0.0000000000 | 0.0865018772 | 0.2236896866 | 0.0117481659 |
| Web | DDoS-ICMP_Fragmentation | Entropy | 0.0500048821 | 0.0000000000 | 0.0904326354 | 0.2259786694 | 0.0115885049 |
| Web | DDoS-ICMP_Fragmentation | MD-Pred | 0.0500048821 | 0.9824561404 | 0.0915080527 | 0.9867245971 | 0.4091467773 |
| Web | DDoS-ICMP_Fragmentation | Min-MD | 0.0500048821 | 0.9740090968 | 0.0917110754 | 0.9787127470 | 0.2928862452 |
| Web | DDoS-ICMP_Fragmentation | MDS | 0.0500048821 | 0.9343729695 | 0.0924861425 | 0.9607610863 | 0.1800920790 |
| Web | DDoS-ICMP_Fragmentation | ClassConditionalKNN | 0.0500048821 | 0.9993502274 | 0.0903309523 | 0.9989133765 | 0.8653228225 |
| Web | DDoS-ICMP_Fragmentation | GlobalKNN | 0.0500048821 | 1.0000000000 | 0.0904477420 | 0.9992591441 | 0.9091674673 |
| Web | DoS-TCP_Flood | MSP | 0.0501538972 | 0.0039595919 | 0.2647431192 | 0.6704722262 | 0.2483773094 |
| Web | DoS-TCP_Flood | Entropy | 0.0500006386 | 0.0000000000 | 0.2686351413 | 0.6335702953 | 0.2297216291 |
| Web | DoS-TCP_Flood | MD-Pred | 0.0500006386 | 0.1857962333 | 0.2537849883 | 0.9279321972 | 0.5750852380 |
| Web | DoS-TCP_Flood | Min-MD | 0.0500006386 | 0.1007665364 | 0.2677039675 | 0.8839407740 | 0.4700201480 |
| Web | DoS-TCP_Flood | MDS | 0.0500006386 | 0.1908726331 | 0.2530695393 | 0.9275393579 | 0.5821236310 |
| Web | DoS-TCP_Flood | ClassConditionalKNN | 0.0500006386 | 0.9708107011 | 0.0904227644 | 0.9678728242 | 0.9198554799 |
| Web | DoS-TCP_Flood | GlobalKNN | 0.0500006386 | 0.0229960912 | 0.2797714408 | 0.2687437885 | 0.1464123647 |


# Appendix D. NOS Bootstrap and Statistics Archive

| held_out_family | metric | estimate | ci_lower | ci_upper | bootstrap_resamples |
|---|---|---|---|---|---|
| DDoS | UADR | 0.5565392088 | 0.5531939906 | 0.5597961189 | 1000 |
| DDoS | overall_selective_risk | 0.4462080514 | 0.4433005426 | 0.4490528228 | 1000 |
| DoS | UADR | 0.0406751364 | 0.0393020503 | 0.0419332983 | 1000 |
| DoS | overall_selective_risk | 0.5958442082 | 0.5934507951 | 0.5983196984 | 1000 |
| Mirai | UADR | 0.9996100000 | 0.9994900000 | 0.9997300000 | 1000 |
| Mirai | overall_selective_risk | 0.2095405006 | 0.2063627066 | 0.2124747686 | 1000 |
| Recon | UADR | 0.3230284987 | 0.3200009523 | 0.3257751180 | 1000 |
| Recon | overall_selective_risk | 0.5443115434 | 0.5418170703 | 0.5468274137 | 1000 |
| Spoofing | UADR | 0.2110819577 | 0.2084976654 | 0.2137274549 | 1000 |
| Spoofing | overall_selective_risk | 0.5959659376 | 0.5933472053 | 0.5983537074 | 1000 |
| BruteForce | UADR | 0.3942992874 | 0.3864837943 | 0.4024231860 | 1000 |
| BruteForce | overall_selective_risk | 0.2310013423 | 0.2283039781 | 0.2336188904 | 1000 |
| Web | UADR | 0.1860861104 | 0.1808957675 | 0.1910332036 | 1000 |
| Web | overall_selective_risk | 0.3104089757 | 0.3076165286 | 0.3132991015 | 1000 |

| outcome | comparison | mean_paired_difference | median_paired_difference | wins | losses | ties | wilcoxon_statistic | p_value |
|---|---|---|---|---|---|---|---|---|
| UADR | EcoConNOS vs EcoConMD | 0.0943944410 | 0.1078755449 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| UADR | EcoConNOS vs Entropy | 0.2684584525 | 0.1433855592 | 5 | 2 | 0 | 4.0000000000 | 0.1093750000 |
| UADR | EcoConNOS vs MSP | 0.2707782771 | 0.1504626149 | 6 | 1 | 0 | 3.0000000000 | 0.0781250000 |
| overall_selective_risk | EcoConNOS vs EcoConMD | -0.0393376749 | -0.0247985560 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| overall_selective_risk | EcoConNOS vs Entropy | -0.0867772040 | -0.0076611771 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |
| overall_selective_risk | EcoConNOS vs MSP | -0.0871340017 | -0.0051621699 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |


# Appendix E. Reproducibility and Integrity Notes

All metrics in narrative claims trace to saved artifacts. No model was loaded for prediction, retrained, or serialized during documentation. No threshold, feature set, split, label mapping, alpha, detector candidate, detector selection, or result artifact was changed. Parquet files were not loaded in full. Binary models were counted and related metadata inspected. Any future reproduction must occur in a separate output namespace because current artifacts are frozen.
