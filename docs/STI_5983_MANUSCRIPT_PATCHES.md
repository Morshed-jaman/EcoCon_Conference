# STI 2026 paper #5983 — exact manuscript replacements

No editable manuscript was found. The tracked TeX files are table/figure snippets, not a document with a documentclass. Apply the text below to the authoring source; section names are intended destinations, not verified section numbers. Do not retain a numbered cross-reference until the final build confirms it.

## 11 — Dataset / experimental setup

The research pool contains 637,892 numerically valid sampled rows from 46,776,700 inventoried raw rows. Removing all 25,777 rows in 6,909 feature-hash groups with conflicting high-level family labels leaves 612,115 modeling rows (428,477 training, 91,819 calibration, and 91,819 closed-set test rows). Consistent duplicates are retained and grouped within a split.

The 637,892 rows are already numerically valid after malformed, missing, nonnumeric, and infinite-value filtering. The additional 25,777-row exclusion is for conflicting family labels, not blanket deduplication. LOAFO unknown evaluation includes all modeling rows of the held-out family; the closed-set test count is not the LOAFO unknown sample size.

## 12 — Family results and Figure 2 caption

Replace the maximum-gain sentence with:

The largest EcoCon-NOS minus EcoCon-MD UADR gain is on Recon: 0.17473110195571326, or 17.47 percentage points, followed by Mirai at 16.78 percentage points. These are absolute percentage-point gains, not relative percentage improvements.

Replace Figure 2 caption with:

Fig. 2. Family-wise unknown-attack detection rate (UADR) under the seven leave-one-attack-family-out folds at approximately 5% known-traffic rejection. EcoCon-NOS improves over EcoCon-MD on six of seven folds, with the largest gain on Recon (17.47 percentage points), followed by Mirai (16.78 percentage points), while DDoS remains a near-tie and Web continues to be a difficult unseen family.

## 13 — Abstract, introduction, results and conclusion

Use this comparison wherever macro UADR is summarized:

EcoCon-NOS achieves macro unknown-attack detection rate (UADR) 0.3873, compared with 0.2929 for EcoCon-MD, 0.1166 for MSP, and 0.1189 for entropy, at approximately 5% known rejection.

Use four decimal places for rates, or consistently use 38.73%, 29.29%, 11.66%, and 11.89%. Do not assign 0.1166 to entropy.

## 14 — Statistical analysis and limitations

The six reported comparisons (three baselines for each of UADR and overall selective risk) use unadjusted, two-sided paired Wilcoxon signed-rank tests on seven held-out families. Training sets overlap, so these family-level observations should not be described as independent replications. The NOS-versus-MD p-value is 0.03125 for each outcome; these are exploratory nominal results, not multiplicity-adjusted evidence of significance. Row-level bootstrap intervals quantify within-fold sample variability and do not resolve dependence between folds.

Differences are EcoCon-NOS minus the baseline, paired by held-out family; positive UADR differences and negative risk differences favor EcoCon-NOS. No zero differences or tied absolute differences occur in these six comparisons. The saved statistics match exact two-sided signed-rank calculations. The 1,000 row-level bootstrap replicates characterize within-fold variability conditional on the fitted models; they are not 1,000 independent family-level replications.

## 15 — Split leakage control

Hashes are computed from all 39 numerically parsed feature columns with pandas hash_pandas_object(index=False), excluding labels and provenance. No explicit rounding, standardization, or similarity tolerance is applied before hashing. Groups with more than one high-level family label are excluded entirely; consistent duplicate groups remain within a single partition. This controls exact feature-vector matches under the stored numeric representation. It does not detect near duplicates or ensure that similar flows cannot cross partitions; possible hash collisions are not separately resolved. Different fine labels within the same high-level family are not treated as family-label conflicts.

## 16 — Results: secondary within-dataset confirmation

A secondary within-CICIoT2023 confirmation evaluated 5,000 additional unknown rows for each of DDoS, DoS, Mirai, Recon, and Spoofing. The saved EcoCon-NOS UADR values were 0.6346, 0.1810, 0.9996, 0.3742, and 0.1904, respectively; corresponding EcoCon-MD values were 0.6642, 0.1780, 0.8482, 0.1928, and 0.0756. MSP values were 0, 0, 0, 0.1774, and 0.2384; entropy values were 0, 0, 0, 0.1918, and 0.2496. The sampling code excludes research-pool feature hashes and duplicates within the fresh sample. Frozen classifiers, selected detectors, calibration scores, and alpha=0.05 are reused. These results provide within-dataset confirmation for five families, not external validation or evidence of uniform improvement.

Replace the dangling limitations reference with:

The secondary fresh-sample confirmation remains within CICIoT2023 and covers five attack families; it does not establish cross-dataset, temporal, or deployment generalization.

Verification caveat for the authors (not manuscript prose): saved CSVs and generating code were checked; a new Parquet-level hash-overlap/provenance audit could not run because scientific Python dependencies were unavailable. Avoid strengthening the claim beyond the code-backed description above.

## 17 — Metrics equation and interpretation

For accepted known rows A_K and accepted unknown rows A_U, use:

R_sel = (sum over i in A_K of 1[prediction_i != label_i] + |A_U|) / (|A_K| + |A_U|).

Selective risk is (accepted misclassified known rows + accepted unknown rows) / all accepted rows. UADR is the fraction of unknown rows rejected; known rejection is the fraction of known rows rejected; coverage is the fraction of all rows accepted; analyst review rate is one minus coverage. Macro values are arithmetic means of the seven per-family fold metrics, not pooled row-weighted ratios. Both the error numerator and accepted-set denominator determine risk: rejecting correctly classified known rows can raise risk even when UADR is unchanged. An empty accepted set has undefined risk (NaN), not zero risk.

Implementation note for authors: frozen bootstrap code uses a denominator floor of one for an empty bootstrap draw; this is a computational convention, not a definition of empty-set risk. The new explicit point-estimate guard does not change saved results. Do not claim bootstrap robustness to an all-rejected evaluation set.

## 18 — Proofreading and six-page integration

If present in the external manuscript, replace “which is the mechanism adopts” with “which is the mechanism adopted” and “99.96%).DDoS” with “99.96%). DDoS”. These exact strings were not found in repository publication prose; their external occurrences are unverified.

Use “unknown-attack detection rate (UADR)”, “EcoCon-NOS”, “EcoCon-MD”, “MSP”, and “entropy” consistently. Keep one explanation per figure/table; repository method narrative was repeated six times and results additions twice, now reduced to one copy each. Retain the limitations on overlap, workload, dataset scope, and family-dependent performance. Apply the statistical paragraph once and shorten repeated results discussion to make room for the concise confirmation addition.

Remaining author action: apply these replacements to the manuscript, verify cross-references, compile, and inspect all six pages for overflow and figure readability. No page-count or visual-layout check has been claimed.
