# Limitations

1. Single primary dataset: CICIoT2023.
2. Fresh confirmation remains within CICIoT2023.
3. LOAFO is not identical to arbitrary future zero-day threats.
4. Sampling changes natural prevalence.
5. Conflicting identical feature hashes were removed.
6. Web remains a major weakness.
7. DoS remains difficult.
8. Selected detector varies by outer training environment.
9. Fine-label pseudo-OOD may not predict future family-level OOD.
10. NOS increases analyst review.
11. Only seven outer folds with overlapping training sets exist.
12. Wilcoxon evidence with n=7 warrants caution.
13. Row bootstrap does not add independent folds.
14. No external deployment study.
15. No physical energy measurement.
16. Efficiency is not publication-verified.

The six reported comparisons (three baselines for each of UADR and overall selective risk) use unadjusted, two-sided paired Wilcoxon signed-rank tests on seven held-out families. Training sets overlap, so these family-level observations should not be described as independent replications. The NOS-versus-MD p-value is 0.03125 for each outcome; these are exploratory nominal results, not multiplicity-adjusted evidence of significance. Row-level bootstrap intervals quantify within-fold sample variability and do not resolve dependence between folds.
