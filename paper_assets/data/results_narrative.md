## Results narrative

### Closed-set model selection
XGBoost was selected on development Macro-F1 and reached test Macro-F1 0.7640.

### Resource budget
The 30-feature model retained Macro-F1 0.7614, an absolute change of -0.00262 from 39 features while reducing dimensionality by 23.08%. This is not evidence of equivalent runtime or energy savings.

### Unseen-family behavior and probability uncertainty
The frozen classifier assigned at least 0.95 confidence to 99.45% of DDoS, 89.85% of DoS, and 95.29% of Mirai unknown samples. Consequently, MSP and entropy can miss confidently forced known-class predictions.

### EcoCon-MD and nested selection
EcoCon-MD raised macro UADR to 0.2929. No fixed signal dominated every family, motivating training-only pseudo-open-set detector selection. EcoCon-NOS selected MD-Pred for DDoS and ClassConditionalKNN for Mirai without opening the true outer unknown.

### Primary results
At known rejection 0.0502, EcoCon-NOS achieved macro UADR 0.3873, coverage 0.7896, review rate 0.2104, and overall selective risk 0.4190. Relative to EcoCon-MD, UADR improved by 0.0944 and risk changed by -0.0393. NOS won six of seven UADR folds against MD. Mirai reached 0.9996; Web remained weak at 0.1861.

### Rescue, confirmation, statistics, and tradeoff
Among high-confidence unknowns, Mirai rescue was 99.98%; DDoS rescue was 55.42%. Fresh confirmation is within CICIoT2023, not external validation. The paired NOS-versus-MD UADR Wilcoxon p-value is 0.03125 with only seven outer folds. NOS improves detection at the cost of a 21.04% review workload. Row-bootstrap intervals quantify sample uncertainty but do not add independent families.

### Limitations
The evidence uses one primary dataset, sampled prevalence, seven outer families, and no deployment or physical-energy validation. LOAFO is a controlled proxy for unseen-family shift, not a guarantee for arbitrary zero-day attacks.

## Family-specific results

EcoCon-NOS UADR is 0.5565 for DDoS, 0.0407 for DoS, 0.9996 for Mirai, 0.3230 for Recon, 0.2111 for Spoofing, 0.3943 for BruteForce, and 0.1861 for Web. DDoS is a small loss to MD, Spoofing is below entropy, and Web remains the clearest weakness. These values prevent a universal-superiority claim.

## Nested choice and macro comparison

The frozen map selects MD-Pred for DDoS and class-conditional kNN for the other six folds. This supports the motivation that useful uncertainty geometry varies with the outer training environment. MSP and entropy reach macro UADR 0.1166 and 0.1189; MD reaches 0.2929; Fuse reaches 0.3021; and NOS reaches 0.3873. Their similar known-rejection rates show that the gain is not caused by a radically different false-rejection allowance. NOS changes UADR by +0.0944 and overall risk by -0.0393 relative to MD.

## Workload, confirmation, and statistical scope

NOS coverage 0.7896 implies review rate 0.2104. This is a material analyst-workload cost, not a free improvement. Fresh NOS UADR is 0.6346 on DDoS, 0.1810 on DoS, 0.9996 on Mirai, 0.3742 on Recon, and 0.1904 on Spoofing, with 5,000 saved rows per eligible family. This is confirmation within CICIoT2023, not external validation. The paired NOS-versus-MD UADR and risk p-values are both 0.03125, but n=7 gives coarse resolution. Bootstrap intervals do not change the number of held-out families.

## Publication interpretation

The supported conclusion is deliberately narrow: under the frozen resource-budgeted CICIoT2023 LOAFO protocol, training-only nested detector selection improves macro unseen-family detection and selective risk relative to fixed detectors at approximately five-percent known rejection. It rescues many high-confidence unknowns, especially Mirai, while retaining serious family-dependent weaknesses and a higher review burden. The evidence does not establish state of the art, arbitrary zero-day guarantees, external generalization, production latency, energy savings, or carbon reduction.

The largest EcoCon-NOS minus EcoCon-MD UADR gain is on Recon: 0.17473110195571326, or 17.47 percentage points, followed by Mirai at 16.78 percentage points. These are absolute percentage-point gains, not relative percentage improvements.

The six reported comparisons (three baselines for each of UADR and overall selective risk) use unadjusted, two-sided paired Wilcoxon signed-rank tests on seven held-out families. Training sets overlap, so these family-level observations should not be described as independent replications. The NOS-versus-MD p-value is 0.03125 for each outcome; these are exploratory nominal results, not multiplicity-adjusted evidence of significance. Row-level bootstrap intervals quantify within-fold sample variability and do not resolve dependence between folds.
