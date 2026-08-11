## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.

## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.

## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.

## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.

## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.

## Method narrative

EcoCon-NOS uses leave-one-attack-family-out (LOAFO) evaluation. In each outer fold, one family is sealed as the true unknown. The remaining data alone provide training, inner pseudo-unknown fine-label folds, and known-only calibration. Seven frozen uncertainty candidates are compared by mean inner UADR; the winner is frozen before the outer unknown is opened. A known-only calibration threshold targets alpha=0.05. The frozen XGBoost prediction is accepted when the selected score conforms and otherwise abstained for analyst review.

**Protocol pseudocode.** For each outer family: seal it; train no models in Step 9; read the frozen classifier and candidate summaries; choose the already-recorded detector; verify the saved selection; calibrate only from the saved known calibration artifact; evaluate the saved known and unknown test outputs; aggregate family metrics without test-time tuning. This nesting prevents direct use of the real outer unknown in detector selection.


## Selection objective, calibration, and aggregation

The seven candidates represent probability, feature-distance, and neighborhood evidence. Inner pseudo-open-set validation compares them by mean UADR under the frozen known-rejection budget. Candidate choice and threshold calibration remain separate: candidate choice uses outer-training pseudo-unknown fine labels, whereas the threshold uses known-only calibration rows. At deployment, only the selected candidate is evaluated. A score beyond the calibrated boundary produces abstention; otherwise the frozen XGBoost known-family prediction is accepted. UADR is the fraction of true unknown rows rejected, coverage is the accepted fraction of all evaluated rows, and review rate is one minus coverage.

The seven outer folds are DDoS, DoS, Mirai, Recon, Spoofing, BruteForce, and Web. Macro summaries give every held-out family equal weight rather than allowing raw prevalence to dominate. Family-wise tables therefore remain essential. Paired tests use the same seven family observations. Row-level bootstrap intervals measure within-fold sampling precision but do not add independent folds.

## Leakage-prevention checklist

For every fold, the saved selection JSON is matched to the final outer result. The true held-out family is sealed during candidate selection, calibration is known-only, alpha stays at 0.05, and no test metric changes a detector or threshold. Step 9 reads frozen artifacts only: it does not refit XGBoost, rebuild detector references, change features, introduce candidates, or search operating points. Fresh confirmation reuses the frozen fold configuration and remains secondary within-dataset evidence. These controls separate development, calibration, outer testing, and confirmation.
