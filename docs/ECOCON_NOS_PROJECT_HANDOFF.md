USE PROJECT ARTIFACTS AS SOURCE OF TRUTH. DO NOT REDESIGN OR RETUNE ECOCON-NOS WITHOUT EXPLICIT INSTRUCTION.

# EcoCon-NOS Project Handoff

## Project root and objective

`D:\CSE_21201016_BRAC\CON_green`. The objective is resource-budgeted selective intrusion detection when one entire attack family is absent from training. The system accepts frozen XGBoost predictions or abstains for review.

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

## Exact detector selections

| Outer held-out family | selected_detector | mean_inner_UADR | mean_inner_risk | inner_folds_used | selection_reason |
|---|---|---|---|---|---|
| DDoS | MD-Pred | 0.39028092988677204 | 0.17890369830675856 | 12 | MD-Pred selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| DoS | ClassConditionalKNN | 0.417312228198145 | 0.17898351573703639 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Mirai | ClassConditionalKNN | 0.5627614948732997 | 0.19875571331518424 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Recon | ClassConditionalKNN | 0.5651918887404866 | 0.16208896298721276 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Spoofing | ClassConditionalKNN | 0.5397898666726954 | 0.16876418102833865 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| BruteForce | ClassConditionalKNN | 0.4156929593264227 | 0.20442654830190643 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |
| Web | ClassConditionalKNN | 0.5325382849343906 | 0.18790086311307427 | 12 | ClassConditionalKNN selected by highest mean inner UADR with <=0.01 risk tie-break, then worst-fold UADR and fixed cost order. |

## Exact macro results

| method | known_rejection_rate | UADR | coverage | review_rate | overall_selective_risk |
|---|---|---|---|---|---|
| EcoConFuse | 0.0480486101 | 0.3021256821 | 0.8326903491 | 0.1673096509 | 0.4602687195 |
| EcoConMD | 0.0486029039 | 0.2929370161 | 0.8325277735 | 0.1674722265 | 0.4583777548 |
| EcoConNOS | 0.0501817236 | 0.3873314571 | 0.7896324763 | 0.2103675237 | 0.4190400799 |
| Entropy | 0.0490118995 | 0.1188730046 | 0.9291944763 | 0.0708055237 | 0.5058172838 |
| ForcedXGBoost | 0.0000000000 | 0.0000000000 | 1.0000000000 | 0.0000000000 | 0.5310883391 |
| MSP | 0.0497585186 | 0.1165531800 | 0.9304956140 | 0.0695043860 | 0.5061740816 |

## Exact outer results

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

## Fresh confirmation

| held_out_family | selected_detector | fresh_rows | MSP_UADR | Entropy_UADR | EcoConMD_UADR | EcoConNOS_UADR |
|---|---|---|---|---|---|---|
| DDoS | MD-Pred | 5000 | 0.0000000000 | 0.0000000000 | 0.6642000000 | 0.6346000000 |
| DoS | ClassConditionalKNN | 5000 | 0.0000000000 | 0.0000000000 | 0.1780000000 | 0.1810000000 |
| Mirai | ClassConditionalKNN | 5000 | 0.0000000000 | 0.0000000000 | 0.8482000000 | 0.9996000000 |
| Recon | ClassConditionalKNN | 5000 | 0.1774000000 | 0.1918000000 | 0.1928000000 | 0.3742000000 |
| Spoofing | ClassConditionalKNN | 5000 | 0.2384000000 | 0.2496000000 | 0.0756000000 | 0.1904000000 |

## Statistics

| outcome | comparison | mean_paired_difference | median_paired_difference | wins | losses | ties | wilcoxon_statistic | p_value |
|---|---|---|---|---|---|---|---|---|
| UADR | EcoConNOS vs EcoConMD | 0.0943944410 | 0.1078755449 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| UADR | EcoConNOS vs Entropy | 0.2684584525 | 0.1433855592 | 5 | 2 | 0 | 4.0000000000 | 0.1093750000 |
| UADR | EcoConNOS vs MSP | 0.2707782771 | 0.1504626149 | 6 | 1 | 0 | 3.0000000000 | 0.0781250000 |
| overall_selective_risk | EcoConNOS vs EcoConMD | -0.0393376749 | -0.0247985560 | 6 | 1 | 0 | 1.0000000000 | 0.0312500000 |
| overall_selective_risk | EcoConNOS vs Entropy | -0.0867772040 | -0.0076611771 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |
| overall_selective_risk | EcoConNOS vs MSP | -0.0871340017 | -0.0051621699 | 4 | 3 | 0 | 8.0000000000 | 0.3750000000 |

## Script inventory

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

## Frozen-method restrictions

Do not retrain XGBoost or any OOD detector; change features, budgets, mappings, alpha, thresholds, detector candidates, or selections; rerun test-driven experiments; or overwrite frozen results. Efficiency timing must remain uncited until a corrected benchmark is completed and audited.
