---
title: "Supplementary Material for EviGate-APT: A Failure-Aware Benchmark for Cross-View Evidence Binding in IIoT Network Forensics"
author:
  - "Anonymous Author(s)"
bibliography: ../references/references.bib
date: 2026-09-19
---

\sloppy

# S1. Scope

This supplement preserves the full comparison, failure, sensitivity, and worked-example analyses summarized or removed from the main text for focus and length. Frozen endpoints use the declared event splits; explicitly post-freeze diagnostics use only the alternative partitions or policies stated in their captions. No result below upgrades the post-freeze EviGate-Bind analyses to independent confirmation.

# S2. Task-level positioning

**Table S1. Task-level comparison with the closest research directions. “No” denotes a property not evaluated as an output in the cited study.**

| Direction and representative work | Trigger and evidence | Output | Reject/integrity evaluation | Reproducibility and analyst evidence |
|---|---|---|---|---|
| CICAPT traffic detection: TraCP, TIPSO-GAN [@li2026tracp; @akpaku2026tipsogan] | network flow/window | traffic class | no higher-level reject; no evidence-integrity test | public traffic benchmarks; no entity evidence |
| Multimodal IDS: Niknami et al., EMT-IDNet [@niknami2025transids; @jain2026emtidnet] | paired network/log/telemetry sample | intrusion class | missing-view analysis; no event-specific corroboration test | public benchmarks; model explanations, not ranked provenance |
| Provenance APT systems: KAIROS, TAPAS, ORTHRUS [@cheng2024kairos; @zhang2025tapas; @jiang2025orthrus] | host event/node/graph | anomaly or attack subgraph | no selective tactic label or held-out integrity test | artifacts and datasets vary; entity evidence, especially ORTHRUS |
| CTI-to-provenance mapping: KnowHow [@meng2026knowhow] | CTI plus provenance pattern | technique match | no selective reject or integrity test | reported corpus; matched provenance indicators |
| LLM-assisted APT investigation [@aly2025ocrapt; @zuo2025semanticapt; @pletzer2026attackpath] | network flow or provenance text/subgraph | anomaly, attack path, or narrative | stage validation in OCR-APT; no matched corruption suite | public datasets vary; narrative/contextualized evidence |
| **EviGate-APT (this work)** | independent network event plus union-derived provenance graph | ranked processes and optional tactic label | **explicit refusal and five held-out evidence transformations** | **public IIoT benchmark; ranked process evidence; schemas, code, hashes, and tests** |

# S3. Frozen conventional endpoint

The frozen composite-controller hypothesis fails at 42/53 accepted events: its risk is 0.381 versus 0.310 for confidence. The paired controller-minus-confidence interval is [−0.05, 0.17], with empirical one-sided bootstrap support probability 0.12. Posterior margin is the lowest-risk rule at this fixed count.

**Table S2. Frozen primary endpoint under oracle entry.**

| Rule | Accepted/test | Coverage | Labeling risk | Cluster-bootstrap 95% CI |
|---|---:|---:|---:|---:|
| Evidence-sufficiency controller | 42/53 | 0.792 | 0.381 | [0.214, 0.524] |
| Maximum confidence | 42/53 | 0.792 | 0.310 | [0.167, 0.476] |
| Top-one/top-two margin | 42/53 | 0.792 | **0.262** | [0.143, 0.429] |
| Coverage-matched majority | 42/53 | 0.792 | 0.548 | not used for inference |

# S4. LLM certificate study and sensitivity

The confirmatory Qwen2.5-7B run [@yang2024qwen25] produces all 954 expected outputs with unique `(variant, sample_id)` keys and a 1.000 JSON parse rate. The raw contracted generator labels almost everything and has a 0.529 corruption-macro wrong-label rate. Enforcing the certificate cuts that rate to 0.271. Its equal-family hallucinated-anchor rate is 0.004 (one shifted-time output among 255 corrupted packages), and no contracted variant cites a nonexistent process reference. Direct LLM is qualitatively different: because its tactic is always issued, the 0.200 hallucinated-anchor macro is a diagnostic of unsupported citation behavior rather than a rejection mechanism.

\begingroup\scriptsize

**Table S3. Confirmatory LLM results and post-hoc coverage-matched selector audit. All rates are proportions; corruption columns are equal-family macro averages over corrupted inputs only. Direct LLM's certificate fields are audited after generation but do not control its forced label. The contracted-generator and EviGate-LLM certificate columns are identical because both rows audit the same generations; only EviGate-LLM enforces verifier failures. A dash means that a certificate-specific metric does not apply.**

| Method | Clean accepted | Clean risk | Clean accuracy | Corruption wrong-label | Corruption rejection | Invalid certificate attempt | Hallucinated anchor |
|---|---:|---:|---:|---:|---:|---:|---:|
| Direct LLM | 50/51 | 0.800 | 0.196 | 0.494 | 0.349 | 0.235 | 0.200 |
| Self-abstaining LLM | 41/51 | 0.341 | 0.529 | 0.310 | 0.404 | 0.286 | 0.004 |
| Contracted generator, verifier off | 48/51 | 0.354 | 0.608 | 0.529 | 0.024 | 0.502 | 0.004 |
| **EviGate-LLM** | **30/51** | 0.333 | 0.392 | **0.271** | 0.525 | 0.502 | 0.004 |
| Calibrated posterior margin | 38/51 | **0.263** | 0.549 | 0.357 | 0.290 | — | — |
| Calibrated margin + missing-process rule | 38/51 | **0.263** | 0.549 | 0.325 | 0.353 | — | — |
| Count-matched posterior margin | **30/51** | 0.300 | 0.412 | 0.286 | 0.486 | — | — |

\endgroup

The frozen aggregate superiority claim is not supported. $H_{L1}$ requires a 0.05 corruption wrong-label reduction over calibrated self-abstention; the observed reduction is 0.039 (paired event-cluster bootstrap 95% CI [−0.024, 0.106]). $H_{L2}$ requires at least 0.60 clean coverage and a gap of at most 0.15 below self-abstention. EviGate-LLM reaches 0.588, and the gap is 0.216 (95% CI [0.039, 0.373]); its selective-risk guardrail passes.

At exactly 30 accepted clean events, margin has one fewer clean error than EviGate-LLM (risk 0.300 versus 0.333). The observed corruption-macro difference is 0.016 and its 95% interval spans zero [−0.051, 0.078]. EviGate-LLM rejects every all-process-deletion case, whereas coherent different-tactic context still yields a 0.686 wrong-label rate. A preliminary affinity audit reduces the latter rate to 0.392 but lowers clean coverage from 0.588 to 0.490.

## S4.1 Checkpoint, decoding, and negative-family sensitivity

The no-LLM cascade matches the full method's clean risk and clean correctness (25/51) but has corruption-macro and context wrong-label rates of 0.129 and 0.431. The LLM changes five of 51 context outcomes: the post-hoc reduction is 0.098 [0.020, 0.196], with exact McNemar $p=0.0625$. Across the three non-mechanical corruption families, its reduction is 0.026 [−0.007, 0.065], with exact sign-flip $p=0.289$.

With Qwen3-8B [@qwen2025qwen3], the complete cascade accepts 34/51 clean events and again obtains 25 correct labels (risk 0.265), with five-family and context wrong-label rates of 0.141 and 0.431. At matched 34-event coverage, posterior margin yields 0.259 and 0.863; the macro and context reductions remain positive at 0.117 [0.078, 0.157] and 0.431 [0.294, 0.569]. Both checkpoints parse all 318 responses. Qwen3 has a higher contract-valid rate (0.833 versus 0.783), yet worse final context error than Qwen2.5 (0.431 versus 0.333). Thus syntactic validity does not predict incident binding.

Across three Qwen2.5 samples per clean and context package, the final attribution decision is unanimous for 90/102 packages (0.882). Clean coverage ranges from 0.706 to 0.745 and every replicate makes ten clean errors. Context wrong-label rates are 0.373, 0.490, and 0.490 (mean 0.451), slightly worse than the fixed CPU-only cascade's 0.431. The deterministic LLM's five-event context gain therefore does not survive sampled decoding, although every sampled run remains below the matched-margin context error of 0.863 because the shared non-LLM gates reject many mismatches.

Full-gate training includes network-most-similar different-tactic donors, and the primary context-replacement test also uses different-tactic donors, so the two negative regimes partly overlap. Training EviGate-Bind with same-tactic hard negatives only nevertheless lowers context wrong labels from 0.863 to 0.471, retaining 74.1% of the full method's context improvement; the 0.392 reduction has interval [0.255, 0.529]. Adding different-tactic hard negatives supplies a further 0.137 context reduction [0.059, 0.235] and a 0.047 macro reduction [0.020, 0.078]. Thus the overlap contributes materially but does not wholly create the main effect.

# S5. Cross-view ablation

The post-freeze cross-view ablation holds the 51-event cohort, grouped temporal folds, hard-negative donors, certificate outputs, temporal rule, threshold selection, and random seed fixed. `Without network posterior` removes the network confidence, margin, entropy, class probabilities, and all pairwise posterior agreement terms while retaining identity-free raw network summaries. The single-view rows are negative controls: a provenance swap cannot alter the features computed from the retained side alone.

**Table S4. Post-freeze EviGate-Bind feature ablation. Wrong-label denominators are 51 events. Intervals compare each ablation with the full mode using 10,000 paired event-cluster bootstrap resamples.**

| Feature mode | Features | Clean accepted/risk | Five-family macro wrong | Context wrong | Context increase vs. full (95% CI) | Synthetic same-/different-tactic alarm |
|---|---:|---:|---:|---:|---:|---:|
| **Full cross-view** | 92 | 33/51 / **0.242** | **0.114** | **0.333** | — | 0.255 / 0.314 |
| Without network posterior | 70 | 35/51 / 0.257 | 0.196 | 0.569 | 0.235 [0.118, 0.353] | 0.039 / 0.059 |
| Network only | 14 | 36/51 / 0.278 | 0.220 | 0.608 | 0.275 [0.157, 0.392] | 0.000 / 0.000 |
| Provenance only | 16 | 36/51 / 0.278 | 0.212 | 0.608 | 0.275 [0.157, 0.392] | 0.000 / 0.000 |

Removing posterior-level network features while retaining raw network summaries increases context wrong labels by 12/51 and the five-family macro wrong-label rate by 0.082 [0.051, 0.114]. The network-only and provenance-only controls each increase context wrong labels by 14/51; they increase the five-family rate by 0.106 [0.075, 0.141] and 0.098 [0.067, 0.133]. Their clean-risk differences from the full mode have intervals crossing zero. The supported inference is therefore specific to mismatch rejection; the ablation does not establish a clean-label accuracy gain or causal network-to-process binding.

# S6. Mechanism-specific stress tests

**Table S5. Mechanism-specific post-freeze results. Each cell is accepted events / wrong-label rate over all 51 transformed events.**

| Evidence condition | EviGate-Bind | Matched margin + structural rules |
|---|---:|---:|
| All-process deletion | 0 / 0.000 | 0 / 0.000 |
| Socket-type deletion | 33 / 0.157 | 31 / 0.216 |
| +600-second time shift | 0 / 0.000 | 0 / 0.000 |
| Hash-parity half-process deletion | 11 / 0.078 | 28 / 0.196 |
| Different-tactic context replacement | 18 / 0.333 | 47 / 0.863 |

Both methods reject all cases with no process evidence and all +600-second shifts after the shared temporal obligation. Excluding these mechanically rejected families, EviGate-Bind lowers the three-family macro wrong-label rate from 0.425 to 0.190, a 0.235 reduction with an event-cluster interval [0.170, 0.301] and a post-freeze embargo-group interval [0.163, 0.306] over 43 groups. The exact paired sign-flip test gives $p=8.23\times10^{-8}$ for consistency of this fixed within-campaign contrast, not cross-campaign generalization. Its context-replacement selective risk remains 0.944 because nearly every accepted foreign package is wrong. Three of five frozen absolute development targets are met: clean risk is 0.242, five-family corruption-macro wrong labels are 0.114, and all-process deletion produces no wrong label. Clean acceptance is 33/51 rather than the targeted 34/51, and context-replacement wrong-label rate is 0.333 rather than below 0.300. A binding-only audit rejects 31.4% of network-similar different-tactic replacements but only 25.5% of same-tactic replacements.

# S7. End-to-end and analyst-facing accounting

**Table S6. Final EviGate-Bind per-tactic and end-to-end accounting over the 51-event cohort.**

| True tactic | Events | Oracle-entry issued/correct | End-to-end issued/correct |
|---|---:|---:|---:|
| Collection | 24 | 18 / 17 | 14 / 13 |
| Command and Control | 5 | 3 / 2 | 2 / 2 |
| Credential Access | 7 | 3 / 0 | 2 / 0 |
| Discovery | 11 | 7 / 6 | 4 / 3 |
| Exfiltration | 4 | 2 / 0 | 2 / 0 |
| **Total** | **51** | **33 / 25** | **24 / 18** |

The final cohort contains 15 Stage A misses, 12 alerted but unattributed events, and 24 attributed events. Each emitted record exposes at most the ten highest-ranked processes rather than the full candidate pool. Evaluation-sidecar truth remains within this top-ten list for 11/12 unattributed alerts. The exception is `case_96a0f492c46e3cc1be5f`, whose 8,924 candidates place the true process at midrank 8,901. This is retrieval coverage, not an analyst-time measurement. The per-tactic table also shows that aggregate risk does not imply broad tactic support: no correct Credential Access or Exfiltration label is issued.

# S8. Decision-cost analysis

For decision analysis, a wrong issued label has unit cost and an abstention has relative cost $c\in[0,1]$. On clean events the cost is $N_{\mathrm{wrong}}+cN_{\mathrm{abstain}}$. For deliberately replaced provenance, every issued label is treated as an integrity failure even if its tactic matches by chance.

**Table S7. Decision-cost equations over 51 oracle-entry events.**

| Scenario and policy | Wrong or unsafe issued | Abstained | Total cost |
|---|---:|---:|---:|
| Clean: full EviGate-Bind | 8 | 18 | $8+18c$ |
| Clean: count-matched margin | 11 | 18 | $11+18c$ |
| Clean: training-calibrated margin | 10 | 13 | $10+13c$ |
| Foreign context: full EviGate-Bind | 18 | 33 | $18+33c$ |
| Foreign context: count-matched margin | 47 | 4 | $47+4c$ |
| Foreign context: training-calibrated margin | 48 | 3 | $48+3c$ |

Full EviGate-Bind strictly dominates count-matched margin on clean events at the same abstention count. Against training-calibrated margin, the clean break-even point is $c=0.40$; the full gate is cheaper below this point and the higher-coverage margin policy is cheaper above it. Both foreign-context comparisons break even only at $c=1$, so the full gate is cheaper whenever rejecting untrusted evidence costs less than accepting it.

# S9. Conventional selector and corruption diagnostics

\begingroup\scriptsize

**Table S8. Matched selector baselines. Exact AURC uses every accepted count.**

| Rule | Risk at 42/53 | 95% CI | Exact AURC | Calibration-only accepted/test | Calibration-only risk |
|---|---:|---:|---:|---:|---:|
| Maximum confidence | 0.310 | [0.167, 0.476] | 0.267 | 45/53 | 0.311 |
| One minus normalized entropy | 0.310 | [0.190, 0.476] | 0.276 | 49/53 | 0.367 |
| Top-one/top-two margin | **0.262** | [0.143, 0.429] | 0.270 | 40/53 | **0.250** |
| Posterior-only Logistic | 0.429 | [0.286, 0.595] | 0.490 | 29/53 | 0.483 |
| Cross-view agreement | 0.357 | [0.190, 0.500] | 0.268 | 49/53 | 0.367 |
| Original controller | 0.381 | [0.214, 0.524] | 0.458 | 37/53 | 0.432 |
| Integrity only | 0.357 | [0.214, 0.500] | 0.407 | 40/53 | 0.350 |
| Dual confidence/integrity | 0.333 | [0.190, 0.500] | **0.176** | 40/53 | 0.325 |

\endgroup

![](figures/figure2_selective_risk_end_to_end.pdf){width=100%}

**Figure S1.** (a) Selective risk across oracle-entry accepted counts. (b) End-to-end counts after intersection with Stage A.

\begingroup\scriptsize

**Table S9. Per-tactic correctness at the fixed 42/53 operating point.**

| Tactic | Events | Full correct | Confidence accepted/correct | Controller accepted/correct | Integrity accepted/correct | Dual accepted/correct |
|---|---:|---:|---:|---:|---:|---:|
| Collection | 26 | 22 | 23/20 | 20/17 | 22/19 | 22/19 |
| Command and Control | 5 | 3 | 3/2 | 3/1 | 3/2 | 3/2 |
| Credential Access | 7 | 0 | 3/0 | 6/0 | 6/0 | 5/0 |
| Discovery | 11 | 8 | 9/7 | 10/8 | 8/6 | 9/7 |
| Exfiltration | 4 | 0 | 4/0 | 3/0 | 3/0 | 3/0 |

\endgroup

**Table S10. Leave-one-corruption-family-out results. Each cell is rejection rate / wrong-label rate over 53 transformed cases.**

| Held-out family | Confidence | Original controller | Integrity only | Dual rule |
|---|---:|---:|---:|---:|
| Context replacement | 0.000 / 0.925 | **0.585 / 0.377** | 0.208 / 0.736 | 0.170 / 0.774 |
| All-process deletion | **1.000 / 0.000** | 0.962 / 0.000 | 0.755 / 0.132 | **1.000 / 0.000** |
| Hash-parity half-process deletion | 0.132 / 0.377 | **0.660 / 0.189** | 0.321 / 0.340 | 0.208 / 0.340 |
| Socket-type deletion | 0.151 / **0.283** | 0.208 / 0.302 | 0.113 / 0.340 | 0.189 / **0.283** |
| +600-second time shift | 0.132 / 0.283 | 0.925 / 0.057 | **0.925 / 0.019** | 0.849 / 0.057 |

![](figures/figure3_corruption_response.pdf){width=100%}

**Figure S2.** Wrong-label and rejection rates under the five held-out synthetic collection failures.

\begingroup\tiny

**Table S11. Fixed-count end-to-end accounting over all 53 in-support events.**

| Rule | Oracle accepted | Stage A alerted | End-to-end attributed | Correct | Wrong | Unattributed after alert | Stage A missed | Attributed risk |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Confidence | 42 | 38 | 31 | 21 | 10 | 7 | 15 | 0.323 |
| Original controller | 42 | 38 | 30 | 19 | 11 | 8 | 15 | 0.367 |
| Integrity only | 42 | 38 | 29 | 20 | 9 | 9 | 15 | 0.310 |
| Dual rule | 42 | 38 | 28 | 20 | 8 | 10 | 15 | 0.286 |

\endgroup

![](figures/figure4_worked_event.pdf){width=95%}

**Figure S3.** Worked event `case_37947035589a61186702`. The figure illustrates the interface; it is not aggregate evidence.

Deleting the three highest-ranked processes reduces true-tactic probability by 0.0345 on average, versus 0.0027 for deterministic equal-size random deletion. The deletion lift is 0.0317 [0.0191, 0.0450], establishing model dependence but not causal responsibility.

# S10. Expanded stage results

This section preserves details removed from the eight-page manuscript. Figure S4 records the full inference and evidence boundary. Stage A aggregates 69 identity-free network features and calibrates each outer fold to 0.5 false alerts/h. Stage B ranks every process in the ±5-minute typed graph from 55 temporal, graph, neighbor, path, utility, and endpoint-match features. Stage C receives normalized evidence from the ten highest-ranked processes. Ground-truth process IDs, tactic labels, and split assignments remain in a separate evaluation sidecar.

![](figures/figure1_pipeline_evidence_boundary.pdf){width=100%}

**Figure S4.** EviGate-APT inference, verification, and evaluation boundary. The sidecar is evaluation-only; the BindGate cascade is a declared post-freeze extension. No packet-to-process causal edge is asserted.

**Table S12. Stage A performance at the primary false-alert budget (mean ± sample SD across three outer folds).**

| Model | Window AP | Precision | Recall | Phase 2 false alerts/h | In-support event coverage | Phase 1 false alerts/h |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.327 ± 0.117 | 0.033 ± 0.058 | 0.013 ± 0.022 | 0.117 ± 0.203 | 0.056 ± 0.096 | 0.031 ± 0.054 |
| HGB | **0.844 ± 0.053** | **0.880 ± 0.112** | **0.609 ± 0.162** | 0.134 ± 0.136 | **0.719 ± 0.190** | **0.000 ± 0.000** |
| MLP | 0.488 ± 0.163 | 0.639 ± 0.187 | 0.305 ± 0.035 | 0.234 ± 0.160 | 0.434 ± 0.049 | 2.259 ± 0.118 |

Phase 2 contains 9,536,823 network rows and 4,325 nonoverlapping 60-second windows over approximately 72.07 h. Of the 15 HGB event misses, six have no attack-labeled network-positive window and nine have a positive window whose score is below the fold-specific threshold. The misses span Collection (5), Discovery (4), Credential Access (3), Command and Control (2), and Exfiltration (1); they do not isolate to one tactic. A provenance-initiated path could recover some host-visible incidents, but it would change the current network-triggered task and its denominators.

**Table S13. Stage B retrieval over all 59 held-out events, averaged across five seeds.** Midrank MRR uses the reciprocal midpoint of the highest-scoring tie containing at least one true process; expected-tie R@$k$ randomizes ordering within ties. The columns measure different tie conventions, not a single-hit identity task.

| Ranker | Midrank MRR | Expected-tie R@1 | R@5 | R@10 | Normalized best rank |
|---|---:|---:|---:|---:|---:|
| Analytical random expectation | 0.412 | 0.221 | 0.681 | 0.860 | 0.215 |
| Recency | 0.325 | 0.280 | 0.757 | **0.966** | 0.230 |
| Degree | 0.147 | 0.000 | 0.340 | 0.866 | 0.381 |
| Recency + degree | 0.198 | 0.000 | 0.644 | 0.915 | 0.306 |
| Typed HGB | 0.679 | 0.915 | **0.966** | **0.966** | **0.004** |
| Full typed Logistic | **0.952** | **0.949** | **0.966** | **0.966** | 0.018 |

In 58/59 cases, the truth sidecar lists multiple process entities. For an HGB case whose best tie contains six true entities, reciprocal midrank is $1/3.5=0.286$, while expected-tie R@1 is 1.000. As a sensitivity analysis, expected reciprocal first-hit rank under uniform tie permutation is 0.941 for HGB and 0.958 for Logistic over all 59 cases; the original midrank values above remain the frozen primary metric. On the 53 supported cases, Logistic midrank MRR is 0.947, corresponding to the 0.95 abstract rounding. `scripts/audit_reviewer_p0.py` reads frozen per-case rankings without retraining and writes `data/derived/reviewer_p0/reviewer_p0_audit.json`, including the 43-group paired bootstrap behind Figure 3.

At the declared ±5-minute radius, the full candidate pool has minimum 7, median 14, mean 285.4, and maximum 8,924 processes, but the emitted analyst record contains at most the top ten. A labeled malicious process is present in 58/59 aligned event windows; because all released provenance is from Ubuntu VM1, this is a lower bound on VM1-visible host activity, not evidence that the paired traffic traversed VM1. Retrieval-radius decoupling is reported separately in Table S18.

**Table S14. Stage B feature and process-family shortcut audit.**

| Split/feature set | Midrank MRR | Expected-tie R@1 | R@5 | R@10 |
|---|---:|---:|---:|---:|
| Event split/full features | **0.952** | **0.949** | **0.966** | **0.966** |
| Event split/without socket bridge | **0.952** | **0.949** | **0.966** | **0.966** |
| Event split/temporal + degree only | 0.706 | 0.534 | 0.949 | **0.966** |
| Event split/process semantics only | 0.521 | 0.808 | 0.932 | 0.949 |
| Event split/without all process semantics | 0.724 | 0.551 | **0.966** | **0.966** |
| Process-family holdout/full features | 0.927 | 0.915 | **0.966** | **0.966** |
| Process-family holdout/without semantics | 0.693 | 0.517 | 0.932 | 0.949 |

The executable-family shortcut audit contains 16 group-disjoint families; `sh|dash` is the largest with 30/59 events. This declared grouping tests sensitivity to name/basename shortcuts rather than semantic malware-family generalization.

# S11. Complete inference-comparison inventory

The paper reports 17 scalar paired contrasts with an interval or exact/empirical probability. Three were declared before their associated test run; 14 are secondary or post-hoc. No family-wise multiplicity correction is applied. As a descriptive sensitivity check, the Bonferroni threshold is 0.05/17=0.00294: the three-family sign-flip result remains below it, whereas the LLM context increment does not. This does not change the post-freeze status of either analysis. The table prevents exploratory contrasts from being mistaken for confirmatory hypotheses.

| ID | Contrast | Status |
|---|---|---|
| C1 | Controller minus confidence clean risk | Prespecified conventional |
| L1 | EviGate-LLM minus self-abstention corruption wrong-label | Prespecified LLM |
| L2 | EviGate-LLM minus self-abstention clean-coverage gap | Prespecified LLM |
| S1 | Controller minus posterior-margin clean risk | Secondary |
| S2 | Top-process minus random-process deletion effect | Secondary |
| B1 | Full EviGate-Bind minus matched margin clean risk | Post-freeze |
| B2 | Full EviGate-Bind minus matched margin five-family wrong-label | Post-freeze |
| B3 | Full EviGate-Bind minus matched margin context wrong-label | Post-freeze |
| B4 | Full EviGate-Bind minus matched margin three-family wrong-label | Post-freeze |
| B5 | Full EviGate-Bind minus no-LLM context wrong-label | Post-freeze |
| B6 | Full EviGate-Bind minus no-LLM three-family wrong-label | Post-freeze |
| B7 | Same-tactic-only EviGate-Bind minus matched margin context wrong-label | Post-freeze |
| B8 | Full minus same-tactic-only EviGate-Bind context wrong-label | Post-freeze |
| B9 | Full minus same-tactic-only EviGate-Bind five-family wrong-label | Post-freeze |
| B10 | Full EviGate-Bind minus matched margin four-family wrong-label | Post-freeze |
| Q3-1 | Qwen3 cascade minus matched margin five-family wrong-label | Post-freeze diagnostic |
| Q3-2 | Qwen3 cascade minus matched margin context wrong-label | Post-freeze diagnostic |

# S12. Compute details

The CPU compatibility path was timed on an Intel Xeon Silver 4215R with one BLAS/OpenMP thread over 306 measurements: mean 2.70 ms, median 2.64 ms, p95 3.83 ms, and maximum 5.44 ms per package. The scope includes two view-posterior calls, network/provenance summary vectorization, pair features, and BindGate inference. It is not an embedded-device benchmark and does not measure Auditd/SPADE collection overhead. The Qwen2.5-7B reviewer ran at the SOC/offline tier on an RTX A6000; it is optional and is not required by the CPU-only cascade.

# S13. Artifact checksums

Representative SHA-256 checksums are listed below; the local machine-readable manifest contains the complete inventory. Each digest is split only for typesetting; concatenate the two adjacent groups without a space. The frozen LLM protocol file `docs/30_evigate_llm_experiment_protocol.md` has current SHA-256 `6A8FEA2BA3339E1DD6E1CE08FD8CF05B3E4FDC9898C52C37DD445C59231CE9A`. The local development-and-freeze log records prompt, schema, input, and truth hashes. These files preserve an internal protocol record but do not establish an independently time-stamped public preregistration.

- **Stage B shortcut per-case:**  
  `5910376B446720F2964BD72E43BC45C6`\allowbreak{}`6ADB1975BBE7B91540072D55F760CA2D`
- **Stage C predictions:**  
  `B23F19B7D5D9F3A5AB228410C803F3C3`\allowbreak{}`1452F8648A9C9AB10E28BC19F13BB77C`
- **Stage C corruptions:**  
  `33DA7E3F71FF2AE4C2DB1F77EE12B421`\allowbreak{}`4192230E37FF064010397FF94D228B49`
- **Frozen 954-output LLM run:**  
  `42C9324E1D4A4D0553656AED1AE12BF4`\allowbreak{}`2149FED2BADA073AE08E1DBD25456856`
- **Proposal-locked 318-output run:**  
  `00A9EC968334D1867C242500E8EAE314`\allowbreak{}`76FC72FCACDF739DB73BB0946B747E4F`
- **EviGate-Bind per-case:**  
  `3C778176C7CEE2D5F9F6BF4D6797CD7F`\allowbreak{}`FF85301246431AC9A676E63F01FF34DE`
- **EviGate-Bind summary:**  
  `4A096E4638E5310D3EC0A198183921A3`\allowbreak{}`B49FB68EAC6191BD42275ADFE6F52381`
- **Qwen3-8B 318 outputs:**  
  `A700D539A3728F41BC71C17C4712A923`\allowbreak{}`5AFD4357064827265BDCA4D6BB652B03`
- **Qwen3-8B cascade per-case:**  
  `BAC4ABAF900C0F11895C76BFD156299E`\allowbreak{}`12920F22A545B8D5E83C4B7B0A52E457`
- **Qwen2.5 sampled 306 outputs:**  
  `3914E064E989FEC707FED69E69B92B20`\allowbreak{}`A7853552B652D18680ADD4D2E3F77C90`
- **LLM robustness summary:**  
  `6312F58D574D0DCC29E42C6BFD47178B`\allowbreak{}`D5EB81F82B580D6D82049190B3D43AA2`

The full compatibility path took 2.24-ms median and 3.44-ms p95 wall time over 306 measurements on the Intel Xeon Silver 4215R server-class CPU. Independent reruns reproduce the retained per-case and synthetic-binding files byte for byte, and reproduce each summary after the nondeterministic timing object is removed.

# S14. Post-freeze P0 diagnostics

The following diagnostics answer four reviewer-facing questions without changing a model, split, feature, or frozen threshold. Their source artifacts, per-case rows, hashes, and executable script are distributed under `data/derived/p0_diagnostics/`.

**Table S15. Post-freeze host-link and supplementary-file audit.** The author's testbed table maps Ubuntu VM1 to `172.16.63.128`, Kali VM1 to `172.16.65.128`, and Raspberry Pi2 to `172.16.67.128` (Table 3.1 in [@ghiasvand2024thesis]). The socket join independently matches a VM1 process's remote address, port, and timestamp to a network row; its opposite endpoint is a corroborating candidate, not the source of the host map. The separately obtained Caldera file is audited without changing the frozen event manifest.

| Audit quantity | Result |
|---|---:|
| Addresses in provenance `ip addr add` commands / occurrences in network rows | 6 / 0 |
| Author-mapped attack endpoints / attack rows using their pair | Ubuntu--Kali / 1,004/1,004 |
| Deduplicated usable nonloopback socket observations | 8,077 |
| Matches within 0.05 s / dominant-endpoint matches | 161 / 148 |
| Matches within 0.1 s / dominant-endpoint matches | 755 / 733 |
| Matches at each of −60, −30, +30, +60 s offsets | 0 |
| Attack-labelled rows touching `172.16.63.128` | 1,004/1,004 |
| Both-view clusters / in-support both-view clusters | 33/59 / 32/53 |
| In-support clusters with attack labels in one view only | 10 network-only / 11 provenance-only |
| Evaluated non-pilot host-link-supported events | 31/51 |
| Caldera-file PIDs found as attack-labeled VM1 Process entities | 58/58 (116 Process rows) |
| Caldera times with a same-tactic attack row within 30 s | 58/58 (13 cleanup rows share one time) |
| Non-cleanup Caldera time/PID pairs with own process time within 60 s | 1/45 |
| Non-cleanup process times within 60 s of the next Caldera row | 38/44 |
| Usable malicious-process socket-to-flow matches | 0 |

The 733 Ubuntu-endpoint matches span the complete capture and are produced mainly by `NetworkManager`. The 22 DNS-only matches to `172.16.67.128` do not identify a second VM1 interface: the author's map assigns that address to Raspberry Pi2. The `ip addr add` records are likewise not a complete NIC inventory. The 0.05-s sensitivity and shifted-time controls corroborate the independent author map, but the released network/provenance CSVs still lack row-level host identifiers.

The official dataset description states that `Attack_info.csv` is extracted from MITRE Caldera reports [@cicapt2024dataset]. The author's thesis describes two complementary labeling procedures: Caldera PIDs and descendants label provenance, while corrected NS3 packet timestamps, Caldera action times, and attacker/victim IPs label individual network packets (Sec. 3.4.2 in [@ghiasvand2024thesis]). The downloaded file has 58 distinct PIDs in 45 non-cleanup and 13 cleanup rows; its local SHA-256 is `C4187AE745875D16BA2823E28E7059B834D4865C305F81717D75066EC2E2A172`. Each PID appears in the VM1 provenance as two attack-labeled Process records. Each listed time is within 30 s of a same-tactic attack-labeled network row (median nearest gap 25.444 s; maximum 28.853 s), although the 13 cleanup rows share a timestamp and are not independent matches. These facts strengthen campaign-level host co-membership and establish separate packet-level attack labels and PID-based process labels; they do not by themselves identify which PID emitted a given packet.

The Caldera time/PID pairing is not step-aligned to provenance process creation: only 1/45 non-cleanup PIDs start within 60 s of their own CSV row's attack time; 38/44 non-final non-cleanup PIDs start within 60 s of the **next** row's time, and 43/44 within 300 s (maximum gap 303.7 s). The 13 cleanup PIDs start 25--49 s after their shared listed time. We do not infer why this offset occurs, shift the rows, or use the Caldera file to retroactively redefine the 59 union-derived clusters. Such a change would require rebuilding splits, truth sidecars, and all reported metrics.

On the 31 supported non-pilot events, EviGate-Bind accepts 22 and makes four clean errors (risk 0.182), versus 21 accepted and five errors (0.238) for matched margin. Under context replacement it produces 7/31 wrong labels versus 25/31. This is a post-hoc scope diagnostic, not independent confirmation. The author-described labeling procedure does not publish a packet-to-PID key in the released CSVs. Because the provenance artifacts omit local address and local port, and no usable malicious-process socket matches a flow in our audit, this analysis does not independently identify which PID generated an attack packet stream.

**Table S16. Stage A alert-budget frontier for HGB.** Each threshold is learned only on its calibration fold under the requested budget. Values are three-fold means; Phase 1 is the independent 95.9-h benign stress set.

| Requested budget (false alerts/h) | Observed Phase 2 false alerts/h | Window recall | All-event coverage | In-support coverage | Phase 1 false alerts/h |
|---:|---:|---:|---:|---:|---:|
| 0.5 | 0.134 | 0.609 | 0.697 | 0.719 | 0.000 |
| 1.0 | 0.134 | 0.621 | 0.714 | 0.739 | 0.000 |
| 2.0 | 0.293 | 0.632 | 0.747 | 0.758 | 0.000 |
| 5.0 | 1.830 | 0.724 | 0.800 | 0.814 | 0.000 |

The requested value constrains calibration rather than test outcomes. The curve exposes the operational coverage--alert trade-off and is not used to replace the declared 0.5-false-alert/h operating point.

**Table S17. Stage B retrieval stratified by process-candidate count.** MRR uses the same best-truth-score midrank definition as the primary endpoint; random values are analytic expectations. The five nominal Logistic seeds produce identical rankings, so the primary seed is shown once.

| Candidate processes | Events | Truth present | Typed MRR | Typed R@1 | Typed R@10 | Random MRR | Random R@1 | Random R@10 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| $\leq20$ | 47 | 47 | 0.993 | 1.000 | 1.000 | 0.454 | 0.237 | 0.969 |
| 21--100 | 4 | 4 | 0.875 | 0.750 | 1.000 | 0.594 | 0.419 | 0.924 |
| $>100$ | 8 | 7 | 0.750 | 0.750 | 0.750 | 0.076 | 0.023 | 0.182 |

Candidate counts have minimum 7, median 14, mean 285.4, and maximum 8,924. The learned ranker is nearly saturated on the 47 smallest graphs. In the largest stratum it still substantially exceeds random expectation, but six cases rank truth first, one 5,119-process case contains no truth process, and one 8,924-process case places truth at midrank 8,901. The aggregate RQ1 headline must therefore be read together with graph size.

# S15. Post-freeze P1 diagnostics

These diagnostics address retrieval-window circularity, three-fold partition sensitivity, omitted trivial baselines, and evidence-retention cost. They do not modify the frozen event definition, features, model seeds, or deployed thresholds. The repeated partitions are sensitivity analyses within one campaign, not independent deployments.

**Table S18. Retrieval radius decoupled from the 300-s event-clustering gap.** All 59 held-out events are scored with the same typed Logistic configuration. The ceiling is the fraction whose truth process occurs in the retrieved candidate graph.

| Radius | Truth ceiling | Median / mean / max candidates | Midrank MRR | Expected-tie R@1 | R@10 |
|---:|---:|---:|---:|---:|---:|
| $\pm60$ s | 0.881 | 9 / 175.5 / 8,918 | 0.833 | 0.814 | 0.864 |
| $\pm300$ s | 0.983 | 14 / 285.4 / 8,924 | **0.952** | **0.949** | **0.966** |
| $\pm900$ s | **1.000** | 24 / 496.3 / 8,935 | 0.941 | 0.915 | **0.966** |

The short radius loses seven truth processes. The long radius recovers the remaining process but nearly doubles the mean candidate count relative to $\pm300$ s and lowers expected-tie R@1 by 0.034. The declared $\pm300$-s radius is therefore an empirical coverage--load compromise rather than a consequence of using the same value for event clustering.

**Table S19. Typed Logistic retrieval over ten randomized embargo-grouped three-fold partitions.** Supported tactic strata determine the split; the two out-of-support groups rotate through test folds and are never eligible for training. The model seed remains 11.

| Split seed | Midrank MRR | Expected-tie R@1 | R@5 | R@10 |
|---:|---:|---:|---:|---:|
| 101 | 0.931 | 0.915 | 0.966 | 0.966 |
| 202 | 0.944 | 0.932 | 0.966 | 0.966 |
| 303 | 0.893 | 0.864 | 0.932 | 0.966 |
| 404 | 0.924 | 0.898 | 0.966 | 0.966 |
| 505 | 0.958 | 0.949 | 0.966 | 0.966 |
| 606 | 0.938 | 0.915 | 0.966 | 0.966 |
| 707 | 0.938 | 0.932 | 0.966 | 0.966 |
| 808 | 0.966 | 0.966 | 0.966 | 0.966 |
| 909 | 0.966 | 0.966 | 0.966 | 0.966 |
| 1010 | 0.941 | 0.915 | 0.966 | 0.966 |
| **Mean ± sample SD** | **0.940 ± 0.022** | **0.925 ± 0.031** | **0.963 ± 0.011** | **0.966 ± 0.000** |

The MRR range is 0.893--0.966. This narrows the interpretation of the original three-fold result: ranking is not tied to one partition, but the repeat variability still pertains to a single scripted campaign.

**Table S20. Trivial tactic baselines on the 53-event in-support cohort.** The fold-local majority class is selected from each outer-training partition. The coverage-matched value is the prespecified 42-event operating point.

| Baseline | Accepted | Correct | Risk | Macro-F1 |
|---|---:|---:|---:|---:|
| Fold-local majority, full coverage | 53/53 | 26/53 | 0.509 | 0.132 |
| Coverage-matched majority | 42/53 | 19/53 | 0.548 | -- |

**Table S21. Endpoint-seeded two-hop pruning baselines over 58 truth-present process graphs.** “Seeded” means that the policy found an endpoint seed and therefore pruned the graph; truth preservation conditional on seeding is the decisive quantity.

| Seed policy | Seeded cases | Truth preserved overall | Truth preserved when seeded | Median retained entities |
|---|---:|---:|---:|---:|
| Joint address and port | 11 | 47/58 | 0/11 | 83 |
| Address | 14 | 46/58 | 2/14 | 81 |
| Port | 40 | 21/58 | 3/40 | 24 |
| Either address or port | 41 | 21/58 | 4/41 | 23 |

These rules are not viable retrieval competitors: their apparent overall preservation comes primarily from cases in which no seed is found and the full graph is retained. The joint rule excludes the malicious PID every time it actually prunes.

**Table S22. Clean outcomes in naturally overlapping evidence contexts.** Multi-event contexts are defined by the pre-existing 600-s embargo groups, not donor injection. Selective risk is wrong/accepted. “Foreign-tactic wrong” means an accepted wrong label equals another tactic present in the same natural group.

| Cohort | Rule | Events | Accepted | Correct | Wrong | Risk | Foreign-tactic wrong |
|---|---|---:|---:|---:|---:|---:|---:|
| Singleton | EviGate-Bind | 30 | 22 | 18 | 4 | 0.182 | 0 |
| Singleton | Matched margin | 30 | 21 | 16 | 5 | 0.238 | 0 |
| Same-tactic overlap | EviGate-Bind | 1 | 1 | 1 | 0 | 0.000 | 0 |
| Same-tactic overlap | Matched margin | 1 | 1 | 1 | 0 | 0.000 | 0 |
| Mixed-tactic overlap | EviGate-Bind | 20 | 10 | 6 | 4 | 0.400 | 4 |
| Mixed-tactic overlap | Matched margin | 20 | 11 | 5 | 6 | 0.545 | 5 |

The 13 multi-event groups contain 26 events. Across their 13 event pairs, median process-set Jaccard is 1.000 and 11 pairs contain each event's truth process in the other's graph. This natural stress test agrees with the controlled replacements in direction---EviGate-Bind suppresses two additional wrong labels relative to matched margin---but shows that shared-context confusion remains. The host-link audit supports involvement of the monitored host but cannot distinguish true co-residence of two event contexts from collection-window contamination.

**Table S23. Evidence-retention and serialization diagnostic at the fixed Stage-A operating point.** Raw-row fractions are restricted to timestamped provenance records; untimed linked entities require a separate store.

| Quantity | Result |
|---|---:|
| Network capture duration | 72.08 h |
| Held-out alert windows | 60 |
| Unmerged $\pm5$-min evidence duration | 10.00 h |
| Merged retention intervals | 39 |
| Merged retention duration / capture time | 6.88 h / 9.5% |
| Timestamped rows retained | 49,149 / 168,288 (29.2%) |
| Timestamped CSV bytes retained | 7.76 / 25.86 MB (30.0%) |
| Compact top-ten / serialized full-graph package bytes | 0.458 / 14.012 MB (3.3%) |

Activity is concentrated around alerts, so a 9.5% time footprint still contains 30.0% of timestamped provenance bytes. Selective acceptance cannot reduce acquisition because the gate requires the window before deciding. Retaining only accepted packages would also discard refusal evidence; the supported claim is compact analyst serialization and bounded alert-centered retention, not permission to delete raw evidence.

# S16. Reusable evaluation protocol and operator policy

**Table S24. Proposed cross-dataset EviGate-APT evaluation interface.** The last column distinguishes an executable requirement from the limitation of the only tested instantiation, CICAPT-IIoT; portability is a design target, not an empirical result.

| Contract item | Required invariant | CICAPT-IIoT realization / surfaced boundary |
|---|---|---|
| Trigger | Investigation begins from an independently observed network decision | Nonoverlapping 60-s traffic windows; host truth is excluded from Stage A |
| Evidence scope | The trigger opens a declared, bounded second-view context | Full $\pm5$-min provenance graph; author-described packet/process labeling and post-hoc audits support host co-membership for 32/53 in-support events; direct packet-to-PID causality is not tested |
| Split unit | Evidence that can overlap at inference cannot cross train/test boundaries | Overlapping contexts form 46 indivisible embargo groups |
| Truth isolation | Labels, malicious process IDs, and evaluation-only time cannot enter inference | Separate input/truth JSONL files plus executable leakage assertions |
| Output and denominator | Every event terminates in `no_alert`, `alert_unattributed`, or `alert_attributed`; oracle-entry and end-to-end results are separate | 51-event non-pilot end-to-end cohort and 53-event oracle-entry cohort |
| Failure probes | Collection and membership failures are declared before comparison | Five deterministic corruption families plus natural overlapping contexts |
| Audit trail | Models, thresholds, data transforms, and outputs are hashable and checkable | Split, feature, schema, reference, donor, and metric assertions with manifests |

This contract specifies what a compatible benchmark must expose; it does not imply that every dataset can validate host-level binding. A future corpus with explicit host identifiers can reuse the same trigger, split, package, output, and corruption interfaces while upgrading the membership claim.

**Table S25. Stage-A coverage--retention frontier.** Thresholds are learned independently within each calibration fold. Retention consists of merged $\pm5$-min intervals around all held-out alert windows and includes refusals. Byte fractions cover timestamped provenance rows only.

| Requested budget (false alerts/h) | Observed Phase 2 false alerts/h | All-event coverage | Alert windows | Merged retention (h / capture) | Timestamped CSV bytes retained |
|---:|---:|---:|---:|---:|---:|
| 0.5 | 0.134 | 0.697 | 60 | 6.88 / 9.5% | 30.0% |
| 1.0 | 0.134 | 0.714 | 61 | 7.05 / 9.8% | 30.2% |
| 2.0 | 0.293 | 0.747 | 73 | 7.88 / 10.9% | 30.9% |
| 5.0 | 1.830 | 0.800 | 183 | 15.83 / 22.0% | 38.5% |

The four points support a bounded operator policy rather than a universal optimum. First choose the Stage-A budget under the deployment's coverage, alert-rate, and retention constraints; the 0.5 point remains the paper's fixed primary setting. Preserve the opened evidence for both attributed and unattributed alerts. Conditional on oracle entry, choose full EviGate-Bind over calibrated margin when the abstention-to-wrong-label cost ratio is below 0.40, or when accepting foreign evidence costs more than abstention; otherwise the margin comparator is cheaper on the declared clean-event loss. These boundaries are empirical for this cohort and must be recalibrated after a domain shift.

**Table S26. Frozen contracted-LLM verifier-failure taxonomy.** Each row contains 53 packages. Counts are outputs violating at least one obligation in the named category; categories overlap, so they do not sum to “any error.” This is a post-freeze descriptive audit, not a revised hypothesis or model run.

| Package family | Contract-valid | Any verifier error | Evidence-sufficiency obligation | Missing-process refusal | Reference / ownership | Decision / schema |
|---|---:|---:|---:|---:|---:|---:|
| Clean | 31 | 22 | 19 | 0 | 0 | 3 |
| Context replacement | 40 | 13 | 12 | 0 | 0 | 1 |
| Process deletion | 0 | 53 | 52 | 53 | 0 | 1 |
| Random entity deletion | 35 | 18 | 17 | 0 | 0 | 2 |
| Socket-type deletion | 29 | 24 | 22 | 0 | 0 | 2 |
| $+600$-s time shift | 23 | 30 | 27 | 0 | 1 | 2 |

All 954 outputs parse as JSON, so parser failure does not explain the contracted reviewer's refusals. Its dominant failures concern whether an issued attribute has observed sufficient support; missing-process corruption is qualitatively different because every package violates the explicit refusal obligation. Context replacement is often locally coherent and therefore has fewer verifier errors than clean data, illustrating why package-local validity cannot prove incident membership. Complete multi-label counts for all three frozen variants are in `data/derived/llm_failure_taxonomy/`.

## S16.1 Frozen certificate examples

The following hash-indexed examples are selected deterministically from the frozen contracted outputs: the first contract-valid clean output whose tactic matches the evaluation sidecar, and the first contract-invalid process-deletion output. Evaluation-only truth is shown here for audit and is not part of the inference record. The complete machine-readable extraction is `data/derived/llm_failure_taxonomy/llm_certificate_examples.json`.

**Valid clean certificate (`sample_26fc1230603a811c2fcd`).** The machine proposal and evaluation-only tactic are both `discovery`. The cited process resolves to rank-1 `sh` (`/usr/bin/dash`, ranker score 0.980441); its four cited anchors resolve to identity, temporal proximity (31.036 s), topology, and `execve` operation facts.

```json
{
  "tactic": "discovery",
  "evidence_sufficient": true,
  "integrity_alarm": false,
  "support_process_ref": "P1",
  "cited_anchor_ids": [
    "P1.identity", "P1.temporal", "P1.topology", "P1.operation"
  ],
  "reason_codes": ["sufficient_observed_support"]
}
```

The verifier returns `attribute`, with `contract_valid=true` and no errors. This is referential validity plus an evaluation-sidecar correct label; it is not packet-to-process causal proof.

**Invalid process-deletion certificate (`sample_0456635a4381dc052e98`).** The package presents no process candidate. The generated record recognizes insufficient process evidence but leaves `integrity_alarm=false`:

```json
{
  "tactic": "collection",
  "evidence_sufficient": false,
  "integrity_alarm": false,
  "support_process_ref": null,
  "cited_anchor_ids": [],
  "reason_codes": ["insufficient_process_evidence"]
}
```

The verifier overrides this to `abstain` with an integrity alarm and records `attribute_without_observed_anchor`, `attribute_without_sufficiency`, and `missing_process_without_integrity_alarm`. The pair illustrates the operational role of the certificate: fields and anchors can be inspected and deterministically checked, while readability or analyst benefit is not inferred without a user study.

# S17. Additional post-freeze diagnostics

**Table S27. Frozen Stage C full-coverage confusion counts over all 53 in-support events.** Columns are predicted tactics; rows are evaluation-only union-derived truth. This is the unrejected classifier before the 51-event LLM/binding exclusions.

| True tactic | Collection | Command and Control | Credential Access | Discovery | Exfiltration | Total |
|---|---:|---:|---:|---:|---:|---:|
| Collection | 22 | 0 | 1 | 2 | 1 | 26 |
| Command and Control | 0 | 3 | 0 | 2 | 0 | 5 |
| Credential Access | 3 | 1 | 0 | 3 | 0 | 7 |
| Discovery | 2 | 0 | 1 | 8 | 0 | 11 |
| Exfiltration | 2 | 1 | 0 | 1 | 0 | 4 |

The diagonal sums to 33/53, giving the reported 0.62 full-coverage accuracy. The matrix comes from `data/derived/stage4_revision/diagnostics/stage4_full_coverage_confusion.csv`; selective results have different denominators and must not be read from this table.

\newpage

**Table S28. Post-freeze clean-versus-foreign score discrimination.** Each of the 51 non-pilot events contributes one clean and one deterministic different-tactic donor-replacement package. The same frozen fold-specific BindGate scores and thresholds used in the main evaluation are applied without refitting. AUROC describes score ordering, not evidence that a true cross-host mismatch can be identified.

| Evaluation set | Paired events | Score AUROC ↑ | Clean binding pass | Foreign binding alarm | Clean cascade accepted | Foreign cascade accepted |
|---|---:|---:|---:|---:|---:|---:|
| Outer fold 1 | 16 | 0.633 | 13 | 8 | 12 | 8 |
| Outer fold 2 | 18 | 0.790 | 14 | 12 | 10 | 2 |
| Outer fold 3 | 17 | 0.647 | 17 | 4 | 11 | 8 |
| Pooled diagnostic | 51 | 0.692 | 44 | 24 | 33 | 18 |

Fold-specific scores are not established as calibrated across folds, so the pooled AUROC is descriptive. Foreign cascade acceptance is 18/51, and 17 of those accepted packages receive a wrong label (0.944 conditional wrong-label risk). The binding alarm alone fires for 24/51 foreign packages; the downstream cascade also applies margin, certificate, and temporal checks. The machine-readable audit is `data/derived/p1_diagnostics/gate_discrimination.json`, produced by `scripts/analyze_evigate_p1_gate_discrimination.py` from the frozen per-case CSV.

**Table S29. Post-freeze signed clock-offset audit over the same 51 non-pilot events.** Thresholds and models remain fixed. The primary path reuses each frozen clean LLM decision and requires its support entity in the shifted top-ten package; this isolates verifier sensitivity and is not a fresh LLM run. Each cell reports accepted / correct / wrong, followed by wrong / accepted clean risk.

| Offset | EviGate-Bind accepted / correct / wrong | EviGate-Bind risk | Calibrated margin accepted / correct / wrong | Calibrated margin risk |
|---:|---:|---:|---:|---:|
| $-120$ s | 38 / 27 / 11 | 0.289 | 41 / 29 / 12 | 0.293 |
| $-30$ s | 38 / 27 / 11 | 0.289 | 39 / 28 / 11 | 0.282 |
| 0 s | 33 / 25 / 8 | 0.242 | 38 / 28 / 10 | 0.263 |
| $+30$ s | 30 / 20 / 10 | 0.333 | 40 / 29 / 11 | 0.275 |
| $+120$ s | 30 / 22 / 8 | 0.267 | 38 / 25 / 13 | 0.342 |

The response is non-monotone and the clean-risk advantage at zero offset does not persist at either 30-s shift: margin has lower risk at both $-30$ s and $+30$ s, although coverage also changes. This supports a time-alignment requirement, not a robust drift-tolerance claim. Only clean packages were shifted; the three-family and foreign-context integrity contrasts under clock skew remain unmeasured. The complete fixed-threshold and CPU-only clean results, including input hashes, are in `data/derived/clock_drift/evaluation/clock_drift.summary.json`.

**Table S30. Post-freeze Stage-B benign-candidate stress.** A frozen outer-fold Logistic ranker is scored after one all-benign Phase 1 provenance window is projected into each held-out Phase 2 alert; its original features, training data, labels, and test truth remain unchanged. Each row covers the same 59 events (58 with a truth process already in the candidate set). Random MRR is the analytic expectation for the enlarged candidate pools.

| Phase 1 donor load | Added processes, median [range] | Total candidates, median | Typed Logistic MRR | Typed Logistic R@1 | Typed Logistic R@10 | Recency+degree MRR | Random MRR |
|---|---:|---:|---:|---:|---:|---:|---:|
| None | 0 [0, 0] | 14 | 0.952 | 0.949 | 0.966 | 0.198 | 0.412 |
| Small | 8 [6, 12] | 23 | 0.927 | 0.898 | 0.966 | 0.111 | 0.313 |
| Busy | 80 [79, 94] | 98 | 0.783 | 0.729 | 0.915 | 0.087 | 0.120 |

Of 63 edge-timestamp quantiles, 52 yield nonoverlapping eligible ±300-s Phase 1 windows: 42 have 5--12 processes and six have 50--120. A case-ID-and-band hash selects one wholly benign donor without inspecting truth. Four alternate deterministic hash assignments, with no model refit, give busy-window MRR 0.760--0.849, R@1 0.695--0.814, and R@10 0.915--0.966 across all five assignments. Relative times preserve within-window order but do not represent naturally co-observed workloads. Donor socket matches use only the alert's released top-five addresses and ports, potentially making rejection easier than with complete flow fields. The primary busy assignment moves 13 more events away from rank one while preserving 54/59 R@10 hits. This is **synthetic** candidate-set enlargement, not proven real multi-host robustness. Per-case indices, hashes, and scores are in `data/derived/p1_diagnostics/benign_distractors/`; the generating script is `scripts/audit_stage_b_benign_distractors.py`.

# References

\small
