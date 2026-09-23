# P1 Results and Validation

Date completed: 2026-09-17

## 1. Decision

The cross-view ablation supports the BindGate mechanism claim within the
post-freeze CICAPT-IIoT cohort. Removing the network tactic posterior degrades
foreign-context and aggregate corruption performance, while either view alone
fails to alarm on the synthetic pair swaps. The result supports a
compatibility-gating contribution; it does not establish packet-to-process
causality, same-incident identity, or deployment generality.

The decision-cost analysis also makes the coverage tradeoff explicit. Full
EviGate-Bind is preferred to the training-calibrated margin policy when the
operational cost of abstaining is below 0.40 times the cost of a wrong label.
For foreign-context integrity, it has lower cost for every abstention cost below
the cost of accepting the foreign package.

An embedded-device latency claim could not be completed because no Raspberry
Pi or Jetson is attached to the available workstation. Workstation timings are
retained and labeled as such; they are not used as a proxy edge benchmark.

## 2. Cross-view feature ablation

All modes use the same 51 events, temporal folds, hard-negative donors,
training-only thresholds, certificate outputs, temporal rule, seed, and 10,000
event-cluster bootstrap draws. Only the BindGate feature contract changes.

| Feature mode | Features | Clean accepted | Clean risk | Five-family macro wrong | Context wrong | Same-/different-tactic synthetic alarm |
|---|---:|---:|---:|---:|---:|---:|
| **Full cross-view** | 92 | 33/51 | **0.242** | **0.114** | **0.333** | 0.255 / 0.314 |
| Without network posterior | 70 | 35/51 | 0.257 | 0.196 | 0.569 | 0.039 / 0.059 |
| Network only | 14 | 36/51 | 0.278 | 0.220 | 0.608 | 0.000 / 0.000 |
| Provenance only | 16 | 36/51 | 0.278 | 0.212 | 0.608 | 0.000 / 0.000 |

Relative to full cross-view BindGate:

- removing the network posterior increases context wrong-label rate by 0.235
  (95% event-cluster bootstrap interval [0.118, 0.353]) and five-family macro
  wrong-label rate by 0.082 [0.051, 0.114];
- network-only increases those rates by 0.275 [0.157, 0.392] and 0.106
  [0.075, 0.141];
- provenance-only increases them by 0.275 [0.157, 0.392] and 0.098
  [0.067, 0.133].

The clean-risk differences are small and their intervals cross zero. The
supported interpretation is therefore specific: network posterior and
cross-view interactions improve mismatch rejection, not clean-label accuracy.
The zero synthetic alarm rates for both single-view controls are expected by
construction because a pair swap cannot alter features computed from only one
side; they validate the negative-control contract rather than demonstrate a
general theorem.

## 3. Decision-cost analysis

Let a wrong issued label cost 1 and an abstention cost `c`, where
`0 <= c <= 1`.

### 3.1 Clean oracle-entry events

| Policy | Wrong | Abstained | Total cost |
|---|---:|---:|---:|
| Full EviGate-Bind | 8 | 18 | `8 + 18c` |
| Count-matched margin | 11 | 18 | `11 + 18c` |
| Training-calibrated margin | 10 | 13 | `10 + 13c` |

Full EviGate-Bind strictly dominates count-matched margin at the same abstention
count. Against the deployable training-calibrated margin policy, the break-even
point solves `8 + 18c = 10 + 13c`, hence `c = 0.40`. Full BindGate has lower
cost below this point; margin has lower cost above it because it correctly labels
three additional events.

### 3.2 Foreign-context integrity

Any label issued from a deliberately replaced provenance package is counted as
an integrity failure, even if its tactic happens to match by chance.

| Policy | Unsafe issued | Abstained | Total cost |
|---|---:|---:|---:|
| Full EviGate-Bind | 18 | 33 | `18 + 33c` |
| Count-matched margin | 47 | 4 | `47 + 4c` |
| Training-calibrated margin | 48 | 3 | `48 + 3c` |

Both comparisons break even only at `c = 1`. Thus, whenever rejecting an
untrusted package costs less than accepting it, the full compatibility gate has
lower integrity cost. The complete 0.00--1.00 grid is exported in
`p1_decision_cost.csv`.

## 4. Provenance-producing host scope

The CICAPT-IIoT paper places Auditd and SPADE on Ubuntu VM1, which acts as the
gateway and MQTT subscriber. In the released `Phase2_Provenance.csv`, all
196,735 rows have `source=syscall`; the schema contains no hostname or device-ID
field. This supports describing the released provenance as gateway/host-level
evidence. It does not support saying that the PLC, sensor, camera, or other IoT
endpoints each ran a provenance agent. The manuscript now states this boundary
explicitly.

## 5. Compute and edge boundary

Available system inventory:

- HP Z8 G4 Workstation;
- Intel Xeon Silver 4215R, 8 physical / 16 logical cores;
- 137 GB RAM;
- NVIDIA RTX A6000, 49 GB VRAM;
- no attached Raspberry Pi or Jetson.

In the P1 workstation runs, the full 92-feature compatibility path had 2.24-ms
median and 3.44-ms p95 wall time over 306 measurements. This is consistent with
the earlier workstation measurement but is not an edge-board result. A genuine
edge measurement requires the named board, OS image, CPU governor, thread
limits, warm-up, repetition count, memory peak, and thermal state. Until then,
the paper retains the deployment claim as CPU-feasible on the measured
workstation only.

## 6. Reproducibility audit

Independent reruns were executed without timing instrumentation. For all four
feature modes:

- `evigate_bindgate.per_case.csv` is byte-identical;
- `evigate_bindgate.synthetic_binding.csv` is byte-identical;
- the JSON summary is structurally identical after removing the nondeterministic
  wall-clock timing object.

Primary deterministic per-case SHA-256 values:

- full: `41626C93CE139048FD2E56BF9573E6B8D531F9F632A594F8A0F2016045E45A14`;
- without network posterior:
  `6F5DCE4A3A4E7D3016E5A07F924A25657974B75C1AC313EE4ACD4082075EB7B6`;
- network only:
  `536B97A238056C0DE38CBE1D59955304E4FB8128F74F5EAD81E8A004D0464627`;
- provenance only:
  `54B5BCA33AAE0698D80952CFE1D08C2A34E1BE4720D660D93DD639E00F01341A`.

The machine-readable outputs are under
`data/derived/evigate_llm/p1_feature_ablation/analysis/`. The full command and
feature definitions are in `docs/43_evigate_p1_protocol.md`.

## 7. Statistical and interpretive audit

The following failure-mode scan was applied:

1. **Pseudoreplication:** event clusters, not rows, are resampled.
2. **Fold-as-sample error:** three folds are not treated as three deployments.
3. **Seed inflation:** one frozen seed defines this diagnostic; no seed rows are
   promoted to independent observations.
4. **Unpaired inference:** all mode differences use matched event clusters.
5. **Post-selection confirmation:** the study is labeled post-freeze and is not
   upgraded by small intervals.
6. **Threshold leakage:** thresholds use outer-training clean cases only.
7. **Corruption leakage:** transformed test packages are never used to fit a
   gate or select a threshold.
8. **Mechanical-win inflation:** the main table reports five families, while
   the paper separately identifies process deletion and time shift as
   deterministically rejected.
9. **Coverage confounding:** clean acceptance is reported with risk, and the
   cost analysis exposes the deployment tradeoff.
10. **Single-view shortcut:** network-only and provenance-only controls are
    included and fail the pair-swap audit as expected.
11. **Causal overreach:** compatibility is not described as packet-to-process
    causality or vulnerability root-cause proof.

## 8. Material passport

- **Primary public data:** CICAPT-IIoT network and provenance archives.
- **External public data:** X-IIoTID, used only for column-partition
  compatibility.
- **P1 cohort:** 51 retained non-pilot CICAPT attack-action clusters; six rows
  per event (clean plus five corruption conditions).
- **Training boundary:** grouped three-fold outer training; no test corruption
  in fitting or threshold selection.
- **Models:** two tactic Logistic regressions and a balanced Logistic BindGate;
  the frozen proposal-locked LLM outputs are reused, not regenerated.
- **Seeds:** evaluator 20260916; P1 bootstrap 20260917--20260920.
- **Uncertainty:** 10,000 event-cluster bootstrap replicates.
- **Hardware:** HP Z8 G4 / Xeon Silver 4215R; timing is workstation-only.
- **Missing material:** named Raspberry Pi/Jetson edge benchmark and per-device
  provenance identifiers are not available.
- **Redistribution:** third-party raw archives remain referenced rather than
  copied into the release; derived artifacts and hashes are retained.
