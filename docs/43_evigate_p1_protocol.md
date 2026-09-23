# P1 Protocol: Cross-View Ablation, Decision Cost, and Deployment Boundaries

Date frozen: 2026-09-17

## 1. Purpose

This post-freeze analysis tests whether the CICAPT-IIoT BindGate result depends
on the network-side tactic posterior, on either view alone, or on genuine
cross-view interactions. It also translates the selective outputs into an
explicit wrong-attribution-versus-abstention cost analysis. No test corruption
is used to fit a model or choose a threshold.

## 2. Cohort, splits, and constants

- Retained clean cohort: 51 events after the two frozen exclusions.
- Outer split: the existing three grouped temporal folds.
- Hard negatives: the existing nearest same-tactic and nearest
  different-tactic training donors.
- BindGate threshold: group-cross-fitted clean-pair scores in the outer
  training partition, targeting 0.90 clean-pair retention.
- Joint margin threshold: outer-training clean events only, targeting 0.67
  clean coverage after the certificate and binding obligations.
- Temporal obligation: a process candidate exists and the top-three mean time
  proximity is positive.
- Random seed: 20260916; bootstrap unit: event cluster; 10,000 replicates.

## 3. Prespecified feature modes

1. **Full:** all cross-view posterior, raw summary, and summary-interaction
   features used by the existing BindGate.
2. **Without network posterior:** removes network posterior confidence, margin,
   entropy, class probabilities, and all pairwise posterior agreement terms;
   retains identity-free raw network summaries, provenance features, and raw
   cross-summary interactions.
3. **Network only:** retains only network posterior and network-summary
   features. Because swapping provenance leaves these features unchanged, this
   is a negative control rather than a deployable compatibility gate.
4. **Provenance only:** retains only provenance posterior and
   provenance-summary features. It tests whether provenance plausibility alone
   explains mismatch rejection.

The primary diagnostic is context-replacement wrong-label rate. Secondary
diagnostics are clean acceptance, clean selective risk, five-family macro
wrong-label rate, and synthetic same-/different-tactic context alarm rates.
The full mode is favored only if it improves mismatch handling without relying
solely on a single view; no superiority claim will be based on clean accuracy
alone.

## 4. Decision-cost analysis

Wrong issued labels have unit cost. Abstention has relative cost
`c in [0,1]`. For clean oracle-entry events, normalized cost is
`(wrong + c * abstained) / 51`. EviGate-Bind is compared with the
training-calibrated posterior-margin baseline and the count-matched margin
baseline. For foreign-context packages, any issued label is counted as an
evidence-integrity failure irrespective of whether its tactic happens to match
the original event; cost is `(issued + c * abstained) / 51`. Break-even points
are reported algebraically and from the exported grid. This is a transparent
decision analysis, not a learned utility model.

## 5. Provenance and hardware boundaries

The CICAPT-IIoT paper places Auditd/SPADE on the Ubuntu VM1 gateway. The
released `Phase2_Provenance.csv` contains no hostname or device identifier and
its `source` column is uniformly `syscall`; therefore the analysis will describe
these records as gateway/host provenance, not per-PLC or per-sensor telemetry.

The available machine is an HP Z8 G4 with an Intel Xeon Silver 4215R, 137 GB
RAM, and an RTX A6000. No Raspberry Pi or Jetson is attached. Workstation timing
may be reproduced, but it will not be relabeled as an embedded-device benchmark.
Actual edge timing remains an author-input item until named edge hardware is
available.

## 6. Reproducibility rule

Each feature mode is written to a separate output directory. The command, input
hashes, feature mode, fold thresholds, per-event decisions, synthetic binding
audit, summary, and output SHA-256 hashes are retained. Unit tests must pass
before and after the runs. Manuscript text will report unsupported or negative
outcomes without suppression.
