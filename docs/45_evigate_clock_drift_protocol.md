# P1 Protocol: Bounded Relative Clock-Drift Stress Test

**Status:** frozen before the first bounded-drift run.  
**Analysis class:** post-freeze robustness analysis; it is not a prespecified
confirmatory endpoint and does not replace the original `+600 s` corruption.

## Question

How sensitive are the frozen EviGate-Bind decisions to realistic, signed
network--provenance clock offsets that remain inside the declared
`+/-300 s` retrieval radius?

## Perturbations

The public CICAPT-IIoT Phase-2 network window and event truth are held fixed.
The provenance clock is shifted by

`delta in {-120, -30, 0, +30, +120} seconds`.

For an original provenance relation time `u` and network anchor `t`, the
shifted relative time is `(u + delta) - t`.  The implementation obtains the
same value by rebuilding the raw provenance graph around `t - delta`.  This
recomputes, rather than edits in place:

- which relations and entities fall inside the `+/-300 s` context;
- signed relation deltas and before/after fractions;
- entity and socket temporal proximity;
- typed-process ranking and the top-10 evidence package; and
- the machine tactic proposal and its posterior margin.

Network features, event labels, outer folds, exclusions, and the retrieval
radius are unchanged.

## Frozen training and decision policy

All trainable components are fitted only on the unshifted outer-training
events.  Ranker and tactic models, BindGate feature definition, hard-negative
policy, seeds, and thresholds are unchanged.  No drifted package is used for
fitting, threshold selection, or model choice.

The primary analysis holds each case's previously frozen language-review
decision fixed to isolate clock sensitivity.  A positive certificate remains
eligible only if its original stable support entity is still present in the
shifted top-10 package; its package-local rank is deterministically remapped.
No new LLM inference is performed.  This is a controlled verifier stress test,
not a claim that an LLM would emit identical text after a shifted input.

Two secondary policies are reported:

1. a CPU-only BindGate + calibrated-margin + temporal-admissibility cascade;
2. the original training-calibrated posterior-margin selector with the same
   process-presence and temporal-admissibility rules.

## Cohort and endpoints

The cohort is the same 51 retained non-pilot, in-support events used in the
EviGate-Bind analysis.  For every signed offset and policy, report:

- accepted events and coverage;
- correct accepted labels and unconditional correct-attribution rate;
- wrong labels, wrong-label rate, and selective risk;
- temporal-admissibility pass count;
- BindGate pass count; and
- for the fixed-review cascade, support-entity retention in the shifted top 10.

The zero-offset row must reproduce the published clean result (33 accepted,
25 correct, 8 wrong) before any nonzero result is interpreted.  Directional
asymmetry is reported; `+delta` and `-delta` are never pooled silently.

## Interpretation boundary

This test evaluates relative timestamp robustness in one public campaign.  It
does not validate clock authenticity, NTP/PTP behavior, adversarial timestamp
tampering, provenance collection overhead, or cross-campaign generalization.
Because the candidate graph has a hard `+/-300 s` boundary, the `+/-120 s`
rows also measure legitimate context turnover near that boundary.
