# P1 Results: Bounded Signed Relative Clock Drift

## Execution status

The protocol in `docs/45_evigate_clock_drift_protocol.md` was frozen before
execution.  Raw CICAPT-IIoT Phase-2 provenance was rebuilt at `-120`, `-30`,
`0`, `+30`, and `+120` seconds relative to the unchanged network anchors.  All
trainable components and thresholds were fitted on unshifted outer-training
events only.  No new LLM inference was performed.

The zero-offset row reproduced both published clean operating points exactly:

- full EviGate-Bind: 33/51 accepted, 25 correct, 8 wrong;
- training-calibrated margin plus structural rules: 38/51 accepted, 28
  correct, 10 wrong.

## Results

Each `accepted/correct/wrong` cell uses the fixed 51-event denominator.

| Provenance offset | Fixed-review EviGate-Bind | CPU BindGate cascade | Calibrated margin + rules | BindGate pass | Support entity retained / 43 positive certificates |
|---:|---:|---:|---:|---:|---:|
| -120 s | 38 / 27 / 11 | 38 / 29 / 9 | 41 / 29 / 12 | 47 | 42 / 43 |
| -30 s | 38 / 27 / 11 | 37 / 28 / 9 | 39 / 28 / 11 | 48 | 43 / 43 |
| 0 s | 33 / 25 / 8 | 32 / 25 / 7 | 38 / 28 / 10 | 44 | 43 / 43 |
| +30 s | 30 / 20 / 10 | 29 / 21 / 8 | 40 / 29 / 11 | 38 | 43 / 43 |
| +120 s | 30 / 22 / 8 | 32 / 21 / 11 | 38 / 25 / 13 | 43 | 42 / 43 |

All 51 events pass the positive-temporal-proximity obligation at every bounded
offset.  The original `+600 s` family is therefore a mechanical missing-time
test and cannot stand in for realistic drift.  Within the window, drift acts
through context turnover, process ranking, proposal margin, and learned
compatibility rather than the hard temporal rule.

The response is directional and non-monotone.  Across offsets `-120`, `-30`,
`0`, `+30`, and `+120` seconds, fixed-review EviGate-Bind selective risk is
0.289, 0.289, 0.242, 0.333, and 0.267; calibrated-margin risk is 0.293,
0.282, 0.263, 0.275, and 0.342.  Both methods are sensitive to drift, but
EviGate-Bind degrades more at `-30` and `+30` seconds.  Its zero-offset
clean-risk advantage is therefore not robust to a 30-second clock error.
The reversal at the larger signed offsets also rules out a monotone tolerance
claim.

Under the primary fixed-review path, acceptance ranges from 30 to 38, correct
issued labels from 20 to 27, and wrong labels from 8 to 11. The original
support entity remains in the shifted top ten for 42--43 of the 43 positive
certificates, so certificate-reference loss is not the main mechanism. The
defensible conclusion is bounded sensitivity, not invariance: the pipeline
remains operational under the tested offsets, but time synchronization is a
deployment precondition.

## Reproduction and validation

The evidence packages and evaluation were generated twice.  The two runs are
byte-identical for both JSONL manifests, the per-case CSV, and the summary JSON.

- drift input packages: `A9F01CFB3250D6F4781CF77089120D973AC8A34DC244719A1E79724C38380D5D`
- drift truth sidecar: `438296611C820F57B39153C9248637BFA953944DB32AF482B9D68EA0A52C52CF`
- per-case decisions: `DA8676B10D23A899241EEE0CBE66852B08D3A5D60BCA08DE8BD3560A5A083411`
- summary: `3078AFF726FC1257D3B39AF6459101BB49F356A36719B0F890F52CDF7D13402C`

Focused unit tests cover the signed offset transform, package-local support
entity resolution, and metric denominators.  The full repository suite is run
after manuscript integration.

## Claim boundary

This is a post-freeze stress test on one public campaign.  It does not measure
trusted clock synchronization, adversarial timestamp tampering, or performance
on an edge board.  Holding the frozen clean language-review judgment fixed
isolates verifier sensitivity; it is not equivalent to rerunning the LLM on
each shifted package.
