# EviGate-Bind Post-Freeze Results

Date: 2026-09-16  
Status: exploratory repair completed and byte-reproduced

## 1. Run integrity

- Public evidence manifest: 318 packages from 53 event clusters and five declared corruptions.
- Retained analysis set: 51 clusters after the same two v6 prompt-development exclusions.
- New inference: one proposal-locked contracted variant, 318/318 generations.
- Model: pinned local Qwen2.5-7B-Instruct revision `a09a35458c702b33eeacc393d103063234e8bc28`.
- Prompt SHA-256: `D608967419BC65E95C48CD37151D188F322A7F6168EF6A18148A2516348EB2FD`.
- Test-output SHA-256: `00A9EC968334D1867C242500E8EAE31476FC72FCACDF739DB73BB0946B747E4F`.
- Inference runtime: 980.56 s on one RTX A6000, BF16, batch size three.
- BindGate fitting: CPU-only, three event-grouped outer folds; no test corruption used for fitting or threshold selection.
- Bootstrap: 10,000 paired event-cluster resamples, seed `20260916`.

The full evaluation was repeated into an independent output directory. The
summary, per-case table, and synthetic-pair audit are byte-identical across the
two runs.

## 2. Main result

At the same 33/51 clean accepted events, the EviGate-Bind cascade improves both
clean correctness and corruption robustness relative to the fold-stratified
posterior-margin comparator. The comparator receives the same missing-process
and positive-time-proximity obligations.

| Method | Clean accepted | Clean risk | Clean correct | Corruption-macro wrong | Context-replacement wrong | All-process-deletion wrong |
|---|---:|---:|---:|---:|---:|---:|
| Count-matched margin + structural rules | 33/51 | 0.333 | 22/51 | 0.255 | 0.863 | 0.000 |
| **EviGate-Bind + temporal admissibility** | **33/51** | **0.242** | **25/51** | **0.114** | **0.333** | **0.000** |

The matched-margin-minus-EviGate corruption-macro wrong-label difference is
0.141 with paired event-cluster bootstrap 95% interval [0.102, 0.180]. The
context-replacement difference is 0.529, 95% interval [0.392, 0.667]. The clean
risk reduction is 0.091, but its interval [−0.009, 0.204] includes zero; the
clean result is therefore supportive rather than confirmatory.

## 3. Component ablation

| Configuration | Clean accepted | Clean risk | Corruption-macro wrong | Context wrong |
|---|---:|---:|---:|---:|
| Frozen v6 EviGate-LLM | 30/51 | 0.333 | 0.271 | 0.686 |
| Frozen v6 + posterior-affinity gate | 25/51 | 0.280 | 0.180 | 0.392 |
| v7 proposal-locked reviewer only | 43/51 | 0.349 | 0.333 | 0.647 |
| v7 + learned BindGate | 33/51 | 0.242 | 0.169 | 0.333 |
| **v7 + BindGate + temporal admissibility** | **33/51** | **0.242** | **0.114** | **0.333** |

The v7 contract correction raises clean certificate coverage from 30 to 43
events, but is unsafe by itself. The learned binding and margin cascade removes
ten clean attributions and seven clean errors. Temporal admissibility then
removes every +600-second attribution without changing a clean decision.

## 4. Mechanism-specific results

| Evidence condition | EviGate-Bind accepted | EviGate-Bind wrong/all | Matched margin accepted | Matched margin wrong/all |
|---|---:|---:|---:|---:|
| Clean | 33 | 8/51 (0.157) | 33 | 11/51 (0.216) |
| All-process deletion | 0 | 0/51 (0.000) | 0 | 0/51 (0.000) |
| Socket-type deletion | 33 | 8/51 (0.157) | 31 | 11/51 (0.216) |
| +600-second time shift | 0 | 0/51 (0.000) | 0 | 0/51 (0.000) |
| Half-process deletion | 11 | 4/51 (0.078) | 28 | 10/51 (0.196) |
| Different-tactic context replacement | 18 | 17/51 (0.333) | 47 | 44/51 (0.863) |

The cascade is no worse than the strengthened comparator in any declared
corruption family and has lower observed wrong-label rate in socket deletion,
half-process deletion, and context replacement. Zero wrong labels for the two
complete-integrity failures are achieved by rejection, not correct tactic
classification.

## 5. Frozen target accounting

The original v7 target table is retained without reinterpretation:

| Target | Result | Status |
|---|---:|---|
| Clean coverage at least 34/51 | 33/51 | Missed by one event |
| Clean risk at most 0.333 | 0.242 | Met |
| Corruption-macro wrong at most 0.200 | 0.114 | Met |
| Context-replacement wrong below 0.300 | 0.333 | Missed by two events |
| Zero wrong labels after all-process deletion | 0.000 | Met |

The paper must not claim that every absolute exploratory target was met. The
strongest positive result is instead the exact-count comparison: at identical
clean acceptance, the cascade reduces the corruption macro by 0.141 with an
interval fully above zero and reduces context-replacement wrong labels by
0.529.

## 6. Residual boundary

The binding-only synthetic audit rejects 31.4% of network-similar
different-tactic replacements and only 25.5% of same-tactic replacements. The
full cascade is substantially safer because certificate validity and posterior
margin reject additional cases, but 17/51 different-tactic replacements still
receive an incorrect label. The system therefore mitigates rather than solves
incident membership. Same-tactic context binding remains the most important
unresolved problem and cannot be presented as causal packet-to-process
attribution.

## 7. Reproduction

```powershell
.venv\Scripts\python.exe scripts\evaluate_evigate_bindgate.py `
  --inputs data\derived\evigate_llm\manifest_v4\evigate_llm.inputs.jsonl `
  --truth data\derived\evigate_llm\manifest_v4\evigate_llm.truth.jsonl `
  --llm-outputs data\derived\evigate_llm\v7_bindgate\test_outputs.jsonl `
  --output-dir data\derived\evigate_llm\v7_bindgate\evaluation_temporal `
  --target-binding-retention 0.9 `
  --target-clean-coverage 0.67 `
  --require-positive-time-proximity `
  --bootstrap-replicates 10000 `
  --seed 20260916
```

Artifact hashes:

- `evigate_bindgate.per_case.csv`: `3C778176C7CEE2D5F9F6BF4D6797CD7FFF85301246431AC9A676E63F01FF34DE`
- `evigate_bindgate.summary.json`: `4A096E4638E5310D3EC0A198183921A3B49FB68EAC6191BD42275ADFE6F52381`
- `evigate_bindgate.synthetic_binding.csv`: `310AC2150E3BDAC7DAADBB6CDF628CC8B8C5FF4480B2D44C5DCB8EC01BDA9125`

## 8. Claim boundary

The defensible new claim is:

> At equal clean acceptance, a proposal-locked certificate, clean-trained
> cross-view binding gate, and deterministic temporal admissibility check reduce
> corruption-macro and foreign-context wrong labels relative to a strengthened
> posterior-margin selector within CICAPT-IIoT.

The result is post-freeze and single-campaign. It does not retroactively rescue
the failed v6 hypotheses, establish universal superiority, or prove causal
network-to-process responsibility.

## 9. Post-freeze component ablations

The following diagnostics were run after the primary repair was frozen. Every
row was matched to the original cascade's clean counts in the three outer folds
(12, 10, and 11; 33 total), and every row used the same missing-process and
positive-time-proximity obligations.

| Configuration | Clean risk | Five-family macro wrong | Context wrong |
|---|---:|---:|---:|
| Count-matched margin + structural rules | 0.333 | 0.255 | 0.863 |
| BindGate + margin + temporal, no LLM | 0.242 | 0.129 | 0.431 |
| Proposal-locked LLM + same-tactic-only BindGate | 0.273 | 0.161 | 0.471 |
| **Full EviGate-Bind** | **0.242** | **0.114** | **0.333** |

The full LLM cascade reduces context wrong labels by 0.098 relative to the
count-matched no-LLM cascade (95% CI [0.020, 0.196]). Its additional macro
reduction is 0.016 with interval [−0.004, 0.035], so the supported incremental
LLM claim is context-specific. Training with same-tactic hard negatives only
still reduces context errors by 0.392 [0.255, 0.529] relative to matched margin,
retaining 74.1% of the full context improvement. Adding different-tactic hard
negatives supplies another 0.137 [0.059, 0.235].

The +600-second transformation sets the same time-proximity signal used by the
temporal rule to zero, so its perfect rejection is true by construction. After
removing that family, full EviGate-Bind has four-family macro wrong-label rate
0.142 versus 0.319 for matched margin, a paired reduction of 0.176 with 95%
interval [0.127, 0.225]. The robustness result therefore survives removal of
the mechanically rejected family.

The test context-replacement donor is selected from sorted outer-training
different-tactic cases by a deterministic case-hash index; it is not the
network-nearest donor. The BindGate training negatives nevertheless overlap
conceptually with that test family, so the paper now labels context replacement
as mechanism-aligned rather than unseen.

Reproduced artifact hashes:

- full-ablation per-case: `41626C93CE139048FD2E56BF9573E6B8D531F9F632A594F8A0F2016045E45A14`
- same-tactic-only per-case: `7D04933643098FCB6BDF8CF048517894ABCCB0BCBD2BD391076B6F7BEB367D05`
- integrated summary: `CD87BE72FC529B11A307FE93D2BC2AB1F7E733DCA5D72409D38348AA5AC9A237`
