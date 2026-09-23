# Aggregate results in this code release

The `results/` directory provides compact, machine-readable summaries from the authors' audited workspace:

| File | Role |
|---|---|
| `stage_a_summary.json` | Network-alert detection and calibration |
| `stage_b_summary.json` | Typed process retrieval |
| `stage_c_summary.json` | Tactic classification and conventional selection |
| `evigate_bindgate_summary.json` | Post-freeze cascade, corruption, and context-replacement comparisons |
| `feature_ablation_summary.json` | BindGate feature-family and component ablations |
| `host_link_summary.json` | Post-freeze endpoint/socket host-link checks |
| `clock_drift_summary.json` | Clean-only signed clock-offset stress; **not** a corruption-under-skew result |
| `full_workspace_integrity_audit.json` | Claim-to-artifact audit from the complete source workspace |

These summaries contain no third-party raw CSV or full per-case provenance packages. They permit inspection of reported aggregates and source hashes, but not independent recomputation of every metric. For that, obtain the source data, regenerate the derived packages, and run the evaluators. The manuscript and selected protocol documents identify which comparisons were frozen and which were exploratory.
