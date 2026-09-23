# EviGate-Bind Post-Freeze Experiment Protocol

## Status and scope

- Status: frozen before inspecting any EviGate-Bind test result.
- Study type: post-freeze exploratory repair of the v6 context-binding failure.
- Public data: CICAPT-IIoT2024 Phase 2 network and provenance views.
- Statistical unit: attack-action cluster.
- Retained test events: 51 after the two previously declared prompt-development exclusions.
- Compute target: one local 7B inference pass plus CPU-only binding and selection models.
- Claim boundary: this experiment may motivate an improved method, but it cannot retroactively change the failed v6 confirmatory hypotheses.

## Research question

Can proposal-locked evidence review and an independently trained cross-view binding gate reduce corrupted-evidence wrong labels while retaining useful clean-event coverage?

## Method frozen for this run

### Proposal-locked reviewer

Stage C supplies the only possible tactic label. The LLM acts as a support auditor rather than a classifier. It must either:

1. return the exact proposal with one package-local process reference and one or more anchors owned by that process; or
2. return JSON `null` for the tactic, no process or anchors, and a declared insufficiency reason.

The v7 prompt adds an explicit output-consistency checklist and generic examples. It does not contain test labels, case identifiers, corruption names, or test outcomes. The deterministic v6 verifier remains unchanged.

### BindGate

For each outer fold, BindGate is trained only with clean events outside that fold. True network--provenance pairs are positive examples. Two deterministic hard negatives are generated for each training event when available:

- the most network-similar different-tactic provenance donor; and
- the most network-similar same-tactic provenance donor from a different event.

The binding features contain network-only and provenance-only tactic posteriors, their agreement/divergence, and identity-free evidence-summary statistics. Test corruptions, test truth, replacement identities, and corruption-family names are not fitting features.

The binding threshold is selected from group-held-out scores within the outer training partition to retain 90% of clean pairs. The final tactic threshold uses Stage C posterior margin and is selected from outer-training clean events only. The target joint clean acceptance is 0.67 where the available certificate and binding passes make that count feasible.

### Decision cascade

An issued label requires all four conditions:

1. Stage C posterior margin passes its fold threshold;
2. the proposal-locked LLM returns an attribution;
3. the deterministic evidence certificate is valid; and
4. BindGate accepts the network--provenance pair.

Otherwise the output is `alert_unattributed`. Integrity alarms remain separate from attribution decisions.

## Frozen evaluation

The following methods use the same 51 events and five corruption families:

1. frozen v6 EviGate-LLM;
2. v7 proposal-locked reviewer without BindGate;
3. v7 reviewer plus the clean-trained BindGate cascade;
4. calibrated posterior margin plus the missing-process rule;
5. fold-stratified posterior margin matched to the cascade's clean acceptance count.

Primary descriptive endpoints are:

- clean coverage and selective risk;
- corruption-macro wrong-label and rejection rates;
- different-tactic context-replacement wrong-label rate;
- all-process-deletion wrong-label and rejection rates.

The harder same-tactic replacement audit is reported separately because it is synthesized after the original manifest and does not provide a Stage C counterfactual proposal.

## Success targets

These are prospective targets for the new exploratory method, not replacements for v6 H1/H2:

- clean coverage at least 34/51 (0.667);
- clean selective risk no greater than 0.333;
- corruption-macro wrong-label rate no greater than 0.200;
- different-tactic context-replacement wrong-label rate below 0.300;
- zero wrong labels under all-process deletion;
- positive paired event-cluster bootstrap interval for the primary corruption reduction against the clean-count-matched margin comparator.

Failure to meet a target is retained and reported. Thresholds or endpoints will not be changed after test evaluation.

## Interpretation boundary

BindGate estimates event-pair compatibility. It does not prove packet-to-process causality, vulnerable-code responsibility, legal admissibility, or cross-campaign generalization. Because the method was designed after v6 test inspection, all v7/BindGate findings remain post-hoc until confirmed on an untouched campaign or dataset.
