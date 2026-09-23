---
title: "EviGate-APT: A Failure-Aware Cross-View Evidence-Binding Protocol for IIoT Network Forensics"
author:
  - "Anonymous Author(s)"
bibliography: ../references/references.bib
date: 2026-09-19
---

# EviGate-APT: A Failure-Aware Cross-View Evidence-Binding Protocol for IIoT Network Forensics

## Abstract

An IIoT network alert does not identify which host process supports an incident interpretation, and a structurally valid provenance package may belong to another event. EviGate-APT formalizes this context-binding gap as a reproducible public-data evaluation protocol with independent network triggering, alert-opened evidence, grouped splits, truth-isolated packages, and three-state outputs. On 53 CICAPT-IIoT attack-action clusters, typed process retrieval reaches 0.95 midrank MRR. A frozen LLM certificate check reduces forced-generator corruption wrong labels from 0.529 to 0.271 but misses its prespecified superiority and coverage criteria. A subsequent post-freeze compatibility cascade is evaluated at matched 33/51 clean acceptance: relative to posterior margin with identical structural rules, it reduces wrong labels over three nonmechanical corruption families from 0.425 to 0.190 and over foreign-context replacements from 0.863 to 0.333, primarily by refusing mismatched evidence. An alert-budget analysis connects coverage to provenance-retention cost. This audited case study concerns evidence sufficiency within one public campaign; it does not test direct packet-to-PID causality or cross-campaign generalization.

**Index Terms—**Industrial Internet of Things, network forensics, advanced persistent threat, data provenance, selective prediction, evidence integrity, explainable artificial intelligence.

## 1. Introduction

Edge-intelligent IIoT systems increasingly combine networked sensors, controllers, gateways, and host software whose failures are difficult to reconstruct after an incident. Network telemetry may be the most consistently available evidence source, yet a suspicious flow does not identify the responsible process or justify a behavioral label. Conversely, host provenance describes process, file, and socket interactions but may be incomplete, temporally misaligned, or unrelated to the observed traffic. Treating both views as a synchronized feature table can therefore produce precise-looking conclusions unsupported by the collected evidence.

This problem differs from ordinary multimodal intrusion detection. A detector asks whether an event is malicious; a forensic workflow must also decide whether the retained evidence supports a more specific interpretation. We call the gap between package-local validity and evidence belonging to the triggering incident the **context-binding gap**. Thus `alert_unattributed` is operationally distinct from both `no_alert` and an issued tactic. Recent work provides strong traffic detection on CICAPT-IIoT [@li2026tracp; @akpaku2026tipsogan], fuses PCAPs and logs [@niknami2025transids], reconstructs attacks from provenance [@cheng2024kairos; @zhang2025tapas; @jiang2025orthrus], and adds LLM narratives [@aly2025ocrapt; @pletzer2026attackpath]. It does not test whether provenance retrieved after an independently observed network event is sufficient to issue a machine-checkable tactic certificate when evidence is missing, shifted, or drawn from another event.

EviGate-APT formulates this boundary as a public-data evaluation protocol and instantiates it on CICAPT-IIoT [@ghiasvand2024cicapt]. A 60-s network detector opens an investigation; a typed retriever ranks processes in a ±5-min provenance context without identity or truth features; and a tactic classifier proposes a label from normalized process evidence. An optional LLM reviews the proposal and must cite one package-owned process plus owned evidence anchors. A deterministic verifier checks the certificate. The post-freeze EviGate-Bind cascade is one low-capacity repair that additionally enforces posterior margin, temporal admissibility, and clean-trained network--provenance compatibility. Ground truth remains in a separate evaluation sidecar.

The study asks whether this design (RQ1) provides usable network entry and process localization, (RQ2) separates clean-error selection from evidence integrity, (RQ3) benefits from a verifiable LLM certificate, and (RQ4) improves robustness after the observed certificate failure. It contributes:

1. a reusable evaluation protocol for three-state, network-triggered forensics, with explicit oracle-entry and end-to-end denominators, grouped evidence windows, controlled failures, and truth-isolation assertions;
2. an audited public-data instantiation that exposes graph-size effects, evidence-retention costs, and distinct clean-error, reference-validity, and incident-compatibility targets;
3. a post-freeze low-capacity compatibility repair and cost-aware operating policy, with the optional LLM retained as a controlled negative finding rather than assumed evidence of correctness.

The work targets network-initiated acquisition, inspectable triage, public benchmarking, and an edge-oriented CPU path. Timing is server-class only; no embedded-device result is claimed.

## 2. Related Work and Task

Whole-system provenance research spans alert triage in NoDoze, suspicious-flow correlation in HOLMES, tactical endpoint investigation in RapSheet, CTI-to-audit graph alignment in POIROT, and sequence-based reconstruction in ATLAS [@hassan2019nodoze; @milajerdi2019holmes; @hassan2020rapsheet; @milajerdi2019poirot; @alsaheel2021atlas]. KAIROS, TAPAS, ORTHRUS, and online NODLINK score anomalous events or reconstruct compact attack subgraphs [@cheng2024kairos; @zhang2025tapas; @jiang2025orthrus; @li2024nodlink]. A unified evaluation warns that complex provenance IDSs do not necessarily improve practical utility [@bilot2025simpler], while KnowHow maps provenance activity to higher-level CTI techniques [@meng2026knowhow]. These systems begin from host events, CTI patterns, or provenance graphs. EviGate-APT instead begins from an independent traffic event and asks whether retrieved process evidence justifies issuing a tactic.

Network-centric forensic readiness and uncertainty-aware edge detection provide complementary starting points. ProvThings instruments IoT applications and device APIs to recover cross-device activity, whereas OmegaLog reconciles application and system-layer logs on a host [@wang2018provthings; @hassan2020omegalog]. Palmese *et al.* move acquisition into a forensic-ready Wi-Fi access point and quantify processing and storage costs [@palmese2023forensic]. IoTSecUT models uncertainty in IoT intrusion classification [@mengara2024iotsecut], while Think Fast couples a lightweight edge detector with LLM-generated threat analysis [@jamshidi2026thinkfast]. EviGate-APT treats a traffic alert as an investigation anchor and tests whether a separately collected provenance view supports the ensuing process-grounded claim. Its unsigned record addresses inspectable incident-response evidence, not legal admissibility or custody as defined by operational guidance [@kent2006forensics].

Language models have also been used to embed provenance descriptions, reconstruct narratives, and generate investigation reports [@zuo2025semanticapt; @aly2025ocrapt; @pletzer2026attackpath]. Such prose can aid an analyst but is not itself an evidence guarantee. Work on citation-grounded generation similarly motivates separating a generated claim from references that can be checked independently [@gao2023citations]. We therefore evaluate optional language review through a compact certificate rather than an unrestricted narrative; the verifier operates on package-local identifiers without another language model, and failure of the language-layer hypotheses is retained as a result.

Multi-view IDSs fuse complementary representations of one observation, including multiple views within provenance graphs [@yang2026provfusion], while out-of-distribution detection asks whether a sample departs from a training distribution [@hendrycks2017baseline]. Our compatibility component, BindGate (Section 3.2), instead scores whether two independently collected views form a coherent pair and evaluates constructed pair mismatches; it is neither generic sample-level OOD detection nor conventional feature fusion.

Selective prediction adds a reject option to a classifier [@geifman2017selective; @geifman2019selectivenet]. In forensics, however, a rejector should respond to evidence integrity as well as prediction confidence. Explanation audits likewise distinguish model dependence from causal responsibility [@maseno2026xaiaudit]. We therefore test both: selective risk measures wrong issued labels, whereas process deletion measures whether the returned entities influence the classifier. Neither establishes that a process caused the packet stream.

Let $X_t^N$ be a 60-s network window and $G_{t,\Delta}^P=(V,E)$ the typed provenance graph from $[t-\Delta,t+\Delta]$, with $\Delta=300$ s. Stage A returns `no_alert` below its calibrated threshold. Otherwise Stage B ranks $v\in V_{proc}$, and Stage C estimates a posterior over Collection, Discovery, Credential Access, Command and Control, and Exfiltration. A gate either returns `alert_attributed` with a process-evidence package or `alert_unattributed` with a reason code. For acceptance indicator $a_i(\tau)$, the main evaluation uses

\[
\begin{aligned}
\operatorname{cov}(\tau)&=|D|^{-1}\sum_i a_i(\tau),\\
\operatorname{risk}(\tau)&=
\frac{\sum_i a_i(\tau)\mathbf{1}[\hat y_i\ne y_i]}{\sum_i a_i(\tau)}.
\end{aligned}
\]

Process ranking reports expected Recall@$k$ under random ordering within ties and MRR from the reciprocal midpoint rank of the highest-scoring truth-containing tie. A case may have several true process entities, so expected-tie R@1 and midrank MRR need not order rankers identically. The midpoint is a conservative tie convention, not expected reciprocal rank; the latter is reported as a sensitivity check in Supplementary Table S13. Supplementary Table S1 compares the task and evidence contract with the closest research directions.

![EviGate-APT pipeline and evidence boundary](figures/figure1_pipeline_evidence_boundary.svg)

**Figure 1. EviGate-APT inference, verification, and evaluation boundary.** The numbered panels separate network triggering, alert-opened process retrieval, proposal-locked certificate checking, and compatibility gating. The optional LLM can be bypassed by the CPU-only path; dashed orange denotes the post-freeze EviGate-Bind extension. The gray sidecar never enters inference, and every event terminates in a three-state analyst record. Temporal association is not asserted as a packet-to-process causal edge.

## 3. Method

The evaluation protocol fixes the trigger, evidence scope, split unit, truth boundary, outputs, and failure probes before model comparison (Table 1). A compatible study must declare how network endpoints map to the provenance host; when row-level host IDs are absent, independent topology documentation and an auditable endpoint check bound the claim. Supplementary Table S24 specifies the proposed cross-dataset interface; only the CICAPT-IIoT instantiation is tested here.

**Table 1. Evaluation protocol and denominator flow. Counts are events unless stated otherwise.**

| Protocol element | Fixed rule | CICAPT-IIoT realization |
|---|---|---|
| Network entry and evidence | Independent 60-s trigger opens a bounded second view | Full $\pm5$-min provenance graph; 0.5 false alerts/h budget per monitored network stream |
| Split and truth | Overlap is embargoed; truth stays outside inference | 46 groups; separate inputs and truth sidecars |
| Output and denominator | Three states; oracle-entry and end-to-end separated | 59 clusters $\rightarrow$ 53 supported $\rightarrow$ 51 non-pilot |
| End-to-end flow | Every non-pilot event ends in exactly one state | 15 `no_alert`, 12 `alert_unattributed`, 24 `alert_attributed` (18 correct) |
| Failure audit | Declared perturbations and executable assertions | Five corruption families, natural overlap, hash manifests |

### 3.1 Network entry and typed retrieval

Stage A aggregates nonoverlapping 60-s traffic windows into 69 identity-free features: protocol and service-port counts, packet/byte summaries, concentration measures, and distributions. IP addresses, absolute timestamps, labels, event IDs, and data-selected ephemeral ports are excluded. Logistic Regression, HistGradientBoosting (HGB), and a lightweight MLP are calibrated per outer fold to 0.5 false alerts/h.

Calibration windows target that operational budget within each outer fold. Fifteen-minute blocks prevent individual windows from crossing partitions, and blocks intersecting an event inherit the event's embargo group. Stage A is fitted on the Phase 2 training partition and evaluated separately on continuous Phase 2 traffic and all-benign Phase 1 traffic. This design measures false-alert exposure rather than reporting IID row accuracy on heavily imbalanced traffic.

An alert opens the full ±5-min provenance graph. Stage B ranks every process using 55 features covering relative time, recency, graph degree, typed neighbors, path summaries, process utility groups, endpoint matches, and normalized name/executable evidence. Raw identifiers, labels, tactics, IP addresses, and ports are excluded. A class-balanced Logistic ranker is the primary model; typed HGB, random expectation, recency, and graph heuristics are baselines. Feature removal and malicious-process-family holdout test semantic shortcuts. Stage C converts the top ten processes into a normalized evidence document and estimates a five-tactic posterior with class-balanced Logistic Regression.

The complete time-window graph is ranked; endpoint matching is retained only as one evidence feature because an early endpoint-seeded implementation excluded the malicious PID in all 11 cases with joint address-and-port pruning. Each event receives equal training weight, divided across its positive and negative process entities, so large graphs cannot dominate the loss. The malicious-process-family audit lowercases executable names, removes numeric substrings, and groups shell-family variants before assigning whole families to held-out folds. It measures sensitivity to executable-family shortcuts under this declared grouping, not generalization to unseen semantic malware families.

Stage C summarizes the posterior by confidence, margin, and entropy; network and provenance-only posteriors; view disagreement; evidence counts and entity fractions; ranked-score concentration; path and socket summaries; and temporal proximity. The frozen 28-feature evidence-sufficiency controller was trained to distinguish correct clean predictions from five case-balanced corruption families. Because that target combines clean-label correctness and integrity, we also evaluate confidence, entropy, posterior margin, a posterior-only learned correctness model, cross-view agreement, an integrity-only score, and a dual rule. Count-matched comparisons isolate ranking behavior; calibration-only thresholds model deployment.

### 3.2 Certificate and compatibility gates

Here, an evidence certificate is an unsigned, non-cryptographic structured claim whose schema and package-local references are checked deterministically; it is not a digital attestation, chain-of-custody record, or proof of legal admissibility. The frozen EviGate-LLM study compares a forced five-way LLM, calibrated self-abstention, and a certificate-enforcing reviewer using the same pinned Qwen2.5-7B checkpoint [@yang2024qwen25]. For each case, the reviewer receives only the machine proposal, network summary, graph-integrity summaries, and top process evidence. An issued certificate must reproduce the proposal and cite one package-local process plus no more than six owned anchors. The verifier checks schema, identifiers, ownership, anchor existence, single-process consistency, and nullable-decision rules. Any failed obligation returns `alert_unattributed`.

The foreign-context failure observed in that frozen study motivated EviGate-Bind. In this cascade, the LLM may audit only the proposed tactic or return null. A balanced Logistic model then maps clean network and provenance views to posteriors and scores their pair using posterior products and differences, Bhattacharyya affinity, Jensen--Shannon divergence, agreement, confidence, margin, entropy, graph-size summaries, and temporal proximity. Training uses clean true pairs and deterministic hard negatives from a different tactic; outer-fold identities and test rows never enter inference features. The issued-label rule requires a valid proposal-locked certificate, posterior margin, compatible pair, and positive temporal proximity. The LLM is optional: the CPU-only cascade uses the same non-language checks.

Formally, let $m(x)$ be the Stage C posterior margin, $c(x)$ certificate validity, $b(x)$ the BindGate score, and $t(x)$ positive temporal proximity. The cascade issues a label only when

\[
a(x)=\mathbf{1}[m(x)\ge\tau_m]\mathbf{1}[c(x)=1]
\mathbf{1}[b(x)\ge\tau_b]\mathbf{1}[t(x)>0].
\]

Binding training uses only clean true pairs outside the evaluated fold. When available, two deterministic hard negatives are added for the same network event: the network-most-similar provenance donor with a different tactic and the most-similar donor sharing the tactic. Donor identities, corruption names, and test rows are excluded from features. The final model refits on all outer-training pairs; margin and compatibility thresholds are selected from training/calibration cases only.

Component comparisons distinguish count-matched diagnosis from deployment. The former accepts the same clean count in each evaluated fold and is not deployable; the latter transfers thresholds selected only from training/calibration data. Five corruption families probe collection failures: all-process deletion, socket-type deletion, hash-parity half-process deletion, a +600-s shift, and different-tactic context replacement. Full procedures are in the Supplementary Material.

## 4. Data and Evaluation

CICAPT-IIoT provides network and provenance records for a staged APT29-inspired IIoT campaign [@ghiasvand2024cicapt]. From the released network attack rows and provenance attack-labeled process/PID records, a declared union manifest groups adjacent observations of the same tactic when their timestamps differ by no more than 300 s; direct labeled PIDs define evaluation-only process truth. This yields 59 **union-derived clusters**, not the 58 Caldera-report rows in the official supplementary `attack_info.csv` [@cicapt2024dataset]. Of these, 53 belong to five supported tactics (Collection 26, Command and Control 5, Credential Access 7, Discovery 11, Exfiltration 4), and six are out-of-support audit cases. Two Collection events used in prompt development are excluded only from the frozen LLM and post-freeze binding cohort, leaving 51 non-pilot events; they remain in the Stage A/B/C and frozen-selector analyses. Overlapping evidence contexts merge into 46 indivisible embargo groups. Three outer folds separate train, calibration, and test groups; every event is tested once. Truth process/PID and tactic labels reside in a separate sidecar, and normalized process-document overlap between train and test is zero. The Caldera file was obtained after these splits and evaluations were fixed; its rows are used only for a post-freeze source audit, not to relabel cases or alter denominators. These controls address common temporal and split-unit failures in security ML [@arp2022dosdonts].

The verified Phase 2 network archive spans approximately 72 h and contains 9,536,823 rows, including 1,004 attack-labeled records; provenance contains 196,735 rows, including 283 attack-labeled rows with usable timestamps. The author's thesis identifies Ubuntu VM1 as the Auditd/SPADE gateway and Caldera victim, maps `172.16.63.128` to it and `172.16.65.128` to the Kali VM1 attacker, and assigns `172.16.67.128` to Raspberry Pi2 (Table 3.1 in [@ghiasvand2024thesis]). The authors used Caldera PIDs to label provenance processes and calibrated NS3 packet times, Caldera action times, and endpoint IPs to label network packets (Sec. 3.4.2 in [@ghiasvand2024thesis]). All 1,004 attack-labeled network rows run between the mapped Kali and Ubuntu endpoints (538 toward Ubuntu; 466 in reverse). The released network CSV itself has no PID or row-level host ID. As a post-freeze corroboration, a socket/flow audit finds 733 Ubuntu-endpoint matches among 755 exact remote-endpoint matches within 0.1 s, with 148 under a 0.05-s bound and none under ±30- or ±60-s shifts. All 58 PIDs listed in the supplementary Caldera file occur as attack-labeled Process entities in the VM1 provenance, and each listed attack time has a same-tactic network row within 30 s (Supplementary Table S15). The author-described labeling procedure and our audit support **host co-membership** for 32/53 in-support both-view clusters and 31/51 evaluated non-pilot events; the other 21 in-support tactic-specific unions contain attack labels in only one view (10 network-only, 11 provenance-only). We do not use these two label channels as a direct packet-to-PID causal key: the released socket artifacts omit local endpoints, no malicious-process socket matches a flow directly in our audit, and the Caldera time/PID pairs have a step-level offset detailed in the supplement.

Every inference package is serialized separately from its truth record. Assertions reject labels, malicious-PID fields, absolute dataset time, and training--test identity overlap. Five Stage A/B seeds measure algorithmic stability but are not treated as independent experiments. Stage C uses one frozen seed. Frozen-selector curves retain 10,000 event-cluster bootstrap resamples; headline post-freeze paired integrity contrasts use 10,000 intact embargo-group resamples as their primary intervals, preserving paired methods and corruption families within each event. The paired sign-flip test aggregates the three corruption-family differences within each of 51 events before sign flipping; exact McNemar tests assess context replacement. These procedures quantify one campaign rather than a population of deployments.

Stage A is evaluated on continuous Phase 2 traffic and an independent 95.9-h benign Phase 1 stress set. Stage B uses MRR and Recall@$k$. Stage C reports full-coverage accuracy, selective risk, exact AURC, corruption rejection and wrong-label rates, and deletion lift. Risk divides wrong issued labels by accepted cases; wrong-label rate divides them by all cases. Thresholds are learned only from training/calibration folds. The analysis sequence is frozen Stage A/B/C and LLM hypotheses, observed certificate failure, then post-freeze EviGate-Bind design and stress audits. The original LLM superiority and coverage thresholds remain in Supplementary Section S4; the repair is exploratory on this campaign.

## 5. Results

### 5.1 Network entry and process localization (RQ1)

At the 0.5-false-alert/h calibration target, HGB achieves 0.84 window AP and covers 38/53 in-support events; the independent benign stress set produces no HGB alert (Table 2). Of 15 misses, six lack a network-positive window and nine fall below their fold threshold. Raising the alert budget increases coverage alongside retention exposure (Figure 2(b); Supplementary Tables S16 and S25). Conditional on oracle entry, the typed Logistic retriever reaches 0.947 midrank MRR over 53 supported events (0.952 over all 59; Table 3). Its expected-tie R@1 is 0.949 over all 59. The median candidate pool is 14, but MRR remains 0.750 versus a random expectation of 0.076 for pools above 100 processes (Supplementary Table S17). Radius-decoupling and ten repeated embargo-grouped partitions give MRR of 0.833--0.952 and $0.940\pm0.022$, respectively (Supplementary Tables S18--S19). Process-family holdout retains 0.93/0.92 MRR/R@1, whereas removing process semantics lowers them to 0.69/0.52. In a post-freeze synthetic concurrency stress adding a median 80 benign Phase 1 processes, the frozen ranker retains 0.783 MRR and 0.915 R@10, while R@1 declines to 0.729 (Supplementary Table S30). These within-campaign retrieval results do not test direct packet-to-process causality.

**Table 2. Stage A performance at 0.5 false alerts/h (three-fold mean ± sample SD).**

| Model | Window AP ↑ | Recall ↑ | Phase 2 false alerts/h ↓ | In-support event coverage ↑ | Phase 1 false alerts/h ↓ |
|---|---:|---:|---:|---:|---:|
| Logistic Regression | 0.327 ± 0.117 | 0.013 ± 0.022 | 0.117 ± 0.203 | 0.056 ± 0.096 | 0.031 ± 0.054 |
| HGB | **0.844 ± 0.053** | **0.609 ± 0.162** | 0.134 ± 0.136 | **0.719 ± 0.190** | **0.000 ± 0.000** |
| Lightweight MLP | 0.488 ± 0.163 | 0.305 ± 0.035 | 0.234 ± 0.160 | 0.434 ± 0.049 | 2.259 ± 0.118 |

**Table 3. Stage B retrieval over all 59 held-out events. Values average five seeds; the abstract's 0.95 rounds the 53-supported-event Logistic MRR of 0.947. Midrank MRR and expected-tie recall use different tie conventions (Supplementary Table S13).**

| Ranker | Midrank MRR ↑ | Expected-tie R@1 ↑ | R@5 ↑ | R@10 ↑ |
|---|---:|---:|---:|---:|
| Random expectation | 0.412 | 0.221 | 0.681 | 0.860 |
| Recency | 0.325 | 0.280 | 0.757 | 0.966 |
| Typed HGB | 0.679 | 0.915 | **0.966** | **0.966** |
| Full typed Logistic | **0.952** | **0.949** | **0.966** | **0.966** |
| Family-holdout Logistic | 0.927 | 0.915 | **0.966** | **0.966** |

Under random tie resolution, expected first-hit reciprocal rank is 0.941 for HGB and 0.958 for Logistic; the larger midrank gap is tie-convention dependent, not an equally large first-hit advantage (Supplementary Table S13).

### 5.2 Selection, certificates, and binding (RQ2--RQ4)

The conventional-selector and frozen LLM hypothesis tests in this subsection were prespecified; EviGate-Bind, its ablations, the natural-overlap audit, and the retention policy are explicitly post-freeze diagnostics. This ordering separates the failed confirmatory tests from the subsequent repair rather than treating the repair as confirmatory evidence.

The ranked-evidence tactic classifier reaches 0.62 full-coverage accuracy and 0.40 macro-F1, versus 26/53 correct and 0.132 macro-F1 for a fold-local majority baseline (Supplementary Table S20). Its class-level confusion counts are in Supplementary Table S27. The early joint address-and-port pruning preserves the truth process in 0/11 cases when it activates (Supplementary Table S21). At 42/53 accepted events, the prespecified composite controller has risk 0.381 versus 0.310 for confidence and 0.262 for posterior margin. Deleting the top three ranked processes reduces true-tactic probability by 0.0345, versus 0.0027 for deterministic random deletion (lift 0.0317, 95% interval [0.0191, 0.0450]). Thus returned processes influence the classifier, while clean-error selection and integrity triage favor different rules. Full curves and held-out-corruption matrices are retained in the supplement.

The operating-region conclusion combines two views. Supplementary Table S2 identifies posterior margin as the lowest-risk rule at the prespecified 42/53 count; Figure 2(a) shows margin alongside confidence and the controller, with the diagnostic dual rule. The dual score has the lowest exact AURC because it isolates a safer low-coverage subset. Calibration-only thresholds also change accepted counts. No selector dominates both clean risk and evidence-integrity failures; posterior selection and integrity alarms should remain separate outputs.

![Selective-risk and evidence-retention operating frontiers](figures/figure2_operating_frontiers.svg)

**Figure 2. Two operating frontiers.** (a) Oracle-entry risk--coverage curves for four selector rules over 53 CICAPT-IIoT events; confidence, posterior margin, and the controller belong to the frozen comparison, whereas dual is diagnostic. Shaded bands are 95% event-cluster bootstrap intervals. (b) All-event Stage-A coverage against the fraction of timestamped provenance CSV bytes inside merged $\pm5$-min alert-opened intervals; point labels are requested calibration budgets in false alerts/h. The inset restores end-to-end accounting over 51 non-pilot events. Panel (b) measures retention exposure, not acquisition or post-decision deletion.

Package-local verification is, by construction, invariant to substitution by another internally coherent package and therefore cannot establish incident membership. The frozen Qwen2.5-7B run produces all 954 outputs; certificate enforcement lowers the forced generator's corruption-macro wrong-label rate from 0.529 to 0.271, but the two prespecified criteria are not met: the corruption wrong-label reduction is 0.039 against a required 0.050, and clean coverage is 0.588 against a required 0.600 with a 0.216 gap against a maximum 0.150 (Supplementary Table S3). A post-freeze failure taxonomy locates the principal verifier failures in evidence-sufficiency obligations, not JSON parsing (Supplementary Table S26).

Table 4 evaluates the post-freeze repair. At matched 33/51 clean acceptance, EviGate-Bind reduces five-family corruption wrong labels by 0.141 [0.098, 0.184] under embargo-group resampling relative to margin with the same structural rules (Figure 3); across the three nonmechanical families, rates are 0.425 versus 0.190. At deployable training-calibrated thresholds EviGate-Bind also accepts 33/51 clean events, a coincident count selected by a different training-only rule, and labels 25 correctly, versus 38/51 and 28 for margin. The 0.242 versus 0.263 clean-risk contrast rests on two wrong events under different denominators and is not a reliable superiority finding. Network-view ablations add 12--14/51 context errors (Supplementary Table S4), and Supplementary Table S28 reports score-level clean/foreign discrimination separately from cascade decisions. The no-LLM cascade attains similar integrity outcomes; an incremental LLM effect is not established, and the reported interval is not an equivalence test (Supplementary Section S4.1).

As a post-hoc scope check, the 31 host-link-supported non-pilot events give EviGate-Bind 4/22 clean errors (risk 0.182) versus 5/21 (0.238) for matched margin; context replacement produces 7/31 versus 25/31 wrong labels. This subgroup is not an independent superiority test, but shows that the integrity contrast is not created by mixing network-only or provenance-only clusters (Supplementary Table S15).

The corruption aggregate combines mechanical and nonmechanical outcomes. Over socket deletion, half-process deletion, and context replacement, EviGate-Bind lowers the macro wrong-label rate from 0.425 to 0.190, a reduction of 0.235 [0.163, 0.306] under paired embargo-group resampling; the original event-level interval is [0.170, 0.301]. The context gain comes primarily from refusal, so the cascade is an integrity gate rather than a tactic-recovery mechanism; family-level rejection and conditional-error details are in Supplementary Table S5.

**Table 4. Post-freeze EviGate-Bind component results. The first four rows are matched at 33/51 clean acceptance; the last row transfers training-calibrated thresholds. Wrong-label denominators are 51 events.**

| Method | Clean accepted | Clean risk | Clean correct | Corruption-macro wrong | Context wrong |
|---|---:|---:|---:|---:|---:|
| Matched margin + structural rules | 33/51 | 0.333 | 22/51 | 0.255 | 0.863 |
| BindGate + temporal, no LLM | 33/51 | **0.242** | **25/51** | 0.129 | 0.431 |
| Proposal-locked LLM + same-tactic gate | 33/51 | 0.273 | 24/51 | 0.161 | 0.471 |
| **Full EviGate-Bind** | **33/51** | **0.242** | **25/51** | **0.114** | **0.333** |
| Training-calibrated margin + rules | 38/51 | 0.263 | 28/51 | 0.278 | 0.882 |

Different-tactic donors occur in both full-gate training and the largest replacement test. Same-tactic-only training retains 74.1% of the context-error reduction, while the natural-overlap audit shows that shared event windows remain ambiguous (Supplementary Table S22). The gate reduces, rather than resolves, context confusion.

Supplementary Table S5 gives the complete frozen-target and rejection accounting. End to end, Stage A returns 15 `no_alert`, 12 `alert_unattributed`, and 24 `alert_attributed`; 18 issued labels are correct.

Each analyst record exposes at most ten ranked processes; evaluation truth is in that list for 11/12 unattributed alerts (Supplementary Table S6). At this sample size, ranked processes and refusal reasons are the primary outputs; tactics are auxiliary triage metadata rather than technique-level findings.

![CICAPT-IIoT adverse-rate reductions over matched posterior margin](figures/figure5_robustness_effect.svg)

**Figure 3. CICAPT-IIoT robustness effects.** Paired absolute reductions in adverse rates relative to matched posterior margin with identical structural rules, including the primary three-family contrast. Error bars are 95% embargo-group bootstrap intervals over 51 events in 43 groups; 43 of the 46 embargo groups contain non-pilot events. Filled circles exclude zero, the open square does not, and positive values favor EviGate-Bind. The clean-risk interval crosses zero.

## 6. Discussion, Validity, and Reproducibility

EviGate-APT separates four assurance layers. Collection integrity asks whether records are missing, shifted, or substituted; model fidelity asks whether returned entities affect the classifier; referential validity asks whether a certificate is structurally grounded in the supplied package; and causal responsibility asks whether the cited process generated the packet stream. The protocol evaluates the first three only. EviGate-Bind improves three nonmechanical corruptions primarily through CPU checks, but its residual foreign-context error and weaker same-tactic alarms preclude a universal binding claim.

The ablations clarify what each component contributes. Proposal locking removes a prompt-interface ambiguity by preventing the reviewer from substituting a preferred tactic, while the certificate verifier rejects references outside the presented package. Neither test relates the package to the originating network event. BindGate and the temporal rule address that missing cross-view relation, and the matched negative family materially affects what the learned score recognizes. The no-LLM cascade carrying most of the improvement is therefore not merely a cost result: it localizes the measured robust contribution to deterministic and low-capacity compatibility checks rather than language generation. The LLM serializes a compact, machine-auditable record; Supplementary Section S16.1 shows frozen valid and invalid examples with resolved anchors and verifier outcomes. No analyst usability study was conducted, and this small study neither demonstrates that language review is necessary nor establishes equivalence with the CPU-only cascade.

This separation changes deployment practice. Alert misses should precede oracle-entry metrics, and compatibility should remain distinct from clean-risk selection. Full EviGate-Bind has lower clean decision cost than calibrated margin only when abstention costs less than 0.40 of a wrong label, but lower foreign-context integrity cost whenever abstention is cheaper than accepting foreign evidence (Supplementary Table S7). Together with the Stage-A frontier, this yields an explicit operator policy: choose the alert budget under a retention/coverage constraint, retain evidence for all alerts including refusals, and use the compatibility cascade when wrong or foreign labels cost more than abstention; otherwise use the calibrated margin comparator (Supplementary Section S16). A language reviewer should be proposal-locked and its certificate should enforce nullable refusal, process ownership, and deterministic citations.

The three-state interface also maps directly to network-centric forensic readiness. `no_alert` records the front-end detection boundary; `alert_unattributed` retains the incident trigger and candidate evidence without overclaiming; and `alert_attributed` binds the issued tactic to a compact certificate and reasoned gate status. At the fixed Stage-A point, 60 alert windows over 72.08 h merge into 6.88 h of provenance-retention intervals (9.5% of capture time), containing 30.0% of timestamped CSV bytes; normalized top-ten packages occupy 3.3% of the serialized full-graph package size (Supplementary Table S23). This is a retention/interface saving, not an acquisition saving: the gate requires the evidence window before accepting or refusing, and refusal evidence remains useful. Signing, trusted time, acquisition custody, and jurisdiction-specific procedures remain outside the present protocol.

Traffic-to-function vulnerability analysis is a separate future task requiring payload-aware program analysis and packet-to-process validation.

Validity has four bounds. CICAPT is one scripted campaign, so grouped folds and family holdout do not establish cross-campaign generalization. Only 53/59 derived clusters fall within the five modeled tactics, with no correct Credential Access or Exfiltration labels. EviGate-Bind and the host-link audits are post-freeze. Finally, all provenance comes from Ubuntu VM1: the author's topology maps its IP and reports separate packet and process labeling procedures, but the released CSV has no explicit packet-to-PID key, the Caldera time/PID pairs do not directly align at step level, and local socket fields are absent. Our audit therefore does not verify a direct causal join for the both-view cohort or localize executions on other devices. In the post-freeze fixed-threshold clock audit, EviGate-Bind clean risk rises from 8/33 (0.242) at zero offset to 10/30 (0.333) at +30 s, versus 11/40 (0.275) for calibrated margin; the zero-offset advantage does not persist, so time alignment is a deployment precondition (Supplementary Table S29). This clean-only audit does not establish whether the three-family integrity advantage survives skew. Independent provenance campaigns with row-level host identifiers and real collection failures remain necessary before deployment.

Three scalar contrasts were declared before testing; the remaining component and repair comparisons are secondary or post-hoc. Across 17 paired contrasts, the descriptive Bonferroni threshold is 0.00294: the three-family EviGate-Bind result remains below it, whereas the incremental LLM result does not. This does not make the post-freeze cascade confirmatory. Primary post-freeze embargo-group intervals and frozen-selector event-cluster intervals characterize only this campaign; folds, optimizer seeds, and repeated rows are not independent deployments. Calibration folds contain 7--8 eligible cases, precluding a stable post-hoc temperature model.

Stage B compares two learned rankers with random, recency, degree, and combined heuristics; whole-system provenance IDSs have incompatible inputs and outputs. Stage C compares eight selectors, held-out corruption models, frozen LLM variants, and matched non-LLM cascades over identical packages. These controls support candidate-ranking and refusal claims, not superiority to a production SOC platform.

All transformations are scripted; 130 tests cover split/truth isolation, feature exclusions, certificate parsing, selectors, donor parity, host-link accounting, claim--artifact consistency, CSV record accounting, and metric invariants. On an Intel Xeon Silver 4215R, the CPU path has 2.64-ms median and 3.83-ms p95 wall time over 306 measurements---a server-class, not edge-board, benchmark. The optional 7B reviewer is SOC/offline.

The local release manifest hashes source archives and derived predictions, corruptions, LLM outputs, and binding results without redistributing raw records. The interface validator checks identifiers, graph references, sidecars, and schemas on this CICAPT-IIoT instantiation; cross-dataset behavior has not been tested. The frozen LLM protocol and its local SHA-256 digest are documented in the supplement, but this was not a public time-stamped preregistration.

## 7. Conclusion

EviGate-APT turns network-triggered IIoT analysis into a reusable three-state evidence-binding evaluation protocol: detect an event, retrieve processes, and issue a tactic only when declared evidence obligations pass. The CICAPT-IIoT instantiation shows strong within-campaign retrieval, an explicit coverage--retention frontier, and a post-freeze compatibility repair; the LLM's failed hypotheses bound the role of language review. The contribution is the failure-aware protocol and its audited instantiation; direct packet-to-PID causality and cross-campaign validation are outside this evaluation.

## References
