"""Audit the maintained EviGate-APT submission against released artifacts.

This audit is intentionally tied to the current submission sources rather than
to any historical draft.  It checks numerical anchors, manuscript boundaries,
figure source data, citation resolution, supplementary-table ordering, the
claim registry, and the executable test inventory.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def close(actual: float, expected: float, tolerance: float = 5e-10) -> bool:
    return abs(float(actual) - float(expected)) <= tolerance


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_test_methods(test_dir: Path) -> int:
    count = 0
    for path in sorted(test_dir.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        count += sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
    return count


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def exact_row(
    rows: Iterable[dict[str, str]], field: str, value: str
) -> dict[str, str] | None:
    return next((row for row in rows if row.get(field) == value), None)


def verify_manifest_outputs(root: Path, manifest_path: Path) -> tuple[bool, str]:
    manifest = load_json(manifest_path)
    checked = 0
    failures: list[str] = []
    for entry in manifest.get("outputs", {}).values():
        path = root / entry["path"]
        checked += 1
        if not path.exists():
            failures.append(f"missing:{entry['path']}")
        elif sha256_file(path) != entry["sha256"].lower():
            failures.append(f"hash:{entry['path']}")
    return not failures, f"{checked} outputs checked; failures={failures}"


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# EviGate-APT submission integrity audit",
        "",
        f"- Overall result: **{'PASS' if result['passed'] else 'FAIL'}**",
        f"- Checks: {result['passed_check_count']}/{result['check_count']} passed",
        f"- Registered claims: {result['claim_registry_rows']}",
        f"- Executable tests discovered: {result['test_method_count']}",
        "",
        "## Check results",
        "",
        "| Category | Check | Result | Evidence |",
        "|---|---|---:|---|",
    ]
    for item in result["checks"]:
        evidence = str(item["evidence"]).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {item['category']} | {item['name']} | "
            f"{'PASS' if item['passed'] else '**FAIL**'} | {evidence} |"
        )
    lines.extend(["", "## Remaining submission actions", ""])
    for warning in result["warnings"]:
        lines.append(f"- {warning}")
    if not result["warnings"]:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A PASS means that the maintained manuscript's registered claims are "
            "consistent with the checked local artifacts and that declared scope "
            "boundaries are present. It is not independent replication, causal "
            "validation, or editorial acceptance.",
            "",
        ]
    )
    return "\n".join(lines)


def audit(root: Path) -> dict[str, Any]:
    root = root.resolve()
    main_path = root / "paper" / "evigate_apt_main.md"
    supplement_path = root / "paper" / "evigate_apt_supplement.md"
    registry_path = root / "paper" / "evigate_apt_claim_registry.csv"
    release_mode = (root / "RESULTS.md").exists()
    readme_path = root / "README.md" if release_mode else root / "submission" / "iotj" / "README.md"
    bib_path = root / "references" / "references.bib"

    main = main_path.read_text(encoding="utf-8")
    supplement = supplement_path.read_text(encoding="utf-8")
    readme = readme_path.read_text(encoding="utf-8")
    combined = main + "\n" + supplement

    clusters = load_json(
        root / "data" / "derived" / "cicapt_phase2_attack_clusters_fallback.json"
    )
    splits = load_json(root / "data" / "derived" / "cicapt_phase2_grouped_splits.json")
    host = load_json(
        root / "data" / "derived" / "host_link_audit" / "host_link.summary.json"
    )
    stage_a = load_json(
        root / "data" / "derived" / "stage_a" / "baseline_run" / "stage_a_summary.json"
    )
    stage_b = load_json(
        root
        / "data"
        / "derived"
        / "stage_b"
        / "typed_ranker_run"
        / "stage_b_typed_ranker.summary.json"
    )
    candidate = load_json(
        root / "data" / "derived" / "p0_diagnostics" / "candidate_size.summary.json"
    )
    radius = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "retrieval_radius.json"
    )
    repeated = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "repeated_group_cv.json"
    )
    retention = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "retention_frontier.json"
    )
    storage = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "retention_storage.json"
    )
    trivial = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "trivial_baselines.json"
    )
    stage_c = load_json(
        root / "data" / "derived" / "stage_c" / "final_run" / "stage_c_summary.json"
    )
    llm = load_json(
        root
        / "data"
        / "derived"
        / "evigate_llm"
        / "v6_full"
        / "evaluation"
        / "evigate_llm.summary.json"
    )
    revision = load_json(
        root
        / "data"
        / "derived"
        / "evigate_llm"
        / "v7_bindgate"
        / "revision_diagnostics"
        / "evigate_bindgate_revision.summary.json"
    )
    feature_ablation = load_json(
        root
        / "data"
        / "derived"
        / "evigate_llm"
        / "p1_feature_ablation"
        / "analysis"
        / "p1_analysis.summary.json"
    )
    natural_overlap = load_json(
        root / "data" / "derived" / "p0_diagnostics" / "natural_overlap.summary.json"
    )

    checks: list[dict[str, Any]] = []

    def add(category: str, name: str, passed: bool, evidence: Any) -> None:
        checks.append(
            {
                "category": category,
                "name": name,
                "passed": bool(passed),
                "evidence": evidence,
            }
        )

    summary = clusters["summary"]
    add(
        "dataset",
        "event and view accounting",
        summary["cluster_count"] == 59
        and summary["clusters_by_view_coverage"]["both"] == 33
        and summary["timestamped_observations"] == {"network": 1004, "provenance": 283}
        and splits["embargo_group_count"] == 46,
        "59 clusters; 33 both-view; 1004 network and 283 provenance observations; 46 groups",
    )
    supported_tactics = {
        "collection",
        "command_and_control",
        "credential_access",
        "discovery",
        "exfiltration",
    }
    supported_views = [
        tuple(cluster["views_present"])
        for cluster in clusters["clusters"]
        if cluster["tactic"] in supported_tactics
    ]
    add(
        "dataset",
        "in-support single-view accounting",
        len(supported_views) == 53
        and supported_views.count(("network", "provenance")) == 32
        and supported_views.count(("network",)) == 10
        and supported_views.count(("provenance",)) == 11
        and "10 network-only, 11 provenance-only" in main
        and "10 network-only / 11 provenance-only" in supplement,
        "53 supported clusters: 32 both-view, 10 network-only, 11 provenance-only",
    )
    add(
        "dataset",
        "host-link endpoint evidence",
        host["provenance"]["usable_socket_observation_count"] == 8077
        and host["unshifted_match_counts_by_tolerance_seconds"]["0.1"] == 755
        and host["endpoint_match_counts_by_tolerance_seconds"]["0.1"]["172.16.63.128"] == 733
        and host["supported_endpoint_attack_rows"] == 1004,
        "8077 usable sockets; 755 exact endpoint/time matches; 733 support the primary endpoint; 1004 attack rows touch it",
    )
    add(
        "dataset",
        "host-link negative controls and causal boundary",
        all(
            host["match_counts_at_primary_tolerance_by_time_offset_seconds"][key] == 0
            for key in ("-60", "-30", "+30", "+60")
        )
        and host["direct_malicious_process_matches_at_primary_tolerance"] == 0,
        "all shifted negative controls are zero; direct malicious-process matches=0",
    )
    cohorts = host["case_cohorts"]
    add(
        "dataset",
        "host-link cohort accounting",
        cohorts["all_cases"] == 59
        and cohorts["host_link_supported_cases"] == 33
        and cohorts["in_support_host_link_supported_cases"] == 32
        and cohorts["evaluated_nonpilot_host_link_supported_cases"] == 31,
        str(cohorts),
    )

    a_metrics = stage_a["aggregate"]["hist_gradient_boosting"]["0.5"]["metrics"]
    add(
        "model",
        "Stage-A feature and primary operating point",
        stage_a["feature_count"] == 69
        and close(a_metrics["window_average_precision"]["mean_of_fold_means"], 0.8444073773)
        and close(a_metrics["all_event_coverage"]["mean_of_fold_means"], 0.6973684211)
        and close(a_metrics["false_alerts_per_hour"]["mean_of_fold_means"], 0.1338448804),
        "69 features; AP=.8444; coverage=.6974; observed false alerts/h=.1338",
    )
    b_metrics = stage_b["results"]["typed_logistic"]["primary_metrics"]
    add(
        "model",
        "Stage-B primary retrieval",
        stage_b["feature_count"] == 55
        and close(
            b_metrics["mean_midrank_reciprocal_all_cases"]["mean_across_seeds"],
            0.9519793053,
        )
        and close(
            b_metrics["expected_tie_recall_at_1_all_cases"]["mean_across_seeds"],
            0.9491525424,
        ),
        "55 features; midrank MRR=.95198; expected-tie R@1=.94915",
    )
    pool = candidate["candidate_pool"]
    add(
        "model",
        "candidate-pool distribution",
        candidate["case_count"] == 59
        and candidate["truth_present_count"] == 58
        and pool["minimum"] == 7
        and pool["median"] == 14
        and pool["maximum"] == 8924,
        str(pool),
    )
    radius_rows = {row["retrieval_radius_seconds"]: row for row in radius["rows"]}
    add(
        "model",
        "retrieval-radius sensitivity",
        close(radius_rows[60]["truth_in_candidate_ceiling"], 0.8813559322)
        and close(radius_rows[300]["midrank_mrr"], 0.9519793053)
        and close(radius_rows[900]["truth_in_candidate_ceiling"], 1.0),
        "60-s ceiling=.8814; 300-s MRR=.9520; 900-s ceiling=1.0",
    )
    repeated_mrr = repeated["aggregate"]["midrank_mrr"]
    add(
        "model",
        "repeated grouped-CV retrieval",
        repeated["repeat_count"] == 10
        and close(repeated_mrr["mean"], 0.9397664993)
        and close(repeated_mrr["sample_sd"], 0.0216410527),
        "10 splits; MRR=.93977 +/- .02164",
    )
    benign_stress = load_json(
        root / "data" / "derived" / "p1_diagnostics" / "benign_distractors"
        / "benign_distractor.summary.json"
    )
    busy = benign_stress["results"]["busy"]["typed_logistic"]
    add(
        "model",
        "post-freeze benign-candidate stress",
        busy["cases"] == 59
        and busy["median_injected_processes"] == 80
        and close(busy["midrank_mrr"], 0.7828365284)
        and close(busy["expected_tie_recall_at_10"], 0.9152542373)
        and "Supplementary Table S30" in main
        and "Table S30" in supplement,
        "59 cases; median +80 benign processes; MRR=.78284; R@10=.91525",
    )
    assignment_runs = [benign_stress] + [
        load_json(
            root / "data" / "derived" / "p1_diagnostics" / "benign_distractors"
            / f"assignment_0{assignment_id}" / "benign_distractor.summary.json"
        )
        for assignment_id in range(1, 5)
    ]
    assignment_mrr = [
        item["results"]["busy"]["typed_logistic"]["midrank_mrr"]
        for item in assignment_runs
    ]
    add(
        "model",
        "benign-donor assignment sensitivity",
        [item["policy"]["assignment_id"] for item in assignment_runs] == list(range(5))
        and all(
            close(item["results"]["none"]["typed_logistic"]["midrank_mrr"], 0.9519793053)
            for item in assignment_runs
        )
        and 0.759 < min(assignment_mrr) < 0.761
        and 0.848 < max(assignment_mrr) < 0.850
        and "0.760--0.849" in supplement,
        f"five no-refit assignments; busy MRR range={min(assignment_mrr):.6f}-{max(assignment_mrr):.6f}",
    )

    full_c = stage_c["full_coverage_tactic_classifier"]
    primary_c = stage_c["primary_fixed_coverage"]
    add(
        "model",
        "Stage-C conventional endpoint",
        close(full_c["accuracy"], 0.6226415094)
        and close(full_c["macro_f1"], 0.3985185185)
        and close(primary_c["controller_attribution_risk"], 0.3809523810)
        and close(primary_c["max_confidence_attribution_risk"], 0.3095238095),
        "accuracy=.6226; macro-F1=.3985; controller/margin risk=.3810/.3095",
    )
    majority = trivial["tactic_baselines"][0]
    endpoint_joint = trivial["endpoint_seeded_baselines"][0]
    add(
        "baseline",
        "trivial baselines",
        majority["accepted"] == 53
        and majority["correct"] == 26
        and endpoint_joint["seeded_cases"] == 11
        and endpoint_joint["truth_preservation_when_seeded"] == 0.0,
        "majority=26/53; joint endpoint rule preserves truth in 0/11 activated cases",
    )

    add(
        "LLM",
        "prespecified LLM hypotheses retained as failures",
        llm["saved_llm_outputs"] == 954
        and llm["prospective_hypotheses"]["H1"]["passed"] is False
        and llm["prospective_hypotheses"]["H2"]["passed"] is False,
        "954 outputs; H1=false; H2=false",
    )
    full = revision["family_results"]["full_cascade"]
    calibrated = revision["family_results"]["calibrated_margin"]
    no_llm = revision["family_results"]["full_no_llm"]
    add(
        "repair",
        "deployable EviGate-Bind and margin counts",
        full["clean"]["accepted"] == 33
        and full["clean"]["correct"] == 25
        and full["clean"]["wrong"] == 8
        and calibrated["clean"]["accepted"] == 38
        and calibrated["clean"]["correct"] == 28
        and calibrated["clean"]["wrong"] == 10
        and full["context_replacement"]["wrong"] == 17
        and calibrated["context_replacement"]["wrong"] == 45,
        "full clean=33/25/8; margin clean=38/28/10; context wrong=17 versus 45",
    )
    add(
        "repair",
        "LLM incremental-effect boundary",
        full["clean"] == no_llm["clean"]
        and close(revision["paired_comparisons"]["no_llm_minus_full"]["estimate"], 0.02614379085)
        and revision["paired_comparisons"]["no_llm_minus_full"]["interval_95"][0] < 0
        and revision["paired_comparisons"]["no_llm_minus_full"]["interval_95"][1] > 0,
        "same clean outcomes; incremental estimate=.0261 with interval spanning zero",
    )
    decision_cost = feature_ablation["decision_cost"]
    add(
        "policy",
        "decision-cost threshold",
        close(decision_cost["full_vs_training_calibrated_clean_break_even_c"], 0.4),
        "break-even abstention cost="
        f"{decision_cost['full_vs_training_calibrated_clean_break_even_c']}",
    )
    add(
        "natural evidence",
        "overlapping-context diagnostic",
        natural_overlap["embargo_group_count"] == 46
        and natural_overlap["overlap_group_count"] == 13
        and natural_overlap["overlap_event_count"] == 26
        and natural_overlap["pair_count"] == 13
        and natural_overlap["bidirectional_truth_overlap_pair_count"] == 11,
        "13/46 overlapping groups; 26 events; 13 pairs, 11 with bidirectional truth overlap",
    )

    first_retention, last_retention = retention["rows"][0], retention["rows"][-1]
    add(
        "retention",
        "coverage-retention frontier",
        close(first_retention["mean_all_event_coverage"], 0.6973684211)
        and close(first_retention["retained_timestamped_byte_fraction"], 0.3001258761)
        and close(last_retention["mean_all_event_coverage"], 0.8)
        and close(last_retention["retained_timestamped_byte_fraction"], 0.3854110418),
        "coverage .6974->.8000; timestamped bytes .3001->.3854",
    )
    add(
        "retention",
        "compact evidence-package accounting",
        storage["serialized_packages"]["clean_event_count"] == 51
        and storage["serialized_packages"]["accepted_event_count"] == 33
        and close(storage["serialized_packages"]["compact_to_full_graph_ratio"], 0.0326737933),
        "51 packages; 33 accepted; compact/full serialized bytes=.03267",
    )

    effect_rows = read_csv(
        root / "output" / "figures" / "ieee" / "source_data" / "figure3_effect_estimates.csv"
    )
    p0_audit = load_json(root / "data" / "derived" / "reviewer_p0" / "reviewer_p0_audit.json")
    group_audit = p0_audit["three_family_group_audit"]
    effect_expected = {
        "Three-family wrong-label": 0.23529411764705882,
        "Foreign-context wrong-label": 0.5294117647058824,
        "Five-family wrong-label": 0.1411764705882353,
        "Clean selective risk": 0.09090909090909088,
    }
    add(
        "figures",
        "Figure 3 source values",
        all(
            (row := exact_row(effect_rows, "metric", metric)) is not None
            and close(float(row["estimate"]), expected)
            and row["bootstrap_unit"] == "embargo group"
            and int(row["n_groups"]) == 43
            for metric, expected in effect_expected.items()
        ),
        str(effect_expected),
    )
    add(
        "figures",
        "three-family grouped sensitivity",
        group_audit["events"] == 51
        and group_audit["embargo_groups"] == 43
        and close(group_audit["observed_reduction"], 12 / 51)
        and close(group_audit["group_bootstrap_ci95"][0], 0.16339869281045752)
        and close(group_audit["group_bootstrap_ci95"][1], 0.30612244897959184)
        and "[0.163, 0.306]" in main,
        "51 events / 43 groups; reduction 12/51; 95% group interval [.163, .306]",
    )
    frontier_rows = read_csv(
        root / "paper" / "figures" / "source_data" / "figure2a_risk_coverage.csv"
    )
    margin_42 = next(
        (row for row in frontier_rows if row["rule"] == "margin" and int(row["accepted_events"]) == 42),
        None,
    )
    add(
        "figures",
        "posterior-margin curve includes fixed point",
        margin_42 is not None and close(float(margin_42["risk"]), 11 / 42),
        "margin risk 11/42 at 42/53 coverage",
    )
    end_rows = read_csv(
        root
        / "output"
        / "figures"
        / "ieee"
        / "source_data"
        / "figure2b_evigate_end_to_end.csv"
    )
    end = end_rows[0]
    add(
        "figures",
        "Figure 2 end-to-end inset",
        [int(end[key]) for key in ("Correct label", "Wrong label", "Unattributed after alert", "Stage-A miss")]
        == [18, 6, 12, 15],
        "18 correct; 6 wrong; 12 unattributed; 15 Stage-A misses",
    )

    required_main = {
        "clean-risk limitation": "not a reliable superiority finding",
        "LLM necessity limitation": "an incremental LLM effect is not established",
        "non-equivalence statement": "not an equivalence test",
        "causal boundary": "does not test direct packet-to-PID causality",
        "cross-campaign boundary": "or cross-campaign generalization",
        "author-described packet and process labels": "The authors used Caldera PIDs to label provenance processes",
        "host-link post-freeze status": "host-link audits are post-freeze",
        "host-link post-hoc subgroup status": "As a post-hoc scope check",
        "author-mapped host source": "Table 3.1 in [@ghiasvand2024thesis]",
        "Caldera-row versus derived-cluster boundary": "59 **union-derived clusters**, not the 58 Caldera-report rows",
        "Caldera PID corroboration": "All 58 PIDs listed in the supplementary Caldera file",
    }
    for name, fragment in required_main.items():
        add("claims", name, fragment in main, fragment)
    add(
        "claims",
        "Caldera step-time limitation retained",
        "1/45" in supplement
        and "38/44" in supplement
        and "do not directly align at step level" in main,
        "Supplement reports 1/45 same-row and 38/44 next-row timing; main limits attribution",
    )

    stale_patterns = {
        "X-IIoTID transfer claim": r"X-?IIoTID",
        "draft version label": r"(?<![A-Za-z0-9_])v\d+(?![A-Za-z0-9_])",
        "obsolete missing-host wording": r"(?:missing|lacks?) host identity|no event-level IP-to-host",
    }
    for name, pattern in stale_patterns.items():
        hits = re.findall(pattern, combined, flags=re.IGNORECASE)
        add("scope", f"no {name}", not hits, f"matches={hits}")

    gate_diagnostic = load_json(root / "data" / "derived" / "p1_diagnostics" / "gate_discrimination.json")
    gate_pooled = gate_diagnostic["pooled"]
    add(
        "scope",
        "post-freeze binding-score diagnostic",
        gate_pooled["events"] == 51
        and close(gate_pooled["clean_vs_foreign_score_auroc"], 0.6924259900)
        and gate_pooled["foreign_binding_alarm"] == 24
        and "0.692" in supplement
        and "Supplementary Table S28" in main,
        "51 paired cases; AUROC=.6924; 24 foreign binding alarms; main points to S28",
    )
    clock_diagnostic = load_json(root / "data" / "derived" / "clock_drift" / "evaluation" / "clock_drift.summary.json")
    clock_results = clock_diagnostic["results"]
    add(
        "scope",
        "post-freeze clock-offset boundary",
        clock_results["30"]["primary_fixed_review"]["wrong_labels"] == 10
        and clock_results["-30"]["primary_fixed_review"]["wrong_labels"] == 11
        and clock_results["30"]["calibrated_margin"]["wrong_labels"] == 11
        and clock_results["-30"]["calibrated_margin"]["wrong_labels"] == 11
        and "time alignment is a deployment precondition" in main
        and "Table S29" in supplement,
        "fixed-threshold ±30-s audit is supplementary; main states deployment precondition",
    )

    main_tables = [int(value) for value in re.findall(r"^\*\*Table (\d+)\.", main, re.MULTILINE)]
    supp_tables = [int(value) for value in re.findall(r"^\*\*Table S(\d+)\.", supplement, re.MULTILINE)]
    add("structure", "main-table sequence", main_tables == [1, 2, 3, 4], str(main_tables))
    add("structure", "supplement-table sequence", supp_tables == list(range(1, 31)), str(supp_tables))

    bib_keys = set(re.findall(r"^@\w+\s*\{\s*([^,\s]+)", bib_path.read_text(encoding="utf-8"), re.MULTILINE))
    cited_keys = set(re.findall(r"(?<![\w])@([A-Za-z][A-Za-z0-9_:.-]+)", combined))
    unresolved = sorted(cited_keys - bib_keys)
    main_cited_keys = set(re.findall(r"(?<![\w])@([A-Za-z][A-Za-z0-9_:.-]+)", main))
    add("citations", "citation-key resolution", not unresolved, f"{len(cited_keys)} keys; unresolved={unresolved}")
    add("citations", "main-text cited-reference count", len(main_cited_keys) == 34, f"main unique keys={len(main_cited_keys)}")

    registry = read_csv(registry_path)
    registry_ids = [row["claim_id"] for row in registry]
    missing_evidence: list[str] = []
    for row in registry:
        for source in row["evidence_source"].split(";"):
            source = source.strip()
            if source and not (root / source).exists():
                missing_evidence.append(f"{row['claim_id']}:{source}")
    add(
        "registry",
        "current claim registry completeness",
        len(registry) >= 60
        and len(registry_ids) == len(set(registry_ids))
        and all(f"C{number}" in registry_ids for number in range(56, 61))
        and all(row["stage_2_5_status"] == "verified" for row in registry),
        f"rows={len(registry)}; unique={len(set(registry_ids))}",
    )
    add("registry", "claim evidence paths exist", not missing_evidence, str(missing_evidence))
    registry_text = registry_path.read_text(encoding="utf-8")
    add(
        "registry",
        "registry excludes retired transfer analysis",
        not re.search(r"X-?IIoTID", registry_text, re.IGNORECASE),
        "no retired transfer claim; post-freeze clock audit is registered",
    )

    manifest_checks = []
    for manifest in (
        root / "data" / "derived" / "host_link_audit" / "manifest.json",
        root / "data" / "derived" / "p1_diagnostics" / "manifest.json",
    ):
        ok, evidence = verify_manifest_outputs(root, manifest)
        manifest_checks.append((manifest.relative_to(root).as_posix(), ok, evidence))
    add(
        "reproducibility",
        "derived-output manifest hashes",
        all(item[1] for item in manifest_checks),
        str(manifest_checks),
    )

    test_count = count_test_methods(root / "tests")
    add(
        "reproducibility",
        "test inventory is synchronized",
        (
            test_count == 114 and "114 portable tests" in readme
            if release_mode
            else test_count == 130 and "130 tests" in main and "130 unit" in readme
        ),
        f"discovered={test_count}; manuscript/readme updated",
    )

    failed = [item for item in checks if not item["passed"]]
    warnings: list[str] = []
    if "Anonymous Author(s)" in main or not (root / "submission" / "iotj" / "author_metadata.json").exists():
        warnings.append(
            "Author names, affiliations, funding, corresponding-author details, and conflict-of-interest text remain placeholders; complete author_metadata.json before submission."
        )
    metadata_path = root / "submission" / "iotj" / "author_metadata.json"
    metadata = load_json(metadata_path) if metadata_path.exists() else {}
    artifact_url = str(metadata.get("artifact_url", "")).strip()
    if (
        not artifact_url.startswith("https://")
        or any(marker in artifact_url.lower() for marker in ("example", "placeholder", "replace-", "[", "]"))
        or any(character.isspace() for character in artifact_url)
    ):
        warnings.append(
            "No verified public artifact URL is configured; the draft uses request-based availability, while the submission-ready build still requires a URL."
        )
    result = {
        "schema_version": "1.0",
        "audit_scope": "maintained EviGate-APT main manuscript and supplement",
        "main_manuscript": main_path.relative_to(root).as_posix(),
        "supplement": supplement_path.relative_to(root).as_posix(),
        "main_sha256": sha256_file(main_path),
        "supplement_sha256": sha256_file(supplement_path),
        "claim_registry": registry_path.relative_to(root).as_posix(),
        "claim_registry_rows": len(registry),
        "test_method_count": test_count,
        "check_count": len(checks),
        "passed_check_count": len(checks) - len(failed),
        "checks": checks,
        "failed_checks": [item["name"] for item in failed],
        "warnings": warnings,
        "passed": not failed,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("reports/submission_integrity/evigate_submission_integrity.json"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("reports/submission_integrity/evigate_submission_integrity.md"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    result = audit(root)
    json_output = args.json_output if args.json_output.is_absolute() else root / args.json_output
    markdown_output = (
        args.markdown_output if args.markdown_output.is_absolute() else root / args.markdown_output
    )
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    markdown_output.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
