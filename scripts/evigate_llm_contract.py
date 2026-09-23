#!/usr/bin/env python3
"""Prompt construction and deterministic evidence-contract verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TACTICS = {
    "collection",
    "command_and_control",
    "credential_access",
    "discovery",
    "exfiltration",
}
DECISIONS = {"attribute", "abstain"}
REASON_CODES = {
    "sufficient_observed_support",
    "missing_process_evidence",
    "insufficient_process_evidence",
    "conflicting_cross_view_evidence",
    "temporal_mismatch",
    "ambiguous_tactic",
    "suspected_evidence_corruption",
}
RESPONSE_KEYS_V1 = {
    "schema_version",
    "case_id",
    "decision",
    "tactic",
    "evidence_sufficient",
    "integrity_alarm",
    "confidence",
    "cited_entity_ids",
    "cited_anchor_ids",
    "reason_codes",
}
RESPONSE_KEYS_V2 = RESPONSE_KEYS_V1 - {"decision"}
RESPONSE_KEYS_V3 = {
    "schema_version",
    "case_id",
    "tactic",
    "evidence_sufficient",
    "integrity_alarm",
    "confidence",
    "support_process_ref",
    "cited_anchor_ids",
    "reason_codes",
}


def load_prompt(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def build_user_prompt(
    evidence_case: dict[str, Any], include_machine_proposal: bool = True
) -> str:
    payload = {
        "case_id": evidence_case["case_id"],
        "network_event": evidence_case["network_event"],
        "provenance_summary": evidence_case["provenance_summary"],
        "ranked_process_candidates": evidence_case["ranked_process_candidates"],
    }
    if include_machine_proposal and "machine_proposal" in evidence_case:
        payload["machine_proposal"] = evidence_case["machine_proposal"]
    return (
        "Analyze this evidence package. The package contains observations only; "
        "it does not contain the ground-truth tactic or corruption label.\n"
        + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


def extract_json_object(raw_text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Extract the first complete JSON object without accepting trailing objects."""
    decoder = json.JSONDecoder()
    text = raw_text.strip()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        trailing = text[index + end :].strip()
        if trailing and trailing not in {"```", "```json"}:
            return value, "trailing_text"
        return value, None
    return None, "no_json_object"


def evidence_index(evidence_case: dict[str, Any]) -> tuple[set[str], dict[str, str]]:
    entity_ids: set[str] = set()
    anchor_owners: dict[str, str] = {}
    for candidate in evidence_case.get("ranked_process_candidates", []):
        entity_id = str(candidate.get("entity_id", ""))
        if entity_id:
            entity_ids.add(entity_id)
        for anchor in candidate.get("anchors", []):
            anchor_id = str(anchor.get("anchor_id", ""))
            if anchor_id:
                anchor_owners[anchor_id] = entity_id
    return entity_ids, anchor_owners


def process_reference_index(evidence_case: dict[str, Any]) -> dict[str, str]:
    """Map compact, package-local process references (P1, P2, ...) to entities."""
    references: dict[str, str] = {}
    for candidate in evidence_case.get("ranked_process_candidates", []):
        entity_id = str(candidate.get("entity_id", ""))
        rank = candidate.get("rank")
        if entity_id and isinstance(rank, int) and rank > 0:
            references[f"P{rank}"] = entity_id
    return references


def response_decision(response: dict[str, Any]) -> str | None:
    if response.get("schema_version") in {"2.0", "3.0"}:
        tactic = response.get("tactic")
        if tactic in TACTICS:
            return "attribute"
        if tactic is None:
            return "abstain"
        return None
    decision = response.get("decision")
    return str(decision) if decision in DECISIONS else None


def verify_response(
    response: dict[str, Any] | None,
    evidence_case: dict[str, Any],
    parse_error: str | None = None,
    enforce_machine_proposal: bool = True,
) -> dict[str, Any]:
    errors: list[str] = []
    hallucinated_entities: list[str] = []
    hallucinated_anchors: list[str] = []
    if parse_error:
        errors.append(parse_error)
    process_count = int(
        evidence_case.get("provenance_summary", {}).get("process_candidate_count", 0)
    )
    deterministic_integrity_alarm = process_count == 0
    if response is None:
        return {
            "contract_valid": False,
            "verifier_decision": "abstain",
            "verifier_integrity_alarm": deterministic_integrity_alarm,
            "errors": sorted(set(errors or ["missing_response"])),
            "hallucinated_entity_ids": [],
            "hallucinated_anchor_ids": [],
        }

    schema_version = response.get("schema_version")
    if schema_version == "3.0":
        expected_keys = RESPONSE_KEYS_V3
    elif schema_version == "2.0":
        expected_keys = RESPONSE_KEYS_V2
    else:
        expected_keys = RESPONSE_KEYS_V1
    missing = expected_keys - set(response)
    extra = set(response) - expected_keys
    if missing:
        errors.append("missing_keys:" + ",".join(sorted(missing)))
    if extra:
        errors.append("extra_keys:" + ",".join(sorted(extra)))
    if schema_version not in {"1.0", "2.0", "3.0"}:
        errors.append("invalid_schema_version")
    if response.get("case_id") != evidence_case.get("case_id"):
        errors.append("case_id_mismatch")

    decision = response_decision(response)
    tactic = response.get("tactic")
    sufficient = response.get("evidence_sufficient")
    integrity_alarm = response.get("integrity_alarm")
    confidence = response.get("confidence")
    if decision not in DECISIONS:
        errors.append("invalid_decision")
    if tactic is not None and tactic not in TACTICS:
        errors.append("invalid_tactic")
    if type(sufficient) is not bool:
        errors.append("invalid_evidence_sufficient")
    if type(integrity_alarm) is not bool:
        errors.append("invalid_integrity_alarm")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        errors.append("invalid_confidence_type")
    elif not 0.0 <= float(confidence) <= 1.0:
        errors.append("invalid_confidence_range")

    process_refs = process_reference_index(evidence_case)
    support_process_ref = response.get("support_process_ref") if schema_version == "3.0" else None
    if schema_version == "3.0":
        if support_process_ref is not None and not isinstance(support_process_ref, str):
            errors.append("invalid_support_process_ref")
        if isinstance(support_process_ref, str) and support_process_ref in process_refs:
            cited_entities = [process_refs[support_process_ref]]
        else:
            cited_entities = []
            if support_process_ref is not None:
                hallucinated_entities = [str(support_process_ref)]
                errors.append("hallucinated_process_ref")
    else:
        cited_entities = response.get("cited_entity_ids", [])
    cited_anchors = response.get("cited_anchor_ids", [])
    reasons = response.get("reason_codes", [])
    if not isinstance(cited_entities, list):
        cited_entities = []
        errors.append("invalid_cited_entity_ids")
    if not isinstance(cited_anchors, list):
        cited_anchors = []
        errors.append("invalid_cited_anchor_ids")
    if not isinstance(reasons, list):
        reasons = []
        errors.append("invalid_reason_codes")
    max_entities = 1 if schema_version == "3.0" else (5 if schema_version == "2.0" else 3)
    max_anchors = 6 if schema_version == "3.0" else (30 if schema_version == "2.0" else 6)
    if len(cited_entities) > max_entities or len(set(map(str, cited_entities))) != len(cited_entities):
        errors.append("invalid_entity_citation_cardinality")
    if len(cited_anchors) > max_anchors or len(set(map(str, cited_anchors))) != len(cited_anchors):
        errors.append("invalid_anchor_citation_cardinality")
    if not 1 <= len(reasons) <= 3 or any(reason not in REASON_CODES for reason in reasons):
        errors.append("invalid_reason_codes")

    allowed_entities, anchor_owners = evidence_index(evidence_case)
    if schema_version != "3.0":
        hallucinated_entities = sorted(
            str(entity_id) for entity_id in cited_entities if str(entity_id) not in allowed_entities
        )
    hallucinated_anchors = sorted(
        str(anchor_id) for anchor_id in cited_anchors if str(anchor_id) not in anchor_owners
    )
    if hallucinated_entities:
        errors.append("hallucinated_entity_id")
    if hallucinated_anchors:
        errors.append("hallucinated_anchor_id")
    cited_entity_set = set(map(str, cited_entities))
    if any(
        anchor_id in anchor_owners and anchor_owners[anchor_id] not in cited_entity_set
        for anchor_id in map(str, cited_anchors)
    ):
        errors.append("anchor_owner_not_cited")

    if decision == "attribute":
        if tactic not in TACTICS:
            errors.append("attribute_without_valid_tactic")
        if sufficient is not True:
            errors.append("attribute_without_sufficiency")
        if not cited_entities or not cited_anchors:
            errors.append("attribute_without_observed_anchor")
        proposal = evidence_case.get("machine_proposal")
        if (
            enforce_machine_proposal
            and isinstance(proposal, dict)
            and tactic != proposal.get("tactic")
        ):
            errors.append("tactic_differs_from_machine_proposal")
    elif decision == "abstain":
        if tactic is not None:
            errors.append("abstain_with_tactic")
        if sufficient is not False:
            errors.append("abstain_marked_sufficient")
        if schema_version == "3.0" and (support_process_ref is not None or cited_anchors):
            errors.append("abstain_with_support_citation")
    if deterministic_integrity_alarm and integrity_alarm is not True:
        errors.append("missing_process_without_integrity_alarm")

    valid = not errors
    return {
        "contract_valid": valid,
        "verifier_decision": "attribute" if valid and decision == "attribute" else "abstain",
        "verifier_integrity_alarm": bool(
            deterministic_integrity_alarm or integrity_alarm is True
        ),
        "errors": sorted(set(errors)),
        "hallucinated_entity_ids": hallucinated_entities,
        "hallucinated_anchor_ids": hallucinated_anchors,
    }
