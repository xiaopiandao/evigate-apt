#!/usr/bin/env python3
"""Summarize verifier-obligation failures in the frozen 954-output LLM study.

The taxonomy is descriptive and multi-label: one response may violate several
obligations.  It reads only the frozen Qwen2.5 outputs and truth sidecar and
writes post-freeze diagnostic artifacts without changing any decision rule.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CATEGORY_CODES = {
    "evidence_obligation": {
        "attribute_without_observed_anchor",
        "attribute_without_sufficiency",
    },
    "missing_process_refusal": {
        "missing_process_without_integrity_alarm",
    },
    "reference_ownership": {
        "hallucinated_process_ref",
        "hallucinated_entity_id",
        "hallucinated_anchor_id",
        "anchor_owner_not_cited",
    },
    "decision_or_schema": {
        "invalid_tactic",
        "invalid_decision",
        "invalid_reason_codes",
        "case_id_mismatch",
    },
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows to write: {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def group_key(record: dict[str, Any]) -> tuple[str, str, str]:
    condition = str(record["condition"])
    family = "clean" if condition == "clean" else str(record["corruption_family"])
    return str(record["variant"]), condition, family


def resolve_certificate_example(
    record: dict[str, Any],
    inference_input: dict[str, Any],
) -> dict[str, Any]:
    response = record["parsed_response"]
    support_ref = response.get("support_process_ref")
    process_by_ref = {
        f"P{candidate['rank']}": candidate
        for candidate in inference_input.get("ranked_process_candidates", [])
    }
    support = process_by_ref.get(support_ref)
    anchor_by_id = {
        anchor["anchor_id"]: anchor
        for candidate in inference_input.get("ranked_process_candidates", [])
        for anchor in candidate.get("anchors", [])
    }
    return {
        "sample_id": record["sample_id"],
        "condition": record["condition"],
        "corruption_family": record.get("corruption_family"),
        "machine_proposal": inference_input["machine_proposal"],
        "certificate": response,
        "resolved_support": None
        if support is None
        else {
            "process_ref": support_ref,
            "rank": support["rank"],
            "ranker_score": support["ranker_score"],
            "process": support["process"],
            "cited_anchors": [
                anchor_by_id[anchor_id]
                for anchor_id in response.get("cited_anchor_ids", [])
                if anchor_id in anchor_by_id
            ],
        },
        "verification": record["verification"],
        "evaluation_only_truth_tactic": record["tactic"],
    }


def analyze(
    outputs_path: Path,
    truth_path: Path,
    inputs_path: Path,
) -> dict[str, Any]:
    truth = {row["sample_id"]: row for row in read_jsonl(truth_path)}
    inputs = {row["sample_id"]: row for row in read_jsonl(inputs_path)}
    joined: list[dict[str, Any]] = []
    for output in read_jsonl(outputs_path):
        sample_id = output["sample_id"]
        if sample_id not in truth:
            raise KeyError(f"Missing truth-sidecar row for {sample_id}")
        joined.append({**output, **truth[sample_id]})

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in joined:
        grouped.setdefault(group_key(record), []).append(record)

    summary_rows: list[dict[str, Any]] = []
    code_rows: list[dict[str, Any]] = []
    for (variant, condition, family), records in sorted(grouped.items()):
        count = len(records)
        error_sets = [set(record["verification"]["errors"]) for record in records]
        contract_valid = sum(
            bool(record["verification"]["contract_valid"]) for record in records
        )
        parse_error = sum(record.get("parse_error") is not None for record in records)
        any_error = sum(bool(errors) for errors in error_sets)
        row: dict[str, Any] = {
            "variant": variant,
            "condition": condition,
            "corruption_family": family,
            "output_count": count,
            "contract_valid_count": contract_valid,
            "contract_valid_rate": contract_valid / count,
            "parse_error_count": parse_error,
            "parse_error_rate": parse_error / count,
            "any_verifier_error_count": any_error,
            "any_verifier_error_rate": any_error / count,
        }
        for category, codes in CATEGORY_CODES.items():
            category_count = sum(bool(errors & codes) for errors in error_sets)
            row[f"{category}_count"] = category_count
            row[f"{category}_rate"] = category_count / count
        summary_rows.append(row)

        error_counts = Counter(
            error
            for errors in error_sets
            for error in errors
        )
        for error, error_count in sorted(
            error_counts.items(), key=lambda item: (-item[1], item[0])
        ):
            code_rows.append(
                {
                    "variant": variant,
                    "condition": condition,
                    "corruption_family": family,
                    "error_code": error,
                    "output_count": count,
                    "outputs_with_error": error_count,
                    "output_rate": error_count / count,
                }
            )

    result = {
        "analysis_status": "post_freeze_diagnostic",
        "analysis_type": "descriptive_multi_label_verifier_failure_taxonomy",
        "output_count": len(joined),
        "sample_count": len(truth),
        "variant_counts": dict(Counter(record["variant"] for record in joined)),
        "category_codes": {
            category: sorted(codes) for category, codes in CATEGORY_CODES.items()
        },
        "interpretation_boundary": (
            "Rates describe obligation failures of the pinned model and prompts on the "
            "declared CICAPT packages. Categories overlap and are not causal error labels."
        ),
        "summary_rows": summary_rows,
        "error_code_rows": code_rows,
    }
    valid_record = next(
        record
        for record in joined
        if record["variant"] == "contracted"
        and record["condition"] == "clean"
        and record["verification"]["contract_valid"]
        and record["parsed_response"]["tactic"] == record["tactic"]
    )
    invalid_record = next(
        record
        for record in joined
        if record["variant"] == "contracted"
        and record.get("corruption_family") == "process_deletion"
        and not record["verification"]["contract_valid"]
    )
    result["illustrative_examples"] = {
        "selection_rule": (
            "First correct contract-valid clean contracted output and first "
            "contract-invalid process-deletion contracted output in the frozen file."
        ),
        "valid_clean": resolve_certificate_example(
            valid_record, inputs[valid_record["sample_id"]]
        ),
        "invalid_process_deletion": resolve_certificate_example(
            invalid_record, inputs[invalid_record["sample_id"]]
        ),
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outputs",
        type=Path,
        default=Path("data/derived/evigate_llm/v6_full/test_outputs.jsonl"),
    )
    parser.add_argument(
        "--truth",
        type=Path,
        default=Path("data/derived/evigate_llm/manifest_v4/evigate_llm.truth.jsonl"),
    )
    parser.add_argument(
        "--inputs",
        type=Path,
        default=Path("data/derived/evigate_llm/manifest_v4/evigate_llm.inputs.jsonl"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/derived/llm_failure_taxonomy"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    payload = analyze(args.outputs, args.truth, args.inputs)
    write_csv(
        args.output_dir / "llm_failure_taxonomy_by_variant_family.csv",
        payload["summary_rows"],
    )
    write_csv(
        args.output_dir / "llm_failure_taxonomy_error_codes.csv",
        payload["error_code_rows"],
    )
    payload["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    payload["inputs"] = {
        "outputs": {
            "path": args.outputs.as_posix(),
            "sha256": sha256_file(args.outputs),
        },
        "truth": {
            "path": args.truth.as_posix(),
            "sha256": sha256_file(args.truth),
        },
        "inputs": {
            "path": args.inputs.as_posix(),
            "sha256": sha256_file(args.inputs),
        },
    }
    examples_path = args.output_dir / "llm_certificate_examples.json"
    examples_path.write_text(
        json.dumps(payload["illustrative_examples"], indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    json_path = args.output_dir / "llm_failure_taxonomy.json"
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "outputs": payload["output_count"],
                "variants": payload["variant_counts"],
                "artifact": json_path.as_posix(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
