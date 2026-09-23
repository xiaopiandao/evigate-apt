"""Summarize second-model and stochastic-decoding EviGate reviewer diagnostics."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np


ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def as_bool(value: object) -> bool:
    return str(value).strip().lower() == "true"


def load_base(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            row: dict[str, Any] = dict(raw)
            for field in (
                "binding_pass",
                "margin_pass",
                "temporal_admissibility_pass",
                "full_cascade_attributed",
                "full_cascade_correct",
                "cascade_attributed",
                "cascade_correct",
            ):
                if field in row:
                    row[field] = as_bool(row[field])
            if "full_cascade_attributed" not in row:
                row["full_cascade_attributed"] = row["cascade_attributed"]
                row["full_cascade_correct"] = row["cascade_correct"]
            output[row["sample_id"]] = row
    return output


def llm_attribute(output: dict[str, Any]) -> tuple[bool, str | None]:
    verification = output.get("verification", {})
    response = output.get("parsed_response")
    accepted = bool(
        isinstance(response, dict)
        and verification.get("contract_valid")
        and verification.get("verifier_decision") == "attribute"
    )
    return accepted, str(response.get("tactic")) if accepted else None


def summarize(rows: Iterable[dict[str, Any]]) -> dict[str, float | int | None]:
    material = list(rows)
    accepted = [row for row in material if row["attributed"]]
    correct = [row for row in material if row["correct"]]
    wrong = len(accepted) - len(correct)
    return {
        "events": len(material),
        "accepted": len(accepted),
        "correct": len(correct),
        "wrong": wrong,
        "coverage": len(accepted) / len(material) if material else None,
        "wrong_label_rate": wrong / len(material) if material else None,
        "selective_risk": wrong / len(accepted) if accepted else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-per-case", type=Path, required=True)
    parser.add_argument("--sampling-outputs", type=Path, required=True)
    parser.add_argument("--second-model-per-case", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base = load_base(args.base_per_case)
    outputs = [
        row
        for row in load_jsonl(args.sampling_outputs)
        if row.get("variant") == "contracted"
    ]
    sampling_rows: list[dict[str, Any]] = []
    for output in outputs:
        source = base[output["sample_id"]]
        llm_ok, prediction = llm_attribute(output)
        attributed = bool(
            llm_ok
            and source["binding_pass"]
            and source["margin_pass"]
            and source["temporal_admissibility_pass"]
        )
        sampling_rows.append(
            {
                "sample_id": output["sample_id"],
                "replicate": int(output.get("sampling_replicate", 0)),
                "family": source["corruption_family"],
                "truth": source["tactic"],
                "attributed": attributed,
                "prediction": prediction if attributed else None,
                "correct": bool(attributed and prediction == source["tactic"]),
                "contract_valid": bool(output.get("verification", {}).get("contract_valid")),
            }
        )

    replicates = sorted({row["replicate"] for row in sampling_rows})
    expected_ids = {
        sample_id
        for sample_id, row in base.items()
        if row["corruption_family"] in {"clean", "context_replacement"}
    }
    by_replicate: dict[str, dict] = {}
    for replicate in replicates:
        selected = [row for row in sampling_rows if row["replicate"] == replicate]
        if {row["sample_id"] for row in selected} != expected_ids:
            raise ValueError(f"replicate {replicate} is incomplete")
        by_replicate[str(replicate)] = {
            family: summarize(row for row in selected if row["family"] == family)
            for family in ("clean", "context_replacement")
        }

    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sampling_rows:
        by_sample[row["sample_id"]].append(row)
    stability = []
    for sample_id, sample_rows in sorted(by_sample.items()):
        decisions = [bool(row["attributed"]) for row in sample_rows]
        predictions = [row["prediction"] for row in sample_rows]
        stability.append(
            {
                "sample_id": sample_id,
                "family": sample_rows[0]["family"],
                "acceptance_rate": float(np.mean(decisions)),
                "unanimous_attribution_decision": len(set(decisions)) == 1,
                "unique_predictions_including_abstention": len(set(predictions)),
            }
        )

    summary: dict[str, Any] = {
        "study": "EviGate-LLM model and decoding robustness",
        "sampling": {
            "replicates": len(replicates),
            "replicate_results": by_replicate,
            "mean_results": {
                family: {
                    metric: float(
                        np.mean(
                            [
                                by_replicate[str(replicate)][family][metric]
                                for replicate in replicates
                            ]
                        )
                    )
                    for metric in ("coverage", "wrong_label_rate")
                }
                for family in ("clean", "context_replacement")
            },
            "decision_unanimity_rate": float(
                np.mean([row["unanimous_attribution_decision"] for row in stability])
            ),
            "packages_with_prediction_variation": sum(
                row["unique_predictions_including_abstention"] > 1 for row in stability
            ),
            "packages": len(stability),
        },
        "input_integrity": {
            "base_per_case_sha256": sha256_file(args.base_per_case),
            "sampling_outputs_sha256": sha256_file(args.sampling_outputs),
        },
    }
    if args.second_model_per_case:
        second = load_base(args.second_model_per_case)
        second_rows = list(second.values())
        summary["second_model"] = {
            family: summarize(
                {
                    "attributed": row["full_cascade_attributed"],
                    "correct": row["full_cascade_correct"],
                }
                for row in second_rows
                if row["corruption_family"] == family
            )
            for family in (
                "clean",
                "socket_type_deletion",
                "random_entity_deletion",
                "context_replacement",
                "process_deletion",
                "time_shift",
            )
        }
        summary["input_integrity"]["second_model_per_case_sha256"] = sha256_file(
            args.second_model_per_case
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
