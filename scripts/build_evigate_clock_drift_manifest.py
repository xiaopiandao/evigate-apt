#!/usr/bin/env python3
"""Build signed clock-offset packages with models fitted on clean data only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_evigate_llm_manifest import build_evidence_case, sample_id, write_jsonl
from run_stage_b_typed_ranker import load_jsonl, sha256_file
from run_stage_c_selective_attribution import (
    TACTICS,
    fit_entity_ranker,
    fit_tactic_models,
    make_representation,
    partition_ids,
    tactic_posteriors,
)


def parse_shifted_inputs(values: list[str]) -> dict[int, Path]:
    result: dict[int, Path] = {}
    for value in values:
        try:
            offset_text, path_text = value.split("=", 1)
            offset = int(offset_text)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"expected OFFSET=PATH, received {value!r}"
            ) from error
        if offset in result:
            raise ValueError(f"duplicate offset {offset}")
        result[offset] = Path(path_text)
    if 0 not in result:
        raise ValueError("the shifted-input set must include offset 0")
    return result


def run(args: argparse.Namespace) -> dict[str, Any]:
    base_inputs = {row["case_id"]: row for row in load_jsonl(args.base_inputs)}
    truths = {row["case_id"]: row for row in load_jsonl(args.truth)}
    shifted_paths = parse_shifted_inputs(args.shifted_input)
    shifted_inputs = {
        offset: {row["case_id"]: row for row in load_jsonl(path)}
        for offset, path in shifted_paths.items()
    }
    if set(base_inputs) != set(truths):
        raise ValueError("base inputs and truth sidecar have different case IDs")
    for offset, rows in shifted_inputs.items():
        if set(rows) != set(base_inputs):
            raise ValueError(f"offset {offset} has a different case-ID set")

    packages: list[dict[str, Any]] = []
    package_truth: list[dict[str, Any]] = []
    fold_counts: dict[str, int] = {}
    for fold in (1, 2, 3):
        train_ids = sorted(partition_ids(truths, fold, "train", in_support=True))
        test_ids = sorted(partition_ids(truths, fold, "test", in_support=True))
        ranker = fit_entity_ranker(train_ids, base_inputs, truths, args.seed)
        train_representations = {
            case_id: make_representation(base_inputs[case_id], ranker)
            for case_id in train_ids
        }
        tactic_models = fit_tactic_models(
            train_ids, train_representations, truths, args.seed
        )
        fold_counts[str(fold)] = len(test_ids)
        for offset in sorted(shifted_inputs):
            for case_id in test_ids:
                evidence = build_evidence_case(
                    shifted_inputs[offset][case_id],
                    ranker,
                    "clean",
                    replacement=None,
                    top_k=args.top_k,
                    machine_proposal=None,
                )
                representation = make_representation(
                    shifted_inputs[offset][case_id], ranker
                )
                probabilities = tactic_posteriors(tactic_models, representation)[
                    "combined"
                ]
                probability_map = {
                    tactic: float(probability)
                    for tactic, probability in zip(TACTICS, probabilities)
                }
                ordered = sorted(probability_map.values(), reverse=True)
                proposal_tactic = max(probability_map, key=probability_map.get)
                evidence["machine_proposal"] = {
                    "tactic": proposal_tactic,
                    "confidence": round(probability_map[proposal_tactic], 6),
                    "margin": round(ordered[0] - ordered[1], 6),
                    "probabilities": {
                        key: round(value, 6)
                        for key, value in probability_map.items()
                    },
                }
                condition = f"clock_offset_{offset:+d}s"
                opaque_sample_id = sample_id(case_id, condition)
                packages.append(
                    {
                        "sample_id": opaque_sample_id,
                        "test_fold": fold,
                        "clock_offset_seconds": offset,
                        **evidence,
                    }
                )
                package_truth.append(
                    {
                        "sample_id": opaque_sample_id,
                        "case_id": case_id,
                        "test_fold": fold,
                        "clock_offset_seconds": offset,
                        "tactic": truths[case_id]["event"]["tactic"],
                        "support_role": truths[case_id]["event"]["support_role"],
                    }
                )

    packages.sort(key=lambda row: (row["clock_offset_seconds"], row["sample_id"]))
    package_truth.sort(
        key=lambda row: (row["clock_offset_seconds"], row["sample_id"])
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    input_path = args.output_dir / "clock_drift.inputs.jsonl"
    truth_path = args.output_dir / "clock_drift.truth.jsonl"
    write_jsonl(input_path, packages)
    write_jsonl(truth_path, package_truth)
    summary = {
        "schema_version": "1.0",
        "study": "EviGate signed relative clock-drift package manifest",
        "status": "post-freeze stress test",
        "seed": args.seed,
        "top_k": args.top_k,
        "offsets_seconds": sorted(shifted_inputs),
        "fit_source": {
            "path": str(args.base_inputs),
            "sha256": sha256_file(args.base_inputs),
        },
        "truth_source": {
            "path": str(args.truth),
            "sha256": sha256_file(args.truth),
        },
        "shifted_sources": {
            str(offset): {"path": str(path), "sha256": sha256_file(path)}
            for offset, path in sorted(shifted_paths.items())
        },
        "fold_test_events": fold_counts,
        "packages": len(packages),
        "artifacts": {
            input_path.name: sha256_file(input_path),
            truth_path.name: sha256_file(truth_path),
        },
    }
    summary_path = args.output_dir / "clock_drift.manifest.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument(
        "--shifted-input", action="append", required=True, metavar="OFFSET=PATH"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), indent=2, sort_keys=True))
