"""Select clean and foreign-context EviGate packages for decoding robustness."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_EXCLUSIONS = {
    "case_006e5fb8ae17aa011cbb",
    "case_012bac4ea9c61dfbe3ef",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--exclude-case", action="append", default=list(DEFAULT_EXCLUSIONS))
    args = parser.parse_args()

    inputs = load_jsonl(args.inputs)
    truths = load_jsonl(args.truth)
    if [row["sample_id"] for row in inputs] != [row["sample_id"] for row in truths]:
        raise ValueError("input and truth order/sample IDs differ")
    exclusions = set(args.exclude_case)
    selected = [
        package
        for package, truth in zip(inputs, truths, strict=True)
        if truth["case_id"] not in exclusions
        and (
            truth["condition"] == "clean"
            or truth.get("corruption_family") == "context_replacement"
        )
    ]
    if len(selected) != 102:
        raise ValueError(f"expected 102 clean/context packages, found {len(selected)}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in selected:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    metadata = {
        "study": "EviGate-LLM decoding robustness subset",
        "selection": "51 clean and 51 context-replacement packages after the two frozen pilot exclusions",
        "excluded_cases": sorted(exclusions),
        "rows": len(selected),
        "source_inputs_sha256": sha256_file(args.inputs),
        "source_truth_sha256": sha256_file(args.truth),
        "output_sha256": sha256_file(args.output),
    }
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
