#!/usr/bin/env python3
"""Run deterministic local-model inference for EviGate-LLM prompt variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any

from evigate_llm_contract import (
    build_user_prompt,
    extract_json_object,
    load_prompt,
    verify_response,
)


VARIANTS = ("direct", "self_abstain", "contracted")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        handle.write("\n")


def completed_keys(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    return {
        (
            str(row["variant"]),
            str(row["sample_id"]),
            int(row.get("sampling_replicate", 0)),
        )
        for row in load_jsonl(path)
        if "variant" in row and "sample_id" in row
    }


def parse_variants(raw: str) -> list[str]:
    values = [item.strip() for item in raw.split(",") if item.strip()]
    invalid = sorted(set(values) - set(VARIANTS))
    if invalid:
        raise ValueError(f"unknown variants: {invalid}")
    return values


def select_rows(rows: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    selected = sorted(rows, key=lambda row: row["sample_id"])
    if args.sample_ids:
        requested = {item.strip() for item in args.sample_ids.split(",") if item.strip()}
        selected = [row for row in selected if row["sample_id"] in requested]
        missing = requested - {row["sample_id"] for row in selected}
        if missing:
            raise ValueError(f"sample IDs not found: {sorted(missing)}")
    if args.limit is not None:
        selected = selected[: args.limit]
    return selected


def model_file_inventory(model_path: Path, hash_weights: bool) -> list[dict[str, Any]]:
    if not model_path.exists() or not model_path.is_dir():
        return []
    rows = []
    for path in sorted(item for item in model_path.rglob("*") if item.is_file()):
        relative = path.relative_to(model_path).as_posix()
        if relative.startswith(".cache/"):
            continue
        record = {"path": relative, "bytes": path.stat().st_size}
        if hash_weights or path.suffix not in {".safetensors", ".bin"}:
            record["sha256"] = sha256_file(path)
        rows.append(record)
    return rows


def run(args: argparse.Namespace) -> dict[str, Any]:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if not torch.cuda.is_available() and args.device == "cuda":
        raise RuntimeError("CUDA was requested but is unavailable")
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    evidence_rows = load_jsonl(args.inputs)
    selected = select_rows(evidence_rows, args)
    variants = parse_variants(args.variants)
    prompt_text = {
        variant: load_prompt(args.prompt_dir / f"{variant}.txt") for variant in variants
    }
    prompt_hashes = {
        variant: sha256_bytes(text.encode("utf-8"))
        for variant, text in prompt_text.items()
    }
    done = completed_keys(args.output)

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        revision=args.revision,
        cache_dir=str(args.cache_dir) if args.cache_dir else None,
        trust_remote_code=False,
        local_files_only=args.local_files_only,
    )
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"
    dtype = torch.bfloat16 if args.dtype == "bfloat16" else torch.float16
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        revision=args.revision,
        cache_dir=str(args.cache_dir) if args.cache_dir else None,
        trust_remote_code=False,
        local_files_only=args.local_files_only,
        dtype=dtype,
    )
    model.to(args.device)
    model.eval()
    model.generation_config.do_sample = args.do_sample
    model.generation_config.temperature = args.temperature if args.do_sample else None
    model.generation_config.top_p = args.top_p if args.do_sample else None
    model.generation_config.top_k = None

    started = time.perf_counter()
    generated = 0
    total_requested = len(variants) * len(selected) * args.replicates
    for replicate in range(args.replicates):
        for variant in variants:
            pending = [
                row
                for row in selected
                if (variant, row["sample_id"], replicate) not in done
            ]
            for offset in range(0, len(pending), args.batch_size):
                batch = pending[offset : offset + args.batch_size]
                rendered = [
                    tokenizer.apply_chat_template(
                        [
                            {"role": "system", "content": prompt_text[variant]},
                            {
                                "role": "user",
                                "content": build_user_prompt(
                                    row, include_machine_proposal=variant != "direct"
                                ),
                            },
                        ],
                        tokenize=False,
                        add_generation_prompt=True,
                        enable_thinking=not args.disable_thinking,
                    )
                    for row in batch
                ]
                encoded = tokenizer(
                    rendered,
                    return_tensors="pt",
                    padding=True,
                    truncation=True,
                    max_length=args.max_input_tokens,
                ).to(args.device)
                batch_started = time.perf_counter()
                with torch.inference_mode():
                    output_ids = model.generate(
                        **encoded,
                        do_sample=args.do_sample,
                        temperature=args.temperature if args.do_sample else None,
                        top_p=args.top_p if args.do_sample else None,
                        max_new_tokens=args.max_new_tokens,
                        pad_token_id=tokenizer.pad_token_id,
                        eos_token_id=tokenizer.eos_token_id,
                        use_cache=True,
                    )
                elapsed = time.perf_counter() - batch_started
                prompt_width = encoded["input_ids"].shape[1]
                for row, sequence in zip(batch, output_ids):
                    raw_text = tokenizer.decode(
                        sequence[prompt_width:], skip_special_tokens=True
                    ).strip()
                    parsed, parse_error = extract_json_object(raw_text)
                    verification = verify_response(
                        parsed,
                        row,
                        parse_error=parse_error,
                        enforce_machine_proposal=variant != "direct",
                    )
                    append_jsonl(
                        args.output,
                        {
                            "schema_version": "1.0",
                            "sample_id": row["sample_id"],
                            "case_id": row["case_id"],
                            "test_fold": row["test_fold"],
                            "variant": variant,
                            "sampling_replicate": replicate,
                            "model": args.model,
                            "model_revision": getattr(model.config, "_commit_hash", None)
                            or args.revision,
                            "prompt_sha256": prompt_hashes[variant],
                            "decoding": {
                                "do_sample": args.do_sample,
                                "temperature": args.temperature if args.do_sample else None,
                                "top_p": args.top_p if args.do_sample else None,
                                "sampling_replicate": replicate,
                                "thinking_disabled": args.disable_thinking,
                                "max_input_tokens": args.max_input_tokens,
                                "max_new_tokens": args.max_new_tokens,
                            },
                            "raw_text": raw_text,
                            "parsed_response": parsed,
                            "parse_error": parse_error,
                            "verification": verification,
                            "batch_runtime_seconds": elapsed,
                        },
                    )
                    generated += 1
                    print(
                        f"[{variant}:r{replicate}] {generated}/{total_requested} "
                        f"{row['sample_id']} valid={verification['contract_valid']}",
                        flush=True,
                    )

    model_path = Path(args.model)
    metadata = {
        "schema_version": "1.0",
        "study": (
            "EviGate-LLM stochastic inference"
            if args.do_sample
            else "EviGate-LLM deterministic inference"
        ),
        "inputs": {"path": str(args.inputs), "sha256": sha256_file(args.inputs)},
        "output": {"path": str(args.output), "sha256": sha256_file(args.output)},
        "model": args.model,
        "requested_revision": args.revision,
        "resolved_revision": getattr(model.config, "_commit_hash", None),
        "model_files": model_file_inventory(model_path, args.hash_model_files),
        "variants": variants,
        "prompt_hashes": prompt_hashes,
        "seed": args.seed,
        "do_sample": args.do_sample,
        "temperature": args.temperature if args.do_sample else None,
        "top_p": args.top_p if args.do_sample else None,
        "replicates": args.replicates,
        "thinking_disabled": args.disable_thinking,
        "dtype": args.dtype,
        "device": args.device,
        "batch_size": args.batch_size,
        "selected_samples": len(selected),
        "new_generations": generated,
        "total_saved_rows": len(load_jsonl(args.output)),
        "runtime_seconds": time.perf_counter() - started,
        "software": {
            "torch": torch.__version__,
            "transformers": __import__("transformers").__version__,
        },
    }
    args.metadata.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", default="main")
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--prompt-dir", type=Path, default=Path("prompts/evigate_llm_v1"))
    parser.add_argument("--variants", default=",".join(VARIANTS))
    parser.add_argument("--sample-ids", default="")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--max-input-tokens", type=int, default=4096)
    parser.add_argument("--max-new-tokens", type=int, default=384)
    parser.add_argument("--seed", type=int, default=20260915)
    parser.add_argument("--do-sample", action="store_true")
    parser.add_argument("--temperature", type=float, default=0.6)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--replicates", type=int, default=1)
    parser.add_argument(
        "--disable-thinking",
        action="store_true",
        help="Disable Qwen3-style thinking blocks in the chat template.",
    )
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--dtype", choices=("bfloat16", "float16"), default="bfloat16")
    parser.add_argument("--local-files-only", action="store_true")
    parser.add_argument("--hash-model-files", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
