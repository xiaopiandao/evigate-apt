# EviGate-APT: failure-aware cross-view evidence binding

This repository contains the research code, tests, prompt contracts, schemas, manuscript source, vector figures, and selected aggregate result summaries for **EviGate-APT**, an IoT network-forensics evaluation protocol built on CICAPT-IIoT2024. The main evaluation is a within-campaign study. It does **not** establish direct packet-to-PID causality, cross-campaign transfer, or edge-board performance.

## What is included

| Path | Contents |
|---|---|
| `scripts/` | Data preparation, Stage A/B/C models, EviGate-LLM/BindGate evaluation, diagnostics, figure generation, and manuscript conversion |
| `tests/` | Portable synthetic-fixture unit tests; full-workspace artifact audits require regenerated data |
| `schemas/`, `prompts/` | Evidence and LLM response contracts, and the recorded prompt variants |
| `paper/`, `references/`, `submission/iotj/` | Current manuscript/supplement source, figures, bibliography, and IEEE build files |
| `results/` | Aggregate JSON summaries and the original full-workspace audit record; these are not a substitute for raw data or per-case outputs |
| `docs/` | Selected frozen protocols and audit reports |
| `MANIFEST.sha256` | SHA-256 digest of every packaged file |

The repository deliberately excludes third-party raw CICAPT files, packet captures, serialized per-case evidence graphs, model weights, generated LLM outputs, local environments, and credentials. See [DATA_ACCESS.md](DATA_ACCESS.md) and [RESULTS.md](RESULTS.md). No code licence is asserted until the authors choose one; GitHub publication alone does not grant reuse rights.

## Environment and portable checks

The code was developed with Python 3.11. Install the CPU environment:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-stage-a.txt
.venv\Scripts\python.exe -m unittest discover -s tests -q
```

On Linux/macOS, use `python3.11 -m venv .venv` and `.venv/bin/python` in the corresponding commands. Figure generation additionally requires `requirements-figures.txt`. The optional local LLM runner has a separate, CUDA-oriented environment in `requirements-llm.txt`; it is not required for the CPU-only cascade or unit tests.

The 114 portable tests use synthetic fixtures. The full-workspace claim audit (`scripts/audit_evigate_submission_claims.py`) additionally needs the complete generated `data/derived/` tree, figure source-data files, and raw data at the documented paths. A pass recorded in `results/full_workspace_integrity_audit.json` is an audit of the authors' source workspace, not independent replication from this compact repository.

## Data-to-result route

1. Obtain the Phase 1/2 CICAPT-IIoT network and provenance data from the original provider; place them under `data/raw/cicapt/` as specified in [DATA_ACCESS.md](DATA_ACCESS.md).
2. Run `scripts/build_cicapt_cluster_manifest.py` and `scripts/build_cicapt_split_manifest.py` with the documented 300-s clustering and embargo settings. The first-stage commands and source hashes are in `docs/11_evigate_apt_week1_data_gate.md`.
3. Generate evidence packages and run Stage A/B/C using the corresponding scripts under `scripts/`. Frozen BindGate, clock, and host-link protocols are in `docs/36_*`, `docs/43_*`, `docs/45_*`, and `docs/47_*`. Each script exposes `--help` for inputs and outputs.
4. Compare new summaries with `results/` and run the full claim audit after regenerating all required intermediate files.

This is a research-code release, **not** a one-command reproduction image. The large, third-party data and optional 7B model must be obtained separately. The original study distinguishes the frozen LLM hypotheses from the post-freeze BindGate analysis; do not treat the latter as preregistered.

## Manuscript build

The IEEE source is generated from `paper/evigate_apt_main.md` with `submission/iotj/build.ps1`; the supplement uses `submission/iotj/build_supplement.ps1`. Supply Pandoc and Tectonic explicitly unless you have the original workspace's `.tmp_tools` layout:

```powershell
submission\iotj\build.ps1 -PandocPath C:\path\to\pandoc.exe -TectonicPath C:\path\to\tectonic.exe
submission\iotj\build_supplement.ps1 -PandocPath C:\path\to\pandoc.exe -TectonicPath C:\path\to\tectonic.exe
```

`IEEEtran.cls` is redistributed under its own LaTeX Project Public License notice. It is not covered by any future licence selected for this project's code. Author metadata in the public package is an example only.

## Scope and citation

Please cite the paper and the original CICAPT-IIoT2024 dataset when using this work. The paper is not yet associated with a final DOI or public code-release identifier; do not invent either. Findings apply to the audited CICAPT campaign and the stated event construction, folds, and collection assumptions.
