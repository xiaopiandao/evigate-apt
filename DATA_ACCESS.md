# Data access and redistribution boundary

The original [CICAPT-IIoT2024 dataset page](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html) describes Phase 1/2 network traffic, provenance CSVs, and a supplementary `Attack_info.csv`. Download those from the provider under its access terms. This code repository does not mirror any of those files. In particular, the network-CSV mirror used during development did not provide a clear redistribution licence, so the raw network files are excluded.

Place the acquired files at these paths relative to the repository root:

```text
data/raw/cicapt/network/phase1_NetworkData.csv
data/raw/cicapt/network/phase2_NetworkData.csv
data/raw/cicapt/Phase1_Provenance.csv
data/raw/cicapt/Phase2_Provenance.csv
```

The audited Phase 2 inputs in the authors' workspace had these SHA-256 hashes. Check the provider's current release before assuming a differing hash is an error:

| File | SHA-256 |
|---|---|
| `phase2_NetworkData.csv` | `90dd6752ead750393f7c75ca157ef27d21861b69f6cbe3d0a8fe295306a638ea` |
| `Phase2_Provenance.csv` | `7f858f479e90ccbe27c3d4f487ddf2f15a26ad0bfa7f472abff3aa68e332976d` |

The released experiment constructs 59 **union-derived tactic clusters** from labelled rows; these are not the 58 rows of the provider's Caldera-derived `Attack_info.csv`. That supplementary file is used only for a post-freeze host-link audit, not to redefine the experiment's cases or splits. See `docs/11_evigate_apt_week1_data_gate.md` and the current manuscript for the exact boundary.

To check local inputs on Windows:

```powershell
Get-FileHash data\raw\cicapt\network\phase2_NetworkData.csv -Algorithm SHA256
Get-FileHash data\raw\cicapt\Phase2_Provenance.csv -Algorithm SHA256
```

Do not commit `data/raw/`, packet captures, account tokens, or model weights. The `.gitignore` blocks the usual paths, but inspect `git status` before every push.
