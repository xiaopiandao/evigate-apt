# CICAPT-IIoT author-source host mapping audit

Date: 2026-09-23. Scope: source discovery, local endpoint verification, and an audit of the user-downloaded official supplementary files. The findings were subsequently incorporated into the manuscript as source and claim-boundary corrections; no model was retrained, event definition changed, or packet-to-process causality claimed.

## Primary source found

Erfan Ghiasvand, *Resilience against APTs: A provenance-based dataset and attack detection framework*, University of New Brunswick master's thesis, June 2024, [institutional record](https://unbscholar.lib.unb.ca/handle/1882/38065), [PDF](https://unbscholar.dspace.lib.unb.ca/server/api/core/bitstreams/2cca33ed-6241-4ec7-914c-da8ed6dc96da/content).

- Table 3.1 (printed p. 36; PDF page 47) explicitly assigns `172.16.63.128`, `172.16.64.2`, `172.16.65.2`, `172.16.66.2`, `172.16.67.2`, and `200.200.200.2` to Ubuntu VM1. It assigns `172.16.65.128` to Kali VM1, the internal attacker and Caldera server. It assigns `172.16.67.128` to Raspberry Pi2, not Ubuntu VM1.
- Section 3.2.2 (printed p. 35; PDF page 46) explicitly designates Ubuntu VM1 as the Caldera victim machine with an installed agent.
- Section 3.2.3 (printed p. 36) states that Ubuntu VM1 hosts Auditd and SPADE. Figure 3.4 (printed p. 34) shows the gateway/attacker/testbed topology and NS3 tap bridges, but it does not provide a per-PCAP capture-interface map, MAC addresses, or NAT translation log.
- Section 3.4.2 (printed pp. 40--42; PDF pp. 51--53) describes **separate** label derivation: Caldera activity PIDs and descendants label provenance, while calibrated NS3 packet times, Caldera action times, and attacker/victim IPs label individual network packets. The text does not specify a released packet identifier or five-tuple-to-PID causal join.
- The thesis abstract calls the dataset `CICADA-IIoT`, whereas the subsequent paper and official dataset page call it `CICAPT-IIoT`. The author, testbed design, APT scenario, and Phase 2 attack-network count of 1,004 agree. Cite the thesis by its own title and note the naming difference if necessary; do not silently assume the names are interchangeable.

The [CICAPT-IIoT paper](https://arxiv.org/html/2407.11278) independently confirms Ubuntu VM1's gateway/Auditd/SPADE role and a Phase 2 network attack count of 1,004, although it does not print the detailed IP table. The [official dataset page](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html) advertises individual and merged NS3 PCAPs and `Attack_info.csv` with attack time, PID, and category.

## Local verification against the released CSV

Source: `data/raw/cicapt/network/phase2_NetworkData.csv`. Streamed all 9,536,823 rows and selected the 1,004 records with `label=1`; counted exact `Source IP`/`Destination IP` pairs:

| Direction | Attack-labelled rows |
|---|---:|
| Kali VM1 `172.16.65.128` -> Ubuntu VM1 `172.16.63.128` | 538 |
| Ubuntu VM1 `172.16.63.128` -> Kali VM1 `172.16.65.128` | 466 |
| Any other address pair | 0 |

Reproduction from repository root (read-only):

```powershell
python -c 'import csv,collections; f=open("data/raw/cicapt/network/phase2_NetworkData.csv",newline="",encoding="utf-8-sig"); r=csv.DictReader(f); a=[(x["Source IP"],x["Destination IP"]) for x in r if x["label"]=="1"]; print(len(a)); print(collections.Counter(a))'
```

This corroborates the author-documented Kali VM1 to Ubuntu VM1 attack path. The previous [data-internal host-link audit](48_cicapt_host_link_results.md) is still useful as an independent consistency check, but its inferred IP ownership should no longer be presented as the best available source. Its secondary `172.16.67.128` candidate is identified in the author's Table 3.1 as Raspberry Pi2; it must not be described as a possible Ubuntu VM1 interface.

## Claim boundary and remaining source gap

The author-source topology plus the raw attack-row endpoint audit supports **network/provenance host co-membership** for events with both released views. The current case manifest has 33 both-view clusters, including 32/53 in-support and 31/51 evaluated non-pilot events. The other events must remain network-only or provenance-only rather than being called confirmed cross-view pairs.

This does **not** establish a packet-to-malicious-PID link: the released socket artifacts lack usable local address/port for that join, and the existing audit found no direct malicious-process-to-flow match. It also does not independently validate every union-derived event boundary or tactic correspondence. For those stronger claims, the remaining inputs are original per-interface PCAPs/capture-point names, if available Caldera agent-target/step metadata, and raw socket/audit records with local endpoints. The now-available `attack_info.csv` provides an additional cross-check, but its time/PID pairs require caution as detailed below.

The local Kaggle network ZIP contains only `phase1_NetworkData.csv` and `phase2_NetworkData.csv`; the local provenance CSVs are separate. Through the user's local Chrome browser, the official `Supplementary Material` directory visibly lists `attack_info.csv`, `Readme.txt`, `Node2Vec final.ipynb`, and `pcap2csv/`. The `Network_Traffic/Phase2` directory visibly lists eleven per-node PCAPs (`2ndPhase-0-0.pcap` through `2ndPhase-0-5.pcap` and `2ndPhase-1-0.pcap` through `2ndPhase-5-0.pcap`), `2ndPhase-timed-MergedV2.pcap`, and `phase2_NetworkData.csv`. The official `Provenance_Logs` directory lists the two provenance CSVs. The user subsequently downloaded the two small supplementary files into the repository root. The browser-control block described in the previous audit was local to the agent and did not prevent the user's download.

## Downloaded supplementary-file audit

The local files are `attack_info.csv` (4,310 bytes; SHA-256 `C4187AE745875D16BA2823E28E7059B834D4865C305F81717D75066EC2E2A172`) and `Readme.txt` (478 bytes; SHA-256 `48825A3A2E254266343A8756552B99DC847EAF0918143D8B8013AE6D3DF5613B`). The README states that `Attack_info.csv` was extracted from MITRE Caldera reports. These are local integrity fingerprints, not hashes independently published by the dataset provider.

- `attack_info.csv` contains 58 rows with attack time, tactic, technique, and PID: 45 non-cleanup steps and 13 cleanup records. Its eight tactic strings are Collection (24), Cleanup (13), Discovery (9), Credential Access (4), Exfiltration (3), Command and Control (3), Persistence (1), and Lateral Movement (1).
- All 58 distinct listed PIDs appear in Phase 2 provenance as `Process` entities, each represented by two rows (116 rows in total). All 116 Process rows have `label=1`. The seven non-cleanup tactic names correspond to provenance `subLabel` after the dataset's naming normalization (`CandC`, `credentialAccess`, `lateralMovement`); the 13 cleanup PIDs carry `defenceEvasion` in provenance. This confirms source-level membership of the listed PIDs in the VM1 provenance corpus, not a packet-to-PID linkage.
- All 1,004 attack-labeled network rows use the author-mapped Kali VM1/Ubuntu VM1 endpoint pair. For every one of the 58 attack-info timestamps, the nearest **same-tactic** attack-labeled network row lies within 30 seconds (median 25.444 s; maximum 28.853 s). This supports the campaign-level network/VM1-provenance co-membership argument. It does not show that the nearest packet was caused by the PID listed on that same CSV row.
- A systematic time/PID alignment warning prevents direct per-step joining: among the 45 non-cleanup rows, only one listed PID's provenance process time is within 60 s of its **own row's** `Time of Attack` (the process-time difference ranges from 30.7 to 4,374.6 s). For the first 44 non-cleanup rows, 38 corresponding process times are within 60 s of the **next row's** attack time, and 43 are within 300 s (maximum 303.7 s). The 13 cleanup process times occur 25--49 s after their shared attack-info timestamp. The mechanism behind the offset is unknown; do not silently shift rows or use these time/PID pairs as packet-level ground truth.

The downloaded file therefore strengthens **host co-membership** because its 58 PIDs are present and attack-labeled in the author-identified VM1 provenance while attack traffic uses VM1's author-mapped IP. The author's documented label-derivation procedure additionally establishes packet-level attack labels and PID-based provenance labels. This audit does not independently verify a same-step, same-flow, or causal packet-to-PID join. The original per-interface PCAPs have not been downloaded or audited.

## Manuscript correction applied

The main manuscript now cites the author's thesis for the VM1-to-IP map and the separate packet/process labeling procedures, as well as the official dataset page for `Attack_info.csv`. It presents the 31-event evaluated subgroup as author-mapped host co-membership corroborated by the local socket and supplementary-file audits, while stating precisely that this study does not test direct packet-to-PID causality. The supplement reports the full PID and timing audit. The 59 union-derived events remain distinct from the 58 Caldera rows; no split, truth label, model result, or denominator was changed. The 31-event subgroup counts remain diagnostic and post-freeze.
