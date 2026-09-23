# CICAPT-IIoT host-link audit results

## Outcome

The post-freeze audit provides a data-internal, non-authoritative host-membership
argument for `172.16.63.128`. It does not establish packet-to-PID causality.

## Reproduced evidence

- The provenance file contains 10,787 socket artifacts and 10,787 timestamped
  connect edges. After deduplication, loopback removal, and exclusion of invalid
  ports, 8,077 process-socket observations remain.
- Exact remote-address and remote-port matching against all 9,536,823 network
  rows gives 755 nearest matches within 0.1 s. Of these, 733 identify
  `172.16.63.128` as the opposite endpoint.
- At the stricter 0.05-s threshold, 148 matches still identify
  `172.16.63.128`.
- Shifting provenance timestamps by -60, -30, +30, or +60 s gives zero matches
  at the 0.1-s threshold.
- A secondary candidate, `172.16.67.128`, has 22 matches at 0.1 s, all from the
  DNS process `named`. It is retained as ambiguous and is not used to define
  host-linked events.
- All 1,004 attack-labelled network rows contain the primary endpoint
  `172.16.63.128`.
- The primary endpoint therefore supports all 33 both-view clusters, including
  32/53 in-support clusters and 31/51 evaluated non-pilot events.
- No usable non-loopback socket observation belongs to a malicious-labelled
  process, and no malicious process has a direct socket-to-flow match.

## Post-hoc supported-cohort diagnostic

On the 31 evaluated events that have both released views and attack traffic
touching the primary endpoint:

| Method | Clean accepted | Clean correct | Clean wrong | Clean risk | Context-replacement wrong |
|---|---:|---:|---:|---:|---:|
| EviGate-Bind | 22/31 | 18/31 | 4/31 | 0.182 | 7/31 (0.226) |
| Matched margin | 21/31 | 16/31 | 5/31 | 0.238 | 25/31 (0.806) |

This subgroup was selected after the original experiment was frozen. It is a
scope audit, not independent confirmation of superiority.

## Reproducibility

Run from the repository root:

```powershell
python scripts/audit_cicapt_host_link.py
```

The script emits per-match, per-endpoint, per-case, and subgroup-evaluation
files plus a SHA-256 manifest under `data/derived/host_link_audit/`.
