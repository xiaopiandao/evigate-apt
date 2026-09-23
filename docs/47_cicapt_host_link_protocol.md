# CICAPT-IIoT host-link audit protocol

## Status and purpose

This is a **post-freeze, post-hoc dataset audit**. It does not change any model,
split, threshold, event definition, or previously frozen hypothesis. Its purpose
is to test a narrower question raised during review: whether the released
network view contains data-internal evidence that it involves the Ubuntu VM1
host from which the provenance stream was collected.

The audit distinguishes three claims:

1. **Host membership:** a network endpoint can be associated with the
   provenance host.
2. **Event membership:** a reconstructed attack event has both network and
   provenance observations and its attack-labelled network rows touch that
   endpoint.
3. **Process causality:** a particular malicious PID generated a particular
   packet stream.

The audit can support Claims 1 and 2. It cannot establish Claim 3 because the
released socket artifacts omit local address and local port.

## Frozen audit rule

1. Read every provenance `network socket` artifact and its timestamped
   `WasGeneratedBy(..., operation=connect)` edge to a process entity.
2. Exclude loopback remote addresses and non-positive remote ports.
3. For every remaining process-socket observation, search the complete Phase 2
   network table for a row with the same remote IP and remote port.
4. Retain the nearest row when the absolute timestamp difference is at most
   0.1 s. The opposite endpoint of that row is the inferred local endpoint.
5. Treat endpoints with at least ten matches as candidates. Use only the
   highest-count candidate as the primary host-link endpoint; retain all other
   candidates as ambiguous secondary endpoints. This prevents common DNS
   traffic observed near-simultaneously on another host from being silently
   converted into a multi-interface claim.
6. Repeat the same join after shifting all provenance times by -60, -30, +30,
   and +60 s. These shifts are negative controls, not clock-robustness tests.
7. A case is `host_link_supported` only when (a) its reconstructed cluster has
   both views and (b) at least one attack-labelled network row assigned to the
   cluster touches the primary endpoint.

The 0.1-s tolerance, ten-observation candidate threshold, and primary-endpoint
rule were selected after exploratory inspection and are therefore diagnostic
choices. Results must not be described as confirmatory or as an authoritative
topology map. Endpoint counts at 0.05 s are retained as a stricter sensitivity
check.

## Outputs

The executable audit writes:

- a per-socket match table with process, endpoint, time, and nearest-row delta;
- endpoint support and time-shift negative-control summaries;
- per-case host-link status;
- clean and context-replacement results restricted to supported, non-pilot
  cases;
- a SHA-256 manifest covering inputs and outputs.

## Interpretation rule

Passing the audit licenses the statement that repeated process-socket/network
tuple matches provide data-internal evidence that the two released views involve
the same monitored host. It does not license packet-to-PID attribution, causal
responsibility, chain-of-custody, or a claim that every process execution in the
window belongs to the network incident.
