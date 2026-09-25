# Architecture and data flow

The lab is a standard-library Python package invoked with `python -m soc` from the
repository root. The entry point dispatches three independent commands:

- `run`: load policy, parse telemetry, detect, correlate, score, mock-investigate,
  assemble incidents, and write a new JSON report.
- `review`: record a named analyst's approve/reject decision and reason.
- `respond`: require recorded approval and append a simulated result.

`normalization.py` owns ingestion and semantic event IDs. `detection.py` returns
signals with supporting event IDs. `correlation.py` groups supporting evidence and
computes a unique-rule risk score. `investigation.py` consumes the candidate and
returns a deterministic template assessment. `incidents.py` assembles that result
with the chronological evidence timeline. `response.py` owns report persistence
and review state transitions. Nothing in the runtime opens a network connection.

Reports contain schema version 1, synthetic/mode markers, telemetry and signal
counts, and an incident list. Signal count includes all detected signals, including
ones that may not qualify for a candidate. Incident evidence contains context as
well as scored events; the signal IDs identify which evidence supports risk.

Events are deduplicated by normalized content and ordered by UTC timestamp then
event ID. Multiple candidates receive sequential IDs beginning at 1842. This is
deterministic for the same inputs, not a globally unique incident registry.

Each candidate window starts with its earliest supporting failure and lasts the
configured number of seconds. Authentication resource is used to pair failures
with success; post-login evidence can involve other resources. This simplified
join deliberately leaves causal interpretation to the analyst.

Output uses a same-directory temporary file and atomic replacement, with a
cooperative exclusive lock. New runs cannot overwrite reports. Review audit times
use the real UTC clock; evidence times come from the synthetic records. This is
a single-user local workflow, not a secure multi-user service.

Return to the [README](../README.md).
