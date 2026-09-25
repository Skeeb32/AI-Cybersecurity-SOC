# Mock investigation and analyst review

The mock layer is deterministic Python template code, not an LLM. It receives a
correlated candidate and emits `mode`, `confidence`, `confidence_basis`, `summary`,
`interpretation`, `alternative_explanation`, `evidence_ids`, `recommended_actions`,
and `requires_human_approval`. The fixed MEDIUM label is a teaching convention.

The summary lists the actual candidate's rules. Evidence IDs point to supporting
events. The interpretation consistently avoids claiming proven compromise, and
the alternative explanation includes an authorized exercise or administration.

An analyst should resolve evidence IDs, verify the configured baseline, inspect
the role change and download, and decide whether simulation is warranted. The
investigation cannot call the response command or approve its own recommendation.

Review is explicit: `PENDING` can become `APPROVED` or `REJECTED`. Only `APPROVED`
with its approval audit entry can become `SIMULATED`. Rejected reviews are final
in this small workflow. A fresh report is a separate exercise, not an amendment
to a prior review. Preserve reports when practicing alternate decisions.

The complete initial report is [incident-1842.json](../data/incidents/incident-1842.json).
Real model providers, prompt handling, model evaluation, and output validation are
not implemented. A future integration would need these controls before its output
could even be treated as reliable assistance; it should never authorize response.

Return to the [README](../README.md).
