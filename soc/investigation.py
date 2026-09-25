"""Deterministic template output, explicitly not an LLM or a compromise verdict."""

from .correlation import Candidate


def investigate(candidate: Candidate) -> dict:
    rules = sorted({signal.rule for signal in candidate.signals})
    return {
        "mode": "mock",
        "confidence": "MEDIUM",
        "confidence_basis": "Fixed teaching label, not a calibrated probability",
        "summary": f"Correlated synthetic signals for {candidate.user}: {', '.join(rules)}.",
        "interpretation": "Possible credential attack candidate; telemetry does not prove compromise.",
        "alternative_explanation": "An authorized lab exercise or user retry followed by approved administration.",
        "evidence_ids": sorted({eid for signal in candidate.signals for eid in signal.event_ids}),
        "recommended_actions": ["Validate authentication evidence and configured source-IP baseline",
                                "Review any role changes and synthetic data access in the timeline",
                                "Decide whether to approve simulated account isolation"],
        "requires_human_approval": True,
    }
