"""Assemble reproducible incident reports from local synthetic telemetry."""

from collections import Counter
from pathlib import Path

from .config import Config
from .correlation import correlate, score
from .detection import detect
from .investigation import investigate
from .normalization import load_events


def run(data: Path, config: Config) -> dict:
    events = load_events(data)
    signals = detect(events, config)
    incidents = []
    for number, candidate in enumerate(correlate(events, signals, config), 1842):
        incidents.append({
            "incident_id": number,
            "category": "Credential Attack Candidate",
            "synthetic": True,
            "user": candidate.user,
            "source_ip": candidate.source_ip,
            "risk": score(candidate.signals),
            "signals": [signal.to_dict() for signal in candidate.signals],
            "investigation": investigate(candidate),
            "timeline": [event.to_dict() for event in candidate.events],
            "status": "PENDING",
            "proposed_response": {"action": "simulate_account_isolation", "target": candidate.user},
            "audit": [],
        })
    return {"schema_version": 1, "synthetic": True, "mode": "offline-lab",
            "telemetry_counts": dict(sorted(Counter(event.source for event in events).items())),
            "event_count": len(events), "signal_count": len(signals), "incidents": incidents}
