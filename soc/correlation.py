"""Join evidence around successful authentication in a bounded time window."""

from dataclasses import dataclass

from .config import Config
from .detection import Signal
from .normalization import Event, moment


@dataclass(frozen=True)
class Candidate:
    user: str
    source_ip: str
    events: list[Event]
    signals: list[Signal]


def correlate(events: list[Event], signals: list[Signal], config: Config) -> list[Candidate]:
    candidates = []
    claimed_successes = set()
    for success in events:
        if success.event_type != "login_success" or success.event_id in claimed_successes:
            continue
        anchor = [signal for signal in signals if success.event_id in signal.event_ids
                  and signal.rule in ("repeated_failures_then_success", "unusual_login")]
        if {signal.rule for signal in anchor} != {"repeated_failures_then_success", "unusual_login"}:
            continue
        evidence_ids = {eid for signal in anchor for eid in signal.event_ids}
        start = min(moment(item.timestamp) for item in events if item.event_id in evidence_ids)
        # One total window from the first supporting failure, not an unbounded chain.
        related = [item for item in events if (item.user, item.source_ip) ==
                   (success.user, success.source_ip)
                   and 0 <= (moment(item.timestamp) - start).total_seconds() <= config.window_seconds]
        after = {item.event_id for item in related
                 if moment(item.timestamp) > moment(success.timestamp)}
        extra = [signal for signal in signals if signal.rule in ("privilege_escalation", "large_transfer")
                 and set(signal.event_ids) <= after]
        candidates.append(Candidate(success.user, success.source_ip, related, anchor + extra))
        claimed_successes.update(item.event_id for item in related if item.event_type == "login_success")
    return candidates


def score(signals: list[Signal]) -> dict:
    # Repeated events cannot inflate a rule's contribution.
    factors = {signal.rule: signal.points for signal in signals}
    total = min(100, sum(factors.values()))
    return {"score": total, "level": "HIGH" if total >= 70 else "MEDIUM" if total >= 40 else "LOW",
            "factors": factors, "model": "transparent-lab-heuristic-v1"}
