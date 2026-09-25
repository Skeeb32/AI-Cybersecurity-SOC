"""Small, inspectable defensive rules. Signals do not prove compromise."""

from dataclasses import asdict, dataclass

from .config import Config
from .normalization import Event, moment


@dataclass(frozen=True)
class Signal:
    rule: str
    points: int
    event_ids: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def detect(events: list[Event], config: Config) -> list[Signal]:
    signals = []
    for event in events:
        if event.event_type == "login_success":
            failed = [item for item in events
                      if item.event_type == "login_failure"
                      and (item.user, item.source_ip, item.resource) ==
                      (event.user, event.source_ip, event.resource)
                      and 0 < (moment(event.timestamp) - moment(item.timestamp)).total_seconds()
                      <= config.window_seconds]
            if len(failed) >= config.failure_threshold:
                signals.append(Signal("repeated_failures_then_success", 20,
                                      tuple(item.event_id for item in failed) + (event.event_id,),
                                      f"{len(failed)} failed logins followed by success"))
            # Missing baseline means unknown, not unusual; fail closed for this rule.
            known = config.known_ips.get(event.user)
            if known and event.source_ip not in known:
                signals.append(Signal("unusual_login", 25, (event.event_id,),
                                      "Successful login outside configured synthetic baseline"))
        elif event.event_type == "privilege_escalation":
            signals.append(Signal("privilege_escalation", 30, (event.event_id,),
                                  "Synthetic role changed from viewer to admin"))
        elif (event.event_type == "data_download"
              and event.metadata["bytes"] >= config.large_transfer_bytes):
            signals.append(Signal("large_transfer", 25, (event.event_id,),
                                  f"Synthetic download: {event.metadata['bytes']} bytes"))
    return signals
