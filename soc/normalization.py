"""Parse five deliberately small lab formats into one evidence schema."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import test_ip

SOURCES = ("nginx", "auth", "cloud", "firewall", "application")
NGINX = re.compile(
    r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>GET|POST) (?P<path>/[\w/-]*) HTTP/1\.1" '
    r'(?P<status>\d{3}) (?P<bytes>\d+)'
)


def timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be an ISO-8601 string with timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def moment(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def label(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,120}", value):
        raise ValueError(f"{field} must be a short synthetic label")
    return value


def byte_count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("bytes must be a nonnegative integer")
    return value


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    user: str
    source_ip: str
    resource: str
    severity: str
    metadata: dict

    def to_dict(self) -> dict:
        return asdict(self)


def normalize(source: str, line: str) -> Event:
    if source not in SOURCES:
        raise ValueError("Unsupported telemetry source")
    metadata = {}
    severity = "info"
    if source == "nginx":
        match = NGINX.fullmatch(line)
        if not match:
            raise ValueError("Expected the documented synthetic Nginx access format")
        raw = match.groupdict()
        time = datetime.strptime(raw["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
        user, ip, resource = raw["user"], raw["ip"], raw["path"]
        kind = "web_request"
        status = int(raw["status"])
        if not 100 <= status <= 599:
            raise ValueError("Invalid HTTP status")
        metadata = {"method": raw["method"], "status": status, "bytes": int(raw["bytes"])}
    else:
        raw = json.loads(line)
        if not isinstance(raw, dict) or raw.get("synthetic") is not True:
            raise ValueError("JSON telemetry must explicitly declare synthetic: true")
        time = raw["timestamp"]
        ip = raw["source_ip"]
        if source == "auth":
            user, resource = raw["username"], raw["resource"]
            if raw["result"] not in ("failure", "success"):
                raise ValueError("Unknown authentication result")
            kind = "login_" + raw["result"]
            severity = "low" if raw["result"] == "failure" else "info"
        elif source == "cloud":
            user, resource = raw["principal"], raw["resource"]
            if raw["action"] not in ("DownloadObject", "ListObjects"):
                raise ValueError("Unknown synthetic cloud action")
            kind = "data_download" if raw["action"] == "DownloadObject" else "cloud_read"
            metadata = {"bytes": byte_count(raw["bytes"]), "action": raw["action"]}
        elif source == "firewall":
            user, resource = raw["user"], raw["destination"]
            if raw["action"] not in ("allowed", "denied"):
                raise ValueError("Unknown firewall action")
            kind = "network_" + raw["action"]
        else:
            user, resource = raw["user"], raw["resource"]
            if raw["action"] not in ("role_change", "page_view"):
                raise ValueError("Unknown application action")
            kind = raw["action"]
            if kind == "role_change":
                before, after = raw["previous_role"], raw["new_role"]
                if before not in ("viewer", "admin") or after not in ("viewer", "admin"):
                    raise ValueError("Unknown synthetic role")
                metadata = {"previous_role": before, "new_role": after}
                if before == "viewer" and after == "admin":
                    kind, severity = "privilege_escalation", "medium"
    payload = dict(timestamp=timestamp(time), source=source, event_type=kind,
                   user=label(user, "user"), source_ip=test_ip(ip),
                   resource=label(resource, "resource"), severity=severity, metadata=metadata)
    # Semantic IDs deduplicate replayed evidence, even across files or key ordering.
    identity = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:20]
    return Event(event_id=identity, **payload)


def load_events(root: Path) -> list[Event]:
    events = {}
    for source in SOURCES:
        suffix = "*.log" if source == "nginx" else "*.jsonl"
        files = sorted((root / source).glob(suffix))
        if not files:
            raise ValueError(f"Missing synthetic telemetry files for {source}")
        for path in files:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip() or line.startswith("#"):
                    continue
                try:
                    event = normalize(source, line)
                except (ValueError, KeyError, TypeError) as exc:
                    # Never echo untrusted raw lines or potentially sensitive field values.
                    raise ValueError(f"Invalid {source} record at {path.name}:{number}") from exc
                events[event.event_id] = event
    return sorted(events.values(), key=lambda event: (event.timestamp, event.event_id))
