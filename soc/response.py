"""Local review state machine. Responses only append a simulation audit entry."""

import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("Report is locked; wait for the other operation to finish") from exc
    try:
        os.close(descriptor)
        yield
    finally:
        lock.unlink()


def write_atomic(path: Path, report: dict) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".soc-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def save_new(path: Path, report: dict) -> None:
    with locked(path):
        if path.exists():
            raise ValueError("Report already exists; choose a new output path to preserve review history")
        write_atomic(path, report)


def transition(report: dict, incident_id: int, operation: str,
               analyst: str = "", reason: str = "") -> str:
    if (report.get("schema_version") != 1 or report.get("synthetic") is not True
            or report.get("mode") != "offline-lab"):
        raise ValueError("Only version 1 synthetic offline-lab reports are supported")
    incidents = report.get("incidents")
    if not isinstance(incidents, list):
        raise ValueError("Malformed report")
    matches = [item for item in incidents if item.get("incident_id") == incident_id]
    if len(matches) != 1:
        raise ValueError("Incident ID must identify exactly one incident")
    incident = matches[0]
    if (incident.get("synthetic") is not True or not isinstance(incident.get("audit"), list)
            or incident.get("proposed_response") != {
                "action": "simulate_account_isolation", "target": incident.get("user")}):
        raise ValueError("Malformed incident or unsupported response")
    if operation in ("approve", "reject"):
        if incident.get("status") != "PENDING":
            raise ValueError("Only pending incidents can be reviewed")
        if not analyst.strip() or not reason.strip() or len(analyst) > 80 or len(reason) > 500:
            raise ValueError("Review requires a short synthetic analyst label and a reason")
        incident["status"] = "APPROVED" if operation == "approve" else "REJECTED"
        incident["audit"].append({"timestamp": now(), "operation": operation,
                                  "analyst": analyst.strip(), "reason": reason.strip()})
    elif operation == "respond":
        if incident.get("status") == "SIMULATED":
            return "Simulation already recorded; no additional action"
        audit = incident["audit"]
        if (incident.get("status") != "APPROVED" or not audit
                or audit[-1].get("operation") != "approve"
                or not audit[-1].get("analyst") or not audit[-1].get("reason")):
            raise ValueError("Recorded human approval is required before simulation")
        incident["status"] = "SIMULATED"
        incident["audit"].append({"timestamp": now(), "operation": "simulate_account_isolation",
                                  "target": incident["user"],
                                  "result": "Simulation complete. No real system was modified."})
    else:
        raise ValueError("Unsupported operation")
    return incident["status"]


def update(path: Path, incident_id: int, operation: str, analyst: str = "", reason: str = "") -> str:
    with locked(path):
        report = json.loads(path.read_text(encoding="utf-8"))
        result = transition(report, incident_id, operation, analyst, reason)
        write_atomic(path, report)
        return result
