"""Recreate only the five named demo fixtures; no randomness or network access."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "data"


def generate(root: Path = ROOT) -> None:
    ip = "198.51.100.42"
    start = datetime(2026, 1, 15, 14, 2, 11, tzinfo=timezone.utc)

    def record(time, **fields):
        return {"synthetic": True, "timestamp": time, "source_ip": ip, **fields}

    auth = [record((start + timedelta(seconds=i * 9)).isoformat().replace("+00:00", "Z"),
                   username="alex", resource="lab-portal", result="failure") for i in range(23)]
    auth += [record("2026-01-15T14:06:02Z", username="alex", resource="lab-portal", result="success"),
             record("2026-01-15T14:01:00Z", username="jordan", resource="lab-portal", result="success",
                    source_ip="192.0.2.20")]
    cloud = [record("2026-01-15T14:09:44Z", principal="alex", action="DownloadObject",
                    resource="synthetic-bucket", bytes=524288000),
             record("2026-01-15T14:01:15Z", principal="jordan", action="ListObjects",
                    resource="synthetic-bucket", bytes=512, source_ip="192.0.2.20")]
    firewall = [record("2026-01-15T14:06:10Z", user="alex", destination="lab-portal", action="allowed"),
                record("2026-01-15T14:01:05Z", user="jordan", destination="lab-portal", action="allowed",
                       source_ip="192.0.2.20")]
    application = [record("2026-01-15T14:07:18Z", user="alex", resource="lab-portal",
                         action="role_change", previous_role="viewer", new_role="admin"),
                   record("2026-01-15T14:01:10Z", user="jordan", resource="lab-portal",
                          action="page_view", source_ip="192.0.2.20")]
    for source, rows in (("auth", auth), ("cloud", cloud), ("firewall", firewall), ("application", application)):
        directory = root / source
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "synthetic.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    nginx = root / "nginx"
    nginx.mkdir(parents=True, exist_ok=True)
    (nginx / "synthetic.log").write_text(
        '# SYNTHETIC LAB ACCESS LOG; user field is a synthetic identity.\n'
        '198.51.100.42 - alex [15/Jan/2026:14:02:00 +0000] "GET /login HTTP/1.1" 200 512\n'
        '198.51.100.42 - alex [15/Jan/2026:14:06:02 +0000] "POST /login HTTP/1.1" 200 256\n'
        '198.51.100.42 - alex [15/Jan/2026:14:06:04 +0000] "GET /dashboard HTTP/1.1" 200 2048\n'
        '198.51.100.42 - alex [15/Jan/2026:14:09:43 +0000] "GET /api/export HTTP/1.1" 200 128\n',
        encoding="utf-8")


if __name__ == "__main__":
    generate()
    print("Recreated five deterministic synthetic telemetry files.")
