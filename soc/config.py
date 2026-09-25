"""Explicit lab policy. No environment variables or external AI services."""

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

TEST_NETS = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
))


def test_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not any(address in net for net in TEST_NETS):
        raise ValueError("Only IPv4 documentation ranges are allowed in this lab")
    return str(address)


@dataclass(frozen=True)
class Config:
    window_seconds: int
    failure_threshold: int
    large_transfer_bytes: int
    known_ips: dict[str, tuple[str, ...]]
    investigation_mode: str

    @classmethod
    def load(cls, path: Path) -> "Config":
        raw = json.loads(path.read_text(encoding="utf-8"))
        fields = {"window_seconds", "failure_threshold", "large_transfer_bytes",
                  "known_ips", "investigation_mode"}
        if not isinstance(raw, dict) or set(raw) != fields:
            raise ValueError("Config must contain exactly the documented fields")
        for field in ("window_seconds", "failure_threshold", "large_transfer_bytes"):
            if type(raw[field]) is not int or raw[field] <= 0:
                raise ValueError(f"{field} must be a positive integer")
        if raw["investigation_mode"] != "mock":
            raise ValueError("Only offline mock investigation is implemented")
        baseline = raw["known_ips"]
        if not isinstance(baseline, dict):
            raise ValueError("known_ips must map synthetic users to IP lists")
        for user, addresses in baseline.items():
            if not isinstance(user, str) or not user or not isinstance(addresses, list):
                raise ValueError("Invalid known_ips entry")
            if not addresses or any(not isinstance(ip, str) for ip in addresses):
                raise ValueError("Each baseline requires at least one documentation IP")
            for ip in addresses:
                test_ip(ip)
        return cls(**{**raw, "known_ips": {u: tuple(v) for u, v in baseline.items()}})
