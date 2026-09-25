import copy
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from scripts.generate_data import generate
from soc.config import Config, test_ip
from soc.correlation import correlate, score
from soc.detection import detect
from soc.incidents import run
from soc.normalization import load_events, moment, normalize, timestamp
from soc.response import locked, save_new, transition, update

ROOT = Path(__file__).resolve().parents[1]


class LabTests(unittest.TestCase):
    def setUp(self):
        self.config = Config.load(ROOT / "config/lab.json")
        self.events = load_events(ROOT / "data")

    def candidates(self, events=None, config=None):
        events = self.events if events is None else events
        config = self.config if config is None else config
        return correlate(events, detect(events, config), config)

    def report(self):
        return run(ROOT / "data", self.config)

    def test_five_parsers_and_counts(self):
        self.assertEqual(len(self.events), 35)
        self.assertEqual(self.report()["telemetry_counts"], {
            "application": 2, "auth": 25, "cloud": 2, "firewall": 2, "nginx": 4})
        nginx = next(e for e in self.events if e.source == "nginx")
        self.assertEqual(nginx.metadata, {"method": "GET", "status": 200, "bytes": 512})
        self.assertEqual(nginx.resource, "/login")

    def test_normalization_schema_and_stable_id(self):
        record = {"synthetic": True, "timestamp": "2026-01-15T09:02:11-05:00",
                  "username": "alex", "source_ip": "198.51.100.42", "result": "failure",
                  "resource": "lab-portal", "extra": "not retained"}
        event = normalize("auth", json.dumps(record))
        self.assertEqual(event.timestamp, "2026-01-15T14:02:11.000000Z")
        self.assertEqual(event.severity, "low")
        self.assertEqual(set(event.to_dict()), {"event_id", "timestamp", "source", "event_type", "user",
                                                "source_ip", "resource", "severity", "metadata"})
        del record["extra"]
        record["timestamp"] = "2026-01-15T14:02:11Z"
        self.assertEqual(event.event_id, normalize("auth", json.dumps(record, sort_keys=True)).event_id)

    def test_invalid_timestamps(self):
        for value in ("2026-01-15T14:02:11", "not-a-time", "2026-02-30T00:00:00Z", 42):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timestamp(value)

    def test_only_documentation_ips(self):
        for value in ("127.0.0.1", "10.0.0.1", "8.8.8.8", "::1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                test_ip(value)
        for value in ("192.0.2.10", "198.51.100.42", "203.0.113.7"):
            self.assertEqual(test_ip(value), value)

    def test_malformed_formats_fail_closed(self):
        for source, raw in (("auth", '{}'), ("cloud", '[]'), ("nginx", 'broken'),
                            ("unknown", '{}'), ("firewall", 'null')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                normalize(source, raw)

    def test_unknown_actions_and_negative_bytes(self):
        for source in ("cloud", "firewall", "application"):
            raw = json.loads((ROOT / "data" / source / "synthetic.jsonl").read_text().splitlines()[0])
            raw["action"] = "unsupported"
            with self.subTest(source=source), self.assertRaises(ValueError):
                normalize(source, json.dumps(raw))
        raw = json.loads((ROOT / "data/cloud/synthetic.jsonl").read_text().splitlines()[0])
        for value in (-1, True, "500", 3.5):
            raw["bytes"] = value
            with self.subTest(bytes=value), self.assertRaises(ValueError):
                normalize("cloud", json.dumps(raw))

    def test_loader_deduplicates_and_sorts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            generate(root)
            auth = root / "auth/synthetic.jsonl"
            lines = auth.read_text().splitlines()
            auth.write_text("\n".join(reversed(lines + lines)) + "\n")
            (root / "auth/replay.jsonl").write_text("\n".join(lines) + "\n")
            self.assertEqual(load_events(root), self.events)

    def test_parse_error_identifies_line_without_raw_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            generate(root)
            (root / "auth/synthetic.jsonl").write_text("do-not-echo-this-input\n")
            with self.assertRaisesRegex(ValueError, r"Invalid auth record at synthetic.jsonl:1") as error:
                load_events(root)
            self.assertNotIn("do-not-echo", str(error.exception))

    def test_missing_source_is_error(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(ValueError, "Missing"):
            load_events(Path(folder))

    def test_config_rejects_invalid_policy(self):
        raw = json.loads((ROOT / "config/lab.json").read_text())
        for changes in ({"window_seconds": 0}, {"failure_threshold": True},
                        {"large_transfer_bytes": -1}, {"investigation_mode": "live"},
                        {"unknown": 1}, {"known_ips": {"alex": ["10.0.0.1"]}},
                        {"known_ips": {"alex": []}}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "config.json"
                path.write_text(json.dumps({**raw, **changes}))
                with self.assertRaises(ValueError):
                    Config.load(path)

    def test_expected_rules_and_risk(self):
        candidate, = self.candidates()
        self.assertEqual(candidate.user, "alex")
        self.assertEqual(score(candidate.signals), {
            "score": 100, "level": "HIGH", "model": "transparent-lab-heuristic-v1",
            "factors": {"repeated_failures_then_success": 20, "unusual_login": 25,
                        "privilege_escalation": 30, "large_transfer": 25}})
        self.assertEqual(len(candidate.events), 30)

    def test_risk_does_not_double_count_rules(self):
        signals = detect(self.events, self.config)
        self.assertEqual(score(signals), score(signals + signals))
        self.assertEqual(score([])["level"], "LOW")
        self.assertEqual(score(signals[:2])["score"], 45)
        self.assertEqual(score(signals[:2])["level"], "MEDIUM")

    def test_failure_threshold_boundary(self):
        for count, expected in ((19, 0), (20, 1), (23, 1)):
            failures = [event for event in self.events if event.event_type == "login_failure"]
            keep = {event.event_id for event in failures[:count]}
            events = [event for event in self.events
                      if event.event_type != "login_failure" or event.event_id in keep]
            with self.subTest(count=count):
                self.assertEqual(len(self.candidates(events)), expected)

    def test_no_success_no_candidate(self):
        events = [event for event in self.events if event.event_type != "login_success"]
        self.assertFalse(self.candidates(events))

    def test_known_or_unknown_baseline_no_candidate(self):
        for baseline in ({"alex": ("198.51.100.42",)}, {}):
            with self.subTest(baseline=baseline):
                self.assertFalse(self.candidates(config=replace(self.config, known_ips=baseline)))

    def test_auth_cannot_cross_user_ip_or_resource(self):
        for change in ({"user": "casey"}, {"source_ip": "203.0.113.9"}, {"resource": "other-portal"}):
            events = [replace(event, **change) if event.event_type == "login_failure" else event
                      for event in self.events]
            with self.subTest(change=change):
                self.assertFalse(self.candidates(events))

    def test_old_failures_do_not_correlate(self):
        events = [replace(event, timestamp="2026-01-15T13:00:00.000000Z")
                  if event.event_type == "login_failure" else event for event in self.events]
        self.assertFalse(self.candidates(events))

    def test_simultaneous_or_future_failures_do_not_establish_order(self):
        for time in ("2026-01-15T14:06:02.000000Z", "2026-01-15T14:08:00.000000Z"):
            events = [replace(event, timestamp=time) if event.event_type == "login_failure" else event
                      for event in self.events]
            with self.subTest(time=time):
                self.assertFalse(self.candidates(events))

    def test_post_auth_signals_must_match_identity_and_ip(self):
        for change in ({"user": "casey"}, {"source_ip": "203.0.113.9"}):
            events = [replace(event, **change) if event.event_type in ("privilege_escalation", "data_download")
                      else event for event in self.events]
            with self.subTest(change=change):
                candidate, = self.candidates(events)
                self.assertEqual(score(candidate.signals)["score"], 45)

    def test_out_of_order_or_late_escalation_not_scored(self):
        for time in ("2026-01-15T14:03:00.000000Z", "2026-01-15T15:03:00.000000Z"):
            events = [replace(event, timestamp=time) if event.event_type == "privilege_escalation" else event
                      for event in self.events]
            with self.subTest(time=time):
                candidate, = self.candidates(events)
                self.assertEqual(score(candidate.signals)["score"], 70)

    def test_total_window_boundary(self):
        start = moment(next(event.timestamp for event in self.events if event.event_type == "login_failure"))
        for offset, expected in ((600, 100), (601, 75)):
            time = timestamp((start + timedelta(seconds=offset)).isoformat())
            events = [replace(event, timestamp=time) if event.event_type == "data_download" else event
                      for event in self.events]
            with self.subTest(offset=offset):
                candidate, = self.candidates(events)
                self.assertEqual(score(candidate.signals)["score"], expected)

    def test_large_transfer_boundary(self):
        for size, expected in ((104857599, False), (104857600, True)):
            events = [replace(event, metadata={**event.metadata, "bytes": size})
                      if event.event_type == "data_download" else event for event in self.events]
            with self.subTest(size=size):
                self.assertEqual(any(s.rule == "large_transfer" for s in detect(events, self.config)), expected)

    def test_role_demotion_not_escalation(self):
        raw = json.loads((ROOT / "data/application/synthetic.jsonl").read_text().splitlines()[0])
        raw.update(previous_role="admin", new_role="viewer")
        self.assertEqual(normalize("application", json.dumps(raw)).event_type, "role_change")

    def test_benign_telemetry_no_incident(self):
        self.assertFalse(self.candidates([event for event in self.events if event.user == "jordan"]))

    def test_repeated_success_in_window_does_not_duplicate_incident(self):
        success = next(e for e in self.events if e.user == "alex" and e.event_type == "login_success")
        another = replace(success, event_id="another-success", timestamp="2026-01-15T14:06:03.000000Z")
        events = sorted(self.events + [another], key=lambda e: (e.timestamp, e.event_id))
        self.assertEqual(len(self.candidates(events)), 1)

    def test_independent_users_and_later_windows_produce_distinct_candidates(self):
        extra = [replace(e, event_id="casey-" + e.event_id, user="casey")
                 for e in self.events if e.user == "alex"]
        later = [replace(e, event_id="later-" + e.event_id,
                         timestamp=timestamp((moment(e.timestamp) + timedelta(hours=1)).isoformat()))
                 for e in self.events if e.user == "alex"]
        events = sorted(self.events + extra + later, key=lambda e: (e.timestamp, e.event_id))
        config = replace(self.config, known_ips={**self.config.known_ips, "casey": ("192.0.2.30",)})
        candidates = self.candidates(events, config)
        self.assertEqual([c.user for c in candidates].count("alex"), 2)
        self.assertEqual([c.user for c in candidates].count("casey"), 1)

    def test_incident_and_investigation_are_reproducible_and_grounded(self):
        report = self.report()
        self.assertEqual(report, self.report())
        incident, = report["incidents"]
        self.assertEqual(incident["incident_id"], 1842)
        self.assertEqual(incident["status"], "PENDING")
        self.assertEqual(incident["investigation"]["mode"], "mock")
        self.assertTrue(incident["investigation"]["requires_human_approval"])
        times = [event["timestamp"] for event in incident["timeline"]]
        self.assertEqual(times, sorted(times))
        ids = {event["event_id"] for event in incident["timeline"]}
        self.assertLessEqual(set(incident["investigation"]["evidence_ids"]), ids)

    def test_pending_and_rejected_response_blocked(self):
        report = self.report()
        with self.assertRaisesRegex(ValueError, "approval"):
            transition(report, 1842, "respond")
        transition(report, 1842, "reject", "analyst-lab", "Expected exercise")
        with self.assertRaisesRegex(ValueError, "approval"):
            transition(report, 1842, "respond")
        with self.assertRaisesRegex(ValueError, "pending"):
            transition(report, 1842, "approve", "analyst-lab", "Changed mind")

    def test_review_requires_named_analyst_and_reason(self):
        for analyst, reason in (("", "Reason"), ("analyst", "  ")):
            with self.subTest(analyst=analyst), self.assertRaises(ValueError):
                transition(self.report(), 1842, "approve", analyst, reason)

    def test_approved_simulation_is_idempotent(self):
        report = self.report()
        transition(report, 1842, "approve", "analyst-lab", "Reviewed synthetic evidence")
        self.assertEqual(transition(report, 1842, "respond"), "SIMULATED")
        before = copy.deepcopy(report)
        self.assertIn("already", transition(report, 1842, "respond"))
        self.assertEqual(report, before)
        self.assertEqual(len(report["incidents"][0]["audit"]), 2)
        self.assertIn("No real system", report["incidents"][0]["audit"][-1]["result"])

    def test_missing_approval_audit_is_blocked(self):
        report = self.report()
        report["incidents"][0]["status"] = "APPROVED"
        with self.assertRaisesRegex(ValueError, "approval"):
            transition(report, 1842, "respond")

    def test_unsupported_response_or_report_is_rejected(self):
        report = self.report()
        report["incidents"][0]["proposed_response"]["action"] = "real_action"
        with self.assertRaises(ValueError):
            transition(report, 1842, "approve", "analyst", "Reason")
        report = self.report()
        report["synthetic"] = False
        with self.assertRaises(ValueError):
            transition(report, 1842, "approve", "analyst", "Reason")

    def test_missing_or_duplicate_incident_id_is_rejected(self):
        report = self.report()
        with self.assertRaises(ValueError):
            transition(report, 999, "respond")
        report["incidents"].append(copy.deepcopy(report["incidents"][0]))
        with self.assertRaises(ValueError):
            transition(report, 1842, "respond")

    def test_report_preserves_history_and_blocks_concurrent_write(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "nested/report.json"
            save_new(path, self.report())
            with self.assertRaisesRegex(ValueError, "already exists"):
                save_new(path, self.report())
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                update(path, 1842, "respond")
            self.assertEqual(path.read_bytes(), before)
            with locked(path), self.assertRaisesRegex(ValueError, "locked"):
                update(path, 1842, "approve", "analyst", "Reason")
            update(path, 1842, "approve", "analyst", "Reason")
            update(path, 1842, "respond")
            self.assertEqual(json.loads(path.read_text())["incidents"][0]["status"], "SIMULATED")

    def test_cli_full_workflow_and_reject_path(self):
        def cli(*args):
            return subprocess.run([sys.executable, "-m", "soc", *map(str, args)],
                                  cwd=ROOT, text=True, capture_output=True)
        with tempfile.TemporaryDirectory() as folder:
            for decision in ("approve", "reject"):
                path = Path(folder) / f"{decision}.json"
                result = cli("run", "--output", path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("INCIDENT #1842", result.stdout)
                self.assertEqual(cli("respond", path, "--incident", 1842).returncode, 2)
                result = cli("review", path, "--incident", 1842, "--decision", decision,
                             "--analyst", "analyst-lab", "--reason", "Reviewed exercise")
                self.assertEqual(result.returncode, 0, result.stderr)
                result = cli("respond", path, "--incident", 1842)
                self.assertEqual(result.returncode, 0 if decision == "approve" else 2, result.stderr)

    def test_checked_in_data_matches_generator(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            generate(root)
            for path in root.rglob("synthetic.*"):
                self.assertEqual(path.read_bytes(), (ROOT / "data" / path.relative_to(root)).read_bytes())


if __name__ == "__main__":
    unittest.main()
