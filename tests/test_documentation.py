"""Keep runnable documentation and checked-in output aligned with the lab."""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from soc.__main__ import main
from soc.config import Config
from soc.incidents import run
from soc.normalization import normalize

ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    def test_internal_file_and_heading_links(self):
        for path in [ROOT / "README.md", *ROOT.glob("docs/*.md"), ROOT / "data/README.md"]:
            text = path.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
                if target.startswith(("https://", "http://")):
                    continue
                filename, _, fragment = target.partition("#")
                linked = path.parent / filename if filename else path
                with self.subTest(file=path.name, target=target):
                    self.assertTrue(linked.is_file(), target)
                    if fragment:
                        headings = re.findall(r"^#{1,6} (.+)$", linked.read_text(), re.MULTILINE)
                        anchors = {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
                                   for heading in headings}
                        self.assertIn(fragment, anchors)

    def test_incident_snapshot_is_generated_output(self):
        expected = run(ROOT / "data", Config.load(ROOT / "config/lab.json"))
        actual = json.loads((ROOT / "data/incidents/incident-1842.json").read_text())
        # JSON serializes evidence tuples as arrays.
        self.assertEqual(actual, json.loads(json.dumps(expected)))

    def test_readme_json_examples_match_config_and_normalization(self):
        readme = (ROOT / "README.md").read_text()
        raw, normalized, config = [json.loads(block) for block in
                                   re.findall(r"```json\n(.*?)\n```", readme, re.DOTALL)]
        event = normalize("auth", json.dumps(raw)).to_dict()
        event.pop("event_id")
        self.assertEqual(event, normalized)
        self.assertEqual(config, json.loads((ROOT / "config/lab.json").read_text()))

    def test_cli_transcript_is_actual_output_and_in_readme(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    result = main(["run", "--data", str(ROOT / "data"),
                                   "--config", str(ROOT / "config/lab.json")])
                self.assertEqual(result, 0)
                output = stream.getvalue()
            finally:
                os.chdir(previous)
        self.assertEqual(output, (ROOT / "examples/demo-output.txt").read_text())
        self.assertIn(output, (ROOT / "README.md").read_text())


if __name__ == "__main__":
    unittest.main()
