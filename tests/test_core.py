import hashlib
import io
import importlib.util
import json
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from capsule_lint.cli import _render_sarif, _render_text, _source_lines, main
from capsule_lint.core import Resolver, lint


class CapsuleLintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "handoff.md").write_text("# Handoff\n", encoding="utf-8")
        self.evidence = self.root / "proof.txt"
        self.evidence.write_text("proof\n", encoding="utf-8")
        self.capsule = {
            "schema_version": 1, "capsule_id": "example", "created_at": "2026-01-01T00:00:00Z",
            "source_revision": "abc", "document": "handoff.md", "summary": "Ready for review",
            "decisions": [{"id": "d1", "statement": "Use JSON", "status": "active", "evidence_ids": ["e1"]}],
            "obligations": [{"id": "o1", "description": "Write tests", "status": "open",
                             "owner": "Ada", "next_action": "Add fixture", "evidence_ids": ["e1"]}],
            "evidence": [{"id": "e1", "type": "file", "ref": "proof.txt", "revision": "abc",
                          "captured_at": "2026-01-01T00:00:00Z",
                          "content_hash": hashlib.sha256(self.evidence.read_bytes()).hexdigest()}],
        }

    def codes(self):
        return {d.code for d in lint(self.capsule, Resolver(self.root))}

    def test_valid_capsule_and_cli_exit(self):
        self.assertEqual(self.codes(), set())
        manifest = self.root / "capsule.json"
        manifest.write_text(json.dumps(self.capsule))
        self.assertEqual(main(["check", str(manifest)]), 0)

    def test_missing_reference_and_open_owner(self):
        self.capsule["decisions"][0]["evidence_ids"] = ["missing"]
        self.capsule["obligations"][0]["owner"] = ""
        self.assertTrue({"CL102", "CL104"} <= self.codes())

    def test_duplicate_and_cycle_and_topic(self):
        self.capsule["decisions"][0]["supersedes"] = "d2"
        self.capsule["decisions"][0]["topic_key"] = "auth"
        self.capsule["decisions"].append({"id": "d2", "statement": "Use YAML", "status": "active",
                                          "topic_key": "auth", "supersedes": "d1", "evidence_ids": []})
        self.capsule["decisions"].append(dict(self.capsule["decisions"][0]))
        self.assertTrue({"CL101", "CL105", "CL300"} <= self.codes())

    def test_hash_and_symlink_escape(self):
        self.capsule["evidence"][0]["content_hash"] = "sha256:deadbeef"
        self.assertIn("CL204", self.codes())
        outside = self.root.parent / f"outside-{self.root.name}.txt"
        outside.write_text("outside")
        self.addCleanup(outside.unlink)
        (self.root / "link.txt").symlink_to(outside)
        self.capsule["evidence"][0]["ref"] = "link.txt"
        self.assertIn("CL202", self.codes())

    def test_status_and_timestamp_and_consistency(self):
        self.capsule["created_at"] = "yesterday"
        self.capsule["decisions"][0]["status"] = "maybe"
        self.capsule["obligations"][0].update(status="blocked", blocker="")
        self.assertTrue({"CL003", "CL009", "CL302"} <= self.codes())
        self.capsule["obligations"][0]["status"] = "done"
        self.capsule["obligations"][0]["evidence_ids"] = []
        self.assertIn("CL301", self.codes())

    def test_profile_age_and_strict(self):
        self.assertIn("CL209", {d.code for d in lint(self.capsule, Resolver(self.root),
                                                      {"max_evidence_age_days": 1})})
        manifest = self.root / "capsule.json"
        manifest.write_text(json.dumps(self.capsule))
        profile = self.root / "profile.json"
        profile.write_text(json.dumps({"max_evidence_age_days": 1}))
        self.assertEqual(main(["check", str(manifest), "--profile", str(profile)]), 0)
        self.assertEqual(main(["check", str(manifest), "--profile", str(profile), "--strict"]), 1)

    def test_renderers_have_same_codes(self):
        self.capsule["summary"] = ""
        diagnostics = lint(self.capsule, Resolver(self.root))
        text = _render_text(diagnostics)
        sarif = json.loads(_render_sarif(diagnostics))
        self.assertEqual({d.code for d in diagnostics}, {r["ruleId"] for r in sarif["runs"][0]["results"]})
        self.assertIn("CL002", text)

    def test_invalid_json_is_input_error(self):
        manifest = self.root / "bad.json"
        manifest.write_text("{not json")
        self.assertEqual(main(["check", str(manifest)]), 2)
        manifest.write_text("[]")
        self.assertEqual(main(["check", str(manifest)]), 2)

    def test_unicode_and_line_anchors(self):
        self.capsule["summary"] = "העברת הקשר — ready"
        self.capsule["evidence"][0]["ref"] = "proof.txt:2"
        self.assertIn("CL205", self.codes())
        self.capsule["evidence"][0]["ref"] = "proof.txt:1"
        self.assertEqual(self.codes(), set())

    def test_markdown_heading_and_explicit_anchors(self):
        notes = self.root / "notes.md"
        notes.write_text("# Overview\n## Café & Tea\n## Duplicate\n## Duplicate\n"
                         "```md\n# Hidden\n```python\n# Still Hidden\n```\n<a id=\"manual\"></a>\n",
                         encoding="utf-8")
        self.capsule["evidence"][0].pop("content_hash")
        for fragment in ("overview", "caf%C3%A9-tea", "duplicate-1", "manual"):
            with self.subTest(fragment=fragment):
                self.capsule["evidence"][0]["ref"] = f"notes.md#{fragment}"
                self.assertEqual(self.codes(), set())

    def test_missing_markdown_anchor_is_a_blocking_diagnostic(self):
        (self.root / "notes.md").write_text("# Present\n```\n# Hidden\n```\n", encoding="utf-8")
        evidence = self.capsule["evidence"][0]
        evidence.pop("content_hash")
        evidence["ref"] = "notes.md#hidden"
        findings = lint(self.capsule, Resolver(self.root))
        missing = [finding for finding in findings if finding.code == "CL210"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].severity, "error")
        self.assertEqual(missing[0].location, "$.evidence[0].ref")
        manifest = self.root / "capsule.json"
        manifest.write_text(json.dumps(self.capsule), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", str(manifest)]), 1)

    def test_markdown_anchor_preserves_path_confinement(self):
        outside = self.root.parent / f"outside-{self.root.name}.md"
        outside.write_text("# Present\n", encoding="utf-8")
        self.addCleanup(outside.unlink)
        self.capsule["evidence"][0].pop("content_hash")
        self.capsule["evidence"][0]["ref"] = f"../{outside.name}#present"
        self.assertIn("CL202", self.codes())

    def test_manifest_line_numbers_in_all_formats(self):
        self.capsule["summary"] = ""
        manifest = self.root / "capsule.json"
        manifest.write_text(json.dumps(self.capsule, ensure_ascii=False, indent=2), encoding="utf-8")
        expected = _source_lines(manifest.read_text(), manifest.name)["$.summary"]
        outputs = {}
        for format_name in ("text", "json", "sarif"):
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main(["check", str(manifest), "--format", format_name]), 1)
            outputs[format_name] = stream.getvalue()
        self.assertIn(f"{manifest}:{expected}: $.summary", outputs["text"])
        report = json.loads(outputs["json"])
        diagnostic = next(d for d in report["diagnostics"] if d["code"] == "CL002")
        self.assertEqual(diagnostic["line"], expected)
        sarif = json.loads(outputs["sarif"])
        finding = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CL002")
        self.assertEqual(finding["locations"][0]["physicalLocation"]["region"]["startLine"], expected)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML optional extra is not installed")
    def test_yaml_line_numbers_and_malformed_input(self):
        manifest = self.root / "capsule.yaml"
        manifest.write_text("schema_version: 1\nsummary: ''\n", encoding="utf-8")
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(["check", str(manifest)]), 1)
        self.assertIn(f"{manifest}:2: $.summary", stream.getvalue())
        manifest.write_text("summary: [unterminated\n", encoding="utf-8")
        self.assertEqual(main(["check", str(manifest)]), 2)

    def test_git_revision_warning(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "handoff.md", "proof.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "first"], check=True)
        first = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        (self.root / "handoff.md").write_text("# Updated\n")
        subprocess.run(["git", "-C", str(self.root), "commit", "-qam", "second"], check=True)
        second = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.capsule["source_revision"] = second
        self.capsule["evidence"][0]["revision"] = first
        self.assertIn("CL207", self.codes())
        self.assertFalse({"CL211", "CL212"} & self.codes())

    def test_git_file_changed_and_removed_since_evidence_revision(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "handoff.md", "proof.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "first"], check=True)
        first = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.capsule["evidence"][0]["revision"] = first
        self.capsule["evidence"][0].pop("content_hash")

        self.evidence.write_text("changed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "commit", "-qam", "changed"], check=True)
        second = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.capsule["source_revision"] = second
        self.assertIn("CL212", self.codes())
        self.assertNotIn("CL211", self.codes())

        self.evidence.unlink()
        subprocess.run(["git", "-C", str(self.root), "commit", "-qam", "removed"], check=True)
        third = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.capsule["source_revision"] = third
        self.assertTrue({"CL201", "CL211"} <= self.codes())
        self.assertNotIn("CL212", self.codes())


if __name__ == "__main__":
    unittest.main()
