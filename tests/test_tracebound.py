import base64
import copy
import json
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tracebound.common import canonical, decode, digest, local_request, local_url
from tracebound.evidence import keygen, save_lab, verify, validate_chain
from tracebound.lab import Lab, SCENARIOS, run_lab
from tracebound.mcp_server import Protocol, VERSION


class LabIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.findings, cls.events, cls.protocol = run_lab()
        cls.bundle = cls.root / "reference"
        cls.receipt = save_lab(cls.bundle, cls.findings, cls.events, cls.protocol)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def clone(self):
        target = self.root / ("case-" + self._testMethodName)
        shutil.copytree(self.bundle, target)
        return target

    def rehash(self, target, name):
        manifest = json.loads((target / "manifest.json").read_text())
        raw = (target / name).read_bytes()
        for entry in manifest["artifacts"]:
            if entry["path"] == name:
                entry.update(bytes=len(raw), sha256=digest(raw))
        (target / "manifest.json").write_bytes(canonical(manifest))

    def test_all_six_surviving_paths_and_fixes_observed(self):
        expected = {"cached_token": "inactive_grant", "application_session": "inactive_grant",
                    "child_agent": "inactive_grant", "queued_job": "submitter_revoked",
                    "approval_replay": "approval_already_used", "approval_scope": "approval_scope_changed"}
        self.assertEqual(set(expected), {f["scenario"] for f in self.findings})
        for finding in self.findings:
            with self.subTest(scenario=finding["scenario"]):
                self.assertEqual(finding["baseline"]["observation"], "succeeded")
                self.assertEqual(finding["initial"]["observation"], "succeeded")
                self.assertEqual(finding["initial"]["state_delta"], 1)
                self.assertEqual(finding["retest"]["observation"], "denied")
                self.assertEqual(finding["retest"]["state_delta"], 0)
                self.assertEqual(finding["retest"]["reason"], expected[finding["scenario"]])

    def test_independent_sources_and_protocol_trace(self):
        self.assertEqual({e["source"] for e in self.events}, {"controller", "resource", "identity"})
        self.assertTrue(all(p["request"]["jsonrpc"] == "2.0" for p in self.protocol))
        validate_chain(self.events)

    def test_afr_projection_against_pinned_upstream_schema(self):
        import jsonschema
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/upstream/ai-investigation-event.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
        rows = (self.bundle / "afr-events.jsonl").read_text().splitlines()
        self.assertGreater(len(rows), 0)
        for row in rows:
            validator.validate(json.loads(row))

    def test_complete_bundle_replays_with_external_digest(self):
        result = verify(self.bundle, expected_manifest=self.receipt["manifest_sha256"])
        self.assertTrue(result["recorded_results_replayed"])
        self.assertTrue(result["pinned_manifest"])

    def test_tampered_bytes_fail(self):
        target = self.clone()
        with (target / "events.jsonl").open("ab") as handle:
            handle.write(b" ")
        with self.assertRaises(ValueError):
            verify(target)

    def test_rehashed_false_summary_fails_replay(self):
        target = self.clone()
        data = json.loads((target / "results.json").read_text())
        data["summary"]["remediated_paths_denied"] = 600
        (target / "results.json").write_bytes(canonical(data))
        self.rehash(target, "results.json")
        with self.assertRaises(ValueError):
            verify(target)

    def test_rehashed_html_misrepresentation_fails_replay(self):
        target = self.clone()
        report = target / "report.html"
        report.write_text(report.read_text().replace("Synthetic", "Production"))
        self.rehash(target, "report.html")
        with self.assertRaises(ValueError):
            verify(target)

    def test_rehashed_chunk_offset_fails(self):
        target = self.clone()
        data = json.loads((target / "chunk-index.json").read_text())
        data[0]["byte_offset"] += 1
        (target / "chunk-index.json").write_bytes(canonical(data))
        self.rehash(target, "chunk-index.json")
        with self.assertRaises(ValueError):
            verify(target)

    def test_rehashed_tail_loss_fails(self):
        target = self.clone()
        lines = (target / "events.jsonl").read_bytes().splitlines(keepends=True)
        (target / "events.jsonl").write_bytes(b"".join(lines[:-1]))
        self.rehash(target, "events.jsonl")
        with self.assertRaises((ValueError, KeyError)):
            verify(target)

    def test_pinned_manifest_detects_whole_manifest_change(self):
        target = self.clone()
        (target / "summary.md").write_text("Modified")
        self.rehash(target, "summary.md")
        with self.assertRaises(ValueError):
            verify(target, expected_manifest=self.receipt["manifest_sha256"])

    def test_added_unmanifested_file_rejected(self):
        target = self.clone()
        (target / "extra.html").write_text("unexpected")
        with self.assertRaises(ValueError):
            verify(target)

    def test_path_traversal_inventory_rejected(self):
        target = self.clone()
        manifest = json.loads((target / "manifest.json").read_text())
        manifest["artifacts"][0]["path"] = "../outside"
        (target / "manifest.json").write_bytes(canonical(manifest))
        with self.assertRaises(ValueError):
            verify(target)

    def test_symlink_artifact_rejected(self):
        target = self.clone()
        victim = target / "summary.md"
        victim.unlink()
        try:
            victim.symlink_to(self.bundle / "summary.md")
        except OSError:
            self.skipTest("symlink permission unavailable")
        with self.assertRaises(ValueError):
            verify(target)

    def test_existing_output_preserved(self):
        manifest = (self.bundle / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            save_lab(self.bundle, self.findings, self.events, self.protocol)
        self.assertEqual((self.bundle / "manifest.json").read_bytes(), manifest)

    def test_signed_bundle_and_wrong_trust_anchor(self):
        try:
            import cryptography
        except ImportError:
            self.skipTest("install signing extra")
        private, public = self.root / "private.pem", self.root / "public.pem"
        keygen(private, public)
        target = self.root / "signed"
        save_lab(target, self.findings, self.events, self.protocol, private)
        self.assertEqual(verify(target, trusted_key=public)["signature"], "verified_against_supplied_key")
        second, wrong = self.root / "second.pem", self.root / "wrong.pem"
        keygen(second, wrong)
        with self.assertRaises(Exception):
            verify(target, trusted_key=wrong)


class Boundaries(unittest.TestCase):
    def test_separate_processes_and_secret_minimization(self):
        with Lab("cached_token") as lab:
            self.assertEqual(len({c.process.pid for c in lab.children}), 4)
            _, events, protocol = lab.experiment()
            export = canonical({"events": events, "protocol": protocol}).decode()
            for secret in [*lab.credentials.values(), lab.id_admin, lab.res_admin, lab.reader, *lab.writers.values()]:
                self.assertNotIn(secret, export)
            status, _ = local_request(lab.resource, "/admin/controls", {"live_grants": False}, lab.credentials["agent"])
            self.assertEqual(status, 403)

    def test_concurrent_approval_consumption_allows_one_action(self):
        with Lab("approval_replay") as lab:
            lab.admin("resource", "/admin/controls", {"approval_once": True, "approval_binding": True})
            approval = lab.approval()
            def attempt(number):
                return local_request(lab.resource, "/approved-ticket", {
                    "approval_id": approval, "request_id": str(number),
                    "action": {"ticket": "TICKET-001", "operation": "increment"}}, lab.credentials["agent"])[0]
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(attempt, [1, 2]))
            self.assertEqual(sorted(outcomes), [200, 403])
            self.assertEqual(lab.admin("resource", "/admin/state", {})["tickets"]["TICKET-001"], 1)

    def test_dependency_failure_stays_unknown_and_can_be_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            with Lab("cached_token") as lab:
                finding, _, _ = lab.experiment()
                lab.children[1].close()  # Identity service becomes unavailable after the working baseline.
                finding["retest"] = lab.probe("remediated_control")
                finding["remediated_control"] = "unknown"
                self.assertEqual(finding["retest"]["observation"], "unknown")
                self.assertEqual(finding["retest"]["state_delta"], 0)
                _, result = local_request(lab.witness, "/events", token=lab.reader)
                target = Path(temp) / "unknown"
                save_lab(target, [finding], result["events"], lab.protocol)
                self.assertTrue(verify(target)["recorded_results_replayed"])

    def test_network_target_must_be_literal_loopback(self):
        for url in ("http://localhost:90/a", "https://127.0.0.1:90/a", "http://127.0.0.1.evil:90/a", "http://user@127.0.0.1:90/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                local_url(url)

    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)


class MCPContract(unittest.TestCase):
    def setUp(self):
        self.protocol = Protocol({"resource": "http://127.0.0.1:1", "credentials": {"agent": "synthetic"}})

    def request(self, method, params=None):
        return self.protocol.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def initialize(self):
        self.request("initialize", {"protocolVersion": VERSION})
        self.protocol.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def test_lifecycle_and_tool_discovery(self):
        self.assertIn("error", self.request("tools/list"))
        self.initialize()
        self.assertEqual(len(self.request("tools/list")["result"]["tools"]), 2)

    def test_version_mismatch_rejected(self):
        self.assertIn("error", self.request("initialize", {"protocolVersion": "unknown"}))

    def test_arbitrary_tool_and_destination_rejected(self):
        self.initialize()
        self.assertIn("error", self.request("tools/call", {"name": "shell", "arguments": {}}))
        self.assertIn("error", self.request("tools/call", {"name": "update_ticket", "arguments": {
            "identity": "agent", "ticket": "TICKET-001", "request_id": "r", "url": "https://example.com"}}))

    def test_tool_call_budget_enforced(self):
        self.initialize()
        self.protocol.calls = 20
        self.assertIn("error", self.request("tools/call", {"name": "update_ticket", "arguments": {}}))


if __name__ == "__main__":
    unittest.main()
