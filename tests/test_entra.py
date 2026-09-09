"""Offline adapter contract tests; these are not live Microsoft tenant results."""

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tracebound.common import canonical, digest
from tracebound.entra import CANARY, check_token_scope, make_plan, observe, validate_plan
from tracebound.evidence import verify

TENANT = "11111111-1111-1111-1111-111111111111"
SUBJECT = "22222222-2222-2222-2222-222222222222"


def token_for(tenant=TENANT, subject=SUBJECT):
    claims = {"tid": tenant, "oid": subject, "aud": "https://graph.microsoft.com", "scp": "User.Read"}
    segment = base64.urlsafe_b64encode(canonical(claims)).rstrip(b"=").decode()
    return "eyJhbGciOiJSUzI1NiJ9." + segment + ".synthetic-signature"


class FixtureTransport:
    def __init__(self, statuses, subject=SUBJECT):
        self.statuses = iter(statuses)
        self.tokens = []
        self.subject = subject

    def probe(self, token):
        self.tokens.append(token)
        status = next(self.statuses)
        return {"http_status": status, "body": {"id": self.subject} if status == 200 else {},
                "response_sha256": "0" * 64, "transport_error": "unavailable" if status is None else None}


class EntraAdapter(unittest.TestCase):
    def setUp(self):
        self.plan = make_plan(TENANT, SUBJECT, "test-operator", attempts=4)
        self.token = token_for()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "bundle"

    def run_fixture(self, statuses, subject=SUBJECT):
        self.transport = FixtureTransport(statuses, subject)
        self.markers = []
        observe(self.plan, digest(canonical(self.plan)), self.token, self.output,
                transport=self.transport, marker=lambda: self.markers.append(True), sleeper=lambda _: None)
        return json.loads((self.output / "results.json").read_text())

    def test_same_token_all_attempts_and_offline_replay(self):
        results = self.run_fixture([200, 200, 401, 403, 429])
        self.assertEqual(results["summary"]["post_marker_allowed"], 1)
        self.assertEqual(results["summary"]["post_marker_denied"], 2)
        self.assertEqual(results["summary"]["post_marker_unknown"], 1)
        self.assertEqual(len(self.transport.tokens), 5)
        self.assertEqual(set(self.transport.tokens), {self.token})
        self.assertTrue(verify(self.output)["recorded_results_replayed"])

    def test_denial_then_success_reported(self):
        results = self.run_fixture([200, 401, 200, 403, 200])
        self.assertTrue(results["summary"]["success_after_first_denial"])
        self.assertEqual(results["summary"]["revocation_causality"], "not established")

    def test_rate_limit_and_transport_error_are_unknown(self):
        results = self.run_fixture([200, 429, None, 500, 302])
        self.assertEqual(results["summary"]["post_marker_denied"], 0)
        self.assertEqual(results["summary"]["post_marker_unknown"], 4)
        self.assertIsNone(results["summary"]["first_denial_observation_interval"])

    def test_failed_baseline_prevents_marker_and_further_requests(self):
        results = self.run_fixture([401])
        self.assertFalse(results["summary"]["baseline_confirmed"])
        self.assertFalse(self.markers)
        self.assertEqual(len(self.transport.tokens), 1)
        self.assertTrue(verify(self.output)["recorded_results_replayed"])

    def test_wrong_subject_does_not_establish_baseline(self):
        results = self.run_fixture([200], subject="33333333-3333-3333-3333-333333333333")
        self.assertFalse(results["summary"]["baseline_confirmed"])
        self.assertFalse(self.markers)

    def test_credential_never_written(self):
        self.run_fixture([200, 200, 401, 401, 401])
        for path in self.output.iterdir():
            self.assertNotIn(self.token.encode(), path.read_bytes())

    def test_plan_digest_mismatch_stops_before_network(self):
        transport = FixtureTransport([200])
        with self.assertRaises(ValueError):
            observe(self.plan, "wrong", self.token, self.output, transport=transport)
        self.assertFalse(transport.tokens)
        self.assertFalse(self.output.exists())

    def test_arbitrary_canary_url_rejected(self):
        self.plan["url"] = "https://example.com/steal"
        with self.assertRaises(ValueError):
            validate_plan(self.plan)

    def test_token_subject_and_tenant_mismatch_rejected(self):
        for token in (token_for(tenant=SUBJECT), token_for(subject=TENANT)):
            with self.assertRaises(ValueError):
                check_token_scope(token, self.plan)

    def test_observation_budget_enforced(self):
        self.plan["attempts"] = 61
        with self.assertRaises(ValueError):
            validate_plan(self.plan)

    def test_expired_plan_cannot_execute_but_can_be_inspected_offline(self):
        self.plan["created_at"] = "2020-01-01T00:00:00+00:00"
        self.plan["expires_at"] = "2020-01-02T00:00:00+00:00"
        with self.assertRaises(ValueError):
            validate_plan(self.plan)
        validate_plan(self.plan, allow_expired=True)


if __name__ == "__main__":
    unittest.main()
