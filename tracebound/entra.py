"""Read-only Entra/Graph canary observations after operator-performed revocation.

No refresh, credential issuance, account disablement, or automatic revocation.
The local marker is an operator assertion, not an authenticated provider event.
"""

import base64
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from .common import MAX_MESSAGE, NoRedirect, canonical, decode, digest, private_write, utc_now
from .evidence import jsonl, validate_chain, write_bundle

CANARY = "https://graph.microsoft.com/v1.0/me?$select=id"


def make_plan(tenant_id, subject_id, operator, attempts=10, interval=1):
    plan = {"schema_version": "tracebound-entra-plan/1", "tenant_id": tenant_id,
        "subject_id": subject_id, "operator": operator, "url": CANARY,
        "method": "GET", "attempts": attempts, "interval_seconds": interval,
        "created_at": utc_now(), "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        "revocation": "performed independently by operator", "token_source": "TRACEBOUND_ENTRA_TOKEN"}
    validate_plan(plan)
    return plan


def validate_plan(plan, allow_expired=False):
    expected = {"schema_version", "tenant_id", "subject_id", "operator", "url", "method",
                "attempts", "interval_seconds", "created_at", "expires_at", "revocation", "token_source"}
    if set(plan) != expected or plan["schema_version"] != "tracebound-entra-plan/1":
        raise ValueError("invalid Entra plan schema")
    for key in ("tenant_id", "subject_id"):
        if str(uuid.UUID(plan[key])) != plan[key]:
            raise ValueError("use canonical lowercase tenant and subject UUIDs")
    if (plan["url"] != CANARY or plan["method"] != "GET"
            or plan["revocation"] != "performed independently by operator"
            or plan["token_source"] != "TRACEBOUND_ENTRA_TOKEN"):
        raise ValueError("only the fixed read-only Graph canary is supported")
    if (not isinstance(plan["operator"], str) or not 1 <= len(plan["operator"]) <= 80
            or not all(c.isprintable() for c in plan["operator"])):
        raise ValueError("invalid operator label")
    if (type(plan["attempts"]) is not int or not 1 <= plan["attempts"] <= 60
            or type(plan["interval_seconds"]) is not int or not 1 <= plan["interval_seconds"] <= 5
            or plan["attempts"] * plan["interval_seconds"] > 120):
        raise ValueError("observation window exceeds limits")
    created = datetime.fromisoformat(plan["created_at"])
    expires = datetime.fromisoformat(plan["expires_at"])
    if (created.utcoffset() != timedelta(0) or expires.utcoffset() != timedelta(0)
            or not timedelta(0) < expires - created <= timedelta(hours=25)):
        raise ValueError("invalid plan validity window")
    if not allow_expired and not created <= datetime.now(timezone.utc) < expires:
        raise ValueError("plan is expired or not yet valid")


def check_token_scope(token, plan):
    if (not isinstance(token, str) or not 20 <= len(token) <= 16384
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", token)):
        raise ValueError("provide a bounded JWT-shaped delegated token in the environment")
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("unsupported token encoding")
        claims = decode(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception as error:
        raise ValueError("unable to inspect token scope") from error
    if (claims.get("tid") != plan["tenant_id"] or claims.get("oid") != plan["subject_id"]
            or claims.get("aud") not in ("https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000")
            or not isinstance(claims.get("scp"), str)):
        raise ValueError("token claims do not match the reviewed delegated Graph scope")
    # These are unverified local claims used only to reject mismatched input.
    # Graph validates the credential; /me.id is checked against the planned subject.


class GraphTransport:
    def probe(self, token):
        request = Request(CANARY, method="GET", headers={"Authorization": "Bearer " + token,
                                                           "Accept": "application/json"})
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            try:
                response = opener.open(request, timeout=10)
            except HTTPError as error:
                response = error
            with response:
                raw = response.read(MAX_MESSAGE + 1)
                if len(raw) > MAX_MESSAGE:
                    return {"http_status": response.status, "body": None, "response_sha256": None,
                            "transport_error": "response_size_limit"}
                try:
                    body = decode(raw)
                except (ValueError, RecursionError):
                    body = None
                return {"http_status": response.status, "body": body,
                        "response_sha256": digest(raw), "transport_error": None}
        except Exception:
            return {"http_status": None, "body": None, "response_sha256": None,
                    "transport_error": "network_or_transport_failure"}


def summarize_observations(events):
    validate_chain(events)
    baselines = [e for e in events if e["kind"] == "cloud.request.observed" and e["details"]["phase"] == "baseline"]
    markers = [e for e in events if e["kind"] == "containment.operator_marker"]
    probes = [e for e in events if e["kind"] == "cloud.request.observed" and e["details"]["phase"] == "post_marker"]
    if len(baselines) != 1 or len(markers) > 1 or (probes and len(markers) != 1):
        raise ValueError("invalid baseline or marker structure")
    if markers and (baselines[0]["details"]["observation"] != "allowed"
                    or baselines[0]["sequence"] >= markers[0]["sequence"]):
        raise ValueError("no successful baseline before marker")
    if any(e["details"]["token_ref"] != baselines[0]["details"]["token_ref"] for e in probes):
        raise ValueError("credential changed during observation")
    for probe in baselines + probes:
        d = probe["details"]
        outcome = "unknown"
        if not d["transport_error"]:
            if d["http_status"] == 200 and d["subject_matches"]:
                outcome = "allowed"
            elif d["http_status"] in (401, 403):
                outcome = "denied"
        if d["observation"] != outcome:
            raise ValueError("unsupported cloud observation")
    for probe in probes:
        if probe["sequence"] <= markers[0]["sequence"] or probe["monotonic_ns"] < markers[0]["monotonic_ns"]:
            raise ValueError("post-marker probe has invalid order")
    allowed = [e for e in probes if e["details"]["observation"] == "allowed"]
    denied = [e for e in probes if e["details"]["observation"] == "denied"]
    first = denied[0] if denied else None
    interval = None
    if first:
        successes = [e for e in allowed if e["sequence"] < first["sequence"]]
        lower = successes[-1]["monotonic_ns"] if successes else markers[0]["monotonic_ns"]
        marker = markers[0]["monotonic_ns"]
        interval = {"last_success_or_marker_ms": round((lower - marker) / 1e6, 3),
                    "first_denial_ms": round((first["monotonic_ns"] - marker) / 1e6, 3)}
    return {"baseline_confirmed": baselines[0]["details"]["observation"] == "allowed",
        "operator_marker_present": bool(markers), "post_marker_allowed": len(allowed),
        "post_marker_denied": len(denied), "post_marker_unknown": len(probes) - len(allowed) - len(denied),
        "first_denial_observation_interval": interval,
        "success_after_first_denial": bool(first and any(e["sequence"] > first["sequence"] for e in allowed)),
        "revocation_causality": "not established", "model_calls": 0, "model_tokens": 0}


def observe(plan, approved_digest, token, output, transport=None, marker=None, sleeper=time.sleep, signing_key=None):
    from .report import render_entra
    validate_plan(plan)
    if approved_digest != digest(canonical(plan)):
        raise ValueError("reviewed plan digest does not match")
    check_token_scope(token, plan)
    if os.path.lexists(output):
        raise ValueError("output already exists")
    transport = transport or GraphTransport()
    events = []
    token_ref = "sha256:" + digest(token.encode())
    def record(kind, details):
        event = {"scenario": "entra-canary", "source": "local-observer", "sequence": len(events),
            "event_id": str(uuid.uuid4()), "timestamp": utc_now(), "monotonic_ns": time.monotonic_ns(),
            "previous": events[-1]["sha256"] if events else "0" * 64, "kind": kind, "details": details}
        event["sha256"] = digest(canonical(event))
        event["chunk_id"] = "sha256:" + event["sha256"]
        events.append(event)
    def probe(phase):
        response = transport.probe(token)
        body = response.pop("body")
        matches = isinstance(body, dict) and body.get("id") == plan["subject_id"]
        outcome = "unknown"
        if not response["transport_error"]:
            if response["http_status"] == 200 and matches:
                outcome = "allowed"
            elif response["http_status"] in (401, 403):
                outcome = "denied"
        record("cloud.request.observed", {"phase": phase, **response, "subject_matches": matches,
            "observation": outcome, "token_ref": token_ref, "url": CANARY, "method": "GET"})
        return outcome
    if probe("baseline") == "allowed":
        if marker is None:
            input("Baseline succeeded. Perform the reviewed revocation in your separate admin session, then press Enter to mark it: ")
        else:
            marker()
        record("containment.operator_marker", {"operator": plan["operator"],
            "approved_plan_sha256": approved_digest, "assurance": "local operator assertion"})
        deadline = time.monotonic() + 120
        for index in range(plan["attempts"]):
            if index:
                sleeper(plan["interval_seconds"])
            if time.monotonic() >= deadline:
                record("observation.window.closed", {"reason": "deadline", "requested_attempts": plan["attempts"]})
                break
            probe("post_marker")
    results = {"schema_version": "tracebound-results/1", "kind": "entra-observation", "created_at": utc_now(),
        "summary": summarize_observations(events), "approved_plan_sha256": approved_digest,
        "limitations": ["Read-only Graph /me path only; no refresh or application session test.",
            "No authenticated revocation event is collected; the marker is an operator assertion.",
            "401/403 can have causes other than revocation; causality remains unverified.",
            "Token claims are inspected locally without signature verification; Graph validates the presented token.",
            "Response bodies are minimized to subject-match flags and hashes; raw bodies are not retained."]}
    text = "# TraceBound Entra observation\n\n```json\n" + json_pretty(results) + "\n```\n"
    return write_bundle(output, {"results.json": canonical(results), "observations.jsonl": jsonl(events),
        "entra-plan.json": canonical(plan), "report.html": render_entra(results).encode(),
        "summary.md": text.encode()}, "entra-observation", signing_key)


def json_pretty(value):
    import json
    return json.dumps(value, indent=2, sort_keys=True)
