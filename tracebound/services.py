"""Three real local HTTP services: identity, resource, and evidence witness.

The agent never receives the administration or witness credentials. All services
run under one OS account in this reference lab: process separation is not an
independent organizational trust boundary.
"""

import hmac
import os
import secrets
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from .common import MAX_MESSAGE, canonical, decode, digest, local_request, utc_now


class Service:
    def __init__(self, config):
        self.config = config
        self.role = config["role"]
        self.events = []
        self.tokens = {}
        self.cache = {}
        self.sessions = {}
        self.approvals = {}
        self.jobs = {}
        self.tickets = {"TICKET-001": 0, "TICKET-002": 0}
        self.controls = {"live_grants": False, "queue_origin": False,
                         "approval_binding": False, "approval_once": False}

    def authorized(self, actual, key):
        expected = self.config.get(key)
        return bool(expected) and hmac.compare_digest(actual, expected)

    def emit(self, kind, details):
        code, result = local_request(self.config["witness"], "/append", {
            "kind": kind, "details": details,
        }, self.config["witness_writer"])
        if code != 200:
            raise RuntimeError("witness unavailable")
        return result["chunk_id"]

    def inspect(self, token, live=False):
        if not live and token in self.cache:
            claim = dict(self.cache[token])
        else:
            code, claim = local_request(self.config["identity"], "/inspect",
                                        {"token": token}, self.config["checker"])
            if code != 200:
                return {"active": False, "principal": "unknown"}
            if claim.get("active"):
                self.cache[token] = dict(claim)
        if claim.get("expires_ns", 0) <= time.monotonic_ns():
            claim["active"] = False
        return claim

    def dispatch(self, path, body, token):
        if self.role == "witness":
            return self.witness(path, body, token)
        if self.role == "identity":
            return self.identity(path, body, token)
        return self.resource(path, body, token)

    def witness(self, path, body, token):
        if path == "/events" and self.authorized(token, "reader"):
            return 200, {"events": self.events}
        writers = self.config["writers"]
        source = next((name for name, key in writers.items()
                       if hmac.compare_digest(token, key)), None)
        if path != "/append" or source is None:
            return 403, {"error": "access denied"}
        if len(self.events) >= 500:
            return 429, {"error": "event limit"}
        event = {"sequence": len(self.events), "source": source,
                 "scenario": self.config["scenario"],
                 "event_id": str(uuid.uuid4()), "timestamp": utc_now(),
                 "monotonic_ns": time.monotonic_ns(),
                 "previous": self.events[-1]["sha256"] if self.events else "0" * 64,
                 "kind": body["kind"], "details": body["details"]}
        event["sha256"] = digest(canonical(event))
        event["chunk_id"] = "sha256:" + event["sha256"]
        self.events.append(event)
        return 200, {"chunk_id": event["chunk_id"]}

    def identity(self, path, body, token):
        if path == "/inspect":
            if not self.authorized(token, "checker"):
                return 403, {"error": "access denied"}
            claim = dict(self.tokens.get(body.get("token"),
                                         {"active": False, "principal": "unknown"}))
            if claim.get("expires_ns", 0) <= time.monotonic_ns():
                claim["active"] = False
            return 200, claim
        if not self.authorized(token, "admin"):
            return 403, {"error": "access denied"}
        if path == "/issue":
            if len(self.tokens) >= 30 or body.get("principal") not in (
                    "agent-001", "child-001", "queue-worker"):
                return 400, {"error": "invalid lab principal or limit"}
            credential = secrets.token_urlsafe(32)
            claim = {"principal": body["principal"], "parent": body.get("parent"),
                     "credential_id": str(uuid.uuid4()), "active": True,
                     "scope": "synthetic-ticket:update",
                     "expires_ns": time.monotonic_ns() + 300_000_000_000}
            ref = self.emit("grant.issued", {k: v for k, v in claim.items()})
            self.tokens[credential] = claim
            return 200, {"token": credential, "claim": claim, "chunk_id": ref}
        if path == "/revoke":
            subject = body["principal"]
            principals = {subject}
            if body.get("descendants"):
                # Iterate to closure so deeper delegated chains are included.
                while True:
                    expanded = principals | {c["principal"] for c in self.tokens.values()
                                             if c.get("parent") in principals}
                    if expanded == principals:
                        break
                    principals = expanded
            ref = self.emit("grant.revocation.requested", {"principals": sorted(principals)})
            for claim in self.tokens.values():
                if claim["principal"] in principals:
                    claim["active"] = False
            done = self.emit("grant.revoked", {"principals": sorted(principals)})
            return 200, {"principals": sorted(principals), "chunk_id": done,
                         "request_chunk_id": ref}
        return 404, {"error": "unknown route"}

    def resource(self, path, body, token):
        if path.startswith("/admin/"):
            if not self.authorized(token, "admin"):
                return 403, {"error": "access denied"}
            if path == "/admin/state":
                ref = self.emit("resource.snapshot", {"tickets": dict(self.tickets)})
                return 200, {"tickets": dict(self.tickets), "chunk_id": ref}
            if path == "/admin/controls":
                if any(k not in self.controls or type(v) is not bool for k, v in body.items()):
                    return 400, {"error": "unknown control"}
                ref = self.emit("control.changed", body)
                self.controls.update(body)
                return 200, {"chunk_id": ref}
            if path == "/admin/revoke-sessions":
                for session in self.sessions.values():
                    if session["principal"] == body["principal"]:
                        session["active"] = False
                ref = self.emit("session.revoked", {"principal": body["principal"]})
                return 200, {"chunk_id": ref}
            if path == "/admin/approval":
                action = body["action"]
                self.validate_action(action)
                approval_id = str(uuid.uuid4())
                self.approvals[approval_id] = {"digest": digest(canonical(action)),
                    "principal": "agent-001", "used": False,
                    "expires_ns": time.monotonic_ns() + 300_000_000_000}
                ref = self.emit("approval.granted", {"approval_id": approval_id,
                    "action": action, "action_digest": digest(canonical(action)),
                    "reviewer": "lab-reviewer", "identity_assurance": "synthetic"})
                return 200, {"approval_id": approval_id, "chunk_id": ref}
            if path == "/admin/worker":
                self.config["worker_token"] = body["token"]
                return 200, {"configured": True}
            if path == "/admin/drain":
                job = self.jobs.get(body.get("job_id"))
                if not job or job["drained"]:
                    return 409, {"error": "job missing or already drained"}
                job["drained"] = True
                worker = self.inspect(self.config["worker_token"], live=True)
                origin = self.inspect(job["token"], live=True)
                reason = None
                if not worker.get("active"):
                    reason = "worker_revoked"
                elif self.controls["queue_origin"] and not origin.get("active"):
                    reason = "submitter_revoked"
                return self.act(job["action"], worker, body["request_id"], reason,
                                {"path": "queue", "origin": origin["principal"]})
            return 404, {"error": "unknown admin route"}
        if path == "/session":
            if len(self.sessions) >= 30:
                return 429, {"error": "session limit"}
            claim = self.inspect(token, live=True)
            if not claim.get("active"):
                return 403, {"error": "inactive grant"}
            session = secrets.token_urlsafe(32)
            self.sessions[session] = {"principal": claim["principal"], "active": True,
                                     "expires_ns": time.monotonic_ns() + 300_000_000_000}
            ref = self.emit("session.created", {"principal": claim["principal"]})
            return 200, {"session": session, "chunk_id": ref}
        if path not in ("/ticket", "/session-ticket", "/approved-ticket", "/queue"):
            return 404, {"error": "unknown route"}
        action = body["action"]
        self.validate_action(action)
        if path == "/session-ticket":
            claim = self.sessions.get(token, {"active": False, "principal": "unknown"})
            active = claim.get("active") and claim.get("expires_ns", 0) > time.monotonic_ns()
        else:
            claim = self.inspect(token, live=self.controls["live_grants"])
            active = claim.get("active")
        reason = None if active else "inactive_grant"
        if path == "/queue":
            if reason:
                return 403, {"error": reason}
            if len(self.jobs) >= 20:
                return 429, {"error": "job limit"}
            job_id = str(uuid.uuid4())
            self.jobs[job_id] = {"action": action, "token": token, "drained": False}
            ref = self.emit("job.queued", {"job_id": job_id, "action": action,
                                          "principal": claim["principal"]})
            return 200, {"job_id": job_id, "chunk_id": ref}
        extra = {"path": path.strip("/")}
        if path == "/approved-ticket" and not reason:
            approval_id = body.get("approval_id")
            approval = self.approvals.get(approval_id)
            extra["approval_id"] = approval_id
            if not approval or approval["expires_ns"] <= time.monotonic_ns():
                reason = "approval_missing_or_expired"
            elif approval["principal"] != claim["principal"]:
                reason = "approval_principal_mismatch"
            elif self.controls["approval_binding"] and approval["digest"] != digest(canonical(action)):
                reason = "approval_scope_changed"
            elif self.controls["approval_once"] and approval["used"]:
                reason = "approval_already_used"
            if not reason:
                approval["used"] = True
        return self.act(action, claim, body["request_id"], reason, extra)

    def validate_action(self, action):
        if (not isinstance(action, dict) or set(action) != {"ticket", "operation"}
                or action["ticket"] not in self.tickets or action["operation"] != "increment"):
            raise ValueError("only bounded synthetic ticket increments are supported")

    def act(self, action, claim, request_id, reason, extra):
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 80:
            raise ValueError("invalid request id")
        details = {"request_id": request_id, "principal": claim["principal"],
                   "action": action, "action_digest": digest(canonical(action)), **extra}
        self.emit("action.evaluated", {**details, "decision": "deny" if reason else "allow"})
        before = self.tickets[action["ticket"]]
        if not reason:
            self.tickets[action["ticket"]] += 1
        after = self.tickets[action["ticket"]]
        details.update({"outcome": "denied" if reason else "succeeded",
                        "reason": reason, "before": before, "after": after})
        ref = self.emit("action.observed", details)
        return (403 if reason else 200), {**details, "chunk_id": ref}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format, *args):
        pass  # Never copy request headers or credentials to console logs.

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, has_body):
        try:
            self.connection.settimeout(5)
            if self.headers.get("Origin") or self.headers.get("Transfer-Encoding"):
                raise ValueError("browser-origin and chunked requests are not supported")
            expected_host = "127.0.0.1:" + str(self.server.server_port)
            if self.headers.get("Host") != expected_host:
                raise ValueError("unexpected Host")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1:
                raise ValueError("ambiguous content length")
            size = int(lengths[0]) if lengths else 0
            if not 0 <= size <= MAX_MESSAGE or (not has_body and size):
                raise ValueError("request limit")
            body = decode(self.rfile.read(size)) if has_body and size else {}
            if not isinstance(body, dict):
                raise ValueError("object required")
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            status, result = self.server.service.dispatch(self.path, body, token)
        except (ValueError, KeyError, TypeError, RecursionError):
            status, result = 400, {"error": "invalid bounded lab request"}
        except Exception:
            status, result = 503, {"error": "dependency unavailable; outcome unknown"}
        raw = canonical(result)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


def main():
    config = decode(os.environ.pop("TRACEBOUND_SERVICE_CONFIG").encode())
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.service = Service(config)
    print(canonical({"url": "http://127.0.0.1:" + str(server.server_port)}).decode(), flush=True)
    server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
