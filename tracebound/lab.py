"""Run independently observed local containment experiments."""

import secrets
import time
import uuid

from .common import local_request
from .mcp_server import VERSION
from .process import Child

SCENARIOS = {
    "cached_token": {"title": "Cached access token", "exposure": "The resource accepts a cached grant after identity revocation.",
        "fix": "Check current grant status at the resource boundary.", "owner": "Identity and application owners"},
    "application_session": {"title": "Application-owned session", "exposure": "An application session survives revocation at the identity service.",
        "fix": "Invalidate application sessions associated with the principal.", "owner": "Application owner"},
    "child_agent": {"title": "Child-agent authority", "exposure": "A child agent retains its separately issued grant.",
        "fix": "Revoke descendant grants and validate them at execution.", "owner": "Agent platform owner"},
    "queued_job": {"title": "Queued work", "exposure": "Queued work executes through a service identity after the submitter loses access.",
        "fix": "Recheck both the submitter and worker authority when dequeuing.", "owner": "Workflow owner"},
    "approval_replay": {"title": "Reused approval", "exposure": "A recorded single-use approval is accepted again.",
        "fix": "Enforce single-use approval consumption at the action boundary.", "owner": "Approval service owner"},
    "approval_scope": {"title": "Changed action scope", "exposure": "An approval for one ticket is applied to a different ticket.",
        "fix": "Bind approval to the principal and exact operation arguments.", "owner": "Approval service owner"},
}


class Lab:
    def __init__(self, scenario):
        self.scenario = scenario
        self.children = []
        self.protocol = []
        self.request_sequence = 0

    def start_service(self, config):
        child = Child("tracebound.services", config, "TRACEBOUND_SERVICE_CONFIG")
        self.children.append(child)
        return child.receive()["url"]

    def __enter__(self):
        try:
            self.reader = secrets.token_urlsafe(32)
            self.writers = {name: secrets.token_urlsafe(32) for name in ("identity", "resource", "controller")}
            self.id_admin, self.res_admin, self.checker = [secrets.token_urlsafe(32) for _ in range(3)]
            self.witness = self.start_service({"role": "witness", "scenario": self.scenario,
                "reader": self.reader, "writers": self.writers})
            self.identity = self.start_service({"role": "identity", "admin": self.id_admin,
                "checker": self.checker, "witness": self.witness, "witness_writer": self.writers["identity"]})
            self.resource = self.start_service({"role": "resource", "admin": self.res_admin,
                "identity": self.identity, "checker": self.checker, "witness": self.witness,
                "witness_writer": self.writers["resource"]})
            self.credentials, self.grants = {}, []
            for label, principal, parent in (("agent", "agent-001", None),
                    ("child", "child-001", "agent-001"), ("worker", "queue-worker", None)):
                issued = self.admin("identity", "/issue", {"principal": principal, "parent": parent})
                self.credentials[label] = issued["token"]
                self.grants.append({**issued["claim"], "chunk_id": issued["chunk_id"]})
            self.admin("resource", "/admin/worker", {"token": self.credentials["worker"]})
            if self.scenario != "cached_token":
                self.admin("resource", "/admin/controls", {"live_grants": True})
            if self.scenario == "application_session":
                code, response = local_request(self.resource, "/session", {}, self.credentials["agent"])
                if code != 200:
                    raise RuntimeError("session setup failed")
                self.credentials["session"] = response["session"]
            # The tool server receives only agent/child/session access; no worker or admin credentials.
            self.agent = Child("tracebound.mcp_server", {"resource": self.resource,
                "credentials": {k: v for k, v in self.credentials.items() if k != "worker"}}, "TRACEBOUND_MCP_CONFIG")
            self.children.append(self.agent)
            self.rpc("initialize", {"protocolVersion": VERSION, "capabilities": {},
                "clientInfo": {"name": "tracebound-bounded-agent", "version": "0.1.0"}})
            self.agent.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.rpc("tools/list", {})
            self.record("agent.instruction", {"instruction": "Run only the selected, bounded synthetic ticket experiment.",
                "scenario": self.scenario, "agent_type": "scripted", "model_calls": 0,
                "model_tokens": 0, "max_tool_calls": 20, "human_authorization": "local CLI invocation"})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        for child in reversed(self.children):
            child.close()

    def admin(self, service, path, body):
        url, credential = (self.identity, self.id_admin) if service == "identity" else (self.resource, self.res_admin)
        status, result = local_request(url, path, body, credential)
        if status != 200:
            raise RuntimeError("lab administration failed: " + path)
        return result

    def record(self, kind, details):
        status, result = local_request(self.witness, "/append", {"kind": kind, "details": details}, self.writers["controller"])
        if status != 200:
            raise RuntimeError("controller evidence unavailable")
        return result["chunk_id"]

    def rpc(self, method, params):
        self.request_sequence += 1
        request = {"jsonrpc": "2.0", "id": self.request_sequence, "method": method, "params": params}
        self.agent.send(request)
        response = self.agent.receive()
        self.protocol.append({"scenario": self.scenario, "request": request, "response": response})
        self.record("mcp.exchange", self.protocol[-1])
        if response.get("id") != self.request_sequence or "error" in response:
            raise RuntimeError("MCP request failed")
        return response["result"]

    def tool(self, identity="agent", ticket="TICKET-001", approval=None, enqueue=False, request_id=None):
        args = {"identity": identity, "ticket": ticket, "request_id": request_id or str(uuid.uuid4())}
        if approval:
            args["approval_id"] = approval
        return self.rpc("tools/call", {"name": "enqueue_ticket" if enqueue else "update_ticket",
                                      "arguments": args})["structuredContent"]

    def probe(self, phase, boundary=None, identity="agent", ticket="TICKET-001", approval=None, job=None):
        before = self.admin("resource", "/admin/state", {})
        request_id = str(uuid.uuid4())
        started = time.monotonic_ns()
        try:
            if job:
                status, response = local_request(self.resource, "/admin/drain",
                    {"job_id": job, "request_id": request_id}, self.res_admin)
                response["http_status"] = status
            else:
                response = self.tool(identity, ticket, approval, request_id=request_id)
        except Exception:
            response = {"http_status": None, "outcome": "unknown"}
            self.record("transport.failed", {"request_id": request_id, "phase": phase,
                                              "outcome": "unknown"})
        ended = time.monotonic_ns()
        after = self.admin("resource", "/admin/state", {})
        delta = after["tickets"][ticket] - before["tickets"][ticket]
        status = response.get("http_status")
        observed = "unknown"
        if status == 200 and response.get("outcome") == "succeeded" and delta == 1:
            observed = "succeeded"
        elif status == 403 and response.get("outcome") == "denied" and delta == 0:
            observed = "denied"
        result = {"phase": phase, "request_id": request_id, "ticket": ticket,
            "observation": observed, "http_status": status, "reason": response.get("reason"),
            "principal": response.get("principal", "unknown"), "state_delta": delta,
            "round_trip_ms": round((ended - started) / 1e6, 3),
            "since_boundary_ms": round((ended - boundary) / 1e6, 3) if boundary else None,
            "receipt_chunk_id": response.get("chunk_id"),
            "before_chunk_id": before["chunk_id"], "after_chunk_id": after["chunk_id"]}
        result["observation_chunk_id"] = self.record("probe.completed", result)
        return result

    def approval(self):
        return self.admin("resource", "/admin/approval", {"action": {
            "ticket": "TICKET-001", "operation": "increment"}})["approval_id"]

    def experiment(self):
        scenario = self.scenario
        identity = "session" if scenario == "application_session" else "child" if scenario == "child_agent" else "agent"
        approval = self.approval() if scenario.startswith("approval_") else None
        baseline = self.probe("baseline", identity=identity, approval=approval)
        if baseline["observation"] != "succeeded":
            raise RuntimeError("baseline was not independently observed to succeed")
        jobs = []
        if scenario == "queued_job":
            jobs = [self.tool(enqueue=True)["job_id"] for _ in range(2)]
        if scenario == "approval_scope":
            approval = self.approval()
        initial_ns = time.monotonic_ns()
        if scenario.startswith("approval_"):
            boundary = self.record("approval.boundary.expected", {
                "approval_id": approval, "expectation": "single use and exact action scope"})
        else:
            boundary = self.admin("identity", "/revoke", {"principal": "agent-001"})["chunk_id"]
        ticket = "TICKET-002" if scenario == "approval_scope" else "TICKET-001"
        initial = self.probe("initial_control", initial_ns, identity, ticket, approval,
                             job=jobs[0] if jobs else None)
        fix_ns = time.monotonic_ns()
        if scenario == "cached_token":
            fixed = self.admin("resource", "/admin/controls", {"live_grants": True})
        elif scenario == "application_session":
            fixed = self.admin("resource", "/admin/revoke-sessions", {"principal": "agent-001"})
        elif scenario == "child_agent":
            fixed = self.admin("identity", "/revoke", {"principal": "agent-001", "descendants": True})
        elif scenario == "queued_job":
            fixed = self.admin("resource", "/admin/controls", {"queue_origin": True})
        else:
            fixed = self.admin("resource", "/admin/controls", {"approval_binding": True, "approval_once": True})
        retest = self.probe("remediated_control", fix_ns, identity, ticket, approval,
                            job=jobs[1] if jobs else None)
        status, result = local_request(self.witness, "/events", token=self.reader)
        if status != 200:
            raise RuntimeError("cannot obtain witness events")
        finding = {"scenario": scenario, **SCENARIOS[scenario], "mode": "running-local-services",
            "baseline": baseline, "initial": initial, "retest": retest,
            "initial_boundary_chunk_id": boundary, "remediation_chunk_id": fixed["chunk_id"],
            "initial_control": "failed" if initial["observation"] == "succeeded" else "unknown",
            "remediated_control": "observed_denied" if retest["observation"] == "denied" else "unknown",
            "untested": ["production deployments", "other credentials and resources",
                         "future executions outside the observation window", "stochastic model behavior"],
            "grants": self.grants}
        return finding, result["events"], self.protocol


def run_lab(scenarios=None):
    selected = list(scenarios or SCENARIOS)
    if not selected or len(selected) != len(set(selected)) or any(s not in SCENARIOS for s in selected):
        raise ValueError("select distinct supported scenarios")
    findings, events, protocol = [], [], []
    for scenario in selected:
        with Lab(scenario) as lab:
            finding, recorded, exchanges = lab.experiment()
            findings.append(finding)
            events.extend(recorded)
            protocol.extend(exchanges)
    return findings, events, protocol
