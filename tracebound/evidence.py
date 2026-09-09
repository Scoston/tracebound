"""Portable bundles, exact byte inventories, optional signatures, and replay.

Hashes detect changes against a retained manifest. The operator must pin the
manifest digest or public key independently to detect whole-bundle replacement.
"""

import base64
import json
import re
import uuid
from pathlib import Path

from .common import MAX_ARTIFACT, MAX_MESSAGE, canonical, decode, digest, new_directory, private_write, utc_now

DOMAIN = b"TraceBound manifest v1\x00"
LAB_FILES = {"results.json", "events.jsonl", "protocol.jsonl", "chunk-index.json",
             "authority.json", "afr-events.jsonl", "report.html", "summary.md"}
ENTRA_FILES = {"results.json", "observations.jsonl", "entra-plan.json", "report.html", "summary.md"}


def event_body(event):
    return {k: v for k, v in event.items() if k not in ("sha256", "chunk_id")}


def validate_chain(events):
    heads, sequences, chunks = {}, {}, {}
    for event in events:
        scenario = event["scenario"]
        if (event["sequence"] != sequences.get(scenario, 0)
                or event["previous"] != heads.get(scenario, "0" * 64)):
            raise ValueError("event sequence or chain is broken")
        computed = digest(canonical(event_body(event)))
        if event["sha256"] != computed or event["chunk_id"] != "sha256:" + computed:
            raise ValueError("event digest mismatch")
        if event["chunk_id"] in chunks:
            raise ValueError("duplicate event")
        heads[scenario], sequences[scenario] = computed, event["sequence"] + 1
        chunks[event["chunk_id"]] = event
    return chunks


def lab_summary(findings):
    return {"scenarios": len(findings), "probes": len(findings) * 3,
        "initial_controls_failed": sum(f["initial_control"] == "failed" for f in findings),
        "remediated_paths_denied": sum(f["remediated_control"] == "observed_denied" for f in findings),
        "unknown_probe_outcomes": sum(p["observation"] == "unknown" for f in findings
                                       for p in (f["baseline"], f["initial"], f["retest"])),
        "model_calls": 0, "model_tokens": 0}


def replay_lab(findings, events):
    from .lab import SCENARIOS
    chunks = validate_chain(events)
    if not findings or len(findings) > len(SCENARIOS):
        raise ValueError("invalid scenario count")
    selected = set()
    for finding in findings:
        scenario = finding["scenario"]
        if scenario in selected or scenario not in SCENARIOS:
            raise ValueError("duplicate or unsupported scenario")
        selected.add(scenario)
        for key, value in SCENARIOS[scenario].items():
            if finding[key] != value:
                raise ValueError("scenario description differs from pinned implementation")
        for key in ("initial_boundary_chunk_id", "remediation_chunk_id"):
            if chunks[finding[key]]["scenario"] != scenario:
                raise ValueError("cross-scenario boundary")
        for key, phase in (("baseline", "baseline"), ("initial", "initial_control"), ("retest", "remediated_control")):
            probe = finding[key]
            if probe["phase"] != phase:
                raise ValueError("phase mismatch")
            recorded = chunks[probe["observation_chunk_id"]]
            if recorded["source"] != "controller" or recorded["kind"] != "probe.completed":
                raise ValueError("missing controller observation")
            if recorded["details"] != {k: v for k, v in probe.items() if k != "observation_chunk_id"}:
                raise ValueError("probe differs from retained observation")
            before, after = chunks[probe["before_chunk_id"]], chunks[probe["after_chunk_id"]]
            if not probe["receipt_chunk_id"]:
                if (probe["observation"] != "unknown" or recorded["scenario"] != scenario
                        or any(e["source"] != "resource" or e["scenario"] != scenario
                               or e["kind"] != "resource.snapshot" for e in (before, after))
                        or not before["sequence"] < after["sequence"] < recorded["sequence"]):
                    raise ValueError("missing receipt cannot establish an outcome")
                if probe["state_delta"] != after["details"]["tickets"][probe["ticket"]] - before["details"]["tickets"][probe["ticket"]]:
                    raise ValueError("unknown observation state mismatch")
                continue
            receipt = chunks[probe["receipt_chunk_id"]]
            if any(e["scenario"] != scenario for e in (recorded, receipt, before, after)):
                raise ValueError("cross-scenario evidence reference")
            if (receipt["source"] != "resource" or receipt["kind"] != "action.observed"
                    or before["source"] != "resource" or after["source"] != "resource"
                    or before["kind"] != "resource.snapshot" or after["kind"] != "resource.snapshot"
                    or not before["sequence"] < receipt["sequence"] < after["sequence"] < recorded["sequence"]):
                raise ValueError("unconfirmed resource observations or event ordering")
            details = receipt["details"]
            if details["request_id"] != probe["request_id"] or details["action"]["ticket"] != probe["ticket"]:
                raise ValueError("receipt does not bind the tested action")
            delta = after["details"]["tickets"][probe["ticket"]] - before["details"]["tickets"][probe["ticket"]]
            if delta != probe["state_delta"] or delta != details["after"] - details["before"]:
                raise ValueError("resource state does not corroborate receipt")
            expected = "unknown"
            if probe["http_status"] == 200 and details["outcome"] == "succeeded" and delta == 1:
                expected = "succeeded"
            elif probe["http_status"] == 403 and details["outcome"] == "denied" and delta == 0:
                expected = "denied"
            if probe["observation"] != expected:
                raise ValueError("unsupported probe conclusion")
            if key == "initial" and chunks[finding["initial_boundary_chunk_id"]]["sequence"] >= receipt["sequence"]:
                raise ValueError("initial probe precedes boundary")
            if key == "retest" and chunks[finding["remediation_chunk_id"]]["sequence"] >= receipt["sequence"]:
                raise ValueError("retest precedes remediation")
        if finding["baseline"]["observation"] != "succeeded":
            raise ValueError("no working baseline")
        if finding["initial_control"] != ("failed" if finding["initial"]["observation"] == "succeeded" else "unknown"):
            raise ValueError("unsupported initial-control conclusion")
        if finding["remediated_control"] != ("observed_denied" if finding["retest"]["observation"] == "denied" else "unknown"):
            raise ValueError("unsupported remediation conclusion")
        for grant in finding["grants"]:
            source = chunks[grant["chunk_id"]]
            if source["source"] != "identity" or source["details"] != {k: v for k, v in grant.items() if k != "chunk_id"}:
                raise ValueError("grant projection mismatch")
    return lab_summary(findings)


def authority_graph(findings):
    nodes, edges = [], []
    for finding in findings:
        scenario = finding["scenario"]
        def node_id(value):
            return scenario + ":" + value
        for grant in finding["grants"]:
            principal = grant["principal"]
            nodes.append({"id": node_id(principal), "type": "principal", "label": principal,
                          "evidence_refs": [grant["chunk_id"]]})
            nodes.append({"id": grant["credential_id"], "type": "grant", "label": grant["scope"],
                          "evidence_refs": [grant["chunk_id"]]})
            edges.append({"from": node_id(principal), "to": grant["credential_id"],
                          "relationship": "holds", "evidence_refs": [grant["chunk_id"]]})
            if grant["parent"]:
                edges.append({"from": node_id(grant["parent"]), "to": node_id(principal),
                              "relationship": "delegates", "evidence_refs": [grant["chunk_id"]]})
        for ticket in ("TICKET-001", "TICKET-002"):
            nodes.append({"id": node_id(ticket), "type": "resource", "label": ticket, "evidence_refs": []})
        for key in ("baseline", "initial", "retest"):
            probe = finding[key]
            if node_id(probe["principal"]) not in {node["id"] for node in nodes}:
                nodes.append({"id": node_id(probe["principal"]), "type": "observed_principal",
                              "label": probe["principal"], "evidence_refs": [probe["observation_chunk_id"]]})
            edges.append({"from": node_id(probe["principal"]), "to": node_id(probe["ticket"]),
                          "relationship": probe["observation"], "phase": probe["phase"],
                          "evidence_refs": [probe["receipt_chunk_id"] or probe["observation_chunk_id"]]})
    return {"schema_version": "tracebound-authority/1", "scope": "declared lab inventory and observed probes",
            "nodes": nodes, "edges": edges}


def afr_projection(events, run_id):
    mapping = {"grant.issued": "ai.delegation.created", "grant.revoked": "ai.delegation.revoked",
        "session.created": "ai.session.started", "session.revoked": "ai.session.ended",
        "control.changed": "ai.policy.evaluated", "approval.granted": "ai.approval.granted",
        "resource.snapshot": "ai.state.validated", "agent.instruction": "ai.instruction.received"}
    rows = []
    for event in events:
        details = event["details"]
        event_type = mapping.get(event["kind"])
        if event["kind"] == "action.observed":
            event_type = "ai.tool.executed" if details["outcome"] == "succeeded" else "ai.tool.failed"
        if not event_type:
            continue
        row = {"schema_version": "0.1.0-draft", "event_id": event["event_id"],
            "event_type": event_type, "timestamp": event["timestamp"], "sequence": event["sequence"],
            "correlation": {"trace_id": event["scenario"], "session_id": run_id + ":" + event["scenario"]},
            "principal": {"agent_id": details.get("principal", "agent-001"),
                          "runtime_identity": "tracebound-lab:" + event["source"]},
            "influence": {"provenance_refs": [event["chunk_id"]]},
            "integrity": {"collector": "tracebound-local-witness", "hash_algorithm": "sha256",
                "hash": event["sha256"], "retention_class": "synthetic-reference",
                "access_label": "synthetic"}}
        if event["kind"] == "action.observed":
            row["action"] = {"tool_id": "synthetic-ticket-service", "operation": "increment",
                "target": details["action"]["ticket"], "arguments_digest": details["action_digest"],
                "outcome": details["outcome"], "result_ref": event["chunk_id"]}
        rows.append(row)
    return rows


def jsonl(rows):
    return b"".join(canonical(row) + b"\n" for row in rows)


def chunk_index(events):
    result, offset = [], 0
    for event in events:
        raw = canonical(event) + b"\n"
        result.append({"chunk_id": event["chunk_id"], "artifact": "events.jsonl",
                       "byte_offset": offset, "byte_length": len(raw), "span_sha256": digest(raw)})
        offset += len(raw)
    return result


def keygen(private_path, public_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.exists() or public_path.exists() or private_path.absolute() == public_path.absolute():
        raise ValueError("key output paths must be distinct new files")
    key = Ed25519PrivateKey.generate()
    private_write(private_path, key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(public_path, key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))


def write_bundle(path, artifacts, kind, signing_key=None):
    expected = LAB_FILES if kind == "local-lab" else ENTRA_FILES if kind == "entra-observation" else None
    if expected is None or set(artifacts) != expected:
        raise ValueError("unexpected bundle artifact set")
    prepared_key = None
    target = Path(path).absolute()
    if signing_key:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if Path(signing_key).resolve().is_relative_to(target.resolve()):
            raise ValueError("signing key must be outside the evidence bundle")
        prepared_key = load_pem_private_key(Path(signing_key).read_bytes(), password=None)
        if not isinstance(prepared_key, Ed25519PrivateKey):
            raise ValueError("Ed25519 key required")
    for raw in artifacts.values():
        if len(raw) > MAX_ARTIFACT:
            raise ValueError("artifact exceeds bundle limit")
    target = new_directory(target)
    inventory = []
    for name, raw in artifacts.items():
        private_write(target / name, raw)
        inventory.append({"path": name, "bytes": len(raw), "sha256": digest(raw)})
    manifest = canonical({"schema_version": "tracebound-manifest/1", "kind": kind,
                          "artifacts": sorted(inventory, key=lambda item: item["path"])})
    private_write(target / "manifest.json", manifest)
    if prepared_key:
        private_write(target / "signature.json", canonical({"algorithm": "Ed25519",
            "domain": "TraceBound manifest v1", "signature": base64.b64encode(
                prepared_key.sign(DOMAIN + manifest)).decode()}))
    return {"output": str(target), "manifest_sha256": digest(manifest), "signed": bool(prepared_key)}


def save_lab(path, findings, events, protocol, signing_key=None):
    from .report import render_lab, markdown_lab
    summary = replay_lab(findings, events)
    run_id = str(uuid.uuid4())
    projection = afr_projection(events, run_id)
    results = {"schema_version": "tracebound-results/1", "kind": "local-lab", "run_id": run_id,
        "created_at": utc_now(), "version": "0.1.0", "summary": summary, "findings": findings,
        "afr_projection": {"emitted": len(projection), "omitted": len(events) - len(projection)},
        "limits": ["Synthetic tickets and principals; real local HTTP/MCP execution.",
            "Scripted agent; no language model or provider was invoked.",
            "All local services share an OS account; witness isolation is process-level only.",
            "A denied probe applies only to the tested path and observation window.",
            "Human reviewer identities are synthetic; effective human judgment was not measured.",
            "Time values are local monotonic observations, not trusted timestamps."]}
    artifacts = {"results.json": canonical(results), "events.jsonl": jsonl(events),
        "protocol.jsonl": jsonl(protocol), "chunk-index.json": canonical(chunk_index(events)),
        "authority.json": canonical(authority_graph(findings)), "afr-events.jsonl": jsonl(projection),
        "report.html": render_lab(results).encode(), "summary.md": markdown_lab(results).encode()}
    return write_bundle(path, artifacts, "local-lab", signing_key)


def _read(path, limit=MAX_ARTIFACT):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("missing, unsafe, or oversized artifact")
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("artifact exceeds size limit")
    return raw


def verify(path, trusted_key=None, expected_manifest=None):
    target = Path(path)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("bundle must be a regular directory")
    manifest_bytes = _read(target / "manifest.json", MAX_MESSAGE)
    if expected_manifest and digest(manifest_bytes) != expected_manifest:
        raise ValueError("independently pinned manifest does not match")
    manifest = decode(manifest_bytes)
    if manifest.get("schema_version") != "tracebound-manifest/1":
        raise ValueError("unsupported manifest")
    expected = LAB_FILES if manifest.get("kind") == "local-lab" else ENTRA_FILES if manifest.get("kind") == "entra-observation" else None
    if expected is None:
        raise ValueError("unsupported bundle kind")
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or len(entries) != len(expected):
        raise ValueError("invalid inventory count")
    names = [entry["path"] for entry in entries]
    if set(names) != expected or len(set(names)) != len(names):
        raise ValueError("unexpected or duplicate artifact path")
    actual = {p.name for p in target.iterdir()}
    if actual - (expected | {"manifest.json", "signature.json"}):
        raise ValueError("unmanifested bundle content")
    raw = {}
    for entry in entries:
        content = _read(target / entry["path"])
        if len(content) != entry["bytes"] or digest(content) != entry["sha256"]:
            raise ValueError("artifact bytes do not match inventory: " + entry["path"])
        raw[entry["path"]] = content
    signature_status = "absent" if "signature.json" not in actual else "present_not_authenticated"
    if "signature.json" in actual:
        signature = decode(_read(target / "signature.json", MAX_MESSAGE))
        if signature.get("algorithm") != "Ed25519" or signature.get("domain") != "TraceBound manifest v1":
            raise ValueError("unsupported signature envelope")
    if trusted_key:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if Path(trusted_key).resolve().is_relative_to(target.resolve()):
            raise ValueError("trusted public key must be provided outside the bundle")
        if "signature.json" not in actual:
            raise ValueError("required signature missing")
        key = load_pem_public_key(_read(Path(trusted_key), MAX_MESSAGE))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Ed25519 public key required")
        key.verify(base64.b64decode(signature["signature"], validate=True), DOMAIN + manifest_bytes)
        signature_status = "verified_against_supplied_key"
    results = decode(raw["results.json"], MAX_ARTIFACT)
    if manifest["kind"] == "local-lab":
        events = [decode(line) for line in raw["events.jsonl"].splitlines()]
        summary = replay_lab(results["findings"], events)
        if summary != results["summary"]:
            raise ValueError("summary does not replay")
        if decode(raw["chunk-index.json"], MAX_ARTIFACT) != chunk_index(events):
            raise ValueError("chunk byte ranges do not replay")
        if decode(raw["authority.json"], MAX_ARTIFACT) != authority_graph(results["findings"]):
            raise ValueError("authority graph does not replay")
        projection = afr_projection(events, results["run_id"])
        if raw["afr-events.jsonl"] != jsonl(projection):
            raise ValueError("AFR projection does not replay")
        protocol = [e["details"] for e in events if e["kind"] == "mcp.exchange"]
        if raw["protocol.jsonl"] != jsonl(protocol):
            raise ValueError("protocol export does not replay")
        from .report import render_lab, markdown_lab
        if raw["report.html"] != render_lab(results).encode() or raw["summary.md"] != markdown_lab(results).encode():
            raise ValueError("presentation does not replay from recorded results")
    else:
        from .entra import summarize_observations, validate_plan
        plan = decode(raw["entra-plan.json"])
        validate_plan(plan, allow_expired=True)
        observations = [decode(line) for line in raw["observations.jsonl"].splitlines()]
        validate_chain(observations)
        if results["summary"] != summarize_observations(observations):
            raise ValueError("cloud observations do not replay")
        if results["approved_plan_sha256"] != digest(canonical(plan)):
            raise ValueError("cloud plan digest mismatch")
        from .report import render_entra
        if raw["report.html"] != render_entra(results).encode():
            raise ValueError("cloud presentation does not replay")
    return {"artifacts_verified": len(entries), "manifest_sha256": digest(manifest_bytes),
            "signature": signature_status, "pinned_manifest": bool(expected_manifest),
            "recorded_results_replayed": True, "source_authenticity": "not established by bundle integrity"}
