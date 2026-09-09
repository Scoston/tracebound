# TraceBound

**What can an AI agent still do after its authority changes?**

TraceBound runs bounded containment experiments, observes the actual resource
effects, and packages the evidence needed to review the result. It connects
delegated identity, incident response, approval enforcement, and forensic
reconstruction.

**v0.1.0 research release.** Six local scenarios use real HTTP services and an
MCP stdio tool server. Principals, credentials, tickets, and approvals are
synthetic. The agent is scripted: **zero model calls and zero model tokens**.
The included Entra adapter observes one real Graph endpoint only when an operator
supplies a reviewed plan and a test-tenant token. Live Entra validation has not
been performed for this release.

## Start in two commands

Python 3.11 or newer is required. From the extracted project directory:

```bash
python -m tracebound demo --output output/first-run
python -m tracebound verify output/first-run
```

Open `output/first-run/report.html` in your browser. The core lab has **no
third-party Python dependencies**. Every run needs a new output directory.

Windows PowerShell:

```powershell
py -3 -m tracebound demo --output output/first-run
py -3 -m tracebound verify output/first-run
Start-Process .\output\first-run\report.html
```

For an installed command, use `python -m pip install .`, then `tracebound`.

## What is tested

| Scenario | Initial behavior | Remediation exercised |
|---|---|---|
| Cached access token | Resource accepts cached authority after the identity grant is revoked | Revalidate current authority at the resource |
| Application session | App-owned session continues after primary identity revocation | Revoke the application's sessions |
| Child agent | Separately issued child grant remains active | Revoke descendant grants and enforce grant status |
| Queued work | Worker executes a job after the submitter loses access | Validate submitter and worker at execution |
| Approval replay | A consumed approval is accepted a second time | Enforce single-use consumption |
| Changed scope | Approval for one ticket is applied to another | Bind principal and exact action arguments |

Each scenario establishes a successful baseline, exercises the initial control,
applies the specific remediation, and retests. The bundled sample observed six
surviving paths and six denied retests across 18 probes. These are **controlled
lab results**, not measurements of Microsoft, AWS, or a production agent.

```bash
python -m tracebound scenarios
python -m tracebound demo --scenario queued_job --output output/queue-case
```

## Evidence you can inspect

- A separate witness process records identity, resource, controller, and MCP events.
- Resource receipts are checked against separately queried ticket-state snapshots.
- SHA-256 event chains, content chunk identifiers, and exact byte-range indexes
  bind each conclusion to retained records.
- Offline verification replays results, authority projections, exports, and report
  rendering. Unknown observations remain unknown.
- Optional Ed25519 signatures verify the manifest against an independently
  supplied public key. Private keys remain outside the bundle.
- An evidence-linked authority graph and a projection into the pinned
  [AI Forensic Readiness](https://github.com/Scoston/ai-forensic-readiness)
  `0.1.0-draft` event envelope support downstream investigation.
- A self-contained HTML report supports scenario filtering, evidence inspection,
  and printing. Markdown and JSON reports are included.

The witness runs under the same OS account as the lab. It is a separate process,
not an independently administered or tamper-proof audit system. See
[evidence semantics](docs/EVIDENCE.md).

## Signed evidence

```bash
python -m pip install '.[signing]'
python -m tracebound keygen --private ../tracebound-private.pem --public ../tracebound-public.pem
python -m tracebound demo --output output/signed-run --signing-key ../tracebound-private.pem
python -m tracebound verify output/signed-run --trusted-key ../tracebound-public.pem
```

PowerShell also accepts single quotes around `'.[signing]'`. Retain the printed
manifest SHA-256 or public key through a separate trusted channel. A key supplied
inside the evidence directory is rejected as a trust anchor. The public key
beside the committed sample is a **demonstration key**, not independent assurance.

## Entra observation adapter

The adapter makes bounded, read-only requests to a fixed Microsoft Graph `/me`
canary with the same existing delegated access token. The operator performs
revocation independently and marks the observation boundary. It records later
successes, denials, and unknown outcomes without claiming the cause of a denial.

Read [Entra setup and interpretation](docs/ENTRA.md) before using it. No credentials
are needed for the local demo, and the lab never contacts a cloud provider.

## Verification and documentation

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate.py
```

The release checks exercise actual local services, concurrent approval use,
negative authorization, dependency failure, evidence modification, signatures,
MCP lifecycle, Entra adapter contracts, and the pinned upstream event schema.
See the [validation record](docs/VALIDATION.md) for exactly what was executed.

| Resource | Purpose |
|---|---|
| [Example report](examples/demo/report.html) | Inspect a completed synthetic run; download or open locally |
| [Example summary](examples/demo/summary.md) | Read the same findings directly on GitHub |
| [Architecture](docs/ARCHITECTURE.md) | Process and trust boundaries |
| [Evidence semantics](docs/EVIDENCE.md) | Hashes, chunk IDs, signatures, and replay limits |
| [Entra guide](docs/ENTRA.md) | Reviewed live observation workflow |
| [Scenario methodology](docs/METHODOLOGY.md) | Assertions, interventions, and timing limits |
| [GitHub publishing](docs/PUBLISHING.md) | PowerShell creation and upload instructions |
| [Sources and attribution](docs/SOURCES.md) | Pinned protocol and reference schema |
| [Security](SECURITY.md) | Data handling and operational limitations |

## Scope and next validation work

This release supplies a reference lab and a read-only cloud observation adapter.
It does not discover every enterprise permission, enforce production containment,
evaluate stochastic model behavior, or certify effective human judgment.

The next validation step is an independently reproduced lab run followed by an
authorized Entra test-tenant run. Additional provider adapters should preserve the
same evidence and uncertainty requirements. See [ROADMAP.md](ROADMAP.md).

Copyright 2026 Stephen Coston. Apache License 2.0. See [NOTICE](NOTICE).
