# TraceBound roadmap

## Implemented in 0.1.0

- Six real local service experiments, each with baseline, initial control, and retest.
- Bounded scripted agent and pinned MCP stdio tools subset.
- Separate identity, ticket resource, and witness services.
- Evidence chains, chunk indexes, authority projections, optional signed manifests,
  and offline reconstruction of recorded results.
- Self-contained HTML and Markdown reports.
- Reviewed, read-only Entra/Graph canary adapter and offline contract tests.
- Pinned AI Forensic Readiness schema projection and validation workflow.

## Requires external evidence

1. Independent reproduction by security practitioners; publish results only with
   their authorization and clear environment/version details.
2. Entra test-tenant observations with provider audit events to establish the
   revocation boundary more strongly than the local operator marker.
3. Validate installation, subprocess handling, and file permissions on Windows
   through the configured GitHub Actions matrix.

## Subsequent engineering

- Authenticated revocation receipts and provider-specific access-token, refresh-
  token, and application-session probes.
- AWS role-session and queued workflow adapters in dedicated test environments.
- Durable independently administered witness storage and trusted timestamps.
- Explicitly scoped model-driven agents with transaction capture and token caps.
- Broader permission discovery with documented coverage and unknown paths.

None of these later capabilities is implied by the first release's test results.
