# Architecture

The CLI launches fresh services for each scenario. It never connects the default
lab to cloud infrastructure or a language-model provider.

| Component | Interface | Authority | Evidence |
|---|---|---|---|
| Controller / scripted agent | Python CLI and MCP client | Prepare the local experiment and administer its synthetic services | Instructions, MCP requests/results, probes and boundary markers |
| MCP tool server | Pinned 2025-06-18 stdio subset | Agent, child or app-session credentials for fixed ticket operations | Exact credential-free application messages |
| Identity service | Authenticated loopback HTTP | Issue/inspect/revoke synthetic grants | Grant creation and revocation receipts |
| Ticket resource | Authenticated loopback HTTP | Enforce grants, sessions, approval rules and queue execution | Evaluation, mutation/denial receipts and separately read state |
| Witness | Authenticated loopback HTTP | Accept source-specific append requests; controller may read | Per-scenario sequential SHA-256 chains |

The controller holds administrative keys. Those keys are not passed to the MCP
server. The resource has a separate identity-inspection credential. The witness
derives the recorded source from the append credential, so the agent cannot
select an arbitrary source label. Different source credentials do not prove
different human custodians or separate administrative organizations.

The resource increments only `TICKET-001` or `TICKET-002`. It stores counters,
grants, sessions, queue entries, and approvals in process memory. The queue has
an explicit operator-controlled dequeue trigger, so the test establishes the
order of enqueue, revocation, and execution without relying on scheduling races.

## MCP boundary

Supported messages are `initialize`, `notifications/initialized`, `ping`,
`tools/list`, and `tools/call`. The client and server agree the pinned protocol
version before operations. The two tools are `update_ticket` and
`enqueue_ticket`. Both reject unsupported arguments and resource names.

This is a bounded protocol subset, not a full MCP SDK, general-purpose server,
provider authorization implementation, or external MCP conformance certification.
There is no sampling, model invocation, roots access, arbitrary command runner,
or dynamic tool discovery outside the bundled server.

## Evidence export

The controller retrieves the witness ledger after a scenario. A local verifier
checks event chaining, source and scenario references, event ordering, resource
receipts, state deltas, derived summaries, authority projections, and exact
rendered reports. The manifest inventories all eight payload artifacts. Optional
Ed25519 signing authenticates the exact manifest against a supplied public key.

## Entra adapter

The optional adapter uses a fixed Microsoft Graph `/me?$select=id` GET request.
It requires a reviewed plan digest and an existing delegated token in an
environment variable. It confirms a working baseline and expected subject,
waits for the operator's independent revocation marker, and observes subsequent
responses using the same token. It does not issue credentials or execute
administrative changes.
