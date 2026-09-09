# Scenario methodology

TraceBound's agent follows a fixed bounded plan. A language model does not
decide which tools to call. The lab evaluates authorization and observation
mechanisms, not model behavior or resistance to prompt injection.

For each scenario:

1. Launch fresh identity, resource, witness and MCP processes.
2. Issue three synthetic grants: primary agent, child agent, and queue worker.
3. Complete the MCP handshake and establish a successful ticket-operation baseline.
4. Change the initial authority boundary or exercise the recorded approval limit.
5. Probe the selected path and compare its receipt with independently read state.
6. Apply the scenario's specific remediation and retest the same access path.
7. Export and verify the evidence, derived findings, and report.

The initial configurations intentionally contain the failure being investigated.
The objective is to reproduce an exposure and its mitigation. The counts are
not estimates of real-world prevalence or detection accuracy.

## Special cases

The queue scenario submits two jobs before revocation. One is dequeued under
the initial policy and the other under the remediated policy. Both use the same
submitter, worker, operation and ticket. The experiment evaluates authorization
at execution; it does not measure a real queue product or asynchronous timing.

Approval replay begins with an approval that has already been consumed. The
weak policy records consumption but does not enforce it. The scope case uses an
approval for `TICKET-001` to request an increment of `TICKET-002`. The remediation
binds both the principal and exact action digest, and enforces single use.
`lab-reviewer` is a synthetic identity. No human-subject experiment is claimed.

## Outcomes

| Observation | Required evidence |
|---|---|
| `succeeded` | HTTP 200, success receipt, and independently read counter increment |
| `denied` | HTTP 403, denial receipt, and unchanged counter |
| `unknown` | Transport error, missing receipt, ambiguous status, or inconsistent observations |

An initial successful probe demonstrates a surviving path in the configured
experiment. A denied retest establishes that path's observed denial following
the intervention. Unseen credentials, different resources, future actions and
production systems remain untested.

Round-trip times and elapsed time after a command are measured using the local
monotonic clock. The resource policy is deliberately changed between initial
and remediated probes. Therefore these intervals must not be described as a
provider's natural revocation latency or token-expiration behavior.

## Independent reproduction

Record operating system, Python version, source commit, selected scenarios,
package versions, manifest digest, and any deviations. Verify the complete
bundle, inspect the resource receipts, and retain the original run separately.
Submit findings with synthetic data only unless disclosure is explicitly approved.
