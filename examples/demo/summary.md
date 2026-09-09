# TraceBound containment report

Mode: running local services with synthetic principals and tickets.

6 scenarios; 18 probes; 6 surviving paths observed; 6 paths denied after remediation.

| Scenario | Initial observation | Remediated observation | Owner |
|---|---|---|---|
| Cached access token | succeeded | denied | Identity and application owners |
| Application-owned session | succeeded | denied | Application owner |
| Child-agent authority | succeeded | denied | Agent platform owner |
| Queued work | succeeded | denied | Workflow owner |
| Reused approval | succeeded | denied | Approval service owner |
| Changed action scope | succeeded | denied | Approval service owner |

## Findings

### Cached access token

The resource accepts a cached grant after identity revocation.

Remediation: Check current grant status at the resource boundary.

Initial resource receipt: `sha256:4aaf07e8bd56819c7bbee7570dba628dc81dbba588bd2db91dcb3f7d3f7a23c9`

Retest resource receipt: `sha256:2789de5f672f9d27b8a69035294118a948044a3e41cc3df2fdae2930e516ed07`

### Application-owned session

An application session survives revocation at the identity service.

Remediation: Invalidate application sessions associated with the principal.

Initial resource receipt: `sha256:25a5c172cc0fa82e204dedeb24d31d4c3f181a3be52dcf04311ca5d0842c5289`

Retest resource receipt: `sha256:e0ff73f49378bfd3c78e56b32d3788dace31ae8839fbe92bc5c70b014ab5d728`

### Child-agent authority

A child agent retains its separately issued grant.

Remediation: Revoke descendant grants and validate them at execution.

Initial resource receipt: `sha256:e83c582fef885bce556fee134d474e0b3a40023e65292c0f83310e90c20d15f0`

Retest resource receipt: `sha256:e5a2a67734cb35ed6263e0fd46a97bdba072d96dc1ba01d1f1372893bc254426`

### Queued work

Queued work executes through a service identity after the submitter loses access.

Remediation: Recheck both the submitter and worker authority when dequeuing.

Initial resource receipt: `sha256:aae8aed8625324e65f089e73a6f04c075db5d07fd2f0c0fcb1d943654800935e`

Retest resource receipt: `sha256:d148e82b1d30f6c84384095221d88cb7d3123dc7992126af988200e2168fc5e9`

### Reused approval

A recorded single-use approval is accepted again.

Remediation: Enforce single-use approval consumption at the action boundary.

Initial resource receipt: `sha256:eb966c21c7bfba920761dc9e84ac055de88d8a3964f13f95d9eadcdd3e179c4c`

Retest resource receipt: `sha256:5365b291fee8da845532390a1393a788e9d349f8ed80e61da4b907038ef2e10a`

### Changed action scope

An approval for one ticket is applied to a different ticket.

Remediation: Bind approval to the principal and exact operation arguments.

Initial resource receipt: `sha256:772277c218d726ffbd63ee328571f66fbce3134ccdf05fdbac59627e89bb7bc5`

Retest resource receipt: `sha256:738d2f14cbb56461ac567c4b9270616fee24e9986e54042ca4988acec0ca2907`

## Limits

- Synthetic tickets and principals; real local HTTP/MCP execution.
- Scripted agent; no language model or provider was invoked.
- All local services share an OS account; witness isolation is process-level only.
- A denied probe applies only to the tested path and observation window.
- Human reviewer identities are synthetic; effective human judgment was not measured.
- Time values are local monotonic observations, not trusted timestamps.

Timing measures controller observation intervals around explicit interventions. It is not a natural token-expiration benchmark.

Verify the manifest and recorded-result replay. Pin the manifest digest or signing key independently.
