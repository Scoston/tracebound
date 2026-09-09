# Security and operational limits

TraceBound v0.1.0 is a research/reference implementation. Run it under an
unprivileged account in an isolated lab. All default HTTP listeners bind to the
literal IPv4 loopback address and ephemeral ports. The fixed MCP server exposes
only synthetic ticket increments and queue submission. It cannot run arbitrary
commands, select arbitrary URLs, or mutate production resources.

## Credentials and evidence

Local bearer credentials are generated for each experiment. Each subprocess
receives only the role-specific configuration it needs; ambient cloud secrets
are not inherited. Agent credentials cannot administer services or append to the
witness. Request logs retain credential identifiers and exact credential-free
MCP arguments/results; they do not retain bearer values.

Local files are created exclusively with mode 0600 and directories with mode
0700 where supported. Windows ACLs must be configured by the operator; POSIX
modes are not a substitute for Windows access control. Signing keys must remain
outside evidence directories. Protect keys separately and distribute verifier
trust anchors through an independent channel.

The Entra adapter reads `TRACEBOUND_ENTRA_TOKEN` from the process environment and
sends it only to the fixed HTTPS Graph endpoint. It never logs the credential,
refreshes it, follows redirects, or invokes administrative revocation APIs.
The token hash is retained to bind the observations to the same credential.
Tenant, subject, and operator identifiers in a live plan can be sensitive.
Keep live plans and evidence outside the public repository.

## Trust and availability

The local services share an OS account. A process with sufficient local access
can inspect credentials or alter memory/files. Process separation does not
provide an adversary-resistant sandbox, WORM storage, trustworthy time, or an
independent witness operator. Do not use the lab as a production enforcement
service. Opaque cached grants model cached authority; they do not reproduce
Microsoft token-signature validation, CAE, or all provider semantics.

Evidence and resource state are in memory until export. A crash can prevent a
complete bundle. The witness writes an evaluation before each resource action,
then its outcome afterward; this is not a distributed atomic commit. If an
outcome cannot be corroborated, it is unknown. If the witness or state snapshot
is unavailable, export may stop rather than claim a complete result.

The reference HTTP server is sequential and intended for bounded local tests.
Use of Python's standard-library HTTP server is not a production serving claim.
Limits include 128 KiB messages, 500 witness events per scenario, 20 MCP calls,
30 local credentials, 20 queued jobs, and five-minute lab credential lifetimes.
Do not expose its listeners to untrusted clients.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if enabled on the repository. Do not
put credentials, production evidence, or personal information in public issues.
If private reporting is unavailable, first request a private contact method in
a public issue without including vulnerability details.
