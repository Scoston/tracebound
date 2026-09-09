# Microsoft Entra canary observation

This adapter is implemented and tested against offline transport fixtures.
**A live Microsoft tenant was not used for release validation.**

The fixed request is `GET https://graph.microsoft.com/v1.0/me?$select=id`.
It exercises a delegated Graph access token against one endpoint. It does not
test token refresh, app-owned cookies, service principals, child-agent grants,
MCP authorization, or the entire Microsoft 365 estate.

## Prepare a reviewed test

Use a dedicated test tenant and subject. Obtain a delegated Graph token through
your organization's approved authentication tooling. The credential must have
permission to read the signed-in user's basic profile, such as `User.Read`.
Use a separate authorized administrative session for revocation. Do not paste
tokens into chat, documentation, or public issues.

From the project directory in PowerShell:

```powershell
py -3 -m tracebound entra-plan `
  --tenant-id "YOUR-TENANT-UUID" `
  --subject-id "YOUR-TEST-USER-OBJECT-UUID" `
  --operator "YOUR-OPERATOR-LABEL" `
  --attempts 10 --interval 1 `
  --output ..\tracebound-entra-plan.json

Get-Content ..\tracebound-entra-plan.json
```

Review the exact target, subject, tenant, request count and timing. The command
prints the canonical plan SHA-256. Plans expire after 24 hours. Changing a field
invalidates the previously reviewed digest.

Load the token without echoing it:

```powershell
$secureToken = Read-Host "Delegated Graph test token" -AsSecureString
$tokenCredential = [System.Net.NetworkCredential]::new("", $secureToken)
$env:TRACEBOUND_ENTRA_TOKEN = $tokenCredential.Password
try {
  py -3 -m tracebound entra-observe `
    --plan ..\tracebound-entra-plan.json `
    --approve-plan-sha256 "PRINTED-REVIEW-DIGEST" `
    --output ..\tracebound-entra-observation
} finally {
  Remove-Item Env:\TRACEBOUND_ENTRA_TOKEN -ErrorAction SilentlyContinue
  $tokenCredential = $null
  $secureToken = $null
}
```

The adapter first requires a successful `/me` response with the expected user
object ID. It also rejects locally inspected token claims that do not match the
reviewed tenant, subject and Graph audience. Those decoded claims are **not
locally signature-verified**; they are only an input-rejection check. Graph
validates the presented credential.

After the baseline succeeds, perform the intended revocation in the separate
administrative session. Press Enter at the adapter prompt immediately afterward.
This creates a local operator marker and begins repeated observations using the
same token. No refresh or retry with a different credential occurs. The adapter
never invokes `revokeSignInSessions` or disables an account itself.

## Interpret the result

- 200 with the expected subject: that request was allowed.
- 401 or 403: that request was denied; the adapter does not establish why.
- 429, 5xx, redirects, network errors, or an unexpected response: unknown.
- Success after a denial remains visible; the tool does not stop at the first denial.

The report can describe the interval between the last observed success (or
operator marker) and first observed denial. This is not proof of the time when
the provider applied revocation. An expired token, permission change, conditional
access policy, or another cause may produce a denial.

The post-marker loop starts requests for at most 120 seconds; the final in-flight
request may take up to its ten-second transport timeout. The plan also bounds
request count and spacing. Waiting for the operator is deliberately separate.

Response bodies are minimized to the subject-match flag, status and response
digest. Raw bodies are not retained. The original token is not written; its hash
binds repeated observations. Protect the plan and exported identifiers as live
environment metadata. Keep them outside the repository.

Microsoft documents token/session distinctions and possible revocation delays:
[emergency revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)
and [revokeSignInSessions API](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0).
