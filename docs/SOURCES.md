# Sources and attribution

These references inform the research implementation; none endorses or certifies
TraceBound. Official documentation was reviewed on September 8, 2026.

| Reference | Use |
|---|---|
| [MCP 2025-06-18 lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle) | Pinned initialization and stdio lifecycle |
| [MCP 2025-06-18 tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | Tool discovery, calls, result and error envelopes |
| [Microsoft Entra emergency revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) | Access-token and application-session distinctions |
| [Microsoft Graph revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) | Administrative operation semantics and possible delay; not called by TraceBound |
| [AI Forensic Readiness](https://github.com/Scoston/ai-forensic-readiness) | Investigation model and reference event envelope |
| [OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Broader agentic-security context; no certification mapping claimed |

## Pinned schema

Source: [ai-investigation-event.schema.json](https://raw.githubusercontent.com/Scoston/ai-forensic-readiness/main/schemas/ai-investigation-event.schema.json)

Retained path: `schemas/upstream/ai-investigation-event.schema.json`  
Envelope version: `0.1.0-draft`  
Retained bytes SHA-256: `e4fba2610f9de797122cbb9b183680725f5beb461214c0d93ee2aa041e1ccc4a`

The source URL is mutable; the included bytes and digest identify the snapshot
used by this release. This is not a claim to implement every later v0.2 field or
all AIRG semantics. The schema is included under its Apache-2.0 code license.
