# Evidence semantics and verification

## Files

| Artifact | Meaning |
|---|---|
| `events.jsonl` | Witness event envelopes, grouped by scenario |
| `chunk-index.json` | Chunk identifier, JSONL byte offset/length, and exact span digest |
| `protocol.jsonl` | Credential-free MCP request/response exchanges |
| `results.json` | Probe observations and scoped derived findings |
| `authority.json` | Declared lab grants plus evidence-linked observed actions |
| `afr-events.jsonl` | Loss-disclosed projection to the pinned AFR event envelope |
| `report.html` | Offline filterable report, regenerated during verification |
| `summary.md` | Readable executive findings, regenerated during verification |
| `manifest.json` | Exact SHA-256 and byte count for every payload artifact |
| `signature.json` | Optional detached Ed25519 signature envelope |

The Entra bundle instead contains the reviewed plan, observation ledger,
structured results, HTML report and Markdown summary. Its observations come from
the local HTTPS client, not from the separate local-lab witness.

## Chunk and chain identity

The TraceBound JSON profile is UTF-8 with sorted object keys, no whitespace
separators, Unicode retained, and non-finite numbers rejected. This profile is
not advertised as RFC 8785 canonicalization. Duplicate JSON keys are rejected
when reading evidence.

An event's `sha256` hashes its canonical body excluding `sha256` and `chunk_id`.
`chunk_id` is `sha256:` followed by that digest. Each event includes the previous
event's digest. The first event in each fresh scenario has sequence 0 and a
64-zero previous digest. Each scenario is a separate chain.

The index locates the full serialized envelope, including its newline, in
`events.jsonl`. `span_sha256` hashes those exact located bytes. The body digest
and full-envelope span digest intentionally have different subjects.

## What verification establishes

`verify` checks the complete expected artifact inventory and rejects unexpected
paths, symlinks, missing files, added files, altered bytes, duplicate event keys,
broken chains and result projections that cannot be reconstructed. For a
confirmed probe, the verifier requires a resource receipt and snapshots ordered
before and after it in the same scenario. A success requires a successful HTTP
observation and an increment of exactly one; a denial requires a denied HTTP
observation and no state increment. Missing receipts can support only unknown.

The verifier compares the report rendering against retained results. Changing a
report and recomputing its file hash is insufficient if it no longer reproduces
the recorded result presentation.

## Trust anchors

Hash verification alone can detect changes against a retained manifest, but an
attacker who replaces the whole bundle and manifest may create a new internally
consistent history. Pin the manifest digest separately:

```bash
python -m tracebound verify output/run --expected-manifest-sha256 YOUR_RETAINED_SHA256
```

Alternatively sign the manifest and supply a public key from an independent
trusted channel. Signatures cover the bytes `TraceBound manifest v1` followed by
a NUL byte and the exact manifest bytes. A self-supplied key inside the bundle
is not accepted. Verification reports signature absence, unauthenticated
presence, and success against the supplied key separately.

Hashes, signatures, and replay do not prove source authenticity, complete
collection, truthful observations, reliable clocks, legal admissibility,
effective human judgment, or production containment. The public key distributed
with the sample demonstrates the API; it is not independent external attestation.

## Interoperability

The AFR projection uses the repository's pinned `0.1.0-draft` envelope. It is
validated against that exact included schema. The original witness chunk is
retained in `influence.provenance_refs`; action receipts retain operation,
target, argument digest and outcome. Unsupported event kinds are omitted from
the projection, with emitted and omitted counts recorded in `results.json`.
They remain present in `events.jsonl`. Grant/session/control context is richer
in the source than in the projection. A projection match does not mean full
v0.2 semantic conformance or direct import support in every related tool.
