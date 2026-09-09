# Validation record

Release: **TraceBound 0.1.0 research implementation**.

The machine-readable local test record is saved beside this document as
`validation.json`. It names the actual Python version, operating system,
dependency versions, test count, failures, errors and skips.

## Executed checks

- Complete six-scenario local run: 18 probes, six observed initial surviving
  paths, and six observed denied retests, with no unknown outcomes in that run.
- Full Python test suite covering actual loopback HTTP/MCP processes, current
  grant checking, sessions, child grants, queue execution, single-use approvals,
  approval scope binding, and concurrent approval consumption.
- Evidence byte tampering, report substitution, false summaries, changed chunk
  offsets, tail loss, path traversal, unexpected files, symlinks and wrong
  signing keys.
- Independent public-key verification of the signed synthetic example.
- Identity-service failure retained as unknown, with a verifiable output bundle.
- Entra transport fixtures covering successful and failed baselines, 401/403,
  429, 5xx, redirects, network failures, success after denial, changed plan,
  wrong subject/tenant and credential minimization.
- AFR projection validated using `jsonschema` against the exact included
  upstream Draft 2020-12 schema.
- HTML structure, embedded-script syntax, local export links, and deterministic
  rendering verified. The cloud browser blocked local-file navigation; no visual
  browser QA result is claimed.
- Wheel build and installed-package CLI smoke check, including a running-service
  scenario and offline verification.

## Not yet executed

- Live Microsoft Entra, Microsoft 365, or any other cloud-tenant test.
- GitHub Actions on Ubuntu and Windows; the workflow is configured for Python
  3.11 and 3.12 and becomes runnable after repository upload.
- Independent external reproduction, a model-driven agent evaluation, production
  deployment testing, or enterprise-scale throughput measurements.

Run the same checks from the source directory:

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate.py --report output/local-validation.json
python -m tracebound verify examples/demo --trusted-key examples/demo-public.pem
```

For a fresh case, use a new output directory. Do not replace the committed
example with live tenant evidence.
