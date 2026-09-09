"""Command line interface: bounded local tests, verified exports, Entra canary."""

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .common import canonical, decode, digest, private_write


def main(argv=None):
    from .lab import SCENARIOS, run_lab
    parser = argparse.ArgumentParser(prog="tracebound", description="Observe what can still execute after an authority boundary changes.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scenarios", help="list the six bounded experiments")
    demo = sub.add_parser("demo", help="run real local HTTP/MCP services against synthetic tickets")
    demo.add_argument("--output", required=True)
    demo.add_argument("--scenario", choices=list(SCENARIOS), action="append")
    demo.add_argument("--signing-key")
    verify = sub.add_parser("verify", help="verify bytes and replay recorded conclusions offline")
    verify.add_argument("bundle")
    verify.add_argument("--trusted-key")
    verify.add_argument("--expected-manifest-sha256")
    key = sub.add_parser("keygen", help="create a private Ed25519 signing key and separate public key")
    key.add_argument("--private", required=True)
    key.add_argument("--public", required=True)
    plan = sub.add_parser("entra-plan", help="prepare a read-only Entra canary plan for review")
    plan.add_argument("--tenant-id", required=True)
    plan.add_argument("--subject-id", required=True)
    plan.add_argument("--operator", required=True)
    plan.add_argument("--attempts", type=int, default=10)
    plan.add_argument("--interval", type=int, default=1)
    plan.add_argument("--output", required=True)
    entra = sub.add_parser("entra-observe", help="observe the reviewed Graph canary; never revokes access")
    entra.add_argument("--plan", required=True)
    entra.add_argument("--approve-plan-sha256", required=True)
    entra.add_argument("--output", required=True)
    entra.add_argument("--signing-key")
    args = parser.parse_args(argv)
    try:
        from . import evidence
        if args.command == "scenarios":
            result = SCENARIOS
        elif args.command == "demo":
            if os.path.lexists(args.output):
                raise ValueError("output already exists; choose a new path")
            findings, events, protocol = run_lab(args.scenario)
            result = evidence.save_lab(args.output, findings, events, protocol, args.signing_key)
            result["summary"] = evidence.lab_summary(findings)
            result["verification"] = evidence.verify(args.output)
        elif args.command == "verify":
            result = evidence.verify(args.bundle, args.trusted_key, args.expected_manifest_sha256)
        elif args.command == "keygen":
            evidence.keygen(args.private, args.public)
            result = {"created": True, "private_key": args.private, "public_key": args.public}
        elif args.command == "entra-plan":
            from .entra import make_plan
            plan = make_plan(args.tenant_id, args.subject_id, args.operator, args.attempts, args.interval)
            private_write(args.output, canonical(plan))
            result = {"plan": args.output, "review_digest": digest(canonical(plan))}
        else:
            from .entra import observe
            plan = decode(Path(args.plan).read_bytes())
            token = os.environ.get("TRACEBOUND_ENTRA_TOKEN", "")
            result = observe(plan, args.approve_plan_sha256, token, args.output, signing_key=args.signing_key)
        print(json.dumps(result, indent=2))
        return 0
    except KeyboardInterrupt:
        print("TraceBound interrupted. No complete bundle is claimed.", file=sys.stderr)
        return 130
    except Exception as error:
        # Exception strings from transports/crypto may contain sensitive material.
        safe = str(error) if type(error) is ValueError else type(error).__name__
        print("TraceBound stopped: " + safe, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
