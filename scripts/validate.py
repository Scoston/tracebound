"""Run the full release tests and optionally retain a machine-readable result."""

import argparse
import importlib.metadata
import json
import os
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    args = parser.parse_args()
    packages = {name: importlib.metadata.version(name) for name in ("cryptography", "jsonschema")}
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"recorded_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
        "platform": platform.platform(), "packages": packages, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "passed": result.wasSuccessful(), "live_entra_validated": False}
    text = json.dumps(report, indent=2) + "\n"
    if args.report:
        from tracebound.common import private_write
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        private_write(target, text)
    print(text)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
