#!/usr/bin/env python3
"""Validate every ready lab candidate, or say there is nothing to validate.

CI calls this. It is deliberately a thin loop over the same `lab validate`
command a human runs; a candidate that cannot pass tier 1 here is not one the
lab should be recommending.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIER = os.environ.get("LAB_TIER", "1")
BASELINE = "reports/baseline.json"


def main() -> int:
    candidates = sorted((ROOT / "reports" / "candidates").glob("*.json"))
    ready = []
    for path in candidates:
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            print(f"skip unreadable candidate: {path}")
            continue
        if doc.get("status") == "ready":
            ready.append(path)
    if not ready:
        print("no ready candidates")
        return 0

    failed = False
    for path in ready:
        argv = [
            sys.executable, "-m", "lab.cli", "validate",
            "--candidate", str(path), "--tier", TIER, "--execute",
        ]
        if (ROOT / BASELINE).is_file():
            argv += ["--baseline", BASELINE]
        print("validate", path.name, "tier", TIER)
        failed |= subprocess.run(argv, cwd=ROOT, check=False).returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
