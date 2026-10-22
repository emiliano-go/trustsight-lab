"""Scan the locked benign corpus for the ranker's negative class.

The scan runs in the pinned TrustSight interpreter with the shipped config
and an isolated temporary database, through the same ``scan_corpus`` the
calibration gates use. A finding on a benign diff is a candidate benign
false positive, never an automatic negative: it stays a separate label.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

SCRIPT = r'''
import json
import sys
from pathlib import Path

from scripts.calibration._core import scan_corpus, shipped_config

corpus = Path(sys.argv[1])
sample = int(sys.argv[2])
with shipped_config():
    rows = scan_corpus(corpus, sample=sample, jobs=1)
print(json.dumps(rows, default=str))
'''


def scan(
    trustsight_root: Path,
    corpus: Path,
    sample: int = 20,
    python: Path | None = None,
) -> list[dict]:
    """Return the raw ``scan_corpus`` rows, or raise on a bad run."""

    python = python or trustsight_root / ".venv" / "bin" / "python"
    if not python.is_file():
        raise RuntimeError("the pinned TrustSight venv is not present")
    completed = subprocess.run(
        [str(python), "-c", SCRIPT, str(corpus), str(max(1, sample))],
        cwd=trustsight_root,
        env={"PYTHONPATH": str(trustsight_root / "src"), "PATH": "/usr/bin:/bin"},
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-2000:])
    return json.loads(completed.stdout)


def flatten(results: list[dict]) -> list[dict]:
    """Flatten scoring findings on benign diffs into label rows."""

    rows = []
    for result in results:
        for entry in result.get("entries") or []:
            if entry.get("rule_id") == "COVERAGE":
                continue
            rows.append(
                {
                    "label": "candidate_benign",
                    "package": result.get("package", ""),
                    "path": result.get("path", ""),
                    "final_score": result.get("score"),
                    "rule_id": entry.get("rule_id", ""),
                    "severity": entry.get("severity", ""),
                    "weight": entry.get("weight"),
                    "params": entry.get("params") or {},
                    "checks": {},
                }
            )
    return rows


def findings(trustsight_root: Path, corpus: Path, sample: int = 20) -> list[dict]:
    return flatten(scan(trustsight_root, corpus, sample=sample))
