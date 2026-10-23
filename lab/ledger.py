"""Link every candidate to the measurement that can retire it.

A candidate is useful only if its effect is visible somewhere the gate
already reads: the archive matrix, the attributed regression report, and the
coverage count.  This module joins those three to the candidate queue and
assigns an outcome, so a merged fix is not left looking pending forever.

Outcomes:

- ``backlog``: no patch, or no tier-0 fixture. Not a claim yet.
- ``pending``: the patch still applies and the rule has not hardened.
- ``landed``: the rule's matrix cell is hardened.
- ``stale``: the patch no longer applies and the rule did not harden. It was
  merged and reverted, superseded by a different change, or written against
  a tree that moved. A human has to say which; the ledger refuses to guess.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .pins import read_pins

LEDGER = "ledger.json"


def _load(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _matrix(root: Path) -> dict[str, dict]:
    doc = _load(root / "trustsight-harness" / "regression" / "matrix.json", {})
    return {row.get("rule"): row for row in doc.get("rules") or []}


def _coverage(root: Path) -> set[str]:
    doc = _load(root / "trustsight-harness" / "coverage" / "report.json", {})
    return set((doc.get("rules") or {}).get("untargeted_ids") or [])


def _regression(root: Path) -> dict[str, dict]:
    doc = _load(root / "trustsight-harness" / "regression" / "report.json", {})
    summary: dict[str, dict] = {}
    for row in doc.get("bypasses") or []:
        for rule in row.get("expected_rules") or ():
            bucket = summary.setdefault(rule, {"open": 0, "closed": 0})
            bucket["open" if row.get("state") == "open" else "closed"] += 1
    return summary


def _tier0(rule_id: str, predicate: str) -> str | None:
    from .validate import fixtures

    case = fixtures.case_for(rule_id, predicate)
    return case.name if case else None


def _applies(patch: str, trustsight_root: Path) -> bool:
    import subprocess

    if not patch:
        return False
    completed = subprocess.run(
        ["git", "-C", str(trustsight_root), "apply", "--check",
         "--whitespace=nowarn", "-"],
        input=patch,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


def _outcome(doc: dict, matrix: dict, applies: bool) -> str:
    if doc.get("rejected"):
        return "rejected"
    if doc.get("superseded_by"):
        return "superseded"
    if doc.get("status") != "ready":
        return "backlog"
    if matrix.get("hardened"):
        return "landed"
    if applies:
        return "pending"
    return "stale"


def _validation(directory: Path, candidate_id: str) -> dict | None:
    doc = _load(directory / f"{candidate_id}.json", {})
    if not doc:
        return None
    benign = (doc.get("verdict") or {}).get("benign") or {}
    return {
        "tier": doc.get("tier"),
        "passed": doc.get("passed"),
        "benign_flag_rate": benign.get("estimate"),
        "benign_flagged": benign.get("flagged"),
        "failures": (doc.get("verdict") or {}).get("failures") or [],
    }


def build(
    root: Path,
    *,
    candidates: Path = Path("reports/candidates"),
    validation: Path = Path("reports/validation"),
) -> dict:
    matrix = _matrix(root)
    regression = _regression(root)
    untargeted = _coverage(root)
    rows = []
    if candidates.is_dir():
        for path in sorted(candidates.glob("*.json")):
            doc = _load(path, {})
            rule = doc.get("rule_id", "")
            applies = _applies(doc.get("patch") or "", root / "trustsight")
            cell = matrix.get(rule) or {}
            rows.append({
                "id": doc.get("id", path.stem),
                "rule_id": rule,
                "predicate": doc.get("predicate", ""),
                "status": doc.get("status", ""),
                "tier0_fixture": _tier0(rule, doc.get("predicate", "")),
                "patch_applies": applies,
                "matrix": {
                    "state": cell.get("state", ""),
                    "hardened": bool(cell.get("hardened")),
                },
                "regression": regression.get(rule, {"open": 0, "closed": 0}),
                "coverage_targeted": rule not in untargeted if rule else False,
                "validation": _validation(validation, doc.get("id", path.stem)),
                "outcome": _outcome(doc, cell, applies),
            })
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "pins": read_pins(root).to_dict(),
        "candidates": rows,
        "counts": {
            outcome: sum(1 for row in rows if row["outcome"] == outcome)
            for outcome in ("backlog", "pending", "landed", "stale",
                            "rejected", "superseded")
        },
    }


def write(doc: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return path
