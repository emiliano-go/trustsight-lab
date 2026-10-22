"""Adjudicated FP reports, the only hard precision labels in the project.

The markdown report is for a human; ``triage.json`` beside it is the
machine-readable record and is preferred. Each adjudicated *finding* becomes
one row. ``TP-but-benign`` is a real finding on a benign practice and is kept
in a separate class: it must never be used as a negative for a rule that is
supposed to keep firing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

MARKDOWN_ROW = re.compile(
    r"^\|\s*(?P<rule>[A-Z]\d{3}|NOVELTY|SOURCE_BUCKET|COVERAGE)\s*\|"
)


def _rows_from_triage(path: Path) -> list[dict]:
    doc = json.loads(path.read_text())
    if doc.get("schema_version") != 1 or not isinstance(doc.get("entries"), list):
        raise ValueError(f"unsupported triage schema: {path}")
    day = path.parent.name
    rows: list[dict] = []
    for entry in doc["entries"]:
        evidence = entry.get("evidence") or {}
        findings = {
            int(f.get("index", -1)): f
            for f in (evidence.get("findings") or [])
            if isinstance(f, dict)
        }
        verdicts = (entry.get("verdicts") or {}).get("findings") or []
        for verdict in verdicts:
            index = int(verdict.get("index", -1))
            finding = findings.get(index, {})
            label = str(verdict.get("verdict", "")).strip()
            if label not in ("FP", "TP-but-benign", "TP"):
                continue
            confidence = verdict.get("confidence")
            rows.append(
                {
                    "source": "triage.json",
                    "day": day,
                    "alert_slug": entry.get("alert_slug", ""),
                    "package": entry.get("package", ""),
                    "report_path": entry.get("report_path", ""),
                    "corpus_paths": list(entry.get("corpus_paths") or []),
                    "score": evidence.get("score"),
                    "config_fingerprint": evidence.get("config_fingerprint"),
                    "aur_files": list(evidence.get("aur_files") or []),
                    "rule_id": verdict.get("rule_id") or finding.get("rule_id", ""),
                    "index": index,
                    "severity": finding.get("severity", ""),
                    "weight": finding.get("weight"),
                    "reason": finding.get("reason", ""),
                    "file": finding.get("file", ""),
                    "line": finding.get("line"),
                    "checks": finding.get("checks") or {},
                    "verdict": label,
                    "confidence": confidence,
                    "root_cause": verdict.get("root_cause", ""),
                    "suggested_fix": verdict.get("suggested_fix", ""),
                }
            )
    return rows


def _rows_from_markdown(path: Path) -> list[dict]:
    """Fallback for reports with no triage.json; evidence stays empty."""

    rows: list[dict] = []
    package = ""
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("# FP Triage: "):
            package = line[len("# FP Triage: "):].strip()
            continue
        match = MARKDOWN_ROW.match(line)
        if not match:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        verdict, _, confidence = cells[3].partition(" (")
        verdict = verdict.strip()
        if verdict not in ("FP", "TP-but-benign", "TP"):
            continue
        try:
            confidence_value = float(confidence.rstrip(")"))
        except ValueError:
            confidence_value = None
        rows.append(
            {
                "source": "markdown",
                "day": path.parent.name,
                "alert_slug": "",
                "package": package,
                "report_path": path.name,
                "corpus_paths": [],
                "score": None,
                "aur_files": [],
                "rule_id": cells[0],
                "index": None,
                "severity": "",
                "weight": None,
                "reason": cells[1],
                "file": "",
                "line": None,
                "checks": {},
                "verdict": verdict,
                "confidence": confidence_value,
                "root_cause": "",
                "suggested_fix": "",
            }
        )
    return rows


def load_reports(harness_root: Path) -> list[dict]:
    """Every adjudicated finding under ``benign/fp-*``.

    A ``triage.json`` describes all entries in its directory, so sibling
    markdown reports are not parsed again. Directories without one fall back
    to the markdown table.
    """

    rows: list[dict] = []
    for directory in sorted((harness_root / "benign").glob("fp-*")):
        triage = directory / "triage.json"
        if triage.is_file():
            rows.extend(_rows_from_triage(triage))
            continue
        for report in sorted(directory.glob("*-fp-report.md")) or sorted(
            directory.glob("*.md")
        ):
            rows.extend(_rows_from_markdown(report))
    return rows


def write_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
