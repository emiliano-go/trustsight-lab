"""Assemble the label set.

Two label families are kept strictly apart:

- ``hard_fp``: adjudicated, provable malicious false positives. This is the
  precision target, 29 findings at confidence 0.9 or higher, 31 overall.
- ``tp_benign``: a real finding on a benign practice. It stays in the report
  and must keep firing. Treating it as a negative is how a lab learns to
  suppress genuine evidence.

Malicious fixtures and harness bypasses are the recall side; IOC entries are
confirmed indicators, not diff-level labels.
"""

from __future__ import annotations

from pathlib import Path

from ..ingest import corpora, reports

CLASSES = ("hard_fp", "tp_benign", "tp", "bypass", "candidate_benign", "benign")


def merge_weak(rows: list[dict], path) -> list[dict]:
    """Append contradiction rows from *path* as ``weak_fp`` labels.

    One path in, one path out. The refresh caller passes the file it just
    built, not a default that may belong to an older sample.
    """

    import json
    from pathlib import Path as _Path

    source = _Path(path)
    if not source.is_file():
        return rows
    for line in source.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("contradiction"):
            rows.append({**row, "label": "weak_fp"})
    return rows


def merge_findings(rows: list[dict], path) -> list[dict]:
    """Append real-finding labels: contradictions are weak FPs, signals are
    real findings that must keep firing."""

    import json
    from pathlib import Path as _Path

    source = _Path(path)
    if not source.is_file():
        return rows
    for line in source.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("contradiction"):
            rows.append({**row, "label": "weak_fp"})
            continue
        signal = row.get("signal") or {}
        if signal.get("label") in ("hard_fp", "tp_benign", "tp"):
            rows.append({**row, "label": signal["label"]})
    return rows


def report_labels(harness_root: Path) -> list[dict]:
    rows = []
    for report in reports.load_reports(harness_root):
        label = {"FP": "hard_fp", "TP-but-benign": "tp_benign", "TP": "tp"}.get(
            report["verdict"]
        )
        if label is None:
            continue
        if label == "hard_fp" and (report.get("confidence") or 0) < 0.9:
            continue
        row = {**report, "label": label}
        if label == "hard_fp":
            # A hard FP is only actionable when its bytes can be re-scored.
            # Keep the row either way, but make the gap countable instead of
            # letting an unbacked label into the precision target.
            row["reproducer_present"] = bool(report.get("corpus_paths"))
        rows.append(row)
    return rows


def build(trustsight_root: Path, harness_root: Path) -> list[dict]:
    rows = report_labels(harness_root)
    for row in corpora.malicious_fixtures(trustsight_root):
        rows.append(row)
    for row in corpora.bypass_fixtures(harness_root):
        rows.append(row)
    return rows


def counts(rows: list[dict]) -> dict[str, int]:
    tally = {name: 0 for name in CLASSES}
    for row in rows:
        tally[row["label"]] = tally.get(row["label"], 0) + 1
    return tally


def audit(rows: list[dict]) -> dict:
    """How much of the precision target can actually be re-measured."""

    hard = [row for row in rows if row.get("label") == "hard_fp"]
    return {
        "hard_fp": len(hard),
        "missing_reproducer": sorted(
            row.get("package", row.get("report_path", ""))
            for row in hard if not row.get("reproducer_present")
        ),
        "missing_fingerprint": sorted(
            row.get("package", row.get("report_path", ""))
            for row in hard if not row.get("config_fingerprint")
        ),
    }
