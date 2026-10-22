"""Assemble the label set.

Two label families are kept strictly apart:

- ``hard_fp``: adjudicated, provable malicious false positives. This is the
  precision target, 31 findings at the time of writing.
- ``tp_benign``: a real finding on a benign practice. It stays in the report
  and must keep firing. Treating it as a negative is how a lab learns to
  suppress genuine evidence.

Malicious fixtures and harness bypasses are the recall side; IOC entries are
confirmed indicators, not diff-level labels.
"""

from __future__ import annotations

from pathlib import Path

from ..ingest import corpora, reports

CLASSES = ("hard_fp", "tp_benign", "tp", "bypass", "benign")


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
        rows.append({**report, "label": label})
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
