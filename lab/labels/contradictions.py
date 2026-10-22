"""Weak precision labels for unlabeled firings.

A finding is a *provable* malicious false positive when the evidence already
in hand contradicts its premise. These are not hard labels: the caller must
treat them as candidates for ranking and re-verify with the deterministic
check before proposing a guard.
"""

from __future__ import annotations

from ..features.checks import flatten

#: A contradiction only says something about the rule it can refute. A
#: package whose SKIPs are all local files does not make an unrelated
#: persistence finding false, so the rule is part of the label.
CONTRADICTION_RULES = {
    "phantom_install": frozenset({"C024", "R007", "H017", "C027", "H035"}),
    "url_in_source_misclassified": frozenset(
        {"NOVELTY", "SOURCE_BUCKET", "C011", "H003", "C020"}
    ),
    "local_skip_only": frozenset(
        {"H001", "H002", "H003", "C001", "C002", "C003"}
    ),
}


def _applies(reason: str, rule_id: str) -> bool:
    return rule_id in CONTRADICTION_RULES.get(reason, ())


def _age_ok(timestamp: str | None, captured_at: str | None, max_age: float) -> bool:
    """A contradiction is only trustworthy while the snapshot is current.

    The watcher stores the recipe as of its last observation. A historical
    finding compared against a snapshot taken a day later can disagree for
    the ordinary reason that upstream moved, not because the rule was wrong.
    """

    if not timestamp or not captured_at:
        return False
    from datetime import datetime

    def parse(value: str) -> datetime | None:
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    start, end = parse(timestamp), parse(captured_at)
    if start is None or end is None:
        return False
    if start.tzinfo is None or end.tzinfo is None:
        start = start.replace(tzinfo=None)
        end = end.replace(tzinfo=None)
    return abs((end - start).total_seconds()) <= max_age


def derive(
    checks: dict | None,
    *,
    rule_id: str = "",
    timestamp: str | None = None,
    captured_at: str | None = None,
    max_snapshot_age: float = 6 * 3600,
) -> dict | None:
    if not _age_ok(timestamp, captured_at, max_snapshot_age):
        return None
    fields = flatten(checks)
    if fields.get("phantom") is True and _applies("phantom_install", rule_id):
        return {
            "label": "contradiction_fp",
            "reason": "phantom_install",
            "rule_id": rule_id,
        }
    if fields.get("misclassified") is True and _applies(
        "url_in_source_misclassified", rule_id
    ):
        return {
            "label": "contradiction_fp",
            "reason": "url_in_source_misclassified",
            "rule_id": rule_id,
        }
    if (
        fields.get("skip_complete") is True
        and fields.get("skip_remote") == 0
        and isinstance(fields.get("skip_local"), int)
        and fields["skip_local"] > 0
        and _applies("local_skip_only", rule_id)
    ):
        return {
            "label": "contradiction_fp",
            "reason": "local_skip_only",
            "rule_id": rule_id,
        }
    return None


def annotate(rows: list[dict]) -> list[dict]:
    """Add ``contradiction`` to rows that do not already carry a hard label."""

    out = []
    for row in rows:
        if row.get("label") in ("hard_fp", "tp_benign", "tp"):
            out.append(row)
            continue
        found = derive(
            row.get("checks"),
            rule_id=row.get("rule_id", ""),
            timestamp=row.get("timestamp"),
            captured_at=row.get("snapshot_captured_at"),
        )
        out.append({**row, "contradiction": found})
    return out
