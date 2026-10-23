"""Weak precision labels for unlabeled firings.

A finding is a *provable* malicious false positive when the evidence already
in hand contradicts its premise. These are not hard labels: the caller must
treat them as candidates for ranking and re-verify with the deterministic
check before proposing a guard.
"""

from __future__ import annotations

from ..features.checks import flatten

#: ``header_match`` stays a miner feature, not a contradiction: without a
#: rename flag from the diff it cannot distinguish a renamed file from a
#: genuine header match. This is the amended plan decision.

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
    "same_upstream": frozenset({"H064", "D004", "H098"}),
    "ref_double_count": frozenset({"H033", "H101"}),
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
    if fields.get("same_upstream") is True and _applies("same_upstream", rule_id):
        return {
            "label": "contradiction_fp",
            "reason": "same_upstream",
            "rule_id": rule_id,
        }
    if fields.get("ref_double_count") is True and _applies(
        "ref_double_count", rule_id
    ):
        return {
            "label": "contradiction_fp",
            "reason": "ref_double_count",
            "rule_id": rule_id,
        }
    return None


def annotate(rows: list[dict]) -> list[dict]:
    """Add ``contradiction`` or a real-signal label to each row.

    A maintainer-first-seen on an existing package is the first signal for an
    adoption campaign, not a false positive.  It is labelled ``tp_benign`` so
    the miner keeps it out of the precision target and the rule keeps firing.
    """

    out = []
    for row in rows:
        if row.get("label") in ("hard_fp", "tp_benign", "tp"):
            out.append(row)
            continue
        context = row.get("novelty_context") or {}
        if (
            row.get("rule_id") == "NOVELTY"
            and row.get("first_seen") is False
            and context.get("maintainer_first_seen_for_this_package") is True
            and not context.get("url_first_seen_globally")
            and not context.get("url_first_seen_in_this_package")
        ):
            out.append({
                **row,
                "signal": {
                    "label": "tp_benign",
                    "reason": "maintainer_adoption",
                },
            })
            continue
        found = derive(
            row.get("checks"),
            rule_id=row.get("rule_id", ""),
            timestamp=row.get("timestamp"),
            captured_at=row.get("snapshot_captured_at"),
        )
        out.append({**row, "contradiction": found})
    return out
