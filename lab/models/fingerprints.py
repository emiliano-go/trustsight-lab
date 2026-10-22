"""Per-instrument summaries.

A score is only comparable within one configuration fingerprint. The lab
keeps all history, so every aggregate is sliced by fingerprint and reports
the mix instead of pooling instruments that measured different rulesets.
"""

from __future__ import annotations

from collections import Counter, defaultdict


def summarize(rows: list[dict]) -> list[dict]:
    groups: dict[str, dict] = defaultdict(
        lambda: {
            "findings": 0,
            "packages": set(),
            "rules": Counter(),
            "versions": Counter(),
            "contradictions": Counter(),
        }
    )
    for row in rows:
        fingerprint = row.get("config_fingerprint") or "unknown"
        group = groups[fingerprint]
        group["findings"] += 1
        if row.get("package"):
            group["packages"].add(row["package"])
        if row.get("rule_id"):
            group["rules"][row["rule_id"]] += 1
        if row.get("new_version"):
            group["versions"][str(row["new_version"])] += 1
        contradiction = row.get("contradiction")
        if contradiction:
            group["contradictions"][contradiction.get("reason", "")] += 1
    summary = []
    for fingerprint, group in groups.items():
        summary.append(
            {
                "config_fingerprint": fingerprint,
                "findings": group["findings"],
                "packages": len(group["packages"]),
                "top_rules": dict(group["rules"].most_common(10)),
                "top_versions": dict(group["versions"].most_common(5)),
                "contradictions": dict(group["contradictions"].most_common()),
            }
        )
    summary.sort(key=lambda row: (-row["findings"], row["config_fingerprint"]))
    return summary
