"""Diagnose the score-versus-size gate.

The gate asks one question: does a bigger diff score higher for reasons
unrelated to risk? This module reads the same sampled corpus scan the gate
reads and names the rules that contribute to the correlation.
"""

from __future__ import annotations

import math
from collections import defaultdict


def pearson(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return 0.0 if dx == 0 or dy == 0 else num / (dx * dy)


def diagnose(rows: list[dict]) -> dict:
    scores = [float(row.get("score") or 0) for row in rows]
    lines = [float(row.get("lines") or 0) for row in rows]
    overall = pearson(scores, lines)

    stats: dict[str, dict] = defaultdict(
        lambda: {
            "count": 0,
            "weight": 0,
            "lines": 0,
            "score": 0,
            "packages": [],
        }
    )
    for row in rows:
        for entry in row.get("entries") or []:
            rule = entry.get("rule_id", "")
            if not rule or rule == "COVERAGE":
                continue
            item = stats[rule]
            item["count"] += 1
            item["weight"] += int(entry.get("weight") or 0)
            item["lines"] += int(row.get("lines") or 0)
            item["score"] += int(row.get("score") or 0)
            package = row.get("package", "")
            if package:
                item["packages"].append((int(row.get("lines") or 0), package))

    rules = []
    for rule, item in stats.items():
        presence = [
            1.0 if any(e.get("rule_id") == rule for e in row.get("entries") or [])
            else 0.0
            for row in rows
        ]
        rules.append(
            {
                "rule_id": rule,
                "count": item["count"],
                "mean_lines": round(item["lines"] / item["count"], 1),
                "mean_score": round(item["score"] / item["count"], 1),
                "presence_corr": round(pearson(presence, lines), 3),
                "total_weight": item["weight"],
                "largest_packages": [
                    package for _lines, package in sorted(
                        item["packages"], reverse=True
                    )[:5]
                ],
            }
        )
    rules.sort(key=lambda row: (-abs(row["presence_corr"]), -row["count"]))
    return {
        "scanned": len(rows),
        "pearson": round(overall, 4),
        "threshold": 0.30,
        "passed": abs(overall) < 0.30,
        "rules": rules[:25],
    }
