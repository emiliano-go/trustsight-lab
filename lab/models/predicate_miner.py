"""Find evidence predicates that separate proven FPs from real findings.

The output is the deliverable, not a coefficient: a conjunct over evidence
fields that a deterministic guard can test. The miner only proposes; the
counterfactual runner is what decides.

Predicates are deliberately a fixed, small set readers can audit. A tree that
invents a threshold is not necessary: the checks already return booleans and
counts, and a guard has to be readable at the rule site.
"""

from __future__ import annotations

from collections import defaultdict

from ..features.checks import flatten, signature

PREDICATES: dict[str, object] = {
    "phantom=true": lambda f: f.get("phantom") is True,
    "phantom=false": lambda f: f.get("phantom") is False,
    "misclassified=true": lambda f: f.get("misclassified") is True,
    "header_match=true": lambda f: f.get("header_match") is True,
    "remote_skip=0": lambda f: f.get("skip_remote") == 0,
    "local_skip>0": lambda f: isinstance(f.get("skip_local"), int)
    and f["skip_local"] > 0,
    "remote_skip=0 and local_skip>0": lambda f: f.get("skip_remote") == 0
    and isinstance(f.get("skip_local"), int)
    and f["skip_local"] > 0,
    "unknown_skip=0": lambda f: f.get("skip_unknown") == 0,
    "skip_complete=true": lambda f: f.get("skip_complete") is True,
    "same_upstream=true": lambda f: f.get("same_upstream") is True,
    "checksum_only=true": lambda f: f.get("checksum_only") is True,
    "ref_double_count=true": lambda f: f.get("ref_double_count") is True,
}


def _prepare(rows: list[dict], positives: tuple[str, ...]) -> dict[str, list[dict]]:
    by_rule: dict[str, list[dict]] = defaultdict(list)
    allowed = set(positives) | {"tp_benign"}
    for row in rows:
        if row["label"] not in allowed:
            continue
        fields = flatten(row.get("checks"))
        by_rule[row["rule_id"]].append(
            {
                "label": row["label"],
                "fields": fields,
                "sig": signature(fields),
                "package": row.get("package", ""),
            }
        )
    return by_rule


def mine(
    rows: list[dict],
    min_support: int = 1,
    min_packages: int = 1,
    min_precision: float = 0.5,
    positives: tuple[str, ...] = ("hard_fp", "weak_fp"),
) -> list[dict]:
    """Rank predicates by FP count, keeping only those that separate.

    A predicate that hits 131 FPs and 36,000 real findings is not a guard; it
    is a census.  Precision is the fraction of hits that are the target label,
    so the default drops any predicate whose hits are mostly real signals.
    """

    candidates = []
    for rule, grouped in sorted(_prepare(rows, positives).items()):
        base_fp = sum(1 for row in grouped if row["label"] in positives)
        if not base_fp:
            continue
        for name, predicate in PREDICATES.items():
            hits = [row for row in grouped if predicate(row["fields"])]
            if len(hits) < min_support:
                continue
            fp = sum(1 for row in hits if row["label"] in positives)
            hard = sum(1 for row in hits if row["label"] == "hard_fp")
            weak = sum(1 for row in hits if row["label"] == "weak_fp")
            benign = sum(1 for row in hits if row["label"] == "tp_benign")
            packages = sorted({
                row.get("package", "") for row in hits if row.get("package")
            })
            precision = fp / len(hits) if hits else 0.0
            if (not fp or len(packages) < min_packages
                    or precision < min_precision):
                continue
            candidates.append(
                {
                    "rule_id": rule,
                    "predicate": name,
                    "support": len(hits),
                    "fp": fp,
                    "hard_fp": hard,
                    "weak_fp": weak,
                    "tp_benign": benign,
                    "fp_lift": round(fp / base_fp, 3),
                    "precision": round(precision, 3),
                    "signatures": sorted({row["sig"] for row in hits}),
                    "packages": packages,
                }
            )
    candidates.sort(key=lambda row: (-row["fp"], -row["support"], row["rule_id"]))
    return candidates


def summarize(candidates: list[dict]) -> dict:
    return {"candidates": len(candidates), "rules": sorted({c["rule_id"] for c in candidates})}
