"""Acceptance checks over the validator's command output.

The harness prints JSON for both ``benign`` and ``fp_verify``; this module
reads those two shapes and turns them into the three questions a candidate
must answer: no new benign flags, every reproducer re-scored under the
threshold, and no command failed.
"""

from __future__ import annotations

import json


def _json(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def parse_benign(text: str) -> dict | None:
    doc = _json(text)
    if not isinstance(doc, dict):
        return None
    rate = doc.get("flag_rate") or {}
    return {
        "scanned": doc.get("scanned"),
        "flagged": doc.get("flagged"),
        "estimate": rate.get("estimate"),
        "threshold": doc.get("threshold"),
    }


def parse_fp_verify(text: str) -> dict | None:
    doc = _json(text)
    if not isinstance(doc, dict) or "results" not in doc:
        return None
    rows = doc.get("results") or []
    return {
        "all_verified": bool(doc.get("all_verified")),
        "still_flagged": [
            row for row in rows if row.get("still_flagged") is True
        ],
        "scores": [
            {"diff": row.get("diff"), "after": row.get("score_after")}
            for row in rows
        ],
    }


def evaluate(results: list[dict], *, baseline_flag_rate: float | None = None) -> dict:
    failures = []
    benign = None
    verified = None
    for result in results:
        if result["returncode"] != 0:
            failures.append(f"command failed: {' '.join(result['argv'])}")
        if "benign" in result["argv"]:
            benign = parse_benign(result["stdout"]) or benign
        if "fp_verify" in result["argv"]:
            verified = parse_fp_verify(result["stdout"]) or verified
    if (
        benign
        and baseline_flag_rate is not None
        and benign["estimate"] is not None
        and benign["estimate"] > baseline_flag_rate
    ):
        failures.append(
            f"benign flag rate rose: {benign['estimate']} > {baseline_flag_rate}"
        )
    if verified is not None:
        if not verified["all_verified"]:
            failures.append("fp_verify did not verify every reproducer")
        if verified["still_flagged"]:
            failures.append(
                f"{len(verified['still_flagged'])} reproducer(s) still flagged"
            )
    return {
        "passed": not failures,
        "failures": failures,
        "benign": benign,
        "fp_verify": verified,
    }
