"""Turn the extracted watcher stream into one row per finding.

The extraction keeps analyses; the unit the lab reasons about is a finding.
This join is deliberately lazy on snapshots: only packages whose findings are
actually being rebuilt are read, so a 50k sample does not load 39k recipes.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from pathlib import Path

from . import evidence

INTERESTING = (
    "C024",
    "C001",
    "NOVELTY",
    "SOURCE_BUCKET",
    "H001",
    "H064",
    "D004",
    "H098",
    "H033",
    "H101",
    "R007",
    "R054",
)


def _rows(path: Path) -> Iterator[dict]:
    if not path.is_file():
        raise FileNotFoundError(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def _names(extract_dir: Path) -> dict[int, str]:
    path = extract_dir / "packages.jsonl.gz"
    if not path.is_file():
        return {}
    return {row["id"]: row["name"] for row in _rows(path)}


def _snapshots(extract_dir: Path) -> dict[str, dict]:
    path = extract_dir / "pkgbuild_snapshots.jsonl.gz"
    if not path.is_file():
        return {}
    return {row["package_name"]: row for row in _rows(path)}


def build(
    extract_dir: Path,
    *,
    limit: int | None = None,
    only_rules: tuple[str, ...] = INTERESTING,
    recompute: bool = True,
    root: Path | None = None,
) -> list[dict]:
    names = _names(extract_dir)
    snapshots = _snapshots(extract_dir) if recompute else {}
    if recompute and root is not None:
        evidence.ensure_imports(root)
    prepared: dict[str, tuple] = {}
    findings: list[dict] = []
    for index, row in enumerate(_rows(extract_dir / "analysis_history.jsonl.gz")):
        if limit is not None and index >= limit:
            break
        package = names.get(row.get("package_id"), "")
        snapshot = snapshots.get(package, {})
        fact = row
        if row.get("fact_json"):
            try:
                fact = {**row, **json.loads(row["fact_json"])}
            except (TypeError, ValueError):
                fact = row
        for entry in fact.get("score_breakdown") or []:
            rule = entry.get("rule_id", "")
            if rule not in only_rules:
                continue
            finding = {
                "package": package,
                "history_id": row.get("id"),
                "timestamp": row.get("timestamp"),
                "snapshot_captured_at": snapshot.get("captured_at"),
                "final_score": fact.get("final_score"),
                "config_fingerprint": fact.get("config_fingerprint"),
                "rule_id": rule,
                "severity": entry.get("severity", ""),
                "weight": entry.get("weight"),
                "reason": entry.get("reason", "") or entry.get("match", ""),
                "file": entry.get("file", ""),
                "line": entry.get("line"),
                "checks": {},
            }
            if recompute and snapshot.get("pkgbuild_text"):
                try:
                    if package not in prepared:
                        prepared[package] = evidence.prepare(
                            snapshot["pkgbuild_text"],
                            file_names=snapshot.get("file_names"),
                        )
                    recipe, files = prepared[package]
                    finding["checks"] = evidence.recompute(
                        finding,
                        snapshot["pkgbuild_text"],
                        recipe=recipe,
                        files=files,
                        source_changes=fact.get("source_changes"),
                    )
                except Exception as exc:  # noqa: BLE001 - a refusal keeps the row
                    finding["evidence_error"] = str(exc)
            findings.append(finding)
    _annotate_ref_double_count(findings)
    return findings


def _annotate_ref_double_count(findings: list[dict]) -> None:
    """Mark the H033/H101 pair when both describe the same analysis.

    The pair counts one ref change twice. The marker is evidence about the
    pair, not a verdict on either finding.
    """

    groups: dict[tuple, list[dict]] = {}
    for row in findings:
        key = (row.get("package"), row.get("history_id"))
        groups.setdefault(key, []).append(row)
    for rows in groups.values():
        rules = {row.get("rule_id") for row in rows}
        if {"H033", "H101"} <= rules:
            for row in rows:
                if row.get("rule_id") in ("H033", "H101"):
                    row.setdefault("checks", {})["ref_double_count"] = True


def write(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
