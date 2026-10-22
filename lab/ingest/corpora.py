"""Enumerate the committed corpora the lab measures against.

Nothing here scans a diff. This module answers "what exists and what is it
labelled", so a manifest can be compared before and after a rebase.
"""

from __future__ import annotations

import json
from pathlib import Path


def _expected(root: Path) -> dict[str, dict]:
    expected: dict[str, dict] = {}
    for path in sorted(root.glob("*/expected.json")):
        group = path.parent.name
        for name, label in json.loads(path.read_text()).items():
            expected[f"{group}/{name}"] = label
    return expected


def malicious_fixtures(trustsight_root: Path) -> list[dict]:
    root = trustsight_root / "tests" / "fixtures" / "malicious"
    expected = _expected(root)
    rows = []
    for path in sorted(root.glob("*/*.diff")):
        key = f"{path.parent.name}/{path.name}"
        signal = expected.get(key, {})
        if not signal or signal.get("known_gap"):
            continue
        rows.append(
            {
                "corpus": "malicious",
                "group": path.parent.name,
                "package": path.name.split(".")[0],
                "path": str(path),
                "label": "tp",
                "must_fire": list(signal.get("must_fire") or []),
                "must_not_fire": list(signal.get("must_not_fire") or []),
                "min_score": signal.get("min_score"),
                "max_score": signal.get("max_score"),
            }
        )
    return rows


def benign_corpus(trustsight_root: Path) -> list[dict]:
    root = trustsight_root / "tests" / "fixtures" / "benign-corpus"
    return [
        {
            "corpus": "benign",
            "group": "benign",
            "package": path.name.split("__")[0],
            "path": str(path),
            "label": "benign",
        }
        for path in sorted(root.glob("*.diff"))
    ]


def bypass_fixtures(harness_root: Path) -> list[dict]:
    root = harness_root / "fixtures-out"
    rows = []
    # The exporter writes into a subdirectory (e.g. `fixtures-gaps/`); a
    # top-level glob silently reported an empty recall corpus.
    for expected_path in sorted(root.rglob("*.expected.json")):
        stem = expected_path.name[: -len(".expected.json")]
        expected = json.loads(expected_path.read_text())
        rows.append(
            {
                "corpus": "bypass",
                "group": (expected.get("provenance") or {}).get("campaign", ""),
                "package": "harness-pkg",
                "path": str(expected_path.parent / f"{stem}.diff"),
                "label": "bypass",
                "must_fire": list(expected.get("must_fire") or []),
                "known_gap": bool(expected.get("known_gap")),
            }
        )
    return rows


def ioc_baselines(trustsight_root: Path) -> list[dict]:
    rows = []
    for directory in sorted((trustsight_root / "ioc-baselines").glob("*")):
        iocs = directory / "iocs.jsonl"
        if not iocs.is_file():
            continue
        count = sum(1 for line in iocs.read_text().splitlines() if line.strip())
        rows.append(
            {
                "corpus": "ioc",
                "group": directory.name,
                "package": "",
                "path": str(iocs),
                "label": "tp",
                "entries": count,
            }
        )
    return rows


def manifest(trustsight_root: Path, harness_root: Path) -> dict:
    malicious = malicious_fixtures(trustsight_root)
    benign = benign_corpus(trustsight_root)
    bypass = bypass_fixtures(harness_root)
    iocs = ioc_baselines(trustsight_root)
    return {
        "counts": {
            "malicious": len(malicious),
            "benign": len(benign),
            "bypass": len(bypass),
            "ioc_baselines": len(iocs),
        },
        "rows": malicious + benign + bypass + iocs,
    }
