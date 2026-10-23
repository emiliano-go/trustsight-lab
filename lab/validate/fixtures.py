"""Tier 0: the candidate's own false-positive and true-positive cases.

Each case is a small, committed input under ``lab/fixtures/fp``. The probe
runs against the unpatched checkout and the patched worktree and asserts the
two expected values. No corpus scan and no harness process is involved.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "fp"

CASES = {
    ("C024", "phantom=true"): "c024_phantom.json",
    ("NOVELTY", "misclassified=true"): "novelty_url.json",
    ("SOURCE_BUCKET", "misclassified=true"): "source_bucket_url.json",
    ("H001", "local_skip_only"): "h001_local.json",
    ("H064", "same_upstream=true"): "h064_same_upstream.json",
    ("D004", "same_upstream=true"): "d004_same_upstream.json",
    ("H101", "ref_double_count=true"): "h101_dedup.json",
}

PROBE = r'''
import difflib
import json
import sys

from trustsight.analysis.structural import _structural_findings
from trustsight.differ._sources import extract_urls_from_diff

case = json.loads(open(sys.argv[1]).read())
rule = case["rule_id"]

def diff(old, new):
    return "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True), "a/PKGBUILD", "b/PKGBUILD"))

if rule in ("NOVELTY", "SOURCE_BUCKET"):
    urls = extract_urls_from_diff(diff(case["old"], case["new"])).added_urls
    value = "find" if "https://new.example" in urls else "absent"
elif rule in ("H064", "D004"):
    import trustsight.db as tsdb
    tsdb.official_package_names = lambda: {"foo"}
    from trustsight.analysis.dependencies import _dependency_findings
    found = []
    def add(rule_id, *args, **kwargs):
        found.append(rule_id)
    _dependency_findings(
        diff(case["old"], case["new"]), case["package_name"], {}, add,
        current_text=case["new"])
    value = "find" if rule in found else "absent"
elif rule == "H001":
    text = diff(case["old"], case["new"])
    changes = extract_urls_from_diff(text)
    findings = _structural_findings(
        text, changes, package_name="h001-demo", current_text=case["new"])
    value = next(
        (item["severity"] for item in findings if item["rule_id"] == "H001"),
        "absent")
elif rule == "H101":
    text = diff(case["old"], case["new"])
    changes = extract_urls_from_diff(text)
    findings = _structural_findings(
        text, changes, package_name="demo", current_text=case["new"])
    value = "find" if any(
        item["rule_id"] == "H033" for item in findings) else "absent"
elif rule == "C024":
    tree = [(name, b"") for name in case["tree_absent"]]
    changes = extract_urls_from_diff(case["diff"])
    findings = _structural_findings(
        case["diff"], changes, package_name="demo",
        current_text=case["current"], tree_manifest=tree)
    value = "find" if any(
        item["rule_id"] == "C024" for item in findings) else "absent"
else:
    value = "unsupported"
print(json.dumps({"value": value}))
'''


def case_for(rule_id: str, predicate: str) -> Path | None:
    name = CASES.get((rule_id, predicate))
    return FIXTURE_DIR / name if name else None


def _probe(tree: Path, case: Path, python: Path) -> str:
    env = {"PYTHONPATH": str(tree / "src"), "PATH": "/usr/bin:/bin"}
    completed = subprocess.run(
        [str(python), "-c", PROBE, str(case)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-2000:])
    return json.loads(completed.stdout)["value"]


def validate(candidate, tree: Path, trustsight_root: Path) -> dict:
    case = case_for(candidate.rule_id, candidate.predicate)
    if case is None:
        return {"passed": False, "detail": "no tier 0 fixture for this predicate"}
    python = trustsight_root / ".venv" / "bin" / "python"
    if not python.is_file():
        return {"passed": False, "detail": "the pinned TrustSight venv is absent"}
    expected = json.loads(case.read_text())
    before = _probe(trustsight_root, case, python)
    after = _probe(tree, case, python)
    passed = before == expected["unpatched"] and after == expected["patched"]
    return {
        "passed": passed,
        "case": case.name,
        "before": before,
        "after": after,
        "expected_before": expected["unpatched"],
        "expected_after": expected["patched"],
    }
