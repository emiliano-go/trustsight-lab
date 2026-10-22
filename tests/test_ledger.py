import json
import subprocess
from pathlib import Path

from lab import ledger


def _root(tmp_path: Path) -> Path:
    repo = tmp_path / "trustsight"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@example.org"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "PKGBUILD").write_text("pkgname=demo\n")
    subprocess.run(["git", "-C", str(repo), "add", "PKGBUILD"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    (tmp_path / "trustsight" / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "trustsight" / "tests" / "fixtures" / "corpus.lock").write_text("lock\n")
    harness = tmp_path / "trustsight-harness"
    (harness / "regression").mkdir(parents=True)
    (harness / "coverage").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(harness)], check=True)
    subprocess.run(["git", "-C", str(harness), "config", "user.email", "t@example.org"], check=True)
    subprocess.run(["git", "-C", str(harness), "config", "user.name", "t"], check=True)
    (harness / ".keep").write_text("x\n")
    subprocess.run(["git", "-C", str(harness), "add", ".keep"], check=True)
    subprocess.run(["git", "-C", str(harness), "commit", "-qm", "init"], check=True)
    return tmp_path


def _write(root: Path, name: str, doc: dict) -> None:
    path = root / "trustsight-harness" / name
    path.write_text(json.dumps(doc))


def _candidate(root: Path, **fields) -> None:
    path = root / "candidates" / "c1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "id": "H001-local-skip",
        "rule_id": "H001",
        "predicate": "local_skip_only",
        "status": "ready",
        "patch": "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgname=demo\n+pkgname=demo2\n",
        **fields,
    }))


def test_a_hardened_rule_marks_the_candidate_landed(tmp_path):
    root = _root(tmp_path)
    _write(root, "regression/matrix.json", {"rules": [
        {"rule": "H001", "state": "hardened", "hardened": True},
    ]})
    _write(root, "coverage/report.json", {"rules": {"untargeted_ids": []}})
    _write(root, "regression/report.json", {"bypasses": []})
    _candidate(root)

    doc = ledger.build(root, candidates=root / "candidates")
    row = doc["candidates"][0]
    assert row["outcome"] == "landed"
    assert row["coverage_targeted"] is True
    assert row["tier0_fixture"] == "h001_local.json"
    assert doc["counts"]["landed"] == 1


def test_an_applying_patch_on_an_unproven_rule_is_pending(tmp_path):
    root = _root(tmp_path)
    _write(root, "regression/matrix.json", {"rules": [
        {"rule": "H001", "state": "unproven", "hardened": False},
    ]})
    _write(root, "coverage/report.json", {"rules": {"untargeted_ids": ["H001"]}})
    _write(root, "regression/report.json", {"bypasses": []})
    _candidate(root)

    row = ledger.build(root, candidates=root / "candidates")["candidates"][0]
    assert row["outcome"] == "pending"
    assert row["coverage_targeted"] is False


def test_a_patch_that_no_longer_applies_on_an_unproven_rule_is_stale(tmp_path):
    root = _root(tmp_path)
    _write(root, "regression/matrix.json", {"rules": [
        {"rule": "H001", "state": "unproven", "hardened": False},
    ]})
    _write(root, "coverage/report.json", {"rules": {"untargeted_ids": []}})
    _write(root, "regression/report.json", {"bypasses": []})
    _candidate(root, patch="--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-wrong\n+x\n")

    row = ledger.build(root, candidates=root / "candidates")["candidates"][0]
    assert row["outcome"] == "stale"


def test_a_candidate_with_no_fixture_stays_in_the_backlog(tmp_path):
    root = _root(tmp_path)
    _write(root, "regression/matrix.json", {"rules": []})
    _write(root, "coverage/report.json", {"rules": {"untargeted_ids": []}})
    _write(root, "regression/report.json", {"bypasses": []})
    _candidate(root, rule_id="H064", predicate="same_upstream=true",
               status="needs_fixture")

    row = ledger.build(root, candidates=root / "candidates")["candidates"][0]
    assert row["outcome"] == "backlog"
    assert row["tier0_fixture"] is None
