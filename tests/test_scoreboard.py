import json
import subprocess
from pathlib import Path

from lab import scoreboard
from lab.pins import read_pins


def _repo(path: Path, name: str, text: str) -> None:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.org"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], check=True)
    (path / name).write_text(text)
    subprocess.run(["git", "-C", str(path), "add", name], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "init"], check=True)


def _root(tmp_path: Path) -> Path:
    root = tmp_path
    _repo(root / "trustsight", "PKGBUILD", "pkgname=demo\n")
    (root / "trustsight" / "tests" / "fixtures").mkdir(parents=True)
    (root / "trustsight" / "tests" / "fixtures" / "corpus.lock").write_text("lock\n")
    _repo(root / "trustsight-harness", "README", "harness\n")
    return root


def _candidate(path: Path, patch: str, reproducers=()) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "status": "ready",
        "patch": patch,
        "reproducers": list(reproducers),
    }))


def test_pin_slug_is_one_safe_directory():
    from lab.pins import Pins

    slug = scoreboard.pin_slug(Pins(
        trustsight_sha="1a77c666fc0384be",
        harness_sha="1315fb9",
        trustsight_version="v0.22.0-39-g1a77c66",
        harness_version="v2.0.0",
        corpus_lock_sha256="x",
    ))
    assert slug == "0.22.0-39-g1a77c66-1a77c66"
    assert "/" not in slug


def test_write_run_stamps_the_pins(tmp_path):
    root = _root(tmp_path)
    pins = read_pins(root)
    directory = scoreboard.write_run(
        pins, {"gaps": 3}, "# report\n", runs_dir=root / "runs"
    )
    saved = json.loads((directory / "summary.json").read_text())
    assert saved["schema_version"] == scoreboard.SCHEMA_VERSION
    assert saved["pins"] == pins.to_dict()
    assert saved["gaps"] == 3
    assert (directory / "report.md").read_text() == "# report\n"


def test_check_passes_when_the_run_and_candidate_match(tmp_path):
    root = _root(tmp_path)
    pins = read_pins(root)
    scoreboard.write_run(pins, {}, "", runs_dir=root / "runs")
    _candidate(
        root / "candidates" / "c1.json",
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgname=demo\n+pkgname=demo2\n",
        ["benign/fp-1"],
    )
    (root / "trustsight-harness" / "benign" / "fp-1").mkdir(parents=True)
    (root / "trustsight-harness" / "benign" / "fp-1" / "triage.json").write_text("{}")

    assert scoreboard.check(
        root, runs_dir=root / "runs", candidates=root / "candidates"
    ) == []


def test_check_names_a_missing_reproducer_and_a_stale_patch(tmp_path):
    root = _root(tmp_path)
    pins = read_pins(root)
    scoreboard.write_run(pins, {}, "", runs_dir=root / "runs")
    _candidate(
        root / "candidates" / "c1.json",
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-wrong\n+also wrong\n",
        ["benign/fp-missing"],
    )
    failures = scoreboard.check(
        root, runs_dir=root / "runs", candidates=root / "candidates"
    )
    assert any("reproducer missing" in failure for failure in failures)
    assert any("patch does not apply" in failure for failure in failures)
