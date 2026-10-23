import json
import tempfile
from pathlib import Path

import pytest

from lab.candidates import known
from lab.validate import fixtures, runner

ROOT = Path(__file__).resolve().parents[2]


def test_every_known_predicate_has_a_fixture():
    assert fixtures.case_for("C024", "phantom=true").is_file()
    assert fixtures.case_for("NOVELTY", "misclassified=true").is_file()
    assert fixtures.case_for("H001", "local_skip_only").is_file()
    assert fixtures.case_for("SOURCE_BUCKET", "misclassified=true").is_file()
    assert fixtures.case_for("H064", "same_upstream=true").is_file()
    assert fixtures.case_for("D004", "same_upstream=true").is_file()
    assert fixtures.case_for("H101", "ref_double_count=true").is_file()
    assert fixtures.case_for("R054", "local_skip_only") is None


def test_fixture_carries_both_expectations():
    case = json.loads(fixtures.case_for("H001", "local_skip_only").read_text())
    assert case["unpatched"] == "HIGH"
    assert case["patched"] == "INFO"


def test_tier0_round_trip_on_the_h001_candidate():
    trustsight = ROOT / "trustsight"
    python = trustsight / ".venv" / "bin" / "python"
    if not python.is_file():
        pytest.skip("trustsight venv is not present")
    candidate = known.for_predicate("H001", "local_skip_only", trustsight)
    tree = runner.worktree(trustsight, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(tree, candidate.patch)
        result = fixtures.validate(candidate, tree, trustsight)
    finally:
        runner.remove_worktree(trustsight, tree)
    assert result["passed"] is True
    assert result["before"] == "HIGH"
    assert result["after"] == "INFO"
