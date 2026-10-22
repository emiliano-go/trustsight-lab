import json
from pathlib import Path

from lab.validate import fixtures

ROOT = Path(__file__).resolve().parents[2]


def test_every_known_predicate_has_a_fixture():
    assert fixtures.case_for("C024", "phantom=true").is_file()
    assert fixtures.case_for("NOVELTY", "misclassified=true").is_file()
    assert fixtures.case_for("H001", "local_skip_only").is_file()
    assert fixtures.case_for("R054", "local_skip_only") is None


def test_fixture_carries_both_expectations():
    case = json.loads(fixtures.case_for("H001", "local_skip_only").read_text())
    assert case["unpatched"] == "HIGH"
    assert case["patched"] == "INFO"
