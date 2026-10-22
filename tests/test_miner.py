from pathlib import Path

from lab.features.checks import flatten
from lab.labels import build
from lab.models import predicate_miner

ROOT = Path(__file__).resolve().parents[2]


def test_flatten_does_not_treat_unknown_as_false():
    assert flatten(None) == {}
    assert flatten({"phantom_install": None}) == {}


def test_miner_recovers_the_known_report_predicates():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    found = {(c["rule_id"], c["predicate"]) for c in predicate_miner.mine(rows)}
    assert ("C024", "phantom=true") in found
    assert ("NOVELTY", "misclassified=true") in found


def test_miner_never_proposes_a_predicate_without_an_fp():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    assert all(c["fp"] > 0 for c in predicate_miner.mine(rows))
