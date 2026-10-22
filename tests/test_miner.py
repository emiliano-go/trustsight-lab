from pathlib import Path

import pytest

from lab.features.checks import flatten
from lab.ingest import reports
from lab.labels import build
from lab.models import predicate_miner

ROOT = Path(__file__).resolve().parents[2]


def _has_fp_reports() -> bool:
    return bool(reports.load_reports(ROOT / "trustsight-harness"))


def test_flatten_does_not_treat_unknown_as_false():
    assert flatten(None) == {}
    assert flatten({"phantom_install": None}) == {}


@pytest.mark.skipif(
    not _has_fp_reports(),
    reason="the adjudicated FP report corpus is not checked out",
)
def test_miner_recovers_the_known_report_predicates():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    found = {(c["rule_id"], c["predicate"]) for c in predicate_miner.mine(rows)}
    assert ("C024", "phantom=true") in found
    assert ("NOVELTY", "misclassified=true") in found


def test_miner_never_proposes_a_predicate_without_an_fp():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    assert all(c["fp"] > 0 for c in predicate_miner.mine(rows))


def test_strict_support_requires_distinct_packages():
    rows = [
        {"label": "weak_fp", "rule_id": "NOVELTY", "package": "a",
         "checks": {"url_in_source": {"misclassified": True}}},
        {"label": "weak_fp", "rule_id": "NOVELTY", "package": "b",
         "checks": {"url_in_source": {"misclassified": True}}},
    ]
    assert predicate_miner.mine(rows, min_packages=1)
    assert predicate_miner.mine(rows, min_packages=3) == []
