from pathlib import Path

from lab.labels import build
from lab.models import fp_ranker

ROOT = Path(__file__).resolve().parents[2]


def test_group_rank_puts_the_known_fp_signatures_first():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    ranked = fp_ranker.rank_groups(rows)
    assert ranked
    assert ranked[0]["fp"] > 0
    assert any(row["rule_id"] == "C024" and "phantom" in row["signature"]
               for row in ranked)
    assert any(row["rule_id"] == "NOVELTY" and "misclassified" in row["signature"]
               for row in ranked)


def test_rank_groups_is_deterministic():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    assert fp_ranker.rank_groups(rows) == fp_ranker.rank_groups(rows)
