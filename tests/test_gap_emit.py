from pathlib import Path

import yaml

from lab.models import gap_cluster


def _cluster(tmp_path: Path, rules):
    diff = tmp_path / "sample.diff"
    diff.write_text("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n")
    sig = "caps=fetch,pipe_shell|files=.PKGBUILD"
    return [{
        "signature": sig,
        "fixture_id": gap_cluster.fixture_id(sig),
        "representative": str(diff),
        "expected_rules": {rule: 1 for rule in rules},
        "count": 1,
    }]


def test_emit_writes_a_raw_diff_campaign_with_the_rules(tmp_path):
    written = gap_cluster.emit(_cluster(tmp_path, ["H075"]), tmp_path / "out")
    assert written[0]["expected_rules"] == ["H075"]
    assert written[0]["needs_rule"] is False
    campaign = yaml.safe_load(
        (tmp_path / "out" / written[0]["campaign"] / "campaign.yml").read_text()
    )
    assert campaign["generator"] == {"type": "raw-diff"}
    assert campaign["prompt"]["expected_rules"] == ["H075"]
    assert campaign["attempts"] == 1
    inputs = yaml.safe_load(
        (tmp_path / "out" / written[0]["campaign"] / "inputs.yml").read_text()
    )
    assert inputs["cells"][0]["diff"].startswith("--- a/PKGBUILD")


def test_a_cluster_without_a_rule_is_emitted_as_needs_rule(tmp_path):
    written = gap_cluster.emit(_cluster(tmp_path, []), tmp_path / "out")
    assert written[0]["needs_rule"] is True
    assert written[0]["expected_rules"] == []


def test_emit_does_not_clobber_an_existing_campaign(tmp_path):
    out = tmp_path / "out"
    gap_cluster.emit(_cluster(tmp_path, ["H075"]), out)
    again = gap_cluster.emit(_cluster(tmp_path, ["H075"]), out)
    assert again[0]["skipped"] == "exists"
