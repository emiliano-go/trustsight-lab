from lab.features import benign
from lab.labels import build


def test_benign_fire_rate_counts_each_rule_once_per_diff():
    results = [
        {"entries": [{"rule_id": "H015"}, {"rule_id": "H015"}, {"rule_id": "C001"}]},
        {"entries": [{"rule_id": "H015"}]},
        {"entries": []},
    ]
    rates = benign.fire_rates(results)
    assert rates["scanned"] == 3
    assert rates["rules"]["H015"] == {"count": 2, "rate": 0.6667}
    assert rates["rules"]["C001"] == {"count": 1, "rate": 0.3333}


def test_audit_names_hard_fps_that_cannot_be_remeasured():
    rows = [
        {"label": "hard_fp", "package": "a", "reproducer_present": True,
         "config_fingerprint": "sha256:x"},
        {"label": "hard_fp", "package": "b", "reproducer_present": False},
        {"label": "tp_benign", "package": "c"},
    ]
    audit = build.audit(rows)
    assert audit["hard_fp"] == 2
    assert audit["missing_reproducer"] == ["b"]
    assert audit["missing_fingerprint"] == ["b"]


def test_ranker_reports_a_package_grouped_holdout():
    import pytest

    pytest.importorskip("sklearn")
    from lab.models import fp_ranker

    rows = []
    for index in range(20):
        rows.append({
            "label": "hard_fp" if index % 2 else "tp_benign",
            "package": f"pkg-{index // 2}",
            "rule_id": "H001",
            "checks": {"skip_local": index % 3},
        })
    trained = fp_ranker.train(rows)
    assert trained["holdout_n"] > 0
    assert trained["holdout_auc"] is not None
