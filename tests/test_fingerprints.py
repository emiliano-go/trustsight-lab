from lab.models import fingerprints


def test_summary_slices_by_fingerprint():
    rows = [
        {"config_fingerprint": "a", "package": "p1", "rule_id": "C024"},
        {"config_fingerprint": "a", "package": "p1", "rule_id": "C024"},
        {"config_fingerprint": "b", "package": "p2", "rule_id": "H001",
         "contradiction": {"reason": "local_skip_only"}},
    ]
    summary = fingerprints.summarize(rows)
    assert len(summary) == 2
    assert summary[0]["config_fingerprint"] == "a"
    assert summary[0]["findings"] == 2
    assert summary[0]["packages"] == 1
    assert summary[1]["contradictions"] == {"local_skip_only": 1}
