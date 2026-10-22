from lab.features import benign


def test_flatten_keeps_findings_on_benign_diffs_separate():
    rows = benign.flatten([
        {
            "package": "demo",
            "path": "x.diff",
            "score": 15,
            "entries": [
                {"rule_id": "R007", "severity": "MEDIUM", "weight": 15,
                 "params": {}},
                {"rule_id": "COVERAGE", "severity": "INFO", "weight": 0},
            ],
        }
    ])
    assert len(rows) == 1
    assert rows[0]["label"] == "candidate_benign"
    assert rows[0]["rule_id"] == "R007"
