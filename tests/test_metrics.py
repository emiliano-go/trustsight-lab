from lab.validate import metrics


def _result(argv, code, stdout):
    return {"argv": argv, "returncode": code, "stdout": stdout, "stderr": ""}


def test_benign_and_fp_verify_accept_a_clean_candidate():
    results = [
        _result(["python", "-m", "harness", "benign"],
                0, '{"scanned": 3739, "flagged": 0, "flag_rate": {"estimate": 0.0}}'),
        _result(["python", "-m", "harness", "fp_verify", "x"],
                0, '{"all_verified": true, "results": [{"still_flagged": false, '
                   '"score_after": 10, "diff": "a.diff"}]}'),
    ]
    verdict = metrics.evaluate(results, baseline_flag_rate=0.0)
    assert verdict["passed"]
    assert verdict["fp_verify"]["still_flagged"] == []


def test_a_still_flagged_reproducer_fails():
    results = [
        _result(["python", "-m", "harness", "fp_verify", "x"],
                0, '{"all_verified": true, "results": [{"still_flagged": true, '
                   '"score_after": 60, "diff": "a.diff"}]}'),
    ]
    verdict = metrics.evaluate(results)
    assert not verdict["passed"]
    assert verdict["fp_verify"]["still_flagged"]


def test_a_failed_command_fails():
    verdict = metrics.evaluate([_result(["python", "x"], 2, "")])
    assert not verdict["passed"]


def test_recall_and_separation_gates_fail_the_candidate():
    gates = [
        {"gate": "labelled attacks still detected", "passed": False, "measured": 2},
        {"gate": "benign_p95 < malicious_p5", "passed": True, "measured": {}},
    ]
    verdict = metrics.evaluate([], gates=gates)
    assert not verdict["passed"]
    assert any("labelled attacks" in item for item in verdict["failures"])


def test_recall_delta_is_reported():
    gates = [
        {"gate": "labelled attacks still detected", "passed": True, "measured": 1},
    ]
    baseline = {
        "gates": {"labelled attacks still detected": {"measured": 0}},
    }
    verdict = metrics.evaluate([], gates=gates, baseline=baseline)
    assert verdict["recall_delta"] == 1
    assert not verdict["passed"]


def test_baseline_flag_rate_is_honoured():
    results = [
        _result(["harness", "benign"], 0,
                '{"scanned": 100, "flagged": 6, "flag_rate": {"estimate": 0.06}}'),
    ]
    verdict = metrics.evaluate(results, baseline={"benign_flag_rate": 0.05})
    assert not verdict["passed"]
