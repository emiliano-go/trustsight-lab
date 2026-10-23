import gzip
import json
import sqlite3
from pathlib import Path

from lab.features import findings
from lab.ingest import watcher
from lab.labels import build, contradictions


def _history_db(tmp_path: Path) -> Path:
    db = tmp_path / "watcher.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY, package_id INTEGER, timestamp TEXT,
            old_version TEXT, new_version TEXT, old_commit TEXT, new_commit TEXT,
            final_score INTEGER, raw_diff_blob BLOB, fact_json TEXT)"""
    )
    rows = [
        (1, 7, "2026-10-22T12:00:00", "1", "2", "", "", 30, None,
         json.dumps({"score_breakdown": [{"rule_id": "H001", "weight": 25}]})),
        (2, 7, "2026-10-22T12:05:00", "1", "2", "", "", 0, None,
         json.dumps({"score_breakdown": [{"rule_id": "H015", "weight": 0}]})),
    ]
    conn.executemany("INSERT INTO analysis_history VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return db


def test_extract_keeps_only_score_bearing_history(tmp_path):
    db = _history_db(tmp_path)
    out = tmp_path / "out"
    manifest = watcher.extract(db, out, ("analysis_history",), min_weight=1)
    assert manifest["tables"]["analysis_history"]["rows"] == 1
    with gzip.open(out / "analysis_history.jsonl.gz", "rt") as handle:
        row = json.loads(handle.readline())
    assert row["id"] == 1


def test_maintainer_adoption_is_a_real_signal_not_a_contradiction():
    rows = [{
        "rule_id": "NOVELTY",
        "first_seen": False,
        "novelty_context": {
            "maintainer_first_seen_for_this_package": True,
            "url_first_seen_globally": False,
            "url_first_seen_in_this_package": False,
        },
        "checks": {},
    }]
    out = contradictions.annotate(rows)[0]
    assert "contradiction" not in out
    assert out["signal"]["label"] == "tp_benign"
    assert out["signal"]["reason"] == "maintainer_adoption"


def test_merge_findings_keeps_the_two_label_classes_apart(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text("\n".join([
        json.dumps({"rule_id": "H001", "contradiction": {"label": "contradiction_fp"}}),
        json.dumps({"rule_id": "NOVELTY", "signal": {"label": "tp_benign",
                                                      "reason": "maintainer_adoption"}}),
        json.dumps({"rule_id": "C024"}),
    ]) + "\n")
    rows = build.merge_findings([], path)
    assert [(row["rule_id"], row["label"]) for row in rows] == [
        ("H001", "weak_fp"),
        ("NOVELTY", "tp_benign"),
    ]


def test_source_changes_are_derived_from_the_raw_diff():
    import sys

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "trustsight" / "src"))
    try:
        from trustsight.differ._sources import extract_urls_from_diff  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("the pinned TrustSight source is not importable")
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -3,2 +3,2 @@\n"
        " source=('https://example.org/a.tar.gz')\n"
        "-sha256sums=('aaaa')\n"
        "+sha256sums=('bbbb')\n"
    )
    change = findings._source_changes({"raw_diff": diff})
    assert change is not None
    assert "checksum_behavior" in change


def test_remote_gzip_command_is_quoted_once():
    argv = watcher._remote_gzip_argv("vps", "trustsight-watch", "/data/x.db")
    assert argv[:2] == ["ssh", "vps"]
    assert argv[2].startswith("docker exec trustsight-watch sh -c ")
    assert "gzip -1 -c /data/x.db" in argv[2]
