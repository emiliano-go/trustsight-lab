import gzip
import json
import sqlite3
from pathlib import Path

from lab.ingest import corpora, reports, watcher
from lab.labels import build

ROOT = Path(__file__).resolve().parents[2]


def test_fp_report_labels_are_counted():
    rows = reports.load_reports(ROOT / "trustsight-harness")
    verdicts = {}
    for row in rows:
        verdicts[row["verdict"]] = verdicts.get(row["verdict"], 0) + 1
    assert verdicts.get("FP", 0) >= 1
    assert verdicts.get("TP-but-benign", 0) >= 1
    assert all(row["rule_id"] for row in rows)


def test_labels_keep_benign_findings_out_of_the_fp_class():
    rows = build.build(ROOT / "trustsight", ROOT / "trustsight-harness")
    tally = build.counts(rows)
    assert tally["hard_fp"] > 0
    assert tally["tp_benign"] > tally["hard_fp"]
    assert all(row["label"] != "hard_fp" or row["verdict"] == "FP" for row in rows
               if "verdict" in row)


def test_corpus_manifest_matches_the_locked_corpus():
    doc = corpora.manifest(ROOT / "trustsight", ROOT / "trustsight-harness")
    assert doc["counts"]["benign"] == 3739
    assert doc["counts"]["malicious"] == 207
    assert doc["counts"]["bypass"] == 9851
    assert doc["counts"]["ioc_baselines"] == 3


def test_extract_normalises_history(tmp_path):
    db = tmp_path / "source.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY, package_id INTEGER NOT NULL, timestamp TEXT,
            old_version TEXT, new_version TEXT, old_commit TEXT, new_commit TEXT,
            final_score INTEGER, raw_diff_blob BLOB, fact_json TEXT);
        CREATE TABLE triggered_rules (
            history_id INTEGER, rule_id TEXT, severity TEXT);
        INSERT INTO analysis_history VALUES
            (1, 7, '2026-10-01', '1', '2', '', '', 25, 'diff',
             '{"config_fingerprint":"sha256:x","adapter":"git","risk":"Medium",
               "final_score":25,"score_breakdown":[{"rule_id":"R007"}],
               "coverage_gaps":[],"source_buckets":{}}');
        INSERT INTO triggered_rules VALUES (1, 'R007', 'MEDIUM');
        """
    )
    conn.commit()
    conn.close()
    snap = watcher.snapshot_local(db, tmp_path / "snap.db")
    manifest = watcher.extract(
        snap, tmp_path / "out", ("analysis_history", "triggered_rules")
    )
    assert manifest["tables"]["analysis_history"]["rows"] == 1
    assert manifest["tables"]["triggered_rules"]["rows"] == 1
    with gzip.open(tmp_path / "out" / "analysis_history.jsonl.gz", "rt") as handle:
        row = json.loads(handle.readline())
    assert row["config_fingerprint"] == "sha256:x"
    assert row["score_breakdown"][0]["rule_id"] == "R007"
    assert "raw_diff" not in row
