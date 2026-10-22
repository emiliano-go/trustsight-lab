import gzip
import json
from pathlib import Path

from lab.features import findings
from lab.labels import contradictions

ROOT = Path(__file__).resolve().parents[2]

PKGBUILD = """\
pkgname=demo-bin
pkgver=1.0
pkgrel=1
install=demo.install
source=("https://example.org/demo-$pkgver.tar.gz")
sha256sums=('SKIP')
"""


def _write(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def test_finding_rows_recompute_evidence_and_contradictions(tmp_path):
    extract = tmp_path / "extract"
    _write(extract / "packages.jsonl.gz", [{"id": 1, "name": "demo-bin"}])
    _write(
        extract / "pkgbuild_snapshots.jsonl.gz",
        [
            {
                "package_name": "demo-bin",
                "pkgbuild_text": PKGBUILD,
                "install_text": None,
                "file_names": ["PKGBUILD", "demo.install"],
                "captured_at": "2026-10-01T00:30:00+00:00",
            }
        ],
    )
    _write(
        extract / "analysis_history.jsonl.gz",
        [
            {
                "id": 10,
                "package_id": 1,
                "timestamp": "2026-10-01",
                "final_score": 20,
                "config_fingerprint": "sha256:x",
                "score_breakdown": [
                    {
                        "rule_id": "C024",
                        "severity": "MEDIUM",
                        "weight": 15,
                        "reason": (
                            "demo-bin.install is shipped but install= names "
                            "demo.install, not it; pacman never runs this hook"
                        ),
                        "file": "demo-bin.install",
                        "line": None,
                    }
                ],
            }
        ],
    )
    rows = findings.build(extract, root=ROOT)
    assert len(rows) == 1
    assert rows[0]["checks"]["phantom_install"]["phantom"] is True
    annotated = contradictions.annotate([{**rows[0], "label": "unlabelled"}])
    assert annotated[0]["contradiction"]["reason"] == "phantom_install"
