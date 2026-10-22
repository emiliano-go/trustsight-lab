from pathlib import Path

from lab.features import evidence
from lab.labels import contradictions

ROOT = Path(__file__).resolve().parents[2]

PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
install=demo.install
source=("https://example.org/demo-$pkgver.tar.gz")
sha256sums=('SKIP')
"""


def setup_module():
    evidence.ensure_imports(ROOT)


def test_phantom_install_is_detected_without_the_new_filename():
    finding = {
        "reason": "demo-bin.install is shipped but install= names demo.install, not it",
        "file": "demo-bin.install",
    }
    checks = evidence.recompute(
        finding, PKGBUILD, file_names={"PKGBUILD", "demo.install"}
    )
    assert checks["phantom_install"]["phantom"] is True
    assert checks["phantom_install"]["declared_install"] == "demo.install"


def test_a_present_install_file_is_not_phantom():
    finding = {"reason": "demo.install", "file": "demo.install"}
    checks = evidence.recompute(
        finding, PKGBUILD, file_names={"PKGBUILD", "demo.install"}
    )
    assert checks["phantom_install"]["phantom"] is False


NOW = "2026-10-01T12:00:00+00:00"
SOON = "2026-10-01T12:30:00+00:00"
STALE = "2026-10-03T12:00:00+00:00"


def test_contradiction_labels_come_from_evidence_only():
    assert contradictions.derive(
        {"phantom_install": {"phantom": True}},
        rule_id="C024", timestamp=NOW, captured_at=SOON,
    )["reason"] == "phantom_install"
    assert contradictions.derive(
        {"url_in_source": {"misclassified": True}},
        rule_id="NOVELTY", timestamp=NOW, captured_at=SOON,
    )["reason"] == "url_in_source_misclassified"
    assert contradictions.derive(
        {"skip_context": {
            "remote_skip_count": 0, "local_skip_count": 2, "complete": True,
        }},
        rule_id="H001", timestamp=NOW, captured_at=SOON,
    )["reason"] == "local_skip_only"
    assert contradictions.derive(
        {"phantom_install": {"phantom": None}},
        timestamp=NOW, captured_at=SOON,
    ) is None
    assert contradictions.derive(
        {"skip_context": {
            "remote_skip_count": 0, "local_skip_count": 2, "complete": True,
        }},
        rule_id="R054", timestamp=NOW, captured_at=SOON,
    ) is None


def test_a_stale_snapshot_produces_no_label():
    assert contradictions.derive(
        {"url_in_source": {"misclassified": True}},
        rule_id="NOVELTY", timestamp=NOW, captured_at=STALE,
    ) is None
