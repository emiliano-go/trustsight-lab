from pathlib import Path

from lab.features import evidence, recipe_checks

ROOT = Path(__file__).resolve().parents[2]

SAME = """\
pkgname=odinls-bin
pkgver=1.0
pkgrel=1
url="https://github.com/dnbln/ols"
provides=("ols")
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')
"""

DIFFERENT = """\
pkgname=something-bin
pkgver=1.0
pkgrel=1
url="https://example.org/something"
provides=("firefox")
source=("$url/x.tar.gz")
sha256sums=('SKIP')
"""


def setup_module():
    evidence.ensure_imports(ROOT)


def test_same_upstream_matches_the_provided_project_repo():
    recipe = evidence.parse(SAME)
    result = recipe_checks.same_upstream(recipe)
    assert result["same_upstream"] is True
    assert result["matched"] == "ols"


def test_a_different_project_does_not_match():
    recipe = evidence.parse(DIFFERENT)
    result = recipe_checks.same_upstream(recipe)
    assert result["same_upstream"] is False


def test_checksum_only_shape():
    assert recipe_checks.checksum_only(
        {"checksum_behavior": "checksum_added_or_changed"}
    )["checksum_only"] is True
    assert recipe_checks.checksum_only(
        {"checksum_behavior": "checksum_added_or_changed",
         "added_urls": ["https://example.org/x"]}
    )["checksum_only"] is False
