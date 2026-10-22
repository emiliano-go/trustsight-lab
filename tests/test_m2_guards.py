"""Targeted FP/TP twins for the M2 guards.

The probe runs in the pinned interpreter with the patched source first on
PYTHONPATH, so it measures the same code the worktree would import. Each
case asserts both directions: the false positive is gone and the true
positive twin still fires.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

from lab.candidates import known
from lab.validate import runner

ROOT = Path(__file__).resolve().parents[2]
TRUSTSIGHT = ROOT / "trustsight"
PYTHON = TRUSTSIGHT / ".venv" / "bin" / "python"

STRUCTURAL = r"""
import json
from trustsight.analysis.structural import _structural_findings
from trustsight.differ._sources import extract_urls_from_diff

pkg_install = '''pkgname=demo
pkgver=1.0
pkgrel=1
install=demo.install
source=('demo.tar.gz')
sha256sums=('abc')
'''
c024_diff = '''diff --git a/demo-bin.install b/demo-bin.install
new file mode 100644
--- /dev/null
+++ b/demo-bin.install
@@ -0,0 +1 @@
+post_install() { :; }
'''
def rules(diff, current, tree):
    changes = extract_urls_from_diff(diff)
    found = _structural_findings(
        diff, changes, package_name="demo", current_text=current,
        tree_manifest=tree,
    )
    return [(item["rule_id"], item["severity"]) for item in found]

base = [("PKGBUILD", b""), ("demo.install", b"")]
h001_diff = '''--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,4 @@
 pkgname=demo
-source=('x')
-sha256sums=('abc')
+source=('fix.patch')
+sha256sums=('SKIP')
'''
h001_local = "pkgname=demo\nsource=('fix.patch')\nsha256sums=('SKIP')\n"
h001_remote = "pkgname=demo\nsource=('https://example.org/x.tar.gz')\nsha256sums=('SKIP')\n"
print(json.dumps({
    "c024_absent": rules(c024_diff, pkg_install, base),
    "c024_present": rules(c024_diff, pkg_install, base + [("demo-bin.install", b"")]),
    "h001_local": rules(h001_diff, h001_local, None),
    "h001_remote": rules(h001_diff, h001_remote, None),
}))
"""


def _probe(tree: Path) -> dict:
    env = {"PYTHONPATH": str(tree / "src"), "PATH": "/usr/bin:/bin"}
    completed = subprocess.run(
        [str(PYTHON), "-c", STRUCTURAL],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    import json

    return json.loads(completed.stdout)


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_c024_guard_keeps_the_true_positive_twin():
    candidate = known.for_predicate("C024", "phantom=true", TRUSTSIGHT)
    tree = runner.worktree(TRUSTSIGHT, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(tree, candidate.patch)
        result = _probe(tree)
    finally:
        runner.remove_worktree(TRUSTSIGHT, tree)
    assert result["c024_absent"] == []
    assert ["C024", "MEDIUM"] in result["c024_present"]


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_h001_guard_keeps_the_remote_skip_twin():
    candidate = known.for_predicate("H001", "local_skip_only", TRUSTSIGHT)
    tree = runner.worktree(TRUSTSIGHT, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(tree, candidate.patch)
        result = _probe(tree)
    finally:
        runner.remove_worktree(TRUSTSIGHT, tree)
    assert ["H001", "INFO"] in result["h001_local"]
    assert ["H001", "HIGH"] in result["h001_remote"]
