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


HELPER_PROBE = r"""
import json
from trustsight.analysis.dependencies import _same_upstream_name
from trustsight.analysis.structural._engine import _dedup_moved_refs

recipe = '''pkgname=odinls-bin
pkgver=1.0
pkgrel=1
url="https://github.com/dnbln/ols"
provides=('ols')
'''
findings = [
    {"rule_id": "H101", "params": {
        "old_url": "https://github.com/dnbln/ols.git",
        "new_url": "https://github.com/dnbln/ols.git#branch=dev"}},
    {"rule_id": "H033", "params": {"repo": "github.com/dnbln/ols"}},
    {"rule_id": "H033", "params": {"repo": "github.com/other/project"}},
]
_dedup_moved_refs(findings)
print(json.dumps({
    "same": _same_upstream_name(recipe, "ols"),
    "different": _same_upstream_name(recipe, "firefox"),
    "rules": [item["rule_id"] + ":" + str((item.get("params") or {}).get("repo", ""))
              for item in findings],
}))
"""


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_same_upstream_and_dedup_helpers():
    tree = runner.worktree(TRUSTSIGHT, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(
            tree, known.for_predicate("H064", "same_upstream=true", TRUSTSIGHT).patch
        )
        runner.apply_patch(
            tree,
            known.for_predicate("H101", "ref_double_count=true", TRUSTSIGHT).patch,
        )
        env = {"PYTHONPATH": str(tree / "src"), "PATH": "/usr/bin:/bin"}
        completed = subprocess.run(
            [str(PYTHON), "-c", HELPER_PROBE],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        runner.remove_worktree(TRUSTSIGHT, tree)
    assert completed.returncode == 0, completed.stderr
    import json

    result = json.loads(completed.stdout)
    assert result["same"] is True
    assert result["different"] is False
    assert result["rules"] == ["H101:", "H033:github.com/other/project"]


C001_PROBE = r'''
import difflib
from trustsight.analysis.structural import _structural_findings
from trustsight.differ._sources import extract_urls_from_diff
import trustsight.analysis.structural._engine as engine

old = """pkgname=demo
pkgver=1.0
pkgrel=1
source=("https://example.org/demo-1.0.tar.gz")
sha256sums=('aaa')
"""
new = old.replace("'aaa'", "'bbb'")
diff = ''.join(difflib.unified_diff(
    old.splitlines(True), new.splitlines(True), 'a/PKGBUILD', 'b/PKGBUILD'))
changes = extract_urls_from_diff(diff)
out = {}
for value in (False, True):
    engine._upstream_hash_corroborated = lambda text, value=value: value
    findings = engine._structural_findings(
        diff, changes, package_name="demo", current_text=new)
    out[str(value)] = [
        [item["rule_id"], item["severity"], item.get("weight_override")]
        for item in findings if item["rule_id"] == "C001"
    ]
print(__import__("json").dumps(out))
'''


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_c001_corroboration_changes_severity():
    tree = runner.worktree(TRUSTSIGHT, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(
            tree, known.for_predicate("C001", "checksum_only=true", TRUSTSIGHT).patch
        )
        env = {"PYTHONPATH": str(tree / "src"), "PATH": "/usr/bin:/bin"}
        completed = subprocess.run(
            [str(PYTHON), "-c", C001_PROBE],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        runner.remove_worktree(TRUSTSIGHT, tree)
    assert completed.returncode == 0, completed.stderr
    import json

    result = json.loads(completed.stdout)
    assert result["False"][0][1] == "HIGH"
    assert result["True"][0][1] == "INFO"
    assert result["True"][0][2] == 0
