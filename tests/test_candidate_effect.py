import subprocess
import tempfile
from pathlib import Path

import pytest

from lab.candidates import known
from lab.validate import runner

ROOT = Path(__file__).resolve().parents[2]
TRUSTSIGHT = ROOT / "trustsight"
PYTHON = TRUSTSIGHT / ".venv" / "bin" / "python"

DIFF = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,3 @@
-url=https://old.example
+url=https://new.example
 source=("https://example.org/x")
"""

PROBE = """\
from trustsight.differ._sources import extract_urls_from_diff
print(extract_urls_from_diff({diff!r}).added_urls)
"""


def _added_urls(tree: Path) -> str:
    env = {"PYTHONPATH": str(tree / "src"), "PATH": "/usr/bin:/bin"}
    completed = subprocess.run(
        [str(PYTHON), "-c", PROBE.format(diff=DIFF)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_novelty_template_stops_scoring_the_url_scalar():
    candidate = known.for_predicate("NOVELTY", "misclassified=true", TRUSTSIGHT)
    tree = runner.worktree(TRUSTSIGHT, Path(tempfile.mkdtemp()) / "tree")
    try:
        runner.apply_patch(tree, candidate.patch)
        assert _added_urls(tree) == "[]"
    finally:
        runner.remove_worktree(TRUSTSIGHT, tree)


@pytest.mark.skipif(not PYTHON.is_file(), reason="trustsight venv is not present")
def test_unpatched_extractor_still_harvests_the_url_scalar():
    assert "https://new.example" in _added_urls(TRUSTSIGHT)
