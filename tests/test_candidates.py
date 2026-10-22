import subprocess
from pathlib import Path

from lab.candidates import known

ROOT = Path(__file__).resolve().parents[2]
TRUSTSIGHT = ROOT / "trustsight"


def test_known_templates_render_and_apply_cleanly():
    for rule, predicate in (("C024", "phantom=true"), ("NOVELTY", "misclassified=true")):
        candidate = known.for_predicate(rule, predicate, TRUSTSIGHT)
        assert candidate is not None
        assert candidate.patch.startswith("--- a/")
        completed = subprocess.run(
            ["git", "-C", str(TRUSTSIGHT), "apply", "--check", "-"],
            input=candidate.patch,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr


def test_unknown_predicate_has_no_template():
    assert known.for_predicate("R054", "local_skip_only", TRUSTSIGHT) is None
