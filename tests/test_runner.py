import subprocess
from pathlib import Path

from lab.candidates import known
from lab.validate import runner

ROOT = Path(__file__).resolve().parents[2]


def test_worktree_and_patch_are_isolated(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@example.org"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "a.txt").write_text("one\n")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)

    tree = runner.worktree(repo, tmp_path / "tree")
    patch = "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+two\n"
    runner.apply_patch(tree, patch)
    assert (tree / "a.txt").read_text() == "two\n"
    assert (repo / "a.txt").read_text() == "one\n"
    runner.remove_worktree(repo, tree)


def test_commands_point_the_worker_at_the_patched_src(tmp_path):
    candidate = known.for_predicate("C024", "phantom=true", ROOT / "trustsight")
    commands = runner.build_commands(
        tmp_path / "tree",
        ROOT / "trustsight-harness",
        tier=2,
        benign_corpus=ROOT / "trustsight" / "tests" / "fixtures" / "benign-corpus",
    )
    assert len(commands) == 3
    for command in commands:
        assert str(tmp_path / "tree" / "src") in command.env["PYTHONPATH"]
    assert candidate is not None


def test_tier_three_adds_the_campaign_sweep(tmp_path):
    commands = runner.build_commands(
        tmp_path / "tree",
        ROOT / "trustsight-harness",
        tier=3,
        benign_corpus=ROOT / "trustsight" / "tests" / "fixtures" / "benign-corpus",
    )
    assert any("sweep" in command.argv for command in commands)


def test_link_corpus_only_links_an_existing_corpus(tmp_path):
    source = tmp_path / "source"
    (source / "tests" / "fixtures" / "benign-corpus").mkdir(parents=True)
    tree = tmp_path / "tree"
    tree.mkdir()
    runner.link_corpus(tree, source)
    assert (tree / "tests" / "fixtures" / "benign-corpus").is_symlink()
    empty = tmp_path / "empty"
    empty.mkdir()
    runner.link_corpus(empty, empty)
    assert not (empty / "tests" / "fixtures" / "benign-corpus").exists()
