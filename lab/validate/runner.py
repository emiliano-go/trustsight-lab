"""Apply a candidate to a throwaway worktree and measure it.

The patched tree is never the operator's checkout and never the harness's
pinned tree: ``git worktree`` gives each candidate its own files, and the
analysis process is pointed at that ``src`` through ``PYTHONPATH`` so the
worker that harness spawns imports the patched code too.

The commands are built here and executed unchanged. A caller can ask for the
plan (``dry_run``) before spending minutes on a corpus replay.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Command:
    argv: list[str]
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    json_out: Path | None = None


def worktree(repo: Path, dest: Path, ref: str = "HEAD") -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "--detach", str(dest), ref],
        check=True,
    )
    return dest


def remove_worktree(repo: Path, dest: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", str(dest)],
        check=False,
    )


def apply_patch(tree: Path, patch: str) -> None:
    subprocess.run(
        ["git", "-C", str(tree), "apply", "--check", "--whitespace=nowarn", "-"],
        input=patch,
        text=True,
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tree), "apply", "--whitespace=nowarn", "-"],
        input=patch,
        text=True,
        check=True,
    )


def _pythonpath(tree: Path, harness_root: Path) -> str:
    return os.pathsep.join([str(tree / "src"), str(harness_root)])


def _interpreter(venv_root: Path) -> str:
    candidate = venv_root / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else "python"


def build_commands(
    tree: Path,
    harness_root: Path,
    *,
    tier: int,
    benign_corpus: Path,
    trustsight_root: Path | None = None,
    reproducers: list[Path] | None = None,
    gates_json: Path | None = None,
) -> list[Command]:
    env = {"PYTHONPATH": _pythonpath(tree, harness_root)}
    harness_python = _interpreter(harness_root)
    tree_python = _interpreter(trustsight_root) if trustsight_root else "python"
    commands: list[Command] = []
    if tier >= 1:
        commands.append(
            Command(
                [harness_python, "-m", "harness", "benign",
                 "--corpus", str(benign_corpus)],
                harness_root,
                env,
            )
        )
        for report in reproducers or []:
            commands.append(
                Command(
                    [harness_python, "-m", "harness", "fp_verify", str(report)],
                    harness_root,
                    env,
                )
            )
    if tier >= 2:
        commands.append(
            Command([harness_python, "-m", "harness", "regression"], harness_root, env)
        )
        gates_argv = [tree_python, "scripts/calibration_gates.py", "--sample", "4"]
        if gates_json is not None:
            gates_argv += ["--json", str(gates_json)]
        commands.append(Command(gates_argv, tree, env, gates_json))
    return commands


def run_commands(commands: list[Command], timeout: int = 1800) -> list[dict]:
    results = []
    for command in commands:
        env = {**os.environ, **command.env}
        completed = subprocess.run(
            command.argv,
            cwd=command.cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        results.append(
            {
                "argv": command.argv,
                "cwd": str(command.cwd),
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-2000:],
            }
        )
    return results


def validate_candidate(
    candidate,
    *,
    trustsight_root: Path,
    harness_root: Path,
    tier: int = 1,
    dry_run: bool = False,
    keep_tree: bool = False,
    baseline: dict | None = None,
) -> dict:
    """Apply *candidate*, then run the tiered suite against the patched tree."""

    scratch = Path(tempfile.mkdtemp(prefix="trustsight-lab-"))
    tree = worktree(trustsight_root, scratch / "tree")
    try:
        apply_patch(tree, candidate.patch)
        reproducers = []
        for report in candidate.reproducers:
            directory = harness_root / report
            target = directory / "triage.json"
            if target.is_file():
                reproducers.append(target)
        gates_json = scratch / "gates.json"
        commands = build_commands(
            tree,
            harness_root,
            tier=tier,
            benign_corpus=trustsight_root / "tests" / "fixtures" / "benign-corpus",
            trustsight_root=trustsight_root,
            reproducers=reproducers,
            gates_json=gates_json if tier >= 2 else None,
        )
        result = {
            "candidate": candidate.id,
            "tier": tier,
            "tree": str(tree),
            "commands": [
                {"argv": command.argv, "cwd": str(command.cwd)}
                for command in commands
            ],
        }
        if not dry_run:
            from . import metrics

            result["results"] = run_commands(commands)
            gates = None
            if gates_json.is_file():
                gates = json.loads(gates_json.read_text())
            result["gates"] = gates
            result["verdict"] = metrics.evaluate(
                result["results"], baseline=baseline, gates=gates
            )
            result["passed"] = result["verdict"]["passed"]
        return result
    finally:
        if not keep_tree:
            remove_worktree(trustsight_root, tree)
