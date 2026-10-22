"""Persist one small, reproducible run per pinned instrument.

The bulk reports stay gitignored: they are working data. What is committed is
a compact summary and its markdown rendering, stamped with every pin a number
depends on. A result that cannot be reproduced from the pins is not a result.

`check` is the drift gate: a candidate whose patch no longer applies, a
reproducer that disappeared, or a missing run for the current pins fails
before the lab publishes anything.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .pins import Pins, read_pins

SCHEMA_VERSION = 1
RUNS = Path("runs")


def pin_slug(pins: Pins) -> str:
    """One directory name per instrument, readable and filesystem safe."""

    version = (pins.trustsight_version or "unknown").lstrip("vV")
    sha = (pins.trustsight_sha or "unknown")[:7]
    safe = "".join(
        char if char.isalnum() or char in "._-" else "-" for char in version
    )
    return f"{safe}-{sha}"


def stamp(pins: Pins, summary: dict, *, now: str | None = None) -> dict:
    """Attach the pins and generation time to a summary."""

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now or datetime.now(UTC).isoformat(),
        "pins": pins.to_dict(),
        **summary,
    }


def write_run(
    pins: Pins,
    summary: dict,
    report: str,
    *,
    runs_dir: Path = RUNS,
) -> Path:
    """Write `runs/<pin>/summary.json` and `report.md`, returning the dir."""

    directory = runs_dir / pin_slug(pins)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text(
        json.dumps(stamp(pins, summary), indent=2, sort_keys=True) + "\n"
    )
    (directory / "report.md").write_text(report)
    return directory


def _candidate_failures(
    candidates: Path,
    trustsight_root: Path,
    harness_root: Path,
) -> list[str]:
    failures: list[str] = []
    if not candidates.is_dir():
        return failures
    for path in sorted(candidates.glob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            failures.append(f"{path.name}: unreadable ({exc})")
            continue
        if doc.get("status") != "ready":
            continue
        for report in doc.get("reproducers") or []:
            triage = harness_root / report / "triage.json"
            if not triage.is_file():
                failures.append(f"{path.name}: reproducer missing: {triage}")
        patch = doc.get("patch") or ""
        if not patch:
            failures.append(f"{path.name}: ready candidate has no patch")
            continue
        checked = subprocess.run(
            ["git", "-C", str(trustsight_root), "apply", "--check",
             "--whitespace=nowarn", "-"],
            input=patch,
            text=True,
            capture_output=True,
            check=False,
        )
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout).strip().splitlines()
            failures.append(
                f"{path.name}: patch does not apply ({detail[-1] if detail else 'unknown'})"
            )
    return failures


def check(
    root: Path,
    *,
    runs_dir: Path = RUNS,
    candidates: Path = Path("reports/candidates"),
) -> list[str]:
    """Return every reason the current result is not reproducible."""

    pins = read_pins(root)
    failures: list[str] = []
    directory = runs_dir / pin_slug(pins)
    summary_path = directory / "summary.json"
    if not summary_path.is_file():
        failures.append(
            f"no committed run for pins {pin_slug(pins)}: {summary_path}"
        )
    else:
        try:
            saved = json.loads(summary_path.read_text())
        except ValueError as exc:
            failures.append(f"{summary_path}: unreadable ({exc})")
        else:
            if saved.get("pins") != pins.to_dict():
                failures.append(
                    f"{summary_path}: pins drifted from the checkout"
                )
    failures.extend(
        _candidate_failures(
            candidates, root / "trustsight", root / "trustsight-harness"
        )
    )
    return failures
