"""Pinned inputs: the instrument and every corpus a measurement rests on.

A TrustSight number is only comparable to another if the tool build, the
config fingerprint, and the corpus are all fixed. This module is the one
place that records them. Everything downstream reads the pins, never a
floating checkout.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Pins:
    trustsight_sha: str
    harness_sha: str
    trustsight_version: str
    harness_version: str
    corpus_lock_sha256: str
    corpora: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True
    ).strip()


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_pins(root: Path = DEFAULT_ROOT) -> Pins:
    """Read the sibling checkouts without modifying them."""

    trustsight = root / "trustsight"
    harness = root / "trustsight-harness"
    lock = trustsight / "tests" / "fixtures" / "corpus.lock"
    return Pins(
        trustsight_sha=_git(trustsight, "rev-parse", "HEAD"),
        harness_sha=_git(harness, "rev-parse", "HEAD"),
        trustsight_version=_git(trustsight, "describe", "--tags", "--always"),
        harness_version=_git(harness, "describe", "--tags", "--always"),
        corpus_lock_sha256=_sha256(lock),
        corpora={
            "benign": "trustsight/tests/fixtures/benign-corpus",
            "malicious": "trustsight/tests/fixtures/malicious",
            "fp_reports": "trustsight-harness/benign",
            "bypass_fixtures": "trustsight-harness/fixtures-out",
            "campaigns": "trustsight-harness/campaigns",
            "ioc_baselines": "trustsight/ioc-baselines",
        },
    )


def write_pins(path: Path, pins: Pins) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pins.to_dict(), indent=2, sort_keys=True) + "\n")
