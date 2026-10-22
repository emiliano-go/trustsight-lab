"""Deterministic recipe checks that the pinned harness does not yet expose.

Each check answers one question the FP reports needed and the analyzer could
answer without fetching anything. They are features for mining, not verdicts:
a candidate still has to pass the counterfactual gates.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

_SUFFIX = re.compile(r"-(?:bin|git|appimage|wine|nightly|dev)$", re.IGNORECASE)
_NAME = re.compile(r"[^A-Za-z0-9@._+-]+")


def _clean(value: object) -> str:
    text = str(value or "").strip().strip("\"'")
    return text.split("=", 1)[0].strip().lower()


def _repo(url: object) -> str:
    text = str(url or "").strip().strip("\"'")
    if not text:
        return ""
    parsed = urlparse(text)
    path = parsed.path if parsed.scheme else text
    tail = path.rstrip("/").rsplit("/", 1)[-1]
    tail = tail.removesuffix(".git")
    return _NAME.sub("-", tail).strip("-").lower()


def normalise_name(value: object) -> str:
    text = _clean(value)
    text = _NAME.sub("-", text).strip("-").lower()
    return _SUFFIX.sub("", text)


def same_upstream(recipe) -> dict:
    """True when the package provides a name its own ``url=`` names.

    The FP shape is a repackage that provides the upstream project's name:
    ``odinls-bin`` provides ``ols`` and its ``url`` points at the ``ols``
    repository. That is normal repackaging, not a dependency hijack.
    """

    provided = [
        _clean(item)
        for item in (recipe.arrays.get("provides") or ())
    ]
    provided = [item for item in provided if item]
    url = recipe.scalars.get("url", "")
    repo = _repo(url)
    names = {normalise_name(item) for item in provided}
    own = normalise_name(
        recipe.scalars.get("pkgname")
        or (recipe.arrays.get("pkgname") or [""])[0]
    )
    match = False
    matched = ""
    if repo:
        if repo in names or normalise_name(repo) in names:
            match = True
            matched = repo
        elif own and own in names:
            match = True
            matched = own
    return {
        "provided": provided,
        "url_repo": repo,
        "same_upstream": match,
        "matched": matched,
    }


def checksum_only(source_changes: dict | None) -> dict:
    """A checksum moved while no source URL moved.

    This is the shape C001 has to separate from a tampered checksum. It is
    not proof of either outcome; it only says which discriminator is missing.
    """

    changes = source_changes or {}
    added = changes.get("added_urls") or []
    removed = changes.get("removed_urls") or []
    behavior = changes.get("checksum_behavior") or ""
    return {
        "checksum_moved": behavior in (
            "checksum_added_or_changed",
            "checksum_array_removed",
        ),
        "sources_stable": not added and not removed,
        "checksum_only": bool(
            behavior in ("checksum_added_or_changed", "checksum_array_removed")
            and not added
            and not removed
        ),
    }
