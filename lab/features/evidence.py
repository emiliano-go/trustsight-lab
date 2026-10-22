"""Recompute the deterministic FP evidence against a local snapshot.

Watcher rows often store only the rendered ``match`` string, so the checks
that distinguish a bad trigger from a real finding have to be recomputed.
The checks themselves live in the pinned harness and are reused verbatim;
this module only supplies the recipe and the snapshot file set.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _prepend(path: Path) -> None:
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)


def ensure_imports(root: Path) -> None:
    """Put the pinned TrustSight and harness on ``sys.path`` (idempotent)."""

    _prepend(root / "trustsight" / "src")
    _prepend(root / "trustsight-harness")


def parse(pkgbuild_text: str):
    from trustsight.recipedoc import parse_recipe

    return parse_recipe(pkgbuild_text, file="PKGBUILD")


def prepare(
    pkgbuild_text: str,
    *,
    file_names: set[str] | None = None,
    install_name: str | None = None,
):
    """Parse the recipe and build the snapshot file set once per package.

    ``file_names`` must be the *complete* snapshot listing to make an
    absence claim.  Without it, ``files`` is None and the phantom check
    reports ``None`` instead of calling every unseen file a phantom.
    """

    recipe = parse(pkgbuild_text)
    files = None
    if file_names is not None:
        files = set(file_names)
        files.add("PKGBUILD")
        declared = install_name or recipe.scalars.get("install", "")
        if declared:
            files.add(str(declared).rsplit("/", 1)[-1])
    return recipe, files


def recompute(
    finding: dict,
    pkgbuild_text: str,
    *,
    file_names: set[str] | None = None,
    install_name: str | None = None,
    recipe=None,
    files: set[str] | None = None,
) -> dict:
    """Return the four checks for one finding.

    ``file_names`` is the snapshot's file set when the caller has it.  The
    PKGBUILD is always present; an ``install=`` target is added from the
    parsed recipe unless the caller names it explicitly.  When the set is
    unknown, pass ``None`` and the phantom check reports ``None`` rather than
    guessing.
    """

    from harness.fp_triage import (
        check_header_match,
        check_phantom_install,
        check_skip_context,
        check_url_in_source,
    )

    if recipe is None:
        recipe, prepared_files = prepare(
            pkgbuild_text, file_names=file_names, install_name=install_name
        )
        files = files if files is not None else prepared_files
    if files is None:
        phantom = check_phantom_install(finding, set(), recipe)
        phantom.update({"exists_in_aur": None, "phantom": None})
    else:
        phantom = check_phantom_install(finding, files, recipe)
    return {
        "phantom_install": phantom,
        "url_in_source": check_url_in_source(finding, recipe),
        "header_match": check_header_match(finding),
        "skip_context": check_skip_context(recipe, files),
    }
