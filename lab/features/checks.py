"""Flatten the deterministic evidence checks into model-ready fields.

The checks are produced by ``harness/fp_triage.py`` and stored beside every
adjudicated finding. A field is only present when the check ran; ``None``
means "not established", never false.
"""

from __future__ import annotations


def _get(checks: dict, name: str) -> dict | None:
    value = (checks or {}).get(name)
    return value if isinstance(value, dict) else None


def flatten(checks: dict | None) -> dict[str, object]:
    checks = checks or {}
    phantom = _get(checks, "phantom_install")
    url = _get(checks, "url_in_source")
    header = _get(checks, "header_match")
    skip = _get(checks, "skip_context")
    out: dict[str, object] = {}
    if phantom is not None:
        out["phantom"] = phantom.get("phantom")
        out["declared_install"] = phantom.get("declared_install")
        out["install_in_source"] = phantom.get("in_source_array")
    if url is not None:
        out["misclassified"] = url.get("misclassified")
        out["url_in_source"] = url.get("in_source_array")
    if header is not None:
        out["header_match"] = header.get("header_match")
    if skip is not None:
        out["skip_remote"] = skip.get("remote_skip_count")
        out["skip_local"] = skip.get("local_skip_count")
        out["skip_unknown"] = skip.get("unknown_skip_count")
        out["skip_complete"] = skip.get("complete")
    return out


def signature(fields: dict[str, object]) -> str:
    """A stable, human-readable key for one evidence shape."""

    parts = [f"{key}={fields[key]}" for key in sorted(fields)]
    return "|".join(parts) or "no-evidence"
