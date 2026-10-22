"""Additional deterministic templates recovered by the miner.

Kept apart from ``known.py`` so each patch family stays readable. The
predicates are the ones the scale run produced: same-upstream provides, the
H033/H101 double count, and checksum corroboration by a signed baseline.
"""

from __future__ import annotations

SAME_UPSTREAM_HELPER = '''\
def _same_upstream_name(current_text, name):
    # The url= repo is the project this package repackages. Providing that
    # project's name is normal, not a scope expansion.
    if not current_text:
        return False
    from ..recipedoc import parse_recipe

    try:
        recipe = parse_recipe(current_text)
    except Exception:
        return False
    url = str(recipe.scalars.get("url", "")).strip().strip("'").strip('"')
    if not url:
        return False
    tail = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    return tail.lower() == str(name).lower()


def _scope_expansion_findings(diff_text, package_name, config, add,
'''

DEDUP_HELPER = '''\
def _dedup_moved_refs(findings):
    # H101 owns a lost pin; H033 restates the same ref move. Drop H033 when
    # its repo is named by an H101 finding on this analysis.
    owners = [
        finding for finding in findings if finding.get("rule_id") == "H101"
    ]
    if not owners:
        return
    for index in range(len(findings) - 1, -1, -1):
        finding = findings[index]
        if finding.get("rule_id") != "H033":
            continue
        params = finding.get("params") or {}
        repo = str(params.get("repo", ""))
        if repo and any(
            repo in str((owner.get("params") or {}).get(key, ""))
            for owner in owners for key in ("old_url", "new_url")
        ):
            del findings[index]


def _structural_findings(
'''

C001_HELPER = '''\
def _upstream_hash_key(current_text):
    # The corroboration key: source URL, version, checksum. A signed
    # upstream_hash baseline names exactly this triple.
    if not current_text:
        return ""
    from ...recipedoc import parse_recipe

    try:
        recipe = parse_recipe(current_text)
    except Exception:
        return ""
    sources = recipe.arrays.get("source", ())
    sums = recipe.arrays.get("sha256sums", ())
    version = recipe.scalars.get("pkgver", "")
    if len(sources) != 1 or len(sums) != 1 or not version:
        return ""
    url = str(sources[0]).strip().split("::", 1)[-1]
    url = url.strip().strip("'").strip('"')
    checksum = str(sums[0]).strip().strip("'").strip('"')
    if not url or checksum in ("", "SKIP"):
        return ""
    return f"{url}|{version}|{checksum}"


def _upstream_hash_corroborated(current_text):
    key = _upstream_hash_key(current_text)
    if not key:
        return False
    try:
        from ...ioc_baseline import match_upstream_hash

        return bool(match_upstream_hash(key))
    except Exception:
        return False


def _structural_findings(
'''

C001_OLD = r'''        elif not version_moved or capability:
            match = (
                "sha256sums changed but source URLs and pkgver/pkgrel/epoch "
                "unchanged"
                if not version_moved
                else "checksum updated with a version bump that also adds "
                     f"{capability}"
            )
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "HIGH", "integrity", match,
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))
'''

C001_NEW = r'''        elif not version_moved or capability:
            match = (
                "sha256sums changed but source URLs and pkgver/pkgrel/epoch "
                "unchanged"
                if not version_moved
                else "checksum updated with a version bump that also adds "
                     f"{capability}"
            )
            corroborated = _upstream_hash_corroborated(current_text)
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "INFO" if corroborated else "HIGH", "integrity", match,
                weight_override=0 if corroborated else None,
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))
'''

EXTRA = {
    ("H064", "same_upstream=true"): {
        "id": "H064-same-upstream",
        "lever": "new_check",
        "rationale": (
            "A repackage that provides the upstream project's own name is "
            "normal. The url= repo names that project, so it is a "
            "deterministic discriminator, not a naming guess."
        ),
        "edits": [
            (
                "src/trustsight/analysis/dependencies.py",
                "def _scope_expansion_findings(diff_text, package_name, config, add,\n",
                SAME_UPSTREAM_HELPER,
            ),
            (
                "src/trustsight/analysis/dependencies.py",
                '''\
        for name in sorted(added_deps.get(field, ())):
            if is_related_package(name, package_name):
                continue
            if is_established_package(name):
                add("H064", "Provides/Replaces Scope Expansion", "HIGH",
''',
                '''\
        for name in sorted(added_deps.get(field, ())):
            if is_related_package(name, package_name):
                continue
            if _same_upstream_name(current_text, name):
                continue
            if is_established_package(name):
                add("H064", "Provides/Replaces Scope Expansion", "HIGH",
''',
            ),
        ],
        "tp_twin": "providing a different project's name still fires H064",
        "reproducers": [],
    },
    ("D004", "same_upstream=true"): {
        "id": "D004-same-upstream",
        "lever": "new_check",
        "rationale": (
            "A repackage that provides the upstream project's own name is "
            "normal. The url= repo names that project, so it is a "
            "deterministic discriminator, not a naming guess."
        ),
        "edits": [
            (
                "src/trustsight/analysis/dependencies.py",
                "def _scope_expansion_findings(diff_text, package_name, config, add,\n",
                SAME_UPSTREAM_HELPER,
            ),
            (
                "src/trustsight/analysis/dependencies.py",
                '''\
            for name in sorted(added_deps.get(field, ())):
                if is_related_package(name, package_name):
                    continue
                if is_established_package(name):
                    add("D004", "Dependency Hijack Via Provides", "HIGH", "dependency",
''',
                '''\
            for name in sorted(added_deps.get(field, ())):
                if is_related_package(name, package_name):
                    continue
                if _same_upstream_name(current_text, name):
                    continue
                if is_established_package(name):
                    add("D004", "Dependency Hijack Via Provides", "HIGH", "dependency",
''',
            ),
        ],
        "tp_twin": "providing a different project's name still fires D004",
        "reproducers": [],
    },
    ("H101", "ref_double_count=true"): {
        "id": "H101-dedup-H033",
        "lever": "dedup",
        "rationale": (
            "H033 and H101 describe the same ref move on one analysis. "
            "Counting both charges the diff twice for one fact."
        ),
        "edits": [
            (
                "src/trustsight/analysis/structural/_engine.py",
                "def _structural_findings(\n",
                DEDUP_HELPER,
            ),
            (
                "src/trustsight/analysis/structural/_engine.py",
                '''\
    _ioc_findings(diff_text, package_name, config or {}, add,
                  current_text=current_text)

    return findings
''',
                '''\
    _ioc_findings(diff_text, package_name, config or {}, add,
                  current_text=current_text)
    _dedup_moved_refs(findings)

    return findings
''',
            ),
        ],
        "tp_twin": "an H033 with no matching H101 still fires",
        "reproducers": [],
    },
    ("C001", "checksum_only=true"): {
        "id": "C001-upstream-hash",
        "lever": "new_check",
        "rationale": (
            "Without upstream data a changed checksum cannot be separated "
            "from a corrected one. A signed upstream_hash baseline supplies "
            "that fact without fetching a declared URL."
        ),
        "edits": [
            (
                "src/trustsight/iocs.py",
                '    "upstream_repo",\n})',
                '    "upstream_repo", "upstream_hash",\n})',
            ),
            (
                "src/trustsight/ioc_baseline.py",
                (
                    '    if type_ == "upstream_repo":\n'
                    '        return normalize_ioc("upstream_repo", value)\n'
                    '    return None\n'
                ),
                (
                    '    if type_ == "upstream_repo":\n'
                    '        return normalize_ioc("upstream_repo", value)\n'
                    '    if type_ == "upstream_hash":\n'
                    '        return value\n'
                    '    return None\n'
                ),
            ),
            (
                "src/trustsight/ioc_baseline.py",
                '    return match_ioc("upstream_repo", repo)\n',
                (
                    '    return match_ioc("upstream_repo", repo)\n'
                    '\n'
                    '\n'
                    'def match_upstream_hash(value: str) -> list[IocMatch]:\n'
                    '    """Active upstream_hash entries for one URL, version, checksum triple."""\n'
                    '    return match_ioc("upstream_hash", value)\n'
                ),
            ),
            (
                "src/trustsight/analysis/structural/_engine.py",
                "def _structural_findings(\n",
                C001_HELPER,
            ),
            (
                "src/trustsight/analysis/structural/_engine.py",
                C001_OLD,
                C001_NEW,
            ),
        ],
        "tp_twin": "a checksum absent from the baseline still fires C001 HIGH",
        "reproducers": [],
    },
}
