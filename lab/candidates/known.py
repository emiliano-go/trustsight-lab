"""Deterministic fixes for the predicates the miner recovers.

A template is a list of literal replacements against the pinned checkout. The
unified diff is generated from that checkout so it applies cleanly and is
reviewed as a normal patch. A template must carry a true-positive twin: the
shape that still has to fire after the guard.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from .extra import EXTRA as _EXTRA

#: A patch may only touch watcher rule code or its tests, the same surface
#: the harness code_fixes gate allows.
ALLOWED_PREFIXES = ("src/trustsight/", "tests/")
MAX_PATCH_CHARS = 32 * 1024
MAX_ADDED_LINES = 400

#: (rule, predicate) -> fix. The predicate names come from predicate_miner.
TEMPLATES: dict[tuple[str, str], dict] = {
    ("C024", "phantom=true"): {
        "id": "C024-phantom-install",
        "lever": "evidence_guard",
        "rationale": (
            "A diff header can name a .install file that has since been "
            "renamed out of the snapshot. When the tree was read, absence "
            "there is decisive: pacman cannot run a hook that does not exist."
        ),
        "edits": [
            (
                "src/trustsight/analysis/structural/_checksums.py",
                """\
        for file in scope_doc.files:
            if not file.path.endswith(".install") or file.status == "removed":
                continue
            base = file.path.rsplit("/", 1)[-1]
""",
                """\
        tree_names = (
            {str(path).rsplit("/", 1)[-1] for path, _body in tree_manifest}
            if tree_manifest else None
        )
        for file in scope_doc.files:
            if not file.path.endswith(".install") or file.status == "removed":
                continue
            base = file.path.rsplit("/", 1)[-1]
            if tree_names is not None and base not in tree_names:
                continue
""",
            )
        ],
        "tp_twin": "an added .install that is present in the tree and not declared still fires",
        "reproducers": [],
    },
    ("H001", "local_skip_only"): {
        "id": "H001-local-skip",
        "lever": "evidence_guard",
        "rationale": (
            "A local source is a file committed beside the recipe; the AUR "
            "git tree is its integrity record, so a SKIP over it has nothing "
            "to verify upstream. Only remote and dynamic sources need a hash."
        ),
        "edits": [
            (
                "src/trustsight/differ/_sources.py",
                """\
def _recipe_skip_justification(recipe_text: str) -> str:
""",
                """\
_SUM_ARRAY_RE = re.compile(
    r"(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_.*)?$"
)
_URL_ENTRY_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*://|^[A-Za-z][A-Za-z0-9+.-]*::"
)


def _all_skips_are_local(recipe) -> bool:
    # Every SKIP must cover a file committed beside the recipe.
    seen = False
    for name, sums in recipe.arrays.items():
        match = _SUM_ARRAY_RE.match(name)
        if not match:
            continue
        sources = recipe.arrays.get("source" + (match.group(1) or ""), ())
        for index, checksum in enumerate(sums):
            if str(checksum).strip().strip("'").strip('"') != "SKIP":
                continue
            seen = True
            source = sources[index] if index < len(sources) else None
            if source is None:
                return False
            target = str(source).strip().split("::", 1)[-1]
            target = target.strip().strip("'").strip('"')
            if _URL_ENTRY_RE.match(target) or target.startswith("/"):
                return False
            if ".." in target.split("/") or "$" in target:
                return False
    return seen


def _recipe_skip_justification(recipe_text: str) -> str:
""",
            ),
            (
                "src/trustsight/differ/_sources.py",
                """\
    keys = list(recipe.arrays) + list(recipe.scalars)
    if any(str(k).upper().startswith("DKMS") for k in keys):
        return "vcs source"
    return ""
""",
                """\
    keys = list(recipe.arrays) + list(recipe.scalars)
    if any(str(k).upper().startswith("DKMS") for k in keys):
        return "vcs source"
    if _all_skips_are_local(recipe):
        return "local file"
    return ""
""",
            ),
        ],
        "tp_twin": "a remote source set to SKIP with no signature still fires H001",
        "reproducers": [],
    },
    ("NOVELTY", "misclassified=true"): {
        "id": "NOVELTY-url-metadata",
        "lever": "normalization",
        "rationale": (
            "url= is the homepage a reader follows, not a source the build "
            "fetches. Scoring it as a source URL made a homepage edit look "
            "like a novel fetch target."
        ),
        "edits": [
            (
                "src/trustsight/differ/_sources.py",
                '_URL_TOKEN_RE = re.compile(r"https?://[^\\s\\\'\\\"\\)]+")\n',
                (
                    '_URL_TOKEN_RE = re.compile(r"https?://[^\\s\\\'\\\"\\)]+")\n'
                    '_URL_SCALAR_RE = re.compile(r"\\s*url\\s*=")\n'
                ),
            ),
            (
                "src/trustsight/differ/_sources.py",
                """\
        resolved = resolve_text(body, new_table if prefix == "+" else old_table)
        if "http" not in resolved:
            continue
""",
                """\
        resolved = resolve_text(body, new_table if prefix == "+" else old_table)
        if "http" not in resolved:
            continue
        if _URL_SCALAR_RE.match(resolved):
            continue
""",
            ),
        ],
        "tp_twin": "a URL added to source=() is still a novel source",
        "reproducers": [],
    },
}


TEMPLATES.update(_EXTRA)

# The same normalisation fixes the synthetic SOURCE_BUCKET entry: a `url=`
# line was harvested as a source URL and opened a new host bucket.  Keep the
# rule id distinct so the ledger and report can attribute the fix.
TEMPLATES[("SOURCE_BUCKET", "misclassified=true")] = {
    **TEMPLATES[("NOVELTY", "misclassified=true")],
    "id": "SOURCE_BUCKET-url-metadata",
}
TEMPLATES[("H003", "misclassified=true")] = {
    **TEMPLATES[("NOVELTY", "misclassified=true")],
    "id": "H003-url-metadata",
}

# H098 is a cluster over D004/H064.  When those members are same-upstream
# repackaging, guarding the members removes the cluster; the patch is the
# same one, and the fixture proves the cluster disappears with it.
TEMPLATES[("H098", "same_upstream=true")] = {
    **TEMPLATES[("H064", "same_upstream=true")],
    "id": "H098-same-upstream",
    "rationale": (
        "The H098 cluster is composed of D004/H064 on a package that "
        "provides its own upstream name; guarding those members removes the "
        "cluster."
    ),
}


@dataclass
class Candidate:
    id: str
    rule_id: str
    predicate: str
    lever: str
    targets: list[str]
    patch: str
    rationale: str
    tp_twin: str
    linked_findings: list[str] = field(default_factory=list)
    reproducers: list[str] = field(default_factory=list)


def check_target(relative: str) -> str:
    if not isinstance(relative, str) or not relative:
        raise ValueError("candidate target must be a non-empty string")
    if relative.startswith("/") or "\\" in relative or ".." in relative.split("/"):
        raise ValueError(f"candidate target escapes the repo: {relative!r}")
    if not relative.startswith(ALLOWED_PREFIXES):
        raise ValueError(
            f"candidate target outside {ALLOWED_PREFIXES}: {relative!r}"
        )
    return relative


def check_patch(patch: str) -> str:
    if len(patch) > MAX_PATCH_CHARS:
        raise ValueError(f"candidate patch exceeds {MAX_PATCH_CHARS} chars")
    added = sum(
        1 for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    if added == 0:
        raise ValueError("candidate patch adds no lines")
    if added > MAX_ADDED_LINES:
        raise ValueError(f"candidate patch exceeds {MAX_ADDED_LINES} added lines")
    return patch


def _unified(relative: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
            n=3,
        )
    )


def render(template: dict, trustsight_root: Path) -> Candidate:
    patches = []
    targets = []
    for relative, old, new in template["edits"]:
        check_target(relative)
        path = trustsight_root / relative
        text = path.read_text()
        if old not in text:
            raise ValueError(f"template anchor drifted in {relative}")
        patches.append(_unified(relative, text, text.replace(old, new, 1)))
        if relative not in targets:
            targets.append(relative)
    patch = "".join(patches)
    check_patch(patch)
    return Candidate(
        id=template["id"],
        rule_id="",
        predicate="",
        lever=template["lever"],
        targets=targets,
        patch=patch,
        rationale=template["rationale"],
        tp_twin=template["tp_twin"],
        linked_findings=list(template.get("linked_findings") or []),
        reproducers=list(template.get("reproducers") or []),
    )


#: The miner names the same shape with a few equivalent predicates.
ALIASES = {
    ("H001", "local_skip>0"): ("H001", "local_skip_only"),
    ("H001", "remote_skip=0 and local_skip>0"): ("H001", "local_skip_only"),
}


def for_predicate(
    rule_id: str, predicate: str, trustsight_root: Path
) -> Candidate | None:
    key = (rule_id, predicate)
    key = ALIASES.get(key, key)
    template = TEMPLATES.get(key)
    if template is None:
        return None
    candidate = render(template, trustsight_root)
    candidate.rule_id = key[0]
    candidate.predicate = key[1]
    return candidate


def to_dict(candidate: Candidate) -> dict:
    return {
        "id": candidate.id,
        "rule_id": candidate.rule_id,
        "predicate": candidate.predicate,
        "lever": candidate.lever,
        "targets": candidate.targets,
        "patch": candidate.patch,
        "rationale": candidate.rationale,
        "tp_twin": candidate.tp_twin,
        "linked_findings": candidate.linked_findings,
        "reproducers": candidate.reproducers,
    }
