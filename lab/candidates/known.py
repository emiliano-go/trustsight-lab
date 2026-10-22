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
        "reproducers": ["benign/fp-2026-10-16"],
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
        "reproducers": ["benign/fp-2026-10-16"],
    },
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
    reproducers: list[str] = field(default_factory=list)


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
        path = trustsight_root / relative
        text = path.read_text()
        if old not in text:
            raise ValueError(f"template anchor drifted in {relative}")
        patches.append(_unified(relative, text, text.replace(old, new, 1)))
        if relative not in targets:
            targets.append(relative)
    return Candidate(
        id=template["id"],
        rule_id="",
        predicate="",
        lever=template["lever"],
        targets=targets,
        patch="".join(patches),
        rationale=template["rationale"],
        tp_twin=template["tp_twin"],
        reproducers=list(template.get("reproducers") or []),
    )


def for_predicate(
    rule_id: str, predicate: str, trustsight_root: Path
) -> Candidate | None:
    template = TEMPLATES.get((rule_id, predicate))
    if template is None:
        return None
    candidate = render(template, trustsight_root)
    candidate.rule_id = rule_id
    candidate.predicate = predicate
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
        "reproducers": candidate.reproducers,
    }
