"""Group uncaught bypass diffs by the shape they exercise.

A bypass is a diff the instrument missed. The first useful question is not
"which model should catch this" but "how many distinct shapes are here, and
what does each one do". Grouping by a deterministic capability signature is
enough to rank the backlog and is reproducible; an embedding pass can replace
the grouping later without changing the output contract.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

CAPABILITIES = {
    "fetch": re.compile(r"\b(curl|wget|aria2c|scp|sftp|rsync)\b"),
    "pipe_shell": re.compile(r"\|\s*(?:bash|sh|zsh|dash|ksh)\b"),
    "shell_file": re.compile(r"\b(bash|sh|zsh|dash|ksh)\s+\S"),
    "eval": re.compile(r"\beval\b"),
    "base64": re.compile(r"\bbase64\b"),
    "python": re.compile(r"\bpython[0-9.]*\b"),
    "node": re.compile(r"\bnode\b"),
    "ruby": re.compile(r"\bruby\b"),
    "perl": re.compile(r"\bperl\b"),
    "php": re.compile(r"\bphp\b"),
    "lua": re.compile(r"\blua\b"),
    "julia": re.compile(r"\bjulia\b"),
    "rscript": re.compile(r"\bRscript\b"),
    "bun": re.compile(r"\bbun\b"),
    "deno": re.compile(r"\bdeno\b"),
    "java": re.compile(r"\bjava\b"),
    "swift": re.compile(r"\bswift\b"),
    "tclsh": re.compile(r"\btclsh\b|\bwish\b"),
    "awk": re.compile(r"\bawk\b"),
    "go_run": re.compile(r"\bgo\s+run\b"),
    "cargo_run": re.compile(r"\bcargo\s+run\b"),
    "dotnet": re.compile(r"\bdotnet\b|\bmono\b"),
    "source": re.compile(r"\bsource\s+\S"),
    "write": re.compile(r">\s*\S|\btee\b"),
    "sed_i": re.compile(r"\bsed\s+-i\b"),
    "heredoc": re.compile(r"<<-?\s*['\"]?[A-Za-z_]"),
    "chmod": re.compile(r"\bchmod\b"),
    "systemctl": re.compile(r"\bsystemctl\b"),
    "git_clone": re.compile(r"\bgit\s+clone\b"),
    "ssh": re.compile(r"\bssh\b"),
    "nc": re.compile(r"\bnc\b|\bnetcat\b"),
    "rm_rf": re.compile(r"\brm\s+-[a-zA-Z]*r"),
    "dd": re.compile(r"\bdd\s+if="),
}

_FILE_KIND = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


def _capabilities(text: str) -> tuple[str, ...]:
    found = [name for name, pattern in CAPABILITIES.items() if pattern.search(text)]
    return tuple(sorted(found)) or ("plain",)


def _file_kinds(text: str) -> tuple[str, ...]:
    kinds = set()
    for path in _FILE_KIND.findall(text):
        name = Path(path).name
        kinds.add(Path(name).suffix or name or "(none)")
    return tuple(sorted(kinds)) or ("(none)",)


def signature(text: str) -> str:
    return f"caps={','.join(_capabilities(text))}|files={','.join(_file_kinds(text))}"


def campaign_rules(harness_root: Path) -> dict[str, list[str]]:
    """Expected rule ids per campaign, from the committed records."""

    import json

    rules: dict[str, list[str]] = {}
    for record in (harness_root / "campaigns").glob("*/record.json"):
        try:
            doc = json.loads(record.read_text())
        except (OSError, ValueError):
            continue
        rules[doc.get("campaign", record.parent.name)] = list(
            doc.get("expected_rules") or []
        )
    return rules


def cluster(
    rows: list[dict],
    limit: int | None = None,
    rules_by_campaign: dict[str, list[str]] | None = None,
) -> list[dict]:
    """Group bypass rows by signature, ranked by support."""

    groups: dict[str, dict] = defaultdict(
        lambda: {
            "signature": "",
            "count": 0,
            "campaigns": Counter(),
            "expected_rules": Counter(),
            "samples": [],
        }
    )
    for index, row in enumerate(rows):
        if limit is not None and index >= limit:
            break
        path = Path(row["path"])
        if not path.is_file():
            continue
        text = path.read_text(errors="replace")
        key = signature(text)
        group = groups[key]
        group["signature"] = key
        group["count"] += 1
        campaign = row.get("group", "")
        group["campaigns"][campaign] += 1
        for rule in (rules_by_campaign or {}).get(campaign, []):
            group["expected_rules"][rule] += 1
        if len(group["samples"]) < 5:
            group["samples"].append(path.name)
    clusters = list(groups.values())
    for group in clusters:
        group["campaigns"] = dict(group["campaigns"].most_common())
        group["expected_rules"] = dict(group["expected_rules"].most_common())
    clusters.sort(key=lambda group: (-group["count"], group["signature"]))
    return clusters


def summarize(clusters: list[dict]) -> dict:
    return {
        "clusters": len(clusters),
        "bypasses": sum(cluster["count"] for cluster in clusters),
        "top": [{"signature": c["signature"], "count": c["count"]} for c in clusters[:10]],
    }
