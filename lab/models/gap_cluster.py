"""Group uncaught bypass diffs by the shape they exercise.

A bypass is a diff the instrument missed. The first useful question is not
"which model should catch this" but "how many distinct shapes are here, and
what does each one do". Grouping by a deterministic capability signature is
enough to rank the backlog and is reproducible; an embedding pass can replace
the grouping later without changing the output contract.
"""

from __future__ import annotations

import hashlib
import json
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

#: One deterministic shape per capability, written for a rule author. A
#: cluster names what the diff does; the proposal names the predicate family
#: that would have to exist to catch it.
PROPOSALS = {
    "fetch": "fetch a remote artifact in an executable context",
    "pipe_shell": "pipe a fetched or decoded stream into a shell",
    "shell_file": "write a script, then invoke it with a shell",
    "eval": "evaluate a dynamically built string",
    "base64": "decode a blob and execute the result",
    "heredoc": "execute a heredoc body",
    "python": "execute a Python payload",
    "node": "execute a Node payload",
    "ruby": "execute a Ruby payload",
    "perl": "execute a Perl payload",
    "php": "execute a PHP payload",
    "lua": "execute a Lua payload",
    "julia": "execute a Julia payload",
    "rscript": "execute an R payload",
    "bun": "execute a Bun payload",
    "deno": "execute a Deno payload",
    "java": "execute a Java payload",
    "swift": "execute a Swift payload",
    "tclsh": "execute a Tcl payload",
    "awk": "execute an awk program",
    "go_run": "run Go source at build time",
    "cargo_run": "run Rust source at build time",
    "dotnet": "run a managed runtime payload",
    "source": "source a file outside the recipe",
    "write": "write a file outside the package root",
    "sed_i": "rewrite a file in place",
    "chmod": "change permissions on a staged file",
    "systemctl": "interact with the service manager",
    "git_clone": "clone a repository at build time",
    "ssh": "open an outbound SSH channel",
    "nc": "open a raw network channel",
    "rm_rf": "delete a tree",
    "dd": "write a raw device",
    "plain": "no capability signature matched; inspect the sample",
}


def propose(signature: str) -> str:
    caps = signature.split("caps=", 1)[-1].split("|", 1)[0]
    names = [cap for cap in caps.split(",") if cap]
    if not names:
        return PROPOSALS["plain"]
    parts = [PROPOSALS.get(name, name) for name in names]
    return " and ".join(parts)


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


def fixture_id(sig: str) -> str:
    """A stable campaign directory name for one capability shape."""

    return "gap-" + hashlib.sha256(sig.encode("utf-8")).hexdigest()[:10]


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
        group["representative"] = str(path)
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
        group["proposed_shape"] = propose(group["signature"])
        group["fixture_id"] = fixture_id(group["signature"])
        group["needs_rule"] = not group["expected_rules"]
    clusters.sort(key=lambda group: (-group["count"], group["signature"]))
    return clusters


def summarize(clusters: list[dict]) -> dict:
    return {
        "clusters": len(clusters),
        "bypasses": sum(cluster["count"] for cluster in clusters),
        "top": [{"signature": c["signature"], "count": c["count"]} for c in clusters[:10]],
    }


def _campaign(fid: str, rules: list[str], version: str) -> dict:
    return {
        "campaign": fid,
        "campaign_type": "deterministic",
        "environment": {
            "trustsight_version": version,
            "trustsight_source": "local-path",
            "db_state": "cold",
            "flag_threshold": 20,
        },
        "generator": {"type": "raw-diff"},
        "prompt": {
            "prompt_id": fid,
            "behavior_goal": "fetch_then_execute",
            "expected_rules": rules,
            "forbidden_techniques": {},
        },
        "attempts": 1,
    }


def emit(
    clusters: list[dict],
    out_dir: Path,
    *,
    limit: int | None = None,
    version: str = "0.22.0",
    overwrite: bool = False,
) -> list[dict]:
    """Write one `raw-diff` campaign per cluster.

    The output is a normal campaign directory, so `coverage` counts the rule
    it targets and `matrix` can move its cell once the rule fires.  A cluster
    with no expected rule is still written, but the caller is told it needs a
    rule rather than being given a guessed one.

    JSON is valid YAML, so this needs no YAML writer in the lab.
    """

    written: list[dict] = []
    for cluster in clusters[:limit]:
        representative = cluster.get("representative")
        if not representative:
            continue
        source = Path(representative)
        if not source.is_file():
            continue
        fid = cluster["fixture_id"]
        directory = out_dir / fid
        if directory.exists() and not overwrite:
            written.append({"campaign": fid, "skipped": "exists"})
            continue
        rules = sorted(cluster.get("expected_rules") or {})
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "campaign.yml").write_text(
            json.dumps(_campaign(fid, rules, version), indent=2) + "\n"
        )
        (directory / "inputs.yml").write_text(
            json.dumps(
                {"cells": [{"id": fid, "diff": source.read_text(errors="replace")}]},
                indent=2,
            )
            + "\n"
        )
        written.append({
            "campaign": fid,
            "signature": cluster["signature"],
            "expected_rules": rules,
            "needs_rule": not rules,
            "path": str(directory),
        })
    return written
