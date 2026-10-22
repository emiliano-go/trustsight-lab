"""Command line entry point. Offline only; no network except the snapshot pull."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .candidates import known
from .features import findings
from .ingest import corpora, reports, watcher
from .labels import build, contradictions
from .models import fingerprints, fp_ranker, gap_cluster, predicate_miner
from .pins import DEFAULT_ROOT, read_pins, write_pins
from .validate import runner

DATA = Path("data")
REPORTS = Path("reports")


def _root(value: str | None) -> Path:
    return Path(value).resolve() if value else DEFAULT_ROOT


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def cmd_pins(args) -> int:
    pins = read_pins(_root(args.root))
    if args.out:
        write_pins(Path(args.out), pins)
    print(json.dumps(pins.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_corpora(args) -> int:
    root = _root(args.root)
    doc = corpora.manifest(root / "trustsight", root / "trustsight-harness")
    out = Path(args.out) if args.out else DATA / "corpora-manifest.json"
    _write_json(out, doc["counts"])
    print(json.dumps(doc["counts"], indent=2, sort_keys=True))
    return 0


def cmd_labels(args) -> int:
    root = _root(args.root)
    rows = build.build(root / "trustsight", root / "trustsight-harness")
    out = Path(args.out) if args.out else DATA / "labels.jsonl"
    reports.write_jsonl(rows, out)
    print(json.dumps(build.counts(rows), indent=2, sort_keys=True))
    return 0


def cmd_mine(args) -> int:
    rows = _read_jsonl(Path(args.labels))
    if args.contradictions:
        rows = build.merge_weak(rows, args.contradictions)
    candidates = predicate_miner.mine(rows, min_support=args.min_support)
    out = Path(args.out) if args.out else REPORTS / "predicates.json"
    _write_json(out, candidates)
    print(json.dumps(predicate_miner.summarize(candidates), indent=2, sort_keys=True))
    return 0


def cmd_rank(args) -> int:
    rows = _read_jsonl(Path(args.labels))
    ranked = fp_ranker.rank_groups(rows, min_support=args.min_support)
    out = Path(args.out) if args.out else REPORTS / "rank.json"
    _write_json(out, ranked)
    print(json.dumps({"groups": len(ranked), "top": ranked[:5]}, indent=2))
    if args.train:
        trained = fp_ranker.train(rows)
        _write_json(Path(args.train), trained)
        print(json.dumps({"in_sample_auc": trained["in_sample_auc"]}, indent=2))
    return 0


def cmd_gaps(args) -> int:
    root = _root(args.root)
    rows = corpora.bypass_fixtures(root / "trustsight-harness")
    clusters = gap_cluster.cluster(
        rows,
        limit=args.limit,
        rules_by_campaign=gap_cluster.campaign_rules(root / "trustsight-harness"),
    )
    out = Path(args.out) if args.out else REPORTS / "gaps.json"
    _write_json(out, clusters)
    print(json.dumps(gap_cluster.summarize(clusters), indent=2))
    return 0


def cmd_findings(args) -> int:
    rows = findings.build(
        Path(args.extract),
        limit=args.limit,
        only_rules=tuple(args.rules or findings.INTERESTING),
        recompute=not args.no_evidence,
        root=_root(args.root),
    )
    out = Path(args.out) if args.out else DATA / "findings.jsonl"
    findings.write(rows, out)
    print(json.dumps({"findings": len(rows)}, indent=2))
    return 0


def cmd_contradictions(args) -> int:
    rows = _read_jsonl(Path(args.findings))
    annotated = contradictions.annotate(rows)
    out = Path(args.out) if args.out else DATA / "contradictions.jsonl"
    findings.write(annotated, out)
    count = sum(1 for row in annotated if row.get("contradiction"))
    reasons: dict[str, int] = {}
    for row in annotated:
        reason = (row.get("contradiction") or {}).get("reason")
        if reason:
            reasons[reason] = reasons.get(reason, 0) + 1
    print(json.dumps({"contradictions": count, "by_reason": reasons}, indent=2))
    return 0


def cmd_candidates(args) -> int:
    root = _root(args.root)
    predicates = json.loads(Path(args.predicates).read_text())
    out_dir = Path(args.out) if args.out else REPORTS / "candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for item in predicates:
        candidate = known.for_predicate(
            item["rule_id"], item["predicate"], root / "trustsight"
        )
        if candidate is None:
            doc = {
                "rule_id": item["rule_id"],
                "predicate": item["predicate"],
                "status": "needs_template",
                "support": item["support"],
                "fp": item["fp"],
            }
        else:
            doc = {**known.to_dict(candidate), "status": "ready"}
            doc["linked_findings"] = item.get("packages", [])
        path = out_dir / f"{doc.get('id', item['rule_id'] + '-' + item['predicate'].replace('=', '-'))}.json"
        _write_json(path, doc)
        written.append(str(path))
    print(json.dumps({"candidates": written}, indent=2))
    return 0


def cmd_refresh(args) -> int:
    root = _root(args.root)
    pins = read_pins(root)
    write_pins(Path("config/pins.json"), pins)
    rows = build.build(root / "trustsight", root / "trustsight-harness")
    reports.write_jsonl(rows, DATA / "labels.jsonl")
    if args.extract:
        watcher.extract(
            Path(args.db),
            Path(args.watcher_out),
            limit=args.limit,
            with_diffs=False,
        )
    weak_path = args.contradictions
    if args.build_findings:
        built = findings.build(
            Path(args.watcher_out),
            limit=args.limit,
            root=root,
        )
        annotations = contradictions.annotate(built)
        findings.write(annotations, DATA / "contradictions.jsonl")
        weak_path = str(DATA / "contradictions.jsonl")
        args.findings = str(DATA / "contradictions.jsonl")
    if weak_path:
        rows = build.merge_weak(rows, weak_path)
    predicates = predicate_miner.mine(rows, min_support=args.min_support)
    _write_json(REPORTS / "predicates.json", predicates)
    _write_json(REPORTS / "rank.json", fp_ranker.rank_groups(rows))
    _write_json(
        REPORTS / "rank_by_fingerprint.json",
        fp_ranker.rank_by_fingerprint(rows),
    )
    bypass = corpora.bypass_fixtures(root / "trustsight-harness")
    gaps = gap_cluster.cluster(
        bypass,
        rules_by_campaign=gap_cluster.campaign_rules(root / "trustsight-harness"),
    )
    _write_json(REPORTS / "gaps.json", gaps)
    fingerprint_rows = []
    findings_path = Path(args.findings) if args.findings else None
    if findings_path and findings_path.is_file():
        fingerprint_rows = fingerprints.summarize(_read_jsonl(findings_path))
        _write_json(REPORTS / "fingerprints.json", fingerprint_rows)
    summary = {
        "pins": pins.to_dict(),
        "labels": build.counts(rows),
        "predicates": len(predicates),
        "gaps": len(gaps),
        "fingerprints": fingerprint_rows,
    }
    _write_json(REPORTS / "refresh.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def cmd_report(args) -> int:
    out = Path(args.out) if args.out else REPORTS / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    predicates = json.loads((REPORTS / "predicates.json").read_text()) \
        if (REPORTS / "predicates.json").is_file() else []
    rank = json.loads((REPORTS / "rank.json").read_text()) \
        if (REPORTS / "rank.json").is_file() else []
    gaps = json.loads((REPORTS / "gaps.json").read_text()) \
        if (REPORTS / "gaps.json").is_file() else []
    lines = ["# TrustSight Lab report", ""]
    lines += ["## Precision candidates", ""]
    if predicates:
        lines += ["| Rule | Predicate | Support | FP | TP-but-benign |", "|---|---|---|---|---|"]
        for row in predicates:
            lines.append(
                f"| {row['rule_id']} | `{row['predicate']}` | {row['support']} | "
                f"{row['fp']} | {row['tp_benign']} |"
            )
    else:
        lines.append("No predicates mined.")
    lines += ["", "## Ranked evidence signatures", ""]
    if rank:
        lines += ["| Rule | Signature | Support | FP | FP rate |", "|---|---|---|---|---|"]
        for row in rank[:20]:
            lines.append(
                f"| {row['rule_id']} | `{row['signature']}` | {row['support']} | "
                f"{row['fp']} | {row['fp_rate']} |"
            )
    lines += ["", "## Bypass clusters (recall backlog)", ""]
    if gaps:
        lines += [
            "| Signature | Count | Proposed shape | Expected rules |",
            "|---|---|---|---|",
        ]
        for row in gaps[:20]:
            rules = ", ".join(row.get("expected_rules") or {}) or "-"
            lines.append(
                f"| `{row['signature']}` | {row['count']} | "
                f"{row.get('proposed_shape', '-')} | {rules} |"
            )
    out.write_text("\n".join(lines) + "\n")
    print(out)
    return 0


def cmd_baseline(args) -> int:
    from .validate import metrics

    root = _root(args.root)
    scratch = Path(tempfile.mkdtemp(prefix="trustsight-lab-base-"))
    tree = runner.worktree(root / "trustsight", scratch / "tree")
    try:
        gates_json = scratch / "gates.json"
        commands = runner.build_commands(
            tree,
            root / "trustsight-harness",
            tier=args.tier,
            benign_corpus=root / "trustsight" / "tests" / "fixtures" / "benign-corpus",
            trustsight_root=root / "trustsight",
            gates_json=gates_json if args.tier >= 2 else None,
        )
        results = runner.run_commands(commands)
        benign = None
        for item in results:
            if "benign" in item["argv"]:
                benign = metrics.parse_benign(item["stdout"])
        gates = json.loads(gates_json.read_text()) if gates_json.is_file() else []
        by_name = {gate.get("gate"): gate for gate in gates}
        doc = {
            "benign_flag_rate": (benign or {}).get("estimate"),
            "benign_flagged": (benign or {}).get("flagged"),
            "gates": by_name,
            "instrument": read_pins(root).to_dict(),
        }
        _write_json(Path(args.out), doc)
        print(json.dumps(doc, indent=2, sort_keys=True))
        return 0
    finally:
        runner.remove_worktree(root / "trustsight", tree)


def cmd_validate(args) -> int:
    root = _root(args.root)
    doc = json.loads(Path(args.candidate).read_text())
    if doc.get("status") != "ready":
        raise SystemExit("candidate has no patch template")
    candidate = known.Candidate(
        id=doc["id"],
        rule_id=doc["rule_id"],
        predicate=doc["predicate"],
        lever=doc["lever"],
        targets=doc["targets"],
        patch=doc["patch"],
        rationale=doc["rationale"],
        tp_twin=doc["tp_twin"],
        reproducers=doc.get("reproducers") or [],
    )
    baseline = None
    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path and baseline_path.is_file():
        baseline = json.loads(baseline_path.read_text())
    result = runner.validate_candidate(
        candidate,
        trustsight_root=root / "trustsight",
        harness_root=root / "trustsight-harness",
        tier=args.tier,
        dry_run=not args.execute,
        baseline=baseline,
    )
    print(json.dumps(result, indent=2))
    if args.execute is False:
        return 0
    return 0 if result.get("passed") else 1


def cmd_snapshot(args) -> int:
    dest = Path(args.dest)
    if args.host:
        watcher.snapshot_remote(args.host, args.container, dest, db_path=args.db)
    else:
        watcher.snapshot_local(Path(args.db), dest)
    print(dest)
    return 0


def cmd_extract(args) -> int:
    manifest = watcher.extract(
        Path(args.db),
        Path(args.out),
        tuple(args.tables or watcher.DEFAULT_TABLES),
        limit=args.limit,
        with_diffs=args.with_diffs,
    )
    print(json.dumps(manifest["tables"], indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab")
    parser.add_argument("--root", help="directory holding the trustsight checkouts")
    sub = parser.add_subparsers(dest="command", required=True)

    pins = sub.add_parser("pins", help="record the pinned instrument and corpora")
    pins.add_argument("--out")
    pins.set_defaults(func=cmd_pins)

    corp = sub.add_parser("corpora", help="count the committed corpora")
    corp.add_argument("--out")
    corp.set_defaults(func=cmd_corpora)

    labels = sub.add_parser("labels", help="build the label set")
    labels.add_argument("--out")
    labels.set_defaults(func=cmd_labels)

    mine = sub.add_parser("mine", help="rank evidence predicates per rule")
    mine.add_argument("--labels", default=str(DATA / "labels.jsonl"))
    mine.add_argument("--out")
    mine.add_argument("--min-support", type=int, default=1)
    mine.add_argument("--contradictions", help="weak labels from the watcher sample")
    mine.set_defaults(func=cmd_mine)

    rank = sub.add_parser("rank", help="rank rule/evidence signatures")
    rank.add_argument("--labels", default=str(DATA / "labels.jsonl"))
    rank.add_argument("--out")
    rank.add_argument("--min-support", type=int, default=1)
    rank.add_argument("--train", help="write the optional logistic model summary")
    rank.set_defaults(func=cmd_rank)

    gaps = sub.add_parser("gaps", help="cluster bypass diffs by capability")
    gaps.add_argument("--out")
    gaps.add_argument("--limit", type=int)
    gaps.set_defaults(func=cmd_gaps)

    find = sub.add_parser("findings", help="build finding rows from an extraction")
    find.add_argument("--extract", default=str(DATA / "watcher"))
    find.add_argument("--out")
    find.add_argument("--limit", type=int)
    find.add_argument("--rules", nargs="*")
    find.add_argument("--no-evidence", action="store_true")
    find.set_defaults(func=cmd_findings)

    contra = sub.add_parser("contradictions", help="derive weak FP labels")
    contra.add_argument("--findings", default=str(DATA / "findings.jsonl"))
    contra.add_argument("--out")
    contra.set_defaults(func=cmd_contradictions)

    cand = sub.add_parser("candidates", help="render patch candidates")
    cand.add_argument("--predicates", default=str(REPORTS / "predicates.json"))
    cand.add_argument("--out")
    cand.set_defaults(func=cmd_candidates)

    refresh = sub.add_parser("refresh", help="re-pin, relabel, and re-rank")
    refresh.add_argument("--findings", default=str(DATA / "contradictions_sample.jsonl"))
    refresh.add_argument("--contradictions", default=str(DATA / "contradictions_sample.jsonl"))
    refresh.add_argument("--min-support", type=int, default=2)
    refresh.add_argument("--extract", action="store_true")
    refresh.add_argument("--build-findings", action="store_true")
    refresh.add_argument("--db", default=str(DATA / "watcher.db"))
    refresh.add_argument("--watcher-out", default=str(DATA / "watcher"))
    refresh.add_argument("--limit", type=int)
    refresh.set_defaults(func=cmd_refresh)

    rep = sub.add_parser("report", help="render the markdown summary")
    rep.add_argument("--out")
    rep.set_defaults(func=cmd_report)

    val = sub.add_parser("validate", help="apply and measure one candidate")
    val.add_argument("--candidate", required=True)
    val.add_argument("--tier", type=int, default=1)
    val.add_argument("--execute", action="store_true")
    val.add_argument("--baseline", default="reports/baseline.json")
    val.set_defaults(func=cmd_validate)

    base = sub.add_parser("baseline", help="measure the unpatched instrument")
    base.add_argument("--tier", type=int, default=2)
    base.add_argument("--out", default="reports/baseline.json")
    base.set_defaults(func=cmd_baseline)

    snap = sub.add_parser("snapshot", help="copy the watcher database")
    snap.add_argument("--db", default="/data/.local/share/trustsight/trustsight.db")
    snap.add_argument("--host", help="ssh host; omit for a local database")
    snap.add_argument("--container", default="trustsight-watch")
    snap.add_argument("--dest", default=str(DATA / "watcher.db"))
    snap.set_defaults(func=cmd_snapshot)

    extract = sub.add_parser("extract", help="stream tables to gzipped JSONL")
    extract.add_argument("--db", default=str(DATA / "watcher.db"))
    extract.add_argument("--out", default=str(DATA / "watcher"))
    extract.add_argument("--tables", nargs="*")
    extract.add_argument("--limit", type=int)
    extract.add_argument("--with-diffs", action="store_true")
    extract.set_defaults(func=cmd_extract)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
