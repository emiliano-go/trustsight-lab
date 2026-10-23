"""Watcher database: one consistent snapshot, then bounded extraction.

The operator's database is never opened read-write. ``snapshot`` asks SQLite
for a consistent copy (the WAL is folded in), and ``extract`` streams row
ranges into gzipped JSONL so a 5 GB database does not need to fit in memory
and a slow ``json_extract`` never scans 866k rows at once.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import shlex
import shutil
import sqlite3
import subprocess
from pathlib import Path

DEFAULT_TABLES = (
    "analysis_history",
    "triggered_rules",
    "packages",
    "pkgbuild_snapshots",
    "source_urls",
    "property_transitions",
    "recipe_observations",
)

#: Fields kept from ``analysis_history.fact_json``. ``raw_diff_blob`` is
#: dropped unless the caller asks for diffs: it is most of the file size.
FACT_FIELDS = (
    "config_fingerprint",
    "package_name",
    "adapter",
    "risk",
    "risk_label",
    "final_score",
    "score_breakdown",
    "coverage_gaps",
    "carried_coverage_gaps",
    "source_buckets",
    "novelty_context",
    "diff_summary",
    "execution_changes",
    "first_seen",
    "version_moved",
)


def snapshot_local(source: Path, dest: Path) -> Path:
    """Consistent copy of a local SQLite database."""

    dest.parent.mkdir(parents=True, exist_ok=True)
    source_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    target_conn = sqlite3.connect(dest)
    try:
        source_conn.backup(target_conn)
    finally:
        target_conn.close()
        source_conn.close()
    return dest


def snapshot_remote(
    host: str,
    container: str,
    dest: Path,
    db_path: str = "/data/.local/share/trustsight/trustsight.db",
    remote_tmp: str = "/data/trustsight-lab-snapshot.db",
) -> Path:
    """Ask the watcher container for a consistent copy, then pull it.

    The backup runs inside the container with its own Python, so the WAL is
    included and no file is copied out from under a live writer. The pull is
    a streamed ``docker exec cat``: no host path is assumed.
    """

    if shutil.which("ssh") is None:
        raise RuntimeError("ssh is required for a remote snapshot")
    dest.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "import sqlite3,sys;"
        f"src=sqlite3.connect('file:{db_path}?mode=ro',uri=True);"
        f"dst=sqlite3.connect('{remote_tmp}');"
        "src.backup(dst);dst.close();src.close()"
    )
    subprocess.run(["ssh", host, "docker", "exec", container, "python", "-c", shlex.quote(script)],
                   check=True)
    # A 4.7 GB SQLite file over a consumer uplink is a coffee break; gzip on
    # the container side and decompress here.  The integrity check below is
    # still against the uncompressed size.
    with dest.open("wb") as handle:
        source = subprocess.Popen(
            _remote_gzip_argv(host, container, remote_tmp),
            stdout=subprocess.PIPE,
        )
        assert source.stdout is not None
        unpack = subprocess.run(
            ["gunzip", "-c"], stdin=source.stdout, stdout=handle, check=False
        )
        source.stdout.close()
        if source.wait() != 0 or unpack.returncode != 0:
            raise RuntimeError("compressed snapshot transfer failed")
    remote_size = subprocess.check_output(
        ["ssh", host, "docker", "exec", container, "stat", "-c", "%s", remote_tmp],
        text=True,
    ).strip()
    if not remote_size.isdigit() or dest.stat().st_size != int(remote_size):
        raise RuntimeError(
            f"snapshot size mismatch: local={dest.stat().st_size} remote={remote_size}"
        )
    subprocess.run(["ssh", host, "docker", "exec", container, "rm", "-f", remote_tmp],
                   check=True)
    return dest


def _remote_gzip_argv(host: str, container: str, remote_tmp: str) -> list[str]:
    """One ssh argv whose remote command keeps its own quoting.

    Passing `sh -c gzip ...` as separate argv words loses the quoting at the
    remote shell; the command must travel as a single quoted string.
    """

    inner = f"gzip -1 -c {shlex.quote(remote_tmp)}"
    remote = f"docker exec {shlex.quote(container)} sh -c {shlex.quote(inner)}"
    return ["ssh", host, remote]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_history(row: sqlite3.Row, with_diffs: bool) -> dict:
    out = {
        "id": row["id"],
        "package_id": row["package_id"],
        "timestamp": row["timestamp"],
        "old_version": row["old_version"],
        "new_version": row["new_version"],
        "old_commit": row["old_commit"],
        "new_commit": row["new_commit"],
        "final_score": row["final_score"],
    }
    raw = row["fact_json"]
    fact = {}
    if raw:
        try:
            fact = json.loads(raw)
        except (TypeError, ValueError):
            fact = {}
    for field in FACT_FIELDS:
        out[field] = fact.get(field)
    if with_diffs and row["raw_diff_blob"] is not None:
        blob = row["raw_diff_blob"]
        out["raw_diff"] = (
            blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        )
    return out


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    if not rows:
        raise KeyError(f"unknown table: {table}")
    return [row[1] for row in rows]


def _write_jsonl_gz(handle, row: dict) -> None:
    handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))


def extract(
    db: Path,
    out_dir: Path,
    tables: tuple[str, ...] = DEFAULT_TABLES,
    *,
    batch: int = 2000,
    limit: int | None = None,
    with_diffs: bool = False,
    min_weight: int | None = None,
) -> dict:
    """Stream selected tables to ``<table>.jsonl.gz`` plus a manifest.

    ``min_weight`` keeps only analyses with a score-bearing finding.  The
    watcher writes 867k rows but only ~47k carry weight; extracting the rest
    makes a full-history run needlessly slow without adding a precision
    signal.  It applies to ``analysis_history`` only; packages and snapshots
    are small and are needed to recompute evidence.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"snapshot failed quick_check: {integrity}")
    outputs: dict[str, dict] = {}
    try:
        for table in tables:
            if table not in DEFAULT_TABLES:
                raise KeyError(f"table not allowed: {table}")
            path = out_dir / f"{table}.jsonl.gz"
            _table_columns(conn, table)
            rows = 0
            with gzip.open(path, "wb", compresslevel=6) as handle:
                last = 0
                while True:
                    if table == "analysis_history":
                        where = "id > ?"
                        params: list = [last]
                        if min_weight is not None:
                            where += (
                                " AND EXISTS (SELECT 1 FROM "
                                "json_each(fact_json, '$.score_breakdown') AS b "
                                "WHERE CAST(json_extract(b.value, '$.weight') "
                                "AS INTEGER) > ?)"
                            )
                            params.append(min_weight)
                        query = (
                            f'SELECT * FROM "analysis_history" WHERE {where} '
                            "ORDER BY id LIMIT ?"
                        )
                        params.append(batch)
                    else:
                        query = (
                            f'SELECT rowid AS _rowid, * FROM "{table}" '
                            "WHERE rowid > ? ORDER BY rowid LIMIT ?"
                        )
                        params = [last, batch]
                    page = conn.execute(query, params).fetchall()
                    if not page:
                        break
                    for row in page:
                        record = dict(row)
                        if table == "analysis_history":
                            record = _normalize_history(row, with_diffs)
                            last = row["id"]
                        else:
                            last = row["_rowid"]
                            record.pop("_rowid", None)
                        _write_jsonl_gz(handle, record)
                        rows += 1
                        if limit is not None and rows >= limit:
                            break
                    if limit is not None and rows >= limit:
                        break
            outputs[table] = {
                "rows": rows,
                "path": path.name,
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
    finally:
        conn.close()
    manifest = {
        "source": str(db),
        "source_bytes": db.stat().st_size,
        "source_sha256": _sha256(db),
        "tables": outputs,
        "quick_check": integrity,
        "with_diffs": with_diffs,
        "min_weight": min_weight,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest
