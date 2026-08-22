from __future__ import annotations

import json
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from collector.config import Settings
from collector.db import Database


class MigrateError(Exception):
    pass


@dataclass
class MigrateReport:
    ok: bool = True
    source: str = ""
    target: str = ""
    dry_run: bool = False
    wiped: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    message: str = ""


TABLES = ("kv", "blocks", "detections", "flow_samples", "events")


def _open_sqlite(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise MigrateError(f"SQLite file not found: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _count_sqlite(conn: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in TABLES:
        try:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            counts[table] = int(row["n"] if row else 0)
        except sqlite3.Error:
            counts[table] = 0
    return counts


def _mysql_target(settings: Settings) -> Database:
    if not settings.mysql_password and not settings.mysql_host:
        pass
    if not settings.mysql_database:
        raise MigrateError("MYSQL_DATABASE is not set")
    if not settings.mysql_user:
        raise MigrateError("MYSQL_USER is not set")
    mysql_settings = settings.model_copy(update={"db_engine": "mysql"})
    return Database.from_settings(mysql_settings)


def _wipe_mysql(db: Database) -> None:
    for table in reversed(TABLES):
        db._execute(f"DELETE FROM {table}")


def _migrate_kv(source: sqlite3.Connection, target: Database, *, dry_run: bool) -> int:
    rows = source.execute("SELECT key, value FROM kv ORDER BY key").fetchall()
    if dry_run:
        return len(rows)
    for row in rows:
        target.set_kv(row["key"], row["value"])
    return len(rows)


def _migrate_blocks(source: sqlite3.Connection, target: Database, *, dry_run: bool) -> int:
    rows = source.execute(
        "SELECT ip, reason, source, created_at, timeout, active FROM blocks ORDER BY id"
    ).fetchall()
    if dry_run:
        return len(rows)
    sql = """
        INSERT INTO blocks(ip, reason, source, created_at, timeout, active)
        VALUES(%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            source = VALUES(source),
            created_at = VALUES(created_at),
            timeout = VALUES(timeout),
            active = VALUES(active)
    """
    for row in rows:
        target._execute(
            sql,
            (
                row["ip"],
                row["reason"],
                row["source"],
                row["created_at"],
                row["timeout"],
                int(row["active"]),
            ),
        )
    return len(rows)


def _migrate_detections(source: sqlite3.Connection, target: Database, *, dry_run: bool) -> int:
    rows = source.execute(
        """
        SELECT src_ip, kind, score, detail, first_seen, last_seen, auto_blocked
        FROM detections ORDER BY id
        """
    ).fetchall()
    if dry_run:
        return len(rows)
    sql = target._upsert_detection_sql()
    for row in rows:
        detail = row["detail"]
        if isinstance(detail, dict):
            detail_json = json.dumps(detail)
        else:
            detail_json = detail or "{}"
        target._execute(
            sql,
            (
                row["src_ip"],
                row["kind"],
                int(row["score"]),
                detail_json,
                float(row["first_seen"]),
                float(row["last_seen"]),
                int(row["auto_blocked"]),
            ),
        )
    return len(rows)


def _migrate_flow_samples(source: sqlite3.Connection, target: Database, *, dry_run: bool) -> int:
    rows = source.execute(
        """
        SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags
        FROM flow_samples ORDER BY id
        """
    ).fetchall()
    if dry_run:
        return len(rows)
    sql = """
        INSERT INTO flow_samples(ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags)
        VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    for row in rows:
        target._execute(
            sql,
            (
                float(row["ts"]),
                row["src_ip"],
                row["dst_ip"],
                int(row["src_port"]),
                int(row["dst_port"]),
                int(row["proto"]),
                int(row["bytes"]),
                int(row["packets"]),
                int(row["tcp_flags"] or 0),
            ),
        )
    return len(rows)


def _migrate_events(source: sqlite3.Connection, target: Database, *, dry_run: bool) -> int:
    rows = source.execute(
        "SELECT ts, level, message FROM events ORDER BY id"
    ).fetchall()
    if dry_run:
        return len(rows)
    sql = "INSERT INTO events(ts, level, message) VALUES(%s, %s, %s)"
    for row in rows:
        target._execute(sql, (float(row["ts"]), row["level"], row["message"]))
    return len(rows)


def migrate_sqlite_to_mysql(
    settings: Settings,
    *,
    sqlite_path: Path | None = None,
    dry_run: bool = False,
    wipe: bool = False,
    backup: bool = False,
) -> MigrateReport:
    """Copy collector data from SQLite into MySQL using MYSQL_* settings."""
    source_path = sqlite_path or settings.db_path
    source_path = Path(source_path)
    report = MigrateReport(
        dry_run=dry_run,
        wiped=wipe and not dry_run,
        source=str(source_path),
        target=f"mysql://{settings.mysql_user}@{settings.mysql_host}:{settings.mysql_port}/{settings.mysql_database}",
    )

    source = _open_sqlite(source_path)
    target: Database | None = None
    try:
        if dry_run:
            report.counts = _count_sqlite(source)
            report.message = "Dry run — no rows written"
            report.log.append(f"source rows: {report.counts}")
            return report

        if backup:
            backup_path = source_path.with_suffix(source_path.suffix + ".bak")
            shutil.copy2(source_path, backup_path)
            report.log.append(f"backup: {backup_path}")

        target = _mysql_target(settings)
        if wipe:
            _wipe_mysql(target)
            report.log.append("wiped existing MySQL tables")

        report.counts["kv"] = _migrate_kv(source, target, dry_run=False)
        report.counts["blocks"] = _migrate_blocks(source, target, dry_run=False)
        report.counts["detections"] = _migrate_detections(source, target, dry_run=False)
        report.counts["flow_samples"] = _migrate_flow_samples(source, target, dry_run=False)
        report.counts["events"] = _migrate_events(source, target, dry_run=False)

        total = sum(report.counts.values())
        report.message = f"Migrated {total} row(s) into MySQL"
        report.log.append("next: set DB_ENGINE=mysql in .env, stop the collector, then restart")
        return report
    finally:
        source.close()
        if target is not None:
            target.close()
