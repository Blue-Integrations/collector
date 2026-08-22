from __future__ import annotations

import json
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from collector.config import Settings


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY,
    src_ip TEXT NOT NULL,
    kind TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '{}',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    auto_blocked INTEGER NOT NULL DEFAULT 0,
    UNIQUE(src_ip, kind)
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    created_at REAL NOT NULL,
    timeout TEXT NOT NULL DEFAULT '1d',
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_samples (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    proto INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    tcp_flags INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_detections_last ON detections(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_blocks_active ON blocks(active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flow_samples(ts DESC);
"""

MYSQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    `key` VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS detections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    score INT NOT NULL DEFAULT 0,
    detail TEXT NOT NULL,
    first_seen DOUBLE NOT NULL,
    last_seen DOUBLE NOT NULL,
    auto_blocked TINYINT NOT NULL DEFAULT 0,
    UNIQUE KEY uq_detections_src_kind (src_ip, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS blocks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    reason VARCHAR(255) NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT 'manual',
    created_at DOUBLE NOT NULL,
    timeout VARCHAR(16) NOT NULL DEFAULT '1d',
    active TINYINT NOT NULL DEFAULT 1,
    UNIQUE KEY uq_blocks_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ts DOUBLE NOT NULL,
    level VARCHAR(16) NOT NULL,
    message TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS flow_samples (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ts DOUBLE NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT NOT NULL,
    dst_port INT NOT NULL,
    proto INT NOT NULL,
    bytes BIGINT NOT NULL,
    packets INT NOT NULL,
    tcp_flags INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

MYSQL_INDEXES = (
    "CREATE INDEX idx_detections_last ON detections(last_seen DESC)",
    "CREATE INDEX idx_blocks_active ON blocks(active, created_at DESC)",
    "CREATE INDEX idx_events_ts ON events(ts DESC)",
    "CREATE INDEX idx_flows_ts ON flow_samples(ts DESC)",
)


class _Backend(ABC):
    engine: str

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def _execute(self, sql: str, params: tuple = ()) -> Any: ...

    @abstractmethod
    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]: ...

    @abstractmethod
    def ensure_schema(self) -> None: ...


class _SQLiteBackend(_Backend):
    engine = "sqlite"

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with self._lock:
            self.conn.executescript(SQLITE_SCHEMA)
            cols = {
                row[1]
                for row in self.conn.execute("PRAGMA table_info(flow_samples)").fetchall()
            }
            if "tcp_flags" not in cols:
                self.conn.execute(
                    "ALTER TABLE flow_samples ADD COLUMN tcp_flags INTEGER NOT NULL DEFAULT 0"
                )
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


class _MySQLBackend(_Backend):
    engine = "mysql"

    def __init__(self, settings: Settings) -> None:
        import pymysql
        from pymysql.cursors import DictCursor

        self._lock = threading.Lock()
        self.conn = pymysql.connect(
            host=settings.mysql_host,
            port=settings.mysql_port,
            user=settings.mysql_user,
            password=settings.mysql_password,
            database=settings.mysql_database,
            charset="utf8mb4",
            autocommit=False,
            cursorclass=DictCursor,
        )
        self.ensure_schema()

    def ensure_schema(self) -> None:
        import pymysql

        with self._lock:
            cur = self.conn.cursor()
            for stmt in MYSQL_SCHEMA.split(";"):
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            for stmt in MYSQL_INDEXES:
                try:
                    cur.execute(stmt)
                except pymysql.err.OperationalError as exc:
                    if exc.args[0] not in {1061, 1062}:  # duplicate index / key name
                        raise
            cur.execute(
                """
                SELECT COUNT(*) AS n FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'flow_samples'
                  AND COLUMN_NAME = 'tcp_flags'
                """
            )
            row = cur.fetchone() or {}
            if not row.get("n"):
                try:
                    cur.execute(
                        "ALTER TABLE flow_samples ADD COLUMN tcp_flags INT NOT NULL DEFAULT 0"
                    )
                except pymysql.err.OperationalError as exc:
                    if exc.args[0] != 1060:  # duplicate column
                        raise
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def _execute(self, sql: str, params: tuple = ()) -> Any:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            self.conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [dict(row) for row in rows]


class Database:
    def __init__(self, backend: _Backend) -> None:
        self.engine = backend.engine
        self._backend = backend

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        engine = (settings.db_engine or "sqlite").strip().lower()
        if engine == "mysql":
            return cls(_MySQLBackend(settings))
        if engine != "sqlite":
            raise ValueError(f"unsupported DB_ENGINE {settings.db_engine!r} (use sqlite or mysql)")
        return cls(_SQLiteBackend(settings.db_path))

    def close(self) -> None:
        self._backend.close()

    def _execute(self, sql: str, params: tuple = ()) -> Any:
        return self._backend._execute(sql, params)

    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        return self._backend._query(sql, params)

    def _upsert_kv_sql(self) -> str:
        if self.engine == "mysql":
            return (
                "INSERT INTO kv(`key`, value) VALUES(%s, %s) "
                "ON DUPLICATE KEY UPDATE value = VALUES(value)"
            )
        return (
            "INSERT INTO kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )

    def _upsert_detection_sql(self) -> str:
        if self.engine == "mysql":
            return """
            INSERT INTO detections(src_ip, kind, score, detail, first_seen, last_seen, auto_blocked)
            VALUES(%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                score = VALUES(score),
                detail = VALUES(detail),
                last_seen = VALUES(last_seen),
                auto_blocked = GREATEST(detections.auto_blocked, VALUES(auto_blocked))
            """
        return """
            INSERT INTO detections(src_ip, kind, score, detail, first_seen, last_seen, auto_blocked)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(src_ip, kind) DO UPDATE SET
                score = excluded.score,
                detail = excluded.detail,
                last_seen = excluded.last_seen,
                auto_blocked = MAX(detections.auto_blocked, excluded.auto_blocked)
            """

    def _upsert_block_sql(self) -> str:
        if self.engine == "mysql":
            return """
            INSERT INTO blocks(ip, reason, source, created_at, timeout, active)
            VALUES(%s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                reason = VALUES(reason),
                source = VALUES(source),
                created_at = VALUES(created_at),
                timeout = VALUES(timeout),
                active = 1
            """
        return """
            INSERT INTO blocks(ip, reason, source, created_at, timeout, active)
            VALUES(?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                source = excluded.source,
                created_at = excluded.created_at,
                timeout = excluded.timeout,
                active = 1
            """

    def _trim_events_sql(self) -> str:
        if self.engine == "mysql":
            return (
                "DELETE FROM events WHERE id NOT IN "
                "(SELECT id FROM (SELECT id FROM events ORDER BY id DESC LIMIT %s) AS keep_events)"
            )
        return "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)"

    def _prune_flows_sql(self) -> str:
        if self.engine == "mysql":
            return (
                "DELETE FROM flow_samples WHERE id NOT IN "
                "(SELECT id FROM (SELECT id FROM flow_samples ORDER BY id DESC LIMIT %s) AS keep_flows)"
            )
        return (
            "DELETE FROM flow_samples WHERE id NOT IN "
            "(SELECT id FROM flow_samples ORDER BY id DESC LIMIT ?)"
        )

    def get_kv(self, key: str, default: str | None = None) -> str | None:
        ph = "%s" if self.engine == "mysql" else "?"
        rows = self._query(f"SELECT value FROM kv WHERE `key` = {ph}" if self.engine == "mysql" else f"SELECT value FROM kv WHERE key = {ph}", (key,))
        return rows[0]["value"] if rows else default

    def set_kv(self, key: str, value: str) -> None:
        self._execute(self._upsert_kv_sql(), (key, value))

    def log(self, message: str, level: str = "info") -> None:
        ph = "%s" if self.engine == "mysql" else "?"
        self._execute(
            f"INSERT INTO events(ts, level, message) VALUES({ph}, {ph}, {ph})",
            (time.time(), level, message),
        )
        self._execute(self._trim_events_sql(), (500,))

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        ph = "%s" if self.engine == "mysql" else "?"
        return self._query(f"SELECT * FROM events ORDER BY id DESC LIMIT {ph}", (limit,))

    def upsert_detection(
        self,
        src_ip: str,
        kind: str,
        score: int,
        detail: dict[str, Any],
        auto_blocked: bool = False,
    ) -> None:
        now = time.time()
        self._execute(
            self._upsert_detection_sql(),
            (src_ip, kind, score, json.dumps(detail), now, now, int(auto_blocked)),
        )

    def detections(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        if since is None:
            since = time.time() - 3600
        ph = "%s" if self.engine == "mysql" else "?"
        rows = self._query(
            f"SELECT * FROM detections WHERE last_seen >= {ph} ORDER BY last_seen DESC LIMIT {ph}",
            (since, limit),
        )
        for row in rows:
            try:
                row["detail"] = json.loads(row["detail"])
            except (json.JSONDecodeError, TypeError):
                row["detail"] = {}
        return rows

    def delete_detections_for_ip(self, ip: str) -> int:
        ph = "%s" if self.engine == "mysql" else "?"
        cur = self._execute(f"DELETE FROM detections WHERE src_ip = {ph}", (ip,))
        return int(getattr(cur, "rowcount", 0) or 0)

    def all_detection_ips(self) -> list[str]:
        return [row["src_ip"] for row in self._query("SELECT DISTINCT src_ip FROM detections")]

    def add_block(self, ip: str, reason: str, source: str, timeout: str) -> None:
        self._execute(
            self._upsert_block_sql(),
            (ip, reason, source, time.time(), timeout),
        )

    def deactivate_block(self, ip: str) -> None:
        ph = "%s" if self.engine == "mysql" else "?"
        self._execute(f"UPDATE blocks SET active = 0 WHERE ip = {ph}", (ip,))

    def blocks(self, active_only: bool = True) -> list[dict[str, Any]]:
        if active_only:
            return self._query("SELECT * FROM blocks WHERE active = 1 ORDER BY created_at DESC")
        ph = "%s" if self.engine == "mysql" else "?"
        return self._query(f"SELECT * FROM blocks ORDER BY created_at DESC LIMIT {ph}", (200,))

    def is_blocked(self, ip: str) -> bool:
        ph = "%s" if self.engine == "mysql" else "?"
        rows = self._query(f"SELECT 1 FROM blocks WHERE ip = {ph} AND active = 1", (ip,))
        return bool(rows)

    def insert_flow(self, flow: dict[str, Any]) -> None:
        ph = "%s" if self.engine == "mysql" else "?"
        self._execute(
            f"""
            INSERT INTO flow_samples(ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags)
            VALUES({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            """,
            (
                time.time(),
                flow["src_ip"],
                flow["dst_ip"],
                flow["src_port"],
                flow["dst_port"],
                flow["proto"],
                flow["bytes"],
                flow["packets"],
                int(flow.get("tcp_flags") or 0),
            ),
        )

    def prune_flows(self, keep: int = 4000) -> None:
        self._execute(self._prune_flows_sql(), (keep,))

    def recent_flows(self, limit: int = 80) -> list[dict[str, Any]]:
        ph = "%s" if self.engine == "mysql" else "?"
        return self._query(f"SELECT * FROM flow_samples ORDER BY id DESC LIMIT {ph}", (limit,))

    def table_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for table in ("kv", "blocks", "detections", "flow_samples", "events"):
            row = self._query(f"SELECT COUNT(*) AS n FROM {table}")[0]
            counts[table] = int(row["n"])
        return counts

    def info(self, settings: Settings) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "engine": self.engine,
            "tables": self.table_counts(),
        }
        if self.engine == "mysql":
            payload["host"] = settings.mysql_host
            payload["port"] = settings.mysql_port
            payload["database"] = settings.mysql_database
        else:
            payload["path"] = str(settings.db_path)
        return payload


def open_database(settings: Settings) -> Database:
    return Database.from_settings(settings)
