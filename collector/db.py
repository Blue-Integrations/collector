from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


SCHEMA = """
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
    packets INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detections_last ON detections(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_blocks_active ON blocks(active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flow_samples(ts DESC);
"""


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
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

    def get_kv(self, key: str, default: str | None = None) -> str | None:
        rows = self._query("SELECT value FROM kv WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    def set_kv(self, key: str, value: str) -> None:
        self._execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def log(self, message: str, level: str = "info") -> None:
        self._execute(
            "INSERT INTO events(ts, level, message) VALUES(?, ?, ?)",
            (time.time(), level, message),
        )
        self._execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)"
        )

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

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
            """
            INSERT INTO detections(src_ip, kind, score, detail, first_seen, last_seen, auto_blocked)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(src_ip, kind) DO UPDATE SET
                score = excluded.score,
                detail = excluded.detail,
                last_seen = excluded.last_seen,
                auto_blocked = MAX(detections.auto_blocked, excluded.auto_blocked)
            """,
            (src_ip, kind, score, json.dumps(detail), now, now, int(auto_blocked)),
        )

    def detections(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        if since is None:
            since = time.time() - 3600
        rows = self._query(
            "SELECT * FROM detections WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
            (since, limit),
        )
        for row in rows:
            try:
                row["detail"] = json.loads(row["detail"])
            except json.JSONDecodeError:
                row["detail"] = {}
        return rows

    def delete_detections_for_ip(self, ip: str) -> int:
        cur = self._execute("DELETE FROM detections WHERE src_ip = ?", (ip,))
        return cur.rowcount

    def all_detection_ips(self) -> list[str]:
        return [row["src_ip"] for row in self._query("SELECT DISTINCT src_ip FROM detections")]

    def add_block(self, ip: str, reason: str, source: str, timeout: str) -> None:
        self._execute(
            """
            INSERT INTO blocks(ip, reason, source, created_at, timeout, active)
            VALUES(?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                source = excluded.source,
                created_at = excluded.created_at,
                timeout = excluded.timeout,
                active = 1
            """,
            (ip, reason, source, time.time(), timeout),
        )

    def deactivate_block(self, ip: str) -> None:
        self._execute("UPDATE blocks SET active = 0 WHERE ip = ?", (ip,))

    def blocks(self, active_only: bool = True) -> list[dict[str, Any]]:
        if active_only:
            return self._query("SELECT * FROM blocks WHERE active = 1 ORDER BY created_at DESC")
        return self._query("SELECT * FROM blocks ORDER BY created_at DESC LIMIT 200")

    def is_blocked(self, ip: str) -> bool:
        rows = self._query("SELECT 1 FROM blocks WHERE ip = ? AND active = 1", (ip,))
        return bool(rows)

    def insert_flow(self, flow: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO flow_samples(ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )

    def prune_flows(self, keep: int = 4000) -> None:
        self._execute(
            "DELETE FROM flow_samples WHERE id NOT IN (SELECT id FROM flow_samples ORDER BY id DESC LIMIT ?)",
            (keep,),
        )

    def recent_flows(self, limit: int = 80) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM flow_samples ORDER BY id DESC LIMIT ?", (limit,))
