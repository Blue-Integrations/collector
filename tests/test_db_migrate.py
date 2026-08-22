import sqlite3

import pytest

from collector.config import Settings
from collector.db import Database
from collector.db_migrate import MigrateError, migrate_sqlite_to_mysql


def _seed_sqlite(path):
    db = Database.from_settings(Settings(db_engine="sqlite", db_path=path))
    db.set_kv("auto_block", "true")
    db.add_block("203.0.113.9", "manual", "manual", "1d")
    db.upsert_detection("203.0.113.9", "spray", 80, {"unique_ports": 80})
    db.insert_flow(
        {
            "src_ip": "203.0.113.9",
            "dst_ip": "151.244.12.6",
            "src_port": 40000,
            "dst_port": 443,
            "proto": 6,
            "bytes": 100,
            "packets": 1,
            "tcp_flags": 2,
        }
    )
    db.log("seed event")
    db.close()


def test_migrate_dry_run_counts(tmp_path):
    src = tmp_path / "source.db"
    _seed_sqlite(src)
    report = migrate_sqlite_to_mysql(
        Settings(db_engine="sqlite", db_path=src),
        sqlite_path=src,
        dry_run=True,
    )
    assert report.ok
    assert report.counts["kv"] >= 1
    assert report.counts["blocks"] == 1
    assert report.counts["detections"] == 1
    assert report.counts["flow_samples"] == 1
    assert report.counts["events"] >= 1


def test_migrate_missing_sqlite(tmp_path):
    with pytest.raises(MigrateError, match="not found"):
        migrate_sqlite_to_mysql(
            Settings(db_engine="sqlite", db_path=tmp_path / "missing.db"),
            sqlite_path=tmp_path / "missing.db",
        )


@pytest.mark.skipif(
    not __import__("os").environ.get("COLLECTOR_TEST_MYSQL"),
    reason="set COLLECTOR_TEST_MYSQL=1 to run live MySQL migration test",
)
def test_migrate_sqlite_to_mysql_live(tmp_path):
    from collector.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    src = tmp_path / "migrate-source.db"
    _seed_sqlite(src)
    report = migrate_sqlite_to_mysql(
        settings,
        sqlite_path=src,
        wipe=True,
    )
    assert report.ok
    assert report.counts["blocks"] == 1
    target = Database.from_settings(settings.model_copy(update={"db_engine": "mysql"}))
    try:
        assert target.get_kv("auto_block") == "true"
        assert target.is_blocked("203.0.113.9")
        rows = target.detections(limit=10, since=0)
        assert any(row["kind"] == "spray" for row in rows)
    finally:
        target.close()
