import pytest

from collector.config import Settings
from collector.db import Database, open_database


def test_open_database_sqlite_default(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DB_ENGINE", "sqlite")
    monkeypatch.setenv("DB_PATH", str(db_file))
    from collector.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    db = open_database(settings)
    assert db.engine == "sqlite"
    db.set_kv("hello", "world")
    assert db.get_kv("hello") == "world"
    db.close()
    assert db_file.exists()


def test_sqlite_detection_upsert(tmp_path):
    db = Database.from_settings(Settings(db_engine="sqlite", db_path=tmp_path / "t.db"))
    db.upsert_detection("203.0.113.1", "spray", 80, {"unique_ports": 80})
    db.upsert_detection("203.0.113.1", "spray", 90, {"unique_ports": 90})
    rows = db.detections(limit=10, since=0)
    assert len(rows) == 1
    assert rows[0]["score"] == 90
    db.close()


def test_sqlite_info_and_table_counts(tmp_path):
    settings = Settings(db_engine="sqlite", db_path=tmp_path / "metrics.db")
    db = Database.from_settings(settings)
    db.insert_flow(
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 443,
            "proto": 6,
            "bytes": 100,
            "packets": 1,
            "tcp_flags": 2,
        }
    )
    db.log("test event")
    counts = db.table_counts()
    assert counts["flow_samples"] == 1
    assert counts["events"] >= 1
    info = db.info(settings)
    assert info["engine"] == "sqlite"
    assert info["path"] == str(settings.db_path)
    assert info["tables"]["flow_samples"] == 1
    db.close()


def test_unsupported_engine_raises(tmp_path):
    with pytest.raises(ValueError, match="unsupported DB_ENGINE"):
        Database.from_settings(Settings(db_engine="postgres", db_path=tmp_path / "x.db"))


@pytest.mark.skipif(
    not __import__("os").environ.get("COLLECTOR_TEST_MYSQL"),
    reason="set COLLECTOR_TEST_MYSQL=1 to run live MySQL integration test",
)
def test_open_database_mysql_live():
    from collector.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    if settings.db_engine != "mysql":
        pytest.skip("DB_ENGINE is not mysql")
    db = open_database(settings)
    assert db.engine == "mysql"
    token = f"probe-{__import__('time').time()}"
    db.set_kv("mysql_probe", token)
    assert db.get_kv("mysql_probe") == token
    db.close()
