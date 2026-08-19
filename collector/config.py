from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    portal_host: str = "0.0.0.0"
    portal_port: int = 8080
    portal_user: str = "admin"
    portal_password: str = "changeme"
    secret_key: str = "dev-insecure-change-me"

    netflow_host: str = "0.0.0.0"
    netflow_port: int = 2055

    mikrotik_host: str = "192.168.88.3"
    mikrotik_port: int = 22232
    mikrotik_user: str = "admin"
    mikrotik_password: str = ""
    mikrotik_key_path: str = ""
    mikrotik_address_list: str = "blocked-scanners"
    mikrotik_block_timeout: str = "1d"

    auto_block: bool = False
    allowlist: str = "192.168.88.0/24,127.0.0.0/8"

    scan_window_sec: int = 30
    vertical_port_threshold: int = 40
    horizontal_host_threshold: int = 40
    unique_port_threshold: int = 80

    demo: bool = False
    db_path: Path = Field(default_factory=lambda: DATA_DIR / "collector.db")

    def allowlist_cidrs(self) -> list[str]:
        return [part.strip() for part in self.allowlist.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()
