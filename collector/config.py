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

    blocker_vendor: str = "mikrotik"

    cisco_host: str = ""
    cisco_port: int = 22
    cisco_user: str = "admin"
    cisco_password: str = ""
    cisco_key_path: str = ""
    cisco_enable_password: str = ""
    cisco_acl: str = "NETFLOW-COLLECTOR"
    cisco_object_group: str = "blocked-scanners"

    juniper_host: str = ""
    juniper_port: int = 22
    juniper_user: str = "admin"
    juniper_password: str = ""
    juniper_key_path: str = ""
    juniper_prefix_list: str = "blocked-scanners"
    juniper_filter: str = "NETFLOW-COLLECTOR"

    auto_block: bool = False
    allowlist: str = "192.168.88.0/24,127.0.0.0/8"
    protected_cidrs: str = "151.244.12.0/27"

    scan_window_sec: int = 30
    vertical_port_threshold: int = 40
    horizontal_host_threshold: int = 40
    unique_port_threshold: int = 80
    icmp_flood_threshold: int = 50
    large_flow_min_bytes: int = 2048
    large_flow_threshold: int = 20

    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    webhook_notify_detections: bool = True
    webhook_notify_blocks: bool = True

    demo: bool = False
    db_engine: str = "sqlite"
    db_path: Path = Field(default_factory=lambda: DATA_DIR / "collector.db")
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "collector"
    mysql_password: str = ""
    mysql_database: str = "collector"

    upgrade_git_remote: str = "origin"
    upgrade_git_branch: str = ""
    upgrade_restart_cmd: str = ""
    upgrade_allow_api: bool = True

    def allowlist_cidrs(self) -> list[str]:
        return [part.strip() for part in self.allowlist.split(",") if part.strip()]

    def protected_cidr_list(self) -> list[str]:
        return [part.strip() for part in self.protected_cidrs.split(",") if part.strip()]

    def blocker_endpoint(self, vendor: str) -> tuple[str, int, str]:
        if vendor == "cisco":
            return self.cisco_host, self.cisco_port, self.cisco_object_group
        if vendor == "juniper":
            return self.juniper_host, self.juniper_port, self.juniper_prefix_list
        return self.mikrotik_host, self.mikrotik_port, self.mikrotik_address_list

    def vendor_profile(self, vendor: str) -> dict[str, object]:
        vendor = vendor.strip().lower()
        if vendor == "cisco":
            host, port, acl = self.cisco_host, self.cisco_port, self.cisco_object_group
            auth_ok = bool(self.cisco_password or self.cisco_key_path)
            missing: list[str] = []
            if not host:
                missing.append("CISCO_HOST")
            if not auth_ok:
                missing.append("CISCO_PASSWORD or CISCO_KEY_PATH")
            return {
                "vendor": "cisco",
                "label": "Cisco",
                "host": host,
                "port": port,
                "access_list": acl,
                "configured": bool(host and auth_ok),
                "env_keys": [
                    "CISCO_HOST",
                    "CISCO_PORT",
                    "CISCO_USER",
                    "CISCO_PASSWORD or CISCO_KEY_PATH",
                    "CISCO_ENABLE_PASSWORD (optional)",
                    "CISCO_ACL",
                    "CISCO_OBJECT_GROUP",
                ],
                "missing": missing,
            }
        if vendor == "juniper":
            host, port, acl = self.juniper_host, self.juniper_port, self.juniper_prefix_list
            auth_ok = bool(self.juniper_password or self.juniper_key_path)
            missing = []
            if not host:
                missing.append("JUNIPER_HOST")
            if not auth_ok:
                missing.append("JUNIPER_PASSWORD or JUNIPER_KEY_PATH")
            return {
                "vendor": "juniper",
                "label": "Juniper",
                "host": host,
                "port": port,
                "access_list": acl,
                "configured": bool(host and auth_ok),
                "env_keys": [
                    "JUNIPER_HOST",
                    "JUNIPER_PORT",
                    "JUNIPER_USER",
                    "JUNIPER_PASSWORD or JUNIPER_KEY_PATH",
                    "JUNIPER_PREFIX_LIST",
                    "JUNIPER_FILTER",
                ],
                "missing": missing,
            }
        host, port, acl = self.mikrotik_host, self.mikrotik_port, self.mikrotik_address_list
        auth_ok = bool(self.mikrotik_password or self.mikrotik_key_path)
        missing = []
        if not auth_ok:
            missing.append("MIKROTIK_PASSWORD or MIKROTIK_KEY_PATH")
        return {
            "vendor": "mikrotik",
            "label": "MikroTik",
            "host": host,
            "port": port,
            "access_list": acl,
            "configured": auth_ok,
            "env_keys": [
                "MIKROTIK_HOST",
                "MIKROTIK_PORT",
                "MIKROTIK_USER",
                "MIKROTIK_PASSWORD or MIKROTIK_KEY_PATH",
                "MIKROTIK_ADDRESS_LIST",
                "MIKROTIK_BLOCK_TIMEOUT",
            ],
            "missing": missing,
        }

    def router_profiles(self) -> dict[str, dict[str, object]]:
        return {vendor: self.vendor_profile(vendor) for vendor in ("mikrotik", "cisco", "juniper")}


@lru_cache
def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()
