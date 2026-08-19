from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from collector.config import Settings

VENDORS = ("mikrotik", "cisco", "juniper")
VENDOR_LABELS = {
    "mikrotik": "MikroTik",
    "cisco": "Cisco",
    "juniper": "Juniper",
}


class RouterError(Exception):
    pass


@dataclass
class RouterStatus:
    connected: bool
    host: str
    port: int
    vendor: str = "mikrotik"
    identity: str = ""
    version: str = ""
    address_list: str = ""
    list_count: int = 0
    filter_ready: bool = False
    last_error: str = ""
    last_ok: float | None = None


class Blocker(Protocol):
    vendor: str
    last_error: str
    last_ok: float | None

    @property
    def configured(self) -> bool: ...

    def close(self) -> None: ...

    def probe(self) -> RouterStatus: ...

    def list_blocked(self) -> list[str]: ...

    def block(self, ip: str, comment: str) -> None: ...

    def unblock(self, ip: str) -> None: ...


def normalize_vendor(value: str | None, default: str = "mikrotik") -> str:
    vendor = (value or default).strip().lower()
    if vendor in {"ios", "ios-xe", "nxos", "nx-os"}:
        return "cisco"
    if vendor in {"junos", "srx", "mx"}:
        return "juniper"
    if vendor in {"routeros", "ros", "mt"}:
        return "mikrotik"
    if vendor in VENDORS:
        return vendor
    return default


def make_blocker(settings: Settings, vendor: str | None = None) -> Blocker:
    chosen = normalize_vendor(vendor or settings.blocker_vendor)
    if chosen == "cisco":
        from collector.cisco import CiscoClient

        return CiscoClient(settings)
    if chosen == "juniper":
        from collector.juniper import JuniperClient

        return JuniperClient(settings)
    from collector.mikrotik import MikroTikClient

    return MikroTikClient(settings)


def empty_status(settings: Settings, vendor: str, error: str = "") -> RouterStatus:
    host, port, acl = settings.blocker_endpoint(vendor)
    return RouterStatus(
        connected=False,
        host=host,
        port=port,
        vendor=vendor,
        address_list=acl,
        last_error=error,
    )
