from __future__ import annotations

import re
import time

import paramiko

from collector.blocker import RouterError, RouterStatus, empty_status
from collector.config import Settings
from collector.ssh import connect, exec_command

MikroTikError = RouterError
MikroTikStatus = RouterStatus


_ROS_FAIL = (
    "no such item",
    "syntax error",
    "bad command",
    "failure:",
    "expected end of command",
    "invalid value",
)


class MikroTikClient:
    """SSH control plane for RouterOS address-list blocking."""

    vendor = "mikrotik"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: paramiko.SSHClient | None = None
        self.last_error = ""
        self.last_ok: float | None = None
        self.identity = ""
        self.version = ""
        self.filter_ready = False

    @property
    def configured(self) -> bool:
        return bool(self.settings.mikrotik_password or self.settings.mikrotik_key_path)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _connect(self):
        return connect(
            self.settings.mikrotik_host,
            self.settings.mikrotik_port,
            self.settings.mikrotik_user,
            self.settings.mikrotik_password,
            self.settings.mikrotik_key_path,
        )

    def _ensure(self) -> paramiko.SSHClient:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()
        self._client = self._connect()
        return self._client

    def run(self, command: str, allow_missing: bool = False) -> str:
        if not self.configured:
            raise MikroTikError("MikroTik credentials are not configured")
        try:
            client = self._ensure()
            text = exec_command(client, command, timeout=12)
            lowered = text.lower()
            failed = any(marker in lowered for marker in _ROS_FAIL)
            if failed and allow_missing:
                return text
            if failed:
                raise MikroTikError(text or "command failed")
            self.last_error = ""
            self.last_ok = time.time()
            return text
        except MikroTikError:
            raise
        except Exception as exc:
            self.last_error = str(exc)
            self.close()
            raise MikroTikError(str(exc)) from exc

    def probe(self) -> MikroTikStatus:
        status = empty_status(self.settings, "mikrotik", self.last_error)
        if not self.configured:
            status.last_error = "Set MIKROTIK_PASSWORD or MIKROTIK_KEY_PATH in .env"
            return status
        try:
            identity = self.run(":put [/system identity get name]")
            version = self.run(":put [/system resource get version]")
            self.identity = _first_line(identity) or self.identity
            self.version = _first_line(version) or self.version
            listed = self.list_blocked()
            self.ensure_filter_rules()
            status.connected = True
            status.identity = self.identity
            status.version = self.version
            status.list_count = len(listed)
            status.filter_ready = self.filter_ready
            status.last_error = ""
            status.last_ok = self.last_ok
        except MikroTikError as exc:
            status.last_error = str(exc)
        return status

    def list_blocked(self) -> list[str]:
        name = self.settings.mikrotik_address_list
        ips: list[str] = []
        for path in ("/ip firewall address-list", "/ipv6 firewall address-list"):
            try:
                raw = self.run(
                    f"{path} print terse without-paging where list={name}",
                    allow_missing=True,
                )
            except MikroTikError:
                continue
            if _is_missing_menu(raw):
                continue
            for match in re.finditer(r"address=([0-9a-fA-F:.]+)", raw):
                ips.append(match.group(1))
        return sorted(set(ips))

    def block(self, ip: str, comment: str) -> None:
        path = _list_path(ip)
        name = self.settings.mikrotik_address_list
        timeout = self.settings.mikrotik_block_timeout
        existing = self.run(
            f"{path} print count-only where list={name} address={ip}",
            allow_missing=True,
        )
        if _count(existing) > 0:
            self._drop_connections(ip)
            return
        safe_comment = comment.replace('"', "'")[:80]
        self.run(
            f"{path} add list={name} address={ip} timeout={timeout} comment=\"{safe_comment}\""
        )
        self._drop_connections(ip)

    def unblock(self, ip: str) -> None:
        path = _list_path(ip)
        name = self.settings.mikrotik_address_list
        self.run(
            f"{path} remove [find where list={name} address={ip}]",
            allow_missing=True,
        )

    def _drop_connections(self, ip: str) -> None:
        """Kill already-established / fasttracked sessions so a new block takes effect."""
        escaped = re.escape(ip)
        table = "/ipv6 firewall connection" if ":" in ip else "/ip firewall connection"
        self.run(
            f'{table} remove [find where src-address~"{escaped}"]',
            allow_missing=True,
        )
        self.run(
            f'{table} remove [find where dst-address~"{escaped}"]',
            allow_missing=True,
        )

    def ensure_filter_rules(self) -> None:
        """One IPv4 forward drop. Other chains never see this traffic."""
        self._scrub_ipv6_collector_rules()
        self._scrub_unused_ip_rules()
        self._ensure_ip_drop("forward", "netflow-collector:drop-scanners-fwd")
        self.filter_ready = True

    def _scrub_ipv6_collector_rules(self) -> None:
        leftover = self.run(
            '/ipv6 firewall filter print count-only where comment~"netflow-collector"',
            allow_missing=True,
        )
        if _count(leftover) == 0:
            return
        self.run(
            '/ipv6 firewall filter remove [find comment~"netflow-collector"]',
            allow_missing=True,
        )

    def _scrub_unused_ip_rules(self) -> None:
        """Remove extra collector rules that sit on chains packets never enter."""
        extras = (
            ("/ip firewall filter", "netflow-collector:drop-scanners"),
            ("/ip firewall filter", "netflow-collector:drop-scanners-fwd-in"),
            ("/ip firewall filter", "netflow-collector:drop-scanners-fwd-in2"),
            ("/ip firewall raw", "netflow-collector:drop-scanners-raw"),
        )
        for path, comment in extras:
            found = self.run(
                f'{path} print count-only where comment="{comment}"',
                allow_missing=True,
            )
            if _count(found) == 0:
                continue
            self.run(
                f'{path} remove [find comment="{comment}"]',
                allow_missing=True,
            )

    def _ensure_ip_drop(self, chain: str, comment: str) -> None:
        name = self.settings.mikrotik_address_list
        existing = self.run(
            f'/ip firewall filter print count-only where comment="{comment}"'
        )
        if _count(existing) > 0:
            return
        self.run(
            "/ip firewall filter add "
            f"chain={chain} action=drop src-address-list={name} comment=\"{comment}\""
        )
        # New rules append at the bottom; drop must run before later accepts.
        self.run(
            f'/ip firewall filter move [find comment="{comment}"] destination=0',
            allow_missing=True,
        )


def _list_path(ip: str) -> str:
    return "/ipv6 firewall address-list" if ":" in ip else "/ip firewall address-list"


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("bad command") and "syntax error" not in line:
            return line
    return ""


def _is_missing_menu(text: str) -> bool:
    lowered = text.lower()
    return "no such item" in lowered or "bad command" in lowered or "syntax error" in lowered


def _count(text: str) -> int:
    """Parse `print count-only` (a lone integer). Ignore 'line 1' in error strings."""
    for line in text.strip().splitlines():
        token = line.strip()
        if token.isdigit():
            return int(token)
    return 0
