from __future__ import annotations

import re
import time
from dataclasses import dataclass

import paramiko

from collector.config import Settings


class MikroTikError(Exception):
    pass


@dataclass
class MikroTikStatus:
    connected: bool
    host: str
    port: int
    identity: str = ""
    version: str = ""
    address_list: str = ""
    list_count: int = 0
    filter_ready: bool = False
    last_error: str = ""
    last_ok: float | None = None


class MikroTikClient:
    """SSH control plane for RouterOS address-list blocking."""

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

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.settings.mikrotik_host,
            "port": self.settings.mikrotik_port,
            "username": self.settings.mikrotik_user,
            "timeout": 8,
            "auth_timeout": 8,
            "banner_timeout": 8,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.settings.mikrotik_key_path:
            kwargs["key_filename"] = self.settings.mikrotik_key_path
            kwargs["look_for_keys"] = True
        if self.settings.mikrotik_password:
            kwargs["password"] = self.settings.mikrotik_password
        client.connect(**kwargs)
        return client

    def _ensure(self) -> paramiko.SSHClient:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()
        self._client = self._connect()
        return self._client

    def run(self, command: str) -> str:
        if not self.configured:
            raise MikroTikError("MikroTik credentials are not configured")
        try:
            client = self._ensure()
            _stdin, stdout, stderr = client.exec_command(command, timeout=12)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            status = stdout.channel.recv_exit_status()
            text = (out + "\n" + err).strip()
            if status not in (0, -1) and "failure" in text.lower():
                raise MikroTikError(text or f"command failed with status {status}")
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
        status = MikroTikStatus(
            connected=False,
            host=self.settings.mikrotik_host,
            port=self.settings.mikrotik_port,
            address_list=self.settings.mikrotik_address_list,
            last_error=self.last_error,
            last_ok=self.last_ok,
        )
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
                raw = self.run(f"{path} print terse without-paging where list={name}")
            except MikroTikError:
                continue
            for match in re.finditer(r"address=([0-9a-fA-F:.]+)", raw):
                ips.append(match.group(1))
        return sorted(set(ips))

    def block(self, ip: str, comment: str) -> None:
        path = _list_path(ip)
        name = self.settings.mikrotik_address_list
        timeout = self.settings.mikrotik_block_timeout
        existing = self.run(f"{path} print count-only where list={name} address={ip}")
        if _count(existing) > 0:
            return
        safe_comment = comment.replace('"', "'")[:80]
        self.run(
            f"{path} add list={name} address={ip} timeout={timeout} comment=\"{safe_comment}\""
        )

    def unblock(self, ip: str) -> None:
        path = _list_path(ip)
        name = self.settings.mikrotik_address_list
        self.run(f"{path} remove [find where list={name} address={ip}]")

    def ensure_filter_rules(self) -> None:
        """Make sure traffic from the address-list is dropped on input and forward."""
        name = self.settings.mikrotik_address_list
        self._ensure_drop("/ip firewall filter", name, "netflow-collector:drop-scanners")
        try:
            self._ensure_drop("/ipv6 firewall filter", name, "netflow-collector:drop-scanners6")
        except MikroTikError:
            pass
        self.filter_ready = True

    def _ensure_drop(self, path: str, name: str, comment: str) -> None:
        existing = self.run(f'{path} print count-only where comment="{comment}"')
        if _count(existing) > 0:
            return
        self.run(
            f"{path} add chain=input action=drop "
            f'src-address-list={name} comment="{comment}" place-before=0'
        )
        self.run(
            f"{path} add chain=forward action=drop "
            f'src-address-list={name} comment="{comment}-fwd"'
        )


def _list_path(ip: str) -> str:
    return "/ipv6 firewall address-list" if ":" in ip else "/ip firewall address-list"


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("bad command") and "syntax error" not in line:
            return line
    return ""


def _count(text: str) -> int:
    for token in text.replace("\n", " ").split():
        if token.isdigit():
            return int(token)
    return 0
