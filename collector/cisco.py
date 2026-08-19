from __future__ import annotations

import ipaddress
import re
import time

from collector.blocker import RouterError, RouterStatus, empty_status
from collector.config import Settings
from collector.ssh import ShellSession, connect, strip_ansi

_IOS_FAIL = (
    "invalid input",
    "incomplete command",
    "ambiguous command",
    "unknown command",
    "authorization failed",
    "% error",
    "connection refused",
)


def parse_object_group(text: str) -> list[str]:
    """Parse `show object-group` / `show run | section object-group` hosts."""
    ips: list[str] = []
    for match in re.finditer(r"\bhost\s+([0-9a-fA-F:.]+)\b", text):
        ips.append(match.group(1))
    for match in re.finditer(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$", text, re.M):
        ips.append(match.group(1))
    out: list[str] = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        out.append(ip)
    return sorted(set(out))


def _acl_mentions_group(text: str, group: str) -> bool:
    lowered = text.lower()
    return group.lower() in lowered and "deny" in lowered


class CiscoClient:
    """IOS / IOS-XE object-group + extended ACL via SSH."""

    vendor = "cisco"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = None
        self.last_error = ""
        self.last_ok: float | None = None
        self.identity = ""
        self.version = ""
        self.filter_ready = False

    @property
    def _group(self) -> str:
        return self.settings.cisco_object_group or self.settings.mikrotik_address_list

    @property
    def _acl(self) -> str:
        return self.settings.cisco_acl

    @property
    def configured(self) -> bool:
        return bool(
            self.settings.cisco_host
            and (self.settings.cisco_password or self.settings.cisco_key_path)
        )

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _ensure(self):
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()
        self._client = connect(
            self.settings.cisco_host,
            self.settings.cisco_port,
            self.settings.cisco_user,
            self.settings.cisco_password,
            self.settings.cisco_key_path,
            timeout=16,
        )
        return self._client

    def _session(self) -> ShellSession:
        session = ShellSession(self._ensure(), timeout=24)
        text = session.drain()
        if not re.search(r"[>#]\s*$", text):
            text += session.read_until(r"[>#]\s*$", timeout=10)
        if re.search(r">\s*$", text):
            session.chan.send("enable\r")
            en = session.read_until(r"[Pp]assword:|#\s*$")
            if re.search(r"[Pp]assword:", en):
                pw = self.settings.cisco_enable_password or self.settings.cisco_password
                session.chan.send(pw + "\r")
                session.read_until(r"#\s*$")
        session.cmd("terminal length 0")
        session.cmd("terminal width 0")
        return session

    def run(self, *commands: str) -> str:
        if not self.configured:
            raise RouterError("Cisco credentials are not configured")
        try:
            session = self._session()
            chunks: list[str] = []
            try:
                for command in commands:
                    text = session.cmd(command)
                    _raise_if_ios_fail(text, command)
                    chunks.append(text)
            finally:
                session.close()
            self.last_error = ""
            self.last_ok = time.time()
            return "\n".join(chunks)
        except RouterError:
            raise
        except Exception as exc:
            self.last_error = str(exc)
            self.close()
            raise RouterError(str(exc)) from exc

    def probe(self) -> RouterStatus:
        status = empty_status(self.settings, "cisco", self.last_error)
        if not self.configured:
            status.last_error = "Set CISCO_PASSWORD or CISCO_KEY_PATH in .env"
            return status
        try:
            ver = self.run("show version")
            self.identity = _cisco_hostname(ver)
            self.version = _cisco_version(ver)
            listed = self.list_blocked()
            if not self.filter_ready:
                self.ensure_acl()
            status.connected = True
            status.identity = self.identity
            status.version = self.version
            status.list_count = len(listed)
            status.filter_ready = self.filter_ready
            status.last_error = ""
            status.last_ok = self.last_ok
        except RouterError as exc:
            status.last_error = str(exc)
        return status

    def list_blocked(self) -> list[str]:
        ips: list[str] = []
        for name in (self._group, f"{self._group}-v6"):
            try:
                text = self.run(f"show object-group {name}")
            except RouterError:
                continue
            ips.extend(parse_object_group(text))
        return sorted(set(ips))

    def block(self, ip: str, comment: str) -> None:
        _ = comment
        group = self._group_for(ip)
        host = _cisco_host(ip)
        self.ensure_acl()
        self._configure(
            f"object-group network {group}",
            f" {host}",
            "exit",
        )

    def unblock(self, ip: str) -> None:
        group = self._group_for(ip)
        host = _cisco_host(ip)
        self._configure(
            f"object-group network {group}",
            f" no {host}",
            "exit",
        )

    def ensure_acl(self) -> None:
        if self.filter_ready:
            return
        group = self._group
        acl = self._acl
        shown = self.run(f"show ip access-lists {acl}")
        missing_acl = "not found" in shown.lower() or not re.search(
            rf"access-list\s+{re.escape(acl)}|{re.escape(acl)}", shown, re.I
        )
        lines = [
            f"object-group network {group}",
            "exit",
            f"ip access-list extended {acl}",
        ]
        if missing_acl or not _acl_mentions_group(shown, group):
            lines.append(f" 1 deny ip object-group {group} any")
        if missing_acl:
            lines.append(" 65534 permit ip any any")
        lines.append("exit")
        self._configure(*lines)
        self.filter_ready = True

    def _group_for(self, ip: str) -> str:
        return f"{self._group}-v6" if ":" in ip else self._group

    def _configure(self, *lines: str) -> str:
        return self.run("configure terminal", *lines, "end")


def _cisco_host(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return f"host {addr.compressed}"
    return f"host {addr.compressed}"


def _cisco_hostname(text: str) -> str:
    match = re.search(r"^(\S+)\s+uptime", text, re.M | re.I)
    if match:
        return match.group(1)
    match = re.search(r"uptime is", text, re.I)
    if match:
        first = text.strip().splitlines()[0].strip()
        return first.split()[0] if first else ""
    return ""


def _cisco_version(text: str) -> str:
    match = re.search(r"Version\s+([0-9A-Za-z.()+]+)", text)
    return match.group(1) if match else ""


def _raise_if_ios_fail(text: str, command: str) -> None:
    lowered = strip_ansi(text).lower()
    if "duplicate" in lowered or "not found" in lowered or "already exists" in lowered:
        return
    if any(marker in lowered for marker in _IOS_FAIL):
        raise RouterError(f"{command}: {text[-500:]}")
