from __future__ import annotations

import ipaddress
import re
import time

from collector.blocker import RouterError, RouterStatus, empty_status
from collector.config import Settings
from collector.ssh import connect, exec_command, strip_ansi

_JUNOS_FAIL = (
    "syntax error",
    "missing argument",
    "unknown command",
    "error:",
    "could not retrieve",
    "permission denied",
)


def parse_prefix_list(text: str) -> list[str]:
    """Parse `show configuration ... prefix-list | display set` or curly form."""
    ips: list[str] = []
    for match in re.finditer(
        r"(?:prefix-list\s+\S+\s+|^\s*)([0-9a-fA-F:.]+)/(\d+)\s*;?",
        text,
        re.M,
    ):
        ip, plen = match.group(1), int(match.group(2))
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4 and plen != 32:
            continue
        if addr.version == 6 and plen != 128:
            continue
        ips.append(str(addr))
    return sorted(set(ips))


class JuniperClient:
    """Junos prefix-list + firewall filter via `cli -c`."""

    vendor = "juniper"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = None
        self.last_error = ""
        self.last_ok: float | None = None
        self.identity = ""
        self.version = ""
        self.filter_ready = False

    @property
    def _list(self) -> str:
        return self.settings.juniper_prefix_list or self.settings.mikrotik_address_list

    @property
    def _filter(self) -> str:
        return self.settings.juniper_filter

    @property
    def configured(self) -> bool:
        return bool(
            self.settings.juniper_host
            and (self.settings.juniper_password or self.settings.juniper_key_path)
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
            self.settings.juniper_host,
            self.settings.juniper_port,
            self.settings.juniper_user,
            self.settings.juniper_password,
            self.settings.juniper_key_path,
            timeout=16,
        )
        return self._client

    def run(self, command: str, allow_missing: bool = False) -> str:
        if not self.configured:
            raise RouterError("Juniper credentials are not configured")
        try:
            wrapped = command if command.strip().startswith("cli") else _cli(command)
            text = strip_ansi(exec_command(self._ensure(), wrapped, timeout=24))
            lowered = text.lower()
            failed = any(marker in lowered for marker in _JUNOS_FAIL)
            if failed and allow_missing:
                return text
            if failed:
                raise RouterError(text or command)
            self.last_error = ""
            self.last_ok = time.time()
            return text
        except RouterError:
            raise
        except Exception as exc:
            self.last_error = str(exc)
            self.close()
            raise RouterError(str(exc)) from exc

    def probe(self) -> RouterStatus:
        status = empty_status(self.settings, "juniper", self.last_error)
        if not self.configured:
            status.last_error = "Set JUNIPER_PASSWORD or JUNIPER_KEY_PATH in .env"
            return status
        try:
            ver = self.run("show version")
            self.identity = _junos_hostname(ver)
            self.version = _junos_version(ver)
            listed = self.list_blocked()
            if not self.filter_ready:
                self.ensure_filter()
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
        for name in (self._list, f"{self._list}-v6"):
            raw = self.run(
                f"show configuration policy-options prefix-list {name} | display set",
                allow_missing=True,
            )
            if _missing_config(raw):
                continue
            ips.extend(parse_prefix_list(raw))
        return sorted(set(ips))

    def block(self, ip: str, comment: str) -> None:
        _ = comment
        name, prefix = _list_and_prefix(self._list, ip)
        self.ensure_filter()
        self._commit([f"set policy-options prefix-list {name} {prefix}"])

    def unblock(self, ip: str) -> None:
        name, prefix = _list_and_prefix(self._list, ip)
        self._commit(
            [f"delete policy-options prefix-list {name} {prefix}"],
            allow_missing=True,
        )

    def ensure_filter(self) -> None:
        if self.filter_ready:
            return
        name = self._list
        filt = self._filter
        shown = self.run(
            f"show configuration firewall family inet filter {filt}",
            allow_missing=True,
        )
        sets = [f"set policy-options prefix-list {name}"]
        if _missing_config(shown):
            sets.extend(
                [
                    f"set firewall family inet filter {filt} term blocked from source-prefix-list {name}",
                    f"set firewall family inet filter {filt} term blocked then discard",
                    f"set firewall family inet filter {filt} term accept-other then accept",
                ]
            )
        v6 = self.run(
            f"show configuration firewall family inet6 filter {filt}-v6",
            allow_missing=True,
        )
        sets.append(f"set policy-options prefix-list {name}-v6")
        if _missing_config(v6):
            sets.extend(
                [
                    f"set firewall family inet6 filter {filt}-v6 term blocked from source-prefix-list {name}-v6",
                    f"set firewall family inet6 filter {filt}-v6 term blocked then discard",
                    f"set firewall family inet6 filter {filt}-v6 term accept-other then accept",
                ]
            )
        self._commit(sets, allow_missing=True)
        self.filter_ready = True

    def _commit(self, sets: list[str], allow_missing: bool = False) -> str:
        body = "; ".join(sets)
        return self.run(
            f"configure private; {body}; commit and-quit",
            allow_missing=allow_missing,
        )


def _cli(command: str) -> str:
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    return f'cli -c "{escaped}"'


def _list_and_prefix(base: str, ip: str) -> tuple[str, str]:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return f"{base}-v6", f"{addr.compressed}/128"
    return base, f"{addr.compressed}/32"


def _junos_hostname(text: str) -> str:
    match = re.search(r"Hostname:\s+(\S+)", text, re.I)
    return match.group(1) if match else ""


def _junos_version(text: str) -> str:
    match = re.search(r"Junos:\s+(\S+)", text, re.I)
    if match:
        return match.group(1)
    match = re.search(r"JUNOS\s+(\S+)", text, re.I)
    return match.group(1).rstrip(",") if match else ""


def _missing_config(text: str) -> bool:
    lowered = text.lower()
    return (
        not text.strip()
        or "no such" in lowered
        or "syntax error" in lowered
        or "could not retrieve" in lowered
    )
