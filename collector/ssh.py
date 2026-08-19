from __future__ import annotations

import re
import time

import paramiko

from collector.blocker import RouterError

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()].|\r")


def connect(
    host: str,
    port: int,
    user: str,
    password: str = "",
    key_path: str = "",
    timeout: int = 12,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
        kwargs["look_for_keys"] = True
    if password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def exec_command(client: paramiko.SSHClient, command: str, timeout: int = 20) -> str:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return strip_ansi((out + "\n" + err).strip())


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


class ShellSession:
    """Interactive SSH for IOS/Junos configure mode."""

    def __init__(self, client: paramiko.SSHClient, timeout: int = 20) -> None:
        chan = client.invoke_shell(width=200, height=2000)
        chan.settimeout(timeout)
        self.chan = chan
        self.timeout = timeout
        time.sleep(0.4)
        self.drain()

    def close(self) -> None:
        try:
            self.chan.close()
        except Exception:
            pass

    def drain(self) -> str:
        buf = ""
        end = time.time() + 1.2
        while time.time() < end:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", errors="replace")
                end = time.time() + 0.25
            else:
                time.sleep(0.05)
        return strip_ansi(buf)

    def read_until(self, pattern: str, timeout: int | None = None) -> str:
        buf = ""
        deadline = time.time() + (timeout or self.timeout)
        rx = re.compile(pattern)
        while time.time() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", errors="replace")
                cleaned = strip_ansi(buf)
                if rx.search(cleaned):
                    return cleaned
            else:
                time.sleep(0.04)
        raise RouterError(f"timed out waiting for {pattern!r}: {strip_ansi(buf)[-400:]}")

    def cmd(self, command: str, prompt: str = r"[>#]\s*$") -> str:
        self.chan.send(command.rstrip() + "\r")
        text = self.read_until(prompt)
        return _strip_echo(text, command)


def _strip_echo(text: str, command: str) -> str:
    lines = text.splitlines()
    if lines and command.strip() and command.strip() in lines[0]:
        return "\n".join(lines[1:]).strip()
    return text.strip()
