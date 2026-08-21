from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from collector.version import installed_version, project_root

__all__ = ["installed_version", "project_root", "UpgradeError", "UpgradeStatus", "UpgradeResult", "check_upgrade", "run_upgrade", "is_git_checkout"]


class UpgradeError(Exception):
    pass


@dataclass
class UpgradeStatus:
    ok: bool = True
    installed_version: str = ""
    project_root: str = ""
    git: bool = False
    branch: str = ""
    commit: str = ""
    remote: str = "origin"
    update_available: bool = False
    commits_behind: int = 0
    latest_commit: str = ""
    message: str = ""
    steps: list[str] = field(default_factory=list)


@dataclass
class UpgradeResult:
    ok: bool
    installed_version: str
    previous_version: str
    previous_commit: str = ""
    new_commit: str = ""
    restarted: bool = False
    message: str = ""
    log: list[str] = field(default_factory=list)


def is_git_checkout(root: Path | None = None) -> bool:
    root = root or project_root()
    return (root / ".git").is_dir()


def check_upgrade(
    remote: str = "origin",
    branch: str = "",
    fetch: bool = True,
) -> UpgradeStatus:
    root = project_root()
    status = UpgradeStatus(
        installed_version=installed_version(),
        project_root=str(root),
        remote=remote,
    )
    if not is_git_checkout(root):
        status.git = False
        status.message = (
            "Not a git checkout. Copy new files into the install directory, then run: "
            f"{sys.executable} -m collector upgrade --no-git"
        )
        return status

    status.git = True
    try:
        status.branch = _run(["git", "branch", "--show-current"], root).stdout.strip()
        status.commit = _run(["git", "rev-parse", "--short", "HEAD"], root).stdout.strip()
    except UpgradeError as exc:
        status.ok = False
        status.message = str(exc)
        return status

    target_branch = branch or status.branch
    if fetch:
        try:
            _run(["git", "fetch", remote], root, timeout=120)
            status.steps.append(f"fetched {remote}")
        except UpgradeError as exc:
            status.ok = False
            status.message = str(exc)
            return status

    try:
        behind_raw = _run(
            ["git", "rev-list", "--count", f"HEAD..{remote}/{target_branch}"],
            root,
            check=False,
        ).stdout.strip()
        status.commits_behind = int(behind_raw or "0")
        status.update_available = status.commits_behind > 0
        if status.update_available:
            status.latest_commit = _run(
                ["git", "rev-parse", "--short", f"{remote}/{target_branch}"],
                root,
            ).stdout.strip()
            status.message = f"{status.commits_behind} commit(s) behind {remote}/{target_branch}"
        else:
            status.message = "Up to date"
    except (UpgradeError, ValueError) as exc:
        status.ok = False
        status.message = str(exc)
    return status


def run_upgrade(
    *,
    remote: str = "origin",
    branch: str = "",
    restart_cmd: str = "",
    use_git: bool = True,
    install_deps: bool = True,
) -> UpgradeResult:
    root = project_root()
    previous_version = installed_version()
    log: list[str] = []
    previous_commit = ""
    new_commit = ""

    if use_git:
        if not is_git_checkout(root):
            raise UpgradeError(
                "Install is not a git repository. Re-copy the project or run with --no-git "
                "after updating files manually."
            )
        previous_commit = _run(["git", "rev-parse", "--short", "HEAD"], root).stdout.strip()
        target_branch = branch or _run(["git", "branch", "--show-current"], root).stdout.strip()
        log.append(_run(["git", "fetch", remote], root, timeout=120).stdout or f"fetched {remote}")
        pull = _run(["git", "pull", "--ff-only", remote, target_branch], root, timeout=120)
        if pull.stdout.strip():
            log.append(pull.stdout.strip())
        if pull.stderr.strip():
            log.append(pull.stderr.strip())
        new_commit = _run(["git", "rev-parse", "--short", "HEAD"], root).stdout.strip()
    else:
        log.append("skipped git pull (--no-git)")

    if install_deps:
        pip = _run(
            [sys.executable, "-m", "pip", "install", "-e", str(root)],
            root,
            timeout=600,
        )
        for line in (pip.stdout + "\n" + pip.stderr).splitlines():
            line = line.strip()
            if line:
                log.append(line)

    restarted = False
    if restart_cmd.strip():
        log.append(f"running: {restart_cmd}")
        _run(restart_cmd.split(), root, timeout=60, shell=False)
        restarted = True

    new_version = installed_version()
    return UpgradeResult(
        ok=True,
        installed_version=new_version,
        previous_version=previous_version,
        previous_commit=previous_commit,
        new_commit=new_commit,
        restarted=restarted,
        message="Upgrade complete" + ("; service restart requested" if restarted else ""),
        log=log[-40:],
    )


def _run(
    cmd: list[str],
    cwd: Path,
    *,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UpgradeError(f"timeout: {' '.join(cmd)}") from exc
    except OSError as exc:
        raise UpgradeError(f"failed to run {' '.join(cmd)}: {exc}") from exc

    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise UpgradeError(detail or f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc
