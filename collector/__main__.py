from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from collector.config import get_settings
from collector.db_migrate import MigrateError, migrate_sqlite_to_mysql
from collector.upgrade import UpgradeError, check_upgrade, installed_version, run_upgrade


def _serve(args: argparse.Namespace) -> None:
    if args.demo:
        os.environ["DEMO"] = "true"
        get_settings.cache_clear()

    settings = get_settings()
    uvicorn.run(
        "collector.app:app",
        host=args.host or settings.portal_host,
        port=args.port or settings.portal_port,
        reload=False,
        log_level="info",
    )


def _upgrade(args: argparse.Namespace) -> None:
    settings = get_settings()
    remote = args.remote or settings.upgrade_git_remote
    branch = args.branch or settings.upgrade_git_branch
    restart = args.restart or settings.upgrade_restart_cmd

    if args.check:
        status = check_upgrade(remote=remote, branch=branch, fetch=not args.no_fetch)
        print(f"version: {status.installed_version}")
        print(f"root:    {status.project_root}")
        if status.git:
            print(f"git:     {status.branch} @ {status.commit}")
            print(f"remote:  {status.remote}")
        print(f"status:  {status.message}")
        if not status.ok:
            sys.exit(1)
        if status.update_available:
            print(f"behind:  {status.commits_behind} ({status.latest_commit})")
            sys.exit(2)
        sys.exit(0)

    try:
        result = run_upgrade(
            remote=remote,
            branch=branch,
            restart_cmd=restart,
            use_git=not args.no_git,
            install_deps=not args.no_install,
        )
    except UpgradeError as exc:
        print(f"upgrade failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"upgraded: {result.previous_version} -> {result.installed_version}")
    if result.previous_commit and result.new_commit:
        print(f"git:      {result.previous_commit} -> {result.new_commit}")
    for line in result.log:
        print(line)
    if result.restarted:
        print(result.message)
    elif restart:
        print("restart command finished")
    else:
        print("restart the collector process to load new code")


def _db_migrate(args: argparse.Namespace) -> None:
    settings = get_settings()
    source = Path(args.source).expanduser() if args.source else settings.db_path
    try:
        report = migrate_sqlite_to_mysql(
            settings,
            sqlite_path=source,
            dry_run=args.dry_run,
            wipe=args.wipe,
            backup=args.backup,
        )
    except MigrateError as exc:
        print(f"migrate failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"source:  {report.source}")
    print(f"target:  {report.target}")
    if report.dry_run:
        print("mode:    dry run")
    if report.wiped:
        print("wiped:   yes")
    for table in ("kv", "blocks", "detections", "flow_samples", "events"):
        if table in report.counts:
            print(f"{table:14} {report.counts[table]}")
    for line in report.log:
        print(line)
    print(report.message)
    if not report.dry_run:
        print("Set DB_ENGINE=mysql in .env and restart the collector when ready.")


def _db(args: argparse.Namespace) -> None:
    if args.db_command == "migrate":
        _db_migrate(args)
    else:
        print("unknown db command", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    # Legacy: python -m collector --demo / --host / --port
    if len(sys.argv) > 1 and sys.argv[1].startswith("-"):
        sys.argv.insert(1, "serve")

    parser = argparse.ArgumentParser(
        description="NetFlow collector portal",
        epilog="Run from the install directory with the venv active: source .venv/bin/activate",
    )
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the web portal and NetFlow probe (default)")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--demo", action="store_true", help="inject synthetic scans")

    up = sub.add_parser("upgrade", help="pull latest code and reinstall dependencies")
    up.add_argument("--check", action="store_true", help="report whether an update is available")
    up.add_argument("--no-fetch", action="store_true", help="check without contacting the git remote")
    up.add_argument("--no-git", action="store_true", help="skip git pull (manual file copy upgrades)")
    up.add_argument("--no-install", action="store_true", help="skip pip install -e .")
    up.add_argument("--remote", default="", help="git remote (default: UPGRADE_GIT_REMOTE or origin)")
    up.add_argument("--branch", default="", help="git branch (default: current branch)")
    up.add_argument(
        "--restart",
        default="",
        help="shell command to run after upgrade (default: UPGRADE_RESTART_CMD from .env)",
    )

    db = sub.add_parser("db", help="database tools")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    mig = db_sub.add_parser(
        "migrate",
        help="copy SQLite data into MySQL (source .venv/bin/activate first; uses MYSQL_* from .env)",
    )
    mig.add_argument(
        "--from",
        dest="source",
        default="",
        help="SQLite file path (default: DB_PATH / data/collector.db)",
    )
    mig.add_argument("--dry-run", action="store_true", help="report row counts only")
    mig.add_argument(
        "--wipe",
        action="store_true",
        help="delete existing MySQL rows before importing",
    )
    mig.add_argument(
        "--backup",
        action="store_true",
        help="copy the SQLite file to .db.bak before migrating",
    )

    parser.set_defaults(
        command="serve",
        host=None,
        port=None,
        demo=False,
        check=False,
        no_fetch=False,
        no_git=False,
        no_install=False,
        remote="",
        branch="",
        restart="",
        db_command="",
        source="",
        dry_run=False,
        wipe=False,
        backup=False,
    )
    args = parser.parse_args()
    if args.command == "upgrade":
        _upgrade(args)
    elif args.command == "db":
        _db(args)
    else:
        _serve(args)


if __name__ == "__main__":
    main()
