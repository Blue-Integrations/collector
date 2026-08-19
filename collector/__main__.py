from __future__ import annotations

import argparse
import os

import uvicorn

from collector.config import get_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="NetFlow collector portal")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve"])
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--demo", action="store_true", help="inject synthetic scans")
    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
