#!/usr/bin/env bash
# Start the NetFlow collector portal and probe from the install directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "Missing .env in $ROOT" >&2
  echo "Run: cp .env.example .env   # then edit portal password and router SSH settings" >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  echo "Missing .venv in $ROOT" >&2
  echo "First-time setup:" >&2
  echo "  python3 -m venv .venv" >&2
  echo "  source .venv/bin/activate" >&2
  echo "  pip install -e ." >&2
  exit 1
fi

# shellcheck source=/dev/null
source .venv/bin/activate
exec python -m collector "$@"
