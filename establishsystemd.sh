#!/usr/bin/env bash
# Install or refresh the collector systemd unit for this checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_NAME="collector.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
TEMPLATE="${ROOT}/deploy/collector.service"
DO_START=1

usage() {
  cat <<EOF
Usage: sudo ./establishsystemd.sh [options]

Install ${UNIT_PATH} using paths from this directory:
  ${ROOT}

Options:
  --no-start   Write unit and daemon-reload only; do not enable/start.
  -h, --help   Show this help.

Requires: .env, .venv, and pip install -e . (see README "First install").
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-start) DO_START=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo ./establishsystemd.sh" >&2
  exit 1
fi

if [[ ! -f "${ROOT}/.env" ]]; then
  echo "Missing ${ROOT}/.env" >&2
  echo "Run: cp .env.example .env   # then edit settings" >&2
  exit 1
fi

if [[ ! -d "${ROOT}/.venv" ]]; then
  echo "Missing ${ROOT}/.venv" >&2
  echo "See README \"First install\" for venv setup." >&2
  exit 1
fi

if [[ ! -x "${ROOT}/.venv/bin/python" ]]; then
  echo "Missing ${ROOT}/.venv/bin/python" >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "Missing template: ${TEMPLATE}" >&2
  exit 1
fi

RUN_USER="$(stat -c '%U' "${ROOT}")"
RUN_GROUP="$(stat -c '%G' "${ROOT}")"

sed \
  -e "s|@INSTALL_ROOT@|${ROOT}|g" \
  -e "s|@RUN_USER@|${RUN_USER}|g" \
  -e "s|@RUN_GROUP@|${RUN_GROUP}|g" \
  "${TEMPLATE}" > "${UNIT_PATH}"

chmod 644 "${UNIT_PATH}"
systemctl daemon-reload

if [[ "${DO_START}" -eq 1 ]]; then
  systemctl enable "${UNIT_NAME}"
  systemctl restart "${UNIT_NAME}"
  systemctl --no-pager --full status "${UNIT_NAME}" || true
else
  echo "Installed ${UNIT_PATH}"
  echo "Enable with: systemctl enable --now ${UNIT_NAME}"
fi

echo
echo "Install root: ${ROOT}"
echo "Service user: ${RUN_USER}:${RUN_GROUP}"
echo "Logs:         journalctl -u ${UNIT_NAME} -f"
echo "Upgrade hook: UPGRADE_RESTART_CMD=systemctl restart ${UNIT_NAME%.service}"
