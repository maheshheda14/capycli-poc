#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_PYTHON="${REPO_ROOT}/.venv_frontend_api/bin/python"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "Creating frontend API virtualenv..."
  "${SCRIPT_DIR}/setup_frontend_api_env.sh"
fi

export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

echo "Starting API on ${HOST}:${PORT}"
exec "${VENV_PYTHON}" -m uvicorn app:app --host "${HOST}" --port "${PORT}"