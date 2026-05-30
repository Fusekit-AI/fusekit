#!/bin/sh
set -eu

APP_PATH="${1:-.}"
PYTHON_BIN="${PYTHON:-}"

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "FuseKit needs Python 3.9+ to start. Install Python, then rerun this script." >&2
    exit 1
  fi
fi

"$PYTHON_BIN" -m venv .fusekit-venv
. .fusekit-venv/bin/activate
python -m ensurepip --upgrade >/dev/null 2>&1 || true
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
fusekit install "$APP_PATH"

echo "FuseKit installed. Launch with:"
echo "  $APP_PATH/.fusekit/setup.sh --capture-llm-key"
