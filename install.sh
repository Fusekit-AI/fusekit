#!/bin/sh
set -eu

APP_PATH="${1:-.}"
PYTHON_BIN="${PYTHON:-}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV_DIR="${FUSEKIT_INSTALL_VENV:-$SCRIPT_DIR/.fusekit-venv}"

retry() {
  attempts=0
  until "$@"; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 3 ]; then
      return 1
    fi
    echo "Retrying after transient install failure: $*" >&2
    sleep $((attempts * 5))
  done
}

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "FuseKit needs Python 3.10+ to start. Install Python, then rerun this script." >&2
    exit 1
  fi
fi

"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("FuseKit needs Python 3.10+ to start.")
PY

"$PYTHON_BIN" -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"
python -m ensurepip --upgrade >/dev/null 2>&1 || true
retry python -m pip install --upgrade pip setuptools wheel
retry python -m pip install -e "$SCRIPT_DIR"
fusekit install "$APP_PATH"

echo "FuseKit installed. Launch with:"
echo "  $APP_PATH/.fusekit/setup.sh --capture-llm-key"
