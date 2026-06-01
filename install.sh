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
  for candidate in python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "FuseKit needs Python to start. Install Python, then rerun this script." >&2
  exit 1
fi

if "$PYTHON_BIN" - <<'PY'
import sys

raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  echo "Python 3.10+ was not the default. Installing an isolated Python 3.12 runtime with uv." >&2
  "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
  retry "$PYTHON_BIN" -m pip install --user --upgrade pip setuptools wheel uv
  export PATH="$HOME/.local/bin:$PATH"
  retry uv python install 3.12
  retry uv venv --python 3.12 "$VENV_DIR"
fi
. "$VENV_DIR/bin/activate"
python -m ensurepip --upgrade >/dev/null 2>&1 || true
retry python -m pip install --upgrade pip setuptools wheel
retry python -m pip install -e "$SCRIPT_DIR"
fusekit install "$APP_PATH"

echo "FuseKit installed. Launch with:"
echo "  $APP_PATH/.fusekit/setup.sh --capture-llm-key"
