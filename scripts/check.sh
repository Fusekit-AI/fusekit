#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  else
    echo "python or python3 is required to run FuseKit checks." >&2
    exit 127
  fi
fi

"$python_bin" -m pytest
"$python_bin" -m ruff check .
"$python_bin" -m mypy src
