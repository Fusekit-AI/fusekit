#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  else
    echo "python or python3 is required to run FuseKit security checks." >&2
    exit 127
  fi
fi

require_module() {
  local module="$1"
  if ! "$python_bin" -m "$module" --help >/dev/null 2>&1; then
    echo "Missing Python security scanner module: $module" >&2
    echo "Install with: python -m pip install bandit pip-audit semgrep" >&2
    exit 127
  fi
}

require_module bandit
require_module pip_audit

if ! command -v semgrep >/dev/null 2>&1; then
  echo "Missing security scanner command: semgrep" >&2
  echo "Install with: python -m pip install bandit pip-audit semgrep" >&2
  exit 127
fi

"$python_bin" -m bandit -r src -x tests \
  --severity-level medium \
  --confidence-level medium

"$python_bin" -m pip_audit --progress-spinner off

semgrep scan \
  --config p/python \
  --config p/secrets \
  --error \
  --strict \
  --metrics=off \
  --timeout=30 \
  --timeout-threshold=0 \
  --exclude .git \
  --exclude .fusekit \
  --exclude .mypy_cache \
  --exclude .pytest_cache \
  --exclude .ruff_cache \
  --exclude .venv \
  --exclude build \
  --exclude dist \
  --exclude tmp
