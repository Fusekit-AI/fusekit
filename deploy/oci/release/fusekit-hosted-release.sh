#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

EXPECTED_COMMIT_SHA="${1:-${EXPECTED_COMMIT_SHA:-}}"
FUSEKIT_REPO_URL="${FUSEKIT_REPO_URL:-https://github.com/Fusekit-AI/fusekit.git}"
RELEASE_ROOT="${FUSEKIT_RELEASE_ROOT:-/opt/fusekit/releases}"
CURRENT_LINK="${FUSEKIT_CURRENT_LINK:-/opt/fusekit/current}"
RECEIPT_DIR="${FUSEKIT_RELEASE_RECEIPT_DIR:-/var/lib/fusekit/release-receipts}"
PROVENANCE_FILE="${FUSEKIT_HOSTED_PROVENANCE_FILE:-/etc/fusekit/hosted-provenance.env}"
HOSTED_SERVICE="${FUSEKIT_HOSTED_SERVICE:-fusekit-hosted.service}"
DISPATCH_SERVICE="${FUSEKIT_DISPATCH_SERVICE:-fusekit-worker-dispatch.service}"

if [[ ! "${EXPECTED_COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected commit must be a 40-character lowercase git sha" >&2
  exit 64
fi

if [[ "${FUSEKIT_REPO_URL}" != "https://github.com/Fusekit-AI/fusekit.git" ]]; then
  echo "refusing non-canonical FuseKit repository URL" >&2
  exit 64
fi

if [[ "$(id -u)" != "0" ]]; then
  echo "run as root on the FuseKit OCI hosted launcher" >&2
  exit 77
fi

for command in git systemctl install ln mv readlink rm; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing required command: ${command}" >&2
    exit 69
  fi
done

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="$(command -v python3.12 || command -v python3 || true)"
fi
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "missing python3.12 or python3" >&2
  exit 69
fi

umask 077
install -d -o root -g root -m 0750 "${RELEASE_ROOT}"
install -d -o fusekit -g fusekit -m 0750 "${RECEIPT_DIR}"
install -d -o root -g root -m 0750 "$(dirname "${PROVENANCE_FILE}")"

RELEASE_DIR="${RELEASE_ROOT}/${EXPECTED_COMMIT_SHA}"
BEFORE_TARGET="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
BEFORE_COMMIT=""
if [[ -n "${BEFORE_TARGET}" && -d "${BEFORE_TARGET}/.git" ]]; then
  BEFORE_COMMIT="$(git -C "${BEFORE_TARGET}" rev-parse HEAD 2>/dev/null || true)"
fi

ROLLBACK_NEEDED=1
INCOMING=""
cleanup_on_exit() {
  local status=$?
  if [[ -n "${INCOMING}" && -d "${INCOMING}" ]]; then
    rm -rf "${INCOMING}"
  fi
  if [[ "${ROLLBACK_NEEDED}" == "1" && -n "${BEFORE_TARGET}" && -d "${BEFORE_TARGET}" ]]; then
    ln -sfn "${BEFORE_TARGET}" "${CURRENT_LINK}.rollback"
    mv -Tf "${CURRENT_LINK}.rollback" "${CURRENT_LINK}"
    systemctl restart "${HOSTED_SERVICE}" "${DISPATCH_SERVICE}" || true
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

if [[ ! -d "${RELEASE_DIR}" ]]; then
  INCOMING="$(mktemp -d "${RELEASE_ROOT}/.incoming.${EXPECTED_COMMIT_SHA}.XXXXXX")"
  git clone --quiet "${FUSEKIT_REPO_URL}" "${INCOMING}/repo"
  git -C "${INCOMING}/repo" checkout --quiet --detach "${EXPECTED_COMMIT_SHA}"
  ACTUAL_COMMIT="$(git -C "${INCOMING}/repo" rev-parse HEAD)"
  if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT_SHA}" ]]; then
    echo "checkout commit mismatch" >&2
    exit 70
  fi
  "${PYTHON_BIN}" -m venv "${INCOMING}/repo/.venv"
  "${INCOMING}/repo/.venv/bin/python" -m pip install --upgrade pip
  "${INCOMING}/repo/.venv/bin/python" -m pip install "${INCOMING}/repo"
  chown -R fusekit:fusekit "${INCOMING}/repo"
  mv "${INCOMING}/repo" "${RELEASE_DIR}"
  rmdir "${INCOMING}"
  INCOMING=""
else
  ACTUAL_COMMIT="$(git -C "${RELEASE_DIR}" rev-parse HEAD)"
  if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT_SHA}" ]]; then
    echo "existing release commit mismatch" >&2
    exit 70
  fi
fi

cat > "${PROVENANCE_FILE}.tmp" <<EOF
FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER=oci
FUSEKIT_HOSTED_DEPLOYMENT_URL=https://fusekit.snowmanai.org
FUSEKIT_HOSTED_GIT_PROVIDER=github
FUSEKIT_HOSTED_GIT_REPO_OWNER=Fusekit-AI
FUSEKIT_HOSTED_GIT_REPO_SLUG=fusekit
FUSEKIT_HOSTED_GIT_COMMIT_REF=main
FUSEKIT_HOSTED_GIT_COMMIT_SHA=${EXPECTED_COMMIT_SHA}
EOF
chown root:root "${PROVENANCE_FILE}.tmp"
chmod 0600 "${PROVENANCE_FILE}.tmp"
mv -f "${PROVENANCE_FILE}.tmp" "${PROVENANCE_FILE}"

ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}.next"
mv -Tf "${CURRENT_LINK}.next" "${CURRENT_LINK}"
systemctl daemon-reload
systemctl restart "${HOSTED_SERVICE}" "${DISPATCH_SERVICE}"
systemctl is-active --quiet "${HOSTED_SERVICE}"
systemctl is-active --quiet "${DISPATCH_SERVICE}"
AFTER_COMMIT="$(git -C "$(readlink -f "${CURRENT_LINK}")" rev-parse HEAD)"

if [[ "${AFTER_COMMIT}" != "${EXPECTED_COMMIT_SHA}" ]]; then
  echo "post-release commit mismatch" >&2
  exit 70
fi

RECEIPT_PATH="${RECEIPT_DIR}/release-${EXPECTED_COMMIT_SHA}.json"
"${PYTHON_BIN}" - "${RECEIPT_PATH}" "${BEFORE_COMMIT}" "${AFTER_COMMIT}" "${RELEASE_DIR}" <<'PY'
import json
import sys
from pathlib import Path

receipt_path, before_commit, after_commit, release_dir = sys.argv[1:5]
payload = {
    "schema_version": "fusekit.oci-hosted-release-receipt.v1",
    "target": "fusekit.snowmanai.org",
    "mutated_paths": [
        "/opt/fusekit/current",
        "/etc/fusekit/hosted-provenance.env",
        "/var/lib/fusekit/release-receipts",
    ],
    "restarted_services": [
        "fusekit-hosted.service",
        "fusekit-worker-dispatch.service",
    ],
    "before_commit_sha": before_commit,
    "after_commit_sha": after_commit,
    "release_dir": release_dir,
    "rollback": {
        "mode": "current_symlink_restore",
        "previous_commit_sha": before_commit,
    },
    "post_deploy_proof_command": (
        "fusekit-hosted-verify --origin https://fusekit.snowmanai.org "
        f"--expected-commit-sha {after_commit}"
    ),
    "secret_boundary": (
        "Receipt contains release paths, service names, and public git commits only. "
        "Runtime secrets remain in /etc/fusekit/hosted-secrets.env and are not read or emitted."
    ),
}
Path(receipt_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
chown fusekit:fusekit "${RECEIPT_PATH}"
chmod 0600 "${RECEIPT_PATH}"

ROLLBACK_NEEDED=0
trap - EXIT
echo "${RECEIPT_PATH}"
