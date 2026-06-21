"""Shared durable-state proof shape for disposable worker launches."""

from __future__ import annotations

DURABLE_STATE_SCHEMA_VERSION = "fusekit.durable-state.v1"
DETONATION_SCOPE_SCHEMA_VERSION = "fusekit.detonation-scope.v1"
DURABLE_STATE_DETONATION_SCOPE_MODE = "worker-and-oci-workspace"
DURABLE_STATE_STATEMENT_TERMS = ("disposable OCI worker", "encrypted/redacted state")
DETONATION_SCOPE_NO_TRACE_TERMS = ("no FuseKit worker state remains", "OCI workspace")
WORKER_REPLACEMENT_STATE_OWNER = "encrypted-vault-and-run-record"
WORKER_REPLACEMENT_STATEMENT_TERMS = (
    "encrypted/redacted run state",
    "plaintext VM scratch",
)
