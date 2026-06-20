"""Shared detonation proof shape for Run Record launch gates."""

from __future__ import annotations

DETONATION_FIELDS = (
    "preflight_safe",
    "workspace_detonated",
    "workspace_receipt",
)
WORKSPACE_DETONATION_RECEIPT_TEXT_FIELDS = (
    "status",
    "reason",
)
WORKSPACE_DETONATION_RECEIPT_LIST_FIELDS = ("deleted",)
WORKSPACE_DETONATION_RECEIPT_FIELDS = (
    *WORKSPACE_DETONATION_RECEIPT_LIST_FIELDS,
    "failures",
    *WORKSPACE_DETONATION_RECEIPT_TEXT_FIELDS,
    "resource_summary",
    "updated_at",
)
WORKSPACE_DETONATION_RESOURCE_SUMMARY_TEXT_FIELDS = (
    "schema_version",
    "compartment_scope",
    "statement",
)
WORKSPACE_DETONATION_RESOURCE_SUMMARY_BOOLEAN_FIELDS = (
    "remote_worker",
    "compute_instance",
    "boot_volume_deleted",
    "ephemeral_public_ip_released",
    "network_resources_deleted",
    "compartment_deleted",
)
WORKSPACE_DETONATION_RESOURCE_SUMMARY_LIST_FIELDS = (
    "network_resources",
    "network_resources_missing",
    "missing",
    "survivors",
)
WORKSPACE_DETONATION_RESOURCE_SUMMARY_FIELDS = (
    *WORKSPACE_DETONATION_RESOURCE_SUMMARY_TEXT_FIELDS,
    *WORKSPACE_DETONATION_RESOURCE_SUMMARY_BOOLEAN_FIELDS,
    "remote_worker_cleanup",
    *WORKSPACE_DETONATION_RESOURCE_SUMMARY_LIST_FIELDS,
)
REMOTE_WORKER_CLEANUP_RECEIPT_TEXT_FIELDS = (
    "schema_version",
    "status",
    "statement",
)
REMOTE_WORKER_CLEANUP_RECEIPT_LIST_FIELDS = (
    "process_patterns",
    "paths",
)
REMOTE_WORKER_CLEANUP_RECEIPT_FIELDS = (
    *REMOTE_WORKER_CLEANUP_RECEIPT_TEXT_FIELDS,
    "host_machine_state_required",
    *REMOTE_WORKER_CLEANUP_RECEIPT_LIST_FIELDS,
)
DETONATION_KEYS = frozenset(DETONATION_FIELDS)
WORKSPACE_DETONATION_RECEIPT_KEYS = frozenset(WORKSPACE_DETONATION_RECEIPT_FIELDS)
WORKSPACE_DETONATION_RESOURCE_SUMMARY_KEYS = frozenset(
    WORKSPACE_DETONATION_RESOURCE_SUMMARY_FIELDS
)
REMOTE_WORKER_CLEANUP_RECEIPT_KEYS = frozenset(REMOTE_WORKER_CLEANUP_RECEIPT_FIELDS)
