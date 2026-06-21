"""Shared Run Record acceptance and recovery proof shapes."""

from __future__ import annotations

ACCEPTANCE_SUMMARY_READY_FIELDS = (
    "launch_ready",
    "public_launch_ready",
    "remote_artifacts_ready",
    "recording_proof_ready",
    "recording_ready",
)
ACCEPTANCE_SUMMARY_FIELDS = (
    "blockers",
    "error",
    *ACCEPTANCE_SUMMARY_READY_FIELDS,
    "missing",
    "mode",
)
ACCEPTANCE_SUMMARY_KEYS = frozenset(ACCEPTANCE_SUMMARY_FIELDS)
ACCEPTANCE_BLOCKER_REQUIRED_FIELDS = ("item", "category", "next_action")
ACCEPTANCE_BLOCKER_OPTIONAL_FIELDS = ("detail",)
ACCEPTANCE_BLOCKER_FIELDS = (
    *ACCEPTANCE_BLOCKER_REQUIRED_FIELDS,
    *ACCEPTANCE_BLOCKER_OPTIONAL_FIELDS,
)
ACCEPTANCE_BLOCKER_KEYS = frozenset(ACCEPTANCE_BLOCKER_FIELDS)
RUN_RECORD_ERROR_FIELDS = ("source", "id", "detail")
RUN_RECORD_ERROR_KEYS = frozenset(RUN_RECORD_ERROR_FIELDS)
