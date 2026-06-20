"""Shared rollback metadata proof shape for launch gates."""

from __future__ import annotations

ROLLBACK_PROOF_STATUSES = frozenset({"planned", "done"})
ROLLBACK_METADATA_ACTIONS_FIELDS = (
    "rollback",
    "actions",
)
ROLLBACK_METADATA_ACTION_TEXT_FIELDS = (
    "action",
    "status",
    "detail",
    "provider",
)
ROLLBACK_METADATA_ACTION_KEYS = frozenset(ROLLBACK_METADATA_ACTION_TEXT_FIELDS)
ROLLBACK_METADATA_KEYS = frozenset(ROLLBACK_METADATA_ACTIONS_FIELDS)
