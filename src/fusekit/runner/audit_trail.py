"""Shared public audit-trail shape for launch proof gates."""

from __future__ import annotations

AUDIT_TRAIL_SCHEMA_VERSION = "fusekit.audit-trail.v1"
AUDIT_TRAIL_ENTRY_KEYS = frozenset(
    {
        "category",
        "action",
        "provider",
        "target",
        "status",
        "source",
        "wake_event_id",
        "summary",
        "resource",
        "audit_log_index",
        "receipt_action_index",
    }
)
AUDIT_TRAIL_CATEGORIES = frozenset(
    {
        "credential_capture",
        "provider_action",
        "dns_write",
        "human_approval",
        "detonation",
    }
)
AUDIT_TRAIL_KEYS = frozenset(
    {
        "schema_version",
        "entry_count",
        "counts",
        "entries",
        "statement",
    }
)
