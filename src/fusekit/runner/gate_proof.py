"""Shared provider-gate and wake-event proof shapes for launch gates."""

from __future__ import annotations

PROVIDER_GATES_ARTIFACT_GATES_FIELD = "gates"
PROVIDER_GATES_ARTIFACT_KEYS = frozenset({PROVIDER_GATES_ARTIFACT_GATES_FIELD})
PROVIDER_GATES_KEYS = frozenset(
    {
        "total",
        "statuses",
        "providers",
        "records",
    }
)
PROVIDER_GATE_RECORD_KEYS = frozenset(
    {
        "id",
        "provider",
        "status",
        "classification",
        "target",
        "captured_targets",
        "reason",
        "resume_url",
        "follow_steps",
        "next_action",
        "resume_hint",
        "success_criteria",
        "avoid_steps",
        "attempts",
        "last_opened_url",
        "last_opened_at",
        "last_wake_event",
        "last_wake_event_id",
        "last_wake_event_at",
        "created_at",
        "updated_at",
    }
)
WAKE_EVENTS_KEYS = frozenset(
    {
        "total",
        "event_counts",
        "events",
    }
)
WAKE_EVENT_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "event",
        "gate_id",
        "provider",
        "classification",
        "status",
        "target",
        "target_count",
        "captured_targets",
        "created_at",
    }
)
