"""Shared standalone audit log survivor proof shape."""

from __future__ import annotations

AUDIT_LOG_EVENT_FIELD = "event"
AUDIT_LOG_DATA_FIELD = "data"
AUDIT_LOG_TIMESTAMP_FIELD = "ts"
AUDIT_LOG_ROW_FIELDS = (
    AUDIT_LOG_DATA_FIELD,
    AUDIT_LOG_EVENT_FIELD,
    AUDIT_LOG_TIMESTAMP_FIELD,
)
AUDIT_LOG_ROW_KEYS = frozenset(AUDIT_LOG_ROW_FIELDS)
