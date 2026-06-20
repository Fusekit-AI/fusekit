"""Shared public artifact and evidence-inventory shape for launch proof gates."""

from __future__ import annotations

EVIDENCE_INVENTORY_SCHEMA_VERSION = "fusekit.evidence-inventory.v1"
ARTIFACT_RECORD_KEYS = frozenset(
    {
        "name",
        "path",
        "exists",
    }
)
EVIDENCE_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "logs",
        "screenshots",
        "visual",
        "receipts",
        "counts",
        "statement",
    }
)
EVIDENCE_COUNT_KEYS = frozenset(
    {
        "logs",
        "screenshots",
        "visual",
        "receipts",
    }
)
EVIDENCE_RECORD_KEYS = frozenset(
    {
        "path",
        "kind",
        "source",
        "exists",
    }
)
