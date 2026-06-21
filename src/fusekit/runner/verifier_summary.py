"""Shared public verifier-summary shape for launch proof gates."""

from __future__ import annotations

VERIFIER_SUMMARY_SCHEMA_VERSION = "fusekit.verifier-summary.v1"
VERIFIER_SUMMARY_KEYS = frozenset(
    {
        "schema_version",
        "overall",
        "all_passed_or_pending_safe",
        "counts",
        "checks",
        "statement",
    }
)
VERIFIER_SUMMARY_CHECK_KEYS = frozenset(
    {
        "provider",
        "check",
        "status",
        "pending_safe",
    }
)
VERIFIER_SUMMARY_COUNT_KEYS = frozenset(
    {
        "passed",
        "pending_safe",
        "pending",
        "repairing",
        "failed",
        "skipped",
        "needs_human_gate",
        "unknown",
    }
)
