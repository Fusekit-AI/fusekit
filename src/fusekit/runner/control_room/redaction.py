"""Display redaction helpers for control-room browser payloads."""

from __future__ import annotations

from fusekit.security.redaction import redact_public_text


def redact_gate_target(value: str) -> str:
    """Redact token-like target material while preserving useful target shape."""

    return redact_public_text(value)
