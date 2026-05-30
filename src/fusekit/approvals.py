"""Approval metadata helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Approval:
    """A human approval record."""

    action_id: str
    approved_by: str
    approved_at: str
    reason: str

    @classmethod
    def now(cls, action_id: str, approved_by: str, reason: str) -> Approval:
        """Create an approval record with the current UTC timestamp."""

        return cls(
            action_id=action_id,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize approval metadata."""

        return {
            "action_id": self.action_id,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "reason": self.reason,
        }
