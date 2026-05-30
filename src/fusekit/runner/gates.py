"""Durable human/service gate state."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

GateStatus = Literal["waiting", "resurfaced", "passed", "failed"]


def _int_value(value: object, default: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if not isinstance(value, (str, bytes, bytearray)):
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_value(value: object, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, (str, bytes, bytearray)):
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass
class GateRecord:
    """A resumable provider-created human gate."""

    id: str
    provider: str
    reason: str
    status: GateStatus = "waiting"
    resume_url: str = ""
    attempts: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, str | int | float]:
        """Serialize gate state."""

        return {
            "id": self.id,
            "provider": self.provider,
            "reason": self.reason,
            "status": self.status,
            "resume_url": self.resume_url,
            "attempts": self.attempts,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> GateRecord:
        """Deserialize gate state."""

        return cls(
            id=str(raw["id"]),
            provider=str(raw["provider"]),
            reason=str(raw["reason"]),
            status=str(raw.get("status", "waiting")),  # type: ignore[arg-type]
            resume_url=str(raw.get("resume_url", "")),
            attempts=_int_value(raw.get("attempts"), 0),
            created_at=_float_value(raw.get("created_at"), time.time()),
            updated_at=_float_value(raw.get("updated_at"), time.time()),
        )


@dataclass
class GateService:
    """Persist and update service gates for control-room/resume flows."""

    path: Path
    records: dict[str, GateRecord] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> GateService:
        """Load gate service state."""

        if not path.exists():
            return cls(path=path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(path=path)
        records = {}
        for item in raw.get("gates", []):
            if isinstance(item, dict):
                record = GateRecord.from_dict(item)
                records[record.id] = record
        return cls(path=path, records=records)

    def wait(
        self,
        gate_id: str,
        *,
        provider: str,
        reason: str,
        resume_url: str = "",
    ) -> GateRecord:
        """Mark a gate as waiting/resurfaced."""

        record = self.records.get(gate_id)
        status: GateStatus = "waiting"
        attempts = 1
        created_at = time.time()
        if record is not None:
            status = "resurfaced"
            attempts = record.attempts + 1
            created_at = record.created_at
        record = GateRecord(
            id=gate_id,
            provider=provider,
            reason=reason,
            status=status,
            resume_url=resume_url,
            attempts=attempts,
            created_at=created_at,
            updated_at=time.time(),
        )
        self.records[gate_id] = record
        self.save()
        return record

    def pass_gate(self, gate_id: str) -> None:
        """Mark a gate as passed."""

        record = self.records[gate_id]
        record.status = "passed"
        record.updated_at = time.time()
        self.save()

    def fail_gate(self, gate_id: str) -> None:
        """Mark a gate as failed."""

        record = self.records[gate_id]
        record.status = "failed"
        record.updated_at = time.time()
        self.save()

    def save(self) -> None:
        """Write gate records."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {"gates": [record.to_dict() for record in self.records.values()]},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
