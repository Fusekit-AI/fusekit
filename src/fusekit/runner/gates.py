"""Durable human/service gate state."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

GateStatus = Literal["waiting", "resurfaced", "resume_requested", "passed", "failed"]


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


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))


def _normalized_string_tuple(value: object) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(item.strip().upper() for item in _string_tuple(value) if item.strip())
    )


@dataclass
class GateRecord:
    """A resumable provider-created human gate."""

    id: str
    provider: str
    reason: str
    status: GateStatus = "waiting"
    resume_url: str = ""
    classification: str = ""
    target: str = ""
    follow_steps: tuple[str, ...] = ()
    next_action: str = ""
    resume_hint: str = ""
    attempts: int = 0
    last_opened_url: str = ""
    last_opened_at: float = 0.0
    captured_targets: tuple[str, ...] = ()
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, str | int | float | list[str]]:
        """Serialize gate state."""

        return {
            "id": self.id,
            "provider": self.provider,
            "reason": self.reason,
            "status": self.status,
            "resume_url": self.resume_url,
            "classification": self.classification,
            "target": self.target,
            "follow_steps": list(self.follow_steps),
            "next_action": self.next_action or _default_next_action(self),
            "resume_hint": self.resume_hint or _default_resume_hint(self),
            "attempts": self.attempts,
            "last_opened_url": self.last_opened_url,
            "last_opened_at": self.last_opened_at,
            "captured_targets": list(self.captured_targets),
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
            classification=str(raw.get("classification", "")),
            target=str(raw.get("target", "")),
            follow_steps=_string_tuple(raw.get("follow_steps", [])),
            next_action=str(raw.get("next_action", "")),
            resume_hint=str(raw.get("resume_hint", "")),
            attempts=_int_value(raw.get("attempts"), 0),
            last_opened_url=str(raw.get("last_opened_url", "")),
            last_opened_at=_float_value(raw.get("last_opened_at"), 0.0),
            captured_targets=_normalized_string_tuple(raw.get("captured_targets", [])),
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
        classification: str = "",
        target: str = "",
        follow_steps: tuple[str, ...] = (),
        next_action: str = "",
        resume_hint: str = "",
    ) -> GateRecord:
        """Mark a gate as waiting/resurfaced."""

        record = self.records.get(gate_id)
        if record is not None and record.status == "passed":
            return record
        status: GateStatus = "waiting"
        attempts = 1
        created_at = time.time()
        if record is not None:
            status = "resurfaced"
            attempts = record.attempts + 1
            created_at = record.created_at
            classification = classification or record.classification
            target = target or record.target
            follow_steps = follow_steps or record.follow_steps
            next_action = next_action or record.next_action
            resume_hint = resume_hint or record.resume_hint
            last_opened_url = record.last_opened_url
            last_opened_at = record.last_opened_at
            captured_targets = (
                () if record.status == "resume_requested" else record.captured_targets
            )
        else:
            last_opened_url = ""
            last_opened_at = 0.0
            captured_targets = ()
        record = GateRecord(
            id=gate_id,
            provider=provider,
            reason=reason,
            status=status,
            resume_url=resume_url,
            classification=classification,
            target=target,
            follow_steps=follow_steps,
            next_action=next_action,
            resume_hint=resume_hint,
            attempts=attempts,
            last_opened_url=last_opened_url,
            last_opened_at=last_opened_at,
            captured_targets=captured_targets,
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
        record.next_action = "No action needed."
        record.resume_hint = "FuseKit verified this gate as passed."
        record.updated_at = time.time()
        self.save()

    def request_resume(self, gate_id: str) -> None:
        """Mark a gate as ready for FuseKit to retry verification."""

        record = self.records[gate_id]
        record.status = "resume_requested"
        record.next_action = _resume_next_action(record)
        record.resume_hint = _resume_hint(record)
        record.updated_at = time.time()
        self.save()

    def mark_opened(self, gate_id: str, url: str) -> None:
        """Record that the provider gate was opened in the shared VM browser."""

        record = self.records[gate_id]
        record.last_opened_url = url
        record.last_opened_at = time.time()
        record.updated_at = time.time()
        self.save()

    def mark_captured(self, gate_id: str, target: str) -> None:
        """Record a captured target value for progress-aware multi-secret gates."""

        record = self.records[gate_id]
        normalized = target.strip().upper()
        record.captured_targets = tuple(dict.fromkeys((*record.captured_targets, normalized)))
        missing = _capture_targets(record.target) - set(record.captured_targets)
        if missing:
            record.next_action = (
                "Copy the next provider value in the VM browser, then capture "
                + ", ".join(sorted(missing))
                + "."
            )
            record.resume_hint = "FuseKit will resume automatically after every target is captured."
        else:
            record.next_action = "All required provider values are captured."
            record.resume_hint = (
                "FuseKit requested verification automatically; watch for the next provider check."
            )
        record.updated_at = time.time()
        self.save()

    def fail_gate(self, gate_id: str) -> None:
        """Mark a gate as failed."""

        record = self.records[gate_id]
        record.status = "failed"
        record.next_action = (
            "Click Open provider gate in VM again and follow the latest visible instruction."
        )
        record.resume_hint = "FuseKit will keep this as a repairable gate instead of hiding it."
        record.updated_at = time.time()
        self.save()

    def save(self) -> None:
        """Write gate records."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_private(
            self.path,
            json.dumps(
                {"gates": [record.to_dict() for record in self.records.values()]},
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )


def _atomic_write_private(path: Path, content: str) -> None:
    temp = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp, path)
        path.chmod(0o600)
    except Exception:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _capture_targets(target: str) -> set[str]:
    return {
        item
        for item in (part.strip().upper() for part in target.split(","))
        if item.isidentifier() and item == item.upper() and len(item) > 2 and "_" in item
    }


def _default_next_action(record: GateRecord) -> str:
    if record.status == "resume_requested":
        return _resume_next_action(record)
    if record.status == "passed":
        return "No action needed."
    if record.status == "failed":
        return "Click Open provider gate in VM again and follow the latest visible instruction."
    targets = _capture_targets(record.target)
    if targets:
        missing = targets - set(record.captured_targets)
        if missing:
            return (
                "Copy the provider value in the VM browser, then click the matching "
                "Capture from VM clipboard button for "
                + ", ".join(sorted(missing))
                + "."
            )
        return "All required provider values are captured."
    provider = record.provider.strip() or "provider"
    return (
        f"Finish the {provider} login, approval, ownership, or consent prompt in the VM "
        "browser, then click I finished this step."
    )


def _default_resume_hint(record: GateRecord) -> str:
    if record.status == "resume_requested":
        return _resume_hint(record)
    if record.status == "passed":
        return "FuseKit verified this gate as passed."
    if record.status == "failed":
        return "FuseKit will keep this as a repairable gate instead of hiding it."
    if _capture_targets(record.target):
        return "FuseKit will resume automatically after every target is captured."
    return "FuseKit will retry verification after you click I finished this step."


def _resume_next_action(record: GateRecord) -> str:
    classification = record.classification.strip().lower()
    provider = record.provider.strip().lower()
    if classification == "dns-approval" or provider == "dns":
        return "FuseKit is applying the approved DNS records now."
    if classification == "setup-approval" or provider == "fusekit":
        return "FuseKit is continuing with the approved setup plan now."
    if classification == "provider-setup-retry":
        return (
            "FuseKit is rerunning the provider setup route now. Keep the VM browser "
            "open so any resurfaced provider gate appears in the same session."
        )
    if classification == "provider-domain":
        return (
            "FuseKit is rechecking the provider domain state now. If the provider still "
            "needs DNS or ownership proof, the same guided gate will resurface."
        )
    if classification == "provider-runtime-values":
        return (
            "FuseKit is rechecking the captured provider values now and will apply them "
            "to downstream services if verification succeeds."
        )
    if classification == "provider-authorization":
        provider_label = provider.title() if provider else "Provider"
        return (
            f"FuseKit is rechecking {provider_label} authorization now. If the provider "
            "rejects the capability, this gate will reopen with the exact repair step."
        )
    return "FuseKit is retrying provider verification now."


def _resume_hint(record: GateRecord) -> str:
    classification = record.classification.strip().lower()
    provider = record.provider.strip().lower()
    if classification == "dns-approval" or provider == "dns":
        return (
            "Keep this control room open; DNS apply and propagation status will appear "
            "after the provider API finishes."
        )
    if classification == "setup-approval" or provider == "fusekit":
        return "Keep this control room open; provider setup will start from the approved plan."
    if classification in {
        "provider-authorization",
        "provider-domain",
        "provider-runtime-values",
        "provider-setup-retry",
    }:
        return (
            "Keep this control room open; FuseKit will either continue automatically "
            "or resurface this same gate with updated follow-me instructions."
        )
    return (
        "Keep this control room open; the next guided blocker or success state "
        "will appear after the provider check finishes."
    )
