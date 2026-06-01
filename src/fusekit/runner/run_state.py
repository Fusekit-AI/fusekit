"""Canonical launch run-state contract."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RUN_STATE_FIELDS = (
    "app_repo_known",
    "runner_selected",
    "oci_ready",
    "browser_ready",
    "provider_sessions_known",
    "vault_created",
    "secrets_captured",
    "provider_checks_passed_or_pending_safe",
    "receipt_written",
    "detonation_safe",
)


@dataclass
class LaunchRunState:
    """Secret-free contract describing whether a launch can safely continue."""

    app_repo_known: bool = False
    runner_selected: bool = False
    oci_ready: bool = False
    browser_ready: bool = False
    provider_sessions_known: bool = False
    vault_created: bool = False
    secrets_captured: bool = False
    provider_checks_passed_or_pending_safe: bool = False
    receipt_written: bool = False
    detonation_safe: bool = False
    updated_at: float = field(default_factory=time.time)
    notes: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> LaunchRunState:
        """Load a run-state contract from disk."""

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("run state must be a JSON object")
        values = {field: _bool_value(data.get(field, False)) for field in RUN_STATE_FIELDS}
        notes = tuple(str(item) for item in data.get("notes", ()) if isinstance(item, str))
        return cls(
            **values,
            updated_at=float(data.get("updated_at", time.time())),
            notes=notes,
        )

    @classmethod
    def load_or_create(cls, path: Path) -> LaunchRunState:
        """Load an existing run state, or return a new empty contract."""

        if not path.exists():
            return cls()
        try:
            return cls.load(path)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return cls().add_note(
                "Run state could not be read; FuseKit rebuilt it from launch checkpoints."
            )

    def mark(self, **updates: bool) -> LaunchRunState:
        """Mark one or more contract fields and refresh the timestamp."""

        unknown = sorted(set(updates) - set(RUN_STATE_FIELDS))
        if unknown:
            raise KeyError(f"Unknown run-state fields: {', '.join(unknown)}")
        for key, value in updates.items():
            setattr(self, key, bool(value))
        self.updated_at = time.time()
        return self

    def add_note(self, note: str) -> LaunchRunState:
        """Add a redacted operational note."""

        cleaned = _redact_note(" ".join(note.split()))
        if cleaned:
            self.notes = (*self.notes[-7:], cleaned[:240])
            self.updated_at = time.time()
        return self

    def missing_for_detonation(self) -> list[str]:
        """Return required contract fields that are not yet satisfied."""

        required = (
            "vault_created",
            "secrets_captured",
            "provider_checks_passed_or_pending_safe",
            "receipt_written",
        )
        return [field for field in required if not bool(getattr(self, field))]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the run-state contract."""

        payload: dict[str, Any] = {
            field: bool(getattr(self, field)) for field in RUN_STATE_FIELDS
        }
        payload["updated_at"] = self.updated_at
        payload["notes"] = list(self.notes)
        payload["missing_for_detonation"] = self.missing_for_detonation()
        payload["ready_to_detonate"] = (
            not payload["missing_for_detonation"] and self.detonation_safe
        )
        return payload

    def save(self, path: Path) -> None:
        """Write the run state atomically with owner-only permissions."""

        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


def update_run_state(path: Path, **updates: bool) -> LaunchRunState:
    """Load, update, save, and return a launch run-state contract."""

    state = LaunchRunState.load_or_create(path)
    state.mark(**updates)
    state.save(path)
    return state


def _bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    return False


def _redact_note(text: str) -> str:
    patterns = (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        r"sk-[A-Za-z0-9_-]{12,}",
        r"gh[pousr]_[A-Za-z0-9_]{12,}",
        r"github_pat_[A-Za-z0-9_]{12,}",
        r"whsec_[A-Za-z0-9_]{12,}",
        r"re_[A-Za-z0-9_-]{12,}",
        r"plaid-[A-Za-z0-9_-]{12,}",
        r"([?&](?:token|secret|key|password|passphrase)=)[^\\s&]+",
        r"\b[A-Za-z0-9_-]{36,}\b",
    )
    redacted = text
    for pattern in patterns:
        replacement = r"\1[redacted]" if pattern.startswith("([?&]") else "[redacted]"
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE | re.DOTALL)
    return redacted
