"""Deterministic, redacted run ledger for launch proof artifacts."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fusekit.audit import redact
from fusekit.security import redact_public_path, redact_public_text


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_json(data: Any) -> str:
    return json.dumps(_public_redact(redact(data)), indent=2, sort_keys=True) + "\n"


def _public_redact(value: Any) -> Any:
    """Apply public artifact redaction after structured secret-key redaction."""

    if isinstance(value, dict):
        return {str(key): _public_redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_public_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_public_redact(item) for item in value]
    if isinstance(value, str):
        redacted = redact_public_text(value)
        return redact_public_path(redacted) if redacted.startswith("/") else redacted
    return value


@dataclass(frozen=True)
class LedgerEntry:
    """One non-secret harness ledger entry."""

    sequence: int
    event: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the ledger entry."""

        return {
            "sequence": self.sequence,
            "ts": self.ts,
            "event": self.event,
            "data": redact(self.data),
        }


@dataclass
class HarnessLedger:
    """Append-only redacted ledger with content-addressed artifact snapshots."""

    root: Path
    entries: list[LedgerEntry] = field(default_factory=list)

    @classmethod
    def create(cls, root: Path) -> HarnessLedger:
        """Create a ledger directory."""

        root.mkdir(parents=True, exist_ok=True)
        (root / "artifacts").mkdir(parents=True, exist_ok=True)
        return cls(root=root)

    def record(self, event: str, data: dict[str, Any]) -> LedgerEntry:
        """Append a redacted event to the in-memory and on-disk ledger."""

        entry = LedgerEntry(len(self.entries) + 1, event, data)
        self.entries.append(entry)
        self._write()
        return entry

    def snapshot_json(self, name: str, data: dict[str, Any]) -> Path:
        """Write a redacted JSON artifact and record its hash."""

        content = _stable_json(data)
        digest = _sha256_text(content)
        safe_name = "".join(char if char.isalnum() or char in "._-" else "-" for char in name)
        path = self.root / "artifacts" / f"{safe_name}.{digest[:12]}.json"
        path.write_text(content, encoding="utf-8")
        self.record(
            "artifact.snapshot",
            {
                "name": name,
                "path": redact_public_path(path),
                "sha256": digest,
                "bytes": len(content.encode("utf-8")),
            },
        )
        return path

    def to_dict(self) -> dict[str, Any]:
        """Serialize the ledger."""

        return {"entries": [entry.to_dict() for entry in self.entries]}

    def _write(self) -> None:
        path = self.root / "ledger.jsonl"
        lines = [json.dumps(entry.to_dict(), sort_keys=True) for entry in self.entries]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
