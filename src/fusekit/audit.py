"""Redacted audit log and setup receipt utilities."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECRET_KEY_PATTERN = re.compile(
    r"(token|secret|password|private[_-]?key|api[_-]?key|credential|passphrase|webhook)",
    re.IGNORECASE,
)


def fingerprint(secret: str) -> str:
    """Return a non-reversible short fingerprint for correlation."""

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def redact(value: Any) -> Any:
    """Redact secret-looking values from structured data."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if SECRET_KEY_PATTERN.search(key_text):
                redacted[key_text] = _redacted_value(item)
            else:
                redacted[key_text] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def assert_no_secret_text(text: str, secrets: list[str]) -> None:
    """Raise AssertionError if any secret appears in text."""

    leaked = [secret for secret in secrets if secret and secret in text]
    if leaked:
        raise AssertionError("Secret material leaked into public text.")


@dataclass
class AuditLog:
    """JSONL redacted audit log writer."""

    path: Path

    def record(self, event: str, data: dict[str, Any]) -> None:
        """Append a redacted event."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": redact(data),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


@dataclass
class Receipt:
    """A public setup receipt."""

    app_name: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    vault_path: str = ""
    live_url: str = ""
    raw_secrets_exposed: int = 0

    def add_action(self, action: str, status: str, details: dict[str, Any]) -> None:
        """Add a redacted action entry."""

        self.actions.append({"action": action, "status": status, "details": redact(details)})

    def to_dict(self) -> dict[str, Any]:
        """Serialize a public receipt."""

        return {
            "app_name": self.app_name,
            "vault_path": self.vault_path,
            "live_url": self.live_url,
            "raw_secrets_exposed": self.raw_secrets_exposed,
            "actions": self.actions,
        }

    def write_json(self, path: Path) -> None:
        """Write a JSON receipt."""

        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        path.write_text(content, encoding="utf-8")

    def write_markdown(self, path: Path) -> None:
        """Write a Markdown receipt."""

        lines = [
            f"# FuseKit Setup Receipt: {self.app_name}",
            "",
            f"- Vault: `{self.vault_path}`",
            f"- Live URL: `{self.live_url or 'not verified'}`",
            f"- Raw secrets exposed to app: `{self.raw_secrets_exposed}`",
            "",
            "## Actions",
            "",
        ]
        for action in self.actions:
            lines.append(f"- `{action['action']}`: {action['status']}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _redacted_value(value: Any) -> str:
    if isinstance(value, str) and value:
        return f"[REDACTED sha256:{fingerprint(value)}]"
    return "[REDACTED]"
