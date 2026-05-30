"""Capability broker that refuses raw secret export."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fusekit.errors import PolicyError
from fusekit.vault import Vault


@dataclass(frozen=True)
class CapabilityBroker:
    """Serve safe capability responses backed by an unlocked vault."""

    vault: Vault

    def request(self, capability: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Handle a capability request without returning raw secrets."""

        if capability in {"secret.raw", "vault.export", "password.read", "token.read"}:
            raise PolicyError("Raw secret export is denied.")
        if capability == "vault.index":
            return {"records": self.vault.public_index()}
        if capability == "health":
            return {"ok": True, "records": len(self.vault.records)}
        raise PolicyError(f"Capability is not allowed: {capability}")
