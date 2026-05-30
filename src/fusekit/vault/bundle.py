"""Passphrase-protected FuseKit vault bundle."""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from fusekit.errors import VaultError

VAULT_VERSION = 1
KDF_N = 2**15
KDF_R = 8
KDF_P = 1
SALT_BYTES = 16
NONCE_BYTES = 12


@dataclass(frozen=True)
class VaultRecord:
    """One encrypted credential or sensitive setting."""

    id: str
    kind: str
    provider: str
    label: str
    value: str
    metadata: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def public_metadata(self) -> dict[str, Any]:
        """Return non-secret record metadata."""

        return {
            "id": self.id,
            "kind": self.kind,
            "provider": self.provider,
            "label": self.label,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class Vault:
    """Unlocked vault state, kept in process memory."""

    records: dict[str, VaultRecord] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> Vault:
        """Create an empty unlocked vault."""

        return cls()

    @classmethod
    def open(cls, path: Path, passphrase: str) -> Vault:
        """Open and decrypt a vault bundle."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError("Cannot read vault bundle.") from exc
        if raw.get("version") != VAULT_VERSION:
            raise VaultError("Unsupported vault version.")
        try:
            salt = _b64decode(str(raw["salt"]))
            nonce = _b64decode(str(raw["nonce"]))
            ciphertext = _b64decode(str(raw["ciphertext"]))
        except (KeyError, ValueError) as exc:
            raise VaultError("Vault bundle is malformed.") from exc
        key = _derive_key(passphrase, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad())
        except InvalidTag as exc:
            raise VaultError("Vault passphrase is incorrect or bundle was modified.") from exc
        try:
            data = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise VaultError("Decrypted vault payload is malformed.") from exc
        records_raw = data.get("records", [])
        if not isinstance(records_raw, list):
            raise VaultError("Decrypted vault records are malformed.")
        vault = cls.empty()
        for item in records_raw:
            if not isinstance(item, dict):
                raise VaultError("Vault record is malformed.")
            record = VaultRecord(
                id=str(item["id"]),
                kind=str(item["kind"]),
                provider=str(item["provider"]),
                label=str(item["label"]),
                value=str(item["value"]),
                metadata={
                    str(key): str(value)
                    for key, value in dict(item.get("metadata", {})).items()
                },
                created_at=float(item.get("created_at", time.time())),
            )
            vault.records[record.id] = record
        return vault

    def put(
        self,
        record_id: str,
        kind: str,
        provider: str,
        label: str,
        value: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Add or replace a vault record."""

        self.records[record_id] = VaultRecord(
            id=record_id,
            kind=kind,
            provider=provider,
            label=label,
            value=value,
            metadata=metadata or {},
        )

    def require(self, record_id: str) -> VaultRecord:
        """Return a record or fail."""

        try:
            return self.records[record_id]
        except KeyError as exc:
            raise VaultError(f"Vault record not found: {record_id}") from exc

    def public_index(self) -> list[dict[str, Any]]:
        """Return non-secret metadata for all records."""

        return [record.public_metadata() for record in self.records.values()]

    def save(self, path: Path, passphrase: str) -> None:
        """Encrypt and write the vault bundle."""

        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        key = _derive_key(passphrase, salt)
        plaintext = json.dumps(
            {
                "records": [
                    {
                        "id": record.id,
                        "kind": record.kind,
                        "provider": record.provider,
                        "label": record.label,
                        "value": record.value,
                        "metadata": record.metadata,
                        "created_at": record.created_at,
                    }
                    for record in self.records.values()
                ]
            },
            sort_keys=True,
        ).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad())
        bundle = {
            "version": VAULT_VERSION,
            "cipher": "AES-256-GCM",
            "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P},
            "salt": _b64encode(salt),
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def open_or_create(path: Path, passphrase: str) -> Vault:
    """Open an existing vault, or create an empty one."""

    if path.exists():
        return Vault.open(path, passphrase)
    return Vault.empty()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise VaultError("Vault passphrase cannot be empty.")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(
        passphrase.encode("utf-8")
    )


def _aad() -> bytes:
    return b"fusekit-vault-v1"


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))
