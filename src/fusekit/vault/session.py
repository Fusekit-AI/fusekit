"""Short-lived local vault session tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from fusekit.errors import VaultError
from fusekit.vault.bundle import Vault

SESSION_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TOKEN_BYTES = 32
DEFAULT_SESSION_TTL_SECONDS = 900
MAX_SESSION_TTL_SECONDS = 3600


def default_session_path(vault_path: Path) -> Path:
    """Return the local session file path for a vault."""

    return vault_path.parent / "vault.session.json"


def create_vault_session(
    *,
    vault_path: Path,
    passphrase: str,
    session_path: Path | None = None,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """Create an encrypted local vault session and return the bearer token once."""

    if not passphrase:
        raise VaultError("Vault passphrase cannot be empty.")
    now = time.time() if now is None else now
    ttl_seconds = _bounded_ttl(ttl_seconds)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    payload = {
        "vault_path": str(vault_path.resolve()),
        "passphrase": passphrase,
        "created_at": now,
        "expires_at": now + ttl_seconds,
    }
    ciphertext = AESGCM(_derive_session_key(token, salt)).encrypt(
        nonce,
        json.dumps(payload, sort_keys=True).encode("utf-8"),
        _aad(),
    )
    session_file = session_path or default_session_path(vault_path)
    bundle = {
        "version": SESSION_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": {"name": "scrypt", "n": 2**14, "r": 8, "p": 1},
        "vault_path": str(vault_path.resolve()),
        "token_fingerprint": _token_fingerprint(token),
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    _atomic_write_private(session_file, json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    return {
        "session_token": token,
        "session_file": str(session_file),
        "expires_at": bundle["expires_at"],
        "ttl_seconds": ttl_seconds,
    }


def open_vault_with_session(
    *,
    vault_path: Path,
    session_token: str,
    session_path: Path | None = None,
    now: float | None = None,
) -> Vault:
    """Open a vault using a non-persistent short-lived session token."""

    passphrase = unlock_session_passphrase(
        vault_path=vault_path,
        session_token=session_token,
        session_path=session_path,
        now=now,
    )
    return Vault.open(vault_path, passphrase)


def unlock_session_passphrase(
    *,
    vault_path: Path,
    session_token: str,
    session_path: Path | None = None,
    now: float | None = None,
) -> str:
    """Return the vault passphrase from a valid encrypted local session."""

    if not session_token:
        raise VaultError("Vault session token is required.")
    session_file = session_path or default_session_path(vault_path)
    raw = _read_session_bundle(session_file)
    now = time.time() if now is None else now
    expires_at = float(raw.get("expires_at", 0))
    if expires_at <= now:
        raise VaultError("Vault session token has expired.")
    expected_path = str(vault_path.resolve())
    if str(raw.get("vault_path", "")) != expected_path:
        raise VaultError("Vault session token is not for this vault.")
    try:
        salt = _b64decode(str(raw["salt"]))
        nonce = _b64decode(str(raw["nonce"]))
        ciphertext = _b64decode(str(raw["ciphertext"]))
        payload = AESGCM(_derive_session_key(session_token, salt)).decrypt(
            nonce,
            ciphertext,
            _aad(),
        )
        data = json.loads(payload.decode("utf-8"))
    except (KeyError, ValueError, InvalidTag, json.JSONDecodeError) as exc:
        raise VaultError("Vault session token is invalid.") from exc
    if str(data.get("vault_path", "")) != expected_path:
        raise VaultError("Vault session token payload is not for this vault.")
    if float(data.get("expires_at", 0)) <= now:
        raise VaultError("Vault session token has expired.")
    passphrase = str(data.get("passphrase", ""))
    if not passphrase:
        raise VaultError("Vault session token payload is malformed.")
    return passphrase


def _read_session_bundle(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultError("Cannot read vault session.") from exc
    if not isinstance(raw, dict) or raw.get("version") != SESSION_VERSION:
        raise VaultError("Vault session is malformed.")
    return raw


def _bounded_ttl(ttl_seconds: int) -> int:
    if ttl_seconds <= 0:
        raise VaultError("Vault session TTL must be positive.")
    return min(ttl_seconds, MAX_SESSION_TTL_SECONDS)


def _derive_session_key(token: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(token.encode("utf-8"))


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _aad() -> bytes:
    return b"fusekit-vault-session-v1"


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _atomic_write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
    except Exception:
        with suppress(OSError):
            temp.unlink()
        raise
