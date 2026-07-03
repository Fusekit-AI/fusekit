"""Signed hosted-launch session state tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fusekit.errors import FuseKitError

HOSTED_STATE_SCHEMA_VERSION = "fusekit.hosted-state.v1"
HOSTED_STATE_TTL_SECONDS = 900


@dataclass(frozen=True)
class HostedLaunchState:
    """Verified public state carried through provider-owned redirects."""

    nonce: str
    issued_at: int
    return_path: str = "/"

    def to_dict(self) -> dict[str, object]:
        """Serialize launch state."""

        return {
            "schema_version": HOSTED_STATE_SCHEMA_VERSION,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "return_path": self.return_path,
        }


def create_hosted_state_token(
    secret: str,
    *,
    return_path: str = "/",
    now: int | None = None,
    nonce: str | None = None,
) -> str:
    """Create a signed state token for hosted provider redirects."""

    if not secret:
        raise FuseKitError("Hosted launcher state secret is required.")
    state = HostedLaunchState(
        nonce=nonce or secrets.token_urlsafe(18),
        issued_at=int(time.time() if now is None else now),
        return_path=_safe_return_path(return_path),
    )
    payload = _base64url_json(state.to_dict())
    signature = _sign(secret, payload)
    return f"{payload}.{signature}"


def verify_hosted_state_token(
    secret: str,
    token: str,
    *,
    now: int | None = None,
    ttl_seconds: int = HOSTED_STATE_TTL_SECONDS,
) -> HostedLaunchState:
    """Verify and decode a hosted state token."""

    if not secret:
        raise FuseKitError("Hosted launcher state secret is required.")
    if ttl_seconds <= 0:
        raise FuseKitError("Hosted launcher state ttl must be positive.")
    try:
        payload, signature = token.split(".", 1)
    except ValueError:
        raise FuseKitError("Hosted launcher state token is malformed.") from None
    expected = _sign(secret, payload)
    if not hmac.compare_digest(signature, expected):
        raise FuseKitError("Hosted launcher state token signature is invalid.")
    raw = _decode_json(payload)
    if raw.get("schema_version") != HOSTED_STATE_SCHEMA_VERSION:
        raise FuseKitError("Hosted launcher state token schema is unsupported.")
    nonce = raw.get("nonce")
    issued_at = raw.get("issued_at")
    return_path = raw.get("return_path", "/")
    if not isinstance(nonce, str) or len(nonce) < 16:
        raise FuseKitError("Hosted launcher state token nonce is invalid.")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int):
        raise FuseKitError("Hosted launcher state token timestamp is invalid.")
    current = int(time.time() if now is None else now)
    if issued_at > current + 60:
        raise FuseKitError("Hosted launcher state token timestamp is in the future.")
    if current - issued_at > ttl_seconds:
        raise FuseKitError("Hosted launcher state token expired.")
    if not isinstance(return_path, str):
        raise FuseKitError("Hosted launcher state token return path is invalid.")
    return HostedLaunchState(
        nonce=nonce,
        issued_at=issued_at,
        return_path=_safe_return_path(return_path),
    )


def _safe_return_path(value: str) -> str:
    if not value.startswith("/") or value.startswith("//") or "\n" in value or "\r" in value:
        return "/"
    return value


def _sign(secret: str, payload: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return _base64url(digest)


def _base64url_json(value: dict[str, object]) -> str:
    return _base64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _decode_json(value: str) -> dict[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("Hosted launcher state token payload is invalid.") from exc
    if not isinstance(decoded, dict):
        raise FuseKitError("Hosted launcher state token payload must be an object.")
    return decoded


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
