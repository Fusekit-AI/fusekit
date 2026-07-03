from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.session import (
    HOSTED_STATE_SCHEMA_VERSION,
    create_hosted_state_token,
    verify_hosted_state_token,
)


def test_hosted_state_token_round_trips_public_redirect_state() -> None:
    token = create_hosted_state_token(
        "test-secret",
        return_path="/launch/github",
        now=1_700_000_000,
        nonce="nonce-for-hosted-state",
    )

    state = verify_hosted_state_token("test-secret", token, now=1_700_000_120)

    assert state.to_dict() == {
        "schema_version": HOSTED_STATE_SCHEMA_VERSION,
        "nonce": "nonce-for-hosted-state",
        "issued_at": 1_700_000_000,
        "return_path": "/launch/github",
    }
    assert "=" not in token


def test_hosted_state_token_rejects_tampering() -> None:
    token = create_hosted_state_token(
        "test-secret",
        now=1_700_000_000,
        nonce="nonce-for-hosted-state",
    )
    tampered = token[:-1] + ("a" if token[-1] != "a" else "b")

    with pytest.raises(FuseKitError, match="signature"):
        verify_hosted_state_token("test-secret", tampered, now=1_700_000_001)


def test_hosted_state_token_rejects_expired_state() -> None:
    token = create_hosted_state_token(
        "test-secret",
        now=1_700_000_000,
        nonce="nonce-for-hosted-state",
    )

    with pytest.raises(FuseKitError, match="expired"):
        verify_hosted_state_token("test-secret", token, now=1_700_001_000)


def test_hosted_state_token_rejects_boolean_timestamp() -> None:
    token = _signed_state_token_payload(
        "test-secret",
        {
            "schema_version": HOSTED_STATE_SCHEMA_VERSION,
            "nonce": "nonce-for-hosted-state",
            "issued_at": True,
            "return_path": "/launch/github",
        },
    )

    with pytest.raises(FuseKitError, match="timestamp"):
        verify_hosted_state_token("test-secret", token, now=1_700_000_001)


def test_hosted_state_token_normalizes_unsafe_return_path() -> None:
    token = create_hosted_state_token(
        "test-secret",
        return_path="//evil.example",
        now=1_700_000_000,
        nonce="nonce-for-hosted-state",
    )

    state = verify_hosted_state_token("test-secret", token, now=1_700_000_001)

    assert state.return_path == "/"


def test_hosted_state_token_requires_secret() -> None:
    with pytest.raises(FuseKitError, match="state secret"):
        create_hosted_state_token("", now=1_700_000_000)

    token = create_hosted_state_token(
        "test-secret",
        now=1_700_000_000,
        nonce="nonce-for-hosted-state",
    )
    with pytest.raises(FuseKitError, match="state secret"):
        verify_hosted_state_token("", token, now=1_700_000_001)


def _signed_state_token_payload(secret: str, payload: dict[str, object]) -> str:
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"
