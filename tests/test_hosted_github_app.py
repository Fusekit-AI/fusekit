from __future__ import annotations

import base64
import json
import urllib.request
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import (
    GitHubAppConfig,
    InstallationToken,
    build_github_app_jwt,
    exchange_installation_token,
    github_app_install_url,
    hosted_github_intake_contract,
    list_installation_repositories,
    require_hosted_installation_token_boundary,
)
from fusekit.hosted.launcher import HOSTED_PLAIN_LANGUAGE_JOURNEY


class FakeResponse:
    def __init__(self, payload: Mapping[str, object], status: int = 200) -> None:
        self.status = status
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class RecordingOpener:
    def __init__(self, payload: Mapping[str, object]) -> None:
        self.payload = payload
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, Any]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        body = request.data or b"{}"
        self.bodies.append(json.loads(body.decode("utf-8")))
        assert timeout == 30.0
        return FakeResponse(self.payload)


def _config() -> GitHubAppConfig:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return GitHubAppConfig(
        app_id="12345",
        app_slug="fusekit-launcher",
        private_key_pem=pem,
    )


def _decode_segment(segment: str) -> dict[str, object]:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    value = json.loads(raw.decode("utf-8"))
    assert isinstance(value, dict)
    return value


def test_github_app_install_url_is_stateful_and_public() -> None:
    config = _config()
    url = github_app_install_url(config, state="run 123")

    assert url == "https://github.com/apps/fusekit-launcher/installations/new?state=run+123"
    public = config.public_dict()
    assert public["app_id"] == "12345"
    assert public["app_slug"] == "fusekit-launcher"
    assert "PRIVATE KEY" not in json.dumps(public)


def test_build_github_app_jwt_has_expected_claims() -> None:
    token = build_github_app_jwt(_config(), now=1_700_000_000, ttl_seconds=540)
    header_segment, payload_segment, signature_segment = token.split(".")

    header = _decode_segment(header_segment)
    payload = _decode_segment(payload_segment)

    assert header == {"alg": "RS256", "typ": "JWT"}
    assert payload == {
        "iat": 1_699_999_940,
        "exp": 1_700_000_480,
        "iss": "12345",
    }
    assert signature_segment
    assert "=" not in token


def test_exchange_installation_token_uses_scoped_request_body() -> None:
    opener = RecordingOpener(
        {
            "token": "ghs_fake_installation_token_for_test",
            "expires_at": "2026-06-21T01:00:00Z",
            "permissions": {"contents": "read", "secrets": "write"},
            "repository_selection": "selected",
        }
    )

    token = exchange_installation_token(
        _config(),
        installation_id=42,
        repository_ids=(1001,),
        permissions={"contents": "read", "secrets": "write"},
        opener=opener,
        now=1_700_000_000,
    )

    request = opener.requests[0]
    assert request.full_url == "https://api.github.com/app/installations/42/access_tokens"
    assert request.get_method() == "POST"
    assert request.headers["Authorization"].startswith("Bearer ")
    assert opener.bodies == [
        {
            "repository_ids": [1001],
            "permissions": {"contents": "read", "secrets": "write"},
        }
    ]
    assert token.token == "ghs_fake_installation_token_for_test"
    assert token.public_dict() == {
        "expires_at": "2026-06-21T01:00:00Z",
        "permissions": {"contents": "read", "secrets": "write"},
        "repository_selection": "selected",
        "token_captured": True,
    }
    assert "ghs_fake" not in json.dumps(token.public_dict())


def test_hosted_installation_token_boundary_allows_selected_contents_read() -> None:
    token = InstallationToken(
        token="ghs_fake_installation_token_for_test",
        expires_at="2026-06-21T01:00:00Z",
        permissions={"contents": "read", "metadata": "read"},
        repository_selection="selected",
    )

    require_hosted_installation_token_boundary(token)


def test_hosted_installation_token_boundary_rejects_broader_scope() -> None:
    with pytest.raises(FuseKitError, match="selected repositories"):
        require_hosted_installation_token_boundary(
            InstallationToken(
                token="ghs_fake_installation_token_for_test",
                expires_at="2026-06-21T01:00:00Z",
                permissions={"contents": "read"},
                repository_selection="all",
            )
        )

    with pytest.raises(FuseKitError, match="contents:read"):
        require_hosted_installation_token_boundary(
            InstallationToken(
                token="ghs_fake_installation_token_for_test",
                expires_at="2026-06-21T01:00:00Z",
                permissions={"contents": "write"},
                repository_selection="selected",
            )
        )

    with pytest.raises(FuseKitError, match="unsupported permissions"):
        require_hosted_installation_token_boundary(
            InstallationToken(
                token="ghs_fake_installation_token_for_test",
                expires_at="2026-06-21T01:00:00Z",
                permissions={"contents": "read", "secrets": "write"},
                repository_selection="selected",
            )
        )


def test_list_installation_repositories_returns_public_repo_rows() -> None:
    opener = RecordingOpener(
        {
            "repositories": [
                {"full_name": "example/one", "private": True},
                {"full_name": "example/two", "private": False},
            ]
        }
    )

    repos = list_installation_repositories(
        _config(),
        token="ghs_fake_installation_token_for_test",
        opener=opener,
    )

    assert repos == (
        {"full_name": "example/one", "private": True},
        {"full_name": "example/two", "private": False},
    )
    request = opener.requests[0]
    assert request.full_url == "https://api.github.com/installation/repositories"
    assert request.headers["Authorization"] == "Bearer ghs_fake_installation_token_for_test"


def test_hosted_github_intake_contract_has_no_secret_material() -> None:
    contract = hosted_github_intake_contract(_config())
    serialized = json.dumps(contract)

    assert contract["route"] == "github-app"
    assert contract["trust_story"] == [
        "open core",
        "narrow permissions",
        "visible plan",
        "redacted proof",
        "reversible setup",
    ]
    assert contract["no_terminal_promise"].startswith("No terminal")
    assert contract["launch_path"] == [
        "Visit the hosted FuseKit URL.",
        "Install the FuseKit GitHub App on one selected repository.",
        "Review the visible plan and approved action ids before worker start.",
        "Click Start hosted launch and pass only provider-owned human gates.",
        "Receive the live URL, redacted proof receipt, rollback metadata, and detonation receipt.",
    ]
    assert contract["plain_language_journey"] == list(HOSTED_PLAIN_LANGUAGE_JOURNEY)
    assert "Run Record" in contract["proof"]
    assert "Detonation receipt" in contract["proof"]
    assert any("rollback" in item for item in contract["reversal"])
    assert contract["open_core"] == {
        "source_repository": "https://github.com/Fusekit-AI/fusekit",
        "license": "MIT",
        "reviewable_entrypoint": "app.py",
    }
    assert contract["permissions"] == [
        "Install the FuseKit GitHub App on one selected repository.",
        "Grant contents:read access for source scan and setup planning.",
        (
            "Approve any GitHub write capability separately through the visible plan "
            "before FuseKit mutates repository settings."
        ),
    ]
    assert contract["token_boundary"] == {
        "repository_selection": "selected",
        "requested_token_permissions": {"contents": "read"},
        "accepted_token_permissions": {"contents": "read", "metadata": "read"},
        "rejects": [
            "all-repository installation tokens",
            "contents:write installation tokens",
            "unexpected GitHub write permissions",
        ],
    }
    assert "GitHub sign-in" in contract["human_gates"]
    assert "PRIVATE KEY" not in serialized
    assert "ghs_" not in serialized
