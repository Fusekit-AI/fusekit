from __future__ import annotations

import json
from io import BytesIO

from fusekit.providers.capability_pack import (
    PackHandoff,
    ProviderCapabilityPack,
    ProviderDetection,
    VerificationRecipe,
    synthesize_provider_pack,
)
from fusekit.providers.verification import verify_provider_pack, verify_recipe_with_retries
from fusekit.vault import Vault


def test_verifies_env_present_from_vault_without_revealing_secret() -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "re_hidden_secret",
    )
    pack = synthesize_provider_pack("resend", _NoPath())

    results = verify_provider_pack(pack, vault)

    env_result = next(result for result in results if result.kind == "env-present")
    assert env_result.status == "ok"
    assert "re_hidden_secret" not in json.dumps([result.to_dict() for result in results])


def test_http_json_recipe_uses_secret_placeholders_without_leaking(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.plaid.plaid_client_id",
        "provider_secret",
        "plaid",
        "PLAID_CLIENT_ID",
        "client-secret-value",
    )
    vault.put(
        "provider.plaid.plaid_secret",
        "provider_secret",
        "plaid",
        "PLAID_SECRET",
        "plaid-secret-value",
    )
    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"request_id":"redacted-request"}'

    def fake_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        captured["body"] = request.data.decode("utf-8")
        captured["headers"] = dict(request.headers)
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("fusekit.providers.verification.urlopen", fake_urlopen)
    pack = synthesize_provider_pack("plaid", _NoPath())

    results = verify_provider_pack(pack, vault)

    http_result = next(result for result in results if result.kind == "http-json")
    assert http_result.status == "ok"
    assert "client-secret-value" in str(captured["body"])
    public = json.dumps(http_result.to_dict())
    assert "client-secret-value" not in public
    assert "plaid-secret-value" not in public


def test_url_health_recipe_reports_status(monkeypatch) -> None:
    vault = Vault.empty()
    pack = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="demo",
        display_name="Demo",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("DEMO_API_KEY",)),
        handoff=PackHandoff(
            signup_url="https://demo.example",
            token_url="https://demo.example/tokens",
            token_env="DEMO_API_KEY",
            token_record_id="provider.demo.token",
            token_label="Demo key",
            required_scopes=("api",),
            account_steps=("Create account.",),
            secret_steps=("Create token.",),
            service_gates=("MFA",),
        ),
        required_secrets=("DEMO_API_KEY",),
        env_vars=("DEMO_API_KEY",),
        setup=(),
        setup_goals=("Verify app.",),
        verification=(
            VerificationRecipe(kind="url-health", target="$live_url", expected="2xx/3xx"),
        ),
        rollback=("Revoke key.",),
    )

    class FakeResponse:
        status = 204

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return BytesIO().read()

    monkeypatch.setattr(
        "fusekit.providers.verification.urlopen",
        lambda *args, **kwargs: FakeResponse(),
    )

    result = verify_provider_pack(pack, vault, live_url="https://app.example")[0]

    assert result.status == "ok"
    assert result.target == "https://app.example"


def test_verification_retry_reports_pending_after_failures() -> None:
    vault = Vault.empty()
    pack = synthesize_provider_pack("resend", _NoPath())
    recipe = VerificationRecipe(kind="not-real", target="provider-status")

    result = verify_recipe_with_retries(
        pack,
        recipe,
        vault,
        attempts=2,
        retry_seconds=0,
    )

    assert result.status == "pending"
    assert result.details["attempts"] == 2


class _NoPath:
    def rglob(self, pattern: str):  # type: ignore[no-untyped-def]
        return []

    def __truediv__(self, other: str) -> _NoPath:
        return self

    def exists(self) -> bool:
        return False
