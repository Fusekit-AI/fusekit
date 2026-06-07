from __future__ import annotations

import json
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError

from fusekit.providers.capability_pack import (
    PackHandoff,
    ProviderCapabilityPack,
    ProviderDetection,
    VerificationRecipe,
    synthesize_provider_pack,
)
from fusekit.providers.verification import (
    VerificationResult,
    verify_provider_pack,
    verify_recipe_with_retries,
)
from fusekit.vault import Vault
from fusekit.verification_report import VerificationReport


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
    object.__setattr__(
        pack,
        "verification",
        (VerificationRecipe("env-present", "RESEND_API_KEY"),),
    )

    results = verify_provider_pack(pack, vault)

    env_result = next(result for result in results if result.kind == "env-present")
    assert env_result.status == "ok"
    assert "re_hidden_secret" not in json.dumps([result.to_dict() for result in results])


def test_http_json_recipe_uses_secret_template_refs_without_leaking(monkeypatch) -> None:
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

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        captured["body"] = request.data.decode("utf-8")
        captured["headers"] = dict(request.headers)
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)
    pack = synthesize_provider_pack("plaid", _NoPath())

    results = verify_provider_pack(pack, vault)

    http_result = next(result for result in results if result.kind == "http-json")
    assert http_result.status == "ok"
    assert "client-secret-value" in str(captured["body"])
    public = json.dumps(http_result.to_dict())
    assert "client-secret-value" not in public
    assert "plaid-secret-value" not in public


def test_http_json_error_body_is_not_retained(monkeypatch) -> None:
    vault = Vault.empty()
    pack = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="test-provider",
        display_name="Test Provider",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(),
        handoff=PackHandoff(
            signup_url="https://test-provider.example",
            token_url="https://test-provider.example/tokens",
            token_env="TEST_PROVIDER_API_KEY",
            token_record_id="provider.test-provider.token",
            token_label="Test provider key",
        ),
        required_secrets=(),
        env_vars=(),
        setup=(),
        setup_goals=(),
        verification=(
            VerificationRecipe(
                kind="http-json",
                target="https://api.test-provider.example/me",
                expected="401 means token rejected",
                inputs={"expected_status": "401"},
            ),
        ),
        rollback=(),
    )

    def local_urlopen(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise HTTPError(
            "https://api.test-provider.example/me",
            401,
            "Unauthorized",
            {},
            BytesIO(b'{"error":"do-not-keep-secret-body"}'),
        )

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(pack, vault)[0]
    public = json.dumps(result.to_dict())

    assert result.status == "ok"
    assert "do-not-keep-secret-body" not in public


def test_authenticated_http_json_403_becomes_human_gate(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.test-provider.test_provider_api_key",
        "provider_secret",
        "test-provider",
        "TEST_PROVIDER_API_KEY",
        "token",
    )
    pack = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="test-provider",
        display_name="Test Provider",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(),
        handoff=PackHandoff(
            signup_url="https://test-provider.example",
            token_url="https://test-provider.example/tokens",
            token_env="TEST_PROVIDER_API_KEY",
            token_record_id="provider.test-provider.token",
            token_label="Test provider key",
        ),
        required_secrets=(),
        env_vars=(),
        setup=(),
        setup_goals=(),
        verification=(
            VerificationRecipe(
                kind="http-json",
                target="https://api.test-provider.example/me",
                expected="token can read account",
                inputs={
                    "auth_secret": "TEST_PROVIDER_API_KEY",
                    "expected_status": "200",
                },
            ),
        ),
        rollback=(),
    )

    def local_urlopen(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise HTTPError("https://api.test-provider.example/me", 403, "Forbidden", {}, BytesIO(b""))

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(pack, vault)[0]

    assert result.status == "needs_human_gate"
    assert result.details["service_gate"] is True


def test_url_health_recipe_reports_status(monkeypatch) -> None:
    vault = Vault.empty()
    pack = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="test-provider",
        display_name="Test Provider",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("DEMO_API_KEY",)),
        handoff=PackHandoff(
            signup_url="https://test-provider.example",
            token_url="https://test-provider.example/tokens",
            token_env="TEST_PROVIDER_API_KEY",
            token_record_id="provider.test-provider.token",
            token_label="Test provider key",
            required_scopes=("api",),
            account_steps=("Create account.",),
            secret_steps=("Create token.",),
            service_gates=("MFA",),
        ),
        required_secrets=("TEST_PROVIDER_API_KEY",),
        env_vars=("TEST_PROVIDER_API_KEY",),
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


def test_verification_report_summarizes_repair_without_secrets(tmp_path) -> None:
    secret = "re_hidden_secret"
    report = VerificationReport(app_name="app", live_url="https://app.example")
    report.add_provider_results(
        "resend",
        [
            VerificationResult(
                provider="resend",
                kind="http-json",
                target="https://api.resend.com/domains",
                status="failed",
                details={"token": secret},
            )
        ],
        repaired=True,
    )
    path = tmp_path / "verification_report.json"

    report.write(path)
    public = path.read_text("utf-8")
    payload = json.loads(public)

    assert payload["overall"] == "repairing"
    assert payload["counts"]["repairing"] == 1
    assert secret not in public
    assert "[REDACTED" in public
    assert "Snowman" not in payload["checks"][0]["summary"]
    assert "repair" in payload["checks"][0]["repair"].lower()


def test_dns_pending_then_passing(monkeypatch) -> None:
    vault = Vault.empty()
    pack = _pack("cloudflare")
    recipe = VerificationRecipe(
        kind="dns-records",
        target="moonlite.rsvp",
        inputs={
            "records_json": json.dumps(
                [{"name": "moonlite.rsvp", "type": "A", "value": "203.0.113.10"}]
            )
        },
    )
    calls = {"count": 0}

    class Resolver:
        def resolve(self, name: str, record_type: str):  # type: ignore[no-untyped-def]
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("not propagated")
            return ["203.0.113.10"]

    monkeypatch.setattr(
        "fusekit.providers.verification.import_module",
        lambda name: Resolver() if name == "dns.resolver" else SimpleNamespace(),
    )

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=2, retry_seconds=0)

    assert result.status == "ok"
    assert calls["count"] == 2


def test_vercel_deploy_lag_reports_pending_then_ready(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put("provider.vercel.token", "provider_secret", "vercel", "VERCEL_TOKEN", "token")
    pack = _pack("vercel")
    recipe = VerificationRecipe(
        kind="vercel-deployment-url",
        target="moonlite",
    )
    calls = {"count": 0}

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        state = "BUILDING" if calls["count"] == 1 else "READY"
        return _JsonResponse({"deployments": [{"url": "moonlite.vercel.app", "readyState": state}]})

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=2, retry_seconds=0)

    assert result.status == "ok"


def test_resend_pending_domain_is_pending_safe(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "token",
    )
    pack = _pack("resend")
    recipe = VerificationRecipe(kind="resend-domain", target="moonlite.rsvp")

    monkeypatch.setattr(
        "fusekit.providers.verification.urlopen",
        lambda *args, **kwargs: _JsonResponse(
            {"data": [{"name": "moonlite.rsvp", "status": "pending"}]}
        ),
    )

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=2, retry_seconds=0)

    assert result.status == "pending"
    assert result.details["pending_safe"] is True


def test_resend_domain_403_becomes_human_gate(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "token",
    )
    pack = _pack("resend")
    recipe = VerificationRecipe(kind="resend-domain", target="moonlite.rsvp")

    monkeypatch.setattr(
        "fusekit.providers.verification.urlopen",
        lambda *args, **kwargs: _JsonResponse({"message": "forbidden"}, status=403),
    )

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=2, retry_seconds=0)

    assert result.status == "needs_human_gate"
    assert result.details["service_gate"] is True


def test_github_missing_secret_reports_failed(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put("provider.github.token", "provider_secret", "github", "GITHUB_TOKEN", "token")
    pack = _pack("github")
    recipe = VerificationRecipe(
        kind="github-repo-secret",
        target="${input:github_repo}",
        inputs={"names": "RESEND_API_KEY"},
    )
    object.__setattr__(pack, "verification", (recipe,))

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        raise HTTPError(request.full_url, 404, "missing", {}, BytesIO())

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(
        pack,
        vault,
        inputs={"github_repo": "fusekitdemo/moonlite"},
    )[0]

    assert result.status == "failed"
    assert result.details["missing"] == ["RESEND_API_KEY"]


def test_live_url_500_then_200(monkeypatch) -> None:
    vault = Vault.empty()
    pack = _pack("vercel")
    recipe = VerificationRecipe(kind="url-health", target="$live_url")
    calls = {"count": 0}

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        if calls["count"] == 1:
            raise HTTPError(request.full_url, 500, "server error", {}, BytesIO())
        return _JsonResponse({}, status=200)

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_recipe_with_retries(
        pack,
        recipe,
        vault,
        live_url="https://moonlite.rsvp",
        attempts=2,
        retry_seconds=0,
    )

    assert result.status == "ok"


def test_webhook_secret_mismatch_reports_failed() -> None:
    vault = Vault.empty()
    pack = _pack("webhook")
    recipe = VerificationRecipe(kind="webhook-secret", target="WEBHOOK_SECRET")
    object.__setattr__(pack, "verification", (recipe,))

    result = verify_provider_pack(pack, vault)[0]

    assert result.status == "missing"


def _pack(provider: str) -> ProviderCapabilityPack:
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider=provider,
        display_name=provider.title(),
        category="service",
        confidence="high",
        evidence=("test",),
        detection=ProviderDetection(),
        handoff=PackHandoff(
            signup_url=f"https://{provider}.example/signup",
            token_url=f"https://{provider}.example/tokens",
        ),
        required_secrets=("TEST_TOKEN",),
        env_vars=("TEST_TOKEN",),
        setup=(),
        setup_goals=(),
        verification=(),
        rollback=("Revoke token.",),
    )


class _JsonResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> _JsonResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class _NoPath:
    def rglob(self, pattern: str):  # type: ignore[no-untyped-def]
        return []

    def __truediv__(self, other: str) -> _NoPath:
        return self

    def exists(self) -> bool:
        return False
