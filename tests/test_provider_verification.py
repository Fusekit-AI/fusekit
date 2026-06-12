from __future__ import annotations

import json
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest

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
    assert captured["headers"]["User-agent"] == "FuseKit provider verification"
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


def test_live_url_health_is_pending_safe_when_custom_dns_is_pending(monkeypatch) -> None:
    vault = Vault.empty()
    pack = _pack("vercel")
    recipe = VerificationRecipe(kind="url-health", target="$live_url", expected="2xx/3xx")
    object.__setattr__(pack, "verification", (recipe,))

    def local_urlopen(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        raise URLError("Name or service not known")

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(
        pack,
        vault,
        live_url="https://moonlite.rsvp",
        inputs={"live_url_dns_pending_safe": "true"},
        attempts=10,
        retry_seconds=30,
    )[0]

    assert result.status == "pending"
    assert result.details["pending_safe"] is True
    assert result.details["reason"] == "custom DNS apply is waiting for approval or propagation"


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


def test_verification_report_uses_launcher_guidance_for_human_gates() -> None:
    report = VerificationReport(app_name="app")
    report.add_provider_results(
        "cloudflare",
        [
            VerificationResult(
                provider="cloudflare",
                kind="provider-gate",
                target="provider.cloudflare.token",
                status="needs_human_gate",
                details={},
            )
        ],
    )
    report.add_provider_results(
        "resend",
        [
            VerificationResult(
                provider="resend",
                kind="http-json",
                target="https://api.resend.com/domains",
                status="failed",
                details={},
            )
        ],
    )
    report.add_provider_results(
        "vercel",
        [
            VerificationResult(
                provider="vercel",
                kind="provider-gate",
                target="provider.vercel.github-login",
                status="pending",
                details={},
            )
        ],
    )

    payload = report.to_dict()
    repairs = [check["repair"] for check in payload["checks"]]

    assert "Open provider gate in VM" in repairs[0]
    assert "Capture CLOUDFLARE_API_TOKEN from VM clipboard" in repairs[0]
    assert "I finished this step" not in repairs[0]
    assert "Capture RESEND_API_KEY from VM clipboard" in repairs[1]
    assert "Open provider gate in VM" in repairs[2]
    assert "Capture VERCEL_TOKEN from VM clipboard" not in repairs[2]
    assert "I finished this step" in repairs[2]
    assert "Capture from VM clipboard for copy-once values" not in " ".join(repairs)
    assert "visible FuseKit Capture" not in " ".join(repairs)
    assert "rerun verification" not in " ".join(repairs).lower()
    assert "provider UI/API" not in " ".join(repairs)


def test_verification_report_names_exact_multi_capture_buttons() -> None:
    report = VerificationReport(app_name="app")
    report.add_provider_results(
        "custom",
        [
            VerificationResult(
                provider="custom",
                kind="provider-gate",
                target="CUSTOM_API_KEY, CUSTOM_WEBHOOK_SECRET",
                status="needs_human_gate",
                details={},
            )
        ],
    )

    repair = report.to_dict()["checks"][0]["repair"]

    assert "these exact Capture buttons" in repair
    assert "Capture CUSTOM_API_KEY from VM clipboard" in repair
    assert "Capture CUSTOM_WEBHOOK_SECRET from VM clipboard" in repair
    assert "each target-specific Capture button" not in repair
    assert "copy-once values" not in repair


def test_verification_report_targetless_gate_fallback_uses_highlighted_action() -> None:
    report = VerificationReport(app_name="app")
    report.add_provider_results(
        "unknownpay",
        [
            VerificationResult(
                provider="unknownpay",
                kind="provider-gate",
                target="",
                status="needs_human_gate",
                details={},
            )
        ],
    )

    repair = report.to_dict()["checks"][0]["repair"]

    assert "Capture <TARGET>" not in repair
    assert "single highlighted next action" in repair
    assert "active launcher gate" in repair
    assert "Capture RESEND_API_KEY from VM clipboard" not in repair


def test_verification_report_live_url_repairs_are_launcher_actionable() -> None:
    pending = VerificationReport(app_name="app")
    pending.add_live_url({"ok": False, "pending_safe": True})
    failed = VerificationReport(app_name="app")
    failed.add_live_url({"ok": False})
    provider_failed = VerificationReport(app_name="app")
    provider_failed.add_provider_results(
        "live_app",
        [
            VerificationResult(
                provider="live_app",
                kind="url-health",
                target="https://app.example",
                status="failed",
                details={},
            )
        ],
    )

    repairs = [
        pending.to_dict()["checks"][0]["repair"],
        failed.to_dict()["checks"][0]["repair"],
        provider_failed.to_dict()["checks"][0]["repair"],
    ]
    joined = " ".join(repairs)

    assert "control room" in repairs[0]
    assert "guided launcher gate" in joined
    assert "provider needs human approval" in joined
    assert "inspect" not in joined.lower()
    assert "redeploy if needed" not in joined.lower()
    assert "provider status" not in joined.lower()


def test_verification_report_downstream_repairs_are_fusekit_owned() -> None:
    report = VerificationReport(app_name="app")
    report.add_provider_results(
        "vercel",
        [
            VerificationResult(
                provider="vercel",
                kind="vercel-env",
                target="RESEND_API_KEY",
                status="failed",
                details={},
            )
        ],
    )
    report.add_provider_results(
        "cloudflare",
        [
            VerificationResult(
                provider="cloudflare",
                kind="dns-records",
                target="moonlite.rsvp",
                status="failed",
                details={},
            )
        ],
    )

    repairs = [check["repair"] for check in report.to_dict()["checks"]]
    joined = " ".join(repairs)

    assert "Vercel's API" in repairs[0]
    assert "guided launcher gate" in repairs[0]
    assert "control room" in repairs[1]
    assert "DNS API" in repairs[1]
    assert "env var and redeploy" not in joined
    assert "Compare expected DNS records" not in joined
    assert "reapply missing records, then retry" not in joined


def test_verification_report_pending_and_repairing_states_stay_in_control_room() -> None:
    pending = VerificationReport(app_name="app")
    pending.add_provider_results(
        "live_app",
        [
            VerificationResult(
                provider="live_app",
                kind="url-health",
                target="https://app.example",
                status="pending",
                details={},
            )
        ],
    )
    repairing = VerificationReport(app_name="app")
    repairing.add_provider_results(
        "vercel",
        [
            VerificationResult(
                provider="vercel",
                kind="vercel-project",
                target="moonlite-rsvp",
                status="failed",
                details={},
            )
        ],
        repaired=True,
    )

    repairs = [
        pending.to_dict()["checks"][0]["repair"],
        repairing.to_dict()["checks"][0]["repair"],
    ]
    joined = " ".join(repairs)

    assert "control room" in joined
    assert "keeps retrying the live URL health check" in repairs[0]
    assert "guided launcher gates" in repairs[1]
    assert "provider APIs" in repairs[1]
    assert "Wait for deployment warmup" not in joined
    assert "FuseKit should reopen" not in joined
    assert "rerun this check" not in joined


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
    object.__setattr__(pack, "verification", (recipe,))
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


def test_dns_cname_allows_trailing_root_dot(monkeypatch) -> None:
    vault = Vault.empty()
    pack = _pack("cloudflare")
    recipe = VerificationRecipe(
        kind="dns-records",
        target="moonlite.rsvp",
        inputs={
            "records_json": json.dumps(
                [
                    {
                        "name": "www.moonlite.rsvp",
                        "type": "CNAME",
                        "value": "cname.vercel-dns.com",
                    }
                ]
            )
        },
    )
    object.__setattr__(pack, "verification", (recipe,))

    class Resolver:
        def resolve(self, name: str, record_type: str):  # type: ignore[no-untyped-def]
            del name, record_type
            return ["cname.vercel-dns.com."]

    monkeypatch.setattr(
        "fusekit.providers.verification.import_module",
        lambda name: Resolver() if name == "dns.resolver" else SimpleNamespace(),
    )

    result = verify_provider_pack(pack, vault, inputs={})[0]

    assert result.status == "ok"
    assert result.details["checked"][0]["expected_value_present"] is True


def test_dns_single_attempt_is_pending_safe(monkeypatch) -> None:
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

    class Resolver:
        def resolve(self, name: str, record_type: str):  # type: ignore[no-untyped-def]
            raise RuntimeError("not propagated")

    monkeypatch.setattr(
        "fusekit.providers.verification.import_module",
        lambda name: Resolver() if name == "dns.resolver" else SimpleNamespace(),
    )

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=1, retry_seconds=0)

    assert result.status == "pending"
    assert result.details["pending_safe"] is True


def test_pending_safe_result_stops_verification_retries(monkeypatch) -> None:
    vault = Vault.empty()
    pack = _pack("cloudflare")
    recipe = VerificationRecipe(kind="dns-records", target="moonlite.rsvp")
    calls = {"count": 0}

    def pending_safe(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        calls["count"] += 1
        return VerificationResult(
            provider="cloudflare",
            kind="dns-records",
            target="moonlite.rsvp",
            status="pending",
            details={"pending_safe": True},
        )

    monkeypatch.setattr("fusekit.providers.verification.verify_recipe", pending_safe)
    monkeypatch.setattr(
        "fusekit.providers.verification.time.sleep",
        lambda seconds: pytest.fail(f"pending-safe result should not sleep for {seconds}s"),
    )

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=10, retry_seconds=30)

    assert result.status == "pending"
    assert result.details["pending_safe"] is True
    assert calls["count"] == 1


def test_cloudflare_dns_api_missing_records_is_pending_safe(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.cloudflare.token",
        "provider_token",
        "cloudflare",
        "CLOUDFLARE_API_TOKEN",
        "token",
    )
    pack = _pack("cloudflare")
    recipe = VerificationRecipe(
        kind="cloudflare-dns-api",
        target="moonlite.rsvp",
        inputs={
            "records_json": json.dumps(
                [{"name": "moonlite.rsvp", "type": "A", "value": "203.0.113.10"}]
            )
        },
    )
    object.__setattr__(pack, "verification", (recipe,))

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        url = request.full_url
        if "/zones?" in url:
            return _JsonResponse({"result": [{"id": "zone-id"}]})
        return _JsonResponse({"result": []})

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(pack, vault)[0]

    assert result.status == "pending"
    assert result.details["pending_safe"] is True
    assert result.details["missing"] == [{"name": "moonlite.rsvp", "type": "A"}]


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


def test_vercel_deployment_accepts_healthy_live_url_when_list_is_ambiguous(
    monkeypatch,
) -> None:
    vault = Vault.empty()
    vault.put("provider.vercel.token", "provider_secret", "vercel", "VERCEL_TOKEN", "token")
    pack = _pack("vercel")
    recipe = VerificationRecipe(kind="vercel-deployment-url", target="moonlite")
    object.__setattr__(pack, "verification", (recipe,))

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        if request.full_url.startswith("https://api.vercel.com/"):
            return _JsonResponse({"deployments": []}, status=200)
        return _JsonResponse({}, status=200)

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(pack, vault, live_url="https://moonlite.rsvp")[0]

    assert result.status == "ok"
    assert result.details["ready"] is True
    assert result.details["live_url_ready"] is True


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
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "resend-token",
    )
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


def test_github_missing_secret_waits_for_uncaptured_provider_value(monkeypatch) -> None:
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

    assert result.status == "needs_human_gate"
    assert result.details["service_gate"] is True


def test_resend_domain_check_sends_user_agent_and_allows_empty_domains(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "resend-token",
    )
    pack = _pack("resend")
    recipe = VerificationRecipe(kind="resend-domain", target="${input:resend_domain}")
    object.__setattr__(pack, "verification", (recipe,))
    captured: dict[str, object] = {}

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        captured["headers"] = dict(request.headers)
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return _JsonResponse({"data": []}, status=200)

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_provider_pack(
        pack,
        vault,
        inputs={"resend_domain": "moonlite.rsvp"},
    )[0]

    assert result.status == "failed"
    assert result.details["missing"] is True
    assert result.details["repair"] == "rerun_resend_domain_setup"
    assert "create or reuse the domain through Resend's API" in result.details["reason"]
    assert captured["headers"]["User-agent"] == "FuseKit provider verification"
    assert captured["url"] == "https://api.resend.com/domains"


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


def test_vercel_env_missing_runtime_values_needs_human_gate(monkeypatch) -> None:
    vault = Vault.empty()
    vault.put("provider.vercel.token", "provider_secret", "vercel", "VERCEL_TOKEN", "token")
    pack = _pack("vercel")
    recipe = VerificationRecipe(
        kind="vercel-env",
        target="moonlite",
        inputs={"names": "WEBHOOK_SECRET,RESEND_FROM_EMAIL"},
    )

    def local_urlopen(request, timeout=30):  # type: ignore[no-untyped-def]
        del request, timeout
        return _JsonResponse({"envs": [{"id": "env_1", "key": "WEBHOOK_SECRET"}]})

    monkeypatch.setattr("fusekit.providers.verification.urlopen", local_urlopen)

    result = verify_recipe_with_retries(pack, recipe, vault, attempts=10, retry_seconds=30)

    assert result.status == "needs_human_gate"
    assert result.details["service_gate"] is True
    reason = result.details["reason"]
    assert "RESEND_FROM_EMAIL" in reason
    assert "Capture or derive" not in reason
    assert "launcher controls" in reason
    assert "Capture copy-once provider values" not in reason
    assert "exact env-named Capture buttons" in reason
    assert "only when a copy-once provider token gate appears" in reason
    assert "regenerate API-owned provider values such as RESEND_FROM_EMAIL" in reason


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
