from __future__ import annotations

import importlib.util
import io
import json
import re
import urllib.request
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fusekit.hosted.github_app import GitHubAppConfig
from fusekit.hosted.server import HostedSettings, hosted_application, render_hosted_home
from fusekit.hosted.session import create_hosted_state_token

FAKE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----"
STATE_SECRET = "hosted-state-secret"
WORKER_SECRET = "hosted-worker-secret"


def _call(
    path: str,
    method: str = "GET",
    *,
    query_string: str = "",
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    settings: HostedSettings | None = None,
) -> tuple[str, dict[str, str], bytes]:
    app = hosted_application(
        settings
        or HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="12345",
            github_app_slug="fusekit-launcher",
            github_private_key_pem=_private_key_pem(),
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
        )
    )
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = json.dumps(json_body).encode("utf-8") if json_body is not None else b""
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    for key, value in (headers or {}).items():
        environ[f"HTTP_{key.upper().replace('-', '_')}"] = value
    chunks = app(environ, start_response)
    body = b"".join(_as_list(chunks))
    return str(captured["status"]), dict(captured["headers"]), body


def _as_list(chunks: Iterable[bytes]) -> list[bytes]:
    return list(chunks)


class FakeResponse:
    def __init__(self, payload: dict[str, object] | bytes) -> None:
        self.status = 200
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self._payload, bytes):
            return self._payload
        return json.dumps(self._payload).encode("utf-8")


class SequenceOpener:
    def __init__(self, payloads: list[dict[str, object] | bytes]) -> None:
        self.payloads = payloads
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, Any]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        self.bodies.append(json.loads((request.data or b"{}").decode("utf-8")))
        assert timeout in {30.0, 90.0}
        return FakeResponse(self.payloads.pop(0))


def _private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _settings_with_github(opener: SequenceOpener) -> HostedSettings:
    config = GitHubAppConfig(
        app_id="12345",
        app_slug="fusekit-launcher",
        private_key_pem=_private_key_pem(),
    )
    return HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id=config.app_id,
        github_app_slug=config.app_slug,
        github_private_key_pem=config.private_key_pem,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        github_opener=opener,
    )


def _github_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "demo-main/package.json",
            json.dumps({"name": "hosted-demo", "dependencies": {"resend": "latest"}}),
        )
        archive.writestr(
            "demo-main/src/mail.ts",
            "const key = process.env.RESEND_API_KEY; const hook = process.env.WEBHOOK_SECRET;",
        )
    return buffer.getvalue()


def test_hosted_home_is_no_terminal_and_subdomain_canonical() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="12345",
            github_app_slug="fusekit-launcher",
            github_private_key_pem=_private_key_pem(),
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
        )
    )

    assert "https://fusekit.snowmanai.org" in html
    assert "Launch any GitHub app without touching a terminal." in html
    assert "Start hosted launch" in html
    assert "open-core setup worker" in html
    assert "narrow permissions" in html
    assert "visible" in html
    assert "redacted proof" in html
    assert "reversible setup" in html
    assert "state=" in html
    assert "Hosted GitHub intake is ready." in html
    assert "fusekit launch" not in html
    assert "source .venv" not in html
    assert "pip install" not in html
    assert "PRIVATE KEY" not in html


def test_hosted_home_waits_for_complete_operator_configuration() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="",
            github_app_slug="fusekit-launcher",
            github_private_key_pem="",
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
        )
    )

    assert "Hosted GitHub intake is waiting for operator configuration." in html
    assert "Operator setup pending" in html
    assert "FUSEKIT_GITHUB_APP_ID" in html
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in html
    assert 'href="#" aria-disabled="true"' in html
    assert "state=" not in html
    assert "PRIVATE KEY" not in html
    assert STATE_SECRET not in html


def test_hosted_home_shows_invalid_operator_configuration_codes_only() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="http://snowmanai.org/path",
            github_app_id="not-a-number",
            github_app_slug="bad/slug",
            github_private_key_pem=FAKE_PRIVATE_KEY,
            state_secret="abc123",
            worker_secret="abc123",
        )
    )

    assert "Hosted GitHub intake is waiting for operator configuration." in html
    assert "invalid:hosted_origin_must_be_https_origin" in html
    assert "invalid:github_app_id_must_be_positive_integer" in html
    assert "invalid:github_app_slug_is_invalid" in html
    assert "invalid:github_app_private_key_must_be_rsa_pem" in html
    assert "invalid:hosted_state_secret_too_short" in html
    assert "invalid:hosted_worker_secret_too_short" in html
    assert 'href="#" aria-disabled="true"' in html
    assert "state=" not in html
    assert "not-a-number" not in html
    assert "bad/slug" not in html
    assert "http://snowmanai.org/path" not in html
    assert "not-real" not in html
    assert "abc123" not in html
    assert WORKER_SECRET not in html


def test_hosted_wsgi_routes_return_safe_responses() -> None:
    status, headers, body = _call("/")

    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert b"Start hosted launch" in body
    assert b"Hosted deployment contract" in body
    assert b"fusekit-hosted-deployment" in body
    assert b"PRIVATE KEY" not in body

    status, headers, body = _call("/healthz")
    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert json.loads(body.decode("utf-8")) == {"ok": True}


def test_hosted_readiness_endpoint_reports_presence_without_secret_values() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=(
            "-----BEGIN PRIVATE KEY-----\nsuper-sensitive-material\n-----END PRIVATE KEY-----"
        ),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, headers, body = _call(
        "/api/hosted/readiness",
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert payload["schema_version"] == "fusekit.hosted-readiness.v1"
    assert payload["ready"] is False
    assert payload["configured"]["FUSEKIT_GITHUB_APP_PRIVATE_KEY"] is True
    assert payload["configured"]["FUSEKIT_GITHUB_APP_ID"] is False
    assert payload["missing"] == ["FUSEKIT_GITHUB_APP_ID"]
    assert payload["configured"]["FUSEKIT_HOSTED_WORKER_SECRET"] is True
    assert "PRIVATE KEY" not in serialized
    assert "super-sensitive-material" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_readiness_endpoint_reports_ready_when_configured() -> None:
    status, _headers, body = _call("/api/hosted/readiness")
    payload = json.loads(body.decode("utf-8"))

    assert status == "200 OK"
    assert payload["ready"] is True
    assert payload["missing"] == []
    assert payload["invalid"] == []
    assert payload["public_origin"] == "https://fusekit.snowmanai.org"
    assert payload["github_app_slug"] == "fusekit-launcher"


def test_hosted_deployment_endpoint_reports_subdomain_contract_without_secrets() -> None:
    status, headers, body = _call("/api/hosted/deployment")
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert payload["schema_version"] == "fusekit.hosted-deployment.v1"
    assert payload["canonical_origin"] == "https://fusekit.snowmanai.org"
    assert payload["domain"] == "fusekit.snowmanai.org"
    assert payload["runtime"] == {
        "provider": "vercel",
        "entrypoint": "app.py",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    assert payload["cloudflare_dns"]["zone"] == "snowmanai.org"
    assert payload["cloudflare_dns"]["record_name"] == "fusekit"
    assert payload["cloudflare_dns"]["record_type"] == "CNAME"
    assert payload["github_app"]["callback_url"] == (
        "https://fusekit.snowmanai.org/github/callback"
    )
    assert payload["github_app"]["repository_permission"] == "contents:read"
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in payload["required_runtime_env"]
    assert "FUSEKIT_HOSTED_WORKER_SECRET" in payload["required_runtime_env"]
    assert "PRIVATE KEY" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_readiness_endpoint_rejects_invalid_config_shape_without_values() -> None:
    settings = HostedSettings(
        public_origin="http://snowmanai.org/path",
        github_app_id="not-a-number",
        github_app_slug="bad/slug",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret="abc123",
        worker_secret="abc123",
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["missing"] == []
    assert payload["invalid"] == [
        "hosted_origin_must_be_https_origin",
        "github_app_id_must_be_positive_integer",
        "github_app_slug_is_invalid",
        "github_app_private_key_must_be_rsa_pem",
        "hosted_state_secret_too_short",
        "hosted_worker_secret_too_short",
    ]
    assert "not-a-number" not in serialized
    assert "bad/slug" not in serialized
    assert "http://snowmanai.org/path" not in serialized
    assert "not-real" not in serialized
    assert "abc123" not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_github_intake_routes_fail_closed_when_not_ready() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="",
        github_app_slug="fusekit-launcher",
        github_private_key_pem="",
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    for path in ("/api/github/intake", "/github/callback"):
        status, headers, body = _call(path, settings=settings)
        payload = json.loads(body.decode("utf-8"))
        serialized = json.dumps(payload)

        assert status == "503 Service Unavailable"
        assert headers["Content-Type"] == "application/json; charset=utf-8"
        assert payload["error"] == "hosted_not_ready"
        assert payload["readiness"]["ready"] is False
        assert "FUSEKIT_GITHUB_APP_ID" in payload["readiness"]["missing"]
        assert "PRIVATE KEY" not in serialized
        assert STATE_SECRET not in serialized
        assert WORKER_SECRET not in serialized


def test_vercel_wsgi_entrypoint_serves_healthz(monkeypatch) -> None:
    monkeypatch.setenv("FUSEKIT_HOSTED_ORIGIN", "https://fusekit.snowmanai.org")
    monkeypatch.setenv("FUSEKIT_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("FUSEKIT_GITHUB_APP_SLUG", "fusekit-launcher")
    monkeypatch.setenv("FUSEKIT_GITHUB_APP_PRIVATE_KEY", FAKE_PRIVATE_KEY)
    monkeypatch.setenv("FUSEKIT_HOSTED_STATE_SECRET", STATE_SECRET)
    monkeypatch.setenv("FUSEKIT_HOSTED_WORKER_SECRET", WORKER_SECRET)
    spec = importlib.util.spec_from_file_location(
        "fusekit_vercel_app",
        Path(__file__).parents[1] / "app.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(
        module.app(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/healthz",
                "QUERY_STRING": "",
            },
            start_response,
        )
    )

    assert captured["status"] == "200 OK"
    assert json.loads(body.decode("utf-8")) == {"ok": True}


def test_hosted_github_intake_endpoint_is_public_safe() -> None:
    status, _headers, body = _call("/api/github/intake")
    payload = json.loads(body.decode("utf-8"))

    assert status == "200 OK"
    assert payload["provider"] == "github"
    assert payload["route"] == "github-app"
    assert payload["install_url"] == (
        "https://github.com/apps/fusekit-launcher/installations/new"
    )
    serialized = json.dumps(payload)
    assert "PRIVATE KEY" not in serialized
    assert "not-real" not in serialized
    assert "ghs_" not in serialized


def test_hosted_github_callback_accepts_signed_state() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )

    status, _headers, body = _call(
        "/github/callback",
        query_string=f"installation_id=42&setup_action=install&state={state}",
    )

    assert status == "200 OK"
    text = body.decode("utf-8")
    assert "GitHub App connected." in text
    assert "installation 42" in text
    assert "No installation token is embedded" in text
    assert "PRIVATE KEY" not in text
    assert "ghs_" not in text


def test_hosted_github_callback_links_repository_selection() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )

    status, _headers, body = _call(
        "/github/callback",
        query_string=f"installation_id=42&setup_action=install&state={state}",
    )

    assert status == "200 OK"
    text = body.decode("utf-8")
    assert "/github/repositories?installation_id=42&amp;state=" in text
    assert "ghs_" not in text


def test_hosted_github_callback_rejects_bad_state() -> None:
    status, _headers, body = _call(
        "/github/callback",
        query_string="installation_id=42&setup_action=install&state=bad",
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_state"}


def test_hosted_github_repositories_lists_selected_repos_without_token_leak() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {
                "repositories": [
                    {"full_name": "example/one", "private": True},
                    {"full_name": "example/two", "private": False},
                ]
            },
        ]
    )

    status, _headers, body = _call(
        "/github/repositories",
        query_string=f"installation_id=42&state={state}",
        settings=_settings_with_github(opener),
    )

    assert status == "200 OK"
    assert len(opener.requests) == 2
    assert opener.requests[0].full_url == (
        "https://api.github.com/app/installations/42/access_tokens"
    )
    assert opener.bodies[0] == {"permissions": {"contents": "read"}}
    assert opener.requests[1].full_url == "https://api.github.com/installation/repositories"
    assert opener.requests[1].headers["Authorization"] == (
        "Bearer ghs_fake_installation_token_for_test"
    )
    text = body.decode("utf-8")
    assert "Choose the repository to scan." in text
    assert "example/one" in text
    assert "example/two" in text
    assert "/github/plan?installation_id=42&amp;repo=example%2Fone&amp;state=" in text
    assert "installation token out of this page" in text
    assert "ghs_fake" not in text
    assert "PRIVATE KEY" not in text


def test_hosted_github_repositories_rejects_bad_state_before_github_call() -> None:
    opener = SequenceOpener([])

    status, _headers, body = _call(
        "/github/repositories",
        query_string="installation_id=42&state=bad",
        settings=_settings_with_github(opener),
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_state"}
    assert opener.requests == []


def test_hosted_github_plan_fetches_source_and_renders_visible_plan() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )

    status, _headers, body = _call(
        "/github/plan",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=_settings_with_github(opener),
    )

    assert status == "200 OK"
    assert len(opener.requests) == 4
    assert opener.requests[2].full_url == "https://api.github.com/repos/example/one"
    assert opener.requests[3].full_url == (
        "https://codeload.github.com/example/one/zip/refs/heads/main"
    )
    assert opener.requests[3].headers["Authorization"] == (
        "Bearer ghs_fake_installation_token_for_test"
    )
    text = body.decode("utf-8")
    assert "Launch hosted-demo with FuseKit" in text
    assert "https://github.com/example/one" in text
    assert "Visible plan" in text
    assert "/github/control-room?installation_id=42&amp;repo=example%2Fone&amp;state=" in text
    assert "RESEND_API_KEY" in text
    assert "redacted proof" in text
    assert "ghs_fake" not in text
    assert "PRIVATE KEY" not in text


def test_hosted_github_plan_requires_selected_repository() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
        ]
    )

    status, _headers, body = _call(
        "/github/plan",
        query_string=f"installation_id=42&repo=example/two&state={state}",
        settings=_settings_with_github(opener),
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "repository_not_selected"}
    assert len(opener.requests) == 2


def test_hosted_github_control_room_fetches_source_and_renders_job() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=_settings_with_github(opener),
    )

    assert status == "200 OK"
    assert len(opener.requests) == 4
    text = body.decode("utf-8")
    assert "Hosted launch control room." in text
    assert "provider-owned" in text
    assert "Worker contract" in text
    assert "View proof receipt" in text
    assert "Run Record" in text
    assert ".fusekit/workspace_detonation.json" in text
    assert "Detonation" in text
    assert "ghs_fake" not in text
    assert "PRIVATE KEY" not in text


def test_hosted_job_api_returns_redacted_status_and_accepts_protected_action() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_worker"
    assert payload["worker_contract"]["required_artifacts"]
    assert payload["worker_contract"]["github_installation_id"] == 42
    assert ".fusekit/run_record.json" in payload["worker_contract"]["required_artifacts"]
    assert "ghs_fake" not in json.dumps(payload)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}",
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    steps = {step["id"]: step for step in payload["steps"]}
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_provider_gates"
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert steps["provider.gates"]["status"] == "waiting"
    assert "ghs_fake" not in json.dumps(payload)


def test_hosted_job_api_accepts_signed_job_token_without_process_memory() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        query_string=f"job={job_token}",
        settings=stateless_settings,
    )
    payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_worker"
    assert payload["job_token"]

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}&job={job_token}",
        settings=stateless_settings,
    )
    payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_provider_gates"
    assert payload["job_token"]
    assert "ghs_fake" not in json.dumps(payload)


def test_hosted_job_action_from_browser_returns_updated_control_room_html() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}&job={job_token}",
        headers={"Accept": "text/html,application/xhtml+xml"},
        settings=settings,
    )
    text = body.decode("utf-8")
    payload = json.loads(
        _match(
            text,
            r'<script id="fusekit-hosted-job" type="application/json">(.*?)</script>',
        ).replace("&quot;", '"')
    )

    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "Hosted launch control room." in text
    assert "waiting for provider gates" in text
    assert "Hosted worker contract queued" in text
    assert "View worker request" in text
    assert "job=" in text
    assert payload["status"] == "waiting_for_provider_gates"
    assert "ghs_fake" not in text


def test_hosted_worker_request_requires_start_and_supports_stateless_job_token() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-request",
        query_string=f"job={job_token}",
        settings=settings,
    )
    assert status == "409 Conflict"
    assert json.loads(body.decode("utf-8")) == {"error": "worker_not_started"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}&job={job_token}",
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-request",
        query_string=f"job={started['job_token']}",
        settings=stateless_settings,
    )
    request = json.loads(body.decode("utf-8"))
    serialized = json.dumps(request)

    assert status == "200 OK"
    assert request["schema_version"] == "fusekit.hosted-worker-request.v1"
    assert request["job_id"] == job_id
    assert request["claim_policy"]["mode"] == "live"
    assert request["claim_policy"]["github_installation_id"] == 42
    assert request["claim_policy"]["remote_artifacts_required"] is True
    assert request["acceptance_gate"]["require_recording"] is True
    assert ".fusekit/run_record.json" in request["required_artifacts"]
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_claim_requires_backend_auth_and_returns_redacted_receipt() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}&job={job_token}",
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-claims",
        method="POST",
        query_string=f"job={started['job_token']}",
        settings=stateless_settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_worker_auth"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-claims",
        method="POST",
        query_string=f"job={started['job_token']}",
        headers={
            "Authorization": f"Bearer {WORKER_SECRET}",
            "X-FuseKit-Worker-Id": "worker-01<script>",
        },
        settings=stateless_settings,
    )
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)
    steps = {step["id"]: step for step in payload["job"]["steps"]}

    assert status == "200 OK"
    assert payload["job"]["status"] == "worker_claimed"
    assert payload["job_token"]
    assert payload["claim_receipt"]["schema_version"] == "fusekit.hosted-worker-claim.v1"
    assert payload["claim_receipt"]["worker_id"] == "worker-01script"
    assert payload["worker_request"]["schema_version"] == "fusekit.hosted-worker-request.v1"
    assert steps["worker.prepare"]["status"] == "done"
    assert steps["provider.gates"]["status"] == "waiting"
    assert WORKER_SECRET not in serialized
    assert STATE_SECRET not in serialized
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "<script>" not in serialized


def test_hosted_worker_proof_submission_requires_backend_auth_and_redacted_evidence() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    control = _match(text, r"control=([A-Za-z0-9_.-]+)")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"control={control}&job={job_token}",
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )
    worker_headers = {
        "Authorization": f"Bearer {WORKER_SECRET}",
        "X-FuseKit-Worker-Id": "worker-01",
    }

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-claims",
        method="POST",
        query_string=f"job={started['job_token']}",
        headers=worker_headers,
        settings=stateless_settings,
    )
    claim = json.loads(body.decode("utf-8"))
    required_artifacts = claim["worker_request"]["required_artifacts"]
    evidence = {
        "live_url": True,
        "provider_verifiers": True,
        "dns_propagation": True,
        "rollback_metadata": True,
        "retrieved_remote_artifacts": True,
        "run_record": True,
        "detonation_receipt": True,
        "live_acceptance_report": True,
        "recording": True,
    }

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-proof",
        method="POST",
        query_string=f"job={claim['job_token']}",
        json_body={
            "schema_version": "fusekit.hosted-worker-proof.v1",
            "evidence": evidence,
            "completed_artifacts": required_artifacts,
            "note": "Authorization: Bearer raw-provider-token",
        },
        headers=worker_headers,
        settings=stateless_settings,
    )
    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_worker_proof"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-proof",
        method="POST",
        query_string=f"job={claim['job_token']}",
        json_body={
            "schema_version": "fusekit.hosted-worker-proof.v1",
            "evidence": evidence,
            "completed_artifacts": required_artifacts,
            "note": "Live proof artifacts passed.",
        },
        headers=worker_headers,
        settings=stateless_settings,
    )
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)
    steps = {step["id"]: step for step in payload["job"]["steps"]}

    assert status == "200 OK"
    assert payload["job"]["status"] == "complete"
    assert payload["proof_receipt"]["schema_version"] == (
        "fusekit.hosted-worker-proof-receipt.v1"
    )
    assert payload["proof_receipt"]["completion_ready"] is True
    assert payload["proof_receipt"]["missing_artifacts"] == []
    assert steps["proof.collect"]["status"] == "done"
    assert steps["rollback.ready"]["status"] == "done"
    assert steps["detonate.worker"]["status"] == "done"
    assert WORKER_SECRET not in serialized
    assert STATE_SECRET not in serialized
    assert "raw-provider-token" not in serialized
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_proof_receipt_page_uses_signed_job_token_without_process_memory() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/proof",
        query_string=f"job={job_token}",
        headers={"Accept": "text/html"},
        settings=stateless_settings,
    )
    text = body.decode("utf-8")
    payload = json.loads(
        _match(
            text,
            r'<script id="fusekit-hosted-proof" type="application/json">(.*?)</script>',
        ).replace("&quot;", '"')
    )

    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "Proof receipt." in text
    assert "Completion is not yet proven" in text
    assert ".fusekit/run_record.json" in text
    assert ".fusekit/workspace_detonation.json" in text
    assert "Reversible setup" in text
    assert payload["schema_version"] == "fusekit.hosted-proof-receipt.v1"
    assert payload["completion_ready"] is False
    assert "ghs_fake" not in text


def test_hosted_proof_receipt_page_rejects_tampered_signed_job_token() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/proof",
        query_string=f"job={job_token}x",
        headers={"Accept": "text/html"},
        settings=stateless_settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_job"}


def test_hosted_job_api_rejects_tampered_signed_job_token() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")
    stateless_settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        query_string=f"job={job_token}x",
        settings=stateless_settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_job"}


def test_hosted_job_api_rejects_bad_control_token() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token_for_test",
                "expires_at": "2026-06-21T01:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"repositories": [{"full_name": "example/one", "private": True}]},
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    settings = _settings_with_github(opener)
    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    job_id = _match(body.decode("utf-8"), r"hosted-[A-Za-z0-9_-]+")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string="control=bad",
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_wsgi_rejects_unknown_or_mutating_routes() -> None:
    status, _headers, body = _call("/missing")
    assert status == "404 Not Found"
    assert json.loads(body.decode("utf-8")) == {"error": "not_found"}

    status, _headers, body = _call("/", method="POST")
    assert status == "405 Method Not Allowed"
    assert json.loads(body.decode("utf-8")) == {"error": "method_not_allowed"}


def _match(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    assert match is not None
    return match.group(1) if match.groups() else match.group(0)
