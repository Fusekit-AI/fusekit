from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import urllib.request
import zipfile
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fusekit.hosted.billing import (
    HOSTED_STRIPE_PRICE_LOOKUP_POLICY,
    HOSTED_STRIPE_PRICE_SETUP_HELPER,
    HOSTED_STRIPE_PRICE_SETUP_MODULE,
    HOSTED_STRIPE_PRICE_SETUP_REQUIRED_FLAGS,
    HOSTED_STRIPE_PRICE_VERIFY_HELPER,
    HOSTED_STRIPE_PRICE_VERIFY_MODULE,
    HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
    HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
)
from fusekit.hosted.github_app import GitHubAppConfig
from fusekit.hosted.job import (
    HOSTED_BYO_OCI_HANDOFF_PREFLIGHT,
    HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION,
    HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION,
    HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION,
    HOSTED_BYO_OCI_REVERSIBILITY_SURVIVORS,
    HOSTED_BYO_OCI_REVERSIBILITY_TARGETS,
    create_hosted_job_token,
    with_hosted_job_payment_receipt,
)
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
)
from fusekit.hosted.launcher import HOSTED_PLAIN_LANGUAGE_JOURNEY, HOSTED_PROHIBITED_ACTIONS
from fusekit.hosted.server import (
    HOSTED_AWS_SOURCE_PROVENANCE_ENV,
    HOSTED_MAX_POST_BODY_BYTES,
    HOSTED_OCI_SOURCE_PROVENANCE_ENV,
    HOSTED_SECURITY_HEADERS_CONTRACT,
    HOSTED_SOURCE_INTEGRITY_CONTRACT,
    HOSTED_SOURCE_PROVENANCE_ENV,
    HostedSettings,
    hosted_application,
    render_hosted_home,
)
from fusekit.hosted.session import create_hosted_state_token

FAKE_PRIVATE_KEY = "not-a-pem-private-key"
STATE_SECRET = "hosted-state-secret"
WORKER_SECRET = "hosted-worker-secret"
VERCEL_COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"
MANAGED_PRICE_LABEL = "$49 one-time managed FuseKit run"


def _vercel_provenance_kwargs() -> dict[str, str]:
    return {
        "vercel_env": "production",
        "vercel_url": "fusekit-snowmanai-org.vercel.app",
        "vercel_git_provider": "github",
        "vercel_git_repo_owner": "Fusekit-AI",
        "vercel_git_repo_slug": "fusekit",
        "vercel_git_commit_ref": "main",
        "vercel_git_commit_sha": VERCEL_COMMIT_SHA,
    }


def _aws_provenance_kwargs() -> dict[str, str]:
    return {
        "deployment_provider": "aws-elastic-beanstalk",
        "aws_deployment_env": "production",
        "aws_deployment_url": "https://fusekit-prod.us-east-1.elasticbeanstalk.com",
        "aws_git_provider": "github",
        "aws_git_repo_owner": "Fusekit-AI",
        "aws_git_repo_slug": "fusekit",
        "aws_git_commit_ref": "main",
        "aws_git_commit_sha": VERCEL_COMMIT_SHA,
    }


def _oci_provenance_kwargs() -> dict[str, str]:
    return {
        "deployment_provider": "oci-compute",
        "aws_deployment_env": "production",
        "aws_deployment_url": "https://fusekit.snowmanai.org",
        "aws_git_provider": "github",
        "aws_git_repo_owner": "Fusekit-AI",
        "aws_git_repo_slug": "fusekit",
        "aws_git_commit_ref": "main",
        "aws_git_commit_sha": VERCEL_COMMIT_SHA,
    }


def _call(
    path: str,
    method: str = "GET",
    *,
    query_string: str = "",
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    form_body: dict[str, str] | None = None,
    raw_body: bytes | None = None,
    raw_content_type: str = "",
    content_length: int | None = None,
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
            worker_dispatch_url="https://worker.snowmanai.org/dispatch",
            **_vercel_provenance_kwargs(),
        )
    )
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b""
    content_type = ""
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        content_type = "application/json"
    if form_body is not None:
        body = urllib.parse.urlencode(form_body).encode("utf-8")
        content_type = "application/x-www-form-urlencoded"
    if raw_body is not None:
        body = raw_body
        content_type = raw_content_type
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_LENGTH": str(len(body) if content_length is None else content_length),
        "wsgi.input": io.BytesIO(body),
    }
    if content_type:
        environ["CONTENT_TYPE"] = content_type
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


class FormSequenceOpener:
    def __init__(self, payloads: list[dict[str, object]]) -> None:
        self.payloads = payloads
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, list[str]]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        body = urllib.parse.parse_qs((request.data or b"").decode("utf-8"))
        self.bodies.append(body)
        assert timeout == 30.0
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
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=opener,
        worker_dispatch_opener=SequenceOpener([{} for _ in range(8)]),
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
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
            worker_dispatch_url="https://worker.snowmanai.org/dispatch",
            **_vercel_provenance_kwargs(),
        )
    )
    payload = json.loads(
        _match(
            html,
            r'<script id="fusekit-github-intake" type="application/json">(.*?)</script>',
        ).replace("&quot;", '"')
    )

    assert "https://fusekit.snowmanai.org" in html
    assert "Launch any GitHub app without touching a terminal." in html
    assert "Start hosted launch" in html
    assert "Launch readiness" in html
    assert "All hosted readiness checks passed." in html
    assert "open-core setup worker" in html
    assert "Open core" in html
    assert "https://github.com/Fusekit-AI/fusekit" in html
    assert "app.py" in html
    assert "Reviewable hosted files" in html
    assert "vercel.json" in html
    assert "src/fusekit/hosted/server.py" in html
    assert "No private generated artifact is required for the hosted click flow." in html
    assert "Deployment provenance" in html
    assert "Fusekit-AI/fusekit" in html
    assert VERCEL_COMMIT_SHA in html
    assert "MIT" in html
    assert "narrow permissions" in html
    assert "selected repository only" in html
    assert "contents:read" in html
    assert "metadata:read" in html
    assert "all-repository" in html
    assert "contents:write" in html
    assert "visible" in html
    assert "redacted proof" in html
    assert "reversible setup" in html
    assert "Capability vault boundary" in html
    assert "Raw secrets must never leave" in html
    assert "Generated apps may request capabilities" in html
    assert "GitHub installation tokens" in html
    assert "copy-once secret values" in html
    assert "approved action ids" in html
    assert "What happens after the click" in html
    assert "What FuseKit will not do" in html
    assert HOSTED_PROHIBITED_ACTIONS[0] in html
    assert HOSTED_PROHIBITED_ACTIONS[1] in html
    assert "For someone who just wants to click" in html
    assert "Open fusekit.snowmanai.org in a browser." in html
    assert "Sign in to GitHub if asked and choose exactly one repository." in html
    assert "Complete only the provider-owned screens FuseKit highlights." in html
    assert "Completion requires" in html
    assert "Live URL verification" in html
    assert "Provider verifier results" in html
    assert "DNS propagation status" in html
    assert "Run Record" in html
    assert "Detonation receipt" in html
    assert "Live acceptance report" in html
    assert "Recording proof" in html
    assert "Reversible setup" in html
    assert "Show rollback metadata before risky changes." in html
    assert "Preserve rollback actions for provider resources FuseKit creates." in html
    assert "Offer stop, revoke access, rollback, and download redacted proof actions." in html
    assert "Install the FuseKit GitHub App on one selected repository." in html
    assert "Click Start hosted launch and pass only provider-owned human gates." in html
    assert "Receive the live URL, redacted proof receipt" in html
    assert "Deploy an HTTPS worker dispatch service" in html
    assert "Set FUSEKIT_HOSTED_WORKER_DISPATCH_URL" in html
    assert "Add fusekit.snowmanai.org as the Vercel custom domain." in html
    assert "set the fusekit record to the exact Vercel-provided CNAME target" in html
    assert "and --worker-dispatch-url checks ok" in html
    assert 'id="fusekit-github-intake"' in html
    assert 'id="fusekit-hosted-readiness"' in html
    assert 'id="fusekit-hosted-deployment"' in html
    assert "state=" in html
    assert "Hosted GitHub intake is ready." in html
    assert "fusekit launch" not in html
    assert "source .venv" not in html
    assert "pip install" not in html
    assert "PRIVATE KEY" not in html
    assert payload["trust_story"] == [
        "open core",
        "narrow permissions",
        "visible plan",
        "redacted proof",
        "reversible setup",
    ]
    assert payload["prohibited"] == list(HOSTED_PROHIBITED_ACTIONS)
    assert payload["open_core"]["source_repository"] == "https://github.com/Fusekit-AI/fusekit"
    assert payload["open_core"]["reviewable_entrypoint"] == "app.py"


def test_hosted_home_uses_selected_provider_contract_copy() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="12345",
            github_app_slug="fusekit-launcher",
            github_private_key_pem=_private_key_pem(),
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
            worker_dispatch_url="https://worker.snowmanai.org/dispatch",
            **_aws_provenance_kwargs(),
        )
    )

    assert "AWS Elastic Beanstalk must serve the Python WSGI entrypoint" in html
    assert "AWS/Git metadata" in html
    assert "Attach fusekit.snowmanai.org to the AWS HTTPS origin." in html
    assert "Use the exact AWS-provided CNAME target" in html
    assert "Vercel must serve" not in html
    assert "Vercel custom domain" not in html
    assert "Vercel-provided CNAME target" not in html
    assert "waiting for Vercel metadata" not in html


def test_hosted_home_uses_oci_provider_contract_copy() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="12345",
            github_app_slug="fusekit-launcher",
            github_private_key_pem=_private_key_pem(),
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
            worker_dispatch_url="https://worker.snowmanai.org/dispatch",
            **_oci_provenance_kwargs(),
        )
    )

    assert "OCI Compute must serve the Python WSGI entrypoint" in html
    assert "OCI/Git metadata" in html
    assert "Attach fusekit.snowmanai.org to the OCI HTTPS origin through Cloudflare." in html
    assert "Use the exact OCI reserved public IP address" in html
    assert "AWS Elastic Beanstalk must serve" not in html
    assert "AWS-provided CNAME target" not in html
    assert "Vercel must serve" not in html
    assert "Vercel-provided CNAME target" not in html


def test_hosted_home_requires_explicit_provider_without_vercel_metadata() -> None:
    html = render_hosted_home(
        HostedSettings(
            public_origin="https://fusekit.snowmanai.org",
            github_app_id="12345",
            github_app_slug="fusekit-launcher",
            github_private_key_pem=_private_key_pem(),
            state_secret=STATE_SECRET,
            worker_secret=WORKER_SECRET,
            worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        )
    )

    assert "select_hosted_deployment_provider" in html
    assert "Select the hosted deployment provider explicitly" in html
    assert "invalid:hosted_deployment_provider_required" in html
    assert "Vercel must serve" not in html
    assert "Vercel custom domain" not in html
    assert "Vercel-provided CNAME target" not in html
    assert "AWS Elastic Beanstalk must serve" not in html
    assert "AWS-provided CNAME target" not in html
    assert "OCI Compute must serve" not in html
    assert "OCI reserved public IP address" not in html


def test_hosted_readiness_rejects_unsupported_provider_without_echoing_value() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        deployment_provider="temporary-secretish-provider-value",
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["ready"] is False
    assert "hosted_deployment_provider_unsupported" in payload["invalid"]
    assert payload["source_provenance"]["provider"] == "unknown"
    assert payload["source_provenance"]["actual"] == {
        "deployment_provider_configured": True,
        "selected_provider": "unknown",
    }
    assert "temporary-secretish-provider-value" not in serialized


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
    assert "Launch readiness" in html
    assert "FUSEKIT_GITHUB_APP_ID" in html
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in html
    assert "FUSEKIT_HOSTED_WORKER_DISPATCH_URL" in html
    assert "Set the GitHub App id for the FuseKit hosted launcher." in html
    assert "Deploy the hosted worker dispatch receiver and set its HTTPS dispatch URL." in html
    assert '<span class="button disabled" aria-disabled="true">Start hosted launch</span>' in html
    assert 'href="#"' not in html
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
            worker_dispatch_url="http://worker.invalid/dispatch",
        )
    )

    assert "Hosted GitHub intake is waiting for operator configuration." in html
    assert "Launch readiness" in html
    assert "invalid:hosted_origin_must_be_https_origin" in html
    assert "invalid:github_app_id_must_be_positive_integer" in html
    assert "invalid:github_app_slug_is_invalid" in html
    assert "invalid:github_app_private_key_must_be_rsa_pem" in html
    assert "invalid:hosted_state_secret_too_short" in html
    assert "invalid:hosted_worker_secret_too_short" in html
    assert "Use an HTTPS origin with no path, query, credentials, or fragment." in html
    assert "Use a positive numeric GitHub App id." in html
    assert '<span class="button disabled" aria-disabled="true">Start hosted launch</span>' in html
    assert 'href="#"' not in html
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
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
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
    assert payload["blocking_checks"] == ["missing:FUSEKIT_GITHUB_APP_ID"]
    assert payload["next_actions"] == [
        "Set the GitHub App id for the FuseKit hosted launcher."
    ]
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
    assert payload["blocking_checks"] == []
    assert payload["next_actions"] == []
    assert payload["public_origin"] == "https://fusekit.snowmanai.org"
    assert payload["github_app_slug"] == "fusekit-launcher"
    assert payload["required_source_provenance_env"] == list(HOSTED_SOURCE_PROVENANCE_ENV)
    assert payload["source_provenance"]["verified"] is True
    assert payload["source_provenance"]["actual"]["commit_sha"] == VERCEL_COMMIT_SHA
    assert payload["lane_readiness"]["default_lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["lane_readiness"]["recommended_lane"] == BYO_OCI_LANE
    assert payload["lane_readiness"]["launchable_lanes"] == [BYO_OCI_LANE]
    lane_readiness = payload["lane_readiness"]["lanes"]
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["launchable"] is False
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["managed_worker_dispatch_allowed"] is False
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["blocking_checks"] == [
        "managed_runs_not_enabled",
        "stripe_secret_key_required_for_managed_runs",
        "stripe_price_id_required_for_managed_runs",
        "managed_run_price_label_required",
    ]
    assert lane_readiness[BYO_OCI_LANE]["launchable"] is True
    assert lane_readiness[BYO_OCI_LANE]["requires_payment"] is False
    assert lane_readiness[BYO_OCI_LANE]["requires_user_cloud_account"] is True
    assert lane_readiness[BYO_OCI_LANE][
        "user_owned_cost_boundary"
    ] == byo_oci_user_owned_cost_boundary()
    assert lane_readiness[BYO_OCI_LANE]["security_contract"] == byo_oci_security_contract()


def test_hosted_readiness_blocks_launch_without_verified_source_provenance() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["missing"] == []
    assert payload["invalid"] == [
        "hosted_deployment_provider_required",
        "source_provenance_not_verified",
    ]
    assert payload["blocking_checks"] == [
        "invalid:hosted_deployment_provider_required",
        "invalid:source_provenance_not_verified",
    ]
    assert payload["next_actions"] == [
        (
            "Set FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER to oci-compute, "
            "aws-elastic-beanstalk, or vercel before relying on provider-specific "
            "setup instructions."
        ),
        (
            "Publish hosted source provenance for Fusekit-AI/fusekit from the "
            "deployment runtime so the public source provenance verifies."
        )
    ]
    assert payload["source_provenance"]["provider"] == "unknown"
    assert payload["source_provenance"]["verified"] is False
    assert "PRIVATE KEY" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_readiness_reports_paid_managed_lane_when_stripe_is_configured() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)
    lane_readiness = payload["lane_readiness"]["lanes"]

    assert status == "200 OK"
    assert payload["ready"] is True
    assert payload["payment"]["enabled"] is True
    assert payload["payment"]["managed_runs_enabled"] is True
    assert payload["payment"]["secret_key_configured"] is True
    assert payload["payment"]["account_mode"] == "live"
    assert payload["payment"]["live_mode_configured"] is True
    assert payload["payment"]["test_mode_allowed"] is False
    assert payload["payment"]["price_configured"] is True
    assert payload["payment"]["price_label_configured"] is True
    assert payload["payment"]["price_label"] == MANAGED_PRICE_LABEL
    assert payload["lane_readiness"]["recommended_lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["lane_readiness"]["launchable_lanes"] == [
        MANAGED_FUSEKIT_RUN_LANE,
        BYO_OCI_LANE,
    ]
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["launchable"] is True
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["managed_worker_dispatch_allowed"] is True
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["blocking_checks"] == []
    assert lane_readiness[BYO_OCI_LANE]["launchable"] is True
    assert lane_readiness[BYO_OCI_LANE]["security_contract"] == byo_oci_security_contract()
    assert "sk_live" not in serialized
    assert "price_managed_run" not in serialized


def test_hosted_readiness_rejects_ambiguous_managed_price_label() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label="Launch validation: .00 FuseKit managed run",
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    managed = payload["lane_readiness"]["lanes"][MANAGED_FUSEKIT_RUN_LANE]

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["invalid"] == ["managed_run_price_label_required"]
    assert payload["payment"]["enabled"] is False
    assert payload["payment"]["price_label_configured"] is False
    assert payload["payment"]["price_label"] == ""
    assert managed["launchable"] is False
    assert managed["blocking_checks"] == ["managed_run_price_label_required"]


def test_hosted_readiness_rejects_test_mode_stripe_for_public_managed_lane() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        managed_runs_enabled=True,
        stripe_secret_key="sk_test_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)
    managed = payload["lane_readiness"]["lanes"][MANAGED_FUSEKIT_RUN_LANE]

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["payment"]["enabled"] is False
    assert payload["payment"]["managed_runs_enabled"] is True
    assert payload["payment"]["secret_key_configured"] is True
    assert payload["payment"]["account_mode"] == "test"
    assert payload["payment"]["live_mode_configured"] is False
    assert payload["payment"]["test_mode_allowed"] is False
    assert managed["launchable"] is False
    assert "stripe_live_secret_key_required_for_managed_runs" in managed["blocking_checks"]
    assert "sk_test" not in serialized
    assert "price_managed_run" not in serialized


def test_hosted_readiness_test_mode_override_rejects_unknown_stripe_key_shape() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        managed_runs_enabled=True,
        stripe_secret_key="sk_redacted_unknown",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        stripe_test_mode_allowed=True,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    managed = payload["lane_readiness"]["lanes"][MANAGED_FUSEKIT_RUN_LANE]

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["payment"]["enabled"] is False
    assert payload["payment"]["account_mode"] == "unknown"
    assert payload["payment"]["test_mode_allowed"] is True
    assert managed["launchable"] is False
    assert "stripe_live_secret_key_required_for_managed_runs" in managed["blocking_checks"]


def test_hosted_deployment_endpoint_reports_subdomain_contract_without_secrets() -> None:
    status, headers, body = _call("/api/hosted/deployment")
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert payload["schema_version"] == "fusekit.hosted-deployment.v1"
    assert payload["canonical_origin"] == "https://fusekit.snowmanai.org"
    assert payload["domain"] == "fusekit.snowmanai.org"
    assert payload["trust_story"] == [
        "open core",
        "narrow permissions",
        "visible plan",
        "redacted proof",
        "reversible setup",
    ]
    assert set(payload["trust_contract"]) == {
        "open_core",
        "narrow_permissions",
        "visible_plan",
        "redacted_proof",
        "reversible_setup",
    }
    assert "contents:read" in payload["trust_contract"]["narrow_permissions"]
    assert "redacted" in payload["trust_contract"]["redacted_proof"]
    boundary = payload["capability_vault_boundary"]
    assert boundary["raw_secret_policy"] == (
        "Only FuseKit may use secrets internally. Raw secrets must never leave the "
        "vault runtime."
    )
    assert boundary["generated_app_policy"].startswith("Generated apps may request capabilities")
    assert "provider credentials" in boundary["forbidden_public_material"]
    assert "GitHub installation tokens" in boundary["forbidden_public_material"]
    assert "vault material" in boundary["forbidden_public_material"]
    assert "approved action ids" in boundary["allowed_public_material"]
    assert "detonation receipt status" in boundary["allowed_public_material"]
    assert payload["one_click_launch"]["public_url"] == "https://fusekit.snowmanai.org"
    assert payload["one_click_launch"]["start_control"] == "Start hosted launch"
    lanes = payload["launch_lanes"]["lanes"]
    managed_lane = next(lane for lane in lanes if lane["id"] == MANAGED_FUSEKIT_RUN_LANE)
    byo_lane = next(lane for lane in lanes if lane["id"] == BYO_OCI_LANE)
    assert "Zero unverified FuseKit-managed infrastructure spend is allowed." in managed_lane[
        "cost_controls"
    ]
    assert "Checkout sessions cannot be reused across launches." in managed_lane[
        "cost_controls"
    ]
    assert "FuseKit-managed worker dispatch is disabled." in byo_lane["cost_controls"]
    assert "Disposable workers must use AMD/x86_64 shapes; ARM images are not allowed." in byo_lane[
        "cost_controls"
    ]
    assert byo_lane["user_owned_cost_boundary"]["spend_owner"] == "user_oci_tenancy"
    assert (
        byo_lane["user_owned_cost_boundary"]["fusekit_managed_infrastructure_spend"] is False
    )
    assert byo_lane["security_contract"]["managed_worker_dispatch_allowed"] is False
    assert byo_lane["security_contract"]["hosted_worker_secret_exported"] is False
    assert byo_lane["security_contract"]["hosted_github_private_key_exported"] is False
    assert byo_lane["security_contract"]["runner_architecture"] == "amd_x86_64_only"
    assert byo_lane["security_contract"]["runner_profile"] == {
        "provider": "oracle-cloud-infrastructure",
        "runner": "oci-existing",
        "shape": "VM.Standard.E5.Flex",
        "shape_family": "standard-e5",
        "architecture": "amd64/x86_64",
        "arm_allowed": False,
        "visual_runner": "novnc",
    }
    assert "live_acceptance_report" in byo_lane["security_contract"][
        "completion_claim_requires"
    ]
    assert payload["payment"]["cost_controls"] == {
        "max_unverified_managed_spend_cents": 0,
        "dispatch_requires_paid_checkout_session": True,
        "reuse_across_jobs_allowed": False,
        "session_binding": [
            "client_reference_id",
            "job_id",
            "lane",
            "github_source_hash",
            "plan_fingerprint",
            "stripe_price_id_hash",
            "price_label_hash",
        ],
    }
    assert payload["worker_dispatch"]["dispatch_binding"] == {
        "required": True,
        "required_fields": [
            "job_id",
            "action",
            "lane",
            "payment_status",
            "plan_fingerprint",
            "price_label_hash",
        ],
        "required_for_actions": ["start", "rollback", "detonate"],
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "payment_status": "paid",
        "hash_fields": ["plan_fingerprint", "price_label_hash"],
        "secret_boundary": (
            "Dispatch binding contains only public job/action/lane/payment labels "
            "and SHA-256 public hashes; job tokens and worker secrets are excluded."
        ),
    }
    assert payload["payment"]["operator_setup"] == {
        "helper_command": HOSTED_STRIPE_PRICE_SETUP_HELPER,
        "verification_command": HOSTED_STRIPE_PRICE_VERIFY_HELPER,
        "module_fallback": HOSTED_STRIPE_PRICE_SETUP_MODULE,
        "verification_module_fallback": HOSTED_STRIPE_PRICE_VERIFY_MODULE,
        "dry_run_default": True,
        "mutation_requires": list(HOSTED_STRIPE_PRICE_SETUP_REQUIRED_FLAGS),
        "lookup_key_policy": HOSTED_STRIPE_PRICE_LOOKUP_POLICY,
        "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
        "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        "managed_runs_enable_after": "live Checkout proof and worker-dispatch acceptance pass",
    }
    lane_readiness = payload["lane_readiness"]["lanes"]
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["launchable"] is False
    assert lane_readiness[MANAGED_FUSEKIT_RUN_LANE]["blocking_checks"] == [
        "managed_runs_not_enabled",
        "stripe_secret_key_required_for_managed_runs",
        "stripe_price_id_required_for_managed_runs",
        "managed_run_price_label_required",
    ]
    assert lane_readiness[BYO_OCI_LANE]["launchable"] is True
    assert payload["one_click_launch"]["terminal_required"] is False
    assert payload["one_click_launch"]["download_required"] is False
    assert payload["one_click_launch"]["intake"] == "github-app"
    assert payload["one_click_launch"]["repository_scope"] == "one selected GitHub repository"
    assert payload["one_click_launch"]["github_repository_permission"] == "contents:read"
    assert payload["one_click_launch"]["launch_path"][0] == "Visit the hosted FuseKit URL."
    assert payload["one_click_launch"]["launch_path"][-1] == (
        "Receive the live URL, redacted proof receipt, rollback metadata, and detonation receipt."
    )
    assert payload["one_click_launch"]["plain_language_journey"] == list(
        HOSTED_PLAIN_LANGUAGE_JOURNEY
    )
    assert payload["one_click_launch"]["prohibited"] == list(HOSTED_PROHIBITED_ACTIONS)
    assert "Run Record" in payload["one_click_launch"]["completion_requires"]
    assert "Detonation receipt" in payload["one_click_launch"]["completion_requires"]
    assert "Recording proof" in payload["one_click_launch"]["completion_requires"]
    assert payload["one_click_launch"]["completion_evidence_keys"] == [
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "rollback_metadata",
        "retrieved_remote_artifacts",
        "run_record",
        "detonation_receipt",
        "live_acceptance_report",
        "recording",
    ]
    assert any("rollback" in item for item in payload["one_click_launch"]["reversal"])
    assert any("MFA" in item for item in payload["one_click_launch"]["human_gates"])
    assert payload["protected_controls"] == {
        "actions": ["start", "stop", "rollback", "detonate"],
        "http_method": "POST",
        "control_token_transport": "hidden_form_field",
        "content_type": "application/x-www-form-urlencoded",
        "query_control_behavior": "rejected_as_missing_control",
        "browser_origin_policy": "reject_cross_origin_when_origin_or_referer_present",
        "job_token_transport": "signed_public_query_parameter",
        "binding": "job_id_and_action",
        "token_lifetime": "short-lived",
        "public_url_policy": "action URLs must not include control tokens",
        "missing_token_behavior": "render disabled protected controls",
        "secret_boundary": (
            "Protected action receipts and public job tokens are redacted. Control "
            "tokens are action-bound click capabilities, not provider credentials, "
            "and must not appear in action URLs, deployment contracts, receipts, or "
            "logs."
        ),
    }
    assert payload["runtime"] == {
        "provider": "vercel",
        "entrypoint": "app.py",
        "routing_config": "vercel.json",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    assert payload["open_core"] == {
        "source_repository": "https://github.com/Fusekit-AI/fusekit",
        "license": "MIT",
        "reviewable_entrypoint": "app.py",
        "public_contracts": [
            "https://fusekit.snowmanai.org/api/hosted/readiness",
            "https://fusekit.snowmanai.org/api/hosted/deployment",
        ],
    }
    assert payload["cloudflare_dns"]["zone"] == "snowmanai.org"
    assert payload["cloudflare_dns"]["record_name"] == "fusekit"
    assert payload["cloudflare_dns"]["record_type"] == "CNAME"
    assert payload["security_headers"] == HOSTED_SECURITY_HEADERS_CONTRACT
    assert "Cache-Control" in payload["security_headers"]["required_headers"]
    assert "tokens" in payload["security_headers"]["secret_boundary"]
    assert payload["source_integrity"] == HOSTED_SOURCE_INTEGRITY_CONTRACT
    assert payload["source_integrity"]["source_repository"] == (
        "https://github.com/Fusekit-AI/fusekit"
    )
    assert payload["source_integrity"]["private_generated_artifact_required"] is False
    assert "vercel.json" in payload["source_integrity"]["reviewable_files"]
    assert "build tokens" in payload["source_integrity"]["secret_boundary"]
    provenance = payload["source_provenance"]
    assert provenance["provider"] == "vercel"
    assert provenance["source"] == "vercel_system_environment_variables"
    assert provenance["verified"] is True
    assert provenance["expected"] == {
        "deployment_environment": "production",
        "git_provider": "github",
        "repo_owner": "Fusekit-AI",
        "repo_slug": "fusekit",
        "source_repository": "https://github.com/Fusekit-AI/fusekit",
    }
    assert provenance["actual"] == {
        "deployment_environment": "production",
        "deployment_url": "fusekit-snowmanai-org.vercel.app",
        "git_provider": "github",
        "repo_owner": "Fusekit-AI",
        "repo_slug": "fusekit",
        "commit_ref": "main",
        "commit_sha": VERCEL_COMMIT_SHA,
    }
    assert provenance["required_env"] == list(HOSTED_SOURCE_PROVENANCE_ENV)
    assert "Vercel tokens" in provenance["secret_boundary"]
    assert payload["operator_setup"]["target_subdomain"] == "fusekit.snowmanai.org"
    assert [step["id"] for step in payload["operator_setup"]["steps"]] == [
        "connect_vercel_project",
        "deploy_worker_dispatch_receiver",
        "configure_worker_dispatch_url",
        "attach_custom_domain",
        "route_cloudflare_cname",
        "verify_public_contracts",
    ]
    assert "fusekit-hosted-worker-dispatch" in payload["operator_setup"]["steps"][1]["label"]
    assert "FUSEKIT_HOSTED_WORKER_DISPATCH_URL" in payload["operator_setup"]["steps"][2][
        "label"
    ]
    assert payload["operator_setup"]["steps"][3]["label"] == (
        "Add fusekit.snowmanai.org as the Vercel custom domain."
    )
    assert (
        "exact Vercel-provided CNAME target"
        in payload["operator_setup"]["steps"][4]["label"]
    )
    assert "tokens" in payload["operator_setup"]["secret_boundary"]
    assert payload["github_app"]["callback_url"] == (
        "https://fusekit.snowmanai.org/github/callback"
    )
    assert payload["github_app"]["repository_permission"] == "contents:read"
    assert payload["github_app"]["token_boundary"] == {
        "repository_selection": "selected",
        "requested_token_permissions": {"contents": "read"},
        "accepted_token_permissions": {"contents": "read", "metadata": "read"},
        "rejects": [
            "all-repository installation tokens",
            "contents:write installation tokens",
            "unexpected GitHub write permissions",
        ],
    }
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in payload["required_runtime_env"]
    assert "FUSEKIT_HOSTED_WORKER_SECRET" in payload["required_runtime_env"]
    assert "FUSEKIT_HOSTED_WORKER_DISPATCH_URL" in payload["required_runtime_env"]
    assert payload["optional_runtime_env"] == []
    assert payload["required_source_provenance_env"] == list(HOSTED_SOURCE_PROVENANCE_ENV)
    assert payload["worker_dispatch"]["schema_version"] == "fusekit.hosted-worker-dispatch.v1"
    assert payload["worker_dispatch"]["receiver_command"] == "fusekit-hosted-worker-dispatch"
    assert payload["worker_dispatch"]["production_required"] is True
    assert payload["worker_dispatch"]["no_terminal_wakeup_required"] is True
    assert payload["worker_dispatch"]["checks"] == {
        "dispatch": "https://worker.snowmanai.org/dispatch",
        "health": "https://worker.snowmanai.org/healthz",
        "readiness": "https://worker.snowmanai.org/readiness",
    }
    assert payload["worker_dispatch"]["required_runtime_env"] == [
        "FUSEKIT_HOSTED_WORKER_SECRET",
        "FUSEKIT_HOSTED_WORKER_ID",
    ]
    assert payload["worker_dispatch"]["optional_runtime_env"] == [
        "FUSEKIT_HOSTED_WORKER_WORKSPACE",
        "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR",
    ]
    assert "PRIVATE KEY" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_deployment_endpoint_supports_aws_wsgi_origin_without_secrets() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        **_aws_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/deployment", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["runtime"] == {
        "provider": "aws-elastic-beanstalk",
        "entrypoint": "app.py",
        "process_config": "Procfile",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    assert "AWS-provided CNAME target" in payload["cloudflare_dns"]["record_value"]
    assert [step["id"] for step in payload["operator_setup"]["steps"]] == [
        "deploy_aws_python_wsgi_origin",
        "deploy_worker_dispatch_receiver",
        "configure_worker_dispatch_url",
        "attach_aws_https_origin",
        "route_cloudflare_cname",
        "verify_public_contracts",
    ]
    provenance = payload["source_provenance"]
    assert provenance["provider"] == "aws-elastic-beanstalk"
    assert provenance["source"] == "fusekit_hosted_environment_variables"
    assert provenance["verified"] is True
    assert provenance["actual"] == {
        "deployment_environment": "production",
        "deployment_url": "https://fusekit-prod.us-east-1.elasticbeanstalk.com",
        "git_provider": "github",
        "repo_owner": "Fusekit-AI",
        "repo_slug": "fusekit",
        "commit_ref": "main",
        "commit_sha": VERCEL_COMMIT_SHA,
    }
    assert provenance["required_env"] == list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    assert payload["required_source_provenance_env"] == list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    assert "AWS credentials" in provenance["secret_boundary"]
    assert "AWS credentials" in payload["operator_setup"]["secret_boundary"]
    assert "PRIVATE KEY" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_deployment_endpoint_supports_oci_compute_origin_without_secrets() -> None:
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        **_oci_provenance_kwargs(),
    )

    status, _headers, body = _call("/api/hosted/deployment", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["runtime"] == {
        "provider": "oci-compute",
        "entrypoint": "app.py",
        "process_config": "systemd:fusekit-hosted.service",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi-on-oci-compute",
    }
    assert payload["cloudflare_dns"]["record_type"] == "A"
    assert "OCI reserved public IP address" in payload["cloudflare_dns"]["record_value"]
    assert [step["id"] for step in payload["operator_setup"]["steps"]] == [
        "deploy_oci_python_wsgi_origin",
        "deploy_worker_dispatch_receiver",
        "configure_worker_dispatch_url",
        "attach_oci_https_origin",
        "route_cloudflare_a_record",
        "verify_public_contracts",
    ]
    provenance = payload["source_provenance"]
    assert provenance["provider"] == "oci-compute"
    assert provenance["source"] == "fusekit_hosted_environment_variables"
    assert provenance["verified"] is True
    assert provenance["actual"]["deployment_url"] == "https://fusekit.snowmanai.org"
    assert provenance["required_env"] == list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    assert payload["required_source_provenance_env"] == list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    assert "OCI credentials" in provenance["secret_boundary"]
    assert "PRIVATE KEY" not in serialized
    assert STATE_SECRET not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_deployment_contract_normalizes_worker_dispatch_receiver_checks() -> None:
    settings = HostedSettings(worker_dispatch_url="https://worker.snowmanai.org/dispatch")

    status, _headers, body = _call("/api/hosted/deployment", settings=settings)
    payload = json.loads(body.decode("utf-8"))

    assert status == "200 OK"
    assert payload["worker_dispatch"]["checks"] == {
        "dispatch": "https://worker.snowmanai.org/dispatch",
        "health": "https://worker.snowmanai.org/healthz",
        "readiness": "https://worker.snowmanai.org/readiness",
    }


def test_hosted_source_provenance_requires_expected_production_git_metadata() -> None:
    settings = HostedSettings(
        vercel_env="preview",
        vercel_git_provider="github",
        vercel_git_repo_owner="Fusekit-AI",
        vercel_git_repo_slug="fusekit",
        vercel_git_commit_ref="main",
        vercel_git_commit_sha="not-a-sha",
    )

    provenance = settings.source_provenance()

    assert provenance["verified"] is False
    assert provenance["actual"] == {
        "deployment_environment": "preview",
        "deployment_url": "",
        "git_provider": "github",
        "repo_owner": "Fusekit-AI",
        "repo_slug": "fusekit",
        "commit_ref": "main",
        "commit_sha": "not-a-sha",
    }


def test_hosted_source_provenance_requires_vercel_deployment_url() -> None:
    settings = HostedSettings(
        vercel_env="production",
        vercel_url="fusekit.snowmanai.org",
        vercel_git_provider="github",
        vercel_git_repo_owner="Fusekit-AI",
        vercel_git_repo_slug="fusekit",
        vercel_git_commit_ref="main",
        vercel_git_commit_sha=VERCEL_COMMIT_SHA,
    )

    provenance = settings.source_provenance()

    assert provenance["provider"] == "vercel"
    assert provenance["verified"] is False


def test_hosted_aws_source_provenance_requires_expected_public_git_metadata() -> None:
    settings = HostedSettings(
        deployment_provider="aws-elastic-beanstalk",
        aws_deployment_env="staging",
        aws_deployment_url="not-a-url",
        aws_git_provider="github",
        aws_git_repo_owner="Fusekit-AI",
        aws_git_repo_slug="fusekit",
        aws_git_commit_ref="main",
        aws_git_commit_sha="not-a-sha",
    )

    provenance = settings.source_provenance()

    assert provenance["provider"] == "aws-elastic-beanstalk"
    assert provenance["verified"] is False
    assert provenance["actual"] == {
        "deployment_environment": "staging",
        "deployment_url": "not-a-url",
        "git_provider": "github",
        "repo_owner": "Fusekit-AI",
        "repo_slug": "fusekit",
        "commit_ref": "main",
        "commit_sha": "not-a-sha",
    }


def test_hosted_aws_source_provenance_requires_elastic_beanstalk_origin() -> None:
    settings = HostedSettings(
        deployment_provider="aws-elastic-beanstalk",
        aws_deployment_env="production",
        aws_deployment_url="https://fusekit.snowmanai.org",
        aws_git_provider="github",
        aws_git_repo_owner="Fusekit-AI",
        aws_git_repo_slug="fusekit",
        aws_git_commit_ref="main",
        aws_git_commit_sha=VERCEL_COMMIT_SHA,
    )

    provenance = settings.source_provenance()

    assert provenance["provider"] == "aws-elastic-beanstalk"
    assert provenance["verified"] is False


def test_hosted_readiness_endpoint_rejects_invalid_config_shape_without_values() -> None:
    settings = HostedSettings(
        public_origin="http://snowmanai.org/path",
        github_app_id="not-a-number",
        github_app_slug="bad/slug",
        github_private_key_pem=FAKE_PRIVATE_KEY,
        state_secret="abc123",
        worker_secret="abc123",
        worker_dispatch_url="http://worker.invalid/dispatch",
    )

    status, _headers, body = _call("/api/hosted/readiness", settings=settings)
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "200 OK"
    assert payload["ready"] is False
    assert payload["missing"] == []
    assert payload["invalid"] == [
        "hosted_origin_must_be_https_origin",
        "hosted_worker_dispatch_url_must_be_https",
        "hosted_deployment_provider_required",
        "github_app_id_must_be_positive_integer",
        "github_app_slug_is_invalid",
        "github_app_private_key_must_be_rsa_pem",
        "hosted_state_secret_too_short",
        "hosted_worker_secret_too_short",
        "source_provenance_not_verified",
    ]
    assert payload["blocking_checks"] == [
        "invalid:hosted_origin_must_be_https_origin",
        "invalid:hosted_worker_dispatch_url_must_be_https",
        "invalid:hosted_deployment_provider_required",
        "invalid:github_app_id_must_be_positive_integer",
        "invalid:github_app_slug_is_invalid",
        "invalid:github_app_private_key_must_be_rsa_pem",
        "invalid:hosted_state_secret_too_short",
        "invalid:hosted_worker_secret_too_short",
        "invalid:source_provenance_not_verified",
    ]
    assert payload["next_actions"] == [
        "Use an HTTPS origin with no path, query, credentials, or fragment.",
        "Use an HTTPS worker dispatch URL with no credentials in the URL.",
        (
            "Set FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER to oci-compute, "
            "aws-elastic-beanstalk, or vercel before relying on provider-specific "
            "setup instructions."
        ),
        "Use a positive numeric GitHub App id.",
        "Use the GitHub App slug exactly as GitHub provides it.",
        "Store a valid RSA PEM private key for the GitHub App.",
        "Use at least 16 characters for the hosted state secret.",
        "Use at least 16 characters for the worker secret.",
        (
            "Publish hosted source provenance for Fusekit-AI/fusekit from the "
            "deployment runtime so the public source provenance verifies."
        ),
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


def test_hosted_deployment_files_route_all_paths_to_wsgi_entrypoint() -> None:
    root = Path(__file__).parents[1]
    vercel = json.loads((root / "vercel.json").read_text(encoding="utf-8"))
    procfile = (root / "Procfile").read_text(encoding="utf-8").strip()
    requirements = (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
    python_version = (root / ".python-version").read_text(encoding="utf-8").strip()

    assert vercel["builds"] == [{"src": "app.py", "use": "@vercel/python"}]
    assert vercel["routes"] == [{"src": "/(.*)", "dest": "app.py"}]
    assert procfile == "web: gunicorn app:app --bind 0.0.0.0:$PORT"
    assert python_version == "3.12"
    assert "cryptography>=48.0.1,<49" in requirements
    assert "gunicorn>=23" in requirements
    assert "PyYAML>=6" in requirements
    assert not any("playwright" in line.lower() for line in requirements)
    assert not any(line.startswith("oci") for line in requirements)


def test_hosted_github_intake_endpoint_is_public_safe() -> None:
    status, _headers, body = _call("/api/github/intake")
    payload = json.loads(body.decode("utf-8"))

    assert status == "200 OK"
    assert payload["provider"] == "github"
    assert payload["route"] == "github-app"
    assert payload["install_url"] == (
        "https://github.com/apps/fusekit-launcher/installations/new"
    )
    assert payload["trust_story"] == [
        "open core",
        "narrow permissions",
        "visible plan",
        "redacted proof",
        "reversible setup",
    ]
    assert payload["no_terminal_promise"].startswith("No terminal")
    assert payload["launch_path"][0] == "Visit the hosted FuseKit URL."
    assert payload["launch_path"][-1] == (
        "Receive the live URL, redacted proof receipt, rollback metadata, and detonation receipt."
    )
    assert payload["plain_language_journey"] == list(HOSTED_PLAIN_LANGUAGE_JOURNEY)
    assert payload["prohibited"] == list(HOSTED_PROHIBITED_ACTIONS)
    assert "Run Record" in payload["proof"]
    assert "Detonation receipt" in payload["proof"]
    assert payload["proof_evidence_keys"] == [
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "rollback_metadata",
        "retrieved_remote_artifacts",
        "run_record",
        "detonation_receipt",
        "live_acceptance_report",
        "recording",
    ]
    assert any("revoke access" in item for item in payload["reversal"])
    assert payload["open_core"] == {
        "source_repository": "https://github.com/Fusekit-AI/fusekit",
        "license": "MIT",
        "reviewable_entrypoint": "app.py",
    }
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


def test_hosted_github_repositories_rejects_broad_installation_token() -> None:
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
                "permissions": {"contents": "read", "secrets": "write"},
                "repository_selection": "selected",
            },
        ]
    )

    status, _headers, body = _call(
        "/github/repositories",
        query_string=f"installation_id=42&state={state}",
        settings=_settings_with_github(opener),
    )

    assert status == "502 Bad Gateway"
    assert json.loads(body.decode("utf-8")) == {"error": "github_repository_intake_failed"}
    assert len(opener.requests) == 1
    assert "ghs_fake" not in body.decode("utf-8")


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
    assert "Launch path" in text
    assert "Review the visible plan and approved action ids before worker start." in text
    assert "Receive the live URL, redacted proof receipt" in text
    assert "What FuseKit will not do" in text
    assert "Do not bypass MFA, CAPTCHA, passkeys, billing, fraud, consent, or domain gates." in text
    assert "Do not mutate DNS or paid provider resources without explicit visible approval." in text
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
    assert "Approved plan integrity" in text
    assert "sha256:" in text
    assert "fresh visible plan before execution" in text
    assert "Permission boundary" in text
    assert "contents:read" in text
    assert "Approved actions" in text
    assert "vercel.deploy_verify" in text
    assert "Provider gates" in text
    assert "human-owned" in text
    assert "Stop launch" in text
    assert "Request rollback" in text
    assert "GitHub App installation" in text
    assert "View proof receipt" in text
    assert "Run Record" in text
    assert ".fusekit/workspace_detonation.json" in text
    assert "Detonation" in text
    assert "ghs_fake" not in text
    assert "PRIVATE KEY" not in text


def test_hosted_plan_renders_managed_and_byo_launch_lanes() -> None:
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
    text = body.decode("utf-8")

    assert status == "200 OK"
    assert "Managed FuseKit run" in text
    assert "Bring your own OCI" in text
    assert f"lane={MANAGED_FUSEKIT_RUN_LANE}" in text
    assert f"lane={BYO_OCI_LANE}" in text
    assert "their tenancy" in text
    assert "ghs_fake" not in text


def test_hosted_plan_disables_managed_lane_until_payment_is_configured() -> None:
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
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=opener,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/plan",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    text = body.decode("utf-8")

    assert status == "200 OK"
    assert "Managed FuseKit run" in text
    assert (
        "Set FUSEKIT_MANAGED_RUNS_ENABLED=1 only after live Stripe Checkout proof "
        "and worker-dispatch acceptance pass."
    ) in text
    assert f"lane={MANAGED_FUSEKIT_RUN_LANE}" not in text
    assert f"lane={BYO_OCI_LANE}" in text
    assert "Bring your own OCI" in text
    assert "ghs_fake" not in text


def test_hosted_control_room_rejects_unlaunchable_managed_lane_before_github_work() -> None:
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
            }
        ]
    )
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=opener,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=(
            f"installation_id=42&repo=example/one&state={state}"
            f"&lane={MANAGED_FUSEKIT_RUN_LANE}"
        ),
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(payload)

    assert status == "409 Conflict"
    assert payload["error"] == "lane_not_launchable"
    assert payload["lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["recommended_lane"] == BYO_OCI_LANE
    assert payload["launchable_lanes"] == [BYO_OCI_LANE]
    assert payload["blocking_checks"] == [
        "managed_runs_not_enabled",
        "stripe_secret_key_required_for_managed_runs",
        "stripe_price_id_required_for_managed_runs",
        "managed_run_price_label_required",
    ]
    assert payload["next_actions"] == [
        (
            "Set FUSEKIT_MANAGED_RUNS_ENABLED=1 only after live Stripe Checkout proof "
            "and worker-dispatch acceptance pass."
        ),
        (
            "Store a live FUSEKIT_STRIPE_SECRET_KEY only in the hosted runtime secret "
            "file before enabling managed paid runs."
        ),
        (
            "Run fusekit-hosted-stripe-price --execute --confirm-shared-account to "
            "create a FuseKit-scoped Stripe Price, then set FUSEKIT_STRIPE_PRICE_ID."
        ),
        (
            "Use the fusekit-hosted-stripe-price output to set "
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL to the public price shown before Checkout."
        ),
    ]
    assert opener.requests == []
    assert settings.hosted_jobs == {}
    assert "ghs_fake" not in serialized


def test_hosted_managed_lane_requires_stripe_payment_before_worker_dispatch() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    github_opener = SequenceOpener(
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
    dispatch_opener = SequenceOpener([{}])
    stripe_opener = FormSequenceOpener(
        [
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.com/c/pay/cs_test_123",
                "status": "open",
                "payment_status": "unpaid",
                "mode": "payment",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "hosted-other-job",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {
                    "job_id": "hosted-other-job",
                    "lane": MANAGED_FUSEKIT_RUN_LANE,
                    "plan_fingerprint": (
                        "sha256:"
                        "0000000000000000000000000000000000000000000000000000000000000000"
                    ),
                },
            },
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "mode": "setup",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
        ]
    )
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=github_opener,
        worker_dispatch_opener=dispatch_opener,
        stripe_opener=stripe_opener,
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=(
            f"installation_id=42&repo=example/one&state={state}"
            f"&lane={MANAGED_FUSEKIT_RUN_LANE}"
        ),
        settings=settings,
    )
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    github_source_hash = _payment_source_hash(settings.hosted_jobs[job_id].github_source)
    plan_fingerprint = settings.hosted_jobs[job_id].worker_contract.plan_fingerprint
    price_id_hash = _payment_public_hash("price_managed_run")
    price_label_hash = _payment_public_hash(MANAGED_PRICE_LABEL)
    stripe_opener.payloads[0]["client_reference_id"] = job_id
    stripe_opener.payloads[0]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": github_source_hash,
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": price_id_hash,
        "price_label_hash": price_label_hash,
    }
    stripe_opener.payloads[1]["client_reference_id"] = job_id
    stripe_opener.payloads[1]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": "sha256:wrong-source",
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": price_id_hash,
        "price_label_hash": price_label_hash,
    }
    stripe_opener.payloads[2]["client_reference_id"] = job_id
    stripe_opener.payloads[2]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": github_source_hash,
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": "sha256:" + ("d" * 64),
        "price_label_hash": "sha256:" + ("e" * 64),
    }
    stripe_opener.payloads[3]["client_reference_id"] = job_id
    stripe_opener.payloads[3]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": github_source_hash,
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": price_id_hash,
        "price_label_hash": price_label_hash,
    }
    stripe_opener.payloads[4]["client_reference_id"] = job_id
    stripe_opener.payloads[4]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": github_source_hash,
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": price_id_hash,
    }
    stripe_opener.payloads[5]["client_reference_id"] = job_id
    stripe_opener.payloads[5]["metadata"] = {
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "github_source_hash": github_source_hash,
        "plan_fingerprint": plan_fingerprint,
        "stripe_price_id_hash": price_id_hash,
        "price_label_hash": price_label_hash,
    }
    job_token = _job_token(text)
    checkout_control = _control_for_payment_checkout(text)
    start_control = create_hosted_state_token(
        STATE_SECRET,
        return_path=f"/api/hosted/jobs/{job_id}/actions/start",
        nonce="nonce-for-blocked-managed-start",
    )

    assert status == "200 OK"
    assert "Authorize managed run payment" in text
    assert "Start worker" not in text

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": start_control},
        settings=settings,
    )
    blocked = json.loads(body.decode("utf-8"))
    assert status == "402 Payment Required"
    assert blocked["error"] == "payment_required"
    assert blocked["payment"]["status"] == "payment_required"
    assert blocked["payment"]["price_label"] == MANAGED_PRICE_LABEL
    assert blocked["checkout_path"] == f"/api/hosted/jobs/{job_id}/payments/checkout"
    assert "Stripe Checkout authorization" in blocked["secret_boundary"]
    assert "payment method ids" in blocked["secret_boundary"]
    blocked_text = json.dumps(blocked)
    assert "sk_live" not in blocked_text
    assert "client_secret" not in blocked_text
    assert len(dispatch_opener.requests) == 0

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/checkout",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": checkout_control},
        settings=settings,
    )
    checkout = json.loads(body.decode("utf-8"))
    checkout_job_token = checkout["job_token"]
    assert status == "200 OK"
    assert checkout["payment"]["status"] == "checkout_pending"
    assert checkout["payment"]["price_label"] == MANAGED_PRICE_LABEL
    assert checkout["payment"]["receipt"]["price_label"] == MANAGED_PRICE_LABEL
    assert checkout["payment"]["receipt"]["checkout_url"] == (
        "https://checkout.stripe.com/c/pay/cs_test_123"
    )
    assert "Stripe secret keys" in checkout["payment"]["receipt"]["secret_boundary"]
    assert "payment method ids" in checkout["payment"]["receipt"]["secret_boundary"]
    assert stripe_opener.bodies[0]["mode"] == ["payment"]
    assert stripe_opener.bodies[0]["line_items[0][price]"] == ["price_managed_run"]
    assert stripe_opener.bodies[0]["metadata[job_id]"] == [job_id]
    assert stripe_opener.bodies[0]["metadata[lane]"] == [MANAGED_FUSEKIT_RUN_LANE]
    assert stripe_opener.bodies[0]["metadata[github_source_hash]"] == [github_source_hash]
    assert stripe_opener.bodies[0]["metadata[plan_fingerprint]"] == [plan_fingerprint]
    assert stripe_opener.bodies[0]["metadata[stripe_price_id_hash]"] == [price_id_hash]
    assert stripe_opener.bodies[0]["metadata[price_label_hash]"] == [price_label_hash]
    assert "sk_live" not in json.dumps(checkout)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/stripe-return",
        query_string=f"job={checkout_job_token}&session_id=cs_test_123",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "payment_binding_mismatch"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/stripe-return",
        query_string=f"job={checkout_job_token}&session_id=cs_test_123",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "payment_binding_mismatch"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/stripe-return",
        query_string=f"job={checkout_job_token}&session_id=cs_test_123",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "payment_binding_mismatch"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/stripe-return",
        query_string=f"job={checkout_job_token}&session_id=cs_test_123",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "payment_binding_mismatch"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/stripe-return",
        query_string=f"job={checkout_job_token}&session_id=cs_test_123",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    paid_text = body.decode("utf-8")
    paid_job_token = _job_token(paid_text)
    paid_start_control = _control_for_action(paid_text, "start")
    assert status == "200 OK"
    assert "Stripe Checkout authorization verified" in paid_text
    assert "Payment return receipts expose only Stripe Checkout authorization" in paid_text
    assert MANAGED_PRICE_LABEL in paid_text
    assert "Start worker" in paid_text
    assert "sk_live" not in paid_text
    assert "client_secret" not in paid_text

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={paid_job_token}",
        form_body={"control": paid_start_control},
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    serialized = json.dumps(started)
    assert status == "200 OK"
    assert started["status"] == "waiting_for_provider_gates"
    assert started["payment"]["status"] == "paid"
    assert started["payment"]["price_label"] == MANAGED_PRICE_LABEL
    assert started["payment"]["receipt"]["price_label"] == MANAGED_PRICE_LABEL
    assert started["worker_dispatch"]["dispatched"] is True
    assert started["worker_dispatch"]["dispatch_binding"] == {
        "action": "start",
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "payment_status": "paid",
        "plan_fingerprint": plan_fingerprint,
        "price_label_hash": price_label_hash,
    }
    assert len(dispatch_opener.requests) == 1
    assert "sk_live" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_payment_checkout_rejects_missing_checkout_url_before_pending_state() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    github_opener = SequenceOpener(
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
    stripe_opener = FormSequenceOpener(
        [
            {
                "id": "cs_test_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.com/not-a-pay-session",
                "status": "open",
                "payment_status": "unpaid",
                "mode": "payment",
                "client_reference_id": "",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {},
            },
        ]
    )
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=github_opener,
        stripe_opener=stripe_opener,
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=(
            f"installation_id=42&repo=example/one&state={state}"
            f"&lane={MANAGED_FUSEKIT_RUN_LANE}"
        ),
        settings=settings,
    )
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    checkout_control = _control_for_payment_checkout(text)
    job_token = _job_token(text)

    assert status == "200 OK"
    assert settings.hosted_jobs[job_id].payment_status == "payment_required"

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/payments/checkout",
        method="POST",
        query_string=f"job={job_token}",
        headers={"Accept": "text/html"},
        form_body={"control": checkout_control},
        settings=settings,
    )

    assert status == "502 Bad Gateway"
    assert json.loads(body.decode("utf-8")) == {"error": "payment_checkout_url_unavailable"}
    assert "Location" not in headers
    assert settings.hosted_jobs[job_id].payment_status == "payment_required"
    assert len(stripe_opener.requests) == 1


def test_hosted_byo_oci_lane_starts_without_managed_worker_dispatch() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    github_opener = SequenceOpener(
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
    dispatch_opener = SequenceOpener([{}])
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id="12345",
        github_app_slug="fusekit-launcher",
        github_private_key_pem=_private_key_pem(),
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=github_opener,
        worker_dispatch_opener=dispatch_opener,
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}&lane={BYO_OCI_LANE}",
        settings=settings,
    )
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    job_token = _job_token(text)
    control = _control_for_action(text, "start")
    assert status == "200 OK"
    assert "Bring your own OCI" in text

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert started["worker_contract"]["lane"] == BYO_OCI_LANE
    assert started["worker_dispatch"]["dispatched"] is False
    assert started["worker_dispatch"]["reason"] == "byo_oci_user_owned_worker_lane"
    assert len(dispatch_opener.requests) == 0

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/byo-oci-bootstrap",
        query_string=f"job={started['job_token']}",
        settings=settings,
    )
    bootstrap = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert bootstrap["schema_version"] == "fusekit.hosted-byo-oci-bootstrap.v1"
    assert bootstrap["lane"] == BYO_OCI_LANE
    assert bootstrap["worker_dispatch"] == "not_applicable_user_owned_oci"
    assert bootstrap["runner_shape_policy"] == "AMD/x86_64 only; ARM images are not allowed."
    assert bootstrap["runner_profile"] == {
        "provider": "oracle-cloud-infrastructure",
        "runner": "oci-existing",
        "shape": "VM.Standard.E5.Flex",
        "shape_family": "standard-e5",
        "architecture": "amd64/x86_64",
        "arm_allowed": False,
        "visual_runner": "novnc",
    }
    assert bootstrap["open_core_execution"] == {
        "mode": "user-owned-oci-cloud-shell",
        "fusekit_package": "fusekit",
        "app_source": "https://github.com/example/one",
        "github_source_policy": (
            "Cloud Shell fetches the selected GitHub source through FuseKit source "
            "handoff. Private source access is approved by the user inside provider-owned "
            "GitHub gates, not by exposing hosted GitHub installation tokens."
        ),
        "worker_secret_required": False,
        "hosted_github_private_key_required": False,
    }
    assert bootstrap["user_owned_cost_boundary"] == {
        "spend_owner": "user_oci_tenancy",
        "fusekit_managed_infrastructure_spend": False,
        "payment_required_by_fusekit": False,
        "billing_gate_owner": "oracle_cloud",
        "review_before_run": [
            "Oracle Cloud account billing status",
            "selected region capacity",
            "AMD/x86_64 disposable worker shape",
            "resources created by the user's Cloud Shell session",
        ],
        "statement": (
            "BYO OCI launches run in the user's Oracle Cloud tenancy. FuseKit does not "
            "charge a managed-run fee and does not dispatch FuseKit-owned workers for "
            "this lane."
        ),
    }
    assert bootstrap["byo_security_contract"] == {
        "managed_worker_dispatch_allowed": False,
        "hosted_worker_secret_exported": False,
        "hosted_github_private_key_exported": False,
        "hosted_github_installation_token_exported": False,
        "raw_provider_secrets_exported": False,
        "runner_architecture": "amd_x86_64_only",
        "runner_profile": {
            "provider": "oracle-cloud-infrastructure",
            "runner": "oci-existing",
            "shape": "VM.Standard.E5.Flex",
            "shape_family": "standard-e5",
            "architecture": "amd64/x86_64",
            "arm_allowed": False,
            "visual_runner": "novnc",
        },
        "human_gate_bypass_allowed": False,
        "completion_claim_requires": [
            "live_url",
            "provider_verifiers",
            "dns_propagation",
            "rollback_metadata",
            "retrieved_remote_artifacts",
            "run_record",
            "detonation_receipt",
            "live_acceptance_report",
            "recording",
        ],
    }
    assert bootstrap["handoff_preflight"] == {
        "schema_version": HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION,
        "must_be_visible_before_cloud_shell": True,
        "checks": [dict(check) for check in HOSTED_BYO_OCI_HANDOFF_PREFLIGHT],
        "cost_acknowledgement": {
            "required": True,
            "spend_owner": "user_oci_tenancy",
            "fusekit_fee": "none_for_byo_oci",
            "oracle_billing_gate_owner": "oracle_cloud",
            "statement": (
                "Starting BYO OCI can create Oracle Cloud resources in the user's tenancy; "
                "FuseKit-managed infrastructure spend remains zero."
            ),
        },
        "secret_boundary": (
            "BYO preflight contains public review labels only. It does not contain OCI "
            "credentials, payment methods, GitHub installation tokens, or vault material."
        ),
    }
    cloud_shell = bootstrap["cloud_shell"]
    command = cloud_shell["bootstrap_command"]
    assert cloud_shell["deeplink_url"] == "https://cloud.oracle.com/?cloudshell=true"
    assert "fusekit launch" in command
    assert "--runner oci-existing" in command
    assert f"--oci-shape {bootstrap['runner_profile']['shape']}" in command
    assert "aarch64" not in command
    assert "Ampere" not in command
    assert "--visual-runner novnc" in command
    assert "--github-repo example/one" in command
    assert "--require-recording" not in command
    assert "fusekit-hosted-worker" not in command
    assert bootstrap["proof_return"]["mode"] == "user_downloads_or_shares_redacted_artifacts"
    assert bootstrap["proof_manifest"]["schema_version"] == (
        HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION
    )
    assert bootstrap["proof_manifest"]["proof_bundle_root"] == ".fusekit/remote-artifacts"
    assert bootstrap["proof_manifest"]["acceptance_gate"] == {
        "mode": "live",
        "remote_artifacts": ".fusekit/remote-artifacts",
        "require_recording": True,
        "command": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
    }
    assert {
        (artifact["path"], artifact["label"])
        for artifact in bootstrap["proof_manifest"]["required_remote_artifacts"]
    } >= {
        (".fusekit/run_record.json", "central Run Record"),
        (".fusekit/rollback_plan.json", "rollback metadata"),
        (".fusekit/workspace_detonation.json", "workspace detonation receipt"),
        (".fusekit/acceptance_report.json", "live acceptance report"),
    }
    assert bootstrap["reversibility"] == {
        "schema_version": HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION,
        "detonation_required": True,
        "rollback_metadata_required": True,
        "delete_targets": list(HOSTED_BYO_OCI_REVERSIBILITY_TARGETS),
        "survivors": list(HOSTED_BYO_OCI_REVERSIBILITY_SURVIVORS),
        "completion_receipt": ".fusekit/workspace_detonation.json",
        "post_run_acceptance_required": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
        "statement": (
            "A BYO OCI run is not considered complete until reversible setup proof, "
            "retrieved redacted artifacts, and workspace detonation proof are present."
        ),
    }
    serialized = json.dumps(bootstrap)
    assert "ghs_fake" not in serialized
    assert WORKER_SECRET not in serialized
    assert "PRIVATE KEY" not in serialized

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/byo-oci-bootstrap",
        query_string=f"job={started['job_token']}",
        headers={"Accept": "text/html,application/xhtml+xml"},
        settings=settings,
    )
    html = body.decode("utf-8")
    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "BYO OCI handoff." in html
    assert "Open Oracle Cloud Shell" in html
    assert "Review Oracle Cloud billing status" in html
    assert "FuseKit fee: none_for_byo_oci" in html
    assert "workspace detonation proof" in html
    assert "Proof Manifest" in html
    assert "central Run Record" in html
    assert "live acceptance report" in html
    assert "Download bootstrap JSON" in html
    assert "--oci-shape VM.Standard.E5.Flex" in html
    assert "ghs_fake" not in html
    assert WORKER_SECRET not in html
    assert "PRIVATE KEY" not in html

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/byo-oci-bootstrap",
        query_string=f"job={started['job_token']}&format=json",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    json_payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert json_payload["schema_version"] == "fusekit.hosted-byo-oci-bootstrap.v1"


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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        query_string=f"job={job_token}",
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_worker"
    assert payload["worker_contract"]["required_artifacts"]
    assert payload["worker_contract"]["github_installation_id"] == 42
    plan_integrity = payload["worker_contract"]["plan_integrity"]
    assert plan_integrity["algorithm"] == "sha256"
    assert str(plan_integrity["fingerprint"]).startswith("sha256:")
    assert "approved_actions" in plan_integrity["covers"]
    assert ".fusekit/run_record.json" in payload["worker_contract"]["required_artifacts"]
    assert "ghs_fake" not in json.dumps(payload)

    settings = replace(settings, worker_dispatch_url="")
    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    steps = {step["id"]: step for step in payload["steps"]}
    assert status == "200 OK"
    assert payload["status"] == "waiting_for_provider_gates"
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["action_receipt"]["schema_version"] == "fusekit.hosted-job-action-receipt.v1"
    assert payload["action_receipt"]["action"] == "start"
    assert payload["action_receipt"]["plan_integrity"] == payload["worker_contract"][
        "plan_integrity"
    ]
    assert "worker_claim" in payload["action_receipt"]["next_required_proof"]
    assert "detonation_receipt" in payload["action_receipt"]["next_required_proof"]
    assert "recording" in payload["action_receipt"]["next_required_proof"]
    assert payload["worker_dispatch"]["dispatched"] is False
    assert payload["worker_dispatch"]["reason"] == "worker_dispatch_url_not_configured"
    assert "omits job tokens" in payload["worker_dispatch"]["secret_boundary"]
    assert "worker secrets" in payload["worker_dispatch"]["secret_boundary"]
    assert steps["provider.gates"]["status"] == "waiting"
    assert "ghs_fake" not in json.dumps(payload)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/rollback",
        method="POST",
        query_string=f"job={payload['job_token']}",
        form_body={"control": control},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_provider_gates"

    rollback_control = create_hosted_state_token(
        STATE_SECRET,
        return_path=f"/api/hosted/jobs/{job_id}/actions/rollback",
        nonce="nonce-for-rollback-control-token",
    )
    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/rollback",
        method="POST",
        query_string=f"job={payload['job_token']}",
        form_body={"control": rollback_control},
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    assert status == "200 OK"
    assert payload["status"] == "rollback_requested"
    assert payload["action_receipt"]["action"] == "rollback"
    assert payload["action_receipt"]["plan_integrity"]["fingerprint"] == plan_integrity[
        "fingerprint"
    ]
    assert "rollback_execution_receipt" in payload["action_receipt"]["next_required_proof"]
    assert "ghs_fake" not in json.dumps(payload)


def test_hosted_job_api_requires_signed_job_token_even_with_process_memory() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_job"}

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        form_body={"control": control},
        settings=settings,
    )
    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_job"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_can_stop_before_worker_start() -> None:
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
    job_token = _job_token(text)
    control = _control_for_action(text, "stop")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/stop",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))
    steps = {step["id"]: step for step in payload["steps"]}

    assert status == "200 OK"
    assert payload["status"] == "stopped"
    assert payload["action_receipt"]["action"] == "stop"
    assert "no_worker_claim_after_stop" in payload["action_receipt"]["next_required_proof"]
    assert "stopped before hosted worker start" in steps["worker.prepare"]["proof"]

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-request",
        query_string=f"job={payload['job_token']}",
        settings=settings,
    )
    assert status == "409 Conflict"
    assert json.loads(body.decode("utf-8")) == {"error": "worker_not_started"}
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
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
        query_string=f"job={job_token}",
        form_body={"control": control},
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
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
    assert "Permission boundary" in text
    assert "Approved actions" in text
    assert "Provider gates" in text
    assert "Request rollback" in text
    assert "Request detonation" in text
    assert "Latest protected action: start" in text
    assert "Next proof required" in text
    assert "Worker dispatch: accepted" in text
    assert "View worker request" in text
    assert "job=" in text
    assert payload["status"] == "waiting_for_provider_gates"
    assert payload["worker_contract"]["permission_boundary"]
    assert payload["worker_contract"]["approved_actions"]
    assert payload["worker_contract"]["gates"]
    assert payload["latest_action_receipt"]["schema_version"] == (
        "fusekit.hosted-job-action-receipt.v1"
    )
    assert payload["latest_action_receipt"]["action"] == "start"
    assert payload["worker_dispatch"]["dispatched"] is True
    assert payload["worker_dispatch"]["dispatch_url"] == "https://worker.snowmanai.org/dispatch"
    assert "ghs_fake" not in text


def test_hosted_job_start_dispatches_signed_worker_envelope_when_configured() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    github_opener = SequenceOpener(
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
    dispatch_opener = SequenceOpener([{}])
    config = GitHubAppConfig(
        app_id="12345",
        app_slug="fusekit-launcher",
        private_key_pem=_private_key_pem(),
    )
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id=config.app_id,
        github_app_slug=config.app_slug,
        github_private_key_pem=config.private_key_pem,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=github_opener,
        worker_dispatch_opener=dispatch_opener,
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    response = json.loads(body.decode("utf-8"))
    dispatch_body = dispatch_opener.bodies[0]
    serialized = json.dumps(response) + json.dumps(dispatch_body)

    assert status == "200 OK"
    assert response["status"] == "waiting_for_provider_gates"
    expected_binding = {
        "action": "start",
        "job_id": job_id,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "payment_status": "paid",
        "plan_fingerprint": response["worker_contract"]["plan_integrity"]["fingerprint"],
        "price_label_hash": _payment_public_hash(MANAGED_PRICE_LABEL),
    }
    assert response["worker_dispatch"] == {
        "schema_version": "fusekit.hosted-worker-dispatch.v1",
        "action": "start",
        "dispatch_binding": expected_binding,
        "dispatched": True,
        "dispatch_url": "https://worker.snowmanai.org/dispatch",
        "secret_boundary": (
            "Dispatch receipt omits the job token, worker secret, signature, provider "
            "tokens, and vault material."
        ),
    }
    assert dispatch_body["schema_version"] == "fusekit.hosted-worker-dispatch.v1"
    assert dispatch_body["action"] == "start"
    assert dispatch_body["origin"] == "https://fusekit.snowmanai.org"
    assert dispatch_body["job_id"] == job_id
    assert dispatch_body["job_token"] == response["job_token"]
    assert dispatch_body["dispatch_binding"] == expected_binding
    assert dispatch_body["worker_command"] == [
        "fusekit-hosted-worker",
        "--origin",
        "https://fusekit.snowmanai.org",
        "--job-id",
        job_id,
        "--job-token",
        "<signed-public-job-token>",
        "--action",
        "start",
    ]
    assert dispatch_opener.requests[0].full_url == "https://worker.snowmanai.org/dispatch"
    assert dispatch_opener.requests[0].headers["X-fusekit-dispatch-schema"] == (
        "fusekit.hosted-worker-dispatch.v1"
    )
    assert dispatch_opener.requests[0].headers["X-fusekit-dispatch-signature"].startswith(
        "sha256="
    )
    assert WORKER_SECRET not in serialized
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_job_actions_reject_duplicate_start_without_second_dispatch() -> None:
    state = create_hosted_state_token(
        STATE_SECRET,
        return_path="/",
        nonce="nonce-for-hosted-state",
    )
    github_opener = SequenceOpener(
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
    dispatch_opener = SequenceOpener([{}, {}])
    config = GitHubAppConfig(
        app_id="12345",
        app_slug="fusekit-launcher",
        private_key_pem=_private_key_pem(),
    )
    settings = HostedSettings(
        public_origin="https://fusekit.snowmanai.org",
        github_app_id=config.app_id,
        github_app_slug=config.app_slug,
        github_private_key_pem=config.private_key_pem,
        state_secret=STATE_SECRET,
        worker_secret=WORKER_SECRET,
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        github_opener=github_opener,
        worker_dispatch_opener=dispatch_opener,
        managed_runs_enabled=True,
        stripe_secret_key="sk_live_redacted",
        stripe_price_id="price_managed_run",
        managed_run_price_label=MANAGED_PRICE_LABEL,
        **_vercel_provenance_kwargs(),
    )

    status, _headers, body = _call(
        "/github/control-room",
        query_string=f"installation_id=42&repo=example/one&state={state}",
        settings=settings,
    )
    assert status == "200 OK"
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, _body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    assert status == "200 OK"

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_action"}
    assert len(dispatch_opener.requests) == 1


def test_hosted_job_actions_reject_rollback_and_detonation_before_start() -> None:
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
    job_token = _job_token(text)

    for action in ("rollback", "detonate"):
        control = create_hosted_state_token(
            STATE_SECRET,
            return_path=f"/api/hosted/jobs/{job_id}/actions/{action}",
            nonce=f"nonce-for-{action}-control-token",
        )
        status, _headers, body = _call(
            f"/api/hosted/jobs/{job_id}/actions/{action}",
            method="POST",
            query_string=f"job={job_token}",
            form_body={"control": control},
            settings=settings,
        )
        assert status == "400 Bad Request"
        assert json.loads(body.decode("utf-8")) == {"error": "invalid_action"}

    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
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
        query_string=f"job={job_token}",
        form_body={"control": control},
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
    assert request["plan_integrity"] == request["worker_contract"]["plan_integrity"]
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
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
    assert payload["claim_receipt"]["plan_integrity"] == payload["job"]["worker_contract"][
        "plan_integrity"
    ]
    assert payload["worker_request"]["plan_integrity"] == payload["job"]["worker_contract"][
        "plan_integrity"
    ]
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
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
    assert payload["proof_receipt"]["plan_integrity"] == payload["job"]["worker_contract"][
        "plan_integrity"
    ]
    assert steps["proof.collect"]["status"] == "done"
    assert steps["rollback.ready"]["status"] == "done"
    assert steps["detonate.worker"]["status"] == "done"
    assert WORKER_SECRET not in serialized
    assert STATE_SECRET not in serialized
    assert "raw-provider-token" not in serialized
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_proof_submission_rejects_oversized_body_before_completion() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    control = _control_for_action(text, "start")
    job_token = _match(text, r"job=([A-Za-z0-9_.-]+)")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )
    started = json.loads(body.decode("utf-8"))
    worker_headers = {
        "Authorization": f"Bearer {WORKER_SECRET}",
        "X-FuseKit-Worker-Id": "worker-01",
    }

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-claims",
        method="POST",
        query_string=f"job={started['job_token']}",
        headers=worker_headers,
        settings=settings,
    )
    claim = json.loads(body.decode("utf-8"))

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/worker-proof",
        method="POST",
        query_string=f"job={claim['job_token']}",
        raw_body=b"{}",
        raw_content_type="application/json",
        content_length=HOSTED_MAX_POST_BODY_BYTES + 1,
        headers=worker_headers,
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_worker_proof"}
    assert settings.hosted_jobs[job_id].status == "worker_claimed"


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
    assert "Reversal playbook" in text
    assert "Request rollback" in text
    assert "GitHub App installation" in text
    assert "https://github.com/settings/installations/42" in text
    assert "Open settings" in text
    assert "Download proof JSON" in text
    assert payload["schema_version"] == "fusekit.hosted-proof-receipt.v1"
    assert payload["reversal_playbook"]
    assert any(
        item.get("action_url") == "https://github.com/settings/installations/42"
        for item in payload["reversal_playbook"]
    )
    assert payload["completion_ready"] is False
    assert "ghs_fake" not in text

    status, headers, body = _call(
        f"/api/hosted/jobs/{job_id}/proof",
        query_string=f"job={job_token}&format=json",
        settings=stateless_settings,
    )
    json_payload = json.loads(body.decode("utf-8"))
    serialized = json.dumps(json_payload)

    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Content-Disposition"] == (
        f'attachment; filename="{job_id}-proof-receipt.json"'
    )
    assert json_payload["schema_version"] == "fusekit.hosted-proof-receipt.v1"
    assert json_payload["completion_ready"] is False
    assert ".fusekit/run_record.json" in json_payload["required_artifacts"]
    assert "ghs_fake" not in serialized
    assert "PRIVATE KEY" not in serialized


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
    text = body.decode("utf-8")
    job_id = _match(text, r"hosted-[A-Za-z0-9_-]+")
    job_token = _job_token(text)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": "bad"},
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_query_control_token() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=urllib.parse.urlencode({"job": job_token, "control": control}),
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "missing_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_accepts_same_origin_control_post() -> None:
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
    job_token = _job_token(text)
    control = _control_for_action(text, "stop")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/stop",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        headers={"Origin": "https://fusekit.snowmanai.org"},
        settings=settings,
    )
    payload = json.loads(body.decode("utf-8"))

    assert status == "200 OK"
    assert payload["status"] == "stopped"
    assert payload["action_receipt"]["action"] == "stop"
    assert settings.hosted_jobs[job_id].status == "stopped"


def test_hosted_job_api_rejects_cross_origin_control_post() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        headers={"Origin": "https://example.invalid"},
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_cross_origin_referer_control_post() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        headers={"Referer": "https://example.invalid/launch"},
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_json_control_body() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        json_body={"control": control},
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "missing_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_untyped_control_body() -> None:
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
    text = _paid_control_room_text(settings, job_id)
    job_token = _job_token(text)
    control = _control_for_action(text, "start")

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        raw_body=urllib.parse.urlencode({"control": control}).encode("utf-8"),
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "missing_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_oversized_control_body_without_dispatch() -> None:
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
    job_token = _job_token(text)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        raw_body=b"control=placeholder",
        raw_content_type="application/x-www-form-urlencoded",
        content_length=HOSTED_MAX_POST_BODY_BYTES + 1,
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "missing_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"
    assert settings.worker_dispatch_opener is not None
    assert settings.worker_dispatch_opener.requests == []


def test_hosted_job_api_rejects_truncated_control_body_without_dispatch() -> None:
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
    job_token = _job_token(text)
    raw_body = b"control=placeholder"

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        raw_body=raw_body,
        raw_content_type="application/x-www-form-urlencoded",
        content_length=len(raw_body) + 1,
        settings=settings,
    )

    assert status == "400 Bad Request"
    assert json.loads(body.decode("utf-8")) == {"error": "missing_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"
    assert settings.worker_dispatch_opener is not None
    assert settings.worker_dispatch_opener.requests == []


def test_hosted_job_api_rejects_expired_control_token(monkeypatch) -> None:
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
    job_token = create_hosted_job_token(
        STATE_SECRET,
        settings.hosted_jobs[job_id],
        now=1_700_000_000,
    )
    control = create_hosted_state_token(
        STATE_SECRET,
        return_path=f"/api/hosted/jobs/{job_id}/actions/start",
        now=1_700_000_000,
        nonce="nonce-for-control-token",
    )
    monkeypatch.setattr("fusekit.hosted.session.time.time", lambda: 1_700_000_301)

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_control_token_for_different_job() -> None:
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
    job_token = _job_token(text)
    control = create_hosted_state_token(
        STATE_SECRET,
        return_path="/api/hosted/jobs/hosted-other/actions/start",
        nonce="nonce-for-control-token",
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
        settings=settings,
    )

    assert status == "403 Forbidden"
    assert json.loads(body.decode("utf-8")) == {"error": "invalid_control"}
    assert settings.hosted_jobs[job_id].status == "waiting_for_worker"


def test_hosted_job_api_rejects_control_token_for_different_action() -> None:
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
    job_token = _job_token(text)
    control = create_hosted_state_token(
        STATE_SECRET,
        return_path=f"/api/hosted/jobs/{job_id}/actions/rollback",
        nonce="nonce-for-rollback-control-token",
    )

    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}/actions/start",
        method="POST",
        query_string=f"job={job_token}",
        form_body={"control": control},
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


def _control_for_action(text: str, action: str) -> str:
    return _match(
        text,
        rf'<form method="post" enctype="application/x-www-form-urlencoded" '
        rf'action="/api/hosted/jobs/[^"]+/actions/{action}'
        rf'(?:\?job=[^"]+)?">\s*'
        rf'<input type="hidden" name="control" value="([A-Za-z0-9_.-]+)">',
    )


def _control_for_payment_checkout(text: str) -> str:
    return _match(
        text,
        r'<form method="post" enctype="application/x-www-form-urlencoded" '
        r'action="/api/hosted/jobs/[^"]+/payments/checkout'
        r'(?:\?job=[^"]+)?">\s*'
        r'<input type="hidden" name="control" value="([A-Za-z0-9_.-]+)">',
    )


def _payment_source_hash(github_source: str) -> str:
    return _payment_public_hash(github_source)


def _payment_public_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _paid_control_room_text(settings: HostedSettings, job_id: str) -> str:
    job = settings.hosted_jobs[job_id]
    receipt = {
        "schema_version": "fusekit.hosted-payment.v1",
        "provider": "stripe-checkout",
        "checkout_session_id": "cs_test_paid",
        "status": "complete",
        "payment_status": "paid",
        "mode": "payment",
        "client_reference_id": job_id,
        "metadata": {
            "job_id": job_id,
            "lane": MANAGED_FUSEKIT_RUN_LANE,
            "github_source_hash": _payment_source_hash(job.github_source),
            "plan_fingerprint": job.worker_contract.plan_fingerprint,
            "stripe_price_id_hash": _payment_public_hash("price_managed_run"),
            "price_label_hash": _payment_public_hash(job.payment_price_label),
        },
        "amount_total": 4900,
        "currency": "usd",
        "paid": True,
        "price_label": job.payment_price_label,
    }
    paid_job = with_hosted_job_payment_receipt(job, receipt)
    settings.hosted_jobs[job_id] = paid_job
    job_token = create_hosted_job_token(STATE_SECRET, paid_job)
    status, _headers, body = _call(
        f"/api/hosted/jobs/{job_id}",
        query_string=f"job={job_token}",
        headers={"Accept": "text/html"},
        settings=settings,
    )
    assert status == "200 OK"
    return body.decode("utf-8")


def _job_token(text: str) -> str:
    return _match(text, r"\?job=([A-Za-z0-9_.-]+)")
