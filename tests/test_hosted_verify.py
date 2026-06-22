from __future__ import annotations

import html
import io
import json
import urllib.error
import urllib.request

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.launcher import HOSTED_PLAIN_LANGUAGE_JOURNEY, HOSTED_PROHIBITED_ACTIONS
from fusekit.hosted.server import (
    HOSTED_AWS_OPERATOR_SETUP_STEPS,
    HOSTED_AWS_SOURCE_PROVENANCE_ENV,
    HOSTED_SECURITY_HEADERS_CONTRACT,
    HOSTED_SOURCE_INTEGRITY_CONTRACT,
    HOSTED_SOURCE_PROVENANCE_ENV,
)
from fusekit.hosted.verify import (
    HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
    verify_hosted_deployment,
)

PUBLIC_DNS_ADDRESSES = ["2606:4700::6810:84e5", "76.76.21.21"]
VERCEL_COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"
SAFE_RESPONSE_HEADERS = {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


class FakeResponse:
    def __init__(
        self,
        payload: dict[str, object] | str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.payload = payload
        self.headers = dict(SAFE_RESPONSE_HEADERS if headers is None else headers)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload).encode("utf-8")


class SequenceOpener:
    def __init__(
        self,
        payloads: list[
            dict[str, object]
            | str
            | urllib.error.HTTPError
            | tuple[dict[str, object] | str, dict[str, str]]
        ],
    ) -> None:
        self.payloads = payloads
        self.requests: list[urllib.request.Request] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        assert timeout == 20.0
        payload = self.payloads.pop(0)
        if isinstance(payload, urllib.error.HTTPError):
            raise payload
        if isinstance(payload, tuple):
            body, headers = payload
            return FakeResponse(body, headers=headers)
        return FakeResponse(payload)


def test_verify_hosted_deployment_passes_launcher_and_dispatch_checks() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
                "production_ready": True,
                "idempotency": {
                    "mode": "dispatch-state-dir",
                    "durable": True,
                    "scope": "worker deployment",
                    "proof": (
                        "Duplicate job/action dispatches are reserved through a configured "
                        "non-secret state directory before worker spawn."
                    ),
                },
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blocking_checks"] == []
    assert report["next_actions"] == []
    assert [check["id"] for check in report["checks"]] == [
        "hosted.dns",
        "hosted.home",
        "hosted.health",
        "hosted.readiness",
        "hosted.deployment",
        "hosted.github_intake",
        "worker_dispatch.health",
        "worker_dispatch.readiness",
    ]
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["hosted.dns"]["hostname"] == "fusekit.snowmanai.org"
    assert checks["hosted.dns"]["addresses"] == PUBLIC_DNS_ADDRESSES
    assert report["worker_dispatch_url"] == "https://worker.snowmanai.org/dispatch"
    assert opener.requests[0].full_url == "https://fusekit.snowmanai.org/"
    assert opener.requests[1].full_url == "https://fusekit.snowmanai.org/healthz"
    assert opener.requests[4].full_url == "https://fusekit.snowmanai.org/api/github/intake"
    assert opener.requests[5].full_url == "https://worker.snowmanai.org/healthz"
    assert opener.requests[6].full_url == "https://worker.snowmanai.org/readiness"
    assert "WORKER_SECRET" not in serialized
    assert "signed-public-job-token" not in serialized


def test_verify_hosted_deployment_requires_security_headers() -> None:
    opener = SequenceOpener(
        [
            (_home_html(), {}),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.home"]["status"] == "failed"
    assert checks["hosted.home"]["failures"] == [
        "security_header_cache_control_missing",
        "security_header_csp_default_src_missing",
        "security_header_csp_frame_ancestors_missing",
        "security_header_cross_origin_opener_policy_missing",
        "security_header_permissions_policy_missing",
        "security_header_referrer_policy_missing",
        "security_header_hsts_missing",
        "security_header_content_type_options_missing",
        "security_header_frame_options_missing",
    ]


def test_verify_hosted_deployment_requires_durable_worker_dispatch_idempotency() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
                "production_ready": False,
                "idempotency": {
                    "mode": "process",
                    "durable": False,
                },
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["worker_dispatch.readiness"]["status"] == "failed"
    assert checks["worker_dispatch.readiness"]["failures"] == [
        "worker_dispatch_idempotency_not_durable",
        "worker_dispatch_idempotency_mode_not_production",
        "worker_dispatch_production_ready_not_true",
    ]


def test_verify_hosted_deployment_requires_worker_dispatch_idempotency_proof() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
                "production_ready": True,
                "idempotency": {
                    "mode": "dispatch-state-dir",
                    "durable": True,
                    "scope": "single receiver process",
                    "proof": "Duplicate dispatches are handled.",
                },
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["worker_dispatch.readiness"]["status"] == "failed"
    assert checks["worker_dispatch.readiness"]["failures"] == [
        "worker_dispatch_idempotency_scope_mismatch",
        "worker_dispatch_idempotency_proof_missing",
    ]


def test_verify_hosted_deployment_reports_cloudflare_error_without_claiming_ready() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/",
                403,
                "Forbidden",
                {},
                io.BytesIO(
                    b"""
                    <title>DNS points to prohibited IP | Cloudflare</title>
                    <h1>Error 1000</h1>
                    <span>Ray ID: test-ray-id</span>
                    """
                ),
            ),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert report["blocking_checks"] == [
        "hosted.home",
        "hosted.readiness",
    ]
    assert report["next_actions"] == [
        (
            "Attach fusekit.snowmanai.org to the Vercel project, then set the "
            "Cloudflare fusekit CNAME to the exact Vercel-provided target. Do not "
            "point the proxied record at a prohibited IP or Cloudflare-owned address."
        )
    ]
    assert checks["hosted.dns"]["status"] == "ok"
    assert checks["hosted.home"]["status"] == "failed"
    assert checks["hosted.home"]["http_status"] == 403
    assert checks["hosted.home"]["failures"] == ["http_error"]
    assert checks["hosted.home"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Vercel-provided target" in checks["hosted.home"]["next_action"]
    assert checks["hosted.readiness"]["failures"] == ["ready_field_not_true"]
    assert "test-ray-id" not in json.dumps(report)


def test_verify_hosted_deployment_requires_readiness_source_provenance_contract() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = ["VERCEL_ENV"]
    provenance = readiness["source_provenance"]
    assert isinstance(provenance, dict)
    provenance["verified"] = False
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            readiness,
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.readiness"]["status"] == "failed"
    assert "required_source_provenance_env_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "readiness_source_provenance_not_verified" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_rejects_non_origin_or_secret_url() -> None:
    with pytest.raises(FuseKitError, match="hosted_origin_must_be_https_origin"):
        verify_hosted_deployment(origin="https://user:pass@fusekit.snowmanai.org")

    with pytest.raises(FuseKitError, match="worker_dispatch_url_must_be_https"):
        verify_hosted_deployment(
            origin="https://fusekit.snowmanai.org",
            worker_dispatch_url="https://token@worker.snowmanai.org/dispatch",
            dns_resolver=_public_dns_resolver,
        )


def test_verify_hosted_deployment_diagnoses_compact_cloudflare_1000_body() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/",
                403,
                "Forbidden",
                {},
                io.BytesIO(b"error code: 1000\n"),
            ),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert checks["hosted.home"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Cloudflare fusekit CNAME" in checks["hosted.home"]["next_action"]


def test_verify_hosted_deployment_requires_runtime_and_dns_contract() -> None:
    contract = _deployment_contract()
    runtime = contract["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "runtime.txt"
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_type"] = "A"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "runtime_python_version_mismatch" in checks["hosted.deployment"]["failures"]
    assert "cloudflare_record_type_mismatch" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_requires_canonical_subdomain_contract() -> None:
    contract = _deployment_contract()
    contract["canonical_origin"] = "https://www.snowmanai.org"
    contract["public_origin"] = "https://preview-fusekit.vercel.app"
    contract["domain"] = "www.snowmanai.org"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "canonical_origin_mismatch" in checks["hosted.deployment"]["failures"]
    assert "public_origin_mismatch" in checks["hosted.deployment"]["failures"]
    assert "domain_mismatch" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_requires_operator_setup_contract() -> None:
    contract = _deployment_contract()
    operator_setup = contract["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["target_subdomain"] = "www.snowmanai.org"
    steps = operator_setup["steps"]
    assert isinstance(steps, list)
    assert isinstance(steps[3], dict)
    steps[3]["label"] = "Add www.snowmanai.org as the Vercel custom domain."
    steps.pop()
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "operator_setup_target_subdomain_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "operator_setup_steps_mismatch" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_requires_github_app_token_boundary() -> None:
    contract = _deployment_contract()
    github_app = contract["github_app"]
    assert isinstance(github_app, dict)
    github_app["repository_permission"] = "contents:write"
    github_app["token_boundary"] = {
        "repository_selection": "all",
        "requested_token_permissions": {"contents": "write"},
        "accepted_token_permissions": {"contents": "write", "secrets": "write"},
    }
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "github_app_repository_permission_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "github_app_token_boundary_mismatch" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_worker_dispatch_contract() -> None:
    contract = _deployment_contract()
    contract["required_runtime_env"] = [
        "FUSEKIT_HOSTED_ORIGIN",
        "FUSEKIT_GITHUB_APP_ID",
        "FUSEKIT_GITHUB_APP_SLUG",
        "FUSEKIT_GITHUB_APP_PRIVATE_KEY",
        "FUSEKIT_HOSTED_STATE_SECRET",
        "FUSEKIT_HOSTED_WORKER_SECRET",
    ]
    contract["optional_runtime_env"] = ["FUSEKIT_HOSTED_WORKER_DISPATCH_URL"]
    worker_dispatch = contract["worker_dispatch"]
    assert isinstance(worker_dispatch, dict)
    worker_dispatch["production_required"] = False
    worker_dispatch["no_terminal_wakeup_required"] = False
    checks = worker_dispatch["checks"]
    assert isinstance(checks, dict)
    checks["dispatch"] = "https://worker.invalid"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks_by_id = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    failures = checks_by_id["hosted.deployment"]["failures"]
    assert "worker_dispatch_runtime_env_not_required" in failures
    assert "optional_runtime_env_mismatch" in failures
    assert "worker_dispatch_production_required_not_true" in failures
    assert "worker_dispatch_no_terminal_wakeup_required_not_true" in failures
    assert "worker_dispatch_dispatch_url_placeholder" in failures


def test_verify_hosted_deployment_requires_public_trust_contract() -> None:
    contract = _deployment_contract()
    contract["trust_story"] = ["open core", "redacted proof"]
    trust_contract = contract["trust_contract"]
    assert isinstance(trust_contract, dict)
    trust_contract.pop("reversible_setup")
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "trust_story_mismatch" in checks["hosted.deployment"]["failures"]
    assert "trust_contract_keys_mismatch" in checks["hosted.deployment"]["failures"]
    assert "trust_contract_reversible_setup_missing" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_capability_vault_boundary() -> None:
    contract = _deployment_contract()
    boundary = contract["capability_vault_boundary"]
    assert isinstance(boundary, dict)
    boundary["raw_secret_policy"] = "Secrets may be copied into generated apps."
    boundary["forbidden_public_material"] = ["debug logs"]
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "capability_vault_boundary_raw_secret_policy_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]
    assert "capability_vault_boundary_forbidden_public_material_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]


def test_verify_hosted_deployment_requires_security_header_contract() -> None:
    contract = _deployment_contract()
    security_headers = contract["security_headers"]
    assert isinstance(security_headers, dict)
    security_headers["required_headers"] = ["Cache-Control"]
    security_headers["requirements"] = {"cache": "public"}
    security_headers["secret_boundary"] = "Header policy."
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "security_headers_required_headers_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "security_headers_requirements_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "security_headers_secret_boundary_missing" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_source_integrity_contract() -> None:
    contract = _deployment_contract()
    source_integrity = contract["source_integrity"]
    assert isinstance(source_integrity, dict)
    source_integrity["source_repository"] = "https://github.com/example/private"
    source_integrity["reviewable_files"] = ["app.py"]
    source_integrity["private_generated_artifact_required"] = True
    source_integrity["secret_boundary"] = "Source proof."
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "source_integrity_source_repository_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "source_integrity_reviewable_files_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "source_integrity_private_generated_artifact_required_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]
    assert "source_integrity_secret_boundary_missing" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_source_provenance_contract() -> None:
    contract = _deployment_contract()
    provenance = contract["source_provenance"]
    assert isinstance(provenance, dict)
    provenance["verified"] = False
    provenance["required_env"] = ["VERCEL_ENV"]
    provenance["secret_boundary"] = "Source proof."
    actual = provenance["actual"]
    assert isinstance(actual, dict)
    actual["deployment_environment"] = "preview"
    actual["git_provider"] = "gitlab"
    actual["repo_owner"] = "example"
    actual["repo_slug"] = "private"
    actual["commit_ref"] = ""
    actual["commit_sha"] = "not-a-sha"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    failures = {
        check["id"]: check for check in report["checks"]
    }["hosted.deployment"]["failures"]

    assert report["ready"] is False
    assert "source_provenance_actual_environment_mismatch" in failures
    assert "source_provenance_actual_git_provider_mismatch" in failures
    assert "source_provenance_actual_repo_owner_mismatch" in failures
    assert "source_provenance_actual_repo_slug_mismatch" in failures
    assert "source_provenance_commit_ref_missing" in failures
    assert "source_provenance_commit_sha_invalid" in failures
    assert "source_provenance_not_verified" in failures
    assert "source_provenance_required_env_mismatch" in failures
    assert "source_provenance_secret_boundary_missing" in failures


def test_verify_hosted_deployment_accepts_aws_source_provenance_contract() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _aws_source_provenance_contract()
    aws_deployment = _aws_deployment_contract()
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=aws_deployment),
            {"ok": True},
            readiness,
            aws_deployment,
            _github_intake_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
                "production_ready": True,
                "idempotency": {
                    "mode": "dispatch-state-dir",
                    "durable": True,
                    "scope": "worker deployment",
                    "proof": (
                        "Duplicate job/action dispatches are reserved through a configured "
                        "non-secret state directory before worker spawn."
                    ),
                },
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is True
    assert checks["hosted.readiness"]["status"] == "ok"
    assert checks["hosted.deployment"]["status"] == "ok"


def test_verify_hosted_deployment_requires_one_click_contract() -> None:
    contract = _deployment_contract()
    one_click = contract["one_click_launch"]
    assert isinstance(one_click, dict)
    one_click["no_terminal_promise"] = "Download the CLI and paste this command."
    one_click["terminal_required"] = True
    one_click["download_required"] = True
    one_click["launch_path"] = ["Run a terminal command."]
    one_click["plain_language_journey"] = ["Open a terminal."]
    one_click["prohibited"] = ["Bypass provider approval screens."]
    one_click["completion_requires"] = ["Live URL verification"]
    one_click["completion_evidence_keys"] = ["live_url"]
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "one_click_launch_no_terminal_promise_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_terminal_required_not_false" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_download_required_not_false" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_path_mismatch" in checks["hosted.deployment"]["failures"]
    assert "one_click_launch_plain_language_journey_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]
    assert "one_click_launch_prohibited_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_completion_requires_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_completion_evidence_keys_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]


def test_verify_hosted_deployment_requires_protected_controls_contract() -> None:
    contract = _deployment_contract()
    protected = contract["protected_controls"]
    assert isinstance(protected, dict)
    protected["actions"] = ["start"]
    protected["control_token_transport"] = "query_parameter"
    protected["content_type"] = "application/json"
    protected["query_control_behavior"] = "accepted"
    protected["browser_origin_policy"] = "not_checked"
    protected["binding"] = "job_id"
    protected["public_url_policy"] = "control tokens may appear in action URLs"
    protected["secret_boundary"] = "Protected controls are public links."
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    failures = checks["hosted.deployment"]["failures"]

    assert report["ready"] is False
    assert "protected_controls_actions_mismatch" in failures
    assert "protected_controls_control_token_transport_mismatch" in failures
    assert "protected_controls_content_type_mismatch" in failures
    assert "protected_controls_query_control_behavior_mismatch" in failures
    assert "protected_controls_browser_origin_policy_mismatch" in failures
    assert "protected_controls_binding_mismatch" in failures
    assert "protected_controls_public_url_policy_mismatch" in failures
    assert "protected_controls_secret_boundary_missing" in failures


def test_verify_hosted_deployment_requires_github_intake_contract() -> None:
    intake = _github_intake_contract()
    intake["route"] = "oauth-app"
    intake["launch_path"] = ["Download a CLI."]
    intake["plain_language_journey"] = ["Paste a command."]
    intake["prohibited"] = ["Bypass provider approval screens."]
    intake["proof_evidence_keys"] = ["live_url"]
    intake["permissions"] = ["Install on every repository."]
    intake["token_boundary"] = {
        "repository_selection": "all",
        "requested_token_permissions": {"contents": "write"},
    }
    open_core = intake["open_core"]
    assert isinstance(open_core, dict)
    open_core["reviewable_entrypoint"] = "server.py"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            intake,
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.github_intake"]["status"] == "failed"
    assert "github_intake_route_mismatch" in checks["hosted.github_intake"]["failures"]
    assert "github_intake_launch_path_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]
    assert "github_intake_plain_language_journey_mismatch" in checks[
        "hosted.github_intake"
    ]["failures"]
    assert "github_intake_prohibited_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]
    assert "github_intake_proof_evidence_keys_mismatch" in checks[
        "hosted.github_intake"
    ]["failures"]
    assert "github_intake_permissions_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]
    assert "github_intake_token_boundary_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]
    assert "github_intake_open_core_entrypoint_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]


def test_verify_hosted_deployment_rejects_credential_text_in_public_json() -> None:
    readiness = _readiness_contract()
    readiness["debug"] = "Authorization: Bearer raw-provider-token"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            readiness,
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    serialized = json.dumps(report)

    assert report["ready"] is False
    assert checks["hosted.readiness"]["failures"] == [
        "public_json_contains_credential_text"
    ]
    assert "raw-provider-token" not in serialized
    assert "Authorization" not in serialized


def test_verify_hosted_deployment_requires_trustworthy_homepage() -> None:
    opener = SequenceOpener(
        [
            (
                "<html><body>Download the CLI. token: "
                "github_pat_1234567890abcdefghijklmnop</body></html>"
            ),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    serialized = json.dumps(report)

    assert report["ready"] is False
    assert checks["hosted.home"]["status"] == "failed"
    assert "public_text_contains_credential_text" in checks["hosted.home"]["failures"]
    assert "hosted_home_headline_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_open_core_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_narrow_permissions_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_visible_plan_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_redacted_proof_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_deployment_provenance_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_deployment_provenance_commit_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_completion_requirements_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_plain_language_click_path_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_prohibited_actions_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_prohibited_mfa_bypass_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_plain_language_provider_step_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_recording_proof_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_selected_repository_boundary_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_contents_read_boundary_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_all_repository_rejection_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_reversible_setup_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_reversal_path_step_1_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_reversal_path_step_2_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_reversal_path_step_3_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "hosted_home_embedded_intake_contract_missing" in checks["hosted.home"][
        "failures"
    ]
    assert "github_pat_" not in serialized


def test_verify_hosted_deployment_requires_valid_homepage_embedded_contracts() -> None:
    home = _home_html(
        github_intake={"provider": "oauth-app"},
        readiness={
            "schema_version": "fusekit.hosted-readiness.v1",
            "ready": False,
        },
        deployment={"runtime": {"provider": "static-html"}},
    )
    opener = SequenceOpener(
        [
            home,
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.home"]["status"] == "failed"
    assert "hosted_home_embedded_github_intake_github_intake_provider_mismatch" in checks[
        "hosted.home"
    ]["failures"]
    assert "hosted_home_embedded_readiness_ready_field_not_true" in checks[
        "hosted.home"
    ]["failures"]
    assert "hosted_home_embedded_deployment_canonical_origin_mismatch" in checks[
        "hosted.home"
    ]["failures"]
    assert "hosted_home_embedded_deployment_runtime_provider_mismatch" in checks[
        "hosted.home"
    ]["failures"]


def test_verify_hosted_deployment_requires_homepage_readiness_source_provenance() -> None:
    provenance = _source_provenance_contract()
    provenance["verified"] = False
    readiness = {
        "schema_version": "fusekit.hosted-readiness.v1",
        "ready": True,
        "blocking_checks": [],
        "next_actions": [],
        "required_source_provenance_env": ["VERCEL_ENV"],
        "source_provenance": provenance,
    }
    home = _home_html(readiness=readiness)
    opener = SequenceOpener(
        [
            home,
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    failures = {check["id"]: check for check in report["checks"]}["hosted.home"][
        "failures"
    ]

    assert report["ready"] is False
    assert (
        "hosted_home_embedded_readiness_required_source_provenance_env_mismatch"
        in failures
    )
    assert (
        "hosted_home_embedded_readiness_readiness_source_provenance_not_verified"
        in failures
    )


def test_verify_hosted_deployment_reports_dns_resolution_failure() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=lambda _hostname: [],
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.dns"]["status"] == "failed"
    assert checks["hosted.dns"]["failures"] == ["dns_no_addresses"]
    assert "Cloudflare fusekit CNAME" in checks["hosted.dns"]["next_action"]


def test_verify_hosted_deployment_rejects_private_dns_addresses() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=lambda _hostname: ["127.0.0.1"],
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.dns"]["failures"] == ["dns_non_public_address"]
    assert checks["hosted.dns"]["addresses"] == ["127.0.0.1"]


def _public_dns_resolver(hostname: str) -> list[str]:
    assert hostname == "fusekit.snowmanai.org"
    return PUBLIC_DNS_ADDRESSES


def _home_html(
    *,
    github_intake: dict[str, object] | None = None,
    readiness: dict[str, object] | None = None,
    deployment: dict[str, object] | None = None,
) -> str:
    github_intake = _github_intake_contract() if github_intake is None else github_intake
    readiness = (
        _readiness_contract()
        if readiness is None
        else readiness
    )
    deployment = _deployment_contract() if deployment is None else deployment
    intake_payload = html.escape(json.dumps(github_intake, sort_keys=True))
    readiness_payload = html.escape(json.dumps(readiness, sort_keys=True))
    deployment_payload = html.escape(json.dumps(deployment, sort_keys=True))
    intake_script = _json_script("fusekit-github-intake", intake_payload)
    readiness_script = _json_script("fusekit-hosted-readiness", readiness_payload)
    deployment_script = _json_script("fusekit-hosted-deployment", deployment_payload)
    return f"""
    <html>
      <body>
        <h1>Launch any GitHub app without touching a terminal.</h1>
        <a>Start hosted launch</a>
        <section>
          open core / narrow permissions / visible plan / redacted proof / reversible setup
        </section>
        <section>Open core https://github.com/xpxpxp-coder/fusekit</section>
        <section>Reviewable hosted files</section>
        <section>app.py vercel.json src/fusekit/hosted/server.py</section>
        <section>No private generated artifact is required for the hosted click flow.</section>
        <section>Deployment provenance</section>
        <section>Commit SHA {VERCEL_COMMIT_SHA}</section>
        <section>Capability vault boundary</section>
        <section>Raw secrets must never leave the vault runtime.</section>
        <section>
          GitHub access is selected repository only, requests contents:read,
          accepts metadata:read, and rejects all-repository or contents:write
          installation tokens.
        </section>
        <section>What happens after the click</section>
        <section>What FuseKit will not do</section>
        <section>{HOSTED_PROHIBITED_ACTIONS[0]}</section>
        <section>For someone who just wants to click</section>
        <section>Open fusekit.snowmanai.org in a browser.</section>
        <section>Complete only the provider-owned screens FuseKit highlights.</section>
        <section>Launch readiness</section>
        <section>Completion requires</section>
        <section>Live URL verification</section>
        <section>Provider verifier results</section>
        <section>DNS propagation status</section>
        <section>Redacted setup receipt</section>
        <section>Redacted audit log</section>
        <section>Run Record</section>
        <section>Detonation receipt</section>
        <section>Live acceptance report</section>
        <section>Recording proof</section>
        <section>Reversible setup</section>
        <section>Show rollback metadata before risky changes.</section>
        <section>Preserve rollback actions for provider resources FuseKit creates.</section>
        <section>Offer stop, revoke access, rollback, and download redacted proof actions.</section>
        <section>What you may need to approve</section>
        <section>Hosted deployment contract</section>
        {intake_script}
        {readiness_script}
        {deployment_script}
      </body>
    </html>
    """


def _json_script(script_id: str, payload: str) -> str:
    return f'<script id="{script_id}" type="application/json">{payload}</script>'


def _readiness_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-readiness.v1",
        "ready": True,
        "blocking_checks": [],
        "next_actions": [],
        "required_source_provenance_env": list(HOSTED_SOURCE_PROVENANCE_ENV),
        "source_provenance": _source_provenance_contract(),
    }


def _deployment_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-deployment.v1",
        "canonical_origin": "https://fusekit.snowmanai.org",
        "public_origin": "https://fusekit.snowmanai.org",
        "domain": "fusekit.snowmanai.org",
        "trust_story": [
            "open core",
            "narrow permissions",
            "visible plan",
            "redacted proof",
            "reversible setup",
        ],
        "trust_contract": {
            "open_core": "Source repository, MIT license, and app.py entrypoint are public.",
            "narrow_permissions": "GitHub App intake starts with contents:read.",
            "visible_plan": "Providers, approved action ids, gates, and artifacts are shown.",
            "redacted_proof": "Public receipts use redacted notes only.",
            "reversible_setup": "Stop, revoke, rollback, and detonation controls exist.",
        },
        "capability_vault_boundary": {
            "raw_secret_policy": (
                "Only FuseKit may use secrets internally. Raw secrets must never leave the "
                "vault runtime."
            ),
            "generated_app_policy": (
                "Generated apps may request capabilities; they must not receive provider "
                "credentials, GitHub installation tokens, worker secrets, or vault material."
            ),
            "public_surface_policy": (
                "Hosted pages, job tokens, receipts, logs, proof, and deployment contracts "
                "use redacted labels, statuses, URLs, and artifact names only."
            ),
            "forbidden_public_material": [
                "provider credentials",
                "GitHub installation tokens",
                "GitHub App private keys",
                "worker secrets",
                "HMAC signatures",
                "vault material",
                "copy-once secret values",
            ],
            "allowed_public_material": [
                "provider names",
                "approved action ids",
                "artifact labels",
                "redacted statuses",
                "public URLs",
                "rollback action summaries",
                "detonation receipt status",
            ],
        },
        "one_click_launch": {
            "public_url": "https://fusekit.snowmanai.org",
            "start_control": "Start hosted launch",
            "no_terminal_promise": (
                "No terminal, local install, download, or copied command is required "
                "in the hosted path."
            ),
            "intake": "github-app",
            "repository_scope": "one selected GitHub repository",
            "github_repository_permission": "contents:read",
            "launch_path": [
                "Visit the hosted FuseKit URL.",
                "Install the FuseKit GitHub App on one selected repository.",
                "Review the visible plan and approved action ids before worker start.",
                "Click Start hosted launch and pass only provider-owned human gates.",
                (
                    "Receive the live URL, redacted proof receipt, rollback metadata, "
                    "and detonation receipt."
                ),
            ],
            "plain_language_journey": list(HOSTED_PLAIN_LANGUAGE_JOURNEY),
            "prohibited": list(HOSTED_PROHIBITED_ACTIONS),
            "human_gates": [
                "GitHub sign-in, MFA, passkey, SSO, consent, or repository selection",
                (
                    "Provider-owned billing, CAPTCHA, domain ownership, or copy-once "
                    "secret screens"
                ),
                "DNS changes only after FuseKit shows the exact proposed records",
            ],
            "completion_requires": [
                "Live URL verification",
                "Provider verifier results",
                "DNS propagation status",
                "Redacted setup receipt",
                "Redacted audit log",
                "Run Record",
                "Detonation receipt",
                "Live acceptance report",
                "Recording proof",
            ],
            "completion_evidence_keys": [
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
            "reversal": [
                "Show rollback metadata before risky changes.",
                "Preserve rollback actions for provider resources FuseKit creates.",
                "Offer stop, revoke access, rollback, and download redacted proof actions.",
            ],
            "terminal_required": False,
            "download_required": False,
        },
        "protected_controls": {
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
        },
        "runtime": {
            "provider": "vercel",
            "entrypoint": "app.py",
            "routing_config": "vercel.json",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        },
        "cloudflare_dns": {
            "zone": "snowmanai.org",
            "record_name": "fusekit",
            "record_type": "CNAME",
        },
        "security_headers": dict(HOSTED_SECURITY_HEADERS_CONTRACT),
        "source_integrity": dict(HOSTED_SOURCE_INTEGRITY_CONTRACT),
        "source_provenance": _source_provenance_contract(),
        "open_core": {
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
        "operator_setup": {
            "target_subdomain": "fusekit.snowmanai.org",
            "steps": [
                {
                    "id": "connect_vercel_project",
                    "label": (
                        "Connect the Vercel project to the open-source FuseKit repository "
                        "and expose Vercel system environment variables."
                    ),
                    "proof": (
                        "Vercel deployment provenance reports the expected GitHub repo, "
                        "branch, commit SHA, and production environment."
                    ),
                },
                {
                    "id": "deploy_worker_dispatch_receiver",
                    "label": (
                        "Deploy an HTTPS worker dispatch service running "
                        "fusekit-hosted-worker-dispatch with durable dispatch state."
                    ),
                    "proof": (
                        "Its /healthz and /readiness endpoints pass with production readiness."
                    ),
                },
                {
                    "id": "configure_worker_dispatch_url",
                    "label": (
                        "Set FUSEKIT_HOSTED_WORKER_DISPATCH_URL in the hosted Vercel "
                        "project to that HTTPS dispatch endpoint."
                    ),
                    "proof": (
                        "Hosted readiness reports the dispatch URL is configured before launch."
                    ),
                },
                {
                    "id": "attach_custom_domain",
                    "label": "Add fusekit.snowmanai.org as the Vercel custom domain.",
                    "proof": "Vercel reports the domain as assigned to this project.",
                },
                {
                    "id": "route_cloudflare_cname",
                    "label": (
                        "In Cloudflare DNS, set the fusekit record to the exact "
                        "Vercel-provided CNAME target."
                    ),
                    "proof": (
                        "The subdomain serves FuseKit instead of a Cloudflare error page."
                    ),
                },
                {
                    "id": "verify_public_contracts",
                    "label": (
                        "Verify https://fusekit.snowmanai.org/healthz, "
                        "/api/hosted/readiness, /api/hosted/deployment, and the "
                        "worker dispatch receiver from outside the deployment."
                    ),
                    "proof": (
                        "fusekit-hosted-verify reports DNS, health, readiness, "
                        "deployment, and --worker-dispatch-url checks ok."
                    ),
                },
            ],
        },
        "github_app": {
            "repository_permission": "contents:read",
            "token_boundary": {
                "repository_selection": "selected",
                "requested_token_permissions": {"contents": "read"},
                "accepted_token_permissions": {"contents": "read", "metadata": "read"},
                "rejects": [
                    "all-repository installation tokens",
                    "contents:write installation tokens",
                    "unexpected GitHub write permissions",
                ],
            },
        },
        "required_runtime_env": [
            "FUSEKIT_HOSTED_ORIGIN",
            "FUSEKIT_GITHUB_APP_ID",
            "FUSEKIT_GITHUB_APP_SLUG",
            "FUSEKIT_GITHUB_APP_PRIVATE_KEY",
            "FUSEKIT_HOSTED_STATE_SECRET",
            "FUSEKIT_HOSTED_WORKER_SECRET",
            "FUSEKIT_HOSTED_WORKER_DISPATCH_URL",
        ],
        "optional_runtime_env": [],
        "required_source_provenance_env": list(HOSTED_SOURCE_PROVENANCE_ENV),
        "worker_dispatch": {
            "schema_version": "fusekit.hosted-worker-dispatch.v1",
            "receiver_command": "fusekit-hosted-worker-dispatch",
            "production_required": True,
            "no_terminal_wakeup_required": True,
            "checks": {
                "dispatch": "https://worker.snowmanai.org/dispatch",
                "health": "https://worker.snowmanai.org/healthz",
                "readiness": "https://worker.snowmanai.org/readiness",
            },
        },
    }


def _source_provenance_contract() -> dict[str, object]:
    return {
        "provider": "vercel",
        "source": "vercel_system_environment_variables",
        "expected": {
            "deployment_environment": "production",
            "git_provider": "github",
            "repo_owner": "xpxpxp-coder",
            "repo_slug": "fusekit",
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
        },
        "actual": {
            "deployment_environment": "production",
            "deployment_url": "fusekit-snowmanai-org.vercel.app",
            "git_provider": "github",
            "repo_owner": "xpxpxp-coder",
            "repo_slug": "fusekit",
            "commit_ref": "main",
            "commit_sha": VERCEL_COMMIT_SHA,
        },
        "verified": True,
        "required_env": list(HOSTED_SOURCE_PROVENANCE_ENV),
        "secret_boundary": (
            "Source provenance publishes only Vercel/Git metadata. It does not "
            "publish Vercel tokens, project IDs, OIDC tokens, deploy hooks, GitHub "
            "installation tokens, provider credentials, or vault material."
        ),
    }


def _aws_source_provenance_contract() -> dict[str, object]:
    return {
        "provider": "aws-elastic-beanstalk",
        "source": "fusekit_hosted_environment_variables",
        "expected": {
            "deployment_environment": "production",
            "git_provider": "github",
            "repo_owner": "xpxpxp-coder",
            "repo_slug": "fusekit",
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
        },
        "actual": {
            "deployment_environment": "production",
            "deployment_url": "https://fusekit-prod.us-east-1.elasticbeanstalk.com",
            "git_provider": "github",
            "repo_owner": "xpxpxp-coder",
            "repo_slug": "fusekit",
            "commit_ref": "main",
            "commit_sha": VERCEL_COMMIT_SHA,
        },
        "verified": True,
        "required_env": list(HOSTED_AWS_SOURCE_PROVENANCE_ENV),
        "secret_boundary": (
            "Source provenance publishes only AWS/Git metadata. It does not publish "
            "AWS credentials, CloudFormation outputs, access keys, deploy hooks, "
            "GitHub installation tokens, provider credentials, or vault material."
        ),
    }


def _aws_deployment_contract() -> dict[str, object]:
    contract = _deployment_contract()
    contract["runtime"] = {
        "provider": "aws-elastic-beanstalk",
        "entrypoint": "app.py",
        "process_config": "Procfile",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_value"] = "Use the exact AWS-provided CNAME target."
    contract["source_provenance"] = _aws_source_provenance_contract()
    contract["required_source_provenance_env"] = list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    operator_setup = contract["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["steps"] = [dict(step) for step in HOSTED_AWS_OPERATOR_SETUP_STEPS]
    return contract


def _github_intake_contract() -> dict[str, object]:
    return {
        "provider": "github",
        "route": "github-app",
        "install_url": "https://github.com/apps/fusekit-launcher/installations/new",
        "trust_story": [
            "open core",
            "narrow permissions",
            "visible plan",
            "redacted proof",
            "reversible setup",
        ],
        "no_terminal_promise": (
            "No terminal, local install, download, or copied command is required "
            "in the hosted path."
        ),
        "launch_path": [
            "Visit the hosted FuseKit URL.",
            "Install the FuseKit GitHub App on one selected repository.",
            "Review the visible plan and approved action ids before worker start.",
            "Click Start hosted launch and pass only provider-owned human gates.",
            (
                "Receive the live URL, redacted proof receipt, rollback metadata, "
                "and detonation receipt."
            ),
        ],
        "plain_language_journey": list(HOSTED_PLAIN_LANGUAGE_JOURNEY),
        "prohibited": list(HOSTED_PROHIBITED_ACTIONS),
        "proof": [
            "Live URL verification",
            "Provider verifier results",
            "DNS propagation status",
            "Redacted setup receipt",
            "Redacted audit log",
            "Run Record",
            "Detonation receipt",
            "Live acceptance report",
            "Recording proof",
        ],
        "proof_evidence_keys": [
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
        "reversal": [
            "Show rollback metadata before risky changes.",
            "Preserve rollback actions for provider resources FuseKit creates.",
            "Offer stop, revoke access, rollback, and download redacted proof actions.",
        ],
        "permissions": [
            "Install the FuseKit GitHub App on one selected repository.",
            "Grant contents:read access for source scan and setup planning.",
            (
                "Approve any GitHub write capability separately through the visible plan "
                "before FuseKit mutates repository settings."
            ),
        ],
        "token_boundary": {
            "repository_selection": "selected",
            "requested_token_permissions": {"contents": "read"},
            "accepted_token_permissions": {"contents": "read", "metadata": "read"},
            "rejects": [
                "all-repository installation tokens",
                "contents:write installation tokens",
                "unexpected GitHub write permissions",
            ],
        },
        "open_core": {
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
    }
