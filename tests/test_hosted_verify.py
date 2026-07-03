from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from fusekit.errors import FuseKitError
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
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
    hosted_launch_lane_contract,
)
from fusekit.hosted.launcher import HOSTED_PLAIN_LANGUAGE_JOURNEY, HOSTED_PROHIBITED_ACTIONS
from fusekit.hosted.script_json import json_script_payload
from fusekit.hosted.server import (
    HOSTED_AWS_OPERATOR_SETUP_STEPS,
    HOSTED_AWS_SOURCE_PROVENANCE_ENV,
    HOSTED_GENERIC_OPERATOR_SETUP_STEPS,
    HOSTED_OCI_OPERATOR_SETUP_STEPS,
    HOSTED_OCI_SOURCE_PROVENANCE_ENV,
    HOSTED_PROVIDER_PERMISSION_COPY,
    HOSTED_SECURITY_HEADERS_CONTRACT,
    HOSTED_SOURCE_INTEGRITY_CONTRACT,
    HOSTED_SOURCE_PROVENANCE_ENV,
    HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV,
)
from fusekit.hosted.verify import (
    HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
    verify_hosted_deployment,
)
from fusekit.hosted.worker_dispatch import HOSTED_WORKER_DISPATCH_BINDING_FIELDS
from fusekit.security import contains_durable_secret_text

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


def _worker_dispatch_binding_contract() -> dict[str, object]:
    return {
        "required": True,
        "required_fields": list(HOSTED_WORKER_DISPATCH_BINDING_FIELDS),
        "required_for_actions": ["start", "rollback", "detonate"],
        "lane": "managed-fusekit-run",
        "payment_status": "paid",
        "hash_fields": ["plan_fingerprint", "price_label_hash"],
        "secret_boundary": (
            "Dispatch binding contains only public job/action/lane/payment labels "
            "and SHA-256 public hashes; job tokens and worker secrets are excluded."
        ),
    }


def _worker_dispatch_readiness_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
        "ready": True,
        "production_ready": True,
        "dispatch_binding": _worker_dispatch_binding_contract(),
        "idempotency": {
            "mode": "dispatch-state-dir",
            "durable": True,
            "scope": "worker deployment",
            "storage": {
                "exists": True,
                "directory": True,
                "symlink": False,
                "mode": "0750",
                "private_enough": True,
                "writable": True,
            },
            "blockers": [],
            "proof": (
                "Duplicate job/action dispatches are reserved through a configured "
                "non-secret state directory before worker spawn."
            ),
        },
        "configured": {
            "FUSEKIT_HOSTED_WORKER_SECRET": True,
            "FUSEKIT_HOSTED_WORKER_ID": True,
            "FUSEKIT_HOSTED_WORKER_WORKSPACE": False,
            "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR": True,
        },
        "invalid": [],
        "optional_runtime_env": [
            "FUSEKIT_HOSTED_WORKER_WORKSPACE",
            "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR",
        ],
        "required_runtime_env": [
            "FUSEKIT_HOSTED_WORKER_SECRET",
            "FUSEKIT_HOSTED_WORKER_ID",
        ],
        "secret_boundary": (
            "Dispatch readiness reports only configuration presence and shape errors. "
            "It never renders worker secrets, signed job tokens, HMAC signatures, "
            "provider credentials, GitHub installation tokens, or vault material."
        ),
    }


def test_verify_hosted_deployment_passes_launcher_and_dispatch_checks() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            _worker_dispatch_readiness_contract(),
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
    assert report["readiness_summary"] == {
        "launchable": True,
        "blocking_count": 0,
        "blockers": [],
        "next_actions": [],
        "secret_boundary": (
            "Readiness summary contains public check ids, failure codes, and redacted "
            "next actions only."
        ),
    }
    assert report["next_actions"] == []
    assert [check["id"] for check in report["checks"]] == [
        "hosted.dns",
        "hosted.home",
        "hosted.health",
        "hosted.readiness",
        "hosted.deployment",
        "hosted.github_intake",
        "worker_dispatch.dns",
        "worker_dispatch.health",
        "worker_dispatch.readiness",
    ]
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["hosted.dns"]["hostname"] == "fusekit.snowmanai.org"
    assert checks["hosted.dns"]["addresses"] == PUBLIC_DNS_ADDRESSES
    assert checks["worker_dispatch.dns"]["hostname"] == "worker.snowmanai.org"
    assert checks["worker_dispatch.dns"]["addresses"] == PUBLIC_DNS_ADDRESSES
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
                "dispatch_binding": _worker_dispatch_binding_contract(),
                "idempotency": {
                    "mode": "process",
                    "durable": False,
                    "storage": {
                        "exists": False,
                        "directory": False,
                        "symlink": False,
                        "mode": "",
                        "private_enough": False,
                        "writable": False,
                    },
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
                "dispatch_binding": _worker_dispatch_binding_contract(),
                "idempotency": {
                    "mode": "dispatch-state-dir",
                    "durable": True,
                    "scope": "single receiver process",
                    "storage": {
                        "exists": True,
                        "directory": True,
                        "symlink": False,
                        "mode": "0750",
                        "private_enough": True,
                        "writable": True,
                    },
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


def test_verify_hosted_deployment_requires_worker_dispatch_readiness_binding_contract() -> None:
    readiness = _worker_dispatch_readiness_contract()
    binding = readiness["dispatch_binding"]
    assert isinstance(binding, dict)
    binding["required"] = False
    binding["required_fields"] = ["job_id", "action"]
    binding["payment_status"] = "checkout_pending"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            readiness,
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
        "worker_dispatch_binding_not_required",
        "worker_dispatch_binding_fields_mismatch",
        "worker_dispatch_binding_payment_status_mismatch",
    ]


def test_verify_hosted_deployment_rejects_worker_dispatch_readiness_sidecars() -> None:
    readiness = _worker_dispatch_readiness_contract()
    readiness["raw_log_excerpt"] = "dispatch worker log lines do not belong here"
    readiness["sk_live_readiness_field_should_not_echo"] = "public"
    binding = readiness["dispatch_binding"]
    idempotency = readiness["idempotency"]
    assert isinstance(binding, dict)
    assert isinstance(idempotency, dict)
    binding["stripe_price_id"] = "price_should_not_be_public_readiness"
    binding["ghp_binding_field_should_not_echo"] = "public"
    idempotency["state_dir"] = "/var/lib/fusekit/dispatch-state"
    storage = {
        "exists": True,
        "directory": True,
        "symlink": False,
        "mode": "0750",
        "private_enough": True,
        "writable": True,
        "path": "/var/lib/fusekit/dispatch-state",
    }
    idempotency["storage"] = storage
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            readiness,
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
    failures = checks["worker_dispatch.readiness"]["failures"]
    assert "sk_live_readiness_field_should_not_echo" not in json.dumps(report)
    assert "ghp_binding_field_should_not_echo" not in json.dumps(report)
    assert not contains_durable_secret_text(json.dumps(report))
    assert "public_json_contains_credential_text" in failures
    assert "worker_dispatch_readiness_unexpected_field:raw_log_excerpt" in failures
    assert "worker_dispatch_binding_unexpected_field:stripe_price_id" in failures
    assert "worker_dispatch_idempotency_unexpected_field:state_dir" in failures
    assert "worker_dispatch_idempotency_storage_unexpected_field:path" in failures
    assert any(
        failure.startswith("worker_dispatch_readiness_unexpected_field:")
        and "redacted" in failure.lower()
        for failure in failures
    )
    assert any(
        failure.startswith("worker_dispatch_binding_unexpected_field:")
        and "redacted" in failure.lower()
        for failure in failures
    )
    assert len(failures) == 7


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
    summary = report["readiness_summary"]
    assert summary["launchable"] is False
    assert summary["blocking_count"] == 2
    assert summary["blockers"][0]["check"] == "hosted.home"
    assert summary["blockers"][0]["failures"] == ["http_error"]
    assert report["next_actions"] == [
        (
            "Attach fusekit.snowmanai.org to the hosted origin, then set the "
            "Cloudflare fusekit CNAME to the exact provider-provided target. Do not "
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
    assert "provider-provided target" in checks["hosted.home"]["next_action"]
    assert "Vercel project" not in checks["hosted.home"]["next_action"]
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


def test_verify_hosted_deployment_requires_readiness_lane_contract() -> None:
    readiness = _readiness_contract()
    readiness.pop("lane_readiness")
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
    assert "lane_readiness_missing" in checks["hosted.readiness"]["failures"]


def test_verify_hosted_deployment_rejects_blocked_recommended_lane() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    assert isinstance(lane_readiness, dict)
    lane_readiness["recommended_lane"] = MANAGED_FUSEKIT_RUN_LANE
    lane_readiness["launchable_lanes"] = [BYO_OCI_LANE]
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
    assert "lane_readiness_recommended_lane_not_launchable" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_byo_readiness_contract() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    assert isinstance(lane_readiness, dict)
    lanes = lane_readiness["lanes"]
    assert isinstance(lanes, dict)
    byo = lanes[BYO_OCI_LANE]
    assert isinstance(byo, dict)
    byo["requires_user_cloud_account"] = False
    byo["user_owned_cost_boundary"] = {}
    byo["security_contract"] = {}
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
    assert "lane_readiness_byo_user_cloud_account_not_required" in checks[
        "hosted.readiness"
    ]["failures"]
    assert "lane_readiness_byo_cost_boundary_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "lane_readiness_byo_security_contract_mismatch" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_lane_cost_and_secret_boundary() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    assert isinstance(lane_readiness, dict)
    lane_readiness["cost_policy"] = "Hosted lanes are available."
    lane_readiness["secret_boundary"] = "Lane readiness exposes redacted status."
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
    assert "lane_readiness_cost_policy_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "lane_readiness_secret_boundary_mismatch" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_rejects_lane_readiness_sidecars() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    assert isinstance(lane_readiness, dict)
    lane_readiness["raw_oci_tenancy"] = "ocid1.tenancy.oc1..not-for-browser"
    lanes = lane_readiness["lanes"]
    assert isinstance(lanes, dict)
    lanes["internal-preview"] = {"launchable": True}
    managed = lanes[MANAGED_FUSEKIT_RUN_LANE]
    byo = lanes[BYO_OCI_LANE]
    assert isinstance(managed, dict)
    assert isinstance(byo, dict)
    managed["stripe_price_id"] = "price_live_sidecar"
    byo["worker_ocid"] = "ocid1.instance.oc1..not-for-browser"
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
    failures = checks["hosted.readiness"]["failures"]
    assert "lane_readiness_unexpected_field:raw_oci_tenancy" in failures
    assert "lane_readiness_unexpected_lane:internal-preview" in failures
    assert "lane_readiness_managed_unexpected_field:stripe_price_id" in failures
    assert "lane_readiness_byo_unexpected_field:worker_ocid" in failures


def test_verify_hosted_deployment_requires_payment_cost_control_contract() -> None:
    readiness = _readiness_contract()
    payment = readiness["payment"]
    assert isinstance(payment, dict)
    payment["stripe_customer_id"] = "cus_hidden_sidecar"
    payment["secret_boundary"] = "Stripe is configured."
    cost_controls = payment["cost_controls"]
    assert isinstance(cost_controls, dict)
    cost_controls["max_unverified_managed_spend_cents"] = 100
    cost_controls["dispatch_requires_paid_checkout_session"] = False
    cost_controls["reuse_across_jobs_allowed"] = True
    cost_controls["session_binding"] = ["client_reference_id", "job_id"]
    cost_controls["raw_checkout_session"] = "cs_live_not-for-readiness"
    operator_setup = payment["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["stripe_dashboard_url"] = "https://dashboard.stripe.com"
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
    failures = checks["hosted.readiness"]["failures"]
    assert "payment_readiness_unexpected_field:stripe_customer_id" in failures
    assert "payment_readiness_secret_boundary_mismatch" in failures
    assert "payment_cost_controls_unexpected_field:raw_checkout_session" in failures
    assert "payment_cost_controls_unverified_spend_mismatch" in failures
    assert "payment_cost_controls_paid_checkout_required_mismatch" in failures
    assert "payment_cost_controls_reuse_policy_mismatch" in failures
    assert "payment_cost_controls_session_binding_mismatch" in failures
    assert "payment_operator_setup_unexpected_field:stripe_dashboard_url" in failures


def test_verify_hosted_deployment_rejects_managed_lane_without_price_label() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    payment = readiness["payment"]
    assert isinstance(lane_readiness, dict)
    assert isinstance(payment, dict)
    lane_readiness["recommended_lane"] = MANAGED_FUSEKIT_RUN_LANE
    lane_readiness["launchable_lanes"] = [MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE]
    lanes = lane_readiness["lanes"]
    assert isinstance(lanes, dict)
    managed = lanes[MANAGED_FUSEKIT_RUN_LANE]
    assert isinstance(managed, dict)
    managed["launchable"] = True
    managed["managed_worker_dispatch_allowed"] = True
    managed["blocking_checks"] = []
    managed["next_actions"] = []
    payment["enabled"] = True
    payment["managed_runs_enabled"] = True
    payment["secret_key_configured"] = True
    payment["account_mode"] = "live"
    payment["live_mode_configured"] = True
    payment["test_mode_allowed"] = False
    payment["price_configured"] = True
    payment["price_label_configured"] = False
    payment["price_label"] = ""
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
    assert "payment_readiness_price_label_not_configured" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_rejects_launchable_managed_lane_in_test_mode() -> None:
    readiness = _readiness_contract()
    lane_readiness = readiness["lane_readiness"]
    payment = readiness["payment"]
    assert isinstance(lane_readiness, dict)
    assert isinstance(payment, dict)
    lane_readiness["recommended_lane"] = MANAGED_FUSEKIT_RUN_LANE
    lane_readiness["launchable_lanes"] = [MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE]
    lanes = lane_readiness["lanes"]
    assert isinstance(lanes, dict)
    managed = lanes[MANAGED_FUSEKIT_RUN_LANE]
    assert isinstance(managed, dict)
    managed["launchable"] = True
    managed["managed_worker_dispatch_allowed"] = True
    managed["blocking_checks"] = []
    managed["next_actions"] = []
    payment["enabled"] = True
    payment["managed_runs_enabled"] = True
    payment["secret_key_configured"] = True
    payment["account_mode"] = "test"
    payment["live_mode_configured"] = False
    payment["test_mode_allowed"] = False
    payment["price_configured"] = True
    payment["price_label_configured"] = True
    payment["price_label"] = "Test mode: $1.00 FuseKit managed run validation"
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
    assert "payment_readiness_live_mode_configured_false_when_enabled" in checks[
        "hosted.readiness"
    ]["failures"]
    assert "payment_readiness_account_mode_not_live" in checks["hosted.readiness"][
        "failures"
    ]


def test_verify_hosted_deployment_allows_staged_managed_price_configuration() -> None:
    readiness = _readiness_contract()
    payment = readiness["payment"]
    assert isinstance(payment, dict)
    payment["secret_key_configured"] = True
    payment["price_configured"] = True
    payment["price_label_configured"] = True
    payment["price_label"] = "Test mode: $1.00 FuseKit managed run validation"
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness),
            {"ok": True},
            readiness,
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            _worker_dispatch_readiness_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is True
    assert checks["hosted.home"]["status"] == "ok"
    assert checks["hosted.readiness"]["status"] == "ok"


def test_verify_hosted_deployment_rejects_ambiguous_payment_price_label() -> None:
    readiness = _readiness_contract()
    payment = readiness["payment"]
    assert isinstance(payment, dict)
    payment["secret_key_configured"] = True
    payment["price_configured"] = True
    payment["price_label_configured"] = True
    payment["price_label"] = "Launch validation: .00 FuseKit managed run"
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness),
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
    assert "payment_readiness_price_label_invalid" in checks["hosted.readiness"][
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
    assert "Vercel project" not in checks["hosted.home"]["next_action"]


def test_verify_hosted_deployment_requires_runtime_and_dns_contract() -> None:
    contract = _deployment_contract()
    runtime = contract["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "runtime.txt"
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_type"] = "A"
    cloudflare_dns["dry_run_policy"] = {"allowed_fqdn": "www.snowmanai.org"}
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
    assert "cloudflare_dns_dry_run_policy_mismatch" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_provider_permissions_and_rollback_contract() -> None:
    contract = _deployment_contract()
    provider_permissions = contract["provider_permissions"]
    assert isinstance(provider_permissions, dict)
    provider_permissions["cloudflare"] = {
        "visible_label": "Cloudflare",
        "requested_permissions": ["any DNS record"],
    }
    rollback_requirements = contract["rollback_requirements"]
    assert isinstance(rollback_requirements, dict)
    rollback_requirements["post_rollback_verification_required"] = False
    rollback_requirements["secret_boundary"] = "Rollback proof may include provider tokens."
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
    failures = checks["hosted.deployment"]["failures"]
    assert "provider_permissions_mismatch" in failures
    assert "rollback_requirements_post_rollback_verification_required_mismatch" in failures
    assert "rollback_requirements_secret_boundary_missing" in failures


def test_verify_hosted_deployment_rejects_dns_and_rollback_sidecars() -> None:
    contract = _deployment_contract()
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["zone_id"] = "redacted-zone-id-does-not-belong"
    dry_run_policy = cloudflare_dns["dry_run_policy"]
    assert isinstance(dry_run_policy, dict)
    dry_run_policy["raw_diff"] = "would upsert fusekit.snowmanai.org"
    rollback_requirements = contract["rollback_requirements"]
    assert isinstance(rollback_requirements, dict)
    rollback_requirements["raw_provider_inventory"] = "cloudflare zone export"
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
    failures = checks["hosted.deployment"]["failures"]
    assert "cloudflare_dns_unexpected_field:zone_id" in failures
    assert "cloudflare_dns_dry_run_policy_unexpected_field:raw_diff" in failures
    assert "rollback_requirements_unexpected_field:raw_provider_inventory" in failures


def test_hosted_deployment_contract_exposes_exact_provider_permission_copy() -> None:
    contract = _deployment_contract()

    assert contract["provider_permissions"] == HOSTED_PROVIDER_PERMISSION_COPY
    assert "MailPilot records" in contract["provider_permissions"]["cloudflare"][
        "forbidden_permissions"
    ]


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


def test_verify_hosted_deployment_requires_payment_operator_setup_contract() -> None:
    readiness = _readiness_contract()
    payment = readiness["payment"]
    assert isinstance(payment, dict)
    operator_setup = payment["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["helper_command"] = "stripe dashboard manual setup"
    operator_setup["verification_command"] = "stripe dashboard manual verification"
    operator_setup["module_fallback"] = "python -m snowman.shared_stripe_setup"
    operator_setup["verification_module_fallback"] = "python -m snowman.shared_stripe_verify"
    operator_setup["mutation_requires"] = ["--execute"]
    operator_setup["lookup_key_policy"] = "Manual dashboard search is enough."
    operator_setup["shared_account_boundary"] = "May reuse existing Snowman AI products."
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
    assert "payment_operator_setup_helper_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "payment_operator_setup_verification_helper_mismatch" in checks[
        "hosted.readiness"
    ]["failures"]
    assert "payment_operator_setup_module_fallback_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "payment_operator_setup_verification_module_fallback_mismatch" in checks[
        "hosted.readiness"
    ]["failures"]
    assert "payment_operator_setup_mutation_gate_mismatch" in checks["hosted.readiness"][
        "failures"
    ]
    assert "payment_operator_setup_lookup_key_policy_mismatch" in checks[
        "hosted.readiness"
    ]["failures"]
    assert "payment_operator_setup_shared_account_boundary_mismatch" in checks[
        "hosted.readiness"
    ]["failures"]


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


def test_verify_hosted_deployment_requires_worker_dispatch_binding_contract() -> None:
    contract = _deployment_contract()
    worker_dispatch = contract["worker_dispatch"]
    assert isinstance(worker_dispatch, dict)
    binding = worker_dispatch["dispatch_binding"]
    assert isinstance(binding, dict)
    binding["required_for_actions"] = ["start"]
    binding["hash_fields"] = ["plan_fingerprint"]
    binding["secret_boundary"] = "Public dispatch labels only."
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
    assert "worker_dispatch_binding_actions_mismatch" in failures
    assert "worker_dispatch_binding_hash_fields_mismatch" in failures
    assert "worker_dispatch_binding_secret_boundary_missing" in failures


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
            _worker_dispatch_readiness_contract(),
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


def test_verify_hosted_deployment_accepts_oci_source_provenance_contract() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _oci_source_provenance_contract()
    oci_deployment = _oci_deployment_contract()
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=oci_deployment),
            {"ok": True},
            readiness,
            oci_deployment,
            _github_intake_contract(),
            {"ok": True},
            _worker_dispatch_readiness_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is True
    assert checks["hosted.deployment"]["status"] == "ok"
    assert checks["hosted.readiness"]["status"] == "ok"


def test_verify_hosted_deployment_accepts_expected_commit_sha() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _oci_source_provenance_contract()
    oci_deployment = _oci_deployment_contract()
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=oci_deployment),
            {"ok": True},
            readiness,
            oci_deployment,
            _github_intake_contract(),
            {"ok": True},
            _worker_dispatch_readiness_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        expected_commit_sha=VERCEL_COMMIT_SHA,
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is True
    assert checks["hosted.expected_commit"]["status"] == "ok"
    assert checks["hosted.expected_commit"]["actual_commit_sha"] == VERCEL_COMMIT_SHA


def test_verify_hosted_deployment_rejects_stale_expected_commit_sha() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _oci_source_provenance_contract()
    oci_deployment = _oci_deployment_contract()
    expected_commit = "fedcba9876543210fedcba9876543210fedcba98"
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=oci_deployment),
            {"ok": True},
            readiness,
            oci_deployment,
            _github_intake_contract(),
            {"ok": True},
            _worker_dispatch_readiness_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        expected_commit_sha=expected_commit,
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "hosted.expected_commit" in report["blocking_checks"]
    assert checks["hosted.expected_commit"]["expected_commit_sha"] == expected_commit
    assert checks["hosted.expected_commit"]["actual_commit_sha"] == VERCEL_COMMIT_SHA
    assert checks["hosted.expected_commit"]["failures"] == ["expected_commit_sha_mismatch"]
    assert "Redeploy the hosted launcher" in checks["hosted.expected_commit"]["next_action"]


def test_verify_hosted_deployment_rejects_invalid_expected_commit_sha() -> None:
    with pytest.raises(FuseKitError, match="expected_commit_sha"):
        verify_hosted_deployment(
            origin="https://fusekit.snowmanai.org",
            expected_commit_sha="main",
            opener=SequenceOpener([]),
            dns_resolver=_public_dns_resolver,
        )


def test_verify_hosted_deployment_rejects_provider_copy_drift_on_homepage() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _aws_source_provenance_contract()
    aws_deployment = _aws_deployment_contract()
    home = _home_html(readiness=readiness, deployment=aws_deployment).replace(
        "<section>Hosted deployment contract</section>",
        (
            "<section>Hosted deployment contract</section>"
            "<section>Vercel must serve app.py.</section>"
            "<section>Add fusekit.snowmanai.org as the Vercel custom domain.</section>"
            "<section>Use the exact Vercel-provided CNAME target.</section>"
        ),
    )
    opener = SequenceOpener(
        [
            home,
            {"ok": True},
            readiness,
            aws_deployment,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert checks["hosted.home"]["status"] == "failed"
    assert "hosted_home_provider_copy_vercel_leak" in checks["hosted.home"]["failures"]


def test_verify_hosted_deployment_rejects_aws_provenance_url_drift() -> None:
    readiness = _readiness_contract()
    readiness["required_source_provenance_env"] = list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    provenance = _aws_source_provenance_contract()
    actual = provenance["actual"]
    assert isinstance(actual, dict)
    actual["deployment_url"] = "https://fusekit.snowmanai.org"
    readiness["source_provenance"] = provenance
    aws_deployment = _aws_deployment_contract()
    aws_deployment["source_provenance"] = provenance
    aws_deployment["required_source_provenance_env"] = list(HOSTED_AWS_SOURCE_PROVENANCE_ENV)
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=aws_deployment),
            {"ok": True},
            readiness,
            aws_deployment,
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
    assert (
        "readiness_source_provenance_deployment_url_invalid"
        in checks["hosted.readiness"]["failures"]
    )
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "source_provenance_deployment_url_invalid" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_rejects_vercel_provenance_url_drift() -> None:
    readiness = _readiness_contract()
    provenance = _source_provenance_contract()
    actual = provenance["actual"]
    assert isinstance(actual, dict)
    actual["deployment_url"] = "https://fusekit.snowmanai.org"
    readiness["source_provenance"] = provenance
    deployment = _deployment_contract()
    deployment["source_provenance"] = provenance
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=deployment),
            {"ok": True},
            readiness,
            deployment,
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
    assert (
        "readiness_source_provenance_deployment_url_invalid"
        in checks["hosted.readiness"]["failures"]
    )
    assert "source_provenance_deployment_url_invalid" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_rejects_unknown_provider_without_vercel_fallback() -> None:
    readiness = _readiness_contract()
    readiness["ready"] = False
    readiness["blocking_checks"] = [
        "invalid:hosted_deployment_provider_required",
        "invalid:source_provenance_not_verified",
    ]
    readiness["next_actions"] = [
        "Set FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER to oci-compute, aws-elastic-beanstalk, or vercel."
    ]
    readiness["required_source_provenance_env"] = list(HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV)
    readiness["source_provenance"] = _unknown_source_provenance_contract()
    deployment = _unknown_deployment_contract()
    opener = SequenceOpener(
        [
            _home_html(readiness=readiness, deployment=deployment),
            {"ok": True},
            readiness,
            deployment,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    deployment_failures = checks["hosted.deployment"]["failures"]

    assert report["ready"] is False
    assert "source_provenance_provider_mismatch" in deployment_failures
    assert "runtime_provider_mismatch" not in deployment_failures
    assert "operator_setup_steps_mismatch" not in deployment_failures
    assert "required_source_provenance_env_mismatch" not in deployment_failures
    assert "source_provenance_source_mismatch" not in deployment_failures
    assert "source_provenance_secret_boundary_missing" not in deployment_failures
    assert "Vercel" not in json.dumps(checks["hosted.deployment"])


def test_verify_hosted_deployment_requires_one_click_contract() -> None:
    contract = _deployment_contract()
    one_click = contract["one_click_launch"]
    assert isinstance(one_click, dict)
    one_click["no_terminal_promise"] = "Download the CLI and paste this command."
    one_click["terminal_required"] = True
    one_click["download_required"] = True
    one_click["lanes"] = {}
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
    assert "one_click_launch_lanes_mismatch" in checks["hosted.deployment"]["failures"]
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


def test_verify_hosted_deployment_requires_launch_lane_contract() -> None:
    contract = _deployment_contract()
    launch_lanes = contract["launch_lanes"]
    assert isinstance(launch_lanes, dict)
    lanes = launch_lanes["lanes"]
    assert isinstance(lanes, list)
    byo_lane = next(lane for lane in lanes if lane["id"] == BYO_OCI_LANE)
    assert isinstance(byo_lane, dict)
    byo_lane.pop("security_contract")
    opener = SequenceOpener(
        [
            _home_html(deployment=contract),
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
    assert "launch_lanes_contract_mismatch" in checks["hosted.deployment"]["failures"]
    assert "hosted_home_embedded_deployment_launch_lanes_contract_mismatch" in checks[
        "hosted.home"
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


def test_verify_hosted_deployment_rejects_html_escaped_embedded_json_contracts() -> None:
    home = _home_html()
    for script_id, contract in {
        "fusekit-github-intake": _github_intake_contract(),
        "fusekit-hosted-readiness": _readiness_contract(),
        "fusekit-hosted-deployment": _deployment_contract(),
    }.items():
        direct = _json_script(script_id, json_script_payload(contract))
        escaped_payload = json.dumps(contract, sort_keys=True).replace('"', "&quot;")
        escaped = _json_script(script_id, escaped_payload)
        home = home.replace(direct, escaped)
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
    assert "hosted_home_embedded_github_intake_contract_not_direct_json" in failures
    assert "hosted_home_embedded_readiness_contract_not_direct_json" in failures
    assert "hosted_home_embedded_deployment_contract_not_direct_json" in failures


def test_verify_hosted_deployment_rejects_duplicate_embedded_json_contracts() -> None:
    home = _home_html()
    for script_id, contract in {
        "fusekit-github-intake": _github_intake_contract(),
        "fusekit-hosted-readiness": _readiness_contract(),
        "fusekit-hosted-deployment": _deployment_contract(),
    }.items():
        direct = _json_script(script_id, json_script_payload(contract))
        duplicate = _json_script(script_id, json_script_payload(contract))
        home = home.replace(direct, f"{duplicate}{direct}")
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
    assert "hosted_home_embedded_github_intake_contract_duplicate" in failures
    assert "hosted_home_embedded_readiness_contract_duplicate" in failures
    assert "hosted_home_embedded_deployment_contract_duplicate" in failures


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
    assert report["blocking_checks"] == ["hosted.dns"]
    assert checks["hosted.dns"]["status"] == "failed"
    assert checks["hosted.dns"]["failures"] == ["dns_no_addresses"]
    assert "Cloudflare fusekit CNAME" in checks["hosted.dns"]["next_action"]
    assert opener.requests == []


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
    assert report["blocking_checks"] == ["hosted.dns"]
    assert checks["hosted.dns"]["failures"] == ["dns_non_public_address"]
    assert checks["hosted.dns"]["addresses"] == ["127.0.0.1"]
    assert opener.requests == []


def test_verify_hosted_deployment_rejects_private_worker_dispatch_dns_before_fetch() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            _readiness_contract(),
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    def resolver(hostname: str) -> list[str]:
        if hostname == "fusekit.snowmanai.org":
            return PUBLIC_DNS_ADDRESSES
        if hostname == "worker.snowmanai.org":
            return ["127.0.0.1"]
        raise AssertionError(hostname)

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert report["blocking_checks"] == ["worker_dispatch.dns"]
    assert checks["worker_dispatch.dns"]["status"] == "failed"
    assert checks["worker_dispatch.dns"]["failures"] == ["dns_non_public_address"]
    assert checks["worker_dispatch.dns"]["addresses"] == ["127.0.0.1"]
    assert "FUSEKIT_HOSTED_WORKER_DISPATCH_URL" in checks["worker_dispatch.dns"][
        "next_action"
    ]
    assert [request.full_url for request in opener.requests] == [
        "https://fusekit.snowmanai.org/",
        "https://fusekit.snowmanai.org/healthz",
        "https://fusekit.snowmanai.org/api/hosted/readiness",
        "https://fusekit.snowmanai.org/api/hosted/deployment",
        "https://fusekit.snowmanai.org/api/github/intake",
    ]


def _public_dns_resolver(hostname: str) -> list[str]:
    assert hostname in {"fusekit.snowmanai.org", "worker.snowmanai.org"}
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
    intake_payload = json_script_payload(github_intake)
    readiness_payload = json_script_payload(readiness)
    deployment_payload = json_script_payload(deployment)
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
        <section>Open core https://github.com/Fusekit-AI/fusekit</section>
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
        "lane_readiness": _lane_readiness_contract(),
        "payment": _payment_contract(),
    }


def _payment_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-payment.v1",
        "provider": "stripe-checkout",
        "enabled": False,
        "managed_runs_enabled": False,
        "secret_key_configured": True,
        "account_mode": "test",
        "live_mode_configured": False,
        "test_mode_allowed": False,
        "price_configured": False,
        "price_label_configured": False,
        "price_label": "",
        "required_for_lanes": [MANAGED_FUSEKIT_RUN_LANE],
        "mode": "payment",
        "cost_controls": {
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
        },
        "operator_setup": {
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
        },
        "secret_boundary": (
            "Stripe secret keys stay server-side. FuseKit never collects or renders card "
            "numbers, CVC, billing address fields, payment method ids, or Stripe client "
            "secrets in hosted pages, job tokens, receipts, or logs."
        ),
    }


def _lane_readiness_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-lane-readiness.v1",
        "default_lane": MANAGED_FUSEKIT_RUN_LANE,
        "recommended_lane": BYO_OCI_LANE,
        "launchable_lanes": [BYO_OCI_LANE],
        "lanes": {
            MANAGED_FUSEKIT_RUN_LANE: {
                "launchable": False,
                "requires_payment": True,
                "managed_worker_dispatch_allowed": False,
                "blocking_checks": [
                    "stripe_price_id_required_for_managed_runs",
                    "managed_run_price_label_required",
                ],
                "next_actions": [
                    (
                        "Run fusekit-hosted-stripe-price --execute --confirm-shared-account "
                        "to create a FuseKit-scoped Stripe Price, then set "
                        "FUSEKIT_STRIPE_PRICE_ID."
                    ),
                    (
                        "Use the fusekit-hosted-stripe-price output to set "
                        "FUSEKIT_MANAGED_RUN_PRICE_LABEL to the public price shown before "
                        "Checkout."
                    ),
                ],
            },
            BYO_OCI_LANE: {
                "launchable": True,
                "requires_payment": False,
                "managed_worker_dispatch_allowed": False,
                "requires_user_cloud_account": True,
                "user_owned_cost_boundary": byo_oci_user_owned_cost_boundary(),
                "security_contract": byo_oci_security_contract(),
                "blocking_checks": [],
                "next_actions": [],
            },
        },
        "cost_policy": (
            "Managed FuseKit runs are not launchable until server-side Stripe Checkout "
            "is fully configured and each job has a paid receipt. BYO OCI remains the "
            "no-FuseKit-managed-infrastructure lane."
        ),
        "secret_boundary": (
            "Lane readiness exposes only booleans, public lane ids, failure codes, and "
            "next-action labels. It never renders Stripe keys, GitHub tokens, worker "
            "secrets, OCI credentials, or vault material."
        ),
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
        "provider_permissions": dict(HOSTED_PROVIDER_PERMISSION_COPY),
        "launch_lanes": hosted_launch_lane_contract(),
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
            "lanes": hosted_launch_lane_contract(),
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
            "verification": "The subdomain must serve this app, not a Cloudflare error page.",
            "dry_run_policy": {
                "allowed_actions": ["create", "update", "upsert", "noop"],
                "allowed_fqdn": "fusekit.snowmanai.org",
                "forbidden_records": [
                    "snowmanai.org",
                    "www.snowmanai.org",
                    "*.snowmanai.org",
                ],
                "requires_visible_approval": True,
            },
        },
        "rollback_requirements": {
            "metadata_required_before_completion": True,
            "execution_receipt_required_for_rollback_request": True,
            "post_rollback_verification_required": True,
            "provider_inventory_required": True,
            "secret_boundary": (
                "Rollback requirements list provider surfaces and proof labels only. "
                "They do not include provider credentials, API tokens, or vault material."
            ),
        },
        "security_headers": dict(HOSTED_SECURITY_HEADERS_CONTRACT),
        "source_integrity": dict(HOSTED_SOURCE_INTEGRITY_CONTRACT),
        "source_provenance": _source_provenance_contract(),
        "open_core": {
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
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
            "dispatch_binding": _worker_dispatch_binding_contract(),
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
            "repo_owner": "Fusekit-AI",
            "repo_slug": "fusekit",
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
        },
        "actual": {
            "deployment_environment": "production",
            "deployment_url": "fusekit-snowmanai-org.vercel.app",
            "git_provider": "github",
            "repo_owner": "Fusekit-AI",
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


def _unknown_source_provenance_contract() -> dict[str, object]:
    return {
        "provider": "unknown",
        "source": "deployment_provider_not_selected",
        "expected": {
            "deployment_provider": "oci-compute | aws-elastic-beanstalk | vercel",
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
        },
        "actual": {
            "deployment_provider_configured": False,
            "selected_provider": "unknown",
        },
        "verified": False,
        "required_env": list(HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV),
        "secret_boundary": (
            "Source provenance publishes only the provider-selection state. It does not "
            "publish deployment credentials, GitHub installation tokens, provider "
            "credentials, or vault material."
        ),
    }


def _aws_source_provenance_contract() -> dict[str, object]:
    return {
        "provider": "aws-elastic-beanstalk",
        "source": "fusekit_hosted_environment_variables",
        "expected": {
            "deployment_environment": "production",
            "git_provider": "github",
            "repo_owner": "Fusekit-AI",
            "repo_slug": "fusekit",
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
        },
        "actual": {
            "deployment_environment": "production",
            "deployment_url": "https://fusekit-prod.us-east-1.elasticbeanstalk.com",
            "git_provider": "github",
            "repo_owner": "Fusekit-AI",
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


def _oci_source_provenance_contract() -> dict[str, object]:
    return {
        "provider": "oci-compute",
        "source": "fusekit_hosted_environment_variables",
        "expected": {
            "deployment_environment": "production",
            "git_provider": "github",
            "repo_owner": "Fusekit-AI",
            "repo_slug": "fusekit",
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
        },
        "actual": {
            "deployment_environment": "production",
            "deployment_url": "https://fusekit.snowmanai.org",
            "git_provider": "github",
            "repo_owner": "Fusekit-AI",
            "repo_slug": "fusekit",
            "commit_ref": "main",
            "commit_sha": VERCEL_COMMIT_SHA,
        },
        "verified": True,
        "required_env": list(HOSTED_OCI_SOURCE_PROVENANCE_ENV),
        "secret_boundary": (
            "Source provenance publishes only OCI/Git metadata. It does not publish "
            "OCI credentials, access keys, deploy hooks, GitHub installation tokens, "
            "provider credentials, or vault material."
        ),
    }


def _unknown_deployment_contract() -> dict[str, object]:
    contract = _deployment_contract()
    contract["runtime"] = {
        "provider": "unknown",
        "entrypoint": "app.py",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    contract["source_provenance"] = _unknown_source_provenance_contract()
    contract["required_source_provenance_env"] = list(HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV)
    contract["operator_setup"] = {
        "target_subdomain": "fusekit.snowmanai.org",
        "steps": [dict(step) for step in HOSTED_GENERIC_OPERATOR_SETUP_STEPS],
        "secret_boundary": (
            "Operator setup names provider surfaces and expected public proof only. "
            "It does not include AWS credentials, Vercel tokens, Cloudflare API tokens, "
            "GitHub private keys, HMAC secrets, or vault material."
        ),
    }
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_value"] = (
        "Use the exact target for the selected hosted deployment provider."
    )
    return contract


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


def _oci_deployment_contract() -> dict[str, object]:
    contract = _deployment_contract()
    contract["runtime"] = {
        "provider": "oci-compute",
        "entrypoint": "app.py",
        "process_config": "systemd:fusekit-hosted.service",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi-on-oci-compute",
    }
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_type"] = "A"
    cloudflare_dns["record_value"] = "Use the exact OCI reserved public IP address."
    contract["source_provenance"] = _oci_source_provenance_contract()
    contract["required_source_provenance_env"] = list(HOSTED_OCI_SOURCE_PROVENANCE_ENV)
    operator_setup = contract["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["steps"] = [dict(step) for step in HOSTED_OCI_OPERATOR_SETUP_STEPS]
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
            "source_repository": "https://github.com/Fusekit-AI/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
    }
