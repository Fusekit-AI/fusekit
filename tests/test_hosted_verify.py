from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.verify import (
    HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
    verify_hosted_deployment,
)


class FakeResponse:
    def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class SequenceOpener:
    def __init__(self, payloads: list[dict[str, object] | urllib.error.HTTPError]) -> None:
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
        return FakeResponse(payload)


def test_verify_hosted_deployment_passes_launcher_and_dispatch_checks() -> None:
    opener = SequenceOpener(
        [
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        opener=opener,
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
    assert report["ready"] is True
    assert [check["id"] for check in report["checks"]] == [
        "hosted.health",
        "hosted.readiness",
        "hosted.deployment",
        "worker_dispatch.health",
        "worker_dispatch.readiness",
    ]
    assert report["worker_dispatch_url"] == "https://worker.snowmanai.org/dispatch"
    assert opener.requests[0].full_url == "https://fusekit.snowmanai.org/healthz"
    assert opener.requests[3].full_url == "https://worker.snowmanai.org/healthz"
    assert opener.requests[4].full_url == "https://worker.snowmanai.org/readiness"
    assert "WORKER_SECRET" not in serialized
    assert "signed-public-job-token" not in serialized


def test_verify_hosted_deployment_reports_cloudflare_error_without_claiming_ready() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/healthz",
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
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.health"]["status"] == "failed"
    assert checks["hosted.health"]["http_status"] == 403
    assert checks["hosted.health"]["failures"] == ["http_error"]
    assert checks["hosted.health"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Vercel-provided target" in checks["hosted.health"]["next_action"]
    assert checks["hosted.readiness"]["failures"] == ["ready_field_not_true"]
    assert "test-ray-id" not in json.dumps(report)


def test_verify_hosted_deployment_rejects_non_origin_or_secret_url() -> None:
    with pytest.raises(FuseKitError, match="hosted_origin_must_be_https_origin"):
        verify_hosted_deployment(origin="https://user:pass@fusekit.snowmanai.org")

    with pytest.raises(FuseKitError, match="worker_dispatch_url_must_be_https"):
        verify_hosted_deployment(
            origin="https://fusekit.snowmanai.org",
            worker_dispatch_url="https://token@worker.snowmanai.org/dispatch",
        )


def test_verify_hosted_deployment_diagnoses_compact_cloudflare_1000_body() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/healthz",
                403,
                "Forbidden",
                {},
                io.BytesIO(b"error code: 1000\n"),
            ),
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert checks["hosted.health"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Cloudflare fusekit CNAME" in checks["hosted.health"]["next_action"]


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
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "runtime_python_version_mismatch" in checks["hosted.deployment"]["failures"]
    assert "cloudflare_record_type_mismatch" in checks["hosted.deployment"]["failures"]


def _deployment_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-deployment.v1",
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
        "open_core": {
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
    }
