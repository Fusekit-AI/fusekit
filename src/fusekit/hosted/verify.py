"""Outside-in verification for hosted FuseKit deployment."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

from fusekit.errors import FuseKitError
from fusekit.hosted.server import (
    HOSTED_DEPLOYMENT_SCHEMA_VERSION,
    HOSTED_READINESS_SCHEMA_VERSION,
)
from fusekit.hosted.worker_dispatch import HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION

HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION = "fusekit.hosted-deployment-verification.v1"


class UrlOpener(Protocol):
    """Subset of urllib opener used by hosted deployment verification."""

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> Any: ...


def verify_hosted_deployment(
    *,
    origin: str,
    worker_dispatch_url: str = "",
    opener: UrlOpener | None = None,
) -> dict[str, object]:
    """Verify hosted launcher and optional worker dispatch endpoints without secrets."""

    public_origin = _valid_public_origin(origin)
    checks: list[dict[str, object]] = []
    checks.append(
        _json_check(
            "hosted.health",
            f"{public_origin}/healthz",
            opener=opener,
            expect_ok_field=True,
        )
    )
    hosted_readiness = _json_check(
        "hosted.readiness",
        f"{public_origin}/api/hosted/readiness",
        opener=opener,
        expect_schema=HOSTED_READINESS_SCHEMA_VERSION,
        expect_ready_field=True,
    )
    checks.append(hosted_readiness)
    checks.append(
        _json_check(
            "hosted.deployment",
            f"{public_origin}/api/hosted/deployment",
            opener=opener,
            expect_schema=HOSTED_DEPLOYMENT_SCHEMA_VERSION,
        )
    )
    dispatch_public_url = ""
    if worker_dispatch_url:
        dispatch_public_url = _valid_https_url(worker_dispatch_url)
        dispatch_base = _worker_dispatch_receiver_base_url(dispatch_public_url)
        checks.append(
            _json_check(
                "worker_dispatch.health",
                f"{dispatch_base}/healthz",
                opener=opener,
                expect_ok_field=True,
            )
        )
        checks.append(
            _json_check(
                "worker_dispatch.readiness",
                f"{dispatch_base}/readiness",
                opener=opener,
                expect_schema=HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION,
                expect_ready_field=True,
            )
        )
    return {
        "schema_version": HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
        "public_origin": public_origin,
        "worker_dispatch_url": dispatch_public_url,
        "ready": all(check["status"] == "ok" for check in checks),
        "checks": checks,
        "secret_boundary": (
            "Hosted deployment verification fetches public JSON endpoints only. It never "
            "requires or returns GitHub private keys, worker secrets, HMAC signatures, "
            "provider credentials, signed job tokens, or vault material."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    """Run hosted deployment verification and print redacted JSON."""

    parser = argparse.ArgumentParser(description="Verify hosted FuseKit deployment endpoints")
    parser.add_argument("--origin", default="https://fusekit.snowmanai.org")
    parser.add_argument("--worker-dispatch-url", default="")
    args = parser.parse_args(argv)
    try:
        report = verify_hosted_deployment(
            origin=args.origin,
            worker_dispatch_url=args.worker_dispatch_url,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
            "ready": False,
            "error": str(exc),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 1


def _json_check(
    check_id: str,
    url: str,
    *,
    opener: UrlOpener | None,
    expect_schema: str = "",
    expect_ok_field: bool = False,
    expect_ready_field: bool = False,
) -> dict[str, object]:
    try:
        status, payload = _fetch_json(url, opener=opener)
    except urllib.error.HTTPError as exc:
        return _failed_check(check_id, url, "http_error", http_status=exc.code)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return _failed_check(check_id, url, exc.__class__.__name__)
    failures: list[str] = []
    if status >= 400:
        failures.append("http_error")
    schema = payload.get("schema_version")
    if expect_schema and schema != expect_schema:
        failures.append("schema_mismatch")
    if expect_ok_field and payload.get("ok") is not True:
        failures.append("ok_field_not_true")
    if expect_ready_field and payload.get("ready") is not True:
        failures.append("ready_field_not_true")
    return {
        "id": check_id,
        "url": _public_url(url),
        "status": "failed" if failures else "ok",
        "http_status": status,
        "schema_version": schema if isinstance(schema, str) else "",
        "failures": failures,
    }


def _fetch_json(
    url: str,
    *,
    opener: UrlOpener | None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "FuseKit"})
    actual_opener = opener or urllib.request.urlopen
    with actual_opener(request, timeout=20.0) as response:
        status = int(getattr(response, "status", 200))
        raw = response.read()
    payload = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(payload, dict):
        raise FuseKitError("Hosted verification endpoint returned non-object JSON.")
    return status, payload


def _failed_check(
    check_id: str,
    url: str,
    reason: str,
    *,
    http_status: int = 0,
) -> dict[str, object]:
    return {
        "id": check_id,
        "url": _public_url(url),
        "status": "failed",
        "http_status": http_status,
        "schema_version": "",
        "failures": [reason],
    }


def _valid_public_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path.rstrip("/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise FuseKitError("hosted_origin_must_be_https_origin")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _valid_https_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise FuseKitError("worker_dispatch_url_must_be_https")
    path = parsed.path or ""
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "", ""))


def _worker_dispatch_receiver_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    path = parsed.path.rstrip("/")
    if path == "/dispatch" or path.endswith("/dispatch"):
        path = path[: -len("/dispatch")]
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _public_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


if __name__ == "__main__":
    raise SystemExit(main())
