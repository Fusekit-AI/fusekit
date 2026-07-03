"""Outside-in verification for hosted FuseKit deployment."""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any, Protocol

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
    _valid_price_label,
)
from fusekit.hosted.evidence import HOSTED_COMPLETION_EVIDENCE_KEYS
from fusekit.hosted.github_app import (
    HOSTED_GITHUB_INTAKE_PERMISSIONS,
    hosted_github_public_token_boundary,
)
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
    hosted_launch_lane_contract,
)
from fusekit.hosted.launcher import (
    HOSTED_LAUNCH_PATH,
    HOSTED_PLAIN_LANGUAGE_JOURNEY,
    HOSTED_PROHIBITED_ACTIONS,
    HOSTED_PROOF_REQUIREMENTS,
    HOSTED_REVERSAL_PATH,
    NO_TERMINAL_PROMISE,
    TRUST_STORY,
)
from fusekit.hosted.server import (
    HOSTED_AWS_OPERATOR_SETUP_STEPS,
    HOSTED_AWS_SOURCE_PROVENANCE_ENV,
    HOSTED_CANONICAL_ORIGIN,
    HOSTED_CAPABILITY_VAULT_BOUNDARY,
    HOSTED_DEPLOYMENT_SCHEMA_VERSION,
    HOSTED_GENERIC_OPERATOR_SETUP_STEPS,
    HOSTED_OCI_OPERATOR_SETUP_STEPS,
    HOSTED_OCI_SOURCE_PROVENANCE_ENV,
    HOSTED_OPERATOR_SETUP_STEPS,
    HOSTED_PROVIDER_PERMISSION_COPY,
    HOSTED_PUBLIC_TRUST_CONTRACT,
    HOSTED_READINESS_SCHEMA_VERSION,
    HOSTED_SECURITY_HEADERS_CONTRACT,
    HOSTED_SOURCE_INTEGRITY_CONTRACT,
    HOSTED_SOURCE_PROVENANCE_ENV,
    HOSTED_SOURCE_REPOSITORY,
    HOSTED_SOURCE_REPOSITORY_NAME,
    HOSTED_SOURCE_REPOSITORY_OWNER,
    HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV,
    HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
    valid_hosted_aws_deployment_url,
    valid_hosted_oci_deployment_url,
    valid_hosted_vercel_deployment_url,
)
from fusekit.hosted.worker_dispatch import (
    HOSTED_WORKER_DISPATCH_BINDING_FIELDS,
    HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION,
)
from fusekit.security import contains_durable_secret_text

HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION = "fusekit.hosted-deployment-verification.v1"
HomeContractValidator = Callable[[dict[str, Any]], list[str]]
SECURITY_HEADER_NAMES = (
    "cache-control",
    "content-security-policy",
    "cross-origin-opener-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)


class UrlOpener(Protocol):
    """Subset of urllib opener used by hosted deployment verification."""

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> Any: ...


class DnsResolver(Protocol):
    """Subset of DNS resolution used by hosted deployment verification."""

    def __call__(self, hostname: str) -> list[str]: ...


def verify_hosted_deployment(
    *,
    origin: str,
    worker_dispatch_url: str = "",
    expected_commit_sha: str = "",
    opener: UrlOpener | None = None,
    dns_resolver: DnsResolver | None = None,
) -> dict[str, object]:
    """Verify hosted launcher and production worker dispatch endpoints without secrets."""

    public_origin = _valid_public_origin(origin)
    expected_commit = _valid_expected_commit_sha(expected_commit_sha)
    public_host = urllib.parse.urlparse(public_origin).hostname or ""
    dispatch_public_url = ""
    if worker_dispatch_url:
        dispatch_public_url = _valid_https_url(worker_dispatch_url)
    checks: list[dict[str, object]] = []
    hosted_dns = _dns_check("hosted.dns", public_host, resolver=dns_resolver)
    checks.append(hosted_dns)
    if hosted_dns.get("status") != "ok":
        return _deployment_verification_report(
            public_origin=public_origin,
            worker_dispatch_url=dispatch_public_url,
            checks=checks,
        )
    checks.append(
        _text_check(
            "hosted.home",
            f"{public_origin}/",
            opener=opener,
            expect_hosted_home=True,
            expected_public_origin=public_origin,
        )
    )
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
        expect_hosted_readiness_contract=True,
    )
    checks.append(hosted_readiness)
    hosted_deployment, deployment_payload = _json_check_with_payload(
        "hosted.deployment",
        f"{public_origin}/api/hosted/deployment",
        opener=opener,
        expect_schema=HOSTED_DEPLOYMENT_SCHEMA_VERSION,
        expect_hosted_runtime_contract=True,
        expected_public_origin=public_origin,
    )
    checks.append(hosted_deployment)
    if expected_commit:
        checks.append(_expected_commit_check(deployment_payload, expected_commit))
    checks.append(
        _json_check(
            "hosted.github_intake",
            f"{public_origin}/api/github/intake",
            opener=opener,
            expect_github_intake_contract=True,
        )
    )
    if not dispatch_public_url and all(check["status"] == "ok" for check in checks):
        dispatch_public_url = _worker_dispatch_url_from_deployment(deployment_payload)
    if dispatch_public_url:
        dispatch_base = _worker_dispatch_receiver_base_url(dispatch_public_url)
        dispatch_host = urllib.parse.urlparse(dispatch_base).hostname or ""
        dispatch_dns = _dns_check(
            "worker_dispatch.dns",
            dispatch_host,
            resolver=dns_resolver,
            next_action=(
                "Configure FUSEKIT_HOSTED_WORKER_DISPATCH_URL to an HTTPS worker "
                "dispatch endpoint that resolves only to internet-routable addresses."
            ),
        )
        checks.append(dispatch_dns)
        if dispatch_dns.get("status") == "ok":
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
                    expect_worker_dispatch_readiness=True,
                )
            )
    return _deployment_verification_report(
        public_origin=public_origin,
        worker_dispatch_url=dispatch_public_url,
        checks=checks,
    )


def _deployment_verification_report(
    *,
    public_origin: str,
    worker_dispatch_url: str,
    checks: list[dict[str, object]],
) -> dict[str, object]:
    blocking_checks = _blocking_check_ids(checks)
    return {
        "schema_version": HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
        "public_origin": public_origin,
        "worker_dispatch_url": worker_dispatch_url,
        "ready": not blocking_checks,
        "blocking_checks": blocking_checks,
        "readiness_summary": _readiness_summary(checks),
        "next_actions": _next_actions(checks),
        "checks": checks,
        "secret_boundary": (
            "Hosted deployment verification fetches public HTML/JSON endpoints only. It never "
            "requires or returns GitHub private keys, worker secrets, HMAC signatures, "
            "provider credentials, signed job tokens, or vault material."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    """Run hosted deployment verification and print redacted JSON."""

    parser = argparse.ArgumentParser(description="Verify hosted FuseKit deployment endpoints")
    parser.add_argument("--origin", default="https://fusekit.snowmanai.org")
    parser.add_argument("--worker-dispatch-url", default="")
    parser.add_argument(
        "--expected-commit-sha",
        default="",
        help="Optional exact Git commit SHA the public deployment must report.",
    )
    args = parser.parse_args(argv)
    try:
        report = verify_hosted_deployment(
            origin=args.origin,
            worker_dispatch_url=args.worker_dispatch_url,
            expected_commit_sha=args.expected_commit_sha,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
            "ready": False,
            "error": str(exc),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 1


def _blocking_check_ids(checks: list[dict[str, object]]) -> list[str]:
    return [
        str(check["id"])
        for check in checks
        if check.get("status") != "ok" and isinstance(check.get("id"), str)
    ]


def _next_actions(checks: list[dict[str, object]]) -> list[str]:
    actions: list[str] = []
    for check in checks:
        action = check.get("next_action")
        if isinstance(action, str) and action and action not in actions:
            actions.append(action)
    return actions


def _readiness_summary(checks: list[dict[str, object]]) -> dict[str, object]:
    blockers: list[dict[str, object]] = []
    for check in checks:
        if check.get("status") == "ok":
            continue
        check_id = check.get("id")
        if not isinstance(check_id, str):
            continue
        failures = check.get("failures")
        failure_codes = [
            str(failure)
            for failure in failures
            if isinstance(failure, str)
        ] if isinstance(failures, list) else []
        blocker: dict[str, object] = {
            "check": check_id,
            "failures": failure_codes,
        }
        next_action = check.get("next_action")
        if isinstance(next_action, str) and next_action:
            blocker["next_action"] = next_action
        blockers.append(blocker)
    return {
        "launchable": not blockers,
        "blocking_count": len(blockers),
        "blockers": blockers,
        "next_actions": _next_actions(checks),
        "secret_boundary": (
            "Readiness summary contains public check ids, failure codes, and redacted "
            "next actions only."
        ),
    }


def _text_check(
    check_id: str,
    url: str,
    *,
    opener: UrlOpener | None,
    expect_hosted_home: bool = False,
    expected_public_origin: str = "",
) -> dict[str, object]:
    try:
        status, text, headers = _fetch_text(url, opener=opener)
    except urllib.error.HTTPError as exc:
        return _http_error_check(check_id, url, exc)
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError) as exc:
        return _failed_check(check_id, url, exc.__class__.__name__)
    failures: list[str] = []
    if status >= 400:
        failures.append("http_error")
    failures.extend(_security_header_failures(headers))
    failures.extend(_public_text_secret_failures(text))
    if expect_hosted_home:
        failures.extend(
            _hosted_home_failures(
                text,
                expected_public_origin=expected_public_origin,
            )
        )
    return {
        "id": check_id,
        "url": _public_url(url),
        "status": "failed" if failures else "ok",
        "http_status": status,
        "schema_version": "",
        "failures": failures,
    }


def _json_check(
    check_id: str,
    url: str,
    *,
    opener: UrlOpener | None,
    expect_schema: str = "",
    expect_ok_field: bool = False,
    expect_ready_field: bool = False,
    expect_hosted_readiness_contract: bool = False,
    expect_hosted_runtime_contract: bool = False,
    expect_github_intake_contract: bool = False,
    expect_worker_dispatch_readiness: bool = False,
    expected_public_origin: str = "",
) -> dict[str, object]:
    check, _payload = _json_check_with_payload(
        check_id,
        url,
        opener=opener,
        expect_schema=expect_schema,
        expect_ok_field=expect_ok_field,
        expect_ready_field=expect_ready_field,
        expect_hosted_readiness_contract=expect_hosted_readiness_contract,
        expect_hosted_runtime_contract=expect_hosted_runtime_contract,
        expect_github_intake_contract=expect_github_intake_contract,
        expect_worker_dispatch_readiness=expect_worker_dispatch_readiness,
        expected_public_origin=expected_public_origin,
    )
    return check


def _json_check_with_payload(
    check_id: str,
    url: str,
    *,
    opener: UrlOpener | None,
    expect_schema: str = "",
    expect_ok_field: bool = False,
    expect_ready_field: bool = False,
    expect_hosted_readiness_contract: bool = False,
    expect_hosted_runtime_contract: bool = False,
    expect_github_intake_contract: bool = False,
    expect_worker_dispatch_readiness: bool = False,
    expected_public_origin: str = "",
) -> tuple[dict[str, object], dict[str, Any]]:
    try:
        status, payload, headers = _fetch_json(url, opener=opener)
    except urllib.error.HTTPError as exc:
        return _http_error_check(check_id, url, exc), {}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return _failed_check(check_id, url, exc.__class__.__name__), {}
    failures: list[str] = []
    if status >= 400:
        failures.append("http_error")
    failures.extend(_security_header_failures(headers))
    failures.extend(_public_payload_secret_failures(payload))
    schema = payload.get("schema_version")
    if expect_schema and schema != expect_schema:
        failures.append("schema_mismatch")
    if expect_ok_field and payload.get("ok") is not True:
        failures.append("ok_field_not_true")
    if expect_ready_field and payload.get("ready") is not True:
        failures.append("ready_field_not_true")
    if expect_hosted_readiness_contract:
        failures.extend(_hosted_home_readiness_failures(payload))
    if expect_hosted_runtime_contract:
        failures.extend(
            _hosted_runtime_contract_failures(
                payload,
                expected_public_origin=expected_public_origin,
            )
        )
    if expect_github_intake_contract:
        failures.extend(_github_intake_contract_failures(payload))
    if expect_worker_dispatch_readiness:
        failures.extend(_worker_dispatch_readiness_failures(payload))
    return (
        {
            "id": check_id,
            "url": _public_url(url),
            "status": "failed" if failures else "ok",
            "http_status": status,
            "schema_version": schema if isinstance(schema, str) else "",
            "failures": failures,
        },
        payload,
    )


def _expected_commit_check(
    deployment_payload: dict[str, Any],
    expected_commit_sha: str,
) -> dict[str, object]:
    actual_commit_sha = _deployment_commit_sha(deployment_payload)
    failures: list[str] = []
    if not actual_commit_sha:
        failures.append("expected_commit_actual_missing")
    elif actual_commit_sha != expected_commit_sha:
        failures.append("expected_commit_sha_mismatch")
    return {
        "id": "hosted.expected_commit",
        "status": "failed" if failures else "ok",
        "expected_commit_sha": expected_commit_sha,
        "actual_commit_sha": actual_commit_sha,
        "failures": failures,
        "next_action": (
            "Redeploy the hosted launcher from the expected commit and update "
            "FUSEKIT_HOSTED_GIT_COMMIT_SHA before claiming live release proof."
            if failures
            else ""
        ),
    }


def _deployment_commit_sha(deployment_payload: dict[str, Any]) -> str:
    provenance = deployment_payload.get("source_provenance")
    if not isinstance(provenance, dict):
        return ""
    actual = provenance.get("actual")
    if not isinstance(actual, dict):
        return ""
    commit_sha = actual.get("commit_sha")
    if not isinstance(commit_sha, str):
        return ""
    return commit_sha if re.fullmatch(r"[0-9a-f]{40}", commit_sha) else ""


def _worker_dispatch_url_from_deployment(payload: dict[str, Any]) -> str:
    worker_dispatch = payload.get("worker_dispatch")
    if not isinstance(worker_dispatch, dict):
        return ""
    checks = worker_dispatch.get("checks")
    if not isinstance(checks, dict):
        return ""
    dispatch_url = checks.get("dispatch")
    if not isinstance(dispatch_url, str) or not dispatch_url:
        return ""
    try:
        return _valid_https_url(dispatch_url)
    except FuseKitError:
        return ""


def _worker_dispatch_readiness_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    failures.extend(_worker_dispatch_binding_failures(payload.get("dispatch_binding")))
    idempotency = payload.get("idempotency")
    if not isinstance(idempotency, dict):
        return ["worker_dispatch_idempotency_missing"]
    if idempotency.get("durable") is not True:
        failures.append("worker_dispatch_idempotency_not_durable")
    mode = idempotency.get("mode")
    if mode not in {"dispatch-state-dir", "workspace"}:
        failures.append("worker_dispatch_idempotency_mode_not_production")
    elif mode == "dispatch-state-dir":
        if idempotency.get("scope") != "worker deployment":
            failures.append("worker_dispatch_idempotency_scope_mismatch")
    elif idempotency.get("scope") != "worker workspace":
        failures.append("worker_dispatch_idempotency_scope_mismatch")
    proof = idempotency.get("proof")
    if mode in {"dispatch-state-dir", "workspace"} and (
        not isinstance(proof, str) or "before worker spawn" not in proof
    ):
        failures.append("worker_dispatch_idempotency_proof_missing")
    production_ready = payload.get("production_ready")
    if production_ready is not True:
        failures.append("worker_dispatch_production_ready_not_true")
    return failures


def _worker_dispatch_binding_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["worker_dispatch_binding_missing"]
    if payload.get("required") is not True:
        failures.append("worker_dispatch_binding_not_required")
    if payload.get("required_fields") != list(HOSTED_WORKER_DISPATCH_BINDING_FIELDS):
        failures.append("worker_dispatch_binding_fields_mismatch")
    if payload.get("required_for_actions") != ["start", "rollback", "detonate"]:
        failures.append("worker_dispatch_binding_actions_mismatch")
    if payload.get("lane") != "managed-fusekit-run":
        failures.append("worker_dispatch_binding_lane_mismatch")
    if payload.get("payment_status") != "paid":
        failures.append("worker_dispatch_binding_payment_status_mismatch")
    if payload.get("hash_fields") != ["plan_fingerprint", "price_label_hash"]:
        failures.append("worker_dispatch_binding_hash_fields_mismatch")
    boundary = payload.get("secret_boundary")
    if (
        not isinstance(boundary, str)
        or "job tokens" not in boundary
        or "worker secrets" not in boundary
    ):
        failures.append("worker_dispatch_binding_secret_boundary_missing")
    return failures


def _dns_check(
    check_id: str,
    hostname: str,
    *,
    resolver: DnsResolver | None,
    next_action: str = "",
) -> dict[str, object]:
    failures: list[str] = []
    addresses: list[str] = []
    try:
        addresses = _resolve_public_addresses(hostname, resolver=resolver)
    except OSError:
        failures.append("dns_resolution_failed")
    if not addresses and not failures:
        failures.append("dns_no_addresses")
    if any(_is_non_public_address(address) for address in addresses):
        failures.append("dns_non_public_address")
    check: dict[str, object] = {
        "id": check_id,
        "url": f"dns://{hostname}",
        "status": "failed" if failures else "ok",
        "http_status": 0,
        "schema_version": "",
        "failures": failures,
        "hostname": hostname,
        "addresses": addresses,
    }
    if failures:
        check["next_action"] = next_action or (
            "Attach fusekit.snowmanai.org to the hosted origin, then set the "
            "Cloudflare fusekit CNAME to the exact provider-provided target and wait "
            "for public DNS to resolve to internet-routable addresses."
        )
    return check


def _resolve_public_addresses(
    hostname: str,
    *,
    resolver: DnsResolver | None,
) -> list[str]:
    if resolver is not None:
        return sorted(set(resolver(hostname)))
    rows = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for row in rows:
        sockaddr = row[4]
        if sockaddr:
            addresses.append(str(sockaddr[0]))
    return sorted(set(addresses))


def _is_non_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return not address.is_global


def _hosted_runtime_contract_failures(
    payload: dict[str, Any],
    *,
    expected_public_origin: str = "",
) -> list[str]:
    failures: list[str] = []
    if payload.get("canonical_origin") != HOSTED_CANONICAL_ORIGIN:
        failures.append("canonical_origin_mismatch")
    if expected_public_origin and payload.get("public_origin") != expected_public_origin:
        failures.append("public_origin_mismatch")
    if payload.get("domain") != urllib.parse.urlparse(HOSTED_CANONICAL_ORIGIN).hostname:
        failures.append("domain_mismatch")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict):
        return ["runtime_contract_missing"]
    trust_story = payload.get("trust_story")
    if trust_story != list(TRUST_STORY):
        failures.append("trust_story_mismatch")
    trust_contract = payload.get("trust_contract")
    if not isinstance(trust_contract, dict):
        failures.append("trust_contract_missing")
    else:
        expected_trust_keys = sorted(HOSTED_PUBLIC_TRUST_CONTRACT)
        actual_trust_keys = sorted(str(key) for key in trust_contract)
        if actual_trust_keys != expected_trust_keys:
            failures.append("trust_contract_keys_mismatch")
        for key in expected_trust_keys:
            if not isinstance(trust_contract.get(key), str) or not trust_contract.get(key):
                failures.append(f"trust_contract_{key}_missing")
    failures.extend(
        _capability_vault_boundary_failures(payload.get("capability_vault_boundary"))
    )
    failures.extend(_provider_permissions_failures(payload.get("provider_permissions")))
    failures.extend(_security_headers_contract_failures(payload.get("security_headers")))
    failures.extend(_source_integrity_contract_failures(payload.get("source_integrity")))
    failures.extend(_source_provenance_failures(payload.get("source_provenance")))
    failures.extend(_launch_lanes_contract_failures(payload.get("launch_lanes")))
    failures.extend(_one_click_launch_contract_failures(payload.get("one_click_launch")))
    failures.extend(_protected_controls_contract_failures(payload.get("protected_controls")))
    provider = str(runtime.get("provider") or "")
    expected_runtime = _expected_runtime_contract(provider)
    for key, expected in expected_runtime.items():
        if runtime.get(key) != expected:
            failures.append(f"runtime_{key}_mismatch")
    if not expected_runtime:
        failures.append("runtime_provider_mismatch")
    cloudflare_dns = payload.get("cloudflare_dns")
    if not isinstance(cloudflare_dns, dict):
        failures.append("cloudflare_dns_contract_missing")
    else:
        if cloudflare_dns.get("zone") != "snowmanai.org":
            failures.append("cloudflare_zone_mismatch")
        if cloudflare_dns.get("record_name") != "fusekit":
            failures.append("cloudflare_record_name_mismatch")
        if cloudflare_dns.get("record_type") != _expected_cloudflare_record_type(provider):
            failures.append("cloudflare_record_type_mismatch")
        dry_run_policy = cloudflare_dns.get("dry_run_policy")
        expected_dry_run_policy = {
            "allowed_actions": ["create", "update", "upsert", "noop"],
            "allowed_fqdn": "fusekit.snowmanai.org",
            "forbidden_records": ["snowmanai.org", "www.snowmanai.org", "*.snowmanai.org"],
            "requires_visible_approval": True,
        }
        if dry_run_policy != expected_dry_run_policy:
            failures.append("cloudflare_dns_dry_run_policy_mismatch")
    rollback_requirements = payload.get("rollback_requirements")
    if not isinstance(rollback_requirements, dict):
        failures.append("rollback_requirements_missing")
    else:
        expected_rollback_flags = {
            "metadata_required_before_completion": True,
            "execution_receipt_required_for_rollback_request": True,
            "post_rollback_verification_required": True,
            "provider_inventory_required": True,
        }
        for key, expected in expected_rollback_flags.items():
            if rollback_requirements.get(key) is not expected:
                failures.append(f"rollback_requirements_{key}_mismatch")
        boundary = rollback_requirements.get("secret_boundary")
        if not isinstance(boundary, str) or "do not include provider credentials" not in boundary:
            failures.append("rollback_requirements_secret_boundary_missing")
    open_core = payload.get("open_core")
    if not isinstance(open_core, dict):
        failures.append("open_core_contract_missing")
    else:
        if open_core.get("source_repository") != "https://github.com/Fusekit-AI/fusekit":
            failures.append("open_core_source_repository_mismatch")
        if open_core.get("license") != "MIT":
            failures.append("open_core_license_mismatch")
        if open_core.get("reviewable_entrypoint") != "app.py":
            failures.append("open_core_entrypoint_mismatch")
    github_app = payload.get("github_app")
    if not isinstance(github_app, dict):
        failures.append("github_app_contract_missing")
    else:
        if github_app.get("repository_permission") != "contents:read":
            failures.append("github_app_repository_permission_mismatch")
        if github_app.get("token_boundary") != hosted_github_public_token_boundary():
            failures.append("github_app_token_boundary_mismatch")
    operator_setup = payload.get("operator_setup")
    if not isinstance(operator_setup, dict):
        failures.append("operator_setup_contract_missing")
    else:
        if operator_setup.get("target_subdomain") != urllib.parse.urlparse(
            HOSTED_CANONICAL_ORIGIN
        ).hostname:
            failures.append("operator_setup_target_subdomain_mismatch")
        steps = operator_setup.get("steps")
        if not isinstance(steps, list):
            failures.append("operator_setup_steps_missing")
        else:
            expected_steps = [dict(step) for step in _expected_operator_setup_steps(provider)]
            actual_steps = [step for step in steps if isinstance(step, dict)]
            if actual_steps != expected_steps:
                failures.append("operator_setup_steps_mismatch")
    required_runtime_env = payload.get("required_runtime_env")
    if not isinstance(required_runtime_env, list):
        failures.append("required_runtime_env_missing")
    elif "FUSEKIT_HOSTED_WORKER_DISPATCH_URL" not in required_runtime_env:
        failures.append("worker_dispatch_runtime_env_not_required")
    optional_runtime_env = payload.get("optional_runtime_env")
    if optional_runtime_env != []:
        failures.append("optional_runtime_env_mismatch")
    expected_source_env = _expected_source_provenance_env(provider)
    if payload.get("required_source_provenance_env") != list(expected_source_env):
        failures.append("required_source_provenance_env_mismatch")
    failures.extend(_worker_dispatch_contract_failures(payload.get("worker_dispatch")))
    return failures


def _expected_runtime_contract(provider: str) -> dict[str, object]:
    if provider == "aws-elastic-beanstalk":
        return {
            "provider": "aws-elastic-beanstalk",
            "entrypoint": "app.py",
            "process_config": "Procfile",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        }
    if provider == "oci-compute":
        return {
            "provider": "oci-compute",
            "entrypoint": "app.py",
            "process_config": "systemd:fusekit-hosted.service",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi-on-oci-compute",
        }
    if provider == "vercel":
        return {
            "provider": "vercel",
            "entrypoint": "app.py",
            "routing_config": "vercel.json",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        }
    if provider == "unknown":
        return {
            "provider": "unknown",
            "entrypoint": "app.py",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        }
    return {}


def _expected_operator_setup_steps(provider: str) -> tuple[dict[str, str], ...]:
    if provider == "aws-elastic-beanstalk":
        return HOSTED_AWS_OPERATOR_SETUP_STEPS
    if provider == "oci-compute":
        return HOSTED_OCI_OPERATOR_SETUP_STEPS
    if provider == "unknown":
        return HOSTED_GENERIC_OPERATOR_SETUP_STEPS
    return HOSTED_OPERATOR_SETUP_STEPS


def _expected_source_provenance_env(provider: str) -> tuple[str, ...]:
    if provider == "aws-elastic-beanstalk":
        return HOSTED_AWS_SOURCE_PROVENANCE_ENV
    if provider == "oci-compute":
        return HOSTED_OCI_SOURCE_PROVENANCE_ENV
    if provider == "unknown":
        return HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV
    return HOSTED_SOURCE_PROVENANCE_ENV


def _expected_cloudflare_record_type(provider: str) -> str:
    if provider == "oci-compute":
        return "A"
    return "CNAME"


def _worker_dispatch_contract_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["worker_dispatch_contract_missing"]
    if payload.get("schema_version") != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        failures.append("worker_dispatch_schema_mismatch")
    if payload.get("receiver_command") != "fusekit-hosted-worker-dispatch":
        failures.append("worker_dispatch_receiver_command_mismatch")
    if payload.get("production_required") is not True:
        failures.append("worker_dispatch_production_required_not_true")
    if payload.get("no_terminal_wakeup_required") is not True:
        failures.append("worker_dispatch_no_terminal_wakeup_required_not_true")
    failures.extend(_worker_dispatch_binding_failures(payload.get("dispatch_binding")))
    checks = payload.get("checks")
    if not isinstance(checks, dict):
        failures.append("worker_dispatch_checks_missing")
        return failures
    dispatch_url = checks.get("dispatch")
    if not isinstance(dispatch_url, str) or not dispatch_url:
        failures.append("worker_dispatch_dispatch_url_missing")
    elif dispatch_url == "https://worker.invalid":
        failures.append("worker_dispatch_dispatch_url_placeholder")
    else:
        try:
            _valid_https_url(dispatch_url)
        except FuseKitError:
            failures.append("worker_dispatch_dispatch_url_invalid")
    health_url = checks.get("health")
    readiness_url = checks.get("readiness")
    if not isinstance(health_url, str) or not health_url.endswith("/healthz"):
        failures.append("worker_dispatch_health_url_invalid")
    if not isinstance(readiness_url, str) or not readiness_url.endswith("/readiness"):
        failures.append("worker_dispatch_readiness_url_invalid")
    return failures


def _capability_vault_boundary_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["capability_vault_boundary_missing"]
    expected = HOSTED_CAPABILITY_VAULT_BOUNDARY
    for key in ("raw_secret_policy", "generated_app_policy", "public_surface_policy"):
        if payload.get(key) != expected[key]:
            failures.append(f"capability_vault_boundary_{key}_mismatch")
    for key in ("forbidden_public_material", "allowed_public_material"):
        if payload.get(key) != expected[key]:
            failures.append(f"capability_vault_boundary_{key}_mismatch")
    return failures


def _provider_permissions_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["provider_permissions_missing"]
    if payload != HOSTED_PROVIDER_PERMISSION_COPY:
        failures.append("provider_permissions_mismatch")
    boundary = payload.get("secret_boundary")
    if not isinstance(boundary, str) or "contains no provider tokens" not in boundary:
        failures.append("provider_permissions_secret_boundary_missing")
    return failures


def _security_headers_contract_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["security_headers_contract_missing"]
    expected = HOSTED_SECURITY_HEADERS_CONTRACT
    if payload.get("applies_to") != expected["applies_to"]:
        failures.append("security_headers_applies_to_mismatch")
    if payload.get("required_headers") != expected["required_headers"]:
        failures.append("security_headers_required_headers_mismatch")
    if payload.get("requirements") != expected["requirements"]:
        failures.append("security_headers_requirements_mismatch")
    boundary = payload.get("secret_boundary")
    if not isinstance(boundary, str) or "do not include tokens" not in boundary:
        failures.append("security_headers_secret_boundary_missing")
    return failures


def _source_integrity_contract_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["source_integrity_contract_missing"]
    expected = HOSTED_SOURCE_INTEGRITY_CONTRACT
    for key in (
        "source_repository",
        "license",
        "deployment_model",
        "reviewable_files",
        "public_contract_endpoints",
        "private_generated_artifact_required",
    ):
        if payload.get(key) != expected[key]:
            failures.append(f"source_integrity_{key}_mismatch")
    boundary = payload.get("secret_boundary")
    if not isinstance(boundary, str) or "does not include build tokens" not in boundary:
        failures.append("source_integrity_secret_boundary_missing")
    return failures


def _source_provenance_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["source_provenance_contract_missing"]
    provider = str(payload.get("provider") or "")
    if provider not in {"vercel", "aws-elastic-beanstalk", "oci-compute"}:
        failures.append("source_provenance_provider_mismatch")
    if provider == "unknown":
        if payload.get("source") != "deployment_provider_not_selected":
            failures.append("source_provenance_source_mismatch")
        expected = payload.get("expected")
        if not isinstance(expected, dict):
            failures.append("source_provenance_expected_missing")
        else:
            if (
                expected.get("deployment_provider")
                != "oci-compute | aws-elastic-beanstalk | vercel"
            ):
                failures.append("source_provenance_expected_provider_selection_mismatch")
            if expected.get("source_repository") != HOSTED_SOURCE_REPOSITORY:
                failures.append("source_provenance_expected_source_repository_mismatch")
        actual = payload.get("actual")
        if not isinstance(actual, dict):
            failures.append("source_provenance_actual_missing")
        else:
            if not isinstance(actual.get("deployment_provider_configured"), bool):
                failures.append("source_provenance_actual_provider_configured_invalid")
            if actual.get("selected_provider") != "unknown":
                failures.append("source_provenance_actual_selected_provider_mismatch")
        if payload.get("verified") is not False:
            failures.append("source_provenance_unknown_provider_must_not_verify")
        if payload.get("required_env") != list(HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV):
            failures.append("source_provenance_required_env_mismatch")
        boundary = payload.get("secret_boundary")
        if not isinstance(boundary, str) or "provider-selection state" not in boundary:
            failures.append("source_provenance_secret_boundary_missing")
        return failures
    expected_source = (
        "vercel_system_environment_variables"
        if provider == "vercel"
        else "fusekit_hosted_environment_variables"
    )
    if payload.get("source") != expected_source:
        failures.append("source_provenance_source_mismatch")
    expected = payload.get("expected")
    if not isinstance(expected, dict):
        failures.append("source_provenance_expected_missing")
    else:
        if expected.get("deployment_environment") != "production":
            failures.append("source_provenance_expected_environment_mismatch")
        if expected.get("git_provider") != "github":
            failures.append("source_provenance_expected_git_provider_mismatch")
        if expected.get("repo_owner") != HOSTED_SOURCE_REPOSITORY_OWNER:
            failures.append("source_provenance_expected_repo_owner_mismatch")
        if expected.get("repo_slug") != HOSTED_SOURCE_REPOSITORY_NAME:
            failures.append("source_provenance_expected_repo_slug_mismatch")
        if expected.get("source_repository") != HOSTED_SOURCE_REPOSITORY:
            failures.append("source_provenance_expected_source_repository_mismatch")
    actual = payload.get("actual")
    if not isinstance(actual, dict):
        failures.append("source_provenance_actual_missing")
    else:
        if actual.get("deployment_environment") != "production":
            failures.append("source_provenance_actual_environment_mismatch")
        if actual.get("git_provider") != "github":
            failures.append("source_provenance_actual_git_provider_mismatch")
        if actual.get("repo_owner") != HOSTED_SOURCE_REPOSITORY_OWNER:
            failures.append("source_provenance_actual_repo_owner_mismatch")
        if actual.get("repo_slug") != HOSTED_SOURCE_REPOSITORY_NAME:
            failures.append("source_provenance_actual_repo_slug_mismatch")
        commit_ref = actual.get("commit_ref")
        if not isinstance(commit_ref, str) or not commit_ref:
            failures.append("source_provenance_commit_ref_missing")
        commit_sha = actual.get("commit_sha")
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            failures.append("source_provenance_commit_sha_invalid")
        if provider == "aws-elastic-beanstalk" and not valid_hosted_aws_deployment_url(
            actual.get("deployment_url")
        ):
            failures.append("source_provenance_deployment_url_invalid")
        if provider == "oci-compute" and not valid_hosted_oci_deployment_url(
            actual.get("deployment_url")
        ):
            failures.append("source_provenance_deployment_url_invalid")
        if provider == "vercel" and not valid_hosted_vercel_deployment_url(
            actual.get("deployment_url")
        ):
            failures.append("source_provenance_deployment_url_invalid")
    if payload.get("verified") is not True:
        failures.append("source_provenance_not_verified")
    expected_env = _expected_source_provenance_env(provider)
    if payload.get("required_env") != list(expected_env):
        failures.append("source_provenance_required_env_mismatch")
    boundary = payload.get("secret_boundary")
    required_boundary = (
        "does not publish AWS credentials"
        if provider == "aws-elastic-beanstalk"
        else "does not publish OCI credentials"
        if provider == "oci-compute"
        else "does not publish Vercel tokens"
    )
    if not isinstance(boundary, str) or required_boundary not in boundary:
        failures.append("source_provenance_secret_boundary_missing")
    return failures


def _one_click_launch_contract_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["one_click_launch_contract_missing"]
    if payload.get("public_url") != HOSTED_CANONICAL_ORIGIN:
        failures.append("one_click_launch_public_url_mismatch")
    if payload.get("start_control") != "Start hosted launch":
        failures.append("one_click_launch_start_control_mismatch")
    if payload.get("no_terminal_promise") != NO_TERMINAL_PROMISE:
        failures.append("one_click_launch_no_terminal_promise_mismatch")
    if payload.get("intake") != "github-app":
        failures.append("one_click_launch_intake_mismatch")
    if payload.get("repository_scope") != "one selected GitHub repository":
        failures.append("one_click_launch_repository_scope_mismatch")
    if payload.get("github_repository_permission") != "contents:read":
        failures.append("one_click_launch_github_permission_mismatch")
    if payload.get("lanes") != hosted_launch_lane_contract():
        failures.append("one_click_launch_lanes_mismatch")
    if payload.get("launch_path") != list(HOSTED_LAUNCH_PATH):
        failures.append("one_click_launch_path_mismatch")
    if payload.get("plain_language_journey") != list(HOSTED_PLAIN_LANGUAGE_JOURNEY):
        failures.append("one_click_launch_plain_language_journey_mismatch")
    if payload.get("prohibited") != list(HOSTED_PROHIBITED_ACTIONS):
        failures.append("one_click_launch_prohibited_mismatch")
    if payload.get("completion_requires") != list(HOSTED_PROOF_REQUIREMENTS):
        failures.append("one_click_launch_completion_requires_mismatch")
    if payload.get("completion_evidence_keys") != list(HOSTED_COMPLETION_EVIDENCE_KEYS):
        failures.append("one_click_launch_completion_evidence_keys_mismatch")
    if payload.get("reversal") != list(HOSTED_REVERSAL_PATH):
        failures.append("one_click_launch_reversal_mismatch")
    if payload.get("terminal_required") is not False:
        failures.append("one_click_launch_terminal_required_not_false")
    if payload.get("download_required") is not False:
        failures.append("one_click_launch_download_required_not_false")
    human_gates = payload.get("human_gates")
    if not isinstance(human_gates, list) or not human_gates:
        failures.append("one_click_launch_human_gates_missing")
    elif not any(isinstance(item, str) and "MFA" in item for item in human_gates):
        failures.append("one_click_launch_human_gates_mfa_missing")
    return failures


def _launch_lanes_contract_failures(payload: object) -> list[str]:
    if payload != hosted_launch_lane_contract():
        return ["launch_lanes_contract_mismatch"]
    return []


def _protected_controls_contract_failures(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["protected_controls_contract_missing"]
    expected = {
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
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            failures.append(f"protected_controls_{key}_mismatch")
    boundary = payload.get("secret_boundary")
    if not isinstance(boundary, str):
        failures.append("protected_controls_secret_boundary_missing")
    else:
        for required in ("action-bound", "must not appear in action URLs"):
            if required not in boundary:
                failures.append("protected_controls_secret_boundary_missing")
                break
    return failures


def _public_payload_secret_failures(payload: dict[str, Any]) -> list[str]:
    serialized = json.dumps(payload, sort_keys=True)
    if contains_durable_secret_text(serialized):
        return ["public_json_contains_credential_text"]
    return []


def _public_text_secret_failures(text: str) -> list[str]:
    if contains_durable_secret_text(text):
        return ["public_text_contains_credential_text"]
    return []


def _hosted_home_failures(
    text: str,
    *,
    expected_public_origin: str = "",
) -> list[str]:
    expected = {
        "hosted_home_headline_missing": "Launch any GitHub app without touching a terminal.",
        "hosted_home_start_control_missing": "Start hosted launch",
        "hosted_home_open_core_missing": "Open core",
        "hosted_home_reviewable_files_missing": "Reviewable hosted files",
        "hosted_home_source_integrity_entrypoint_missing": "app.py",
        "hosted_home_no_private_generated_artifact_missing": (
            "No private generated artifact is required for the hosted click flow."
        ),
        "hosted_home_deployment_provenance_missing": "Deployment provenance",
        "hosted_home_deployment_provenance_commit_missing": "Commit SHA",
        "hosted_home_narrow_permissions_missing": "narrow permissions",
        "hosted_home_visible_plan_missing": "visible plan",
        "hosted_home_redacted_proof_missing": "redacted proof",
        "hosted_home_capability_vault_boundary_missing": "Capability vault boundary",
        "hosted_home_raw_secret_policy_missing": (
            "Raw secrets must never leave the vault runtime."
        ),
        "hosted_home_selected_repository_boundary_missing": "selected repository only",
        "hosted_home_contents_read_boundary_missing": "contents:read",
        "hosted_home_metadata_read_boundary_missing": "metadata:read",
        "hosted_home_all_repository_rejection_missing": "all-repository",
        "hosted_home_contents_write_rejection_missing": "contents:write",
        "hosted_home_launch_path_missing": "What happens after the click",
        "hosted_home_prohibited_actions_missing": "What FuseKit will not do",
        "hosted_home_prohibited_mfa_bypass_missing": HOSTED_PROHIBITED_ACTIONS[0],
        "hosted_home_plain_language_click_path_missing": (
            "For someone who just wants to click"
        ),
        "hosted_home_plain_language_open_step_missing": HOSTED_PLAIN_LANGUAGE_JOURNEY[0],
        "hosted_home_plain_language_provider_step_missing": HOSTED_PLAIN_LANGUAGE_JOURNEY[5],
        "hosted_home_launch_readiness_missing": "Launch readiness",
        "hosted_home_completion_requirements_missing": "Completion requires",
        "hosted_home_live_url_proof_missing": "Live URL verification",
        "hosted_home_provider_verifier_proof_missing": "Provider verifier results",
        "hosted_home_dns_propagation_proof_missing": "DNS propagation status",
        "hosted_home_setup_receipt_proof_missing": "Redacted setup receipt",
        "hosted_home_audit_log_proof_missing": "Redacted audit log",
        "hosted_home_run_record_proof_missing": "Run Record",
        "hosted_home_detonation_receipt_missing": "Detonation receipt",
        "hosted_home_live_acceptance_report_missing": "Live acceptance report",
        "hosted_home_recording_proof_missing": "Recording proof",
        "hosted_home_reversible_setup_missing": "Reversible setup",
        "hosted_home_reversal_path_step_1_missing": HOSTED_REVERSAL_PATH[0],
        "hosted_home_reversal_path_step_2_missing": HOSTED_REVERSAL_PATH[1],
        "hosted_home_reversal_path_step_3_missing": HOSTED_REVERSAL_PATH[2],
        "hosted_home_provider_gates_missing": "What you may need to approve",
        "hosted_home_deployment_contract_missing": "Hosted deployment contract",
        "hosted_home_embedded_intake_contract_missing": 'id="fusekit-github-intake"',
        "hosted_home_embedded_readiness_contract_missing": 'id="fusekit-hosted-readiness"',
        "hosted_home_embedded_deployment_contract_missing": (
            'id="fusekit-hosted-deployment"'
        ),
        "hosted_home_source_repository_missing": "https://github.com/Fusekit-AI/fusekit",
    }
    failures = [failure for failure, marker in expected.items() if marker not in text]
    failures.extend(
        _hosted_home_embedded_contract_failures(
            text,
            expected_public_origin=expected_public_origin,
        )
    )
    return failures


def _hosted_home_embedded_contract_failures(
    text: str,
    *,
    expected_public_origin: str,
) -> list[str]:
    scripts = _embedded_json_scripts(text)
    checks: dict[str, tuple[str, HomeContractValidator]] = {
        "fusekit-github-intake": (
            "github_intake",
            lambda payload: _github_intake_contract_failures(payload),
        ),
        "fusekit-hosted-readiness": (
            "readiness",
            _hosted_home_readiness_failures,
        ),
        "fusekit-hosted-deployment": (
            "deployment",
            lambda payload: _hosted_runtime_contract_failures(
                payload,
                expected_public_origin=expected_public_origin,
            ),
        ),
    }
    failures: list[str] = []
    for script_id, (label, validator) in checks.items():
        raw = scripts.get(script_id)
        if raw is None:
            failures.append(f"hosted_home_embedded_{label}_contract_missing")
            continue
        try:
            payload = json.loads(html.unescape(raw))
        except json.JSONDecodeError:
            failures.append(f"hosted_home_embedded_{label}_contract_invalid_json")
            continue
        if not isinstance(payload, dict):
            failures.append(f"hosted_home_embedded_{label}_contract_not_object")
            continue
        secret_failures = _public_payload_secret_failures(payload)
        failures.extend(
            f"hosted_home_embedded_{label}_{failure}"
            for failure in secret_failures
        )
        contract_failures = validator(payload)
        failures.extend(
            f"hosted_home_embedded_{label}_{failure}"
            for failure in contract_failures
        )
        if script_id == "fusekit-hosted-deployment":
            failures.extend(_hosted_home_visible_deployment_failures(text, payload))
    return failures


def _hosted_home_visible_deployment_failures(
    text: str,
    payload: dict[str, Any],
) -> list[str]:
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict):
        return []
    provider = str(runtime.get("provider") or "")
    provider_forbidden_markers = {
        "aws-elastic-beanstalk": {
            "hosted_home_provider_copy_vercel_leak": (
                "Vercel must serve",
                "Vercel custom domain",
                "Vercel-provided CNAME target",
                "waiting for Vercel metadata",
            )
        },
        "oci-compute": {
            "hosted_home_provider_copy_vercel_leak": (
                "Vercel must serve",
                "Vercel custom domain",
                "Vercel-provided CNAME target",
                "waiting for Vercel metadata",
            ),
            "hosted_home_provider_copy_aws_leak": (
                "AWS Elastic Beanstalk must serve",
                "AWS HTTPS origin",
                "AWS-provided CNAME target",
                "waiting for AWS/Git metadata",
            ),
        },
        "vercel": {
            "hosted_home_provider_copy_aws_leak": (
                "AWS Elastic Beanstalk must serve",
                "AWS HTTPS origin",
                "AWS-provided CNAME target",
                "waiting for AWS/Git metadata",
            )
        },
    }
    failures: list[str] = []
    for failure, markers in provider_forbidden_markers.get(provider, {}).items():
        if any(marker in text for marker in markers):
            failures.append(failure)
    return failures


def _hosted_home_readiness_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != HOSTED_READINESS_SCHEMA_VERSION:
        failures.append("schema_mismatch")
    if payload.get("ready") is not True:
        failures.append("ready_field_not_true")
    if payload.get("ready") is True:
        if payload.get("blocking_checks") != []:
            failures.append("blocking_checks_not_empty")
        if payload.get("next_actions") != []:
            failures.append("next_actions_not_empty")
        provenance = payload.get("source_provenance")
        provider = (
            str(provenance.get("provider") or "") if isinstance(provenance, dict) else ""
        )
        expected_env = _expected_source_provenance_env(provider)
        if payload.get("required_source_provenance_env") != list(expected_env):
            failures.append("required_source_provenance_env_mismatch")
        for failure in _source_provenance_failures(provenance):
            failures.append(f"readiness_{failure}")
        lane_readiness = payload.get("lane_readiness")
        failures.extend(_lane_readiness_failures(lane_readiness))
        failures.extend(_payment_readiness_failures(payload.get("payment"), lane_readiness))
    return failures


def _lane_readiness_failures(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["lane_readiness_missing"]
    failures: list[str] = []
    if value.get("default_lane") != MANAGED_FUSEKIT_RUN_LANE:
        failures.append("lane_readiness_default_lane_mismatch")
    launchable_lanes = value.get("launchable_lanes")
    if not isinstance(launchable_lanes, list) or not launchable_lanes:
        failures.append("lane_readiness_launchable_lanes_missing")
        launchable_lanes = []
    elif any(lane not in {MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE} for lane in launchable_lanes):
        failures.append("lane_readiness_launchable_lanes_invalid")
    recommended_lane = value.get("recommended_lane")
    if recommended_lane not in {MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE}:
        failures.append("lane_readiness_recommended_lane_invalid")
    elif recommended_lane not in launchable_lanes:
        failures.append("lane_readiness_recommended_lane_not_launchable")
    cost_policy = value.get("cost_policy")
    if not _contains_all_markers(
        cost_policy,
        (
            "paid receipt",
            "BYO OCI",
            "no-FuseKit-managed-infrastructure",
        ),
    ):
        failures.append("lane_readiness_cost_policy_mismatch")
    secret_boundary = value.get("secret_boundary")
    if not _contains_all_markers(
        secret_boundary,
        (
            "Stripe keys",
            "GitHub tokens",
            "worker secrets",
            "OCI credentials",
            "vault material",
        ),
    ):
        failures.append("lane_readiness_secret_boundary_mismatch")
    lanes = value.get("lanes")
    if not isinstance(lanes, dict):
        return failures + ["lane_readiness_lanes_missing"]
    managed = lanes.get(MANAGED_FUSEKIT_RUN_LANE)
    byo = lanes.get(BYO_OCI_LANE)
    if not isinstance(managed, dict):
        failures.append("lane_readiness_managed_lane_missing")
    else:
        failures.extend(_managed_lane_readiness_failures(managed, launchable_lanes))
    if not isinstance(byo, dict):
        failures.append("lane_readiness_byo_oci_lane_missing")
    else:
        failures.extend(_byo_lane_readiness_failures(byo, launchable_lanes))
    return failures


def _contains_all_markers(value: object, markers: tuple[str, ...]) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower()
    return all(marker.lower() in normalized for marker in markers)


def _managed_lane_readiness_failures(
    lane: dict[str, Any],
    launchable_lanes: list[object],
) -> list[str]:
    failures: list[str] = []
    launchable = lane.get("launchable")
    if lane.get("requires_payment") is not True:
        failures.append("lane_readiness_managed_payment_not_required")
    if lane.get("managed_worker_dispatch_allowed") is not launchable:
        failures.append("lane_readiness_managed_dispatch_mismatch")
    blockers = lane.get("blocking_checks")
    if not isinstance(blockers, list):
        failures.append("lane_readiness_managed_blockers_invalid")
    elif launchable is True and blockers:
        failures.append("lane_readiness_managed_launchable_with_blockers")
    elif launchable is False and not blockers:
        failures.append("lane_readiness_managed_blocked_without_reason")
    if launchable is True and MANAGED_FUSEKIT_RUN_LANE not in launchable_lanes:
        failures.append("lane_readiness_managed_missing_from_launchable_lanes")
    if launchable is False and MANAGED_FUSEKIT_RUN_LANE in launchable_lanes:
        failures.append("lane_readiness_managed_blocked_but_listed")
    return failures


def _byo_lane_readiness_failures(
    lane: dict[str, Any],
    launchable_lanes: list[object],
) -> list[str]:
    failures: list[str] = []
    launchable = lane.get("launchable")
    if lane.get("requires_payment") is not False:
        failures.append("lane_readiness_byo_payment_required")
    if lane.get("managed_worker_dispatch_allowed") is not False:
        failures.append("lane_readiness_byo_dispatch_allowed")
    if lane.get("requires_user_cloud_account") is not True:
        failures.append("lane_readiness_byo_user_cloud_account_not_required")
    if lane.get("user_owned_cost_boundary") != byo_oci_user_owned_cost_boundary():
        failures.append("lane_readiness_byo_cost_boundary_mismatch")
    if lane.get("security_contract") != byo_oci_security_contract():
        failures.append("lane_readiness_byo_security_contract_mismatch")
    blockers = lane.get("blocking_checks")
    if not isinstance(blockers, list):
        failures.append("lane_readiness_byo_blockers_invalid")
    elif launchable is True and blockers:
        failures.append("lane_readiness_byo_launchable_with_blockers")
    if launchable is True and BYO_OCI_LANE not in launchable_lanes:
        failures.append("lane_readiness_byo_missing_from_launchable_lanes")
    if launchable is False and BYO_OCI_LANE in launchable_lanes:
        failures.append("lane_readiness_byo_blocked_but_listed")
    return failures


def _payment_readiness_failures(value: object, lane_readiness: object) -> list[str]:
    if not isinstance(value, dict):
        return ["payment_readiness_missing"]
    failures: list[str] = []
    if value.get("provider") != "stripe-checkout":
        failures.append("payment_readiness_provider_mismatch")
    if value.get("mode") != "payment":
        failures.append("payment_readiness_mode_mismatch")
    required_for_lanes = value.get("required_for_lanes")
    if required_for_lanes != [MANAGED_FUSEKIT_RUN_LANE]:
        failures.append("payment_readiness_required_lanes_mismatch")
    enabled = value.get("enabled")
    managed_launchable = _managed_lane_launchable(lane_readiness)
    if managed_launchable is True and enabled is not True:
        failures.append("payment_readiness_disabled_for_launchable_managed_lane")
    if enabled is True and managed_launchable is not True:
        failures.append("payment_readiness_enabled_for_blocked_managed_lane")
    label_configured = value.get("price_label_configured")
    label = value.get("price_label")
    if enabled is True:
        for key in (
            "managed_runs_enabled",
            "secret_key_configured",
            "live_mode_configured",
            "price_configured",
        ):
            if value.get(key) is not True:
                failures.append(f"payment_readiness_{key}_false_when_enabled")
        if value.get("account_mode") != "live":
            failures.append("payment_readiness_account_mode_not_live")
        if label_configured is not True:
            failures.append("payment_readiness_price_label_not_configured")
        if not _valid_public_price_label(label):
            failures.append("payment_readiness_price_label_invalid")
    elif label not in ("", None):
        if label_configured is not True:
            failures.append("payment_readiness_blocked_lane_price_label_flag_mismatch")
        if not _valid_public_price_label(label):
            failures.append("payment_readiness_price_label_invalid")
    failures.extend(_payment_operator_setup_failures(value.get("operator_setup")))
    return failures


def _payment_operator_setup_failures(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["payment_operator_setup_missing"]
    failures: list[str] = []
    if value.get("helper_command") != HOSTED_STRIPE_PRICE_SETUP_HELPER:
        failures.append("payment_operator_setup_helper_mismatch")
    if value.get("verification_command") != HOSTED_STRIPE_PRICE_VERIFY_HELPER:
        failures.append("payment_operator_setup_verification_helper_mismatch")
    if value.get("module_fallback") != HOSTED_STRIPE_PRICE_SETUP_MODULE:
        failures.append("payment_operator_setup_module_fallback_mismatch")
    if value.get("verification_module_fallback") != HOSTED_STRIPE_PRICE_VERIFY_MODULE:
        failures.append("payment_operator_setup_verification_module_fallback_mismatch")
    if value.get("dry_run_default") is not True:
        failures.append("payment_operator_setup_dry_run_policy_mismatch")
    if value.get("mutation_requires") != list(HOSTED_STRIPE_PRICE_SETUP_REQUIRED_FLAGS):
        failures.append("payment_operator_setup_mutation_gate_mismatch")
    if value.get("lookup_key_policy") != HOSTED_STRIPE_PRICE_LOOKUP_POLICY:
        failures.append("payment_operator_setup_lookup_key_policy_mismatch")
    if value.get("shared_account_boundary") != HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY:
        failures.append("payment_operator_setup_shared_account_boundary_mismatch")
    if value.get("secret_boundary") != HOSTED_STRIPE_SETUP_SECRET_BOUNDARY:
        failures.append("payment_operator_setup_secret_boundary_mismatch")
    enable_after = value.get("managed_runs_enable_after")
    if not isinstance(enable_after, str) or "live Checkout proof" not in enable_after:
        failures.append("payment_operator_setup_enable_gate_mismatch")
    return failures


def _managed_lane_launchable(lane_readiness: object) -> bool | None:
    if not isinstance(lane_readiness, dict):
        return None
    lanes = lane_readiness.get("lanes")
    if not isinstance(lanes, dict):
        return None
    managed = lanes.get(MANAGED_FUSEKIT_RUN_LANE)
    if not isinstance(managed, dict):
        return None
    launchable = managed.get("launchable")
    return launchable if isinstance(launchable, bool) else None


def _valid_public_price_label(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return _valid_price_label(value)


def _embedded_json_scripts(text: str) -> dict[str, str]:
    parser = _EmbeddedJsonScriptParser()
    parser.feed(text)
    parser.close()
    return parser.scripts


class _EmbeddedJsonScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: dict[str, str] = {}
        self._active_id = ""
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("type") != "application/json":
            return
        script_id = values.get("id", "")
        if script_id in {
            "fusekit-github-intake",
            "fusekit-hosted-readiness",
            "fusekit-hosted-deployment",
        }:
            self._active_id = script_id
            self._chunks = []

    def handle_data(self, data: str) -> None:
        if self._active_id:
            self._chunks.append(data)

    def handle_entityref(self, name: str) -> None:
        if self._active_id:
            self._chunks.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if self._active_id:
            self._chunks.append(f"&#{name};")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._active_id:
            self.scripts[self._active_id] = "".join(self._chunks)
            self._active_id = ""
            self._chunks = []


def _github_intake_contract_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if payload.get("provider") != "github":
        failures.append("github_intake_provider_mismatch")
    if payload.get("route") != "github-app":
        failures.append("github_intake_route_mismatch")
    install_url = payload.get("install_url")
    if not isinstance(install_url, str) or not install_url.startswith(
        "https://github.com/apps/"
    ):
        failures.append("github_intake_install_url_invalid")
    if payload.get("trust_story") != list(TRUST_STORY):
        failures.append("github_intake_trust_story_mismatch")
    if payload.get("no_terminal_promise") != NO_TERMINAL_PROMISE:
        failures.append("github_intake_no_terminal_promise_mismatch")
    if payload.get("launch_path") != list(HOSTED_LAUNCH_PATH):
        failures.append("github_intake_launch_path_mismatch")
    if payload.get("plain_language_journey") != list(HOSTED_PLAIN_LANGUAGE_JOURNEY):
        failures.append("github_intake_plain_language_journey_mismatch")
    if payload.get("prohibited") != list(HOSTED_PROHIBITED_ACTIONS):
        failures.append("github_intake_prohibited_mismatch")
    if payload.get("proof") != list(HOSTED_PROOF_REQUIREMENTS):
        failures.append("github_intake_proof_mismatch")
    if payload.get("proof_evidence_keys") != list(HOSTED_COMPLETION_EVIDENCE_KEYS):
        failures.append("github_intake_proof_evidence_keys_mismatch")
    if payload.get("reversal") != list(HOSTED_REVERSAL_PATH):
        failures.append("github_intake_reversal_mismatch")
    if payload.get("permissions") != list(HOSTED_GITHUB_INTAKE_PERMISSIONS):
        failures.append("github_intake_permissions_mismatch")
    if payload.get("token_boundary") != hosted_github_public_token_boundary():
        failures.append("github_intake_token_boundary_mismatch")
    open_core = payload.get("open_core")
    if not isinstance(open_core, dict):
        failures.append("github_intake_open_core_missing")
    else:
        if open_core.get("source_repository") != "https://github.com/Fusekit-AI/fusekit":
            failures.append("github_intake_open_core_source_repository_mismatch")
        if open_core.get("license") != "MIT":
            failures.append("github_intake_open_core_license_mismatch")
        if open_core.get("reviewable_entrypoint") != "app.py":
            failures.append("github_intake_open_core_entrypoint_mismatch")
    return failures


def _fetch_text(
    url: str,
    *,
    opener: UrlOpener | None,
) -> tuple[int, str, dict[str, str]]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "FuseKit"})
    actual_opener = opener or urllib.request.urlopen
    with actual_opener(request, timeout=20.0) as response:
        status = int(getattr(response, "status", 200))
        raw = response.read()
        headers = _response_headers(response)
    return status, raw.decode("utf-8"), headers


def _fetch_json(
    url: str,
    *,
    opener: UrlOpener | None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "FuseKit"})
    actual_opener = opener or urllib.request.urlopen
    with actual_opener(request, timeout=20.0) as response:
        status = int(getattr(response, "status", 200))
        raw = response.read()
        headers = _response_headers(response)
    payload = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(payload, dict):
        raise FuseKitError("Hosted verification endpoint returned non-object JSON.")
    return status, payload, headers


def _response_headers(response: object) -> dict[str, str]:
    raw_headers = getattr(response, "headers", {})
    headers: dict[str, str] = {}
    for name in SECURITY_HEADER_NAMES:
        value = ""
        getter = getattr(raw_headers, "get", None)
        if callable(getter):
            value = str(getter(name, "") or getter(name.title(), "") or "")
        if value:
            headers[name] = value
    return headers


def _security_header_failures(headers: dict[str, str]) -> list[str]:
    failures: list[str] = []
    cache_control = headers.get("cache-control", "")
    if "no-store" not in cache_control.lower():
        failures.append("security_header_cache_control_missing")
    csp = headers.get("content-security-policy", "")
    if "default-src 'none'" not in csp:
        failures.append("security_header_csp_default_src_missing")
    if "frame-ancestors 'none'" not in csp:
        failures.append("security_header_csp_frame_ancestors_missing")
    if headers.get("cross-origin-opener-policy", "") != "same-origin":
        failures.append("security_header_cross_origin_opener_policy_missing")
    permissions = headers.get("permissions-policy", "")
    if "camera=()" not in permissions or "microphone=()" not in permissions:
        failures.append("security_header_permissions_policy_missing")
    if headers.get("referrer-policy", "") != "no-referrer":
        failures.append("security_header_referrer_policy_missing")
    if "max-age=31536000" not in headers.get("strict-transport-security", ""):
        failures.append("security_header_hsts_missing")
    if headers.get("x-content-type-options", "") != "nosniff":
        failures.append("security_header_content_type_options_missing")
    if headers.get("x-frame-options", "") != "DENY":
        failures.append("security_header_frame_options_missing")
    return failures


def _failed_check(
    check_id: str,
    url: str,
    reason: str,
    *,
    http_status: int = 0,
    diagnosis: str = "",
    next_action: str = "",
) -> dict[str, object]:
    check: dict[str, object] = {
        "id": check_id,
        "url": _public_url(url),
        "status": "failed",
        "http_status": http_status,
        "schema_version": "",
        "failures": [reason],
    }
    if diagnosis:
        check["diagnosis"] = diagnosis
    if next_action:
        check["next_action"] = next_action
    return check


def _http_error_check(
    check_id: str,
    url: str,
    exc: urllib.error.HTTPError,
) -> dict[str, object]:
    diagnostic = _diagnose_http_error(_read_error_body(exc))
    return _failed_check(
        check_id,
        url,
        "http_error",
        http_status=exc.code,
        diagnosis=diagnostic.get("diagnosis", ""),
        next_action=diagnostic.get("next_action", ""),
    )


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read(65_536)
    except OSError:
        return ""
    if not isinstance(raw, bytes):
        return ""
    return raw.decode("utf-8", errors="replace")


def _diagnose_http_error(body: str) -> dict[str, str]:
    lower = body.lower()
    if (
        ("error 1000" in lower and "dns points to prohibited ip" in lower)
        or "error code: 1000" in lower
    ):
        return {
            "diagnosis": "cloudflare_error_1000_dns_points_to_prohibited_ip",
            "next_action": (
                "Attach fusekit.snowmanai.org to the hosted origin, then set the "
                "Cloudflare fusekit CNAME to the exact provider-provided target. Do not "
                "point the proxied record at a prohibited IP or Cloudflare-owned address."
            ),
        }
    return {}


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


def _valid_expected_commit_sha(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        return ""
    if not re.fullmatch(r"[0-9a-f]{40}", cleaned):
        raise FuseKitError("expected_commit_sha_must_be_40_hex_chars")
    return cleaned


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
