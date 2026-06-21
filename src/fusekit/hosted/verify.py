"""Outside-in verification for hosted FuseKit deployment."""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any, Protocol

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import (
    HOSTED_GITHUB_INTAKE_PERMISSIONS,
    hosted_github_public_token_boundary,
)
from fusekit.hosted.launcher import (
    HOSTED_COMPLETION_EVIDENCE_KEYS,
    HOSTED_LAUNCH_PATH,
    HOSTED_PROOF_REQUIREMENTS,
    HOSTED_REVERSAL_PATH,
    NO_TERMINAL_PROMISE,
    TRUST_STORY,
)
from fusekit.hosted.server import (
    HOSTED_CANONICAL_ORIGIN,
    HOSTED_CAPABILITY_VAULT_BOUNDARY,
    HOSTED_DEPLOYMENT_SCHEMA_VERSION,
    HOSTED_OPERATOR_SETUP_STEPS,
    HOSTED_PUBLIC_TRUST_CONTRACT,
    HOSTED_READINESS_SCHEMA_VERSION,
)
from fusekit.hosted.worker_dispatch import HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION
from fusekit.security import contains_durable_secret_text

HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION = "fusekit.hosted-deployment-verification.v1"
HomeContractValidator = Callable[[dict[str, Any]], list[str]]


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
    opener: UrlOpener | None = None,
    dns_resolver: DnsResolver | None = None,
) -> dict[str, object]:
    """Verify hosted launcher and optional worker dispatch endpoints without secrets."""

    public_origin = _valid_public_origin(origin)
    public_host = urllib.parse.urlparse(public_origin).hostname or ""
    dispatch_public_url = ""
    if worker_dispatch_url:
        dispatch_public_url = _valid_https_url(worker_dispatch_url)
    checks: list[dict[str, object]] = []
    checks.append(_dns_check("hosted.dns", public_host, resolver=dns_resolver))
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
        expect_ready_field=True,
    )
    checks.append(hosted_readiness)
    checks.append(
        _json_check(
            "hosted.deployment",
            f"{public_origin}/api/hosted/deployment",
            opener=opener,
            expect_schema=HOSTED_DEPLOYMENT_SCHEMA_VERSION,
            expect_hosted_runtime_contract=True,
            expected_public_origin=public_origin,
        )
    )
    checks.append(
        _json_check(
            "hosted.github_intake",
            f"{public_origin}/api/github/intake",
            opener=opener,
            expect_github_intake_contract=True,
        )
    )
    if dispatch_public_url:
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
                expect_worker_dispatch_readiness=True,
            )
        )
    return {
        "schema_version": HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
        "public_origin": public_origin,
        "worker_dispatch_url": dispatch_public_url,
        "ready": all(check["status"] == "ok" for check in checks),
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


def _text_check(
    check_id: str,
    url: str,
    *,
    opener: UrlOpener | None,
    expect_hosted_home: bool = False,
    expected_public_origin: str = "",
) -> dict[str, object]:
    try:
        status, text = _fetch_text(url, opener=opener)
    except urllib.error.HTTPError as exc:
        return _http_error_check(check_id, url, exc)
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError) as exc:
        return _failed_check(check_id, url, exc.__class__.__name__)
    failures: list[str] = []
    if status >= 400:
        failures.append("http_error")
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
    expect_hosted_runtime_contract: bool = False,
    expect_github_intake_contract: bool = False,
    expect_worker_dispatch_readiness: bool = False,
    expected_public_origin: str = "",
) -> dict[str, object]:
    try:
        status, payload = _fetch_json(url, opener=opener)
    except urllib.error.HTTPError as exc:
        return _http_error_check(check_id, url, exc)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return _failed_check(check_id, url, exc.__class__.__name__)
    failures: list[str] = []
    if status >= 400:
        failures.append("http_error")
    failures.extend(_public_payload_secret_failures(payload))
    schema = payload.get("schema_version")
    if expect_schema and schema != expect_schema:
        failures.append("schema_mismatch")
    if expect_ok_field and payload.get("ok") is not True:
        failures.append("ok_field_not_true")
    if expect_ready_field and payload.get("ready") is not True:
        failures.append("ready_field_not_true")
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
    return {
        "id": check_id,
        "url": _public_url(url),
        "status": "failed" if failures else "ok",
        "http_status": status,
        "schema_version": schema if isinstance(schema, str) else "",
        "failures": failures,
    }


def _worker_dispatch_readiness_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    idempotency = payload.get("idempotency")
    if not isinstance(idempotency, dict):
        return ["worker_dispatch_idempotency_missing"]
    if idempotency.get("durable") is not True:
        failures.append("worker_dispatch_idempotency_not_durable")
    mode = idempotency.get("mode")
    if mode not in {"dispatch-state-dir", "workspace"}:
        failures.append("worker_dispatch_idempotency_mode_not_production")
    production_ready = payload.get("production_ready")
    if production_ready is not True:
        failures.append("worker_dispatch_production_ready_not_true")
    return failures


def _dns_check(
    check_id: str,
    hostname: str,
    *,
    resolver: DnsResolver | None,
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
        check["next_action"] = (
            "Attach fusekit.snowmanai.org to the Vercel project, then set the "
            "Cloudflare fusekit CNAME to the exact Vercel-provided target and wait "
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
    failures.extend(_one_click_launch_contract_failures(payload.get("one_click_launch")))
    expected_runtime = {
        "provider": "vercel",
        "entrypoint": "app.py",
        "routing_config": "vercel.json",
        "requirements": "requirements.txt",
        "python_version": ".python-version",
        "application_export": "app",
        "mode": "python-wsgi",
    }
    for key, expected in expected_runtime.items():
        if runtime.get(key) != expected:
            failures.append(f"runtime_{key}_mismatch")
    cloudflare_dns = payload.get("cloudflare_dns")
    if not isinstance(cloudflare_dns, dict):
        failures.append("cloudflare_dns_contract_missing")
    else:
        if cloudflare_dns.get("zone") != "snowmanai.org":
            failures.append("cloudflare_zone_mismatch")
        if cloudflare_dns.get("record_name") != "fusekit":
            failures.append("cloudflare_record_name_mismatch")
        if cloudflare_dns.get("record_type") != "CNAME":
            failures.append("cloudflare_record_type_mismatch")
    open_core = payload.get("open_core")
    if not isinstance(open_core, dict):
        failures.append("open_core_contract_missing")
    else:
        if open_core.get("source_repository") != "https://github.com/xpxpxp-coder/fusekit":
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
            expected_step_ids = [step["id"] for step in HOSTED_OPERATOR_SETUP_STEPS]
            actual_step_ids = [
                step.get("id")
                for step in steps
                if isinstance(step, dict) and isinstance(step.get("id"), str)
            ]
            if actual_step_ids != expected_step_ids:
                failures.append("operator_setup_steps_mismatch")
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
    if payload.get("launch_path") != list(HOSTED_LAUNCH_PATH):
        failures.append("one_click_launch_path_mismatch")
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
        "hosted_home_completion_requirements_missing": "Completion requires",
        "hosted_home_live_url_proof_missing": "Live URL verification",
        "hosted_home_run_record_proof_missing": "Run Record",
        "hosted_home_detonation_receipt_missing": "Detonation receipt",
        "hosted_home_reversible_setup_missing": "Reversible setup",
        "hosted_home_rollback_metadata_missing": "Show rollback metadata before risky changes.",
        "hosted_home_revoke_access_missing": "revoke access",
        "hosted_home_provider_gates_missing": "What you may need to approve",
        "hosted_home_deployment_contract_missing": "Hosted deployment contract",
        "hosted_home_embedded_intake_contract_missing": 'id="fusekit-github-intake"',
        "hosted_home_embedded_readiness_contract_missing": 'id="fusekit-hosted-readiness"',
        "hosted_home_embedded_deployment_contract_missing": (
            'id="fusekit-hosted-deployment"'
        ),
        "hosted_home_source_repository_missing": "https://github.com/xpxpxp-coder/fusekit",
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
    return failures


def _hosted_home_readiness_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != HOSTED_READINESS_SCHEMA_VERSION:
        failures.append("schema_mismatch")
    if payload.get("ready") is not True:
        failures.append("ready_field_not_true")
    return failures


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
        if open_core.get("source_repository") != "https://github.com/xpxpxp-coder/fusekit":
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
) -> tuple[int, str]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "FuseKit"})
    actual_opener = opener or urllib.request.urlopen
    with actual_opener(request, timeout=20.0) as response:
        status = int(getattr(response, "status", 200))
        raw = response.read()
    return status, raw.decode("utf-8")


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
                "Attach fusekit.snowmanai.org to the Vercel project, then set the "
                "Cloudflare fusekit CNAME to the exact Vercel-provided target. Do not "
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
