"""Operator helper for hosted managed-run Stripe webhooks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
    HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
    HOSTED_STRIPE_WEBHOOK_LOOKUP_POLICY,
    STRIPE_API_BASE,
    STRIPE_LIVE_SECRET_KEY_PREFIXES,
    _stripe_account_mode,
    _valid_stripe_secret_key,
)
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_FILE,
    _parse_systemd_env_file,
    install_hosted_runtime_secret_file,
)
from fusekit.hosted.server import HOSTED_CANONICAL_ORIGIN
from fusekit.security import contains_durable_secret_text, contains_private_marker_text

STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION = "fusekit.stripe-managed-webhook-setup.v1"
STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION = "fusekit.stripe-managed-webhook-verify.v1"
STRIPE_MANAGED_WEBHOOK_EVENT = "checkout.session.completed"
DEFAULT_MANAGED_WEBHOOK_DESCRIPTION = "FuseKit Managed Run Checkout Webhook"


@dataclass(frozen=True)
class StripeManagedRunWebhookPlan:
    """Public plan for a FuseKit-managed Stripe webhook endpoint."""

    account_mode: str
    endpoint_url: str
    enabled_events: tuple[str, ...]
    description: str
    metadata: Mapping[str, str]

    def public_dict(self) -> dict[str, object]:
        """Return public setup plan data without Stripe secrets."""

        return {
            "schema_version": STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION,
            "provider": "stripe",
            "lane": MANAGED_FUSEKIT_RUN_LANE,
            "account_mode": self.account_mode,
            "endpoint_url": self.endpoint_url,
            "enabled_events": list(self.enabled_events),
            "description": self.description,
            "metadata": dict(self.metadata),
            "lookup_policy": HOSTED_STRIPE_WEBHOOK_LOOKUP_POLICY,
            "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
            "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        }


def build_stripe_managed_run_webhook_plan(
    *,
    stripe_secret_key: str,
    endpoint_url: str = "",
    allow_test_mode: bool = False,
    description: str = DEFAULT_MANAGED_WEBHOOK_DESCRIPTION,
) -> StripeManagedRunWebhookPlan:
    """Validate operator input and return the public Stripe webhook setup plan."""

    account_mode = _stripe_account_mode(stripe_secret_key)
    if account_mode == "unconfigured":
        raise FuseKitError("Stripe secret key is not configured.")
    if account_mode == "unknown":
        raise FuseKitError("Stripe secret key mode is unknown.")
    if account_mode == "test" and not allow_test_mode:
        raise FuseKitError("Live managed-run webhooks require a live Stripe secret key.")
    if not _valid_stripe_secret_key(
        stripe_secret_key,
        allowed_prefixes=STRIPE_LIVE_SECRET_KEY_PREFIXES,
    ) and not (allow_test_mode and account_mode == "test"):
        raise FuseKitError("Stripe webhook setup requires a live Stripe secret key.")
    public_url = _canonical_webhook_url(endpoint_url or _default_endpoint_url())
    if not public_url:
        raise FuseKitError("Stripe webhook endpoint URL must be the canonical FuseKit URL.")
    public_description = _public_description(description)
    if not public_description:
        raise FuseKitError("Stripe webhook description is invalid.")
    return StripeManagedRunWebhookPlan(
        account_mode=account_mode,
        endpoint_url=public_url,
        enabled_events=(STRIPE_MANAGED_WEBHOOK_EVENT,),
        description=public_description,
        metadata=_stripe_webhook_metadata(endpoint_url=public_url),
    )


def create_stripe_managed_run_webhook(
    *,
    stripe_secret_key: str,
    endpoint_url: str = "",
    allow_test_mode: bool = False,
    execute: bool = False,
    confirm_shared_account: bool = False,
    runtime_secret_file: str = "",
    confirm_runtime_secret_install: bool = False,
    opener: UrlOpener | None = None,
) -> dict[str, object]:
    """Create or reuse a FuseKit-scoped Stripe webhook endpoint."""

    runtime_secret_path = runtime_secret_file.strip()
    plan = build_stripe_managed_run_webhook_plan(
        stripe_secret_key=stripe_secret_key,
        endpoint_url=endpoint_url,
        allow_test_mode=allow_test_mode,
    )
    if not execute:
        return _webhook_setup_report(
            plan,
            executed=False,
            endpoint_id="",
            webhook_secret_received=False,
            runtime_secret_file=runtime_secret_path,
        )
    if not confirm_shared_account:
        raise FuseKitError(
            "Refusing Stripe webhook mutation without --confirm-shared-account acknowledgement."
        )
    if runtime_secret_path and not confirm_runtime_secret_install:
        raise FuseKitError(
            "Refusing runtime secret-file mutation without --confirm-runtime-secret-install."
        )
    existing = _find_existing_stripe_managed_run_webhook(
        stripe_secret_key,
        plan,
        opener=opener,
    )
    if existing:
        return _webhook_setup_report(
            plan,
            executed=True,
            endpoint_id=existing["endpoint_id"],
            webhook_secret_received=False,
            reused_existing=True,
            mutated=False,
            runtime_secret_file=runtime_secret_path,
        )
    payload = _stripe_request(
        stripe_secret_key,
        "POST",
        "/v1/webhook_endpoints",
        _webhook_form(plan),
        idempotency_key=f"fusekit-webhook-{_public_hash(plan.endpoint_url)[:24]}",
        opener=opener,
    )
    endpoint_id = _public_stripe_id(payload.get("id"), prefix="we_")
    if not endpoint_id:
        raise FuseKitError("Stripe webhook response did not include a public endpoint id.")
    secret = payload.get("secret")
    webhook_secret_received = isinstance(secret, str) and secret.startswith("whsec_")
    runtime_install_report: Mapping[str, object] | None = None
    if runtime_secret_path:
        if not webhook_secret_received or not isinstance(secret, str):
            raise FuseKitError("Stripe webhook setup did not return a signing secret to install.")
        runtime_install_report = _install_webhook_secret_to_runtime_file(
            runtime_secret_file=runtime_secret_path,
            webhook_secret=secret,
        )
    return _webhook_setup_report(
        plan,
        executed=True,
        endpoint_id=endpoint_id,
        webhook_secret_received=webhook_secret_received,
        reused_existing=False,
        mutated=True,
        runtime_secret_file=runtime_secret_path,
        runtime_secret_install_report=runtime_install_report,
    )


def verify_stripe_managed_run_webhook(
    *,
    stripe_secret_key: str,
    webhook_endpoint_id: str,
    endpoint_url: str = "",
    allow_test_mode: bool = False,
    opener: UrlOpener | None = None,
) -> dict[str, object]:
    """Verify a Stripe webhook endpoint is the expected FuseKit endpoint."""

    plan = build_stripe_managed_run_webhook_plan(
        stripe_secret_key=stripe_secret_key,
        endpoint_url=endpoint_url,
        allow_test_mode=allow_test_mode,
    )
    endpoint_id = _public_stripe_id(webhook_endpoint_id, prefix="we_")
    if not endpoint_id:
        raise FuseKitError("Stripe webhook endpoint id is invalid.")
    payload = _stripe_get(
        stripe_secret_key,
        f"/v1/webhook_endpoints/{urllib.parse.quote(endpoint_id, safe='')}",
        {},
        opener=opener,
    )
    blockers = _webhook_verification_blockers(payload, plan=plan, endpoint_id=endpoint_id)
    report = {
        "schema_version": STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION,
        "setup_schema_version": STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION,
        "provider": "stripe",
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "ready": not blockers,
        "blockers": blockers,
        "account_mode": _stripe_account_mode(stripe_secret_key),
        "webhook_endpoint_id": endpoint_id if not blockers else "",
        "endpoint_url": plan.endpoint_url,
        "enabled_events": list(plan.enabled_events),
        "checks": {
            "endpoint_id_matches": payload.get("id") == endpoint_id,
            "endpoint_enabled": payload.get("status") == "enabled",
            "endpoint_url_matches": payload.get("url") == plan.endpoint_url,
            "enabled_events_match": _events_match(payload.get("enabled_events"), plan),
            "metadata_matches": _metadata_matches(payload.get("metadata"), plan.metadata),
        },
        "hosted_runtime_env": {
            "FUSEKIT_STRIPE_WEBHOOK_ENDPOINT_ID": endpoint_id if not blockers else "",
            "FUSEKIT_STRIPE_WEBHOOK_SECRET": {
                "configured_by_helper": False,
                "secret_value_emitted": False,
                "required_before_managed_runs_enabled": True,
            },
            "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
        },
        "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
        "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        "next_actions": _webhook_verify_next_actions(blockers),
    }
    _assert_public_webhook_report(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Create, plan, or verify a FuseKit-managed Stripe webhook."""

    parser = argparse.ArgumentParser(
        description="Create or verify a FuseKit-scoped Stripe webhook for hosted managed runs."
    )
    parser.add_argument("--endpoint-url", default="")
    parser.add_argument("--webhook-endpoint-id", default="")
    parser.add_argument("--secret-key-env", default="FUSEKIT_STRIPE_SECRET_KEY")
    parser.add_argument("--webhook-endpoint-id-env", default="FUSEKIT_STRIPE_WEBHOOK_ENDPOINT_ID")
    parser.add_argument(
        "--runtime-secret-file",
        default="",
        help=(
            "Optional hosted EnvironmentFile to read for FUSEKIT_STRIPE_SECRET_KEY and, "
            "with --execute plus --confirm-runtime-secret-install, update with the returned "
            "Stripe webhook signing secret"
        ),
    )
    parser.add_argument("--allow-test-mode", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument(
        "--confirm-shared-account",
        action="store_true",
        help=(
            "Acknowledge this Stripe account is shared and only FuseKit-scoped webhook "
            "resources may be made"
        ),
    )
    parser.add_argument(
        "--confirm-runtime-secret-install",
        action="store_true",
        help=(
            "Acknowledge that the helper may update only FUSEKIT_STRIPE_WEBHOOK_SECRET in "
            "the hosted runtime EnvironmentFile without printing it"
        ),
    )
    args = parser.parse_args(argv)
    try:
        runtime_secret_env = _runtime_secret_file_env(args.runtime_secret_file)
        secret_key = os.environ.get(args.secret_key_env, "") or runtime_secret_env.get(
            args.secret_key_env, ""
        )
        endpoint_id = args.webhook_endpoint_id or os.environ.get(args.webhook_endpoint_id_env, "")
        if args.verify:
            report = verify_stripe_managed_run_webhook(
                stripe_secret_key=secret_key,
                webhook_endpoint_id=endpoint_id,
                endpoint_url=args.endpoint_url,
                allow_test_mode=args.allow_test_mode,
            )
        else:
            report = create_stripe_managed_run_webhook(
                stripe_secret_key=secret_key,
                endpoint_url=args.endpoint_url,
                allow_test_mode=args.allow_test_mode,
                execute=args.execute,
                confirm_shared_account=args.confirm_shared_account,
                runtime_secret_file=args.runtime_secret_file,
                confirm_runtime_secret_install=args.confirm_runtime_secret_install,
            )
    except FuseKitError as exc:
        report = {
            "schema_version": (
                STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION
                if args.verify
                else STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION
            ),
            "ready": False,
            "executed": False,
            "error": str(exc),
            "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 2


def verify_main(argv: Sequence[str] | None = None) -> int:
    """Verify a FuseKit-managed Stripe webhook from the dedicated console script."""

    return main(["--verify", *(list(argv) if argv is not None else [])])


def _webhook_setup_report(
    plan: StripeManagedRunWebhookPlan,
    *,
    executed: bool,
    endpoint_id: str,
    webhook_secret_received: bool,
    reused_existing: bool = False,
    mutated: bool = False,
    runtime_secret_file: str = "",
    runtime_secret_install_report: Mapping[str, object] | None = None,
) -> dict[str, object]:
    next_actions = [
        "Store FUSEKIT_STRIPE_WEBHOOK_SECRET only in the hosted runtime secret file.",
        "Keep FUSEKIT_MANAGED_RUNS_ENABLED=0 until live Checkout, webhook, and "
        "worker-dispatch acceptance proof pass.",
    ]
    report = plan.public_dict()
    report.update(
        {
            "ready": True,
            "executed": executed,
            "mutated": mutated,
            "reused_existing": reused_existing,
            "webhook_endpoint_id": endpoint_id,
            "webhook_secret_received": webhook_secret_received,
            "hosted_runtime_env": {
                "FUSEKIT_STRIPE_WEBHOOK_ENDPOINT_ID": endpoint_id,
                "FUSEKIT_STRIPE_WEBHOOK_SECRET": {
                    "configured_by_helper": bool(runtime_secret_install_report),
                    "secret_value_emitted": False,
                    "required_before_managed_runs_enabled": True,
                },
                "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
            },
            "runtime_secret_install": _runtime_secret_install_public_status(
                requested=bool(runtime_secret_file),
                report=runtime_secret_install_report,
                reused_existing=reused_existing,
            ),
            "next_actions": next_actions,
        }
    )
    if not executed:
        report["dry_run"] = True
        report["mutated"] = False
        report["reused_existing"] = False
        report["next_actions"] = [
            "Re-run with --execute --confirm-shared-account after reviewing this plan.",
            *next_actions,
        ]
    if executed and mutated and webhook_secret_received:
        if runtime_secret_install_report:
            report["next_actions"] = [
                "Verify the hosted runtime secret file and keep managed runs disabled until "
                "live Checkout, webhook, and worker-dispatch acceptance proof pass.",
                *next_actions,
            ]
        else:
            report["next_actions"] = [
                "Install the write-only Stripe webhook signing secret returned by Stripe into "
                "/etc/fusekit/hosted-secrets.env without printing it.",
                *next_actions,
            ]
    if executed and reused_existing:
        report["next_actions"] = [
            "Existing Stripe webhook endpoints do not return signing secrets; retrieve the "
            "endpoint signing secret in Stripe and install it without printing it.",
            *next_actions,
        ]
    _assert_public_webhook_report(report)
    return report


def _install_webhook_secret_to_runtime_file(
    *,
    runtime_secret_file: str,
    webhook_secret: str,
) -> Mapping[str, object]:
    env, failures = _read_runtime_secret_env(runtime_secret_file)
    if failures:
        raise FuseKitError("Runtime secret file is not readable or parseable.")
    env["FUSEKIT_STRIPE_WEBHOOK_SECRET"] = webhook_secret
    return install_hosted_runtime_secret_file(
        env=env,
        output_path=runtime_secret_file,
        execute=True,
    )


def _runtime_secret_file_env(runtime_secret_file: str) -> dict[str, str]:
    if not runtime_secret_file.strip():
        return {}
    env, failures = _read_runtime_secret_env(runtime_secret_file)
    if failures:
        raise FuseKitError("Runtime secret file is not readable or parseable.")
    return env


def _read_runtime_secret_env(runtime_secret_file: str) -> tuple[dict[str, str], list[str]]:
    path = runtime_secret_file.strip() or HOSTED_RUNTIME_SECRET_FILE
    try:
        return _parse_systemd_env_file(Path(path))
    except OSError:
        return {}, ["runtime_secret_file_unreadable"]


def _runtime_secret_install_public_status(
    *,
    requested: bool,
    report: Mapping[str, object] | None,
    reused_existing: bool,
) -> dict[str, object]:
    if not requested:
        return {
            "requested": False,
            "mutates_host": False,
            "written": False,
            "secret_value_emitted": False,
        }
    if report:
        return {
            "requested": True,
            "mutates_host": report.get("mutates_host") is True,
            "written": report.get("written") is True,
            "ready_to_write_secret_file": report.get("ready_to_write_secret_file") is True,
            "ready_for_managed_payment_staging": report.get(
                "ready_for_managed_payment_staging"
            )
            is True,
            "blockers": _string_list(report.get("blockers")),
            "keys_written": _string_list(report.get("keys_written")),
            "secret_value_emitted": False,
        }
    return {
        "requested": True,
        "mutates_host": False,
        "written": False,
        "reused_existing_without_returned_secret": reused_existing,
        "secret_value_emitted": False,
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value]


def _find_existing_stripe_managed_run_webhook(
    stripe_secret_key: str,
    plan: StripeManagedRunWebhookPlan,
    *,
    opener: UrlOpener | None,
) -> dict[str, str]:
    payload = _stripe_get(
        stripe_secret_key,
        "/v1/webhook_endpoints",
        {"limit": "100"},
        opener=opener,
    )
    data = payload.get("data")
    if not isinstance(data, list):
        return {}
    occupied = []
    for item in data:
        if not isinstance(item, Mapping) or item.get("url") != plan.endpoint_url:
            continue
        if _webhook_matches_plan(item, plan):
            return {"endpoint_id": _public_stripe_id(item.get("id"), prefix="we_")}
        occupied.append(item)
    if occupied:
        raise FuseKitError(
            "Existing Stripe webhook endpoint URL is occupied by non-FuseKit metadata "
            "or broader events."
        )
    return {}


def _webhook_verification_blockers(
    payload: Mapping[str, object],
    *,
    plan: StripeManagedRunWebhookPlan,
    endpoint_id: str,
) -> list[str]:
    blockers: list[str] = []
    if payload.get("id") != endpoint_id:
        blockers.append("stripe_webhook_endpoint_id_mismatch")
    if payload.get("status") != "enabled":
        blockers.append("stripe_webhook_endpoint_not_enabled")
    if payload.get("url") != plan.endpoint_url:
        blockers.append("stripe_webhook_endpoint_url_mismatch")
    if not _events_match(payload.get("enabled_events"), plan):
        blockers.append("stripe_webhook_enabled_events_mismatch")
    if not _metadata_matches(payload.get("metadata"), plan.metadata):
        blockers.append("stripe_webhook_metadata_mismatch")
    return blockers


def _webhook_matches_plan(
    value: Mapping[str, object],
    plan: StripeManagedRunWebhookPlan,
) -> bool:
    return (
        _public_stripe_id(value.get("id"), prefix="we_") != ""
        and value.get("status") == "enabled"
        and value.get("url") == plan.endpoint_url
        and _events_match(value.get("enabled_events"), plan)
        and _metadata_matches(value.get("metadata"), plan.metadata)
    )


def _stripe_get(
    stripe_secret_key: str,
    path: str,
    query: Mapping[str, str],
    *,
    opener: UrlOpener | None,
) -> dict[str, object]:
    suffix = "?" + urllib.parse.urlencode(query) if query else ""
    request = urllib.request.Request(
        STRIPE_API_BASE + path + suffix,
        method="GET",
        headers={
            "Authorization": f"Bearer {stripe_secret_key}",
            "User-Agent": "FuseKit",
        },
    )
    return _stripe_json(request, opener=opener, failure_label="Stripe webhook lookup")


def _stripe_request(
    stripe_secret_key: str,
    method: str,
    path: str,
    form: Mapping[str, str],
    *,
    idempotency_key: str,
    opener: UrlOpener | None,
) -> dict[str, object]:
    request = urllib.request.Request(
        STRIPE_API_BASE + path,
        data=urllib.parse.urlencode(dict(form)).encode("utf-8"),
        method=method,
        headers={
            "Authorization": f"Bearer {stripe_secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": idempotency_key,
            "User-Agent": "FuseKit",
        },
    )
    return _stripe_json(request, opener=opener, failure_label="Stripe webhook setup request")


def _stripe_json(
    request: urllib.request.Request,
    *,
    opener: UrlOpener | None,
    failure_label: str,
) -> dict[str, object]:
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=30.0) as response:
            raw = response.read()
            status = int(getattr(response, "status", 200))
    except urllib.error.HTTPError as exc:
        raise FuseKitError(f"{failure_label} returned HTTP {exc.code}.") from exc
    if status >= 400:
        raise FuseKitError(f"{failure_label} returned HTTP {status}.")
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError(f"{failure_label} response is invalid.")
    return decoded


def _webhook_form(plan: StripeManagedRunWebhookPlan) -> dict[str, str]:
    form = {
        "url": plan.endpoint_url,
        "description": plan.description,
    }
    for event in plan.enabled_events:
        form["enabled_events[]"] = event
    for key, value in plan.metadata.items():
        form[f"metadata[{key}]"] = value
    return form


def _stripe_webhook_metadata(*, endpoint_url: str) -> dict[str, str]:
    return {
        "fusekit_component": "hosted-launcher",
        "fusekit_lane": MANAGED_FUSEKIT_RUN_LANE,
        "fusekit_scope": "managed-run-webhook",
        "public_endpoint_hash": _public_hash(endpoint_url),
    }


def _webhook_verify_next_actions(blockers: Sequence[str]) -> list[str]:
    if not blockers:
        return [
            "Confirm FUSEKIT_STRIPE_WEBHOOK_SECRET is installed in the hosted runtime "
            "secret file.",
            "Keep FUSEKIT_MANAGED_RUNS_ENABLED=0 until live Checkout, webhook, and "
            "worker-dispatch acceptance proof pass.",
        ]
    return [
        "Do not enable managed paid runs with this Stripe webhook endpoint.",
        "Create or verify a FuseKit-scoped Stripe webhook endpoint with "
        "fusekit-hosted-stripe-webhook, then rerun this verifier.",
    ]


def _default_endpoint_url() -> str:
    return HOSTED_CANONICAL_ORIGIN + "/api/hosted/payments/stripe-webhook"


def _canonical_webhook_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    expected = urllib.parse.urlparse(_default_endpoint_url())
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != expected.netloc
        or parsed.path != expected.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        return ""
    return urllib.parse.urlunparse(("https", expected.netloc, expected.path, "", "", ""))


def _public_description(value: str) -> str:
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > 120:
        return ""
    if contains_durable_secret_text(cleaned) or _contains_private_marker(cleaned):
        return ""
    if any(ch in cleaned for ch in "<>{}") or not all(ch.isprintable() for ch in cleaned):
        return ""
    return cleaned


def _events_match(value: object, plan: StripeManagedRunWebhookPlan) -> bool:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return False
    events = sorted(str(item) for item in value)
    return events == sorted(plan.enabled_events)


def _metadata_matches(value: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value.keys()) != set(expected.keys()):
        return False
    return all(value.get(key) == expected_value for key, expected_value in expected.items())


def _public_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_stripe_id(value: object, *, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix):
        return ""
    if not all(ch.isalnum() or ch == "_" for ch in value):
        return ""
    if _contains_private_marker(value):
        return ""
    return value


def _assert_public_webhook_report(report: Mapping[str, object]) -> None:
    serialized = json.dumps(report, sort_keys=True)
    if contains_durable_secret_text(serialized) or _contains_private_marker(serialized):
        raise FuseKitError("stripe_webhook_report_contains_secret_text")


def _contains_private_marker(value: str) -> bool:
    return contains_private_marker_text(value)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
