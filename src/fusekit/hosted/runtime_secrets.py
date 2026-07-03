"""Redacted runtime-secret readiness for the hosted launcher."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
from collections.abc import Mapping, Sequence

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import _stripe_account_mode, _valid_price_label
from fusekit.hosted.server import HOSTED_CANONICAL_ORIGIN, REQUIRED_HOSTED_ENV
from fusekit.security import contains_durable_secret_text, redact_public_text

HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION = "fusekit.hosted-runtime-secret-plan.v1"
HOSTED_RUNTIME_SECRET_FILE = "/etc/fusekit/hosted-secrets.env"
HOSTED_RUNTIME_GENERATABLE_SECRETS = (
    "FUSEKIT_HOSTED_STATE_SECRET",
    "FUSEKIT_HOSTED_WORKER_SECRET",
)
HOSTED_RUNTIME_STRIPE_ENV = (
    "FUSEKIT_STRIPE_SECRET_KEY",
    "FUSEKIT_STRIPE_PRICE_ID",
    "FUSEKIT_MANAGED_RUN_PRICE_LABEL",
    "FUSEKIT_MANAGED_RUNS_ENABLED",
)


def build_hosted_runtime_secret_plan(
    *,
    env: Mapping[str, str],
    allow_generated_state_secrets: bool = False,
) -> dict[str, object]:
    """Build a public, redacted plan for hosted runtime secret-file readiness."""

    configured = {name: bool(env.get(name, "")) for name in REQUIRED_HOSTED_ENV}
    generated = {
        name: bool(allow_generated_state_secrets and not configured.get(name, False))
        for name in HOSTED_RUNTIME_GENERATABLE_SECRETS
    }
    effective_configured = {
        name: configured[name] or generated.get(name, False) for name in configured
    }
    missing = [name for name, present in effective_configured.items() if not present]
    invalid = _runtime_invalid(env, generated=generated)
    stripe = _stripe_runtime_status(env)
    blockers = [*missing, *invalid, *_string_list(stripe["blockers"])]
    ready = not blockers
    plan = {
        "schema_version": HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION,
        "mode": "plan_only",
        "mutates_host": False,
        "mutates_provider": False,
        "ready_to_write_secret_file": ready,
        "ready_for_managed_payment_staging": stripe["ready_for_managed_payment_staging"],
        "blockers": blockers,
        "secret_file": {
            "path": HOSTED_RUNTIME_SECRET_FILE,
            "owner": "root:root",
            "mode": "0600",
            "directory_owner": "root:root",
            "directory_mode": "0750",
        },
        "required_runtime_env": {
            name: {
                "configured": configured[name],
                "generated_at_install": generated.get(name, False),
                "source": _runtime_env_source(name, generated=generated),
            }
            for name in REQUIRED_HOSTED_ENV
        },
        "stripe_runtime_env": stripe["public_env"],
        "install_contract": {
            "write_values_to": HOSTED_RUNTIME_SECRET_FILE,
            "never_print_values": True,
            "quote_multiline_private_key": True,
            "managed_runs_default": "0",
            "state_and_worker_secrets": (
                "Generate on the host only when --allow-generated-state-secrets is "
                "explicitly selected; generated values are never emitted by this plan."
            ),
        },
        "next_actions": _next_actions(blockers),
        "secret_boundary": (
            "This plan reports only env names, booleans, modes, and public Stripe object "
            "ids/labels. It never emits GitHub App private keys, hosted state secrets, "
            "worker secrets, Stripe secret keys, OCI credentials, provider credentials, "
            "vault material, or generated secret values."
        ),
    }
    _assert_public_runtime_plan(plan)
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    """Print redacted hosted runtime secret-file readiness."""

    parser = argparse.ArgumentParser(
        description="Build a redacted hosted runtime secret-file readiness plan."
    )
    parser.add_argument("--env-json", default="")
    parser.add_argument("--allow-generated-state-secrets", action="store_true")
    args = parser.parse_args(argv)
    try:
        env = _read_env(args.env_json) if args.env_json else dict(os.environ)
        plan = build_hosted_runtime_secret_plan(
            env=env,
            allow_generated_state_secrets=args.allow_generated_state_secrets,
        )
    except FuseKitError as exc:
        plan = {
            "schema_version": HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION,
            "mode": "plan_only",
            "ready_to_write_secret_file": False,
            "mutates_host": False,
            "mutates_provider": False,
            "error": str(exc),
            "secret_boundary": "Runtime secret planning errors never emit secret values.",
        }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0 if plan.get("ready_to_write_secret_file") is True else 2


def _runtime_invalid(env: Mapping[str, str], *, generated: Mapping[str, bool]) -> list[str]:
    failures: list[str] = []
    origin = env.get("FUSEKIT_HOSTED_ORIGIN", "")
    if origin and _https_origin(origin) != HOSTED_CANONICAL_ORIGIN:
        failures.append("hosted_origin_must_be_canonical_https_origin")
    app_id = env.get("FUSEKIT_GITHUB_APP_ID", "")
    if app_id and not app_id.isdigit():
        failures.append("github_app_id_must_be_positive_integer")
    slug = env.get("FUSEKIT_GITHUB_APP_SLUG", "")
    if slug and not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?", slug):
        failures.append("github_app_slug_is_invalid")
    private_key = env.get("FUSEKIT_GITHUB_APP_PRIVATE_KEY", "")
    if private_key and not _rsa_private_key_pem(private_key):
        failures.append("github_app_private_key_must_be_rsa_pem")
    for name in HOSTED_RUNTIME_GENERATABLE_SECRETS:
        value = env.get(name, "")
        if value and len(value) < 32:
            failures.append(f"{name.lower()}_too_short")
        if generated.get(name) is True:
            continue
    dispatch_url = env.get("FUSEKIT_HOSTED_WORKER_DISPATCH_URL", "")
    if dispatch_url and not _valid_https_url(dispatch_url):
        failures.append("hosted_worker_dispatch_url_must_be_https_without_credentials")
    return failures


def _stripe_runtime_status(env: Mapping[str, str]) -> dict[str, object]:
    secret_key = env.get("FUSEKIT_STRIPE_SECRET_KEY", "")
    price_id = env.get("FUSEKIT_STRIPE_PRICE_ID", "")
    label = env.get("FUSEKIT_MANAGED_RUN_PRICE_LABEL", "")
    enabled = env.get("FUSEKIT_MANAGED_RUNS_ENABLED", "0")
    account_mode = _stripe_account_mode(secret_key)
    blockers: list[str] = []
    if secret_key and account_mode != "live":
        blockers.append("stripe_secret_key_must_be_live")
    if price_id and not price_id.startswith("price_"):
        blockers.append("stripe_price_id_invalid")
    if label and not _valid_price_label(label):
        blockers.append("managed_run_price_label_invalid")
    if enabled not in {"", "0", "false", "False", "FALSE"}:
        blockers.append("managed_runs_must_stay_disabled_until_checkout_proof")
    ready_for_staging = bool(
        account_mode == "live"
        and price_id.startswith("price_")
        and label
        and _valid_price_label(label)
        and "managed_runs_must_stay_disabled_until_checkout_proof" not in blockers
    )
    return {
        "ready_for_managed_payment_staging": ready_for_staging,
        "blockers": blockers,
        "public_env": {
            "FUSEKIT_STRIPE_SECRET_KEY": {
                "configured": bool(secret_key),
                "account_mode": account_mode,
            },
            "FUSEKIT_STRIPE_PRICE_ID": {
                "configured": bool(price_id),
                "public_id": redact_public_text(price_id) if price_id.startswith("price_") else "",
            },
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL": {
                "configured": bool(label),
                "public_label": (
                    redact_public_text(label) if label and _valid_price_label(label) else ""
                ),
            },
            "FUSEKIT_MANAGED_RUNS_ENABLED": {
                "configured": bool(enabled),
                "must_remain_disabled": True,
                "enabled": enabled in {"1", "true", "True", "TRUE"},
            },
        },
    }


def _runtime_env_source(name: str, *, generated: Mapping[str, bool]) -> str:
    if generated.get(name):
        return "generated_on_host_install"
    if name in HOSTED_RUNTIME_GENERATABLE_SECRETS:
        return "provided_or_generated_on_host_install"
    return "provided_secret_input"


def _next_actions(blockers: Sequence[str]) -> list[str]:
    if not blockers:
        return [
            "Write the secret values to /etc/fusekit/hosted-secrets.env as root:root mode 0600.",
            "Keep FUSEKIT_MANAGED_RUNS_ENABLED=0 until live Checkout proof passes.",
            "Run hosted verifier, OCI inventory, replacement plan, and host posture before "
            "DNS cutover.",
        ]
    return [
        "Collect the missing hosted runtime values without pasting them into docs or logs.",
        "Generate hosted state/worker secrets only on the replacement host when explicitly "
        "allowed.",
        "Keep managed paid runs disabled until live Checkout proof and worker-dispatch "
        "acceptance pass.",
    ]


def _read_env(path: str) -> Mapping[str, str]:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except OSError as exc:
        raise FuseKitError("runtime_secret_env_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("runtime_secret_env_input_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("runtime_secret_env_input_must_be_json_object")
    return {str(key): str(item) for key, item in value.items()}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value]


def _rsa_private_key_pem(value: str) -> bool:
    return (
        "-----BEGIN" in value
        and "PRIVATE KEY-----" in value
        and "-----END" in value
        and "PRIVATE KEY-----" in value.split("-----END", 1)[-1]
    )


def _https_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return ""
    if parsed.username or parsed.password or parsed.path not in {"", "/"}:
        return ""
    if parsed.params or parsed.query or parsed.fragment:
        return ""
    return f"https://{parsed.netloc.lower()}"


def _valid_https_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


def _assert_public_runtime_plan(plan: Mapping[str, object]) -> None:
    serialized = json.dumps(plan, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("hosted_runtime_secret_plan_contains_secret_text")
    forbidden = [
        r"sk_live_",
        r"sk_test_",
        r"-----BEGIN ",
        r"-----END ",
        r"ocid1\.",
    ]
    if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in forbidden):
        raise FuseKitError("hosted_runtime_secret_plan_contains_private_material")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
