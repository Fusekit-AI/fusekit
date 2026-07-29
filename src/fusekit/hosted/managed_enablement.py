"""Guarded enablement for hosted paid Managed FuseKit runs."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import _valid_price_label, _valid_stripe_price_id
from fusekit.hosted.lanes import BYO_OCI_LANE, MANAGED_FUSEKIT_RUN_LANE
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_FILE,
    HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION,
    _parse_systemd_env_file,
    _write_secret_env_file,
    verify_hosted_runtime_secret_file,
)
from fusekit.hosted.stripe_verify import STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION
from fusekit.hosted.stripe_webhook import STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION
from fusekit.hosted.verify import HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
from fusekit.security import contains_durable_secret_text, contains_private_marker_text

HOSTED_MANAGED_ENABLEMENT_SCHEMA_VERSION = "fusekit.hosted-managed-enablement.v1"
HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION = (
    "fusekit.hosted-managed-live-checkout-proof.v1"
)
HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY = (
    "Managed-run enablement proof contains only public verifier status, public Stripe "
    "Price/Webhook object ids, lane state, job ids, and booleans. It must not contain "
    "Stripe secret keys, webhook signing secrets, card data, payment method ids, "
    "GitHub private keys, worker secrets, OCI credentials, provider credentials, or "
    "vault material."
)
HOSTED_MANAGED_ENABLEMENT_MAX_JSON_BYTES = 1_048_576


def build_hosted_managed_enablement_report(
    *,
    runtime_secret_verify: Mapping[str, Any],
    hosted_verify: Mapping[str, Any],
    stripe_price_verify: Mapping[str, Any],
    stripe_webhook_verify: Mapping[str, Any],
    hosted_readiness: Mapping[str, Any],
    live_checkout_proof: Mapping[str, Any],
) -> dict[str, object]:
    """Return a redacted proof report for enabling paid managed hosted runs."""

    blockers: list[str] = []
    blockers.extend(_runtime_secret_verify_blockers(runtime_secret_verify))
    blockers.extend(_hosted_verify_blockers(hosted_verify))
    blockers.extend(_stripe_price_verify_blockers(stripe_price_verify))
    blockers.extend(_stripe_webhook_verify_blockers(stripe_webhook_verify))
    blockers.extend(_hosted_readiness_blockers(hosted_readiness))
    blockers.extend(_live_checkout_proof_blockers(live_checkout_proof, hosted_verify))
    blockers = _unique(blockers)
    report: dict[str, object] = {
        "schema_version": HOSTED_MANAGED_ENABLEMENT_SCHEMA_VERSION,
        "ready_to_enable": not blockers,
        "mutates_host": False,
        "mutates_provider": False,
        "blockers": blockers,
        "proof_summary": {
            "runtime_secret_verify_ready": runtime_secret_verify.get("ready") is True,
            "hosted_verify_ready": hosted_verify.get("ready") is True,
            "stripe_price_ready": stripe_price_verify.get("ready") is True,
            "stripe_webhook_ready": stripe_webhook_verify.get("ready") is True,
            "job_store_ready": _job_store_ready(hosted_readiness),
            "live_checkout_ready": live_checkout_proof.get("ready") is True,
            "live_checkout_bound_to_current_deployment": (
                _live_checkout_bound_to_hosted_commit(live_checkout_proof, hosted_verify)
            ),
            "managed_runs_currently_disabled": _managed_runs_disabled(hosted_readiness),
            "byo_lane_launchable": _byo_lane_launchable(hosted_readiness),
        },
        "enablement_contract": {
            "runtime_key": "FUSEKIT_MANAGED_RUNS_ENABLED",
            "from_value": "0",
            "to_value": "1",
            "requires_live_checkout_proof": True,
            "requires_worker_dispatch_acceptance": True,
            "requires_durable_public_job_store": True,
            "requires_byo_lane_still_launchable": True,
            "requires_current_deployment_commit_binding": True,
        },
        "next_actions": _next_actions(blockers),
        "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
    }
    _assert_public_report(report)
    return report


def enable_hosted_managed_runs(
    *,
    runtime_secret_file: str,
    runtime_secret_verify: Mapping[str, Any],
    hosted_verify: Mapping[str, Any],
    stripe_price_verify: Mapping[str, Any],
    stripe_webhook_verify: Mapping[str, Any],
    hosted_readiness: Mapping[str, Any],
    live_checkout_proof: Mapping[str, Any],
    execute: bool = False,
    confirm_managed_enablement: bool = False,
) -> dict[str, object]:
    """Dry-run or enable paid managed runs in the hosted runtime secret file."""

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=runtime_secret_verify,
        hosted_verify=hosted_verify,
        stripe_price_verify=stripe_price_verify,
        stripe_webhook_verify=stripe_webhook_verify,
        hosted_readiness=hosted_readiness,
        live_checkout_proof=live_checkout_proof,
    )
    blockers = _string_list(report.get("blockers"))
    if execute and not confirm_managed_enablement:
        blockers.append("confirm_managed_enablement_required")
    if execute and report.get("ready_to_enable") is not True:
        blockers.append("enablement_proof_not_ready")
    written = False
    if execute and not blockers:
        preflight = verify_hosted_runtime_secret_file(path=runtime_secret_file)
        if preflight.get("ready") is not True:
            blockers.append("runtime_secret_file_preflight_not_ready")
        material: dict[str, str] = {}
        if not blockers:
            material, parse_failures = _parse_systemd_env_file(Path(runtime_secret_file))
            if parse_failures:
                blockers.extend(f"runtime_secret_{failure}" for failure in parse_failures)
        if (
            material
            and material.get("FUSEKIT_MANAGED_RUNS_ENABLED")
            not in {"", "0", "false", "False"}
        ):
            blockers.append("managed_runs_already_enabled_or_ambiguous")
        if not blockers:
            material["FUSEKIT_MANAGED_RUNS_ENABLED"] = "1"
            _write_secret_env_file(Path(runtime_secret_file), material)
            written = True
    final_report: dict[str, object] = {
        **report,
        "mode": "write" if execute else "plan_only",
        "mutates_host": bool(execute),
        "mutates_provider": False,
        "executed": bool(execute),
        "written": written,
        "ready_to_enable": not blockers,
        "blockers": _unique(blockers),
        "runtime_secret_file": {
            "path": runtime_secret_file,
            "value_written": "1" if written else "",
            "secret_values_emitted": False,
        },
        "next_actions": _next_actions(blockers, written=written),
        "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
    }
    _assert_public_report(final_report)
    return final_report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify proof and optionally enable hosted paid Managed FuseKit runs."
    )
    parser.add_argument("--runtime-secret-file", default=HOSTED_RUNTIME_SECRET_FILE)
    parser.add_argument("--runtime-secret-verify-report", required=True)
    parser.add_argument("--hosted-verify-report", required=True)
    parser.add_argument("--stripe-price-verify-report", required=True)
    parser.add_argument("--stripe-webhook-verify-report", required=True)
    parser.add_argument("--hosted-readiness-report", required=True)
    parser.add_argument("--live-checkout-proof", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-managed-enablement", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = enable_hosted_managed_runs(
            runtime_secret_file=args.runtime_secret_file,
            runtime_secret_verify=_read_json(args.runtime_secret_verify_report),
            hosted_verify=_read_json(args.hosted_verify_report),
            stripe_price_verify=_read_json(args.stripe_price_verify_report),
            stripe_webhook_verify=_read_json(args.stripe_webhook_verify_report),
            hosted_readiness=_read_json(args.hosted_readiness_report),
            live_checkout_proof=_read_json(args.live_checkout_proof),
            execute=args.execute,
            confirm_managed_enablement=args.confirm_managed_enablement,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": HOSTED_MANAGED_ENABLEMENT_SCHEMA_VERSION,
            "ready_to_enable": False,
            "mutates_host": False,
            "mutates_provider": False,
            "error": str(exc),
            "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready_to_enable") is True else 2


def _runtime_secret_verify_blockers(report: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION:
        blockers.append("runtime_secret_verify_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("runtime_secret_verify_not_ready")
    if report.get("ready_for_managed_payment_staging") is not True:
        blockers.append("runtime_secret_payment_staging_not_ready")
    stripe = _mapping(report.get("stripe_runtime_env"))
    managed = _mapping(stripe.get("FUSEKIT_MANAGED_RUNS_ENABLED"))
    secret = _mapping(stripe.get("FUSEKIT_STRIPE_SECRET_KEY"))
    webhook = _mapping(stripe.get("FUSEKIT_STRIPE_WEBHOOK_SECRET"))
    if managed.get("enabled") is not False:
        blockers.append("managed_runs_must_be_disabled_before_enablement")
    if secret.get("account_mode") != "live":
        blockers.append("stripe_secret_key_must_be_live")
    if webhook.get("configured") is not True or webhook.get("valid_shape") is not True:
        blockers.append("stripe_webhook_secret_not_ready")
    return blockers


def _hosted_verify_blockers(report: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION:
        blockers.append("hosted_verify_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("hosted_verify_not_ready")
    if report.get("blocking_checks") != []:
        blockers.append("hosted_verify_blocking_checks_not_empty")
    checks = _checks_by_id(report.get("checks"))
    for check_id in (
        "hosted.home",
        "hosted.health",
        "hosted.readiness",
        "hosted.deployment",
        "hosted.github_intake",
        "hosted.stripe_webhook_fail_closed",
        "hosted.expected_commit",
        "worker_dispatch.health",
        "worker_dispatch.readiness",
    ):
        if _mapping(checks.get(check_id)).get("status") != "ok":
            blockers.append(f"{check_id}_not_ok")
    return blockers


def _stripe_price_verify_blockers(report: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION:
        blockers.append("stripe_price_verify_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("stripe_price_verify_not_ready")
    if report.get("account_mode") != "live":
        blockers.append("stripe_price_verify_not_live")
    if _string_list(report.get("blockers")):
        blockers.append("stripe_price_verify_blockers_not_empty")
    if not _valid_stripe_price_id(str(report.get("price_id") or "")):
        blockers.append("stripe_price_id_invalid")
    if not _valid_price_label(str(report.get("price_label") or "")):
        blockers.append("managed_run_price_label_invalid")
    checks = _mapping(report.get("checks"))
    for key, value in checks.items():
        if value is not True:
            blockers.append(f"stripe_price_check_{key}_not_true")
    return blockers


def _stripe_webhook_verify_blockers(report: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION:
        blockers.append("stripe_webhook_verify_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("stripe_webhook_verify_not_ready")
    if report.get("account_mode") != "live":
        blockers.append("stripe_webhook_verify_not_live")
    if _string_list(report.get("blockers")):
        blockers.append("stripe_webhook_verify_blockers_not_empty")
    checks = _mapping(report.get("checks"))
    for key, value in checks.items():
        if value is not True:
            blockers.append(f"stripe_webhook_check_{key}_not_true")
    endpoint_url = str(report.get("endpoint_url") or "")
    if endpoint_url != "https://fusekit.snowmanai.org/api/hosted/payments/stripe-webhook":
        blockers.append("stripe_webhook_endpoint_url_mismatch")
    return blockers


def _hosted_readiness_blockers(report: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != "fusekit.hosted-readiness.v1":
        blockers.append("hosted_readiness_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("hosted_readiness_not_ready")
    if _job_store_ready(report) is not True:
        blockers.append("hosted_job_store_not_ready")
    if _managed_runs_disabled(report) is not True:
        blockers.append("managed_runs_must_be_disabled_before_enablement")
    if _byo_lane_launchable(report) is not True:
        blockers.append("byo_lane_must_remain_launchable")
    managed = _lane(report, MANAGED_FUSEKIT_RUN_LANE)
    if managed.get("blocking_checks") != ["managed_runs_not_enabled"]:
        blockers.append("managed_lane_blockers_not_enablement_only")
    payment = _mapping(report.get("payment"))
    if payment.get("account_mode") != "live":
        blockers.append("hosted_payment_account_mode_not_live")
    if payment.get("live_mode_configured") is not True:
        blockers.append("hosted_payment_live_mode_not_configured")
    if payment.get("price_configured") is not True:
        blockers.append("hosted_payment_price_not_configured")
    if payment.get("price_label_configured") is not True:
        blockers.append("hosted_payment_price_label_not_configured")
    if payment.get("enabled") is not False or payment.get("managed_runs_enabled") is not False:
        blockers.append("managed_runs_must_be_disabled_before_enablement")
    return blockers


def _live_checkout_proof_blockers(
    report: Mapping[str, Any], hosted_verify: Mapping[str, Any]
) -> list[str]:
    blockers: list[str] = []
    if report.get("schema_version") != HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION:
        blockers.append("live_checkout_proof_schema_mismatch")
    if report.get("ready") is not True:
        blockers.append("live_checkout_proof_not_ready")
    if report.get("lane") != MANAGED_FUSEKIT_RUN_LANE:
        blockers.append("live_checkout_lane_mismatch")
    for key in (
        "checkout_session_paid",
        "webhook_applied",
        "worker_dispatch_acceptance",
        "dispatch_requires_paid_checkout_session",
    ):
        if report.get(key) is not True:
            blockers.append(f"live_checkout_{key}_not_true")
    if report.get("payment_status") != "paid":
        blockers.append("live_checkout_payment_status_not_paid")
    proof_commit = _valid_git_sha(str(report.get("expected_commit_sha") or ""))
    hosted_commit = _hosted_verified_commit(hosted_verify)
    if not proof_commit:
        blockers.append("live_checkout_expected_commit_sha_missing")
    elif hosted_commit and proof_commit != hosted_commit:
        blockers.append("live_checkout_expected_commit_sha_mismatch")
    boundary = report.get("secret_boundary")
    if (
        not isinstance(boundary, str)
        or "card data" not in boundary
        or "Stripe keys" not in boundary
        or "worker secrets" not in boundary
        or "provider credentials" not in boundary
    ):
        blockers.append("live_checkout_secret_boundary_missing")
    return blockers


def _live_checkout_bound_to_hosted_commit(
    live_checkout_proof: Mapping[str, Any], hosted_verify: Mapping[str, Any]
) -> bool:
    proof_commit = _valid_git_sha(str(live_checkout_proof.get("expected_commit_sha") or ""))
    hosted_commit = _hosted_verified_commit(hosted_verify)
    return bool(proof_commit and hosted_commit and proof_commit == hosted_commit)


def _hosted_verified_commit(report: Mapping[str, Any]) -> str:
    check = _mapping(_checks_by_id(report.get("checks")).get("hosted.expected_commit"))
    if check.get("status") != "ok":
        return ""
    expected = _valid_git_sha(str(check.get("expected_commit_sha") or ""))
    actual = _valid_git_sha(str(check.get("actual_commit_sha") or ""))
    if not expected or expected != actual:
        return ""
    return actual


def _valid_git_sha(value: str) -> str:
    return value if len(value) == 40 and all(char in "0123456789abcdef" for char in value) else ""


def _job_store_ready(report: Mapping[str, Any]) -> bool:
    store = _mapping(report.get("job_store"))
    return (
        store.get("configured") is True
        and store.get("writable") is True
        and store.get("path_configured") is True
        and store.get("stores_public_snapshots_only") is True
    )


def _managed_runs_disabled(report: Mapping[str, Any]) -> bool:
    payment = _mapping(report.get("payment"))
    return payment.get("enabled") is False and payment.get("managed_runs_enabled") is False


def _byo_lane_launchable(report: Mapping[str, Any]) -> bool:
    return _lane(report, BYO_OCI_LANE).get("launchable") is True


def _lane(report: Mapping[str, Any], lane_id: str) -> Mapping[str, Any]:
    lane_readiness = _mapping(report.get("lane_readiness"))
    lanes = _mapping(lane_readiness.get("lanes"))
    return _mapping(lanes.get(lane_id))


def _checks_by_id(value: object) -> dict[str, Mapping[str, Any]]:
    checks: dict[str, Mapping[str, Any]] = {}
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return checks
    for item in value:
        if isinstance(item, Mapping):
            check_id = item.get("id")
            if isinstance(check_id, str):
                checks[check_id] = item
    return checks


def _read_json(path: str) -> Mapping[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise FuseKitError("managed_enablement_proof_file_symlink")
    _reject_symlinked_parents(candidate)
    try:
        value = _read_json_no_follow(candidate)
    except OSError as exc:
        raise FuseKitError("managed_enablement_proof_file_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("managed_enablement_proof_file_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("managed_enablement_proof_file_must_be_object")
    return value


def _reject_symlinked_parents(candidate: Path) -> None:
    for parent in candidate.parents:
        if parent == Path("."):
            continue
        if parent.is_symlink():
            raise FuseKitError("managed_enablement_proof_file_parent_symlink")


def _read_json_no_follow(candidate: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(candidate, flags)
    try:
        file_status = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise FuseKitError("managed_enablement_proof_file_not_file")
        if file_status.st_size > HOSTED_MANAGED_ENABLEMENT_MAX_JSON_BYTES:
            raise FuseKitError("managed_enablement_proof_file_too_large")
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            return json.load(handle)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value]


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _next_actions(blockers: Sequence[str], *, written: bool = False) -> list[str]:
    if written:
        return [
            "Restart fusekit-hosted.service after this file write.",
            "Run fusekit-hosted-verify and a live managed Checkout smoke test.",
            "Keep rollback metadata and the prior release receipt attached to the run record.",
        ]
    if blockers:
        return [
            "Collect fresh hosted verifier, runtime-secret verifier, Stripe price verifier, "
            "Stripe webhook verifier, public readiness, and live Checkout/dispatch proof.",
            "Do not enable FUSEKIT_MANAGED_RUNS_ENABLED until this report is ready.",
        ]
    return [
        "Re-run with --execute --confirm-managed-enablement on the hosted OCI VM.",
        "Restart fusekit-hosted.service after the write and immediately verify public readiness.",
    ]


def _assert_public_report(report: Mapping[str, object]) -> None:
    text = json.dumps(report, sort_keys=True)
    if contains_durable_secret_text(text) or contains_private_marker_text(text):
        raise FuseKitError("managed_enablement_report_contains_secret_text")


if __name__ == "__main__":
    raise SystemExit(main())
