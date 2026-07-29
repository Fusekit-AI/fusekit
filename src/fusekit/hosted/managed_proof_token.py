"""Operator token helper for hosted managed Checkout proof runs."""

from __future__ import annotations

import argparse
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import GitHubAppConfig, github_app_install_url
from fusekit.hosted.job_store import hosted_job_store_status
from fusekit.hosted.lanes import BYO_OCI_LANE, MANAGED_FUSEKIT_RUN_LANE
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_FILE,
    HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION,
    _parse_systemd_env_file,
    verify_hosted_runtime_secret_file,
)
from fusekit.hosted.session import (
    HOSTED_STATE_TTL_SECONDS,
    create_hosted_state_token,
)

HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION = (
    "fusekit.hosted-managed-proof-token-report.v1"
)
HOSTED_MANAGED_PROOF_TOKEN_SECRET_BOUNDARY = (
    "The managed proof state is the normal short-lived GitHub OAuth state token "
    "with an operator-only proof purpose. It is not a Stripe key, webhook secret, "
    "GitHub private key, worker secret, OCI credential, provider credential, or "
    "vault secret. Do not store it in docs, logs, or durable receipts."
)
HOSTED_MANAGED_PROOF_TOKEN_MAX_JSON_BYTES = 1_048_576


def build_hosted_managed_proof_token_report(
    *,
    state_secret: str,
    github_app_slug: str = "",
    runtime_secret_verify: Mapping[str, object] | None = None,
    hosted_readiness: Mapping[str, object] | None = None,
    include_token: bool = True,
) -> dict[str, object]:
    """Return an operator-use token report without exposing raw runtime secrets."""

    blockers = _managed_proof_preflight_blockers(
        runtime_secret_verify=runtime_secret_verify,
        hosted_readiness=hosted_readiness,
    )
    ready = not blockers
    state_token = (
        create_hosted_state_token(
            state_secret,
            return_path="/",
            managed_proof=True,
        )
        if ready
        else ""
    )
    install_url = ""
    if ready and github_app_slug:
        install_url = github_app_install_url(
            GitHubAppConfig(
                app_id="0",
                app_slug=github_app_slug,
                private_key_pem="",
            ),
            state=state_token,
        )
    report: dict[str, object] = {
        "schema_version": HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
        "query_param": "state",
        "state_token_present": bool(state_token),
        "install_url_present": bool(install_url),
        "ready": ready,
        "blockers": blockers,
        "expires_in_seconds": HOSTED_STATE_TTL_SECONDS,
        "preflight": {
            "runtime_secret_verify_ready": _mapping(runtime_secret_verify).get("ready") is True,
            "hosted_readiness_ready": _mapping(hosted_readiness).get("ready") is True,
            "job_store_ready": _job_store_ready(_mapping(hosted_readiness)),
            "managed_lane_disabled_for_enablement": _managed_lane_enablement_only(
                _mapping(hosted_readiness)
            ),
            "byo_lane_launchable": _lane_launchable(_mapping(hosted_readiness), BYO_OCI_LANE),
        },
        "operator_use": (
            "Visit install_url when present, or use state=<state_token> in the "
            "GitHub App install URL for the supervised managed Checkout proof run."
        ),
        "public_managed_runs_enabled": False,
        "mutates_host": False,
        "mutates_provider": False,
        "secret_boundary": HOSTED_MANAGED_PROOF_TOKEN_SECRET_BOUNDARY,
    }
    if include_token:
        report["state_token"] = state_token
        report["install_url"] = install_url
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a short-lived hosted managed Checkout proof token."
    )
    parser.add_argument("--runtime-secret-file", default=HOSTED_RUNTIME_SECRET_FILE)
    parser.add_argument("--state-secret-env", default="FUSEKIT_HOSTED_STATE_SECRET")
    parser.add_argument("--hosted-readiness-report", default="")
    parser.add_argument(
        "--redacted",
        action="store_true",
        help="Emit durable preflight proof without the short-lived state token or install URL.",
    )
    args = parser.parse_args(argv)
    try:
        state_secret = os.environ.get(args.state_secret_env, "")
        github_app_slug = os.environ.get("FUSEKIT_GITHUB_APP_SLUG", "")
        runtime_secret_verify = verify_hosted_runtime_secret_file(path=args.runtime_secret_file)
        if runtime_secret_verify.get("ready") is not True:
            raise FuseKitError("managed_proof_token_runtime_secret_file_preflight_not_ready")
        material, failures = _parse_systemd_env_file(Path(args.runtime_secret_file))
        if failures:
            raise FuseKitError("managed_proof_token_runtime_secret_file_invalid")
        state_secret = state_secret or material.get("FUSEKIT_HOSTED_STATE_SECRET", "")
        github_app_slug = github_app_slug or material.get("FUSEKIT_GITHUB_APP_SLUG", "")
        hosted_readiness = (
            _read_json(args.hosted_readiness_report)
            if args.hosted_readiness_report
            else _fetch_hosted_readiness(material.get("FUSEKIT_HOSTED_ORIGIN", ""))
        )
        report = build_hosted_managed_proof_token_report(
            state_secret=state_secret,
            github_app_slug=github_app_slug,
            runtime_secret_verify=runtime_secret_verify,
            hosted_readiness=hosted_readiness,
            include_token=not args.redacted,
        )
    except (FuseKitError, OSError) as exc:
        report = {
            "schema_version": HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
            "error": str(exc),
            "mutates_host": False,
            "mutates_provider": False,
            "secret_boundary": "Managed proof token errors never emit secret values.",
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 2


def _managed_proof_preflight_blockers(
    *,
    runtime_secret_verify: Mapping[str, object] | None,
    hosted_readiness: Mapping[str, object] | None,
) -> list[str]:
    blockers: list[str] = []
    runtime = _mapping(runtime_secret_verify)
    readiness = _mapping(hosted_readiness)
    if runtime.get("schema_version") != HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION:
        blockers.append("runtime_secret_verify_schema_mismatch")
    if runtime.get("ready") is not True:
        blockers.append("runtime_secret_verify_not_ready")
    if runtime.get("ready_for_managed_payment_staging") is not True:
        blockers.append("runtime_secret_payment_staging_not_ready")
    stripe = _mapping(runtime.get("stripe_runtime_env"))
    managed = _mapping(stripe.get("FUSEKIT_MANAGED_RUNS_ENABLED"))
    webhook = _mapping(stripe.get("FUSEKIT_STRIPE_WEBHOOK_SECRET"))
    if managed.get("enabled") is not False:
        blockers.append("managed_runs_must_be_disabled_before_proof")
    if webhook.get("configured") is not True or webhook.get("valid_shape") is not True:
        blockers.append("stripe_webhook_secret_required_for_managed_proof")
    if readiness.get("schema_version") != "fusekit.hosted-readiness.v1":
        blockers.append("hosted_readiness_schema_mismatch")
    if readiness.get("ready") is not True:
        blockers.append("hosted_readiness_not_ready")
    if _string_list(readiness.get("blocking_checks")):
        blockers.append("hosted_readiness_blocking_checks_not_empty")
    if not _job_store_ready(readiness):
        blockers.append("hosted_job_store_not_ready")
    if not _managed_lane_enablement_only(readiness):
        blockers.append("managed_lane_must_be_blocked_only_by_enablement")
    if not _lane_launchable(readiness, BYO_OCI_LANE):
        blockers.append("byo_lane_must_remain_launchable")
    payment = _mapping(readiness.get("payment"))
    if payment.get("account_mode") != "live":
        blockers.append("hosted_payment_account_mode_not_live")
    if payment.get("live_mode_configured") is not True:
        blockers.append("hosted_payment_live_mode_not_configured")
    if payment.get("price_configured") is not True:
        blockers.append("hosted_payment_price_not_configured")
    if payment.get("price_label_configured") is not True:
        blockers.append("hosted_payment_price_label_not_configured")
    if payment.get("enabled") is not False or payment.get("managed_runs_enabled") is not False:
        blockers.append("managed_runs_must_be_disabled_before_proof")
    return _unique(blockers)


def _fetch_hosted_readiness(origin: str) -> Mapping[str, object]:
    parsed = urllib.parse.urlparse(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"}:
        raise FuseKitError("managed_proof_token_hosted_origin_invalid")
    url = origin.rstrip("/") + "/api/hosted/readiness"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "FuseKit"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15.0) as response:  # nosec B310
            raw = response.read(1_000_000)
            status = int(getattr(response, "status", 200))
    except (OSError, urllib.error.URLError) as exc:
        raise FuseKitError("managed_proof_token_hosted_readiness_unreachable") from exc
    if status >= 400:
        raise FuseKitError("managed_proof_token_hosted_readiness_unavailable")
    try:
        decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("managed_proof_token_hosted_readiness_invalid") from exc
    if not isinstance(decoded, Mapping):
        raise FuseKitError("managed_proof_token_hosted_readiness_invalid")
    return decoded


def _read_json(path: str) -> Mapping[str, object]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise FuseKitError("managed_proof_token_report_symlink")
    _reject_symlinked_parents(candidate)
    try:
        decoded = _read_json_no_follow(candidate)
    except OSError as exc:
        raise FuseKitError("managed_proof_token_report_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("managed_proof_token_report_invalid_json") from exc
    if not isinstance(decoded, Mapping):
        raise FuseKitError("managed_proof_token_report_must_be_object")
    return decoded


def _reject_symlinked_parents(candidate: Path) -> None:
    for parent in candidate.parents:
        if parent == Path("."):
            continue
        if parent.is_symlink():
            raise FuseKitError("managed_proof_token_report_parent_symlink")


def _read_json_no_follow(candidate: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(candidate, flags)
    try:
        file_status = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise FuseKitError("managed_proof_token_report_not_file")
        if file_status.st_size > HOSTED_MANAGED_PROOF_TOKEN_MAX_JSON_BYTES:
            raise FuseKitError("managed_proof_token_report_too_large")
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            return json.load(handle)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _job_store_ready(report: Mapping[str, object]) -> bool:
    store = _mapping(report.get("job_store"))
    if not store:
        store = hosted_job_store_status("")
    return (
        store.get("configured") is True
        and store.get("writable") is True
        and store.get("path_configured") is True
        and store.get("stores_public_snapshots_only") is True
    )


def _managed_lane_enablement_only(report: Mapping[str, object]) -> bool:
    managed = _lane(report, MANAGED_FUSEKIT_RUN_LANE)
    return (
        managed.get("launchable") is False
        and managed.get("blocking_checks") == ["managed_runs_not_enabled"]
    )


def _lane_launchable(report: Mapping[str, object], lane_id: str) -> bool:
    return _lane(report, lane_id).get("launchable") is True


def _lane(report: Mapping[str, object], lane_id: str) -> Mapping[str, object]:
    lane_readiness = _mapping(report.get("lane_readiness"))
    lanes = _mapping(lane_readiness.get("lanes"))
    return _mapping(lanes.get(lane_id))


def _mapping(value: object) -> Mapping[str, object]:
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


if __name__ == "__main__":
    raise SystemExit(main())
