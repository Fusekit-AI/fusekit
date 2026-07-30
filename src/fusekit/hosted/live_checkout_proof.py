"""Build redacted live managed Checkout proof from hosted receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_PAYMENT_SCHEMA_VERSION,
    STRIPE_CHECKOUT_PROVIDER,
    _price_label_matches_checkout_receipt,
    _valid_price_label,
    _valid_sha256_label,
    _valid_stripe_checkout_session_id,
)
from fusekit.hosted.job_store import (
    HOSTED_JOB_STORE_MANAGED_START_RESPONSE_BOUNDARY,
    HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION,
    HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
    HOSTED_JOB_STORE_WEBHOOK_RECEIPT_BOUNDARY,
    HOSTED_STRIPE_WEBHOOK_NEXT_REQUIRED_PROOF,
    HOSTED_STRIPE_WEBHOOK_RECEIPT_KEYS,
    HOSTED_STRIPE_WEBHOOK_SECRET_BOUNDARY_TERMS,
)
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE
from fusekit.hosted.managed_enablement import (
    HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
    HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
)
from fusekit.hosted.server import (
    HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
    HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
)
from fusekit.security import contains_durable_secret_text, contains_private_marker_text

HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_INPUT_SCHEMA_VERSION = (
    "fusekit.hosted-managed-live-checkout-proof-input.v1"
)
HOSTED_MANAGED_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-stripe-webhook.v1"
HOSTED_JOB_ID_PATTERN = re.compile(r"\Ahosted-[A-Za-z0-9_-]{8,160}\Z")
DEFAULT_HOSTED_JOB_STORE_DIR = "/var/lib/fusekit/hosted-jobs"
HOSTED_LIVE_CHECKOUT_PROOF_MAX_JSON_BYTES = 1_048_576
HOSTED_LIVE_CHECKOUT_METADATA_FIELDS = (
    "job_id",
    "lane",
    "github_source_hash",
    "plan_fingerprint",
    "stripe_price_id_hash",
    "price_label_hash",
)
HOSTED_LIVE_CHECKOUT_HASH_FIELDS = frozenset(
    {
        "github_source_hash",
        "plan_fingerprint",
        "stripe_price_id_hash",
        "price_label_hash",
    }
)
HOSTED_LIVE_CHECKOUT_DISPATCH_HASH_FIELDS = (
    "plan_fingerprint",
    "stripe_price_id_hash",
    "price_label_hash",
)
HOSTED_LIVE_CHECKOUT_WEBHOOK_WRAPPER_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "receipt_schema_version",
        "receipt_sha256",
        "receipt",
        "secret_boundary",
    }
)
HOSTED_LIVE_CHECKOUT_START_WRAPPER_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "response_schema_version",
        "response_sha256",
        "response",
        "secret_boundary",
    }
)


def build_hosted_managed_live_checkout_proof(
    *,
    webhook_receipt: Mapping[str, Any],
    start_action_response: Mapping[str, Any],
    expected_commit_sha: str = "",
) -> dict[str, object]:
    """Validate live managed payment receipts and emit enablement-ready proof."""

    blockers: list[str] = []
    blockers.extend(_webhook_receipt_blockers(webhook_receipt))
    blockers.extend(_start_action_response_blockers(start_action_response))
    webhook_job_id = _public_job_id(webhook_receipt.get("job_id"))
    start_job_id = _public_job_id(start_action_response.get("job_id"))
    job_id = start_job_id or webhook_job_id
    if webhook_job_id and start_job_id and webhook_job_id != start_job_id:
        blockers.append("live_checkout_job_id_mismatch")
    payment = _mapping(start_action_response.get("payment"))
    receipt = _mapping(payment.get("receipt"))
    worker_dispatch = _mapping(start_action_response.get("worker_dispatch"))
    dispatch_binding = _mapping(worker_dispatch.get("dispatch_binding"))
    if dispatch_binding.get("job_id") != job_id:
        blockers.append("live_checkout_dispatch_job_id_mismatch")
    if dispatch_binding.get("lane") != MANAGED_FUSEKIT_RUN_LANE:
        blockers.append("live_checkout_dispatch_lane_mismatch")
    if dispatch_binding.get("payment_status") != "paid":
        blockers.append("live_checkout_dispatch_payment_status_not_paid")
    if receipt.get("client_reference_id") != job_id:
        blockers.append("live_checkout_checkout_client_reference_mismatch")
    metadata = _mapping(receipt.get("metadata"))
    if metadata.get("job_id") != job_id:
        blockers.append("live_checkout_checkout_metadata_job_mismatch")
    if metadata.get("lane") != MANAGED_FUSEKIT_RUN_LANE:
        blockers.append("live_checkout_checkout_metadata_lane_mismatch")
    for field in ("plan_fingerprint", "stripe_price_id_hash", "price_label_hash"):
        if dispatch_binding.get(field) != metadata.get(field):
            blockers.append(f"live_checkout_{field}_binding_mismatch")
    if expected_commit_sha and not re.fullmatch(r"[0-9a-f]{40}", expected_commit_sha):
        blockers.append("live_checkout_expected_commit_sha_invalid")
    blockers = _unique(blockers)
    proof: dict[str, object] = {
        "schema_version": HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
        "input_schema_version": HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_INPUT_SCHEMA_VERSION,
        "ready": not blockers,
        "blockers": blockers,
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "job_id": job_id,
        "payment_status": "paid" if payment.get("status") == "paid" else "",
        "checkout_session_paid": _paid_checkout_receipt_ready(receipt),
        "webhook_applied": webhook_receipt.get("payment_applied") is True,
        "worker_dispatch_acceptance": _worker_dispatch_ready(worker_dispatch),
        "dispatch_requires_paid_checkout_session": (
            dispatch_binding.get("payment_status") == "paid"
            and payment.get("status") == "paid"
            and receipt.get("paid") is True
        ),
        "expected_commit_sha": expected_commit_sha,
        "proof_inputs": {
            "webhook_receipt_schema": webhook_receipt.get("schema_version", ""),
            "start_action_schema": start_action_response.get("schema_version", ""),
            "worker_dispatch_schema": worker_dispatch.get("schema_version", ""),
            "worker_dispatch_receiver_schema": worker_dispatch.get(
                "receiver_schema_version", ""
            ),
        },
        "proof_artifacts": {
            "webhook_receipt": f"{job_id}.stripe-webhook-receipt.json" if job_id else "",
            "webhook_receipt_sha256": _payload_hash(webhook_receipt),
            "managed_start_response": (
                f"{job_id}.managed-start-response.json" if job_id else ""
            ),
            "managed_start_response_sha256": _payload_hash(start_action_response),
            "live_checkout_proof": "live-checkout-proof.json",
        },
        "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
    }
    if blockers:
        proof["ready"] = False
    _assert_public_proof(proof)
    return proof


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build redacted live managed Checkout proof from hosted receipts."
    )
    parser.add_argument("--webhook-receipt")
    parser.add_argument("--start-action-response")
    parser.add_argument("--job-id", default="")
    parser.add_argument("--job-store-dir", default=DEFAULT_HOSTED_JOB_STORE_DIR)
    parser.add_argument("--expected-commit-sha", default="")
    args = parser.parse_args(argv)
    try:
        webhook_receipt_path, start_action_response_path = _input_paths(
            webhook_receipt=args.webhook_receipt or "",
            start_action_response=args.start_action_response or "",
            job_id=args.job_id,
            job_store_dir=args.job_store_dir,
        )
        proof = build_hosted_managed_live_checkout_proof(
            webhook_receipt=_read_webhook_receipt_json(webhook_receipt_path),
            start_action_response=_read_start_action_response_json(
                start_action_response_path
            ),
            expected_commit_sha=args.expected_commit_sha,
        )
    except FuseKitError as exc:
        proof = _error_proof(
            str(exc),
            job_id=args.job_id,
            job_store_dir=args.job_store_dir,
            expected_commit_sha=args.expected_commit_sha,
        )
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0 if proof.get("ready") is True else 2


def _error_proof(
    error: str,
    *,
    job_id: str = "",
    job_store_dir: str = DEFAULT_HOSTED_JOB_STORE_DIR,
    expected_commit_sha: str = "",
) -> dict[str, object]:
    public_job_id = _public_job_id(job_id)
    proof: dict[str, object] = {
        "schema_version": HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
        "ready": False,
        "error": error,
        "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
    }
    if public_job_id:
        expected_artifacts = {
            "webhook_receipt": f"{public_job_id}.stripe-webhook-receipt.json",
            "managed_start_response": f"{public_job_id}.managed-start-response.json",
            "job_store": (
                "default_hosted_job_store"
                if job_store_dir == DEFAULT_HOSTED_JOB_STORE_DIR
                else "configured_job_store"
            ),
        }
        proof["expected_artifacts"] = expected_artifacts
        proof["next_actions"] = [
            "Complete the supervised managed Checkout proof run from the short-lived "
            "managed-proof install URL.",
            "Wait for Stripe's signed checkout.session.completed webhook to write the "
            "redacted webhook receipt.",
            "Use the paid managed start action so worker dispatch acceptance writes the "
            "redacted managed-start response.",
            "Re-run fusekit-hosted-live-checkout-proof with this job id and the current "
            "hosted deployment commit.",
        ]
        commit_label = (
            expected_commit_sha
            if _valid_git_sha(expected_commit_sha)
            else "<current-commit-sha>"
        )
        proof["retry_command"] = (
            "fusekit-hosted-live-checkout-proof "
            f"--job-id {public_job_id} "
            "--expected-commit-sha "
            f"{commit_label}"
        )
    _assert_public_proof(proof)
    return proof


def _webhook_receipt_blockers(receipt: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if set(str(key) for key in receipt) != HOSTED_STRIPE_WEBHOOK_RECEIPT_KEYS:
        blockers.append("live_checkout_webhook_shape_mismatch")
    if receipt.get("schema_version") != HOSTED_MANAGED_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION:
        blockers.append("live_checkout_webhook_schema_mismatch")
    if receipt.get("action") != "payment_webhook":
        blockers.append("live_checkout_webhook_action_mismatch")
    if receipt.get("event_type") != "checkout.session.completed":
        blockers.append("live_checkout_webhook_event_type_mismatch")
    if receipt.get("accepted") is not True:
        blockers.append("live_checkout_webhook_not_accepted")
    if receipt.get("payment_applied") is not True:
        blockers.append("live_checkout_webhook_applied_not_true")
    if receipt.get("payment_status") != "paid":
        blockers.append("live_checkout_webhook_payment_status_not_paid")
    if receipt.get("managed_worker_dispatch_unlocked") is not True:
        blockers.append("live_checkout_webhook_dispatch_not_unlocked")
    if receipt.get("worker_dispatch_sent") is not False:
        blockers.append("live_checkout_webhook_must_not_dispatch_worker")
    if receipt.get("next_required_proof") != list(HOSTED_STRIPE_WEBHOOK_NEXT_REQUIRED_PROOF):
        blockers.append("live_checkout_webhook_next_required_proof_mismatch")
    boundary = receipt.get("secret_boundary")
    if not isinstance(boundary, str) or not all(
        term in boundary for term in HOSTED_STRIPE_WEBHOOK_SECRET_BOUNDARY_TERMS
    ):
        blockers.append("live_checkout_webhook_secret_boundary_missing")
    if not _public_job_id(receipt.get("job_id")):
        blockers.append("live_checkout_webhook_job_id_invalid")
    return blockers


def _start_action_response_blockers(response: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if response.get("schema_version") != "fusekit.hosted-job.v1":
        blockers.append("live_checkout_start_job_schema_mismatch")
    if response.get("launch_lane") != MANAGED_FUSEKIT_RUN_LANE:
        blockers.append("live_checkout_start_lane_mismatch")
    if response.get("status") != "waiting_for_provider_gates":
        blockers.append("live_checkout_start_status_mismatch")
    if not _public_job_id(response.get("job_id")):
        blockers.append("live_checkout_start_job_id_invalid")
    blockers.extend(_payment_blockers(response.get("payment")))
    blockers.extend(_worker_dispatch_blockers(response.get("worker_dispatch")))
    action_receipt = _mapping(response.get("action_receipt"))
    if action_receipt.get("action") != "start":
        blockers.append("live_checkout_action_receipt_start_missing")
    return blockers


def _payment_blockers(value: object) -> list[str]:
    payment = _mapping(value)
    receipt = _mapping(payment.get("receipt"))
    metadata = _mapping(receipt.get("metadata"))
    blockers: list[str] = []
    if payment.get("required") is not True:
        blockers.append("live_checkout_payment_not_required")
    if payment.get("status") != "paid":
        blockers.append("live_checkout_payment_status_not_paid")
    if payment.get("price_label") != receipt.get("price_label"):
        blockers.append("live_checkout_price_label_mismatch")
    if payment.get("price_id_hash") != metadata.get("stripe_price_id_hash"):
        blockers.append("live_checkout_price_id_hash_mismatch")
    if receipt.get("schema_version") != HOSTED_PAYMENT_SCHEMA_VERSION:
        blockers.append("live_checkout_payment_schema_mismatch")
    if receipt.get("provider") != STRIPE_CHECKOUT_PROVIDER:
        blockers.append("live_checkout_payment_provider_mismatch")
    session_id = receipt.get("checkout_session_id")
    if not isinstance(session_id, str) or not _valid_stripe_checkout_session_id(session_id):
        blockers.append("live_checkout_checkout_session_id_invalid")
    if receipt.get("paid") is not True:
        blockers.append("live_checkout_checkout_session_paid_not_true")
    if receipt.get("status") != "complete":
        blockers.append("live_checkout_checkout_status_not_complete")
    if receipt.get("payment_status") != "paid":
        blockers.append("live_checkout_checkout_payment_status_not_paid")
    if receipt.get("mode") != "payment":
        blockers.append("live_checkout_checkout_mode_mismatch")
    if not isinstance(receipt.get("amount_total"), int) or receipt.get("amount_total", 0) <= 0:
        blockers.append("live_checkout_checkout_amount_invalid")
    currency = receipt.get("currency")
    if not isinstance(currency, str) or len(currency) != 3:
        blockers.append("live_checkout_checkout_currency_invalid")
    price_label = receipt.get("price_label")
    if not isinstance(price_label, str) or not _valid_price_label(price_label):
        blockers.append("live_checkout_price_label_invalid")
    elif not _price_label_matches_checkout_receipt(
        price_label,
        amount_total=receipt.get("amount_total"),
        currency=receipt.get("currency"),
    ):
        blockers.append("live_checkout_price_label_amount_currency_mismatch")
    for field in HOSTED_LIVE_CHECKOUT_METADATA_FIELDS:
        if field not in metadata:
            blockers.append(f"live_checkout_checkout_metadata_{field}_missing")
        elif field in HOSTED_LIVE_CHECKOUT_HASH_FIELDS and not _valid_sha256_label(
            str(metadata.get(field) or "")
        ):
            blockers.append(f"live_checkout_checkout_metadata_{field}_invalid")
    return blockers


def _worker_dispatch_blockers(value: object) -> list[str]:
    dispatch = _mapping(value)
    dispatch_binding = _mapping(dispatch.get("dispatch_binding"))
    idempotency = _mapping(dispatch.get("idempotency"))
    blockers: list[str] = []
    if dispatch.get("schema_version") != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        blockers.append("live_checkout_worker_dispatch_schema_mismatch")
    if dispatch.get("action") != "start":
        blockers.append("live_checkout_worker_dispatch_action_mismatch")
    if dispatch.get("dispatched") is not True:
        blockers.append("live_checkout_worker_dispatch_not_sent")
    if dispatch.get("accepted") is not True:
        blockers.append("live_checkout_worker_dispatch_not_accepted")
    if dispatch.get("receiver_schema_version") != HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION:
        blockers.append("live_checkout_worker_dispatch_receiver_schema_mismatch")
    for field in HOSTED_LIVE_CHECKOUT_DISPATCH_HASH_FIELDS:
        if not _valid_sha256_label(str(dispatch_binding.get(field) or "")):
            blockers.append(f"live_checkout_worker_dispatch_{field}_invalid")
    if idempotency.get("mode") != "dispatch-state-dir":
        blockers.append("live_checkout_worker_dispatch_idempotency_mode_mismatch")
    if idempotency.get("durable") is not True:
        blockers.append("live_checkout_worker_dispatch_idempotency_not_durable")
    if idempotency.get("scope") != "worker deployment":
        blockers.append("live_checkout_worker_dispatch_idempotency_scope_mismatch")
    proof = idempotency.get("proof")
    if not isinstance(proof, str) or "before worker spawn" not in proof:
        blockers.append("live_checkout_worker_dispatch_idempotency_proof_missing")
    return blockers


def _paid_checkout_receipt_ready(receipt: Mapping[str, Any]) -> bool:
    return (
        receipt.get("paid") is True
        and receipt.get("status") == "complete"
        and receipt.get("payment_status") == "paid"
        and receipt.get("mode") == "payment"
    )


def _worker_dispatch_ready(dispatch: Mapping[str, Any]) -> bool:
    idempotency = _mapping(dispatch.get("idempotency"))
    return (
        dispatch.get("dispatched") is True
        and dispatch.get("accepted") is True
        and dispatch.get("action") == "start"
        and idempotency.get("durable") is True
        and idempotency.get("mode") == "dispatch-state-dir"
    )


def _public_job_id(value: object) -> str:
    if not isinstance(value, str) or not HOSTED_JOB_ID_PATTERN.fullmatch(value):
        return ""
    if contains_durable_secret_text(value) or contains_private_marker_text(value):
        return ""
    return value


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _read_json(path: str) -> Mapping[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise FuseKitError("live_checkout_proof_input_symlink")
    _reject_symlinked_parents(candidate)
    try:
        value = _read_json_no_follow(candidate)
    except OSError as exc:
        raise FuseKitError("live_checkout_proof_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("live_checkout_proof_input_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("live_checkout_proof_input_must_be_object")
    return value


def _reject_symlinked_parents(candidate: Path) -> None:
    for parent in candidate.parents:
        if parent == Path("."):
            continue
        if parent.is_symlink():
            raise FuseKitError("live_checkout_proof_input_parent_symlink")


def _read_json_no_follow(candidate: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(candidate, flags)
    try:
        file_status = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise FuseKitError("live_checkout_proof_input_not_file")
        if file_status.st_size > HOSTED_LIVE_CHECKOUT_PROOF_MAX_JSON_BYTES:
            raise FuseKitError("live_checkout_proof_input_too_large")
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            return json.load(handle)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _input_paths(
    *,
    webhook_receipt: str,
    start_action_response: str,
    job_id: str,
    job_store_dir: str,
) -> tuple[str, str]:
    if webhook_receipt and start_action_response:
        return webhook_receipt, start_action_response
    if webhook_receipt or start_action_response:
        raise FuseKitError("live_checkout_proof_requires_both_artifact_paths")
    public_job_id = _public_job_id(job_id)
    if not public_job_id:
        raise FuseKitError("live_checkout_proof_job_id_required")
    root = Path(job_store_dir)
    if not str(root).strip() or not root.is_absolute():
        raise FuseKitError("live_checkout_proof_job_store_dir_must_be_absolute")
    return (
        str(root / f"{public_job_id}.stripe-webhook-receipt.json"),
        str(root / f"{public_job_id}.managed-start-response.json"),
    )


def _read_webhook_receipt_json(path: str) -> Mapping[str, Any]:
    payload = _read_json(path)
    if (
        payload.get("schema_version")
        == HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION
    ):
        _require_exact_wrapper_keys(
            payload,
            expected=HOSTED_LIVE_CHECKOUT_WEBHOOK_WRAPPER_KEYS,
            error="live_checkout_proof_webhook_receipt_wrapper_shape_mismatch",
        )
        if payload.get("secret_boundary") != HOSTED_JOB_STORE_WEBHOOK_RECEIPT_BOUNDARY:
            raise FuseKitError(
                "live_checkout_proof_webhook_receipt_boundary_mismatch"
            )
        receipt = payload.get("receipt")
        if not isinstance(receipt, Mapping):
            raise FuseKitError("live_checkout_proof_webhook_receipt_missing")
        if payload.get("job_id") != receipt.get("job_id"):
            raise FuseKitError("live_checkout_proof_webhook_receipt_job_id_mismatch")
        if payload.get("receipt_schema_version") != receipt.get("schema_version"):
            raise FuseKitError("live_checkout_proof_webhook_receipt_schema_mismatch")
        if payload.get("receipt_sha256") != _payload_hash(receipt):
            raise FuseKitError("live_checkout_proof_webhook_receipt_hash_mismatch")
        return receipt
    return payload


def _read_start_action_response_json(path: str) -> Mapping[str, Any]:
    payload = _read_json(path)
    if (
        payload.get("schema_version")
        == HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION
    ):
        _require_exact_wrapper_keys(
            payload,
            expected=HOSTED_LIVE_CHECKOUT_START_WRAPPER_KEYS,
            error="live_checkout_proof_start_response_wrapper_shape_mismatch",
        )
        if (
            payload.get("secret_boundary")
            != HOSTED_JOB_STORE_MANAGED_START_RESPONSE_BOUNDARY
        ):
            raise FuseKitError("live_checkout_proof_start_response_boundary_mismatch")
        response = payload.get("response")
        if not isinstance(response, Mapping):
            raise FuseKitError("live_checkout_proof_start_response_missing")
        if payload.get("job_id") != response.get("job_id"):
            raise FuseKitError("live_checkout_proof_start_response_job_id_mismatch")
        if payload.get("response_schema_version") != response.get("schema_version"):
            raise FuseKitError("live_checkout_proof_start_response_schema_mismatch")
        if payload.get("response_sha256") != _payload_hash(response):
            raise FuseKitError("live_checkout_proof_start_response_hash_mismatch")
        return response
    return payload


def _require_exact_wrapper_keys(
    payload: Mapping[str, Any],
    *,
    expected: frozenset[str],
    error: str,
) -> None:
    if set(str(key) for key in payload) != expected:
        raise FuseKitError(error)


def _payload_hash(value: Mapping[str, Any]) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _valid_git_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", value))


def _assert_public_proof(proof: Mapping[str, object]) -> None:
    text = json.dumps(proof, sort_keys=True)
    if contains_durable_secret_text(text) or contains_private_marker_text(text):
        raise FuseKitError("live_checkout_proof_contains_secret_text")


if __name__ == "__main__":
    raise SystemExit(main())
