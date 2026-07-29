"""Build redacted live managed Checkout proof from hosted receipts."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.job_store import HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION
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
    parser.add_argument("--webhook-receipt", required=True)
    parser.add_argument("--start-action-response", required=True)
    parser.add_argument("--expected-commit-sha", default="")
    args = parser.parse_args(argv)
    try:
        proof = build_hosted_managed_live_checkout_proof(
            webhook_receipt=_read_webhook_receipt_json(args.webhook_receipt),
            start_action_response=_read_json(args.start_action_response),
            expected_commit_sha=args.expected_commit_sha,
        )
    except FuseKitError as exc:
        proof = {
            "schema_version": HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
            "ready": False,
            "error": str(exc),
            "secret_boundary": HOSTED_MANAGED_ENABLEMENT_SECRET_BOUNDARY,
        }
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0 if proof.get("ready") is True else 2


def _webhook_receipt_blockers(receipt: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
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
    blockers: list[str] = []
    if payment.get("required") is not True:
        blockers.append("live_checkout_payment_not_required")
    if payment.get("status") != "paid":
        blockers.append("live_checkout_payment_status_not_paid")
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
    for field in ("job_id", "lane", "plan_fingerprint", "stripe_price_id_hash", "price_label_hash"):
        if field not in _mapping(receipt.get("metadata")):
            blockers.append(f"live_checkout_checkout_metadata_{field}_missing")
    return blockers


def _worker_dispatch_blockers(value: object) -> list[str]:
    dispatch = _mapping(value)
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
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise FuseKitError("live_checkout_proof_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("live_checkout_proof_input_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("live_checkout_proof_input_must_be_object")
    return value


def _read_webhook_receipt_json(path: str) -> Mapping[str, Any]:
    payload = _read_json(path)
    if (
        payload.get("schema_version")
        == HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION
    ):
        receipt = payload.get("receipt")
        if not isinstance(receipt, Mapping):
            raise FuseKitError("live_checkout_proof_webhook_receipt_missing")
        return receipt
    return payload


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _assert_public_proof(proof: Mapping[str, object]) -> None:
    text = json.dumps(proof, sort_keys=True)
    if contains_durable_secret_text(text) or contains_private_marker_text(text):
        raise FuseKitError("live_checkout_proof_contains_secret_text")


if __name__ == "__main__":
    raise SystemExit(main())
