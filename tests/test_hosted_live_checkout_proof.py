from __future__ import annotations

import json
from pathlib import Path

from fusekit.hosted.job_store import (
    HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION,
    HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
)
from fusekit.hosted.live_checkout_proof import (
    HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_INPUT_SCHEMA_VERSION,
    build_hosted_managed_live_checkout_proof,
    main,
)
from fusekit.hosted.managed_enablement import (
    HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
)

JOB_ID = "hosted-live-checkout-proof"
PLAN_HASH = "sha256:" + ("a" * 64)
PRICE_HASH = "sha256:" + ("b" * 64)
LABEL_HASH = "sha256:" + ("c" * 64)
COMMIT_SHA = "bd95448989f969e08fc201baa86b25206835b9e9"


def test_live_checkout_proof_accepts_bound_webhook_and_start_receipts() -> None:
    proof = build_hosted_managed_live_checkout_proof(
        webhook_receipt=_webhook_receipt(),
        start_action_response=_start_action_response(),
        expected_commit_sha=COMMIT_SHA,
    )
    serialized = json.dumps(proof)

    assert proof["schema_version"] == HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION
    assert proof["input_schema_version"] == HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_INPUT_SCHEMA_VERSION
    assert proof["ready"] is True
    assert proof["blockers"] == []
    assert proof["lane"] == "managed-fusekit-run"
    assert proof["job_id"] == JOB_ID
    assert proof["payment_status"] == "paid"
    assert proof["checkout_session_paid"] is True
    assert proof["webhook_applied"] is True
    assert proof["worker_dispatch_acceptance"] is True
    assert proof["dispatch_requires_paid_checkout_session"] is True
    assert proof["expected_commit_sha"] == COMMIT_SHA
    assert "sk_live" not in serialized
    assert "whsec" not in serialized
    assert "payment_method" not in serialized


def test_live_checkout_proof_rejects_binding_mismatch() -> None:
    start = _start_action_response()
    payment = start["payment"]
    assert isinstance(payment, dict)
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["stripe_price_id_hash"] = "sha256:" + ("d" * 64)

    proof = build_hosted_managed_live_checkout_proof(
        webhook_receipt=_webhook_receipt(),
        start_action_response=start,
    )

    assert proof["ready"] is False
    assert "live_checkout_stripe_price_id_hash_binding_mismatch" in proof["blockers"]


def test_live_checkout_proof_rejects_unpaid_or_undispatched_start() -> None:
    start = _start_action_response()
    payment = start["payment"]
    dispatch = start["worker_dispatch"]
    assert isinstance(payment, dict)
    assert isinstance(dispatch, dict)
    payment["status"] = "checkout_pending"
    dispatch["dispatched"] = False

    proof = build_hosted_managed_live_checkout_proof(
        webhook_receipt=_webhook_receipt(),
        start_action_response=start,
    )

    assert proof["ready"] is False
    assert "live_checkout_payment_status_not_paid" in proof["blockers"]
    assert "live_checkout_worker_dispatch_not_sent" in proof["blockers"]


def test_live_checkout_proof_cli_outputs_redacted_proof(tmp_path: Path, capsys) -> None:
    webhook_path = tmp_path / "webhook.json"
    start_path = tmp_path / "start.json"
    webhook_path.write_text(json.dumps(_webhook_receipt()), encoding="utf-8")
    start_path.write_text(json.dumps(_start_action_response()), encoding="utf-8")

    exit_code = main(
        [
            "--webhook-receipt",
            str(webhook_path),
            "--start-action-response",
            str(start_path),
            "--expected-commit-sha",
            COMMIT_SHA,
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ready"] is True
    assert payload["job_id"] == JOB_ID


def test_live_checkout_proof_cli_accepts_job_store_webhook_receipt_wrapper(
    tmp_path: Path,
    capsys,
) -> None:
    webhook_path = tmp_path / "webhook-wrapper.json"
    start_path = tmp_path / "start.json"
    webhook_path.write_text(
        json.dumps(
            {
                "schema_version": HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
                "job_id": JOB_ID,
                "receipt_schema_version": "fusekit.hosted-stripe-webhook.v1",
                "receipt_sha256": "sha256:" + ("f" * 64),
                "receipt": _webhook_receipt(),
            }
        ),
        encoding="utf-8",
    )
    start_path.write_text(json.dumps(_start_action_response()), encoding="utf-8")

    exit_code = main(
        [
            "--webhook-receipt",
            str(webhook_path),
            "--start-action-response",
            str(start_path),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ready"] is True
    assert payload["proof_inputs"]["webhook_receipt_schema"] == (
        "fusekit.hosted-stripe-webhook.v1"
    )


def test_live_checkout_proof_cli_accepts_job_store_managed_start_response_wrapper(
    tmp_path: Path,
    capsys,
) -> None:
    webhook_path = tmp_path / "webhook.json"
    start_path = tmp_path / "start-wrapper.json"
    webhook_path.write_text(json.dumps(_webhook_receipt()), encoding="utf-8")
    start_path.write_text(
        json.dumps(
            {
                "schema_version": HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION,
                "job_id": JOB_ID,
                "response_schema_version": "fusekit.hosted-job.v1",
                "response_sha256": "sha256:" + ("f" * 64),
                "response": _start_action_response(),
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--webhook-receipt",
            str(webhook_path),
            "--start-action-response",
            str(start_path),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ready"] is True
    assert payload["proof_inputs"]["start_action_schema"] == "fusekit.hosted-job.v1"


def _webhook_receipt() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-stripe-webhook.v1",
        "action": "payment_webhook",
        "event_type": "checkout.session.completed",
        "accepted": True,
        "payment_applied": True,
        "job_id": JOB_ID,
        "payment_status": "paid",
        "managed_worker_dispatch_unlocked": True,
        "worker_dispatch_sent": False,
        "next_required_proof": ["worker_claim", "detonation_receipt", "recording"],
        "receipt_statement": "Stripe Checkout completion webhook verified.",
        "secret_boundary": (
            "Stripe webhook receipts never include card data, payment method ids, "
            "Stripe keys, webhook signing secrets, or provider credentials."
        ),
    }


def _start_action_response() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-job.v1",
        "job_id": JOB_ID,
        "app_name": "Live Checkout Proof",
        "github_source": "https://github.com/example/live-checkout-proof",
        "status": "waiting_for_provider_gates",
        "created_at": 1800000000,
        "launch_lane": "managed-fusekit-run",
        "payment": {
            "required": True,
            "status": "paid",
            "price_label": "Launch validation: $1.00 FuseKit managed run",
            "price_id_hash": PRICE_HASH,
            "receipt": {
                "schema_version": "fusekit.hosted-payment.v1",
                "provider": "stripe-checkout",
                "checkout_session_id": "cs_live_checkoutproof",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": JOB_ID,
                "amount_total": 100,
                "currency": "usd",
                "paid": True,
                "price_label": "Launch validation: $1.00 FuseKit managed run",
                "metadata": _metadata(),
            },
        },
        "action_receipt": {
            "schema_version": "fusekit.hosted-job-action-receipt.v1",
            "action": "start",
        },
        "worker_dispatch": {
            "schema_version": "fusekit.hosted-worker-dispatch.v1",
            "action": "start",
            "dispatched": True,
            "dispatch_url": "https://fusekit.snowmanai.org/worker-dispatch/dispatch",
            "dispatch_binding": {
                "job_id": JOB_ID,
                "action": "start",
                "lane": "managed-fusekit-run",
                "payment_status": "paid",
                "plan_fingerprint": PLAN_HASH,
                "stripe_price_id_hash": PRICE_HASH,
                "price_label_hash": LABEL_HASH,
            },
            "accepted": True,
            "duplicate": False,
            "receiver_schema_version": "fusekit.hosted-worker-dispatch-receipt.v1",
            "idempotency": {
                "mode": "dispatch-state-dir",
                "durable": True,
                "scope": "worker deployment",
                "duplicate": False,
                "proof": "non-secret worker dispatch marker recorded before worker spawn.",
            },
            "secret_boundary": (
                "Dispatch receipt omits job tokens, worker secrets, provider credentials, "
                "GitHub installation tokens, and vault material."
            ),
        },
    }


def _metadata() -> dict[str, str]:
    return {
        "job_id": JOB_ID,
        "lane": "managed-fusekit-run",
        "github_source_hash": "sha256:" + ("e" * 64),
        "plan_fingerprint": PLAN_HASH,
        "stripe_price_id_hash": PRICE_HASH,
        "price_label_hash": LABEL_HASH,
    }
