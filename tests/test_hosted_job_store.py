from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.job_store import (
    HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
    HostedJobStore,
)

JOB_ID = "hosted-job-store-proof"


def test_hosted_job_store_writes_redacted_stripe_webhook_receipt(tmp_path: Path) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")

    path = store.put_stripe_webhook_receipt(
        job_id=JOB_ID,
        receipt=_stripe_webhook_receipt(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload)

    assert path.name == f"{JOB_ID}.stripe-webhook-receipt.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert payload["schema_version"] == HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION
    assert payload["job_id"] == JOB_ID
    assert payload["receipt_schema_version"] == "fusekit.hosted-stripe-webhook.v1"
    assert payload["receipt"]["payment_applied"] is True
    assert payload["receipt_sha256"].startswith("sha256:")
    assert "sk_live" not in serialized
    assert "whsec" not in serialized
    assert "payment_method" not in serialized


def test_hosted_job_store_rejects_private_webhook_receipt_text(tmp_path: Path) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")
    receipt = _stripe_webhook_receipt()
    receipt["receipt_statement"] = "Do not store " + "sk_" + "live_private_fixture"

    with pytest.raises(FuseKitError, match="private-looking"):
        store.put_stripe_webhook_receipt(job_id=JOB_ID, receipt=receipt)

    assert not list((tmp_path / "hosted-jobs").glob("*.stripe-webhook-receipt.json"))


def test_hosted_job_store_rejects_unbound_webhook_receipt(tmp_path: Path) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")
    receipt = _stripe_webhook_receipt()
    receipt["job_id"] = "hosted-other-proof"

    with pytest.raises(FuseKitError, match="job id mismatch"):
        store.put_stripe_webhook_receipt(job_id=JOB_ID, receipt=receipt)


def _stripe_webhook_receipt() -> dict[str, object]:
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
