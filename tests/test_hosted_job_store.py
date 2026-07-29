from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted import build_hosted_launch_job
from fusekit.hosted.job_store import (
    HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION,
    HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
    HostedJobStore,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.manifest import ServiceRequirement, SetupManifest

JOB_ID = "hosted-job-store-proof"
PLAN_HASH = "sha256:" + ("a" * 64)
PRICE_HASH = "sha256:" + ("b" * 64)
LABEL_HASH = "sha256:" + ("c" * 64)


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


def test_hosted_job_store_reads_only_bounded_regular_snapshots(tmp_path: Path) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")
    job = build_hosted_launch_job(_plan(), job_id=JOB_ID, now=1_800_000_000)

    store.put(job)
    loaded = store.get(JOB_ID)

    assert loaded is not None
    assert loaded.job_id == JOB_ID


def test_hosted_job_store_rejects_symlinked_job_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "hosted-jobs"
    root.mkdir()
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    os.symlink(target, root / f"{JOB_ID}.json")
    store = HostedJobStore(root)

    with pytest.raises(FuseKitError, match="regular file"):
        store.get(JOB_ID)


def test_hosted_job_store_rejects_oversized_job_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "hosted-jobs"
    root.mkdir()
    (root / f"{JOB_ID}.json").write_text(
        '{"schema_version":"fusekit.hosted-job-store.v1","padding":"'
        + ("x" * 1_048_577)
        + '"}',
        encoding="utf-8",
    )
    store = HostedJobStore(root)

    with pytest.raises(FuseKitError, match="too large"):
        store.get(JOB_ID)


def test_hosted_job_store_writes_redacted_managed_start_response(tmp_path: Path) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")

    path = store.put_managed_start_response(
        job_id=JOB_ID,
        response=_managed_start_response(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload)

    assert path.name == f"{JOB_ID}.managed-start-response.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert payload["schema_version"] == HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION
    assert payload["job_id"] == JOB_ID
    assert payload["response_schema_version"] == "fusekit.hosted-job.v1"
    assert payload["response"]["action_receipt"]["action"] == "start"
    assert payload["response"]["worker_dispatch"]["accepted"] is True
    assert payload["response_sha256"].startswith("sha256:")
    assert "job_token" not in serialized
    assert "sk_live" not in serialized
    assert "whsec" not in serialized
    assert "payment_method" not in serialized


def test_hosted_job_store_rejects_token_bearing_managed_start_response(
    tmp_path: Path,
) -> None:
    store = HostedJobStore(tmp_path / "hosted-jobs")
    response = _managed_start_response()
    response["job_token"] = "signed-job-token"

    with pytest.raises(FuseKitError, match="must not contain job token"):
        store.put_managed_start_response(job_id=JOB_ID, response=response)

    assert not list((tmp_path / "hosted-jobs").glob("*.managed-start-response.json"))


def _plan():
    manifest = SetupManifest(
        app_name="job-store-demo",
        required_env=("RESEND_API_KEY",),
        services=(
            ServiceRequirement(
                provider="github",
                kind="repository",
                name="source",
                capabilities=("repo_secrets", "deploy_keys"),
                secrets=("GITHUB_TOKEN",),
            ),
        ),
    )
    return build_hosted_launch_plan(
        manifest,
        github_source="https://github.com/example/job-store-demo",
    )


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


def _managed_start_response() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-job.v1",
        "job_id": JOB_ID,
        "app_name": "Durable Proof",
        "github_source": "https://github.com/example/durable-proof",
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
                "checkout_session_id": "cs_test_jobstoreproof",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": JOB_ID,
                "amount_total": 100,
                "currency": "usd",
                "paid": True,
                "price_label": "Launch validation: $1.00 FuseKit managed run",
                "metadata": {
                    "job_id": JOB_ID,
                    "lane": "managed-fusekit-run",
                    "github_source_hash": "sha256:" + ("d" * 64),
                    "plan_fingerprint": PLAN_HASH,
                    "stripe_price_id_hash": PRICE_HASH,
                    "price_label_hash": LABEL_HASH,
                },
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
        },
    }
