from __future__ import annotations

import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_PAYMENT_SCHEMA_VERSION,
    STRIPE_CHECKOUT_PROVIDER,
    stripe_checkout_session_receipt,
)


def test_stripe_checkout_session_receipt_is_public_and_bound() -> None:
    receipt = stripe_checkout_session_receipt(
        {
            "id": "cs_live_public",
            "url": "https://checkout.stripe.com/c/pay/cs_live_public",
            "status": "complete",
            "payment_status": "paid",
            "mode": "payment",
            "client_reference_id": "hosted-job",
            "amount_total": 100,
            "currency": "usd",
            "metadata": {
                "job_id": "hosted-job",
                "lane": "managed-fusekit-run",
                "github_source_hash": "sha256:source",
                "plan_fingerprint": "sha256:plan",
                "ignored": "not-rendered",
            },
            "customer_email": "buyer@example.com",
        }
    )

    serialized = json.dumps(receipt)
    assert receipt["schema_version"] == HOSTED_PAYMENT_SCHEMA_VERSION
    assert receipt["provider"] == STRIPE_CHECKOUT_PROVIDER
    assert receipt["paid"] is True
    assert receipt["checkout_session_id"] == "cs_live_public"
    assert receipt["checkout_url"] == "https://checkout.stripe.com/c/pay/cs_live_public"
    assert receipt["metadata"] == {
        "job_id": "hosted-job",
        "lane": "managed-fusekit-run",
        "github_source_hash": "sha256:source",
        "plan_fingerprint": "sha256:plan",
    }
    assert "buyer@example.com" not in serialized
    assert "not-rendered" not in serialized


def test_stripe_checkout_session_receipt_rejects_secret_text_in_public_fields() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_receipt_contains_secret_text"):
        stripe_checkout_session_receipt(
            {
                "id": "cs_live_public",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "hosted-job",
                "amount_total": 100,
                "currency": "usd",
                "metadata": {
                    "job_id": "sk_live_should_not_be_public",
                    "lane": "managed-fusekit-run",
                },
            }
        )


def test_stripe_checkout_session_receipt_only_keeps_checkout_payment_urls() -> None:
    receipt = stripe_checkout_session_receipt(
        {
            "id": "cs_live_public",
            "url": "https://checkout.stripe.com/not-a-pay-session",
            "status": "open",
            "payment_status": "unpaid",
            "mode": "payment",
        }
    )

    assert receipt["checkout_url"] == ""

    receipt = stripe_checkout_session_receipt(
        {
            "id": "cs_live_public",
            "url": "https://checkout.stripe.com/c/pay/cs_live_public#fragment",
            "status": "open",
            "payment_status": "unpaid",
            "mode": "payment",
        }
    )

    assert receipt["checkout_url"] == ""
