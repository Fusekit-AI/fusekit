from __future__ import annotations

import hashlib
import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_PAYMENT_SCHEMA_VERSION,
    STRIPE_CHECKOUT_PROVIDER,
    HostedPaymentConfig,
    create_stripe_checkout_session,
    payment_required_receipt,
    stripe_checkout_session_receipt,
)


class FakeStripeResponse:
    def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> FakeStripeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class StripeCheckoutOpener:
    def __init__(self) -> None:
        self.requests: list[object] = []

    def __call__(self, request: object, *, timeout: float) -> FakeStripeResponse:
        self.requests.append(request)
        return FakeStripeResponse(
            {
                "id": "cs_live_public",
                "url": "https://checkout.stripe.com/c/pay/cs_live_public",
                "status": "open",
                "payment_status": "unpaid",
                "mode": "payment",
            }
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
                "github_source_hash": _sha256_label("source"),
                "plan_fingerprint": _sha256_label("plan"),
                "stripe_price_id_hash": _sha256_label("price"),
                "price_label_hash": _sha256_label("label"),
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
        "github_source_hash": _sha256_label("source"),
        "plan_fingerprint": _sha256_label("plan"),
        "stripe_price_id_hash": _sha256_label("price"),
        "price_label_hash": _sha256_label("label"),
    }
    assert "buyer@example.com" not in serialized


def test_stripe_checkout_session_receipt_rejects_boolean_amount_total() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_paid_receipt_incomplete"):
        stripe_checkout_session_receipt(
            {
                "id": "cs_live_public",
                "url": "https://checkout.stripe.com/c/pay/cs_live_public",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "client_reference_id": "hosted-job",
                "amount_total": True,
                "currency": "usd",
                "metadata": {
                    "job_id": "hosted-job",
                    "lane": "managed-fusekit-run",
                    "github_source_hash": _sha256_label("source"),
                    "plan_fingerprint": _sha256_label("plan"),
                    "stripe_price_id_hash": _sha256_label("price"),
                    "price_label_hash": _sha256_label("label"),
                },
            }
        )


def test_stripe_checkout_session_receipt_rejects_incomplete_paid_metadata() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_paid_receipt_incomplete"):
        stripe_checkout_session_receipt(
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
                    "github_source_hash": _sha256_label("source"),
                    "plan_fingerprint": _sha256_label("plan"),
                },
            }
        )


def test_stripe_checkout_session_receipt_rejects_unexpected_metadata() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_metadata_unexpected_field"):
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
                    "job_id": "hosted-job",
                    "lane": "managed-fusekit-run",
                    "github_source_hash": _sha256_label("source"),
                    "plan_fingerprint": _sha256_label("plan"),
                    "stripe_price_id_hash": _sha256_label("price"),
                    "price_label_hash": _sha256_label("label"),
                    "provider_token": "not-allowed-here",
                },
            }
        )


def test_stripe_checkout_session_receipt_rejects_malformed_hash_metadata() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_metadata_hash_invalid"):
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
                    "job_id": "hosted-job",
                    "lane": "managed-fusekit-run",
                    "github_source_hash": _sha256_label("source"),
                    "plan_fingerprint": "sha256:not-a-real-digest",
                    "stripe_price_id_hash": _sha256_label("price"),
                    "price_label_hash": _sha256_label("label"),
                },
            }
        )


def test_stripe_checkout_session_receipt_rejects_secret_text_in_public_fields() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_metadata_contains_secret_text"):
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

    with pytest.raises(FuseKitError, match="stripe_checkout_metadata_contains_secret_text"):
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
                    "job_id": "<sk_live_should_not_be_public>",
                    "lane": "managed-fusekit-run",
                },
            }
        )


def test_stripe_checkout_session_receipt_rejects_private_markers_in_metadata() -> None:
    with pytest.raises(FuseKitError, match="stripe_checkout_metadata_contains_secret_text"):
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
                    "job_id": "hosted-ocid1.instance.oc1..not-public",
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
            "url": "https://checkout.stripe.com/c/pay/cs_live_public?client_secret=hidden",
            "status": "open",
            "payment_status": "unpaid",
            "mode": "payment",
        }
    )

    serialized = json.dumps(receipt)
    assert receipt["checkout_url"] == ""
    assert "client_secret" not in serialized


@pytest.mark.parametrize(
    ("override", "error"),
    [
        ({"job_id": "hosted job"}, "stripe_checkout_job_id_invalid"),
        (
            {"job_id": "sk_live_should_not_leave"},
            "stripe_checkout_job_id_contains_secret_text",
        ),
        (
            {"job_id": "hosted-ocid1.instance.oc1..not-public"},
            "stripe_checkout_job_id_contains_secret_text",
        ),
        ({"lane": "byo-oci"}, "stripe_checkout_lane_not_managed"),
        (
            {"github_source": "https://example.com/Fusekit-AI/fusekit"},
            "stripe_checkout_github_source_invalid",
        ),
        (
            {"github_source": "https://github.com/Fusekit-AI/fusekit?tab=readme"},
            "stripe_checkout_github_source_invalid",
        ),
        (
            {"github_source": "https://github.com/Fusekit-AI/fusekit/tree/main"},
            "stripe_checkout_github_source_invalid",
        ),
        (
            {"github_source": "https://github.com/Fusekit-AI/sk_live_should_not_leave"},
            "stripe_checkout_github_source_contains_secret_text",
        ),
        (
            {"github_source": "https://github.com/Fusekit-AI/ocid1.instance.oc1..not-public"},
            "stripe_checkout_github_source_contains_secret_text",
        ),
        (
            {"plan_fingerprint": "sha256:not-a-real-digest"},
            "stripe_checkout_plan_fingerprint_invalid",
        ),
    ],
)
def test_create_stripe_checkout_session_rejects_bad_binding_before_network(
    override: dict[str, str],
    error: str,
) -> None:
    opener = StripeCheckoutOpener()
    kwargs = {
        "job_id": "hosted-job",
        "job_token": "signed.public.job",
        "lane": "managed-fusekit-run",
        "github_source": "https://github.com/Fusekit-AI/fusekit",
        "plan_fingerprint": _sha256_label("visible-plan"),
    }
    kwargs.update(override)

    with pytest.raises(FuseKitError, match=error):
        create_stripe_checkout_session(
            HostedPaymentConfig(
                enabled=True,
                stripe_secret_key="sk_live_secret_value",
                stripe_price_id="price_managed_run",
                price_label="Launch validation: $1.00 FuseKit managed run",
                public_origin="https://fusekit.snowmanai.org",
                opener=opener,
            ),
            **kwargs,
        )

    assert opener.requests == []


@pytest.mark.parametrize(
    "public_origin",
    [
        "http://fusekit.snowmanai.org",
        "https://fusekit.snowmanai.org/path",
        "https://fusekit.snowmanai.org?job=token",
        "https://fusekit.snowmanai.org#fragment",
        "https://user@fusekit.snowmanai.org",
    ],
)
def test_create_stripe_checkout_session_rejects_bad_return_origin_before_network(
    public_origin: str,
) -> None:
    opener = StripeCheckoutOpener()

    with pytest.raises(FuseKitError, match="Hosted payment return origin must be https"):
        create_stripe_checkout_session(
            HostedPaymentConfig(
                enabled=True,
                stripe_secret_key="sk_live_secret_value",
                stripe_price_id="price_managed_run",
                price_label="Launch validation: $1.00 FuseKit managed run",
                public_origin=public_origin,
                opener=opener,
            ),
            job_id="hosted-job",
            job_token="signed.public.job",
            lane="managed-fusekit-run",
            github_source="https://github.com/Fusekit-AI/fusekit",
            plan_fingerprint=_sha256_label("visible-plan"),
        )

    assert opener.requests == []


def test_payment_required_receipt_is_public_and_scanned() -> None:
    receipt = payment_required_receipt(
        lane="managed-fusekit-run",
        price_label="Launch validation: $1.00 FuseKit managed run",
    )

    serialized = json.dumps(receipt)
    assert receipt["schema_version"] == HOSTED_PAYMENT_SCHEMA_VERSION
    assert receipt["provider"] == STRIPE_CHECKOUT_PROVIDER
    assert receipt["status"] == "payment_required"
    assert receipt["paid"] is False
    assert receipt["price_label"] == "Launch validation: $1.00 FuseKit managed run"
    assert receipt["cost_controls"] == {
        "max_unverified_managed_spend_cents": 0,
        "dispatch_requires_paid_checkout_session": True,
        "reuse_across_jobs_allowed": False,
    }
    assert "Payment method details stay with Stripe Checkout" in receipt["secret_boundary"]
    assert "sk_live" not in serialized
    assert "client_secret" not in serialized


def test_payment_required_receipt_rejects_secret_shaped_lane() -> None:
    with pytest.raises(FuseKitError, match="payment_required_lane_not_managed"):
        payment_required_receipt(
            lane="managed-fusekit-run sk_live_should_not_render",
            price_label="Launch validation: $1.00 FuseKit managed run",
        )


def test_payment_required_receipt_rejects_non_managed_lane() -> None:
    with pytest.raises(FuseKitError, match="payment_required_lane_not_managed"):
        payment_required_receipt(
            lane="byo-oci",
            price_label="Launch validation: $1.00 FuseKit managed run",
        )


def test_payment_required_receipt_rejects_secret_shaped_price_label() -> None:
    with pytest.raises(FuseKitError, match="payment_required_price_label_invalid"):
        payment_required_receipt(
            lane="managed-fusekit-run",
            price_label="Launch validation: $1.00 FuseKit managed run sk_live_should_not_render",
        )

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


def _sha256_label(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
