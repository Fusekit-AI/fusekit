"""Server-side hosted billing helpers for managed FuseKit runs."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE

HOSTED_PAYMENT_SCHEMA_VERSION = "fusekit.hosted-payment.v1"
STRIPE_CHECKOUT_PROVIDER = "stripe-checkout"
STRIPE_API_BASE = "https://api.stripe.com"
STRIPE_CHECKOUT_METADATA_KEYS = (
    "job_id",
    "lane",
    "github_source_hash",
    "plan_fingerprint",
)


@dataclass(frozen=True)
class HostedPaymentConfig:
    """Backend-only Stripe Checkout configuration."""

    enabled: bool = False
    stripe_secret_key: str = ""
    stripe_price_id: str = ""
    public_origin: str = ""
    opener: UrlOpener | None = None

    def public_dict(self) -> dict[str, object]:
        """Return redacted hosted payment readiness."""

        secret_key_configured = self.stripe_secret_key.startswith("sk_")
        price_configured = self.stripe_price_id.startswith("price_")
        ready = self.enabled and secret_key_configured and price_configured
        return {
            "schema_version": HOSTED_PAYMENT_SCHEMA_VERSION,
            "provider": STRIPE_CHECKOUT_PROVIDER,
            "enabled": ready,
            "managed_runs_enabled": self.enabled,
            "secret_key_configured": secret_key_configured,
            "price_configured": price_configured,
            "required_for_lanes": [MANAGED_FUSEKIT_RUN_LANE],
            "mode": "payment",
            "cost_controls": {
                "max_unverified_managed_spend_cents": 0,
                "dispatch_requires_paid_checkout_session": True,
                "reuse_across_jobs_allowed": False,
                "session_binding": [
                    "client_reference_id",
                    *STRIPE_CHECKOUT_METADATA_KEYS,
                ],
            },
            "secret_boundary": (
                "Stripe secret keys stay server-side. FuseKit never collects or renders card "
                "numbers, CVC, billing address fields, payment method ids, or Stripe client "
                "secrets in hosted pages, job tokens, receipts, or logs."
            ),
        }


def create_stripe_checkout_session(
    config: HostedPaymentConfig,
    *,
    job_id: str,
    job_token: str,
    lane: str,
    github_source: str,
    plan_fingerprint: str,
) -> dict[str, object]:
    """Create a Stripe Checkout Session and return a redacted receipt."""

    _require_stripe_config(config)
    success_url = _payment_return_url(
        config.public_origin,
        job_id=job_id,
        job_token=job_token,
        outcome="stripe-return",
    )
    cancel_url = _payment_return_url(
        config.public_origin,
        job_id=job_id,
        job_token=job_token,
        outcome="stripe-cancel",
    )
    form = {
        "mode": "payment",
        "line_items[0][price]": config.stripe_price_id,
        "line_items[0][quantity]": "1",
        "success_url": success_url + "&session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": cancel_url,
        "client_reference_id": job_id,
        "metadata[job_id]": job_id,
        "metadata[lane]": lane,
        "metadata[github_source_hash]": _public_hash(github_source),
        "metadata[plan_fingerprint]": plan_fingerprint,
    }
    response = _stripe_request(
        config,
        "POST",
        "/v1/checkout/sessions",
        urllib.parse.urlencode(form).encode("utf-8"),
    )
    return stripe_checkout_session_receipt(response)


def retrieve_stripe_checkout_session(
    config: HostedPaymentConfig,
    *,
    session_id: str,
) -> dict[str, object]:
    """Retrieve a Stripe Checkout Session and return a redacted receipt."""

    _require_stripe_config(config)
    if not _valid_stripe_checkout_session_id(session_id):
        raise FuseKitError("Stripe Checkout session id is invalid.")
    response = _stripe_request(
        config,
        "GET",
        f"/v1/checkout/sessions/{urllib.parse.quote(session_id, safe='')}",
        None,
    )
    return stripe_checkout_session_receipt(response)


def stripe_checkout_session_receipt(payload: dict[str, object]) -> dict[str, object]:
    """Return a browser-safe Checkout Session receipt."""

    session_id = _public_stripe_id(payload.get("id"))
    checkout_url = payload.get("url")
    return {
        "schema_version": HOSTED_PAYMENT_SCHEMA_VERSION,
        "provider": STRIPE_CHECKOUT_PROVIDER,
        "checkout_session_id": session_id,
        "checkout_url": checkout_url if _valid_checkout_url(checkout_url) else "",
        "status": _public_status(payload.get("status")),
        "payment_status": _public_status(payload.get("payment_status")),
        "mode": _public_status(payload.get("mode")) or "payment",
        "client_reference_id": _public_identifier(payload.get("client_reference_id")),
        "metadata": _public_metadata(payload.get("metadata")),
        "amount_total": _public_int(payload.get("amount_total")),
        "currency": _public_status(payload.get("currency")),
        "paid": payload.get("payment_status") == "paid",
        "secret_boundary": (
            "Payment receipt exposes only Stripe Checkout session status and public "
            "reconciliation fields. Card data, payment method ids, billing details, Stripe "
            "secret keys, and client secrets are not accepted into FuseKit receipts."
        ),
    }


def payment_required_receipt(*, lane: str) -> dict[str, object]:
    """Return a public payment-required receipt."""

    return {
        "schema_version": HOSTED_PAYMENT_SCHEMA_VERSION,
        "provider": STRIPE_CHECKOUT_PROVIDER,
        "lane": lane,
        "status": "payment_required",
        "paid": False,
        "cost_controls": {
            "max_unverified_managed_spend_cents": 0,
            "dispatch_requires_paid_checkout_session": True,
            "reuse_across_jobs_allowed": False,
        },
        "secret_boundary": (
            "Managed worker dispatch is blocked until server-side payment authorization "
            "is recorded. Payment method details stay with Stripe Checkout."
        ),
    }


def _stripe_request(
    config: HostedPaymentConfig,
    method: str,
    path: str,
    body: bytes | None,
) -> dict[str, object]:
    request = urllib.request.Request(
        STRIPE_API_BASE + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {config.stripe_secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "FuseKit",
        },
    )
    opener = config.opener or urllib.request.urlopen
    with opener(request, timeout=30.0) as response:
        raw = response.read()
        status = int(getattr(response, "status", 200))
    if status >= 400:
        raise FuseKitError(f"Stripe Checkout request returned HTTP {status}.")
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError("Stripe Checkout response is invalid.")
    return decoded


def _require_stripe_config(config: HostedPaymentConfig) -> None:
    if not config.enabled:
        raise FuseKitError("Managed run billing is not enabled.")
    if not config.stripe_secret_key or not config.stripe_secret_key.startswith("sk_"):
        raise FuseKitError("Stripe secret key is not configured.")
    if not config.stripe_price_id or not config.stripe_price_id.startswith("price_"):
        raise FuseKitError("Stripe price id is not configured.")
    if not config.public_origin.startswith("https://"):
        raise FuseKitError("Hosted payment return origin must be https.")


def _payment_return_url(
    public_origin: str,
    *,
    job_id: str,
    job_token: str,
    outcome: str,
) -> str:
    return (
        public_origin.rstrip("/")
        + f"/api/hosted/jobs/{urllib.parse.quote(job_id, safe='')}/payments/{outcome}?"
        + urllib.parse.urlencode({"job": job_token})
    )


def _valid_stripe_checkout_session_id(value: str) -> bool:
    return value.startswith("cs_") and all(ch.isalnum() or ch == "_" for ch in value)


def _valid_checkout_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme == "https" and parsed.netloc == "checkout.stripe.com"


def _public_stripe_id(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value if _valid_stripe_checkout_session_id(value) else ""


def _public_status(value: object) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip().lower()
    if not cleaned or len(cleaned) > 80:
        return ""
    if not all(ch.isalnum() or ch in {"_", "-", ".", ":"} for ch in cleaned):
        return ""
    return cleaned


def _public_metadata(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key in STRIPE_CHECKOUT_METADATA_KEYS:
        metadata_value = value.get(key)
        if isinstance(metadata_value, str):
            public = _public_identifier(metadata_value)
            if public:
                result[key] = public
    return result


def _public_identifier(value: object) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 160:
        return ""
    if not all(ch.isalnum() or ch in {"_", "-", ".", ":"} for ch in cleaned):
        return ""
    return cleaned


def _public_int(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _public_hash(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
