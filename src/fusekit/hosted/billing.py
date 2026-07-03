"""Server-side hosted billing helpers for managed FuseKit runs."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE
from fusekit.security import contains_durable_secret_text

HOSTED_PAYMENT_SCHEMA_VERSION = "fusekit.hosted-payment.v1"
STRIPE_CHECKOUT_PROVIDER = "stripe-checkout"
STRIPE_API_BASE = "https://api.stripe.com"
STRIPE_CHECKOUT_METADATA_KEYS = (
    "job_id",
    "lane",
    "github_source_hash",
    "plan_fingerprint",
    "stripe_price_id_hash",
    "price_label_hash",
)
HOSTED_STRIPE_PRICE_SETUP_HELPER = "fusekit-hosted-stripe-price"
HOSTED_STRIPE_PRICE_VERIFY_HELPER = "fusekit-hosted-stripe-price-verify"
HOSTED_STRIPE_PRICE_SETUP_MODULE = "python -m fusekit.hosted.stripe_setup"
HOSTED_STRIPE_PRICE_VERIFY_MODULE = "python -m fusekit.hosted.stripe_verify"
HOSTED_STRIPE_PRICE_SETUP_REQUIRED_FLAGS = (
    "--execute",
    "--confirm-shared-account",
)
HOSTED_STRIPE_PRICE_LOOKUP_POLICY = (
    "Before creating Stripe objects, list active Prices by the deterministic FuseKit "
    "lookup_key with expanded Product. Reuse only an existing active FuseKit-scoped "
    "Price/Product with matching amount, currency, metadata, and public label hash; "
    "halt if that lookup key is occupied by non-FuseKit metadata."
)
HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY = (
    "Creates a new FuseKit-scoped Stripe Product and Price only. It does not edit, "
    "archive, or reuse existing Snowman AI products, prices, customers, subscriptions, "
    "payment links, or webhooks."
)
HOSTED_STRIPE_SETUP_SECRET_BOUNDARY = (
    "Stripe secret keys are read from the selected environment variable and are never "
    "emitted in JSON output, docs, hosted pages, receipts, or logs."
)
PUBLIC_PRICE_LABEL_CURRENCY_CODES = frozenset(
    {
        "aud",
        "cad",
        "chf",
        "eur",
        "gbp",
        "jpy",
        "mxn",
        "nzd",
        "sgd",
        "usd",
    }
)


@dataclass(frozen=True)
class HostedPaymentConfig:
    """Backend-only Stripe Checkout configuration."""

    enabled: bool = False
    stripe_secret_key: str = ""
    stripe_price_id: str = ""
    price_label: str = ""
    public_origin: str = ""
    test_mode_allowed: bool = False
    opener: UrlOpener | None = None

    def public_dict(self) -> dict[str, object]:
        """Return redacted hosted payment readiness."""

        secret_key_configured = self.stripe_secret_key.startswith("sk_")
        account_mode = _stripe_account_mode(self.stripe_secret_key)
        live_mode_configured = account_mode == "live"
        live_or_allowed_test_mode = live_mode_configured or (
            account_mode == "test" and self.test_mode_allowed
        )
        price_configured = self.stripe_price_id.startswith("price_")
        price_label_configured = _valid_price_label(self.price_label)
        ready = (
            self.enabled
            and secret_key_configured
            and live_or_allowed_test_mode
            and price_configured
            and price_label_configured
        )
        return {
            "schema_version": HOSTED_PAYMENT_SCHEMA_VERSION,
            "provider": STRIPE_CHECKOUT_PROVIDER,
            "enabled": ready,
            "managed_runs_enabled": self.enabled,
            "secret_key_configured": secret_key_configured,
            "account_mode": account_mode,
            "live_mode_configured": live_mode_configured,
            "test_mode_allowed": self.test_mode_allowed,
            "price_configured": price_configured,
            "price_label_configured": price_label_configured,
            "price_label": self.price_label if price_label_configured else "",
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
            "operator_setup": {
                "helper_command": HOSTED_STRIPE_PRICE_SETUP_HELPER,
                "verification_command": HOSTED_STRIPE_PRICE_VERIFY_HELPER,
                "module_fallback": HOSTED_STRIPE_PRICE_SETUP_MODULE,
                "verification_module_fallback": HOSTED_STRIPE_PRICE_VERIFY_MODULE,
                "dry_run_default": True,
                "mutation_requires": list(HOSTED_STRIPE_PRICE_SETUP_REQUIRED_FLAGS),
                "lookup_key_policy": HOSTED_STRIPE_PRICE_LOOKUP_POLICY,
                "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
                "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
                "managed_runs_enable_after": (
                    "live Checkout proof and worker-dispatch acceptance pass"
                ),
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
    _require_checkout_binding(
        job_id=job_id,
        lane=lane,
        github_source=github_source,
        plan_fingerprint=plan_fingerprint,
    )
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
        "metadata[stripe_price_id_hash]": _public_hash(config.stripe_price_id),
        "metadata[price_label_hash]": _public_hash(config.price_label),
    }
    response = _stripe_request(
        config,
        "POST",
        "/v1/checkout/sessions",
        urllib.parse.urlencode(form).encode("utf-8"),
    )
    receipt = stripe_checkout_session_receipt(response)
    receipt["price_label"] = config.price_label
    _assert_public_payment_receipt(receipt)
    return receipt


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
    receipt = stripe_checkout_session_receipt(response)
    receipt["price_label"] = config.price_label
    _assert_public_payment_receipt(receipt)
    return receipt


def stripe_checkout_session_receipt(payload: dict[str, object]) -> dict[str, object]:
    """Return a browser-safe Checkout Session receipt."""

    session_id = _public_stripe_id(payload.get("id"))
    checkout_url = payload.get("url")
    receipt = {
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
    _assert_public_payment_receipt(receipt)
    return receipt


def payment_required_receipt(*, lane: str, price_label: str = "") -> dict[str, object]:
    """Return a public payment-required receipt."""

    receipt: dict[str, object] = {
        "schema_version": HOSTED_PAYMENT_SCHEMA_VERSION,
        "provider": STRIPE_CHECKOUT_PROVIDER,
        "lane": lane,
        "status": "payment_required",
        "paid": False,
        "price_label": price_label if _valid_price_label(price_label) else "",
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
    _assert_public_payment_receipt(receipt)
    return receipt


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
    test_key_allowed = config.test_mode_allowed and config.stripe_secret_key.startswith("sk_test_")
    if not config.stripe_secret_key.startswith("sk_live_") and not test_key_allowed:
        raise FuseKitError("Managed run billing requires a live Stripe secret key.")
    if not config.stripe_price_id or not config.stripe_price_id.startswith("price_"):
        raise FuseKitError("Stripe price id is not configured.")
    if not _valid_price_label(config.price_label):
        raise FuseKitError("Managed run public price label is not configured.")
    if not _valid_public_payment_origin(config.public_origin):
        raise FuseKitError("Hosted payment return origin must be https.")


def _require_checkout_binding(
    *,
    job_id: str,
    lane: str,
    github_source: str,
    plan_fingerprint: str,
) -> None:
    if lane != MANAGED_FUSEKIT_RUN_LANE:
        raise FuseKitError("stripe_checkout_lane_not_managed")
    if _public_identifier(job_id) != job_id:
        raise FuseKitError("stripe_checkout_job_id_invalid")
    if contains_durable_secret_text(job_id):
        raise FuseKitError("stripe_checkout_job_id_contains_secret_text")
    if not _valid_public_github_source(github_source):
        raise FuseKitError("stripe_checkout_github_source_invalid")
    if contains_durable_secret_text(github_source):
        raise FuseKitError("stripe_checkout_github_source_contains_secret_text")
    if not _valid_sha256_label(plan_fingerprint):
        raise FuseKitError("stripe_checkout_plan_fingerprint_invalid")


def _assert_public_payment_receipt(receipt: dict[str, object]) -> None:
    serialized = json.dumps(receipt, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("stripe_checkout_receipt_contains_secret_text")


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
    return (
        parsed.scheme == "https"
        and parsed.netloc == "checkout.stripe.com"
        and parsed.path.startswith("/c/pay/")
        and not parsed.query
        and not parsed.params
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
    )


def _valid_price_label(value: str) -> bool:
    if not value:
        return False
    if len(value) > 120:
        return False
    if contains_durable_secret_text(value):
        return False
    if "price_" in value or "sk_" in value or "pk_" in value:
        return False
    if any(ch in value for ch in "<>{}"):
        return False
    return (
        all(ch.isprintable() for ch in value)
        and any(ch.isdigit() for ch in value)
        and _has_public_currency_marker(value)
    )


def _has_public_currency_marker(value: str) -> bool:
    if "$" in value:
        return True
    tokens = {
        "".join(ch for ch in token.lower() if ch.isalpha())
        for token in value.replace("/", " ").replace("-", " ").split()
    }
    return bool(tokens & PUBLIC_PRICE_LABEL_CURRENCY_CODES)


def _stripe_account_mode(value: str) -> str:
    if value.startswith("sk_live_"):
        return "live"
    if value.startswith("sk_test_"):
        return "test"
    if value.startswith("sk_"):
        return "unknown"
    return "unconfigured"


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
    unexpected = sorted(str(key) for key in value if key not in STRIPE_CHECKOUT_METADATA_KEYS)
    if unexpected:
        raise FuseKitError("stripe_checkout_metadata_unexpected_field")
    result: dict[str, str] = {}
    for key in STRIPE_CHECKOUT_METADATA_KEYS:
        metadata_value = value.get(key)
        if isinstance(metadata_value, str):
            if contains_durable_secret_text(metadata_value):
                raise FuseKitError("stripe_checkout_metadata_contains_secret_text")
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
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _valid_sha256_label(value: str) -> bool:
    digest = value.removeprefix("sha256:")
    return (
        value.startswith("sha256:")
        and len(digest) == 64
        and all(ch in "0123456789abcdef" for ch in digest)
    )


def _valid_public_github_source(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    return (
        parsed.scheme == "https"
        and parsed.netloc == "github.com"
        and len(parts) == 2
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
        and all(_valid_github_path_segment(part) for part in parts)
    )


def _valid_github_path_segment(value: str) -> bool:
    return bool(value) and len(value) <= 100 and all(
        ch.isalnum() or ch in {"-", "_", "."} for ch in value
    )


def _valid_public_payment_origin(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.path.rstrip("/")
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
    )


def _public_hash(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
