"""Operator helper for creating hosted managed-run Stripe prices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import STRIPE_API_BASE, _stripe_account_mode, _valid_price_label
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE

STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION = "fusekit.stripe-managed-price-setup.v1"
DEFAULT_MANAGED_RUN_PRODUCT_NAME = "FuseKit Managed Run"
DEFAULT_MANAGED_RUN_PRODUCT_DESCRIPTION = (
    "One-time payment authorization for a FuseKit-managed hosted launch worker."
)
MAX_MANAGED_RUN_AMOUNT_CENTS = 1_000_000


@dataclass(frozen=True)
class StripeManagedRunPricePlan:
    """Public plan for a FuseKit-managed Stripe Product and Price."""

    account_mode: str
    amount_cents: int
    currency: str
    price_label: str
    product_name: str
    product_description: str
    lookup_key: str

    def public_dict(self) -> dict[str, object]:
        """Return public setup plan data without Stripe secrets."""

        return {
            "schema_version": STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION,
            "provider": "stripe",
            "lane": MANAGED_FUSEKIT_RUN_LANE,
            "account_mode": self.account_mode,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "price_label": self.price_label,
            "product": {
                "name": self.product_name,
                "description": self.product_description,
                "metadata": _stripe_setup_metadata(
                    lane=MANAGED_FUSEKIT_RUN_LANE,
                    price_label=self.price_label,
                ),
            },
            "price": {
                "lookup_key": self.lookup_key,
                "metadata": _stripe_setup_metadata(
                    lane=MANAGED_FUSEKIT_RUN_LANE,
                    price_label=self.price_label,
                ),
            },
            "shared_account_boundary": (
                "Creates a new FuseKit-scoped Stripe Product and Price only. It does not "
                "edit, archive, or reuse existing Snowman AI products, prices, customers, "
                "subscriptions, payment links, or webhooks."
            ),
            "secret_boundary": (
                "Stripe secret keys are read from the selected environment variable and are "
                "never emitted in JSON output, docs, hosted pages, receipts, or logs."
            ),
        }


def build_stripe_managed_run_price_plan(
    *,
    stripe_secret_key: str,
    amount_cents: int,
    currency: str,
    price_label: str,
    product_name: str = DEFAULT_MANAGED_RUN_PRODUCT_NAME,
    product_description: str = DEFAULT_MANAGED_RUN_PRODUCT_DESCRIPTION,
    allow_test_mode: bool = False,
) -> StripeManagedRunPricePlan:
    """Validate operator input and return the public Stripe setup plan."""

    account_mode = _stripe_account_mode(stripe_secret_key)
    if account_mode == "unconfigured":
        raise FuseKitError("Stripe secret key is not configured.")
    if account_mode == "unknown":
        raise FuseKitError("Stripe secret key mode is unknown.")
    if account_mode == "test" and not allow_test_mode:
        raise FuseKitError("Live managed-run pricing requires a live Stripe secret key.")
    if amount_cents <= 0 or amount_cents > MAX_MANAGED_RUN_AMOUNT_CENTS:
        raise FuseKitError("Managed-run amount must be between 1 and 1000000 cents.")
    normalized_currency = currency.strip().lower()
    if len(normalized_currency) != 3 or not normalized_currency.isalpha():
        raise FuseKitError("Stripe currency must be a three-letter code.")
    if not _valid_price_label(price_label):
        raise FuseKitError("Managed-run public price label is invalid.")
    cleaned_product_name = " ".join(product_name.split())
    if not cleaned_product_name or "fusekit" not in cleaned_product_name.lower():
        raise FuseKitError("Stripe product name must be FuseKit-scoped.")
    cleaned_description = " ".join(product_description.split())
    if not cleaned_description or len(cleaned_description) > 240:
        raise FuseKitError("Stripe product description is invalid.")
    return StripeManagedRunPricePlan(
        account_mode=account_mode,
        amount_cents=amount_cents,
        currency=normalized_currency,
        price_label=price_label.strip(),
        product_name=cleaned_product_name,
        product_description=cleaned_description,
        lookup_key=_managed_run_lookup_key(
            amount_cents=amount_cents,
            currency=normalized_currency,
            price_label=price_label,
        ),
    )


def create_stripe_managed_run_price(
    *,
    stripe_secret_key: str,
    amount_cents: int,
    currency: str,
    price_label: str,
    product_name: str = DEFAULT_MANAGED_RUN_PRODUCT_NAME,
    product_description: str = DEFAULT_MANAGED_RUN_PRODUCT_DESCRIPTION,
    allow_test_mode: bool = False,
    execute: bool = False,
    confirm_shared_account: bool = False,
    opener: UrlOpener | None = None,
) -> dict[str, object]:
    """Create a FuseKit-scoped Stripe Product and Price, or return a dry-run plan."""

    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key=stripe_secret_key,
        amount_cents=amount_cents,
        currency=currency,
        price_label=price_label,
        product_name=product_name,
        product_description=product_description,
        allow_test_mode=allow_test_mode,
    )
    if not execute:
        return _stripe_setup_report(
            plan,
            executed=False,
            product_id="",
            price_id="",
        )
    if not confirm_shared_account:
        raise FuseKitError(
            "Refusing Stripe mutation without --confirm-shared-account acknowledgement."
        )
    product = _stripe_request(
        stripe_secret_key,
        "POST",
        "/v1/products",
        _product_form(plan),
        idempotency_key=f"fusekit-product-{plan.lookup_key}",
        opener=opener,
    )
    product_id = _public_stripe_id(product.get("id"), prefix="prod_")
    if not product_id:
        raise FuseKitError("Stripe Product response did not include a public product id.")
    price = _stripe_request(
        stripe_secret_key,
        "POST",
        "/v1/prices",
        _price_form(plan, product_id=product_id),
        idempotency_key=f"fusekit-price-{plan.lookup_key}",
        opener=opener,
    )
    price_id = _public_stripe_id(price.get("id"), prefix="price_")
    if not price_id:
        raise FuseKitError("Stripe Price response did not include a public price id.")
    return _stripe_setup_report(
        plan,
        executed=True,
        product_id=product_id,
        price_id=price_id,
    )


def main(argv: list[str] | None = None) -> int:
    """Create or plan a FuseKit-managed Stripe Price and print redacted JSON."""

    parser = argparse.ArgumentParser(
        description="Create a FuseKit-scoped Stripe Price for hosted managed runs."
    )
    parser.add_argument("--amount-cents", type=int, required=True)
    parser.add_argument("--currency", default="usd")
    parser.add_argument("--label", required=True, help="Public price label shown before Checkout")
    parser.add_argument("--product-name", default=DEFAULT_MANAGED_RUN_PRODUCT_NAME)
    parser.add_argument(
        "--product-description",
        default=DEFAULT_MANAGED_RUN_PRODUCT_DESCRIPTION,
    )
    parser.add_argument("--secret-key-env", default="FUSEKIT_STRIPE_SECRET_KEY")
    parser.add_argument("--allow-test-mode", action="store_true")
    parser.add_argument("--execute", action="store_true", help="Actually create Product and Price")
    parser.add_argument(
        "--confirm-shared-account",
        action="store_true",
        help=(
            "Acknowledge this Stripe account is shared and only FuseKit-scoped resources "
            "may be made"
        ),
    )
    args = parser.parse_args(argv)
    secret_key = os.environ.get(args.secret_key_env, "")
    try:
        report = create_stripe_managed_run_price(
            stripe_secret_key=secret_key,
            amount_cents=args.amount_cents,
            currency=args.currency,
            price_label=args.label,
            product_name=args.product_name,
            product_description=args.product_description,
            allow_test_mode=args.allow_test_mode,
            execute=args.execute,
            confirm_shared_account=args.confirm_shared_account,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION,
            "ready": False,
            "executed": False,
            "error": str(exc),
            "secret_boundary": (
                "Stripe secret keys are read from the selected environment variable and are "
                "never emitted in setup output."
            ),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 2


def _stripe_setup_report(
    plan: StripeManagedRunPricePlan,
    *,
    executed: bool,
    product_id: str,
    price_id: str,
) -> dict[str, object]:
    next_actions = [
        "Store FUSEKIT_STRIPE_SECRET_KEY only in the hosted runtime secret file.",
        "Set FUSEKIT_STRIPE_PRICE_ID to the created price id.",
        "Set FUSEKIT_MANAGED_RUN_PRICE_LABEL to the public label in this report.",
        "Keep FUSEKIT_MANAGED_RUNS_ENABLED=0 until a live Checkout proof is tested.",
    ]
    report = plan.public_dict()
    report.update(
        {
            "ready": True,
            "executed": executed,
            "product_id": product_id,
            "price_id": price_id,
            "hosted_runtime_env": {
                "FUSEKIT_STRIPE_PRICE_ID": price_id,
                "FUSEKIT_MANAGED_RUN_PRICE_LABEL": plan.price_label,
                "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
            },
            "next_actions": next_actions,
        }
    )
    if not executed:
        report["dry_run"] = True
        report["next_actions"] = [
            "Re-run with --execute --confirm-shared-account after reviewing this plan.",
            *next_actions,
        ]
    return report


def _stripe_request(
    stripe_secret_key: str,
    method: str,
    path: str,
    form: Mapping[str, str],
    *,
    idempotency_key: str,
    opener: UrlOpener | None,
) -> dict[str, object]:
    body = urllib.parse.urlencode(dict(form)).encode("utf-8")
    request = urllib.request.Request(
        STRIPE_API_BASE + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {stripe_secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": idempotency_key,
            "User-Agent": "FuseKit",
        },
    )
    open_url = opener or urllib.request.urlopen
    with open_url(request, timeout=30.0) as response:
        raw = response.read()
        status = int(getattr(response, "status", 200))
    if status >= 400:
        raise FuseKitError(f"Stripe setup request returned HTTP {status}.")
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError("Stripe setup response is invalid.")
    return decoded


def _product_form(plan: StripeManagedRunPricePlan) -> dict[str, str]:
    form = {
        "name": plan.product_name,
        "description": plan.product_description,
    }
    for key, value in _stripe_setup_metadata(
        lane=MANAGED_FUSEKIT_RUN_LANE,
        price_label=plan.price_label,
    ).items():
        form[f"metadata[{key}]"] = value
    return form


def _price_form(plan: StripeManagedRunPricePlan, *, product_id: str) -> dict[str, str]:
    form = {
        "product": product_id,
        "unit_amount": str(plan.amount_cents),
        "currency": plan.currency,
        "lookup_key": plan.lookup_key,
    }
    for key, value in _stripe_setup_metadata(
        lane=MANAGED_FUSEKIT_RUN_LANE,
        price_label=plan.price_label,
    ).items():
        form[f"metadata[{key}]"] = value
    return form


def _stripe_setup_metadata(*, lane: str, price_label: str) -> dict[str, str]:
    return {
        "fusekit_component": "hosted-launcher",
        "fusekit_lane": lane,
        "fusekit_scope": "managed-run-price",
        "public_price_label_hash": _public_hash(price_label),
    }


def _managed_run_lookup_key(*, amount_cents: int, currency: str, price_label: str) -> str:
    digest = _public_hash(f"{amount_cents}:{currency}:{price_label}")[:16]
    return f"fusekit_managed_run_{currency}_{amount_cents}_{digest}"


def _public_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_stripe_id(value: object, *, prefix: str) -> str:
    if not isinstance(value, str):
        return ""
    if not value.startswith(prefix):
        return ""
    if not all(ch.isalnum() or ch == "_" for ch in value):
        return ""
    return value


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
