"""Operator helper for creating hosted managed-run Stripe prices."""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
    HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
    STRIPE_API_BASE,
    _stripe_account_mode,
    _valid_price_label,
)
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE
from fusekit.security import contains_durable_secret_text

STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION = "fusekit.stripe-managed-price-setup.v1"
DEFAULT_MANAGED_RUN_PRODUCT_NAME = "FuseKit Managed Run"
DEFAULT_MANAGED_RUN_PRODUCT_DESCRIPTION = (
    "One-time payment authorization for a FuseKit-managed hosted launch worker."
)
MAX_MANAGED_RUN_AMOUNT_CENTS = 1_000_000
MAX_MANAGED_RUN_PRODUCT_NAME_LENGTH = 80
MAX_MANAGED_RUN_PRODUCT_DESCRIPTION_LENGTH = 240


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
            "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
            "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
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
    if not _price_label_matches_amount(
        price_label,
        amount_cents=amount_cents,
        currency=normalized_currency,
    ):
        raise FuseKitError(
            "Managed-run public price label must match the configured amount and currency."
        )
    cleaned_product_name = _public_stripe_product_name(product_name)
    if not _valid_fusekit_product_name(cleaned_product_name):
        raise FuseKitError("Stripe product name must be FuseKit-scoped.")
    cleaned_description = _public_stripe_product_description(product_description)
    if not cleaned_description:
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
    existing_price = _find_existing_stripe_managed_run_price(
        stripe_secret_key,
        plan,
        opener=opener,
    )
    if existing_price:
        return _stripe_setup_report(
            plan,
            executed=True,
            product_id=existing_price["product_id"],
            price_id=existing_price["price_id"],
            reused_existing=True,
            mutated=False,
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
        reused_existing=False,
        mutated=True,
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
    reused_existing: bool = False,
    mutated: bool = False,
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
            "mutated": mutated,
            "reused_existing": reused_existing,
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
        report["mutated"] = False
        report["reused_existing"] = False
        report["next_actions"] = [
            "Re-run with --execute --confirm-shared-account after reviewing this plan.",
            *next_actions,
        ]
    return report


def _find_existing_stripe_managed_run_price(
    stripe_secret_key: str,
    plan: StripeManagedRunPricePlan,
    *,
    opener: UrlOpener | None,
) -> dict[str, str]:
    payload = _stripe_get(
        stripe_secret_key,
        "/v1/prices",
        {
            "active": "true",
            "limit": "10",
            "lookup_keys[]": plan.lookup_key,
            "expand[]": "data.product",
        },
        opener=opener,
    )
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return {}
    expected_metadata = _stripe_setup_metadata(
        lane=MANAGED_FUSEKIT_RUN_LANE,
        price_label=plan.price_label,
    )
    for item in data:
        if _stripe_price_matches_plan(
            item,
            plan=plan,
            expected_metadata=expected_metadata,
        ):
            assert isinstance(item, Mapping)
            product = item.get("product")
            assert isinstance(product, Mapping)
            return {
                "price_id": _public_stripe_id(item.get("id"), prefix="price_"),
                "product_id": _public_stripe_id(product.get("id"), prefix="prod_"),
            }
    raise FuseKitError(
        "Existing Stripe Price with FuseKit lookup key does not match the requested "
        "FuseKit-scoped managed-run price."
    )


def _stripe_price_matches_plan(
    value: object,
    *,
    plan: StripeManagedRunPricePlan,
    expected_metadata: Mapping[str, str],
) -> bool:
    if not isinstance(value, Mapping):
        return False
    product = value.get("product")
    if not isinstance(product, Mapping):
        return False
    return (
        _public_stripe_id(value.get("id"), prefix="price_") != ""
        and value.get("active") is True
        and value.get("type") in {"one_time", "", None}
        and value.get("unit_amount") == plan.amount_cents
        and str(value.get("currency") or "").lower() == plan.currency
        and value.get("lookup_key") == plan.lookup_key
        and _metadata_matches(value.get("metadata"), expected_metadata)
        and _public_stripe_id(product.get("id"), prefix="prod_") != ""
        and product.get("active") is True
        and _product_name_scoped(product)
        and _metadata_matches(product.get("metadata"), expected_metadata)
    )


def _metadata_matches(value: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(value, Mapping):
        return False
    return all(value.get(key) == expected_value for key, expected_value in expected.items())


def _product_name_scoped(value: Mapping[str, object]) -> bool:
    name = value.get("name")
    return isinstance(name, str) and _valid_fusekit_product_name(name)


def _stripe_get(
    stripe_secret_key: str,
    path: str,
    query: Mapping[str, str],
    *,
    opener: UrlOpener | None,
) -> dict[str, object]:
    url = STRIPE_API_BASE + path + "?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {stripe_secret_key}",
            "User-Agent": "FuseKit",
        },
    )
    open_url = opener or urllib.request.urlopen
    with open_url(request, timeout=30.0) as response:
        raw = response.read()
        status = int(getattr(response, "status", 200))
    if status >= 400:
        raise FuseKitError(f"Stripe setup lookup returned HTTP {status}.")
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError("Stripe setup lookup response is invalid.")
    return decoded


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


def _valid_fusekit_product_name(value: str) -> bool:
    cleaned = _public_stripe_product_name(value)
    return bool(cleaned and cleaned == value and "fusekit" in cleaned.lower())


def _public_stripe_product_name(value: str) -> str:
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > MAX_MANAGED_RUN_PRODUCT_NAME_LENGTH:
        return ""
    if contains_durable_secret_text(cleaned) or any(ch in cleaned for ch in "<>{}"):
        return ""
    if not all(ch.isprintable() for ch in cleaned):
        return ""
    return cleaned


def _public_stripe_product_description(value: str) -> str:
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > MAX_MANAGED_RUN_PRODUCT_DESCRIPTION_LENGTH:
        return ""
    if contains_durable_secret_text(cleaned) or any(ch in cleaned for ch in "<>{}"):
        return ""
    if not all(ch.isprintable() for ch in cleaned):
        return ""
    return cleaned


def _managed_run_lookup_key(*, amount_cents: int, currency: str, price_label: str) -> str:
    digest = _public_hash(f"{amount_cents}:{currency}:{price_label}")[:16]
    return f"fusekit_managed_run_{currency}_{amount_cents}_{digest}"


def _price_label_matches_amount(
    value: str,
    *,
    amount_cents: int,
    currency: str,
) -> bool:
    normalized = " ".join(value.split())
    currency_marker = currency.lower()
    amounts = set(_currency_amount_matches(normalized, currency_marker))
    if "$" in normalized:
        if currency_marker != "usd" and currency_marker not in normalized.lower():
            return False
        amounts.update(_dollar_amount_matches(normalized))
    expected = decimal.Decimal(amount_cents) / decimal.Decimal(100)
    return expected in amounts


def _currency_amount_matches(value: str, currency: str) -> list[decimal.Decimal]:
    pattern = re.compile(
        rf"(?:\b{re.escape(currency)}\b\s*)"
        r"(?P<after>\d[\d,]*(?:\.\d{1,2})?)"
        r"|(?P<before>\d[\d,]*(?:\.\d{1,2})?)"
        rf"\s*(?:\b{re.escape(currency)}\b)",
        re.IGNORECASE,
    )
    amounts: list[decimal.Decimal] = []
    for match in pattern.finditer(value):
        raw = match.group("after") or match.group("before")
        amount = _public_decimal_amount(raw)
        if amount is not None:
            amounts.append(amount)
    return amounts


def _dollar_amount_matches(value: str) -> list[decimal.Decimal]:
    amounts: list[decimal.Decimal] = []
    for match in re.finditer(r"\$\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?)", value):
        amount = _public_decimal_amount(match.group("amount"))
        if amount is not None:
            amounts.append(amount)
    return amounts


def _public_decimal_amount(value: str) -> decimal.Decimal | None:
    try:
        amount = decimal.Decimal(value.replace(",", ""))
    except decimal.InvalidOperation:
        return None
    if amount <= 0:
        return None
    return amount.quantize(decimal.Decimal("0.01"))


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
