"""Operator helper for verifying hosted managed-run Stripe prices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from collections.abc import Mapping

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
    HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
    STRIPE_API_BASE,
    _stripe_account_mode,
)
from fusekit.hosted.github_app import UrlOpener
from fusekit.hosted.lanes import MANAGED_FUSEKIT_RUN_LANE
from fusekit.hosted.stripe_setup import (
    STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION,
    StripeManagedRunPricePlan,
    _valid_fusekit_product_name,
    build_stripe_managed_run_price_plan,
)
from fusekit.security import contains_durable_secret_text

STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION = "fusekit.stripe-managed-price-verify.v1"


def verify_stripe_managed_run_price(
    *,
    stripe_secret_key: str,
    price_id: str,
    amount_cents: int,
    currency: str,
    price_label: str,
    allow_test_mode: bool = False,
    opener: UrlOpener | None = None,
) -> dict[str, object]:
    """Verify a Stripe Price is the expected FuseKit-scoped managed-run price."""

    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key=stripe_secret_key,
        amount_cents=amount_cents,
        currency=currency,
        price_label=price_label,
        allow_test_mode=allow_test_mode,
    )
    public_price_id = _public_stripe_id(price_id, prefix="price_")
    if not public_price_id:
        raise FuseKitError("Stripe price id is invalid.")
    payload = _stripe_get(
        stripe_secret_key,
        f"/v1/prices/{urllib.parse.quote(public_price_id, safe='')}",
        {"expand[]": "product"},
        opener=opener,
    )
    blockers = _price_verification_blockers(
        payload,
        price_id=public_price_id,
        amount_cents=plan.amount_cents,
        currency=plan.currency,
        lookup_key=plan.lookup_key,
        expected_metadata=_expected_metadata(plan),
    )
    product = payload.get("product")
    product_id = _public_stripe_id(
        product.get("id") if isinstance(product, Mapping) else "",
        prefix="prod_",
    )
    report = {
        "schema_version": STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION,
        "setup_schema_version": STRIPE_MANAGED_PRICE_SETUP_SCHEMA_VERSION,
        "provider": "stripe",
        "lane": MANAGED_FUSEKIT_RUN_LANE,
        "ready": not blockers,
        "blockers": blockers,
        "account_mode": _stripe_account_mode(stripe_secret_key),
        "price_id": public_price_id,
        "product_id": product_id,
        "amount_cents": plan.amount_cents,
        "currency": plan.currency,
        "price_label": plan.price_label,
        "lookup_key": plan.lookup_key,
        "checks": {
            "price_active": payload.get("active") is True,
            "price_id_matches": payload.get("id") == public_price_id,
            "price_is_one_time": payload.get("type") in {"one_time", "", None},
            "amount_matches": _unit_amount_matches(
                payload.get("unit_amount"),
                plan.amount_cents,
            ),
            "currency_matches": str(payload.get("currency") or "").lower() == plan.currency,
            "lookup_key_matches": payload.get("lookup_key") == plan.lookup_key,
            "price_metadata_matches": _metadata_matches(
                payload.get("metadata"),
                _expected_metadata(plan),
            ),
            "product_expanded": isinstance(product, Mapping),
            "product_active": isinstance(product, Mapping) and product.get("active") is True,
            "product_name_scoped": _product_name_scoped(product),
            "product_metadata_matches": isinstance(product, Mapping)
            and _metadata_matches(product.get("metadata"), _expected_metadata(plan)),
        },
        "hosted_runtime_env": {
            "FUSEKIT_STRIPE_PRICE_ID": public_price_id if not blockers else "",
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL": plan.price_label if not blockers else "",
            "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
        },
        "shared_account_boundary": HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
        "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        "next_actions": _verification_next_actions(blockers),
    }
    serialized = json.dumps(report, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("stripe_price_verify_report_contains_secret_text")
    return report


def main(argv: list[str] | None = None) -> int:
    """Verify a FuseKit-managed Stripe Price and print redacted JSON."""

    parser = argparse.ArgumentParser(
        description="Verify a FuseKit-scoped Stripe Price for hosted managed runs."
    )
    parser.add_argument("--price-id", default="")
    parser.add_argument("--amount-cents", type=int, required=True)
    parser.add_argument("--currency", default="usd")
    parser.add_argument("--label", required=True, help="Public price label shown before Checkout")
    parser.add_argument("--secret-key-env", default="FUSEKIT_STRIPE_SECRET_KEY")
    parser.add_argument("--price-id-env", default="FUSEKIT_STRIPE_PRICE_ID")
    parser.add_argument("--allow-test-mode", action="store_true")
    args = parser.parse_args(argv)
    secret_key = os.environ.get(args.secret_key_env, "")
    price_id = args.price_id or os.environ.get(args.price_id_env, "")
    try:
        report = verify_stripe_managed_run_price(
            stripe_secret_key=secret_key,
            price_id=price_id,
            amount_cents=args.amount_cents,
            currency=args.currency,
            price_label=args.label,
            allow_test_mode=args.allow_test_mode,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION,
            "ready": False,
            "error": str(exc),
            "secret_boundary": HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 2


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
        raise FuseKitError(f"Stripe price verification returned HTTP {status}.")
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError("Stripe price verification response is invalid.")
    return decoded


def _price_verification_blockers(
    payload: Mapping[str, object],
    *,
    price_id: str,
    amount_cents: int,
    currency: str,
    lookup_key: str,
    expected_metadata: Mapping[str, str],
) -> list[str]:
    blockers: list[str] = []
    if payload.get("id") != price_id:
        blockers.append("stripe_price_id_mismatch")
    if payload.get("active") is not True:
        blockers.append("stripe_price_inactive")
    if payload.get("type") not in {"one_time", "", None}:
        blockers.append("stripe_price_must_be_one_time")
    if not _unit_amount_matches(payload.get("unit_amount"), amount_cents):
        blockers.append("stripe_price_amount_mismatch")
    if str(payload.get("currency") or "").lower() != currency:
        blockers.append("stripe_price_currency_mismatch")
    if payload.get("lookup_key") != lookup_key:
        blockers.append("stripe_price_lookup_key_mismatch")
    if not _metadata_matches(payload.get("metadata"), expected_metadata):
        blockers.append("stripe_price_metadata_mismatch")
    product = payload.get("product")
    if not isinstance(product, Mapping):
        blockers.append("stripe_product_not_expanded")
        return blockers
    if not _public_stripe_id(product.get("id"), prefix="prod_"):
        blockers.append("stripe_product_id_invalid")
    if product.get("active") is not True:
        blockers.append("stripe_product_inactive")
    if not _product_name_scoped(product):
        blockers.append("stripe_product_not_fusekit_scoped")
    if not _metadata_matches(product.get("metadata"), expected_metadata):
        blockers.append("stripe_product_metadata_mismatch")
    return blockers


def _verification_next_actions(blockers: list[str]) -> list[str]:
    if not blockers:
        return [
            "Store the verified FUSEKIT_STRIPE_PRICE_ID and "
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL in the hosted runtime secret file.",
            "Keep FUSEKIT_MANAGED_RUNS_ENABLED=0 until live Checkout proof and "
            "worker-dispatch acceptance pass.",
        ]
    return [
        "Do not enable managed paid runs with this Stripe Price.",
        "Create or verify a FuseKit-scoped Stripe Product and Price with "
        "fusekit-hosted-stripe-price, then rerun this verifier.",
    ]


def _expected_metadata(plan: StripeManagedRunPricePlan) -> dict[str, str]:
    return {
        "fusekit_component": "hosted-launcher",
        "fusekit_lane": MANAGED_FUSEKIT_RUN_LANE,
        "fusekit_scope": "managed-run-price",
        "public_price_label_hash": _public_hash(plan.price_label),
    }


def _metadata_matches(value: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value.keys()) != set(expected.keys()):
        return False
    return all(value.get(key) == expected_value for key, expected_value in expected.items())


def _unit_amount_matches(value: object, amount_cents: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value == amount_cents
    )


def _product_name_scoped(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    name = value.get("name")
    return isinstance(name, str) and _valid_fusekit_product_name(name)


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
