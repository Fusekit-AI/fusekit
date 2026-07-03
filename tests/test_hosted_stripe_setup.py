from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Mapping

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_STRIPE_SETUP_SECRET_BOUNDARY,
    HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY,
)
from fusekit.hosted.stripe_setup import (
    DEFAULT_MANAGED_RUN_PRODUCT_NAME,
    build_stripe_managed_run_price_plan,
    create_stripe_managed_run_price,
    main,
)


class FakeResponse:
    def __init__(self, payload: Mapping[str, object], status: int = 200) -> None:
        self.status = status
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class StripeSetupOpener:
    def __init__(self, *, existing_prices: list[Mapping[str, object]] | None = None) -> None:
        self.existing_prices = list(existing_prices or [])
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, list[str]]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        body = urllib.parse.parse_qs((request.data or b"").decode("utf-8"))
        self.bodies.append(body)
        assert timeout == 30.0
        if request.full_url.startswith("https://api.stripe.com/v1/prices?"):
            parsed = urllib.parse.urlparse(request.full_url)
            query = urllib.parse.parse_qs(parsed.query)
            assert query["active"] == ["true"]
            assert query["limit"] == ["10"]
            assert query["expand[]"] == ["data.product"]
            assert query["lookup_keys[]"]
            return FakeResponse(
                {
                    "object": "list",
                    "data": self.existing_prices,
                    "has_more": False,
                }
            )
        if request.full_url.endswith("/v1/products"):
            return FakeResponse({"id": "prod_fusekit_managed_run"})
        if request.full_url.endswith("/v1/prices"):
            return FakeResponse({"id": "price_fusekit_managed_run"})
        raise AssertionError(f"Unexpected Stripe URL: {request.full_url}")


def test_stripe_price_setup_dry_run_has_no_network_and_no_secret() -> None:
    opener = StripeSetupOpener()

    report = create_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="USD",
        price_label="Launch validation: $1.00 FuseKit managed run",
        execute=False,
        confirm_shared_account=False,
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["ready"] is True
    assert report["dry_run"] is True
    assert report["executed"] is False
    assert report["product_id"] == ""
    assert report["price_id"] == ""
    assert report["product"]["name"] == DEFAULT_MANAGED_RUN_PRODUCT_NAME
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "Launch validation: $1.00 FuseKit managed run",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    assert report["shared_account_boundary"] == HOSTED_STRIPE_SHARED_ACCOUNT_BOUNDARY
    assert report["secret_boundary"] == HOSTED_STRIPE_SETUP_SECRET_BOUNDARY
    assert opener.requests == []
    assert "sk_live_secret_value" not in serialized
    assert "card" not in serialized.lower()


def test_stripe_price_setup_execute_creates_fusekit_scoped_product_and_price() -> None:
    opener = StripeSetupOpener()

    report = create_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=4900,
        currency="usd",
        price_label="$49 one-time managed FuseKit run",
        execute=True,
        confirm_shared_account=True,
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["executed"] is True
    assert report["mutated"] is True
    assert report["reused_existing"] is False
    assert report["product_id"] == "prod_fusekit_managed_run"
    assert report["price_id"] == "price_fusekit_managed_run"
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "price_fusekit_managed_run",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "$49 one-time managed FuseKit run",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    assert opener.requests[0].full_url.startswith("https://api.stripe.com/v1/prices?")
    assert [request.full_url for request in opener.requests[1:]] == [
        "https://api.stripe.com/v1/products",
        "https://api.stripe.com/v1/prices",
    ]
    assert opener.requests[0].headers["Authorization"] == "Bearer sk_live_secret_value"
    assert opener.requests[1].headers["Idempotency-key"].startswith("fusekit-product-")
    assert opener.requests[2].headers["Idempotency-key"].startswith("fusekit-price-")
    assert opener.bodies[1]["name"] == [DEFAULT_MANAGED_RUN_PRODUCT_NAME]
    assert opener.bodies[1]["metadata[fusekit_scope]"] == ["managed-run-price"]
    assert opener.bodies[1]["metadata[fusekit_lane]"] == ["managed-fusekit-run"]
    assert opener.bodies[2]["product"] == ["prod_fusekit_managed_run"]
    assert opener.bodies[2]["unit_amount"] == ["4900"]
    assert opener.bodies[2]["currency"] == ["usd"]
    assert opener.bodies[2]["metadata[fusekit_scope]"] == ["managed-run-price"]
    assert "sk_live_secret_value" not in serialized


def test_stripe_price_setup_reuses_existing_matching_fusekit_price() -> None:
    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="usd",
        price_label="Launch validation: $1.00 FuseKit managed run",
    )
    metadata = plan.public_dict()["price"]["metadata"]
    assert isinstance(metadata, dict)
    opener = StripeSetupOpener(
        existing_prices=[
            {
                "id": "price_existing_fusekit",
                "active": True,
                "type": "one_time",
                "unit_amount": 100,
                "currency": "usd",
                "lookup_key": plan.lookup_key,
                "metadata": metadata,
                "product": {
                    "id": "prod_existing_fusekit",
                    "active": True,
                    "name": "FuseKit Managed Run",
                    "metadata": metadata,
                },
            }
        ]
    )

    report = create_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="usd",
        price_label="Launch validation: $1.00 FuseKit managed run",
        execute=True,
        confirm_shared_account=True,
        opener=opener,
    )

    assert report["executed"] is True
    assert report["mutated"] is False
    assert report["reused_existing"] is True
    assert report["price_id"] == "price_existing_fusekit"
    assert report["product_id"] == "prod_existing_fusekit"
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url.startswith("https://api.stripe.com/v1/prices?")
    assert "lookup_keys%5B%5D=" in opener.requests[0].full_url


def test_stripe_price_setup_blocks_occupied_lookup_key_that_is_not_fusekit_scoped() -> None:
    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="usd",
        price_label="Launch validation: $1.00 FuseKit managed run",
    )
    opener = StripeSetupOpener(
        existing_prices=[
            {
                "id": "price_existing_other",
                "active": True,
                "type": "one_time",
                "unit_amount": 100,
                "currency": "usd",
                "lookup_key": plan.lookup_key,
                "metadata": {},
                "product": {
                    "id": "prod_mailpilot",
                    "active": True,
                    "name": "Snowman AI MailPilot",
                    "metadata": {},
                },
            }
        ]
    )

    with pytest.raises(FuseKitError, match="lookup key does not match"):
        create_stripe_managed_run_price(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
            execute=True,
            confirm_shared_account=True,
            opener=opener,
        )

    assert len(opener.requests) == 1


def test_stripe_price_setup_rejects_secret_or_markup_public_product_fields() -> None:
    with pytest.raises(FuseKitError, match="product name"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
            product_name="FuseKit sk_live_thisshouldnotrender",
        )
    with pytest.raises(FuseKitError, match="product description"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
            product_description="<script>FuseKit $1.00 managed run</script>",
        )


def test_stripe_price_setup_does_not_reuse_secret_shaped_product_name() -> None:
    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="usd",
        price_label="Launch validation: $1.00 FuseKit managed run",
    )
    metadata = plan.public_dict()["price"]["metadata"]
    assert isinstance(metadata, dict)
    opener = StripeSetupOpener(
        existing_prices=[
            {
                "id": "price_existing_fusekit",
                "active": True,
                "type": "one_time",
                "unit_amount": 100,
                "currency": "usd",
                "lookup_key": plan.lookup_key,
                "metadata": metadata,
                "product": {
                    "id": "prod_existing_fusekit",
                    "active": True,
                    "name": "FuseKit sk_live_thisshouldnotrender",
                    "metadata": metadata,
                },
            }
        ]
    )

    with pytest.raises(FuseKitError, match="lookup key does not match"):
        create_stripe_managed_run_price(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
            execute=True,
            confirm_shared_account=True,
            opener=opener,
        )

    assert len(opener.requests) == 1


def test_stripe_price_setup_refuses_mutation_without_shared_account_confirmation() -> None:
    with pytest.raises(FuseKitError, match="confirm-shared-account"):
        create_stripe_managed_run_price(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
            execute=True,
            confirm_shared_account=False,
        )


def test_stripe_price_setup_requires_live_key_unless_test_mode_allowed() -> None:
    with pytest.raises(FuseKitError, match="live Stripe secret key"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_test_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Test mode: $1.00 FuseKit managed run",
        )

    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key="sk_test_secret_value",
        amount_cents=100,
        currency="usd",
        price_label="Test mode: $1.00 FuseKit managed run",
        allow_test_mode=True,
    )

    assert plan.account_mode == "test"


def test_stripe_price_setup_rejects_ambiguous_or_secret_like_labels() -> None:
    with pytest.raises(FuseKitError, match="price label"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="FuseKit managed run",
        )
    with pytest.raises(FuseKitError, match="price label"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Use price_123 for FuseKit",
        )
    with pytest.raises(FuseKitError, match="price label"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="Launch validation: .00 FuseKit managed run",
        )
    with pytest.raises(FuseKitError, match="price label"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="usd",
            price_label="<b>Launch validation: $1.00 FuseKit managed run</b>",
        )


def test_stripe_price_setup_requires_label_to_match_amount_and_currency() -> None:
    with pytest.raises(FuseKitError, match="match the configured amount"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=4900,
            currency="usd",
            price_label="Launch validation: $1.00 FuseKit managed run",
        )
    with pytest.raises(FuseKitError, match="match the configured amount"):
        build_stripe_managed_run_price_plan(
            stripe_secret_key="sk_live_secret_value",
            amount_cents=100,
            currency="cad",
            price_label="Launch validation: $1.00 FuseKit managed run",
        )

    plan = build_stripe_managed_run_price_plan(
        stripe_secret_key="sk_live_secret_value",
        amount_cents=100,
        currency="cad",
        price_label="Launch validation: CAD 1.00 FuseKit managed run",
    )

    assert plan.currency == "cad"
    assert plan.price_label == "Launch validation: CAD 1.00 FuseKit managed run"


def test_stripe_price_setup_main_reads_secret_from_env_and_redacts_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("FUSEKIT_STRIPE_SECRET_KEY", "sk_live_secret_value")

    assert (
        main(
            [
                "--amount-cents",
                "100",
                "--label",
                "Launch validation: $1.00 FuseKit managed run",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["ready"] is True
    assert payload["dry_run"] is True
    assert payload["hosted_runtime_env"]["FUSEKIT_MANAGED_RUNS_ENABLED"] == "0"
    assert "sk_live_secret_value" not in json.dumps(payload)


def test_stripe_price_setup_main_reports_missing_env_without_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("FUSEKIT_STRIPE_SECRET_KEY", raising=False)

    assert (
        main(
            [
                "--amount-cents",
                "100",
                "--label",
                "Launch validation: $1.00 FuseKit managed run",
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["ready"] is False
    assert payload["error"] == "Stripe secret key is not configured."
    assert "sk_" not in json.dumps(payload)
