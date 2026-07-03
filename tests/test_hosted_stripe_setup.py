from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Mapping

import pytest

from fusekit.errors import FuseKitError
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
    def __init__(self) -> None:
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
    assert report["product_id"] == "prod_fusekit_managed_run"
    assert report["price_id"] == "price_fusekit_managed_run"
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "price_fusekit_managed_run",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "$49 one-time managed FuseKit run",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    assert [request.full_url for request in opener.requests] == [
        "https://api.stripe.com/v1/products",
        "https://api.stripe.com/v1/prices",
    ]
    assert opener.requests[0].headers["Authorization"] == "Bearer sk_live_secret_value"
    assert opener.requests[0].headers["Idempotency-key"].startswith("fusekit-product-")
    assert opener.requests[1].headers["Idempotency-key"].startswith("fusekit-price-")
    assert opener.bodies[0]["name"] == [DEFAULT_MANAGED_RUN_PRODUCT_NAME]
    assert opener.bodies[0]["metadata[fusekit_scope]"] == ["managed-run-price"]
    assert opener.bodies[0]["metadata[fusekit_lane]"] == ["managed-fusekit-run"]
    assert opener.bodies[1]["product"] == ["prod_fusekit_managed_run"]
    assert opener.bodies[1]["unit_amount"] == ["4900"]
    assert opener.bodies[1]["currency"] == ["usd"]
    assert opener.bodies[1]["metadata[fusekit_scope]"] == ["managed-run-price"]
    assert "sk_live_secret_value" not in serialized


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
