from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from collections.abc import Mapping

from fusekit.hosted.stripe_verify import (
    STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION,
    main,
    verify_stripe_managed_run_price,
)

PRICE_LABEL = "Launch validation: $1.00 FuseKit managed run"


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


class StripeVerifyOpener:
    def __init__(self, payload: Mapping[str, object]) -> None:
        self.payload = payload
        self.requests: list[urllib.request.Request] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        assert timeout == 30.0
        return FakeResponse(self.payload)


def _price_payload(**overrides: object) -> dict[str, object]:
    metadata = {
        "fusekit_component": "hosted-launcher",
        "fusekit_lane": "managed-fusekit-run",
        "fusekit_scope": "managed-run-price",
        "public_price_label_hash": hashlib.sha256(PRICE_LABEL.encode("utf-8")).hexdigest(),
    }
    payload: dict[str, object] = {
        "id": "price_fusekit_managed_run",
        "active": True,
        "type": "one_time",
        "unit_amount": 100,
        "currency": "usd",
        "lookup_key": (
            "fusekit_managed_run_usd_100_"
            + hashlib.sha256(f"100:usd:{PRICE_LABEL}".encode()).hexdigest()[:16]
        ),
        "metadata": dict(metadata),
        "product": {
            "id": "prod_fusekit_managed_run",
            "active": True,
            "name": "FuseKit Managed Run",
            "metadata": dict(metadata),
        },
    }
    payload.update(overrides)
    return payload


def test_stripe_price_verify_accepts_fusekit_scoped_price() -> None:
    opener = StripeVerifyOpener(_price_payload())

    report = verify_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        price_id="price_fusekit_managed_run",
        amount_cents=100,
        currency="usd",
        price_label=PRICE_LABEL,
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["schema_version"] == STRIPE_MANAGED_PRICE_VERIFY_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blockers"] == []
    assert report["price_id"] == "price_fusekit_managed_run"
    assert report["product_id"] == "prod_fusekit_managed_run"
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "price_fusekit_managed_run",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": PRICE_LABEL,
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    assert report["checks"]["price_metadata_matches"] is True
    assert report["checks"]["product_metadata_matches"] is True
    request = opener.requests[0]
    assert request.full_url == (
        "https://api.stripe.com/v1/prices/price_fusekit_managed_run?expand%5B%5D=product"
    )
    assert request.headers["Authorization"] == "Bearer sk_live_secret_value"
    assert "sk_live_secret_value" not in serialized
    assert "card" not in serialized.lower()


def test_stripe_price_verify_blocks_shared_account_wrong_price() -> None:
    opener = StripeVerifyOpener(
        _price_payload(
            unit_amount=4900,
            lookup_key="snowman_other_product",
            metadata={},
            product={
                "id": "prod_mailpilot",
                "active": True,
                "name": "Snowman AI MailPilot",
                "metadata": {},
            },
        )
    )

    report = verify_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        price_id="price_fusekit_managed_run",
        amount_cents=100,
        currency="usd",
        price_label=PRICE_LABEL,
        opener=opener,
    )

    assert report["ready"] is False
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    assert report["blockers"] == [
        "stripe_price_amount_mismatch",
        "stripe_price_lookup_key_mismatch",
        "stripe_price_metadata_mismatch",
        "stripe_product_not_fusekit_scoped",
        "stripe_product_metadata_mismatch",
    ]
    assert "Do not enable managed paid runs" in report["next_actions"][0]


def test_stripe_price_verify_blocks_secret_shaped_product_name() -> None:
    opener = StripeVerifyOpener(
        _price_payload(
            product={
                "id": "prod_fusekit_managed_run",
                "active": True,
                "name": "FuseKit sk_live_thisshouldnotrender",
                "metadata": _price_payload()["metadata"],
            },
        )
    )

    report = verify_stripe_managed_run_price(
        stripe_secret_key="sk_live_secret_value",
        price_id="price_fusekit_managed_run",
        amount_cents=100,
        currency="usd",
        price_label=PRICE_LABEL,
        opener=opener,
    )

    assert report["ready"] is False
    assert "stripe_product_not_fusekit_scoped" in report["blockers"]
    assert report["hosted_runtime_env"] == {
        "FUSEKIT_STRIPE_PRICE_ID": "",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }


def test_stripe_price_verify_main_reads_env_and_redacts_output(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("FUSEKIT_STRIPE_SECRET_KEY", "sk_live_secret_value")
    monkeypatch.setenv("FUSEKIT_STRIPE_PRICE_ID", "price_fusekit_managed_run")
    opener = StripeVerifyOpener(_price_payload())
    monkeypatch.setattr("fusekit.hosted.stripe_verify.urllib.request.urlopen", opener)

    exit_code = main(
        [
            "--amount-cents",
            "100",
            "--label",
            PRICE_LABEL,
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ready"] is True
    assert "sk_live_secret_value" not in json.dumps(payload)
