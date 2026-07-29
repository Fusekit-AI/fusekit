from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from collections.abc import Mapping

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.stripe_webhook import (
    STRIPE_MANAGED_WEBHOOK_EVENT,
    STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION,
    STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION,
    build_stripe_managed_run_webhook_plan,
    create_stripe_managed_run_webhook,
    main,
    verify_main,
    verify_stripe_managed_run_webhook,
)

LIVE_STRIPE_SECRET = "sk_" "live_secret_value"
WEBHOOK_URL = "https://fusekit.snowmanai.org/api/hosted/payments/stripe-webhook"


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


class StripeWebhookOpener:
    def __init__(
        self,
        *,
        existing_endpoints: list[Mapping[str, object]] | None = None,
        retrieve_payload: Mapping[str, object] | None = None,
    ) -> None:
        self.existing_endpoints = list(existing_endpoints or [])
        self.retrieve_payload = retrieve_payload
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, list[str]]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        self.bodies.append(urllib.parse.parse_qs((request.data or b"").decode("utf-8")))
        assert timeout == 30.0
        if request.full_url == "https://api.stripe.com/v1/webhook_endpoints?limit=100":
            return FakeResponse({"object": "list", "data": self.existing_endpoints})
        if request.full_url == "https://api.stripe.com/v1/webhook_endpoints":
            return FakeResponse(
                {
                    "id": "we_fusekit_managed_run",
                    "secret": "whsec_" + ("a" * 24),
                    "status": "enabled",
                    "url": WEBHOOK_URL,
                    "enabled_events": [STRIPE_MANAGED_WEBHOOK_EVENT],
                    "metadata": _metadata(),
                }
            )
        if request.full_url == (
            "https://api.stripe.com/v1/webhook_endpoints/we_fusekit_managed_run"
        ):
            return FakeResponse(self.retrieve_payload or _webhook_payload())
        raise AssertionError(f"Unexpected Stripe URL: {request.full_url}")


def _metadata() -> dict[str, str]:
    return {
        "fusekit_component": "hosted-launcher",
        "fusekit_lane": "managed-fusekit-run",
        "fusekit_scope": "managed-run-webhook",
        "public_endpoint_hash": hashlib.sha256(WEBHOOK_URL.encode("utf-8")).hexdigest(),
    }


def _webhook_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": "we_fusekit_managed_run",
        "status": "enabled",
        "url": WEBHOOK_URL,
        "enabled_events": [STRIPE_MANAGED_WEBHOOK_EVENT],
        "metadata": _metadata(),
    }
    payload.update(overrides)
    return payload


def test_stripe_webhook_setup_dry_run_has_no_network_and_no_secret() -> None:
    opener = StripeWebhookOpener()

    report = create_stripe_managed_run_webhook(
        stripe_secret_key=LIVE_STRIPE_SECRET,
        execute=False,
        confirm_shared_account=False,
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["schema_version"] == STRIPE_MANAGED_WEBHOOK_SETUP_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["dry_run"] is True
    assert report["endpoint_url"] == WEBHOOK_URL
    assert report["enabled_events"] == [STRIPE_MANAGED_WEBHOOK_EVENT]
    assert report["webhook_endpoint_id"] == ""
    assert report["webhook_secret_received"] is False
    assert opener.requests == []
    assert "whsec_" not in serialized
    assert LIVE_STRIPE_SECRET not in serialized


def test_stripe_webhook_setup_creates_fusekit_scoped_endpoint_without_emitting_secret() -> None:
    opener = StripeWebhookOpener()

    report = create_stripe_managed_run_webhook(
        stripe_secret_key=LIVE_STRIPE_SECRET,
        execute=True,
        confirm_shared_account=True,
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["executed"] is True
    assert report["mutated"] is True
    assert report["reused_existing"] is False
    assert report["webhook_endpoint_id"] == "we_fusekit_managed_run"
    assert report["webhook_secret_received"] is True
    assert [request.full_url for request in opener.requests] == [
        "https://api.stripe.com/v1/webhook_endpoints?limit=100",
        "https://api.stripe.com/v1/webhook_endpoints",
    ]
    assert opener.requests[1].headers["Idempotency-key"].startswith("fusekit-webhook-")
    assert opener.bodies[1]["url"] == [WEBHOOK_URL]
    assert opener.bodies[1]["enabled_events[]"] == [STRIPE_MANAGED_WEBHOOK_EVENT]
    assert opener.bodies[1]["metadata[fusekit_scope]"] == ["managed-run-webhook"]
    assert "whsec_" not in serialized
    assert LIVE_STRIPE_SECRET not in serialized


def test_stripe_webhook_setup_reuses_matching_fusekit_endpoint() -> None:
    opener = StripeWebhookOpener(existing_endpoints=[_webhook_payload()])

    report = create_stripe_managed_run_webhook(
        stripe_secret_key=LIVE_STRIPE_SECRET,
        execute=True,
        confirm_shared_account=True,
        opener=opener,
    )

    assert report["executed"] is True
    assert report["mutated"] is False
    assert report["reused_existing"] is True
    assert report["webhook_endpoint_id"] == "we_fusekit_managed_run"
    assert report["webhook_secret_received"] is False
    assert len(opener.requests) == 1


def test_stripe_webhook_setup_blocks_occupied_non_fusekit_endpoint() -> None:
    opener = StripeWebhookOpener(
        existing_endpoints=[
            _webhook_payload(
                id="we_mailpilot",
                enabled_events=["checkout.session.completed", "customer.created"],
                metadata={"snowman_product": "mailpilot"},
            )
        ]
    )

    with pytest.raises(FuseKitError, match="occupied"):
        create_stripe_managed_run_webhook(
            stripe_secret_key=LIVE_STRIPE_SECRET,
            execute=True,
            confirm_shared_account=True,
            opener=opener,
        )

    assert len(opener.requests) == 1


def test_stripe_webhook_verify_accepts_fusekit_endpoint() -> None:
    opener = StripeWebhookOpener(retrieve_payload=_webhook_payload())

    report = verify_stripe_managed_run_webhook(
        stripe_secret_key=LIVE_STRIPE_SECRET,
        webhook_endpoint_id="we_fusekit_managed_run",
        opener=opener,
    )

    serialized = json.dumps(report)
    assert report["schema_version"] == STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blockers"] == []
    assert report["webhook_endpoint_id"] == "we_fusekit_managed_run"
    assert report["checks"]["metadata_matches"] is True
    assert "whsec_" not in serialized
    assert LIVE_STRIPE_SECRET not in serialized


def test_stripe_webhook_verify_blocks_broader_events() -> None:
    opener = StripeWebhookOpener(
        retrieve_payload=_webhook_payload(
            enabled_events=["checkout.session.completed", "customer.created"]
        )
    )

    report = verify_stripe_managed_run_webhook(
        stripe_secret_key=LIVE_STRIPE_SECRET,
        webhook_endpoint_id="we_fusekit_managed_run",
        opener=opener,
    )

    assert report["ready"] is False
    assert report["webhook_endpoint_id"] == ""
    assert report["blockers"] == ["stripe_webhook_enabled_events_mismatch"]


def test_stripe_webhook_rejects_noncanonical_url_and_private_marker_id() -> None:
    with pytest.raises(FuseKitError, match="canonical FuseKit URL"):
        build_stripe_managed_run_webhook_plan(
            stripe_secret_key=LIVE_STRIPE_SECRET,
            endpoint_url="https://example.com/api/hosted/payments/stripe-webhook",
        )
    with pytest.raises(FuseKitError, match="endpoint id is invalid"):
        verify_stripe_managed_run_webhook(
            stripe_secret_key=LIVE_STRIPE_SECRET,
            webhook_endpoint_id="we_rk_live_should_not_render",
            opener=StripeWebhookOpener(retrieve_payload=_webhook_payload()),
        )


def test_stripe_webhook_main_reads_env_and_redacts_output(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FUSEKIT_STRIPE_SECRET_KEY", LIVE_STRIPE_SECRET)
    monkeypatch.setenv("FUSEKIT_STRIPE_WEBHOOK_ENDPOINT_ID", "we_fusekit_managed_run")
    monkeypatch.setattr(
        "fusekit.hosted.stripe_webhook.urllib.request.urlopen",
        StripeWebhookOpener(retrieve_payload=_webhook_payload()),
    )

    exit_code = main(["--verify"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ready"] is True
    assert "whsec_" not in json.dumps(payload)


def test_stripe_webhook_verify_main_defaults_to_verify(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FUSEKIT_STRIPE_SECRET_KEY", LIVE_STRIPE_SECRET)
    monkeypatch.setenv("FUSEKIT_STRIPE_WEBHOOK_ENDPOINT_ID", "we_fusekit_managed_run")
    monkeypatch.setattr(
        "fusekit.hosted.stripe_webhook.urllib.request.urlopen",
        StripeWebhookOpener(retrieve_payload=_webhook_payload()),
    )

    exit_code = verify_main([])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["schema_version"] == STRIPE_MANAGED_WEBHOOK_VERIFY_SCHEMA_VERSION
    assert payload["ready"] is True
