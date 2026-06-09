from __future__ import annotations

import pytest

from fusekit.errors import ProviderError
from fusekit.providers.resend import ResendProvider, _record_from_resend


def test_resend_domain_creation_uses_explicit_region_and_sending_capability(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    class FakeClient:
        def __init__(self, api_base: str, token: str, *, auth_header: str) -> None:
            assert api_base == "https://api.resend.com"
            assert token == "resend-token"
            assert auth_header == "Bearer"

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, object] | None = None,
        ) -> dict[str, object]:
            calls.append((method, path, payload))
            if method == "GET" and path == "/domains":
                return {"data": []}
            if method == "POST" and path == "/domains":
                return {
                    "id": "domain-1",
                    "name": "moonlite.rsvp",
                    "status": "pending",
                    "region": "eu-west-1",
                    "records": [],
                }
            raise AssertionError(f"unexpected request {method} {path}")

    monkeypatch.setattr("fusekit.providers.resend.JsonHttpClient", FakeClient)

    domain = ResendProvider("resend-token").ensure_domain(
        "moonlite.rsvp",
        region="eu-west-1",
    )

    assert calls == [
        ("GET", "/domains", None),
        (
            "POST",
            "/domains",
            {
                "name": "moonlite.rsvp",
                "region": "eu-west-1",
                "capabilities": {"sending": "enabled", "receiving": "disabled"},
            },
        ),
    ]
    assert domain.id == "domain-1"
    assert domain.region == "eu-west-1"
    assert domain.reused is False


def test_resend_domain_rejects_unknown_region_before_mutation(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("client should not be created for invalid region")

    monkeypatch.setattr("fusekit.providers.resend.JsonHttpClient", FakeClient)

    with pytest.raises(ProviderError) as exc:
        ResendProvider("resend-token").ensure_domain(
            "moonlite.rsvp",
            region="moon-base-1",
        )

    assert "Resend region must be one of" in str(exc.value)


def test_resend_dns_record_accepts_auto_ttl() -> None:
    record = _record_from_resend(
        {
            "name": "send",
            "type": "MX",
            "value": "feedback-smtp.us-east-1.amazonses.com",
            "ttl": "Auto",
            "priority": 10,
        },
        "moonlite.rsvp",
    )

    assert record.name == "send.moonlite.rsvp"
    assert record.type == "MX"
    assert record.value == "feedback-smtp.us-east-1.amazonses.com"
    assert record.ttl == 300
    assert record.priority == 10
