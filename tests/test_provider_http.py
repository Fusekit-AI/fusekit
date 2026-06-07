from __future__ import annotations

import io
from urllib.error import HTTPError

import pytest

from fusekit.errors import ProviderError
from fusekit.providers import http
from fusekit.providers.http import JsonHttpClient


def test_json_http_client_does_not_echo_error_bodies(monkeypatch) -> None:
    secret = "provider-secret-from-error-body"

    def failing_urlopen(request: object, timeout: int) -> object:
        del request, timeout
        raise HTTPError(
            url="https://api.example.test/resource",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(f'{{"token":"{secret}"}}'.encode()),
        )

    monkeypatch.setattr(http, "urlopen", failing_urlopen)

    with pytest.raises(ProviderError) as exc:
        JsonHttpClient("https://api.example.test", "provider-token").request("GET", "/resource")

    assert "HTTP 400" in str(exc.value)
    assert secret not in str(exc.value)


def test_json_http_client_includes_safe_provider_error_details(monkeypatch) -> None:
    def failing_urlopen(request: object, timeout: int) -> object:
        del request, timeout
        raise HTTPError(
            url="https://api.example.test/resource",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(
                b'{"error":{"code":"bad_request","message":"Failed to link repo.",'
                b'"action":"Add a Login Connection",'
                b'"link":"https://vercel.com/docs/accounts/create-an-account",'
                b'"repo":"owner/app"}}'
            ),
        )

    monkeypatch.setattr(http, "urlopen", failing_urlopen)

    with pytest.raises(ProviderError) as exc:
        JsonHttpClient("https://api.example.test", "provider-token").request("POST", "/resource")

    message = str(exc.value)
    assert "HTTP 400" in message
    assert "message=Failed to link repo." in message
    assert "action=Add a Login Connection" in message
    assert "repo=owner/app" in message
