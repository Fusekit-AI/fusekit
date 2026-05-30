"""Small JSON HTTP client for provider APIs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError


@dataclass(frozen=True)
class JsonHttpClient:
    """Minimal JSON HTTP client using the standard library."""

    base_url: str
    token: str
    auth_header: str = "Bearer"

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a JSON request and return a JSON mapping."""

        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            self.base_url.rstrip("/") + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"{self.auth_header} {self.token}",
                **(headers or {}),
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                text = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProviderError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ProviderError(f"{method} {path} failed: {exc.reason}") from exc
        if not text:
            return {}
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ProviderError(f"{method} {path} returned non-object JSON.")
        return data
