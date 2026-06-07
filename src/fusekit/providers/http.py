"""Small JSON HTTP client for provider APIs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.security.url import require_relative_api_path, require_safe_url


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

        base_url = require_safe_url(self.base_url, label="Provider API base URL")
        path = require_relative_api_path(path)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            base_url.rstrip("/") + path,
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
            with urlopen(request, timeout=30) as response:  # nosec B310
                text = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = _safe_http_error_detail(exc)
            suffix = f": {detail}" if detail else "."
            raise ProviderError(f"{method} {path} failed with HTTP {exc.code}{suffix}") from exc
        except URLError as exc:
            raise ProviderError(f"{method} {path} failed: {exc.reason}") from exc
        if not text:
            return {}
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ProviderError(f"{method} {path} returned non-object JSON.")
        return data


def _safe_http_error_detail(exc: HTTPError) -> str:
    """Return actionable provider error text without echoing arbitrary response bodies."""

    try:
        raw = exc.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    error = data.get("error")
    if isinstance(error, dict):
        source = error
    else:
        source = data
    safe_keys = ("message", "action", "link", "repo", "code")
    parts: list[str] = []
    for key in safe_keys:
        value = source.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        parts.append(f"{key}={value.strip()[:500]}")
    return "; ".join(parts)
