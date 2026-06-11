"""URL safety helpers for outbound provider and runtime calls."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from fusekit.errors import FuseKitError


def require_safe_url(
    url: str,
    *,
    label: str = "URL",
    allow_http_loopback: bool = False,
) -> str:
    """Return a URL only when it uses an allowed network scheme and host."""

    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise FuseKitError(f"{label} must not include credentials.")
    if not parsed.hostname:
        raise FuseKitError(f"{label} must include a host.")
    if _is_unsafe_network_host(parsed.hostname) and not allow_http_loopback:
        raise FuseKitError(f"{label} must not target local or private network hosts.")
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and allow_http_loopback and _is_loopback(parsed.hostname):
        return url
    raise FuseKitError(f"{label} must use HTTPS.")


def require_relative_api_path(path: str) -> str:
    """Return a provider API path only when it is relative to the configured API host."""

    if not path.startswith("/") or "://" in path or path.startswith("//"):
        raise FuseKitError("Provider API path must be a relative absolute path.")
    return path


def _is_loopback(hostname: str) -> bool:
    host = hostname.strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_unsafe_network_host(hostname: str) -> bool:
    host = hostname.strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global
