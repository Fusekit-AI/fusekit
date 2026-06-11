from __future__ import annotations

import pytest

from fusekit.errors import FuseKitError
from fusekit.security.url import require_relative_api_path, require_safe_url


def test_require_safe_url_allows_https_and_loopback_http_only() -> None:
    assert require_safe_url("https://api.example.test/v1") == "https://api.example.test/v1"
    assert (
        require_safe_url("http://127.0.0.1:11434/v1", allow_http_loopback=True)
        == "http://127.0.0.1:11434/v1"
    )

    with pytest.raises(FuseKitError, match="HTTPS"):
        require_safe_url("http://api.example.test/v1", allow_http_loopback=True)
    with pytest.raises(FuseKitError, match="credentials"):
        require_safe_url("https://user:secret@api.example.test/v1")
    with pytest.raises(FuseKitError, match="host"):
        require_safe_url("file:///tmp/secret")


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8765/admin",
        "https://localhost:8765/admin",
        "https://10.0.0.5/provider",
        "https://169.254.169.254/latest/meta-data",
    ],
)
def test_require_safe_url_rejects_local_or_private_hosts_by_default(url: str) -> None:
    with pytest.raises(FuseKitError, match="local or private network hosts"):
        require_safe_url(url)


def test_require_safe_url_allows_loopback_when_explicitly_requested() -> None:
    assert (
        require_safe_url("https://127.0.0.1:3000/health", allow_http_loopback=True)
        == "https://127.0.0.1:3000/health"
    )


def test_require_relative_api_path_rejects_absolute_or_scheme_paths() -> None:
    assert require_relative_api_path("/v1/projects") == "/v1/projects"

    with pytest.raises(FuseKitError, match="relative"):
        require_relative_api_path("https://evil.example.test/v1")
    with pytest.raises(FuseKitError, match="relative"):
        require_relative_api_path("//evil.example.test/v1")
    with pytest.raises(FuseKitError, match="relative"):
        require_relative_api_path("v1/projects")
