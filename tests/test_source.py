from __future__ import annotations

import io
import json
import zipfile
from urllib.request import Request

import pytest

from fusekit.errors import FuseKitError
from fusekit.source import fetch_github_source_archive, normalize_github_repo_slug


class Response(io.BytesIO):
    def __init__(self, payload: bytes, status: int = 200) -> None:
        super().__init__(payload)
        self.status = status

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _zip_bytes(*, root: str = "repo-main", name: str = "package.json") -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(f"{root}/{name}", "{}")
    return payload.getvalue()


def test_fetch_private_github_source_uses_token_without_putting_it_in_url(tmp_path) -> None:
    seen: list[Request | str] = []

    def opener(request: Request | str, timeout: float | None = None) -> Response:
        seen.append(request)
        url = request.full_url if isinstance(request, Request) else request
        if url == "https://api.github.com/repos/owner/private":
            assert isinstance(request, Request)
            assert request.headers["Authorization"] == "Bearer ghp_secret_token"
            return Response(json.dumps({"default_branch": "trunk"}).encode())
        if url == "https://codeload.github.com/owner/private/zip/refs/heads/trunk":
            assert isinstance(request, Request)
            assert request.headers["Authorization"] == "Bearer ghp_secret_token"
            return Response(_zip_bytes(root="private-trunk", name="index.js"))
        raise AssertionError(url)

    result = fetch_github_source_archive(
        "https://github.com/owner/private.git",
        tmp_path / "app",
        token="ghp_secret_token",
        opener=opener,
    )

    assert result.repo == "owner/private"
    assert result.default_branch == "trunk"
    assert result.private is True
    assert result.auth_source == "github-token"
    assert (tmp_path / "app" / "index.js").exists()
    assert all("ghp_secret_token" not in str(item) for item in seen)


def test_fetch_public_github_source_tries_main_archive(tmp_path) -> None:
    def opener(request: Request | str, timeout: float | None = None) -> Response:
        url = request.full_url if isinstance(request, Request) else request
        if url == "https://api.github.com/repos/owner/public":
            assert isinstance(request, Request)
            assert "Authorization" not in request.headers
            return Response(json.dumps({"default_branch": "main"}).encode())
        assert url == "https://codeload.github.com/owner/public/zip/refs/heads/main"
        return Response(_zip_bytes(root="public-main"))

    result = fetch_github_source_archive(
        "https://github.com/owner/public.git",
        tmp_path / "app",
        opener=opener,
    )

    assert result.private is False
    assert result.auth_source == "public-archive"
    assert (tmp_path / "app" / "package.json").exists()


def test_fetch_public_github_source_uses_default_branch_from_api(tmp_path) -> None:
    def opener(request: Request | str, timeout: float | None = None) -> Response:
        url = request.full_url if isinstance(request, Request) else request
        if url == "https://api.github.com/repos/owner/public":
            return Response(json.dumps({"default_branch": "release"}).encode())
        assert url == "https://codeload.github.com/owner/public/zip/refs/heads/release"
        return Response(_zip_bytes(root="public-release", name="app.js"))

    result = fetch_github_source_archive(
        "https://github.com/owner/public.git",
        tmp_path / "app",
        opener=opener,
    )

    assert result.default_branch == "release"
    assert (tmp_path / "app" / "app.js").exists()


def test_fetch_github_source_rejects_unsafe_archive_paths(tmp_path) -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("repo-main/package.json", "{}")
        archive.writestr("../escape.txt", "bad")

    def opener(request: Request | str, timeout: float | None = None) -> Response:
        return Response(payload.getvalue())

    with pytest.raises(FuseKitError, match="unexpected layout"):
        fetch_github_source_archive(
            "https://github.com/owner/public.git",
            tmp_path / "app",
            opener=opener,
        )


def test_normalize_github_repo_slug_accepts_common_forms() -> None:
    assert normalize_github_repo_slug("https://github.com/owner/repo.git") == "owner/repo"
    assert normalize_github_repo_slug("git@github.com:owner/repo.git") == "owner/repo"
    assert normalize_github_repo_slug("owner/repo") == "owner/repo"
