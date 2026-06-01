"""App source retrieval for public and private repositories."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from fusekit.errors import FuseKitError

GITHUB_API_BASE = "https://api.github.com"
GITHUB_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_HTTPS_RE = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?(?:[?#].*)?$"
)


class UrlOpener(Protocol):
    """Small protocol for testable HTTP opening."""

    def __call__(
        self,
        request: urllib.request.Request | str,
        timeout: float | None = None,
    ) -> Any:
        """Open a URL request."""


@dataclass(frozen=True)
class SourceFetchResult:
    """Non-secret source retrieval result."""

    source: str
    dest: Path
    provider: str
    repo: str
    default_branch: str
    auth_source: str
    private: bool

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize the result without secrets."""

        return {
            "source": self.source,
            "dest": str(self.dest),
            "provider": self.provider,
            "repo": self.repo,
            "default_branch": self.default_branch,
            "auth_source": self.auth_source,
            "private": self.private,
        }


def normalize_github_repo_slug(value: str) -> str:
    """Return an owner/repo slug from common GitHub URL forms."""

    raw = value.strip()
    if raw.startswith("git@github.com:"):
        raw = raw.removeprefix("git@github.com:").removesuffix(".git").strip("/")
        if GITHUB_REPO_SLUG_RE.match(raw):
            return raw
        raise FuseKitError("GitHub app source must be a root owner/repo URL or slug.")
    match = GITHUB_HTTPS_RE.match(raw)
    if match:
        return f"{match.group('owner')}/{match.group('repo')}"
    raw = raw.removesuffix(".git").strip("/")
    if GITHUB_REPO_SLUG_RE.match(raw):
        return raw
    raise FuseKitError("GitHub app source must be a root owner/repo URL or slug.")


def is_github_https_source(value: str) -> bool:
    """Return whether the value is a GitHub HTTPS repository URL."""

    return bool(GITHUB_HTTPS_RE.match(value.strip()))


def fetch_github_source_archive(
    source: str,
    dest: Path,
    *,
    token: str = "",
    opener: UrlOpener | None = None,
    timeout: float = 90.0,
) -> SourceFetchResult:
    """Download a GitHub repo archive into dest using public or token auth."""

    actual_opener = opener or cast(UrlOpener, urllib.request.urlopen)
    repo = normalize_github_repo_slug(source)
    default_branch = _github_default_branch(
        repo,
        token=token,
        opener=actual_opener,
        timeout=timeout,
    )
    branches = _branch_candidates(default_branch)
    last_error = ""
    with tempfile.TemporaryDirectory(prefix="fusekit-source-") as tmp:
        # Keep the archive outside the destination until the zip has been validated.
        archive = Path(tmp) / "source.zip"
        for branch in branches:
            try:
                _download(
                    _github_codeload_url(repo, branch),
                    archive,
                    token=token,
                    opener=actual_opener,
                    timeout=timeout,
                )
                _extract_single_root_zip(archive, dest)
                return SourceFetchResult(
                    source=source,
                    dest=dest,
                    provider="github",
                    repo=repo,
                    default_branch=branch,
                    auth_source="github-token" if token else "public-archive",
                    private=bool(token),
                )
            except (OSError, FuseKitError, urllib.error.URLError, zipfile.BadZipFile) as exc:
                last_error = _safe_error(exc)
        raise FuseKitError(f"Could not fetch GitHub app source {repo}: {last_error}")


def _github_default_branch(
    repo: str,
    *,
    token: str,
    opener: UrlOpener,
    timeout: float,
) -> str:
    request = _request(f"{GITHUB_API_BASE}/repos/{repo}", token=token)
    try:
        with opener(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        branch = str(payload.get("default_branch", "")).strip()
    except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError):
        branch = ""
    return branch or "main"


def _branch_candidates(default_branch: str) -> tuple[str, ...]:
    ordered = [default_branch, "main", "master"]
    return tuple(dict.fromkeys(branch for branch in ordered if branch))


def _github_codeload_url(repo: str, branch: str) -> str:
    quoted_repo = "/".join(urllib.parse.quote(part, safe="") for part in repo.split("/"))
    quoted_branch = urllib.parse.quote(branch, safe="")
    return f"https://codeload.github.com/{quoted_repo}/zip/refs/heads/{quoted_branch}"


def _download(
    url: str,
    archive: Path,
    *,
    token: str,
    opener: UrlOpener,
    timeout: float,
) -> None:
    request = _request(url, token=token)
    with opener(request, timeout=timeout) as response:
        status = int(getattr(response, "status", 200))
        if status >= 400:
            raise FuseKitError(f"GitHub returned HTTP {status}")
        archive.write_bytes(response.read())


def _request(url: str, *, token: str) -> urllib.request.Request:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "FuseKit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def _extract_single_root_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as zipped:
        names = [name for name in zipped.namelist() if name and not name.endswith("/")]
        if not names:
            raise FuseKitError("GitHub source archive was empty.")
        root = names[0].split("/", 1)[0]
        for name in names:
            if not name.startswith(f"{root}/"):
                raise FuseKitError("GitHub source archive has an unexpected layout.")
            target = (dest.parent / name).resolve()
            if not _within(target, dest.parent.resolve()):
                raise FuseKitError("GitHub source archive contains unsafe paths.")
        staging = dest.with_name(f"{dest.name}.download")
        if staging.exists():
            shutil.rmtree(staging)
        try:
            for member in zipped.infolist():
                if member.is_dir():
                    continue
                target = (staging / member.filename).resolve()
                if not _within(target, staging.resolve()):
                    raise FuseKitError("GitHub source archive contains unsafe paths.")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            extracted_root = staging / root
            if not extracted_root.exists():
                raise FuseKitError("GitHub source archive root was missing.")
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(str(extracted_root), str(dest))
        finally:
            shutil.rmtree(staging, ignore_errors=True)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_error(exc: BaseException) -> str:
    text = str(exc)
    if "Authorization" in text:
        return type(exc).__name__
    return text or type(exc).__name__


def token_from_env(*names: str) -> tuple[str, str]:
    """Return the first token found in environment variables."""

    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value, f"env:{name}"
    return "", ""
