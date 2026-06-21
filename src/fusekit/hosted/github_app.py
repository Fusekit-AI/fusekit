"""GitHub App intake helpers for the hosted FuseKit launcher."""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from fusekit.errors import FuseKitError
from fusekit.hosted.launcher import (
    HOSTED_COMPLETION_EVIDENCE_KEYS,
    HOSTED_LAUNCH_PATH,
    HOSTED_PLAIN_LANGUAGE_JOURNEY,
    HOSTED_PROOF_REQUIREMENTS,
    HOSTED_REVERSAL_PATH,
    NO_TERMINAL_PROMISE,
    TRUST_STORY,
)

GITHUB_APP_JWT_ALGORITHM = "RS256"
GITHUB_APP_JWT_MAX_TTL_SECONDS = 600
GITHUB_APP_JWT_CLOCK_SKEW_SECONDS = 60
HOSTED_GITHUB_INTAKE_PERMISSIONS = (
    "Install the FuseKit GitHub App on one selected repository.",
    "Grant contents:read access for source scan and setup planning.",
    (
        "Approve any GitHub write capability separately through the visible plan "
        "before FuseKit mutates repository settings."
    ),
)
HOSTED_GITHUB_ALLOWED_TOKEN_PERMISSIONS = {
    "contents": "read",
    "metadata": "read",
}


class UrlOpener(Protocol):
    """Small opener protocol for testable GitHub HTTP calls."""

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> Any:
        """Open a URL request."""


@dataclass(frozen=True)
class GitHubAppConfig:
    """Non-secret hosted GitHub App configuration plus private signing key."""

    app_id: str
    app_slug: str
    private_key_pem: str
    api_url: str = "https://api.github.com"
    web_url: str = "https://github.com"

    def public_dict(self) -> dict[str, str]:
        """Return browser-safe GitHub App metadata."""

        return {
            "app_id": self.app_id,
            "app_slug": self.app_slug,
            "install_url": github_app_install_url(self, state=""),
        }


@dataclass(frozen=True)
class InstallationToken:
    """GitHub App installation token metadata without logging token values."""

    token: str
    expires_at: str
    permissions: Mapping[str, str]
    repository_selection: str

    def public_dict(self) -> dict[str, object]:
        """Return safe installation-token metadata."""

        return {
            "expires_at": self.expires_at,
            "permissions": dict(self.permissions),
            "repository_selection": self.repository_selection,
            "token_captured": bool(self.token),
        }


def require_hosted_installation_token_boundary(token: InstallationToken) -> None:
    """Fail closed unless a GitHub installation token matches hosted intake scope."""

    if token.repository_selection != "selected":
        raise FuseKitError("Hosted GitHub token must be scoped to selected repositories.")
    permissions = {str(key): str(value) for key, value in token.permissions.items()}
    if permissions.get("contents") != "read":
        raise FuseKitError("Hosted GitHub token must grant contents:read.")
    for key, value in permissions.items():
        if HOSTED_GITHUB_ALLOWED_TOKEN_PERMISSIONS.get(key) != value:
            raise FuseKitError("Hosted GitHub token includes unsupported permissions.")


def hosted_github_public_token_boundary() -> dict[str, object]:
    """Return browser-safe GitHub installation-token boundary metadata."""

    return {
        "repository_selection": "selected",
        "requested_token_permissions": {"contents": "read"},
        "accepted_token_permissions": dict(HOSTED_GITHUB_ALLOWED_TOKEN_PERMISSIONS),
        "rejects": [
            "all-repository installation tokens",
            "contents:write installation tokens",
            "unexpected GitHub write permissions",
        ],
    }


def github_app_install_url(config: GitHubAppConfig, *, state: str) -> str:
    """Return the hosted GitHub App installation URL."""

    base = config.web_url.rstrip("/")
    slug = urllib.parse.quote(config.app_slug.strip("/"), safe="")
    query = urllib.parse.urlencode({"state": state}) if state else ""
    suffix = f"?{query}" if query else ""
    return f"{base}/apps/{slug}/installations/new{suffix}"


def build_github_app_jwt(
    config: GitHubAppConfig,
    *,
    now: int | None = None,
    ttl_seconds: int = 540,
) -> str:
    """Build a GitHub App JWT signed with the app private key."""

    if ttl_seconds <= 0 or ttl_seconds > GITHUB_APP_JWT_MAX_TTL_SECONDS:
        raise FuseKitError("GitHub App JWT ttl must be between 1 and 600 seconds.")
    issued_at = int(time.time() if now is None else now) - GITHUB_APP_JWT_CLOCK_SKEW_SECONDS
    expires_at = issued_at + ttl_seconds
    header = {"alg": GITHUB_APP_JWT_ALGORITHM, "typ": "JWT"}
    payload = {"iat": issued_at, "exp": expires_at, "iss": str(config.app_id)}
    signing_input = (
        _base64url_json(header).encode("ascii")
        + b"."
        + _base64url_json(payload).encode("ascii")
    )
    private_key = serialization.load_pem_private_key(
        config.private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise FuseKitError("GitHub App private key must be an RSA key for RS256 signing.")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + _base64url(signature)


def exchange_installation_token(
    config: GitHubAppConfig,
    *,
    installation_id: int,
    repository_ids: tuple[int, ...] = (),
    permissions: Mapping[str, str] | None = None,
    opener: UrlOpener | None = None,
    timeout: float = 30.0,
    now: int | None = None,
) -> InstallationToken:
    """Exchange a GitHub App JWT for an installation token."""

    if installation_id <= 0:
        raise FuseKitError("GitHub App installation id must be positive.")
    body: dict[str, object] = {}
    if repository_ids:
        body["repository_ids"] = list(repository_ids)
    if permissions:
        body["permissions"] = dict(permissions)
    token = build_github_app_jwt(config, now=now)
    request = urllib.request.Request(
        f"{config.api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "FuseKit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    raw = _open_json(request, opener=opener, timeout=timeout)
    value = raw.get("token")
    expires_at = raw.get("expires_at")
    if not isinstance(value, str) or not value:
        raise FuseKitError("GitHub App installation response did not include a token.")
    if not isinstance(expires_at, str) or not expires_at:
        raise FuseKitError("GitHub App installation response did not include expiry.")
    raw_permissions = raw.get("permissions", {})
    parsed_permissions = (
        {str(key): str(value) for key, value in raw_permissions.items()}
        if isinstance(raw_permissions, dict)
        else {}
    )
    repository_selection = str(raw.get("repository_selection", "") or "")
    return InstallationToken(
        token=value,
        expires_at=expires_at,
        permissions=parsed_permissions,
        repository_selection=repository_selection,
    )


def list_installation_repositories(
    config: GitHubAppConfig,
    *,
    token: str,
    opener: UrlOpener | None = None,
    timeout: float = 30.0,
) -> tuple[dict[str, object], ...]:
    """List repositories accessible through an installation token."""

    if not token:
        raise FuseKitError("GitHub installation token is required.")
    request = urllib.request.Request(
        f"{config.api_url.rstrip('/')}/installation/repositories",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "FuseKit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    raw = _open_json(request, opener=opener, timeout=timeout)
    repositories = raw.get("repositories", [])
    if not isinstance(repositories, list):
        raise FuseKitError("GitHub installation repositories response was invalid.")
    return tuple(item for item in repositories if isinstance(item, dict))


def hosted_github_intake_contract(
    config: GitHubAppConfig,
    *,
    state: str = "",
    source_repository: str = "https://github.com/xpxpxp-coder/fusekit",
    license_name: str = "MIT",
    reviewable_entrypoint: str = "app.py",
) -> dict[str, object]:
    """Return public GitHub intake text for the hosted launcher."""

    return {
        "provider": "github",
        "route": "github-app",
        "install_url": github_app_install_url(config, state=state),
        "trust_story": list(TRUST_STORY),
        "no_terminal_promise": NO_TERMINAL_PROMISE,
        "launch_path": list(HOSTED_LAUNCH_PATH),
        "plain_language_journey": list(HOSTED_PLAIN_LANGUAGE_JOURNEY),
        "proof": list(HOSTED_PROOF_REQUIREMENTS),
        "proof_evidence_keys": list(HOSTED_COMPLETION_EVIDENCE_KEYS),
        "reversal": list(HOSTED_REVERSAL_PATH),
        "open_core": {
            "source_repository": source_repository,
            "license": license_name,
            "reviewable_entrypoint": reviewable_entrypoint,
        },
        "permissions": list(HOSTED_GITHUB_INTAKE_PERMISSIONS),
        "token_boundary": hosted_github_public_token_boundary(),
        "human_gates": [
            "GitHub sign-in",
            "MFA, passkey, CAPTCHA, SSO, or consent screens GitHub requires",
            "Repository selection for the app being launched",
        ],
        "secret_boundary": (
            "GitHub installation tokens stay server-side and are exchanged only for "
            "the selected launch job. They are never embedded in hosted pages."
        ),
    }


def _open_json(
    request: urllib.request.Request,
    *,
    opener: UrlOpener | None,
    timeout: float,
) -> dict[str, Any]:
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            body = response.read()
    except OSError as exc:
        raise FuseKitError("GitHub App request failed.") from exc
    if status >= 400:
        raise FuseKitError(f"GitHub App request returned HTTP {status}.")
    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("GitHub App response was not JSON.") from exc
    if not isinstance(raw, dict):
        raise FuseKitError("GitHub App response was not a JSON object.")
    return raw


def _base64url_json(value: Mapping[str, object]) -> str:
    return _base64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
