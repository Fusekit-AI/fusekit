"""GitHub repository configuration adapter."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from nacl import encoding, public

from fusekit.crypto.sshkeys import SshKeyPair
from fusekit.providers.http import JsonHttpClient


@dataclass(frozen=True)
class GitHubProvider:
    """Real GitHub adapter for repo secrets and deploy keys."""

    token: str
    api_base: str = "https://api.github.com"

    def _client(self) -> JsonHttpClient:
        return JsonHttpClient(self.api_base, self.token, auth_header="Bearer")

    def contract_health(self) -> dict[str, Any]:
        """Check the token-backed GitHub API contract without mutating the repo."""

        self._client().request(
            "GET",
            "/rate_limit",
            headers={"X-GitHub-Api-Version": "2022-11-28"},
        )
        return {"route": "/rate_limit", "ok": True}

    def put_repo_secret(self, repo: str, name: str, value: str) -> dict[str, Any]:
        """Encrypt and store a GitHub Actions repo secret."""

        owner_repo = _repo_path(repo)
        key = self._client().request("GET", f"/repos/{owner_repo}/actions/secrets/public-key")
        public_key = str(key["key"])
        encrypted_value = _encrypt_for_github(public_key, value)
        self._client().request(
            "PUT",
            f"/repos/{owner_repo}/actions/secrets/{name}",
            {"encrypted_value": encrypted_value, "key_id": str(key["key_id"])},
            headers={"X-GitHub-Api-Version": "2022-11-28"},
        )
        return {"repo": owner_repo, "secret": name}

    def add_deploy_key(self, repo: str, title: str, key_pair: SshKeyPair) -> dict[str, Any]:
        """Add a read-only deploy key to a repository."""

        owner_repo = _repo_path(repo)
        response = self._client().request(
            "POST",
            f"/repos/{owner_repo}/keys",
            {"title": title, "key": key_pair.public_key, "read_only": True},
            headers={"X-GitHub-Api-Version": "2022-11-28"},
        )
        return {"repo": owner_repo, "key_id": str(response.get("id", "")), "title": title}

    def delete_repo_secret(self, repo: str, name: str) -> dict[str, Any]:
        """Delete a GitHub Actions repo secret created or managed by FuseKit."""

        owner_repo = _repo_path(repo)
        self._client().request(
            "DELETE",
            f"/repos/{owner_repo}/actions/secrets/{name}",
            headers={"X-GitHub-Api-Version": "2022-11-28"},
        )
        return {"repo": owner_repo, "secret": name, "deleted": True}

    def delete_deploy_key(self, repo: str, key_id: str) -> dict[str, Any]:
        """Delete a deploy key by id."""

        owner_repo = _repo_path(repo)
        self._client().request(
            "DELETE",
            f"/repos/{owner_repo}/keys/{key_id}",
            headers={"X-GitHub-Api-Version": "2022-11-28"},
        )
        return {"repo": owner_repo, "key_id": key_id, "deleted": True}


def _encrypt_for_github(public_key_b64: str, value: str) -> str:
    public_key = public.PublicKey(base64.b64decode(public_key_b64), encoding.RawEncoder)
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def _repo_path(repo: str) -> str:
    stripped = repo.strip().removeprefix("https://github.com/").removesuffix(".git")
    if stripped.count("/") != 1:
        raise ValueError("GitHub repo must be owner/name.")
    return stripped
