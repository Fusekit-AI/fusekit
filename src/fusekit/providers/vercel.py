"""Vercel project, env, deployment, and verification adapter."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.providers.http import JsonHttpClient
from fusekit.security.url import require_safe_url


@dataclass(frozen=True)
class VercelProvider:
    """Real Vercel adapter."""

    token: str
    api_base: str = "https://api.vercel.com"

    def _client(self) -> JsonHttpClient:
        return JsonHttpClient(self.api_base, self.token, auth_header="Bearer")

    def ensure_project(
        self,
        name: str,
        framework: str | None = None,
        git_repository: str | None = None,
        root_directory: str | None = None,
    ) -> dict[str, Any]:
        """Get or create a Vercel project."""

        try:
            project = self._client().request("GET", f"/v9/projects/{name}")
            return {
                "id": str(project["id"]),
                "name": str(project.get("name", name)),
                "created": False,
                "git_connected": bool(project.get("link") or project.get("gitRepository")),
            }
        except ProviderError:
            payload: dict[str, Any] = {"name": name}
            if framework:
                payload["framework"] = framework
            if git_repository:
                payload["gitRepository"] = {"type": "github", "repo": git_repository}
            if root_directory:
                payload["rootDirectory"] = root_directory
            created = self._client().request("POST", "/v11/projects", payload)
            return {
                "id": str(created["id"]),
                "name": str(created.get("name", name)),
                "created": True,
                "git_connected": bool(git_repository),
            }

    def put_env(
        self,
        project_id_or_name: str,
        key: str,
        value: str,
        target: tuple[str, ...],
    ) -> dict[str, Any]:
        """Create or replace an encrypted Vercel environment variable."""

        payload = {"key": key, "value": value, "type": "encrypted", "target": list(target)}
        existing = self._env_ids_by_key(project_id_or_name, key)
        replaced_existing = bool(existing)
        try:
            self._client().request("POST", f"/v10/projects/{project_id_or_name}/env", payload)
        except ProviderError:
            if not existing:
                raise
            self._delete_env_ids(project_id_or_name, existing)
            self._client().request("POST", f"/v10/projects/{project_id_or_name}/env", payload)
        else:
            if existing:
                self._delete_env_ids(project_id_or_name, existing)
        return {
            "project": project_id_or_name,
            "env": key,
            "target": ",".join(target),
            "replaced_existing": replaced_existing,
        }

    def create_git_deployment(
        self,
        project_name: str,
        git_repo_id: str | None = None,
        ref: str = "main",
        repo_type: str = "github",
        org: str | None = None,
        repo: str | None = None,
    ) -> dict[str, Any]:
        """Trigger a Vercel deployment from a connected git source."""

        if git_repo_id:
            git_source = {"type": repo_type, "repoId": git_repo_id, "ref": ref}
            source = {"repo_id": git_repo_id}
        elif org and repo:
            git_source = {"type": repo_type, "org": org, "repo": repo, "ref": ref}
            source = {"org": org, "repo": repo}
        else:
            raise ProviderError("Vercel git deployment requires a repo id or GitHub owner/repo.")
        payload = {
            "name": project_name,
            "target": "production",
            "gitSource": git_source,
        }
        response = self._client().request("POST", "/v13/deployments", payload)
        url = str(response.get("url", ""))
        return {
            "deployment_id": str(response.get("id", "")),
            "url": f"https://{url}" if url else "",
            "source": source,
        }

    def create_file_deployment(
        self,
        project_name: str,
        app_path: Path,
        *,
        framework: str | None = None,
    ) -> dict[str, Any]:
        """Trigger a Vercel deployment from a sanitized local file tree."""

        payload: dict[str, Any] = {
            "name": project_name,
            "project": project_name,
            "target": "production",
            "files": _deployment_files(app_path),
        }
        if framework:
            payload["projectSettings"] = {"framework": framework}
        response = self._client().request(
            "POST",
            "/v13/deployments?skipAutoDetectionConfirmation=1",
            payload,
        )
        url = str(response.get("url", ""))
        return {
            "deployment_id": str(response.get("id", "")),
            "url": f"https://{url}" if url else "",
            "source": {"type": "files"},
        }

    def delete_project(self, project_id_or_name: str) -> dict[str, Any]:
        """Delete a Vercel project created by FuseKit when rollback is requested."""

        self._client().request("DELETE", f"/v9/projects/{project_id_or_name}")
        return {"project": project_id_or_name, "deleted": True}

    def delete_env_by_key(self, project_id_or_name: str, key: str) -> dict[str, Any]:
        """Delete Vercel env vars matching a key."""

        deleted = self._delete_env_ids(
            project_id_or_name,
            self._env_ids_by_key(project_id_or_name, key),
        )
        return {"project": project_id_or_name, "env": key, "deleted_ids": deleted}

    def _env_ids_by_key(self, project_id_or_name: str, key: str) -> list[str]:
        env_response = self._client().request("GET", f"/v9/projects/{project_id_or_name}/env")
        envs = env_response.get("envs", env_response.get("data", []))
        ids: list[str] = []
        if isinstance(envs, list):
            for item in envs:
                if not isinstance(item, dict) or str(item.get("key", "")) != key:
                    continue
                env_id = str(item.get("id", ""))
                if not env_id:
                    continue
                ids.append(env_id)
        return ids

    def _delete_env_ids(self, project_id_or_name: str, env_ids: list[str]) -> list[str]:
        deleted: list[str] = []
        for env_id in env_ids:
            self._client().request("DELETE", f"/v9/projects/{project_id_or_name}/env/{env_id}")
            deleted.append(env_id)
        return deleted


def verify_live_url(url: str, expected_status: int = 200) -> dict[str, Any]:
    """Verify a live URL returns an acceptable HTTP status."""

    url = require_safe_url(url, label="Live URL", allow_http_loopback=True)
    request = Request(url, headers={"User-Agent": "FuseKit/0.1"})
    try:
        with urlopen(request, timeout=30) as response:  # nosec B310
            status = int(response.status)
    except URLError as exc:
        raise ProviderError(f"Live URL verification failed: {url}") from exc
    return {"url": url, "status": status, "ok": status == expected_status}


def _deployment_files(app_path: Path) -> list[dict[str, str]]:
    root = app_path.resolve()
    files: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _excluded_from_deployment(root, path):
            continue
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if rel == "vercel.json":
            data = _sanitized_vercel_json(data)
        files.append(
            {
                "file": rel,
                "data": base64.b64encode(data).decode("ascii"),
                "encoding": "base64",
            }
        )
    return files


def _excluded_from_deployment(root: Path, path: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    blocked_dirs = {".git", ".fusekit", "node_modules", ".venv", "__pycache__"}
    return any(part in blocked_dirs for part in rel_parts)


def _sanitized_vercel_json(data: bytes) -> bytes:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return data
    if not isinstance(raw, dict) or "domains" not in raw:
        return data
    cleaned = dict(raw)
    cleaned.pop("domains", None)
    return (json.dumps(cleaned, indent=2, sort_keys=True) + "\n").encode("utf-8")
