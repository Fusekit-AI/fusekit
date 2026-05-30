"""Vercel project, env, deployment, and verification adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.providers.http import JsonHttpClient


@dataclass(frozen=True)
class VercelProvider:
    """Real Vercel adapter."""

    token: str
    api_base: str = "https://api.vercel.com"

    def _client(self) -> JsonHttpClient:
        return JsonHttpClient(self.api_base, self.token, auth_header="Bearer")

    def ensure_project(self, name: str, framework: str | None = None) -> dict[str, Any]:
        """Get or create a Vercel project."""

        try:
            project = self._client().request("GET", f"/v9/projects/{name}")
            return {
                "id": str(project["id"]),
                "name": str(project.get("name", name)),
                "created": False,
            }
        except ProviderError:
            payload: dict[str, Any] = {"name": name}
            if framework:
                payload["framework"] = framework
            created = self._client().request("POST", "/v9/projects", payload)
            return {
                "id": str(created["id"]),
                "name": str(created.get("name", name)),
                "created": True,
            }

    def put_env(
        self,
        project_id_or_name: str,
        key: str,
        value: str,
        target: tuple[str, ...],
    ) -> dict[str, Any]:
        """Create an encrypted Vercel environment variable."""

        payload = {"key": key, "value": value, "type": "encrypted", "target": list(target)}
        self._client().request("POST", f"/v10/projects/{project_id_or_name}/env", payload)
        return {"project": project_id_or_name, "env": key, "target": ",".join(target)}

    def create_git_deployment(
        self,
        project_name: str,
        git_repo_id: str,
        ref: str = "main",
        repo_type: str = "github",
    ) -> dict[str, Any]:
        """Trigger a Vercel deployment from a connected git source."""

        payload = {
            "name": project_name,
            "target": "production",
            "gitSource": {"type": repo_type, "repoId": git_repo_id, "ref": ref},
        }
        response = self._client().request("POST", "/v13/deployments", payload)
        url = str(response.get("url", ""))
        return {
            "deployment_id": str(response.get("id", "")),
            "url": f"https://{url}" if url else "",
        }

    def delete_project(self, project_id_or_name: str) -> dict[str, Any]:
        """Delete a Vercel project created by FuseKit when rollback is requested."""

        self._client().request("DELETE", f"/v9/projects/{project_id_or_name}")
        return {"project": project_id_or_name, "deleted": True}

    def delete_env_by_key(self, project_id_or_name: str, key: str) -> dict[str, Any]:
        """Delete Vercel env vars matching a key."""

        env_response = self._client().request("GET", f"/v9/projects/{project_id_or_name}/env")
        envs = env_response.get("envs", env_response.get("data", []))
        deleted: list[str] = []
        if isinstance(envs, list):
            for item in envs:
                if not isinstance(item, dict) or str(item.get("key", "")) != key:
                    continue
                env_id = str(item.get("id", ""))
                if not env_id:
                    continue
                self._client().request("DELETE", f"/v9/projects/{project_id_or_name}/env/{env_id}")
                deleted.append(env_id)
        return {"project": project_id_or_name, "env": key, "deleted_ids": deleted}


def verify_live_url(url: str, expected_status: int = 200) -> dict[str, Any]:
    """Verify a live URL returns an acceptable HTTP status."""

    request = Request(url, headers={"User-Agent": "FuseKit/0.1"})
    try:
        with urlopen(request, timeout=30) as response:
            status = int(response.status)
    except URLError as exc:
        raise ProviderError(f"Live URL verification failed: {url}") from exc
    return {"url": url, "status": status, "ok": status == expected_status}
