from __future__ import annotations

from typing import Any

from fusekit.providers.vercel import VercelProvider


def test_vercel_project_creation_connects_github_repo(monkeypatch) -> None:
    requests: list[tuple[str, str, dict[str, Any] | None]] = []

    class FakeClient:
        def __init__(self, base_url: str, token: str, auth_header: str = "Bearer") -> None:
            self.base_url = base_url
            self.token = token
            self.auth_header = auth_header

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
            headers: dict[str, str] | None = None,
        ) -> dict[str, Any]:
            del headers
            requests.append((method, path, payload))
            if method == "GET":
                from fusekit.errors import ProviderError

                raise ProviderError("not found")
            return {"id": "prj_123", "name": "moonlite-rsvp"}

    monkeypatch.setattr("fusekit.providers.vercel.JsonHttpClient", FakeClient)

    result = VercelProvider("token").ensure_project(
        "moonlite-rsvp",
        framework="nextjs",
        git_repository="owner/moonlite-rsvp",
        root_directory="apps/web",
    )

    assert result == {
        "id": "prj_123",
        "name": "moonlite-rsvp",
        "created": True,
        "git_connected": True,
    }
    assert requests[-1] == (
        "POST",
        "/v11/projects",
        {
            "name": "moonlite-rsvp",
            "framework": "nextjs",
            "gitRepository": {"type": "github", "repo": "owner/moonlite-rsvp"},
            "rootDirectory": "apps/web",
        },
    )


def test_vercel_git_deployment_can_use_owner_repo_without_repo_id(monkeypatch) -> None:
    requests: list[tuple[str, str, dict[str, Any] | None]] = []

    class FakeClient:
        def __init__(self, base_url: str, token: str, auth_header: str = "Bearer") -> None:
            self.base_url = base_url
            self.token = token
            self.auth_header = auth_header

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
            headers: dict[str, str] | None = None,
        ) -> dict[str, Any]:
            del headers
            requests.append((method, path, payload))
            return {"id": "dpl_123", "url": "moonlite-rsvp.vercel.app"}

    monkeypatch.setattr("fusekit.providers.vercel.JsonHttpClient", FakeClient)

    result = VercelProvider("token").create_git_deployment(
        "moonlite-rsvp",
        ref="main",
        org="owner",
        repo="moonlite-rsvp",
    )

    assert result == {
        "deployment_id": "dpl_123",
        "url": "https://moonlite-rsvp.vercel.app",
        "source": {"org": "owner", "repo": "moonlite-rsvp"},
    }
    assert requests == [
        (
            "POST",
            "/v13/deployments",
            {
                "name": "moonlite-rsvp",
                "target": "production",
                "gitSource": {
                    "type": "github",
                    "org": "owner",
                    "repo": "moonlite-rsvp",
                    "ref": "main",
                },
            },
        )
    ]
