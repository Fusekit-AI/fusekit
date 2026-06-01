from __future__ import annotations

from typing import Any

from fusekit.errors import ProviderError
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


def test_vercel_put_env_replaces_existing_key_before_create(monkeypatch) -> None:
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
                return {"envs": [{"id": "env_1", "key": "RESEND_API_KEY"}]}
            return {}

    monkeypatch.setattr("fusekit.providers.vercel.JsonHttpClient", FakeClient)

    result = VercelProvider("token").put_env(
        "moonlite-rsvp",
        "RESEND_API_KEY",
        "hidden",
        ("production", "preview"),
    )

    assert result["replaced_existing"] is True
    assert requests == [
        ("GET", "/v9/projects/moonlite-rsvp/env", None),
        (
            "POST",
            "/v10/projects/moonlite-rsvp/env",
            {
                "key": "RESEND_API_KEY",
                "value": "hidden",
                "type": "encrypted",
                "target": ["production", "preview"],
            },
        ),
        ("DELETE", "/v9/projects/moonlite-rsvp/env/env_1", None),
    ]


def test_vercel_put_env_deletes_existing_key_only_when_create_needs_repair(
    monkeypatch,
) -> None:
    requests: list[tuple[str, str, dict[str, Any] | None]] = []
    post_attempts = 0

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
            nonlocal post_attempts
            del headers
            requests.append((method, path, payload))
            if method == "GET":
                return {"envs": [{"id": "env_1", "key": "RESEND_API_KEY"}]}
            if method == "POST":
                post_attempts += 1
                if post_attempts == 1:
                    raise ProviderError("duplicate")
            return {}

    monkeypatch.setattr("fusekit.providers.vercel.JsonHttpClient", FakeClient)

    result = VercelProvider("token").put_env(
        "moonlite-rsvp",
        "RESEND_API_KEY",
        "hidden",
        ("production",),
    )

    assert result["replaced_existing"] is True
    assert requests == [
        ("GET", "/v9/projects/moonlite-rsvp/env", None),
        (
            "POST",
            "/v10/projects/moonlite-rsvp/env",
            {
                "key": "RESEND_API_KEY",
                "value": "hidden",
                "type": "encrypted",
                "target": ["production"],
            },
        ),
        ("DELETE", "/v9/projects/moonlite-rsvp/env/env_1", None),
        (
            "POST",
            "/v10/projects/moonlite-rsvp/env",
            {
                "key": "RESEND_API_KEY",
                "value": "hidden",
                "type": "encrypted",
                "target": ["production"],
            },
        ),
    ]
