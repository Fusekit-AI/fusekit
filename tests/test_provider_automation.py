from __future__ import annotations

import json

from fusekit.audit import AuditLog, Receipt, assert_no_secret_text
from fusekit.errors import ProviderError
from fusekit.manifest import DnsRecord, DomainRequirement, SetupManifest
from fusekit.providers.automation import ProviderSetupContext, run_provider_pack_setup
from fusekit.providers.capability_pack import synthesize_provider_pack
from fusekit.vault import Vault


def test_github_pack_setup_runs_through_capability_executor(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, str]] = []

    class FakeGitHubProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def add_deploy_key(self, repo, title, key_pair):  # type: ignore[no-untyped-def]
            calls.append(("deploy_key", repo))
            return {"repo": repo, "key_id": "1", "title": title}

        def put_repo_secret(self, repo, name, value):  # type: ignore[no-untyped-def]
            calls.append((name, repo))
            assert value == "webhook-secret-value"
            return {"repo": repo, "secret": name}

    monkeypatch.setattr("fusekit.providers.automation.GitHubProvider", FakeGitHubProvider)
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "GitHub token",
        "test-github-token-hidden",
    )
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app"),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={
            "WEBHOOK_SECRET": "webhook-secret-value",
            "GITHUB_TOKEN": "must-not-be-routed",
            "VERCEL_TOKEN": "must-not-be-routed-either",
        },
        provider_names={"github", "vercel"},
        inputs={"github_repo": "owner/repo"},
    )
    pack = synthesize_provider_pack("github", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert ("deploy_key", "owner/repo") in calls
    assert ("WEBHOOK_SECRET", "owner/repo") in calls
    assert ("GITHUB_TOKEN", "owner/repo") not in calls
    assert ("VERCEL_TOKEN", "owner/repo") not in calls
    assert any(record.kind == "ssh_private_key" for record in vault.records.values())
    public = json.dumps(result) + json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["webhook-secret-value", "test-github-token-hidden"])


def test_github_pack_setup_reuses_existing_deploy_key_on_resume(monkeypatch, tmp_path) -> None:
    calls: list[str] = []

    class FakeGitHubProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def add_deploy_key(self, repo, title, key_pair):  # type: ignore[no-untyped-def]
            calls.append(repo)
            return {"repo": repo, "key_id": "1", "title": title}

        def put_repo_secret(self, repo, name, value):  # type: ignore[no-untyped-def]
            return {"repo": repo, "secret": name}

    monkeypatch.setattr("fusekit.providers.automation.GitHubProvider", FakeGitHubProvider)
    vault = Vault.empty()
    vault.put("provider.github.token", "provider_token", "github", "GitHub token", "token")
    vault.put(
        "github.owner/repo.deploy_key.private",
        "ssh_private_key",
        "github",
        "GitHub deploy key private half",
        "private-key-hidden",
        {"repo": "owner/repo"},
    )
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app"),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"github"},
        inputs={"github_repo": "owner/repo"},
    )
    pack = synthesize_provider_pack("github", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert calls == []
    reused = [item for item in result["setup"] if item["kind"] == "github-deploy-key"]
    assert reused[0]["reused"] is True


def test_github_pack_setup_reports_browser_strategy_when_token_missing(tmp_path) -> None:
    vault = Vault.empty()
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app"),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"github"},
        inputs={"github_repo": "owner/repo"},
        allow_incomplete=True,
    )
    pack = synthesize_provider_pack("github", tmp_path)

    result = run_provider_pack_setup(pack, context)

    deploy_key = next(item for item in result["setup"] if item["kind"] == "github-deploy-key")
    assert deploy_key["status"] == "needs_human_gate"
    assert deploy_key["strategy"] == "browser_guided"
    assert deploy_key["strategy_decision"]["selected"]["kind"] == "browser_guided"
    assert "login/MFA/CAPTCHA/consent" in deploy_key["next_action"]


def test_vercel_pack_connects_project_and_deploys_from_github_repo(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    class FakeVercelProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def ensure_project(
            self,
            name: str,
            framework: str | None = None,
            git_repository: str | None = None,
            root_directory: str | None = None,
        ) -> dict[str, object]:
            calls.append(
                (
                    "project",
                    {
                        "name": name,
                        "framework": framework or "",
                        "git_repository": git_repository or "",
                        "root_directory": root_directory or "",
                    },
                )
            )
            return {"id": "prj_123", "name": name, "created": True, "git_connected": True}

        def put_env(
            self,
            project_id_or_name: str,
            key: str,
            value: str,
            target: tuple[str, ...],
        ) -> dict[str, object]:
            calls.append(
                (
                    "env",
                    {
                        "project": project_id_or_name,
                        "key": key,
                        "value": value,
                        "target": ",".join(target),
                    },
                )
            )
            return {"project": project_id_or_name, "env": key}

        def create_git_deployment(
            self,
            project_name: str,
            git_repo_id: str | None = None,
            ref: str = "main",
            repo_type: str = "github",
            org: str | None = None,
            repo: str | None = None,
        ) -> dict[str, object]:
            calls.append(
                (
                    "deployment",
                    {
                        "project": project_name,
                        "git_repo_id": git_repo_id or "",
                        "ref": ref,
                        "repo_type": repo_type,
                        "org": org or "",
                        "repo": repo or "",
                    },
                )
            )
            return {
                "deployment_id": "dpl_123",
                "url": "https://moonlite-rsvp.vercel.app",
                "source": {"org": org, "repo": repo},
            }

    monkeypatch.setattr("fusekit.providers.automation.VercelProvider", FakeVercelProvider)
    vault = Vault.empty()
    vault.put(
        "provider.vercel.token",
        "provider_token",
        "vercel",
        "Vercel token",
        "test-vercel-token-hidden",
    )
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app"),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={
            "WEBHOOK_SECRET": "webhook-secret-value",
            "VERCEL_TOKEN": "must-not-be-routed",
        },
        provider_names={"vercel"},
        inputs={
            "github_repo": "owner/moonlite-rsvp",
            "vercel_project": "moonlite-rsvp",
            "vercel_framework": "nextjs",
            "vercel_git_ref": "main",
        },
    )
    pack = synthesize_provider_pack("vercel", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert ("project", {
        "name": "moonlite-rsvp",
        "framework": "nextjs",
        "git_repository": "owner/moonlite-rsvp",
        "root_directory": "",
    }) in calls
    assert ("deployment", {
        "project": "moonlite-rsvp",
        "git_repo_id": "",
        "ref": "main",
        "repo_type": "github",
        "org": "owner",
        "repo": "moonlite-rsvp",
    }) in calls
    assert context.receipt.live_url == "https://moonlite-rsvp.vercel.app"
    public = json.dumps(result) + json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["webhook-secret-value", "test-vercel-token-hidden"])


def test_vercel_pack_falls_back_to_file_deployment_when_git_config_is_rejected(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    calls: list[tuple[str, dict[str, str]]] = []

    class FakeVercelProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def ensure_project(
            self,
            name: str,
            framework: str | None = None,
            git_repository: str | None = None,
            root_directory: str | None = None,
        ) -> dict[str, object]:
            calls.append(
                (
                    "project",
                    {
                        "name": name,
                        "framework": framework or "",
                        "git_repository": git_repository or "",
                        "root_directory": root_directory or "",
                    },
                )
            )
            return {"id": "prj_123", "name": name, "created": False, "git_connected": True}

        def put_env(
            self,
            project_id_or_name: str,
            key: str,
            value: str,
            target: tuple[str, ...],
        ) -> dict[str, object]:
            calls.append(
                (
                    "env",
                    {
                        "project": project_id_or_name,
                        "key": key,
                        "value": value,
                        "target": ",".join(target),
                    },
                )
            )
            return {"project": project_id_or_name, "env": key}

        def create_git_deployment(
            self,
            project_name: str,
            git_repo_id: str | None = None,
            ref: str = "main",
            repo_type: str = "github",
            org: str | None = None,
            repo: str | None = None,
        ) -> dict[str, object]:
            del project_name, git_repo_id, ref, repo_type, org, repo
            calls.append(("git_deployment", {}))
            raise ProviderError(
                "POST /v13/deployments failed with HTTP 400: "
                "message=Invalid request: should NOT have additional property 'domains'."
            )

        def create_file_deployment(
            self,
            project_name: str,
            app_path,
            *,
            framework: str | None = None,
        ) -> dict[str, object]:
            calls.append(
                (
                    "file_deployment",
                    {
                        "project": project_name,
                        "app_path": str(app_path),
                        "framework": framework or "",
                    },
                )
            )
            return {
                "deployment_id": "dpl_file",
                "url": "https://moonlite-rsvp.vercel.app",
                "source": {"type": "files"},
            }

    monkeypatch.setattr("fusekit.providers.automation.VercelProvider", FakeVercelProvider)
    vault = Vault.empty()
    vault.put(
        "provider.vercel.token",
        "provider_token",
        "vercel",
        "Vercel token",
        "test-vercel-token-hidden",
    )
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app", app_path=str(app)),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={"WEBHOOK_SECRET": "webhook-secret-value"},
        provider_names={"vercel"},
        inputs={
            "github_repo": "owner/moonlite-rsvp",
            "vercel_project": "moonlite-rsvp",
            "vercel_framework": "vite",
        },
    )
    pack = synthesize_provider_pack("vercel", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert ("git_deployment", {}) in calls
    assert ("file_deployment", {
        "project": "moonlite-rsvp",
        "app_path": str(app),
        "framework": "vite",
    }) in calls
    deployment = next(item for item in result["setup"] if item["kind"] == "vercel-git-deployment")
    assert deployment["source"] == {"type": "files"}
    assert deployment["fallback"] == "vercel-files"
    assert context.receipt.live_url == "https://moonlite-rsvp.vercel.app"


def test_vercel_pack_pauses_for_github_login_connection_gate(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    class FakeVercelProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def ensure_project(
            self,
            name: str,
            framework: str | None = None,
            git_repository: str | None = None,
            root_directory: str | None = None,
        ) -> dict[str, object]:
            del name, framework, git_repository, root_directory
            calls.append("project")
            raise ProviderError(
                "POST /v11/projects failed with HTTP 400: "
                "message=Failed to link owner/app.; action=Add a Login Connection"
            )

        def put_env(
            self,
            project_id_or_name: str,
            key: str,
            value: str,
            target: tuple[str, ...],
        ) -> dict[str, object]:
            del project_id_or_name, key, value, target
            calls.append("env")
            return {}

    monkeypatch.setattr("fusekit.providers.automation.VercelProvider", FakeVercelProvider)
    vault = Vault.empty()
    vault.put(
        "provider.vercel.token",
        "provider_token",
        "vercel",
        "Vercel token",
        "test-vercel-token-hidden",
    )
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="app"),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={"WEBHOOK_SECRET": "webhook-secret-value"},
        provider_names={"vercel"},
        inputs={
            "github_repo": "owner/app",
            "vercel_project": "app",
            "vercel_framework": "nextjs",
        },
    )
    pack = synthesize_provider_pack("vercel", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert calls == ["project"]
    assert result["setup"] == [
        {
            "kind": "vercel-project",
            "status": "needs_human_gate",
            "strategy": "browser_guided",
            "reason": (
                "Vercel needs GitHub connected as a login connection before its API can "
                "link the requested repository."
            ),
            "next_action": (
                "Open Vercel Login Connections in the VM browser, connect GitHub, approve "
                "only the FuseKit account/repo access Vercel requests, then resume FuseKit."
            ),
            "resume_url": "https://vercel.com/account/settings/login-connections",
            "follow_steps": (
                "Use the live VM browser surface, not a local browser tab.",
                "Open Vercel Login Connections and choose GitHub.",
                (
                    "Complete GitHub login, MFA, CAPTCHA, or consent only for the "
                    "account/repo FuseKit named."
                ),
                "Return to FuseKit and mark the gate finished after Vercel confirms the connection.",
            ),
            "strategy_decision": result["setup"][0]["strategy_decision"],
        }
    ]


def test_cloudflare_dns_proposes_without_apply_when_scope_missing(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    class FakeCloudflareDnsProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def propose(self, zone: str, records: tuple[DnsRecord, ...]):  # type: ignore[no-untyped-def]
            calls.append(f"propose:{zone}:{len(records)}")
            return [
                type(
                    "Change",
                    (),
                    {
                        "to_dict": lambda self: {
                            "zone_id": "zone-1",
                            "record": {"name": records[0].name, "type": records[0].type},
                            "rollback": {"delete_created_record": True},
                        }
                    },
                )()
            ]

        def apply(self, changes):  # type: ignore[no-untyped-def]
            calls.append("apply")
            return []

        def verify(self, zone, records):  # type: ignore[no-untyped-def]
            calls.append("verify")
            return []

    monkeypatch.setattr(
        "fusekit.providers.automation.CloudflareDnsProvider",
        FakeCloudflareDnsProvider,
    )
    vault = Vault.empty()
    vault.put("provider.cloudflare.token", "provider_token", "cloudflare", "token", "hidden")
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(
            app_name="app",
            domains=(
                DomainRequirement(
                    domain="moonlite.rsvp",
                    provider="cloudflare",
                    records=(DnsRecord(name="moonlite.rsvp", type="A", value="76.76.21.21"),),
                ),
            ),
        ),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={},
        provider_names={"cloudflare"},
        approve_dns=False,
    )
    pack = synthesize_provider_pack("cloudflare", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert calls == ["propose:moonlite.rsvp:1"]
    assert result["setup"][0]["domains"][0]["proposed"][0]["zone_id"] == "zone-1"
    actions = receipt.to_dict()["actions"]
    assert any(action["action"] == "dns.propose" and action["status"] == "ok" for action in actions)
    assert any(
        action["action"] == "dns.apply" and action["status"] == "skipped"
        for action in actions
    )


def test_cloudflare_dns_apply_requires_explicit_dns_scope(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    class FakeCloudflareDnsProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def propose(self, zone: str, records: tuple[DnsRecord, ...]):  # type: ignore[no-untyped-def]
            calls.append(f"propose:{zone}:{len(records)}")
            return [
                type(
                    "Change",
                    (),
                    {
                        "to_dict": lambda self: {
                            "zone_id": "zone-1",
                            "record": {"name": records[0].name, "type": records[0].type},
                            "rollback": {"delete_created_record": True},
                        }
                    },
                )()
            ]

        def apply(self, changes):  # type: ignore[no-untyped-def]
            calls.append(f"apply:{len(changes)}")
            return [{"id": "record-1", "name": "moonlite.rsvp"}]

        def verify(self, zone, records):  # type: ignore[no-untyped-def]
            calls.append(f"verify:{zone}:{len(records)}")
            return [{"name": "moonlite.rsvp", "ok": True}]

    monkeypatch.setattr(
        "fusekit.providers.automation.CloudflareDnsProvider",
        FakeCloudflareDnsProvider,
    )
    vault = Vault.empty()
    vault.put("provider.cloudflare.token", "provider_token", "cloudflare", "token", "hidden")
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(
            app_name="app",
            domains=(
                DomainRequirement(
                    domain="moonlite.rsvp",
                    provider="cloudflare",
                    records=(DnsRecord(name="moonlite.rsvp", type="A", value="76.76.21.21"),),
                ),
            ),
        ),
        vault=vault,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=receipt,
        secrets={},
        provider_names={"cloudflare"},
        approve_dns=True,
    )
    pack = synthesize_provider_pack("cloudflare", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert calls == ["propose:moonlite.rsvp:1", "apply:1", "verify:moonlite.rsvp:1"]
    assert result["setup"][0]["domains"][0]["applied"] == [
        {"id": "record-1", "name": "moonlite.rsvp"}
    ]
    actions = receipt.to_dict()["actions"]
    assert any(action["action"] == "dns.apply" and action["status"] == "ok" for action in actions)
    assert any(action["action"] == "dns.verify" and action["status"] == "ok" for action in actions)
