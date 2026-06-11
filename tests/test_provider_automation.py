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
    assert "follow the GitHub steps below" in deploy_key["next_action"]
    assert "create or reveal the GitHub API token" in deploy_key["next_action"]
    assert "fine-grained token named FuseKit setup" in " ".join(deploy_key["follow_steps"])
    assert "Resource owner" in " ".join(deploy_key["follow_steps"])
    assert "visible gate is finished" in deploy_key["resume_hint"]


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
                "Click Open provider gate in VM, connect GitHub in Vercel Login Connections, "
                "approve only the FuseKit account/repo access Vercel requests, then click "
                "the visible I finished this step button in the control room."
            ),
            "resume_url": "https://vercel.com/account/settings/login-connections",
            "follow_steps": (
                "Use the live VM browser, not a local browser tab.",
                "Open Vercel Login Connections and choose GitHub.",
                (
                    "Complete GitHub login, MFA, CAPTCHA, or consent only for the "
                    "account/repo FuseKit named."
                ),
                (
                    "After Vercel confirms the connection, click the visible I finished "
                    "this step button in the control room."
                ),
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


def test_resend_pack_creates_domain_audience_and_feeds_dns(monkeypatch, tmp_path) -> None:
    calls: list[str] = []

    class FakeResendProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def ensure_domain(self, domain: str, *, region: str = "us-east-1"):  # type: ignore[no-untyped-def]
            calls.append(f"resend-domain:{domain}:{region}:{self.token}")
            return type(
                "Domain",
                (),
                {
                    "id": "domain-1",
                    "name": domain,
                    "status": "pending",
                    "region": region,
                    "reused": False,
                    "records": (
                        DnsRecord(
                            name=f"send.{domain}",
                            type="MX",
                            value="feedback-smtp.us-east-1.amazonses.com",
                            priority=10,
                        ),
                    ),
                },
            )()

        def ensure_audience(self, name: str):  # type: ignore[no-untyped-def]
            calls.append(f"resend-audience:{name}")
            return type(
                "Audience",
                (),
                {"id": "audience-1", "name": name, "reused": False},
            )()

    monkeypatch.setattr("fusekit.providers.automation.ResendProvider", FakeResendProvider)
    vault = Vault.empty()
    receipt = Receipt(app_name="app")
    context = ProviderSetupContext(
        manifest=SetupManifest(
            app_name="Moonlite RSVP",
            required_env=("RESEND_AUDIENCE_ID", "RESEND_FROM_EMAIL"),
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
        secrets={"RESEND_API_KEY": "resend-key-hidden"},
        provider_names={"resend"},
    )
    pack = synthesize_provider_pack("resend", tmp_path)

    result = run_provider_pack_setup(pack, context)

    assert calls == [
        "resend-domain:moonlite.rsvp:us-east-1:resend-key-hidden",
        "resend-audience:Moonlite RSVP audience",
    ]
    assert [item["kind"] for item in result["setup"]] == [
        "vault-capture-env",
        "resend-domain",
        "resend-audience",
    ]
    assert context.generated_dns_records["moonlite.rsvp"][0].priority == 10
    assert context.secrets["RESEND_FROM_EMAIL"] == "rsvp@moonlite.rsvp"
    assert context.secrets["RESEND_AUDIENCE_ID"] == "audience-1"
    assert vault.require("provider.resend.resend_audience_id").value == "audience-1"
    assert vault.require("provider.resend.resend_from_email").value == "rsvp@moonlite.rsvp"
    resend_domain = next(item for item in result["setup"] if item["kind"] == "resend-domain")
    resend_audience = next(item for item in result["setup"] if item["kind"] == "resend-audience")
    assert resend_domain["generated_env"] == ["RESEND_FROM_EMAIL"]
    assert resend_domain["region"] == "us-east-1"
    assert resend_domain["requested_region"] == "us-east-1"
    assert resend_audience["generated_env"] == ["RESEND_AUDIENCE_ID"]
    receipt_actions = receipt.to_dict()["actions"]
    assert any(
        action["action"] == "resend.domain"
        and action["details"]["generated_env"] == ["RESEND_FROM_EMAIL"]
        for action in receipt_actions
    )
    assert any(
        action["action"] == "resend.audience"
        and action["details"]["generated_env"] == ["RESEND_AUDIENCE_ID"]
        for action in receipt_actions
    )
    public = json.dumps(result) + json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["resend-key-hidden"])


def test_provider_setup_checks_contract_health_before_api_mutation(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    class FakeVercelProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def contract_health(self) -> dict[str, object]:
            calls.append("health")
            return {"route": "/v2/user", "ok": True}

        def ensure_project(
            self,
            name: str,
            framework: str | None = None,
            git_repository: str | None = None,
            root_directory: str | None = None,
        ) -> dict[str, object]:
            del framework, git_repository, root_directory
            calls.append("project")
            return {"id": "prj_123", "name": name, "created": False, "git_connected": True}

        def put_env(
            self,
            project_id_or_name: str,
            key: str,
            value: str,
            target: tuple[str, ...],
        ) -> dict[str, object]:
            del value, target
            calls.append(f"env:{key}")
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
            calls.append("deployment")
            return {"deployment_id": "dpl_123", "url": "https://app.vercel.app"}

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

    assert calls[0] == "health"
    assert calls.count("health") == 1
    assert "project" in calls
    assert "vercel" in context.contract_health_checked
    actions = receipt.to_dict()["actions"]
    assert any(
        action["action"] == "vercel.contract_health" and action["status"] == "ok"
        for action in actions
    )
    public = json.dumps(result) + json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["webhook-secret-value", "test-vercel-token-hidden"])


def test_provider_setup_contract_health_failure_stops_before_mutation(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    class FakeVercelProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def contract_health(self) -> dict[str, object]:
            calls.append("health")
            raise ProviderError("GET /v2/user failed with HTTP 401: message=invalid token")

        def ensure_project(
            self,
            name: str,
            framework: str | None = None,
            git_repository: str | None = None,
            root_directory: str | None = None,
        ) -> dict[str, object]:
            del name, framework, git_repository, root_directory
            calls.append("project")
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

    assert calls == ["health"]
    assert "vercel" not in context.contract_health_checked
    gate = result["setup"][0]
    assert gate["kind"] == "vercel-project"
    assert gate["status"] == "needs_human_gate"
    assert gate["strategy"] == "browser_guided"
    assert gate["resume_url"] == "https://vercel.com/account/tokens"
    assert gate["target"] == "VERCEL_TOKEN"
    assert gate["contract_health_failed"] is True
    assert "follow the Vercel steps below" in gate["next_action"]
    assert "create or reveal a fresh Vercel API token" in gate["next_action"]
    assert "Capture VERCEL_TOKEN from VM clipboard" in gate["next_action"]
    assert "fresh VERCEL_TOKEN" not in gate["next_action"]
    assert "matching Capture from VM clipboard button" not in gate["next_action"]
    follow_steps = " ".join(gate["follow_steps"])
    assert "read-only API health check" in follow_steps
    assert "Capture VERCEL_TOKEN from VM clipboard" in follow_steps
    assert "invalid token" not in json.dumps(gate)
    actions = receipt.to_dict()["actions"]
    assert any(
        action["action"] == "vercel.contract_health" and action["status"] == "failed"
        for action in actions
    )
    public = json.dumps(result) + json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["webhook-secret-value", "test-vercel-token-hidden"])


def test_cloudflare_dns_includes_provider_generated_records(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    seen_records: list[DnsRecord] = []

    class FakeCloudflareDnsProvider:
        def __init__(self, token: str) -> None:
            self.token = token

        def propose(self, zone: str, records: tuple[DnsRecord, ...]):  # type: ignore[no-untyped-def]
            calls.append(f"propose:{zone}:{len(records)}")
            seen_records.extend(records)
            return []

        def apply(self, changes):  # type: ignore[no-untyped-def]
            calls.append(f"apply:{len(changes)}")
            return []

        def verify(self, zone, records):  # type: ignore[no-untyped-def]
            calls.append(f"verify:{zone}:{len(records)}")
            return []

    monkeypatch.setattr(
        "fusekit.providers.automation.CloudflareDnsProvider",
        FakeCloudflareDnsProvider,
    )
    vault = Vault.empty()
    vault.put("provider.cloudflare.token", "provider_token", "cloudflare", "token", "hidden")
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
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"cloudflare"},
        approve_dns=True,
        generated_dns_records={
            "moonlite.rsvp": [
                DnsRecord(
                    name="send.moonlite.rsvp",
                    type="MX",
                    value="feedback-smtp.us-east-1.amazonses.com",
                    priority=10,
                )
            ]
        },
    )
    pack = synthesize_provider_pack("cloudflare", tmp_path)

    run_provider_pack_setup(pack, context)

    assert calls == ["propose:moonlite.rsvp:2", "apply:0", "verify:moonlite.rsvp:2"]
    assert ("send.moonlite.rsvp", "MX", 10) in {
        (record.name, record.type, record.priority) for record in seen_records
    }
