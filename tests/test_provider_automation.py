from __future__ import annotations

import json

from fusekit.audit import AuditLog, Receipt, assert_no_secret_text
from fusekit.manifest import SetupManifest
from fusekit.providers.automation import ProviderSetupContext, run_provider_pack_setup
from fusekit.providers.capability_pack import synthesize_provider_pack
from fusekit.vault import Vault


def test_github_pack_setup_runs_through_generic_executor(monkeypatch, tmp_path) -> None:
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
    receipt = Receipt(app_name="demo")
    context = ProviderSetupContext(
        manifest=SetupManifest(app_name="demo"),
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
