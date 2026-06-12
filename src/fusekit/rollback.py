"""Rollback and start-over helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fusekit.detonation.cleanup import detonate
from fusekit.errors import FuseKitError
from fusekit.vault import Vault


@dataclass(frozen=True)
class RollbackAction:
    """One redacted rollback action."""

    action: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        """Serialize the action."""

        return {"action": self.action, "status": self.status, "detail": self.detail}


def plan_rollback(receipt_path: Path) -> list[RollbackAction]:
    """Build a rollback plan from a redacted receipt."""

    if not receipt_path.exists():
        return [RollbackAction("receipt.read", "missing", str(receipt_path))]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    actions: list[RollbackAction] = []
    seen: set[str] = set()
    for item in list(receipt.get("actions", [])):
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "unknown"))
        rollback_action = _planned_provider_rollback_action(action)
        if rollback_action and rollback_action not in seen:
            seen.add(rollback_action)
            actions.append(
                RollbackAction(
                    action=rollback_action,
                    status="planned",
                    detail="provider-native rollback/revoke/delete where supported",
                )
            )
    actions.append(
        RollbackAction(
            action="detonate.local_worker_state",
            status="planned",
            detail="remove local worker/tmp state while preserving encrypted vault and receipts",
        )
    )
    return actions


def _planned_provider_rollback_action(action: str) -> str:
    normalized = action.strip().lower()
    if normalized.startswith(("github.", "vercel.", "resend.", "webhook.")):
        return f"rollback.{normalized}"
    if normalized.startswith("dns."):
        return "rollback.cloudflare.dns"
    return ""


def plan_pack_rollback(pack_path: Path) -> list[RollbackAction]:
    """Build executable-intent rollback actions from a provider pack."""

    from fusekit.providers.capability_pack import load_provider_pack

    pack = load_provider_pack(pack_path)
    actions = [
        RollbackAction(
            action=f"rollback.{pack.provider}.{index}",
            status="planned",
            detail=step,
        )
        for index, step in enumerate(pack.rollback, start=1)
    ]
    if not actions:
        actions.append(
            RollbackAction(
                action=f"rollback.{pack.provider}",
                status="missing",
                detail="provider pack does not define rollback steps",
            )
        )
    return actions


def execute_native_rollback(
    receipt_path: Path,
    vault: Vault,
) -> list[RollbackAction]:
    """Execute provider-native rollback actions from a redacted receipt."""

    if not receipt_path.exists():
        return [RollbackAction("receipt.read", "missing", str(receipt_path))]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    executed: list[RollbackAction] = []
    dns_proposals: list[dict[str, Any]] = []
    for item in list(receipt.get("actions", [])):
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", ""))
        details = item.get("details", {})
        if not isinstance(details, dict):
            continue
        if action == "github.deploy_key":
            executed.append(_rollback_github_deploy_key(vault, details))
        elif action == "github.secret":
            executed.append(_rollback_github_secret(vault, details))
        elif action == "vercel.env":
            executed.append(_rollback_vercel_env(vault, details))
        elif action == "vercel.project" and str(details.get("created", "")).lower() == "true":
            executed.append(_rollback_vercel_project(vault, details))
        elif action == "dns.propose":
            changes = details.get("changes", [])
            if isinstance(changes, list):
                dns_proposals.extend(item for item in changes if isinstance(item, dict))
    if dns_proposals:
        executed.append(_rollback_cloudflare_dns(vault, dns_proposals))
    executed.append(
        RollbackAction(
            action="detonate.local_worker_state",
            status="planned",
            detail="run fusekit start-over or detonate after provider rollback completes",
        )
    )
    return executed


def _rollback_github_secret(vault: Vault, details: dict[str, Any]) -> RollbackAction:
    from fusekit.providers.github import GitHubProvider

    repo = str(details.get("repo", ""))
    secret = str(details.get("secret", ""))
    if not repo or not secret:
        return RollbackAction("rollback.github.secret", "skipped", "missing repo or secret")
    provider = GitHubProvider(_provider_token(vault, "github", "GITHUB_TOKEN"))
    provider.delete_repo_secret(repo, secret)
    return RollbackAction("rollback.github.secret", "done", f"{repo}:{secret}")


def _rollback_github_deploy_key(vault: Vault, details: dict[str, Any]) -> RollbackAction:
    from fusekit.providers.github import GitHubProvider

    repo = str(details.get("repo", ""))
    key_id = str(details.get("key_id", ""))
    if not repo or not key_id:
        return RollbackAction("rollback.github.deploy_key", "skipped", "missing repo or key id")
    GitHubProvider(_provider_token(vault, "github", "GITHUB_TOKEN")).delete_deploy_key(repo, key_id)
    return RollbackAction("rollback.github.deploy_key", "done", f"{repo}:{key_id}")


def _rollback_vercel_env(vault: Vault, details: dict[str, Any]) -> RollbackAction:
    from fusekit.providers.vercel import VercelProvider

    project = str(details.get("project", ""))
    env_name = str(details.get("env", ""))
    if not project or not env_name:
        return RollbackAction("rollback.vercel.env", "skipped", "missing project or env")
    VercelProvider(_provider_token(vault, "vercel", "VERCEL_TOKEN")).delete_env_by_key(
        project, env_name
    )
    return RollbackAction("rollback.vercel.env", "done", f"{project}:{env_name}")


def _rollback_vercel_project(vault: Vault, details: dict[str, Any]) -> RollbackAction:
    from fusekit.providers.vercel import VercelProvider

    project = str(details.get("id", details.get("name", "")))
    if not project:
        return RollbackAction("rollback.vercel.project", "skipped", "missing project id")
    VercelProvider(_provider_token(vault, "vercel", "VERCEL_TOKEN")).delete_project(project)
    return RollbackAction("rollback.vercel.project", "done", project)


def _rollback_cloudflare_dns(vault: Vault, proposals: list[dict[str, Any]]) -> RollbackAction:
    from fusekit.providers.cloudflare import CloudflareDnsProvider

    results = CloudflareDnsProvider(
        _provider_token(vault, "cloudflare", "CLOUDFLARE_API_TOKEN")
    ).rollback_proposals(proposals)
    return RollbackAction("rollback.cloudflare.dns", "done", f"{len(results)} change(s)")


def _provider_token(vault: Vault, provider: str, env_name: str) -> str:
    import os

    env_value = os.environ.get(env_name)
    if env_value:
        return env_value
    for record_id in (
        f"provider.{provider}.token",
        f"provider.{provider}.{env_name.lower()}",
        env_name,
    ):
        try:
            return vault.require(record_id).value
        except FuseKitError:
            continue
    raise FuseKitError(f"Provider token is required for rollback: {provider}")


def start_over(app_path: Path) -> dict[str, Any]:
    """Remove restartable FuseKit state while preserving encrypted artifacts."""

    fusekit_dir = app_path / ".fusekit"
    removed = detonate(
        [
            fusekit_dir / "worker",
            fusekit_dir / "tmp",
            fusekit_dir / "job.json",
            fusekit_dir / "runner_plan.json",
            fusekit_dir / "oci_workspace.json",
            fusekit_dir / "control-room.html",
            fusekit_dir / "remote-artifacts",
        ],
        preserve=[
            fusekit_dir / "fusekit.vault.json",
            fusekit_dir / "audit.jsonl",
            fusekit_dir / "setup_receipt.json",
            fusekit_dir / "setup_receipt.md",
        ],
        workspace_root=app_path,
    )
    return {"removed": removed, "preserved": "vault, audit log, and receipts"}
