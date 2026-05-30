"""Provider-pack setup executor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from fusekit.audit import AuditLog, Receipt
from fusekit.crypto.secrets import token_urlsafe
from fusekit.crypto.sshkeys import generate_ed25519_keypair
from fusekit.errors import FuseKitError
from fusekit.manifest import SetupManifest
from fusekit.policy import require_allowed
from fusekit.providers.capability_pack import ProviderCapabilityPack, SetupRecipe
from fusekit.providers.cloudflare import CloudflareDnsProvider
from fusekit.providers.github import GitHubProvider
from fusekit.providers.secret_routing import select_app_env_secrets
from fusekit.providers.vercel import VercelProvider
from fusekit.vault import Vault


@dataclass
class ProviderSetupContext:
    """Runtime inputs available to provider-pack setup recipes."""

    manifest: SetupManifest
    vault: Vault
    audit: AuditLog
    receipt: Receipt
    secrets: dict[str, str]
    provider_names: set[str] = field(default_factory=set)
    inputs: dict[str, str] = field(default_factory=dict)
    approve_dns: bool = False
    allow_incomplete: bool = False
    fusekit_gates: str = "service-only"


SetupHandler = Callable[[SetupRecipe, ProviderSetupContext], dict[str, Any]]


def run_provider_pack_setup(
    pack: ProviderCapabilityPack,
    context: ProviderSetupContext,
) -> dict[str, Any]:
    """Execute setup recipes from a provider capability pack."""

    results: list[dict[str, Any]] = []
    handlers = setup_handler_registry()
    for recipe in pack.setup:
        if recipe.when and not context.inputs.get(recipe.when):
            results.append({"kind": recipe.kind, "status": "skipped", "reason": recipe.when})
            continue
        try:
            handler = handlers.get(recipe.kind)
            if handler is None:
                if recipe.optional:
                    result = {"kind": recipe.kind, "target": recipe.target, "status": "skipped"}
                else:
                    raise FuseKitError(f"Unsupported provider-pack setup recipe: {recipe.kind}")
            else:
                result = handler(recipe, context)
        except FuseKitError:
            if not context.allow_incomplete:
                raise
            result = {"kind": recipe.kind, "status": "skipped", "reason": "incomplete"}
        results.append(result)
    return {"provider": pack.provider, "setup": results}


def setup_handler_registry() -> dict[str, SetupHandler]:
    """Return capability recipe handlers."""

    return {
        "vault-capture-env": _vault_capture_env,
        "github-deploy-key": _github_deploy_key,
        "github-repo-secrets": _github_repo_secrets,
        "vercel-project": _vercel_project,
        "vercel-env": _vercel_env,
        "vercel-git-deployment": _vercel_git_deployment,
        "cloudflare-dns": _cloudflare_dns_recipe,
    }


def _vault_capture_env(
    recipe: SetupRecipe,
    context: ProviderSetupContext,
) -> dict[str, Any]:
    captured: list[str] = []
    names = _secret_names(recipe, context)
    for name in names:
        value = context.secrets.get(name)
        if not value:
            continue
        context.vault.put(
            f"provider.{_provider_for_recipe(context, name)}.{name.lower()}",
            "provider_secret",
            _provider_for_recipe(context, name),
            name,
            value,
            {"source": "setup-context"},
        )
        captured.append(name)
    return {"kind": recipe.kind, "status": "ok", "captured": captured}


def _provider_for_recipe(context: ProviderSetupContext, name: str) -> str:
    prefix = name.split("_", 1)[0].lower()
    return prefix if prefix in context.provider_names else "fusekit"


def _github_deploy_key(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    repo = _required_input(context, "github_repo", recipe.target)
    token = _provider_token(context.vault, "github", "GITHUB_TOKEN")
    provider = GitHubProvider(token)
    key_pair = generate_ed25519_keypair(f"fusekit-{repo}")
    context.vault.put(
        f"github.{repo}.deploy_key.private",
        "ssh_private_key",
        "github",
        "GitHub deploy key private half",
        key_pair.private_key,
        {"repo": repo, "fingerprint": key_pair.fingerprint},
    )
    result = provider.add_deploy_key(repo, "FuseKit deploy key", key_pair)
    context.audit.record("provider_pack.github.deploy_key", result)
    context.receipt.add_action("github.deploy_key", "ok", result)
    return {"kind": recipe.kind, "status": "ok", **result}


def _github_repo_secrets(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    repo = _required_input(context, "github_repo", recipe.target)
    token = _provider_token(context.vault, "github", "GITHUB_TOKEN")
    provider = GitHubProvider(token)
    configured: list[str] = []
    for name, value in _selected_secrets(recipe, context).items():
        result = provider.put_repo_secret(repo, name, value)
        context.audit.record("provider_pack.github.secret", result)
        context.receipt.add_action("github.secret", "ok", result)
        configured.append(name)
    return {"kind": recipe.kind, "status": "ok", "repo": repo, "secrets": configured}


def _vercel_project(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    project_name = _required_input(context, "vercel_project", recipe.target)
    token = _provider_token(context.vault, "vercel", "VERCEL_TOKEN")
    provider = VercelProvider(token)
    project = provider.ensure_project(
        project_name,
        context.inputs.get("vercel_framework") or None,
        git_repository=_github_repo_slug_from_context(context),
        root_directory=context.inputs.get("vercel_root_directory") or None,
    )
    context.inputs["vercel_project_id"] = str(project["id"])
    context.audit.record("provider_pack.vercel.project", project)
    context.receipt.add_action("vercel.project", "ok", project)
    return {"kind": recipe.kind, "status": "ok", **project}


def _vercel_env(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    project = context.inputs.get("vercel_project_id") or _required_input(
        context, "vercel_project", recipe.target
    )
    token = _provider_token(context.vault, "vercel", "VERCEL_TOKEN")
    provider = VercelProvider(token)
    configured: list[str] = []
    for name, value in _selected_secrets(recipe, context).items():
        result = provider.put_env(project, name, value, ("production", "preview", "development"))
        context.audit.record("provider_pack.vercel.env", result)
        context.receipt.add_action("vercel.env", "ok", result)
        configured.append(name)
    return {"kind": recipe.kind, "status": "ok", "project": project, "env": configured}


def _vercel_git_deployment(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    project_name = _required_input(context, "vercel_project", recipe.target)
    git_repo_id = context.inputs.get("vercel_git_repo_id") or None
    github_repo = _github_repo_slug_from_context(context)
    if not git_repo_id and not github_repo:
        result = {
            "kind": recipe.kind,
            "status": "skipped",
            "reason": "missing GitHub repo source",
        }
        context.audit.record("provider_pack.vercel.deployment", result)
        context.receipt.add_action("vercel.deployment", "skipped", result)
        return result
    token = _provider_token(context.vault, "vercel", "VERCEL_TOKEN")
    provider = VercelProvider(token)
    org, repo = _split_repo_slug(github_repo) if github_repo else ("", "")
    deployment = provider.create_git_deployment(
        project_name,
        git_repo_id=git_repo_id,
        ref=context.inputs.get("vercel_git_ref", "main"),
        org=org or None,
        repo=repo or None,
    )
    if deployment.get("url"):
        context.receipt.live_url = str(deployment["url"])
    context.audit.record("provider_pack.vercel.deployment", deployment)
    context.receipt.add_action("vercel.deployment", "ok", deployment)
    return {"kind": recipe.kind, "status": "ok", **deployment}


def _github_repo_slug_from_context(context: ProviderSetupContext) -> str:
    for key in ("github_repo", "app_source"):
        value = context.inputs.get(key, "")
        slug = _normalize_github_repo_slug(value)
        if slug:
            return slug
    return ""


def _normalize_github_repo_slug(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    raw = raw.removesuffix(".git")
    if raw.startswith("git@github.com:"):
        raw = raw.removeprefix("git@github.com:")
    elif "github.com/" in raw:
        raw = raw.split("github.com/", 1)[1]
    raw = raw.strip("/")
    parts = raw.split("/")
    if len(parts) >= 2 and all(parts[:2]):
        return f"{parts[0]}/{parts[1]}"
    return ""


def _split_repo_slug(slug: str) -> tuple[str, str]:
    owner, repo = slug.split("/", 1)
    return owner, repo


def _cloudflare_dns_recipe(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    del recipe
    return _cloudflare_dns(context)


def _cloudflare_dns(context: ProviderSetupContext) -> dict[str, Any]:
    if not context.manifest.domains:
        return {"kind": "cloudflare-dns", "status": "skipped", "reason": "no domains"}
    token = _provider_token(context.vault, "cloudflare", "CLOUDFLARE_API_TOKEN")
    provider = CloudflareDnsProvider(token)
    summaries: list[dict[str, Any]] = []
    for domain in context.manifest.domains:
        zone = context.inputs.get("dns_zone") or domain.domain
        changes = provider.propose(zone, domain.records)
        proposal = [change.to_dict() for change in changes]
        details = {"domain": domain.domain, "changes": proposal}
        context.audit.record("provider_pack.dns.proposed", details)
        context.receipt.add_action("dns.propose", "ok", details)
        summary: dict[str, Any] = {"domain": domain.domain, "proposed": proposal}
        if not context.approve_dns:
            context.receipt.add_action(
                "dns.apply",
                "skipped",
                {"domain": domain.domain, "reason": "dns scope not granted upfront"},
            )
            summaries.append(summary)
            continue
        require_allowed("dns.apply", approved=True)
        applied = provider.apply(changes)
        verified = provider.verify(zone, domain.records)
        apply_details = {"domain": domain.domain, "applied": applied, "verified": verified}
        context.audit.record("provider_pack.dns.applied", apply_details)
        context.receipt.add_action("dns.apply", "ok", {"domain": domain.domain, "applied": applied})
        context.receipt.add_action(
            "dns.verify", "ok", {"domain": domain.domain, "verified": verified}
        )
        summary.update({"applied": applied, "verified": verified})
        summaries.append(summary)
    return {"kind": "cloudflare-dns", "status": "ok", "domains": summaries}


def _selected_secrets(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, str]:
    names = _secret_names(recipe, context)
    if names == ("*",):
        return select_app_env_secrets(context.secrets, provider_names=context.provider_names)
    return {name: context.secrets[name] for name in names if name in context.secrets}


def _secret_names(recipe: SetupRecipe, context: ProviderSetupContext) -> tuple[str, ...]:
    if recipe.secret_refs:
        return recipe.secret_refs
    return tuple(name.strip() for name in recipe.target.split(",") if name.strip()) or tuple(
        context.secrets
    )


def _required_input(
    context: ProviderSetupContext,
    name: str,
    templated: str = "",
) -> str:
    value = context.inputs.get(name, "")
    if value:
        return value
    if templated and not templated.startswith("${input:"):
        return templated
    raise FuseKitError(f"Provider-pack setup input is required: {name}")


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
    raise FuseKitError(f"Provider token is required for {provider}: {env_name}")


def ensure_webhook_secrets(manifest: SetupManifest, context: ProviderSetupContext) -> None:
    """Generate webhook secrets as pack-runtime setup context."""

    for webhook in manifest.webhooks:
        context.secrets.setdefault(webhook.secret_name, token_urlsafe())
        context.vault.put(
            f"webhook.{webhook.name}.secret",
            "webhook_secret",
            "fusekit",
            webhook.secret_name,
            context.secrets[webhook.secret_name],
            {"webhook": webhook.name},
        )
        details = {"name": webhook.name, "secret_name": webhook.secret_name}
        context.audit.record("webhook.secret.generated", details)
        context.receipt.add_action("webhook.secret", "ok", details)
