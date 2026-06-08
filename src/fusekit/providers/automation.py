"""Provider-pack setup executor."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from shutil import which
from typing import Any

from fusekit.audit import AuditLog, Receipt
from fusekit.crypto.secrets import token_urlsafe
from fusekit.crypto.sshkeys import generate_ed25519_keypair
from fusekit.errors import FuseKitError, ProviderError
from fusekit.manifest import DnsRecord, SetupManifest
from fusekit.policy import require_allowed
from fusekit.providers.capability_pack import ProviderCapabilityPack, SetupRecipe
from fusekit.providers.cloudflare import CloudflareDnsProvider
from fusekit.providers.github import GitHubProvider
from fusekit.providers.resend import ResendProvider
from fusekit.providers.secret_routing import select_app_env_secrets
from fusekit.providers.strategy import (
    StrategySignal,
    choose_provider_strategy,
    summarize_strategy_action,
)
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
    available_cli_tools: set[str] = field(default_factory=set)
    generated_dns_records: dict[str, list[DnsRecord]] = field(default_factory=dict)
    contract_health_checked: set[str] = field(default_factory=set)


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
        decision = choose_provider_strategy(pack, recipe, _strategy_signal(pack, context))
        strategy_payload = decision.to_dict()
        if not decision.executable:
            action = summarize_strategy_action(decision, pack)
            action.update({"kind": recipe.kind, "strategy_decision": strategy_payload})
            if not context.allow_incomplete and action["status"] != "needs_human_gate":
                raise FuseKitError(str(action["reason"]))
            results.append(action)
            if action["status"] == "needs_human_gate":
                break
            continue
        if decision.selected.kind == "api" and _recipe_may_touch_provider_api(recipe, context):
            try:
                _ensure_provider_contract_health(pack, context)
            except FuseKitError:
                if not context.allow_incomplete:
                    raise
                results.append(
                    {
                        "kind": recipe.kind,
                        "status": "skipped",
                        "reason": "provider contract health failed",
                        "strategy_decision": strategy_payload,
                    }
                )
                break
        result: dict[str, Any]
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
        result["strategy_decision"] = strategy_payload
        results.append(result)
        if result.get("status") == "needs_human_gate":
            break
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
        "resend-domain": _resend_domain,
        "resend-audience": _resend_audience,
    }


def _recipe_may_touch_provider_api(recipe: SetupRecipe, context: ProviderSetupContext) -> bool:
    """Return whether a recipe can call a provider API before it resolves."""

    if recipe.kind == "github-deploy-key":
        repo = _optional_input(context, "github_repo", recipe.target)
        return bool(repo) and f"github.{repo}.deploy_key.private" not in context.vault.records
    if recipe.kind == "github-repo-secrets":
        return bool(_optional_input(context, "github_repo", recipe.target)) and bool(
            _selected_secrets(recipe, context)
        )
    if recipe.kind == "vercel-project":
        return bool(_optional_input(context, "vercel_project", recipe.target))
    if recipe.kind == "vercel-env":
        return bool(
            context.inputs.get("vercel_project_id")
            or _optional_input(context, "vercel_project", recipe.target)
        ) and bool(_selected_secrets(recipe, context))
    if recipe.kind == "vercel-git-deployment":
        return bool(_optional_input(context, "vercel_project", recipe.target))
    if recipe.kind == "cloudflare-dns":
        return bool(context.manifest.domains)
    if recipe.kind == "resend-domain":
        return bool(context.inputs.get("resend_domain") or _default_domain(context))
    if recipe.kind == "resend-audience":
        return _needs_resend_audience(context)
    return recipe.kind != "vault-capture-env"


def _ensure_provider_contract_health(
    pack: ProviderCapabilityPack,
    context: ProviderSetupContext,
) -> None:
    """Check token-backed provider API health before setup mutates provider state."""

    provider = pack.provider.lower()
    if provider in context.contract_health_checked:
        return
    try:
        details = _provider_contract_health(provider, context)
    except (FuseKitError, ProviderError) as exc:
        failure = {
            "provider": provider,
            "status": "failed",
            "reason": str(exc)[:500],
        }
        context.audit.record("provider_pack.contract_health", failure)
        context.receipt.add_action(f"{provider}.contract_health", "failed", failure)
        raise FuseKitError(
            f"{pack.display_name} API contract health failed before setup: {exc}"
        ) from exc
    context.contract_health_checked.add(provider)
    context.audit.record("provider_pack.contract_health", details)
    context.receipt.add_action(f"{provider}.contract_health", "ok", details)


def _provider_contract_health(
    provider: str,
    context: ProviderSetupContext,
) -> dict[str, Any]:
    token_envs = {
        "github": "GITHUB_TOKEN",
        "vercel": "VERCEL_TOKEN",
        "cloudflare": "CLOUDFLARE_API_TOKEN",
        "dns": "CLOUDFLARE_API_TOKEN",
        "resend": "RESEND_API_KEY",
    }
    token_provider = "cloudflare" if provider == "dns" else provider
    env_name = token_envs.get(provider, "")
    if not env_name:
        return {
            "provider": provider,
            "ok": True,
            "checked": False,
            "reason": "no contract health hook",
        }
    token = _provider_token(context.vault, token_provider, env_name)
    adapter: Any
    if token_provider == "github":
        adapter = GitHubProvider(token)
    elif token_provider == "vercel":
        adapter = VercelProvider(token)
    elif token_provider == "cloudflare":
        adapter = CloudflareDnsProvider(token)
    elif token_provider == "resend":
        adapter = ResendProvider(token)
    else:
        return {
            "provider": provider,
            "ok": True,
            "checked": False,
            "reason": "no contract health hook",
        }
    health = getattr(adapter, "contract_health", None)
    if not callable(health):
        return {
            "provider": provider,
            "ok": True,
            "checked": False,
            "reason": "adapter does not expose contract health",
        }
    result = health()
    return {"provider": provider, "checked": True, **result}


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
    record_id = f"github.{repo}.deploy_key.private"
    if record_id in context.vault.records:
        result = {"repo": repo, "title": "FuseKit deploy key", "reused": True}
        context.audit.record("provider_pack.github.deploy_key", result)
        context.receipt.add_action("github.deploy_key", "ok", result)
        return {"kind": recipe.kind, "status": "ok", **result}
    token = _provider_token(context.vault, "github", "GITHUB_TOKEN")
    provider = GitHubProvider(token)
    key_pair = generate_ed25519_keypair(f"fusekit-{repo}")
    context.vault.put(
        record_id,
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
    try:
        project = provider.ensure_project(
            project_name,
            context.inputs.get("vercel_framework") or None,
            git_repository=_github_repo_slug_from_context(context),
            root_directory=context.inputs.get("vercel_root_directory") or None,
        )
    except ProviderError as exc:
        gate = _vercel_github_connection_gate(recipe, exc)
        if gate:
            context.audit.record("provider_pack.vercel.project_gate", gate)
            context.receipt.add_action("vercel.project", "needs_human_gate", gate)
            return gate
        raise
    context.inputs["vercel_project_id"] = str(project["id"])
    context.audit.record("provider_pack.vercel.project", project)
    context.receipt.add_action("vercel.project", "ok", project)
    return {"kind": recipe.kind, "status": "ok", **project}


def _vercel_github_connection_gate(
    recipe: SetupRecipe,
    exc: ProviderError,
) -> dict[str, Any] | None:
    message = str(exc)
    lowered = message.lower()
    if not (
        "login connection" in lowered
        or "connect your github account" in lowered
        or "failed to link" in lowered
    ):
        return None
    return {
        "kind": recipe.kind,
        "status": "needs_human_gate",
        "strategy": "browser_guided",
        "reason": (
            "Vercel needs GitHub connected as a login connection before its API can "
            "link the requested repository."
        ),
        "next_action": (
            "Click Open provider gate in VM, connect GitHub in Vercel Login Connections, "
            "approve only the FuseKit account/repo access Vercel requests, then click "
            "I finished this step."
        ),
        "resume_url": "https://vercel.com/account/settings/login-connections",
        "follow_steps": (
            "Use the live VM browser surface, not a local browser tab.",
            "Open Vercel Login Connections and choose GitHub.",
            (
                "Complete GitHub login, MFA, CAPTCHA, or consent only for the "
                "account/repo FuseKit named."
            ),
            (
                "Return to FuseKit and click I finished this step after Vercel confirms "
                "the connection."
            ),
        ),
    }


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
    try:
        deployment = provider.create_git_deployment(
            project_name,
            git_repo_id=git_repo_id,
            ref=context.inputs.get("vercel_git_ref", "main"),
            org=org or None,
            repo=repo or None,
        )
    except ProviderError as exc:
        if not _vercel_config_file_rejected(exc):
            raise
        deployment = provider.create_file_deployment(
            project_name,
            Path(context.manifest.app_path),
            framework=context.inputs.get("vercel_framework") or None,
        )
        deployment["fallback"] = "vercel-files"
    if deployment.get("url"):
        context.receipt.live_url = str(deployment["url"])
    context.audit.record("provider_pack.vercel.deployment", deployment)
    context.receipt.add_action("vercel.deployment", "ok", deployment)
    return {"kind": recipe.kind, "status": "ok", **deployment}


def _vercel_config_file_rejected(exc: ProviderError) -> bool:
    lowered = str(exc).lower()
    return "additional property" in lowered and "domains" in lowered


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
        records = domain.records + tuple(context.generated_dns_records.get(domain.domain, ()))
        changes = provider.propose(zone, records)
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
        verified = provider.verify(zone, records)
        apply_details = {"domain": domain.domain, "applied": applied, "verified": verified}
        context.audit.record("provider_pack.dns.applied", apply_details)
        context.receipt.add_action("dns.apply", "ok", {"domain": domain.domain, "applied": applied})
        context.receipt.add_action(
            "dns.verify", "ok", {"domain": domain.domain, "verified": verified}
        )
        summary.update({"applied": applied, "verified": verified})
        summaries.append(summary)
    return {"kind": "cloudflare-dns", "status": "ok", "domains": summaries}


def _resend_domain(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    del recipe
    domain = context.inputs.get("resend_domain") or _default_domain(context)
    if not domain:
        return {"kind": "resend-domain", "status": "skipped", "reason": "no domain"}
    token = _provider_token(context.vault, "resend", "RESEND_API_KEY")
    provider = ResendProvider(token)
    resend_domain = provider.ensure_domain(domain)
    context.generated_dns_records.setdefault(domain, [])
    for record in resend_domain.records:
        if record not in context.generated_dns_records[domain]:
            context.generated_dns_records[domain].append(record)
    from_email = context.inputs.get("resend_from_email") or f"rsvp@{domain}"
    context.secrets.setdefault("RESEND_FROM_EMAIL", from_email)
    context.vault.put(
        "provider.resend.resend_from_email",
        "provider_setting",
        "resend",
        "RESEND_FROM_EMAIL",
        context.secrets["RESEND_FROM_EMAIL"],
        {"domain": domain},
    )
    result = {
        "kind": "resend-domain",
        "status": "ok",
        "domain": resend_domain.name,
        "domain_id": resend_domain.id,
        "domain_status": resend_domain.status,
        "reused": resend_domain.reused,
        "dns_records": [
            {
                "name": record.name,
                "type": record.type,
                "value": record.value,
                "ttl": record.ttl,
                "priority": record.priority,
            }
            for record in resend_domain.records
        ],
    }
    context.inputs["resend_domain_id"] = resend_domain.id
    context.audit.record("provider_pack.resend.domain", result)
    context.receipt.add_action("resend.domain", "ok", result)
    return result


def _resend_audience(recipe: SetupRecipe, context: ProviderSetupContext) -> dict[str, Any]:
    del recipe
    if not _needs_resend_audience(context):
        return {"kind": "resend-audience", "status": "skipped", "reason": "not required"}
    token = _provider_token(context.vault, "resend", "RESEND_API_KEY")
    provider = ResendProvider(token)
    name = context.inputs.get("resend_audience_name") or f"{context.manifest.app_name} audience"
    audience = provider.ensure_audience(name)
    context.secrets["RESEND_AUDIENCE_ID"] = audience.id
    context.vault.put(
        "provider.resend.resend_audience_id",
        "provider_setting",
        "resend",
        "RESEND_AUDIENCE_ID",
        audience.id,
        {"name": audience.name},
    )
    result = {
        "kind": "resend-audience",
        "status": "ok",
        "audience_id": audience.id,
        "name": audience.name,
        "reused": audience.reused,
    }
    context.audit.record("provider_pack.resend.audience", result)
    context.receipt.add_action("resend.audience", "ok", result)
    return result


def _default_domain(context: ProviderSetupContext) -> str:
    if context.manifest.domains:
        return context.manifest.domains[0].domain.strip().lower().removeprefix("www.")
    return ""


def _needs_resend_audience(context: ProviderSetupContext) -> bool:
    if "RESEND_AUDIENCE_ID" in context.manifest.required_env:
        return True
    if "RESEND_AUDIENCE_ID" in context.secrets:
        return True
    return any(
        service.provider.lower() == "resend"
        and (
            "RESEND_AUDIENCE_ID" in service.secrets
            or "RESEND_AUDIENCE_ID" in service.env
            or "audience" in service.capabilities
        )
        for service in context.manifest.services
    )


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
    value = _optional_input(context, name, templated)
    if value:
        return value
    raise FuseKitError(f"Provider-pack setup input is required: {name}")


def _optional_input(
    context: ProviderSetupContext,
    name: str,
    templated: str = "",
) -> str:
    value = context.inputs.get(name, "")
    if value:
        return value
    if templated and not templated.startswith("${input:"):
        return templated
    return ""


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


def _provider_token_available(vault: Vault, provider: str, env_name: str) -> bool:
    import os

    if os.environ.get(env_name):
        return True
    for record_id in (
        f"provider.{provider}.token",
        f"provider.{provider}.{env_name.lower()}",
        env_name,
    ):
        try:
            vault.require(record_id)
            return True
        except FuseKitError:
            continue
    return False


def _strategy_signal(pack: ProviderCapabilityPack, context: ProviderSetupContext) -> StrategySignal:
    env_names = {
        "github": "GITHUB_TOKEN",
        "vercel": "VERCEL_TOKEN",
        "cloudflare": "CLOUDFLARE_API_TOKEN",
        "dns": "CLOUDFLARE_API_TOKEN",
        "resend": "RESEND_API_KEY",
        "plaid": "PLAID_SECRET",
    }
    provider = pack.provider.lower()
    env_name = env_names.get(provider, pack.handoff.token_env)
    cli_tools = context.available_cli_tools or _discover_cli_tools()
    return StrategySignal(
        token_available=_provider_token_available(context.vault, provider, env_name),
        cli_tools=frozenset(cli_tools),
        browser_available=True,
        human_gate_allowed=context.fusekit_gates in {"service-only", "explicit"},
        approve_dns=context.approve_dns,
    )


def _discover_cli_tools() -> set[str]:
    candidates = {"gh", "vercel", "wrangler"}
    return {tool for tool in candidates if which(tool)}


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
