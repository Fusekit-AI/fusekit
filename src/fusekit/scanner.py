"""Repository scanner for generated web apps."""

from __future__ import annotations

import json
import re
from pathlib import Path

from fusekit.manifest import (
    DnsRecord,
    DomainRequirement,
    ServiceRequirement,
    SetupManifest,
    WebhookRequirement,
)
from fusekit.providers.capability_pack import (
    ProviderEvidence,
    infer_provider_candidates,
    pack_default_path,
)

ENV_PATTERNS = (
    re.compile(r"process\.env\.([A-Z][A-Z0-9_]+)"),
    re.compile(r"process\.env\[['\"]([A-Z][A-Z0-9_]+)['\"]\]"),
    re.compile(r"import\.meta\.env\.([A-Z][A-Z0-9_]+)"),
    re.compile(r"os\.environ\[['\"]([A-Z][A-Z0-9_]+)['\"]\]"),
    re.compile(r"os\.getenv\(['\"]([A-Z][A-Z0-9_]+)['\"]\)"),
    re.compile(r"Deno\.env\.get\(['\"]([A-Z][A-Z0-9_]+)['\"]\)"),
)
DOMAIN_PATTERN = re.compile(r"https?://([A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[:/'\"]|$)")
TEXT_EXTENSIONS = {
    ".env",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".rb",
    ".php",
    ".md",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "node_modules",
    ".next",
    ".nuxt",
    ".fusekit",
}
SKIP_FILES = {
    "bun.lock",
    "bun.lockb",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
ROUTE_ROOTS = {"api", "app", "pages", "routes"}
ROUTE_FILENAMES = {"route", "page", "+server", "index"}
CONFIG_FILES = (
    "vercel.json",
    "next.config.js",
    "next.config.mjs",
    "vite.config.ts",
    "vite.config.js",
    "wrangler.toml",
    "netlify.toml",
    "package.json",
)


def scan_repo(path: Path) -> SetupManifest:
    """Scan a repo and infer a setup manifest."""

    root = path.resolve()
    app_name = root.name
    package = _read_package_json(root)
    if isinstance(package.get("name"), str):
        app_name = str(package["name"])

    text_index = _text_index(root)
    env_names = sorted(_find_env_names(text_index))
    route_paths = _find_routes(root)
    webhook_routes = _find_webhook_routes(route_paths, text_index)
    oauth_callbacks = _find_oauth_callbacks(route_paths, env_names, text_index)
    domains = _find_domains(root, text_index)
    providers = _detect_providers(root, package, env_names)
    services = list(providers)
    webhooks = _webhook_requirements(webhook_routes, env_names)
    if "WEBHOOK_SECRET" not in env_names and webhooks:
        env_names.append("WEBHOOK_SECRET")

    if not any(service.provider == "github" for service in services):
        services.append(
            ServiceRequirement(
                provider="github",
                kind="repository",
                name="source-repo",
                capabilities=("repo_secrets", "deploy_keys", "capability_pack", "verify"),
                secrets=("GITHUB_TOKEN",),
                settings={
                    "capability_pack": str(pack_default_path(root, "github").relative_to(root)),
                    "setup_lane": "pack-runtime",
                },
            )
        )
    if not any(service.provider == "vercel" for service in services):
        services.append(
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web-deployment",
                capabilities=("project", "env", "deploy", "verify", "capability_pack"),
                secrets=("VERCEL_TOKEN",),
                settings={
                    "capability_pack": str(pack_default_path(root, "vercel").relative_to(root)),
                    "setup_lane": "pack-runtime",
                },
            )
        )

    return SetupManifest(
        app_name=app_name,
        app_path=str(root),
        required_env=tuple(sorted(set(env_names))),
        services=tuple(services),
        domains=tuple(domains),
        webhooks=tuple(webhooks),
        approvals=("dns.apply", "billing.change", "payment.change", "destructive.infra"),
        metadata={
            "scanner": "fusekit-v2",
            "routes": ",".join(route_paths),
            "webhook_routes": ",".join(webhook_routes),
            "oauth_callbacks": ",".join(oauth_callbacks),
            "domain_candidates": ",".join(domain.domain for domain in domains),
            "config_files": ",".join(_config_files(root)),
        },
    )


def _read_package_json(root: Path) -> dict[str, object]:
    path = root / "package.json"
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _text_index(root: Path) -> dict[Path, str]:
    index: dict[Path, str] = {}
    for file_path in _walk_text_files(root):
        try:
            index[file_path] = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    return index


def _find_env_names(text_index: dict[Path, str]) -> set[str]:
    names: set[str] = set()
    for text in text_index.values():
        for pattern in ENV_PATTERNS:
            names.update(match.group(1) for match in pattern.finditer(text))
    return names


def _find_routes(root: Path) -> tuple[str, ...]:
    routes: set[str] = set()
    for file_path in _walk_text_files(root):
        route = _route_from_path(root, file_path)
        if route:
            routes.add(route)
    return tuple(sorted(routes))


def _route_from_path(root: Path, file_path: Path) -> str:
    try:
        parts = file_path.relative_to(root).parts
    except ValueError:
        return ""
    roots = [index for index, part in enumerate(parts) if part in ROUTE_ROOTS]
    if not roots:
        return ""
    root_name = parts[roots[0]]
    start = roots[0] + 1
    route_parts = list(parts[start:])
    if root_name == "api":
        route_parts = ["api", *route_parts]
    if not route_parts:
        return ""
    stem = Path(route_parts[-1]).stem
    if stem in ROUTE_FILENAMES:
        route_parts = route_parts[:-1]
    else:
        route_parts[-1] = stem
    cleaned = route_parts
    route = "/" + "/".join(part.strip("[]()") for part in cleaned if part)
    return route.replace("//", "/") or "/"


def _find_webhook_routes(
    route_paths: tuple[str, ...],
    text_index: dict[Path, str],
) -> tuple[str, ...]:
    routes = {route for route in route_paths if "webhook" in route.lower()}
    for path, text in text_index.items():
        lowered = f"{path} {text}".lower()
        if "webhook" not in lowered:
            continue
        route_root = path.parent.parent if path.parent.name == "api" else path.parent
        route = _route_from_path(route_root, path)
        if route:
            routes.add(route)
    return tuple(sorted(routes))


def _find_oauth_callbacks(
    route_paths: tuple[str, ...],
    env_names: list[str],
    text_index: dict[Path, str],
) -> tuple[str, ...]:
    callbacks = {
        route
        for route in route_paths
        if any(marker in route.lower() for marker in ("oauth", "callback", "redirect"))
    }
    has_oauth_env = any(
        any(marker in name for marker in ("OAUTH", "CLIENT_ID", "REDIRECT_URI"))
        for name in env_names
    )
    if has_oauth_env:
        for route in route_paths:
            if any(marker in route.lower() for marker in ("auth", "callback")):
                callbacks.add(route)
    for path, text in text_index.items():
        lowered = f"{path} {text}".lower()
        if "redirect_uri" in lowered or "oauth" in lowered:
            route_root = path.parent.parent if path.parent.name == "api" else path.parent
            route = _route_from_path(route_root, path)
            if route:
                callbacks.add(route)
    return tuple(sorted(callbacks))


def _find_domains(root: Path, text_index: dict[Path, str]) -> list[DomainRequirement]:
    domains: set[str] = set()
    for text in text_index.values():
        for match in DOMAIN_PATTERN.finditer(text):
            domain = match.group(1).lower()
            if _is_custom_domain_candidate(domain):
                domains.add(domain)
    vercel_config = root / "vercel.json"
    if vercel_config.exists():
        try:
            raw = json.loads(vercel_config.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        if isinstance(raw, dict):
            for item in raw.get("domains", []):
                if isinstance(item, str) and _is_custom_domain_candidate(item):
                    domains.add(item.lower())
    return [
        DomainRequirement(
            domain=domain,
            provider="cloudflare",
            records=_vercel_dns_records(domain),
        )
        for domain in sorted(domains)
    ]


def _vercel_dns_records(domain: str) -> tuple[DnsRecord, ...]:
    """Return Vercel-friendly DNS records for apex or subdomain targets."""

    if _looks_like_apex_domain(domain):
        return (
            DnsRecord(name=domain, type="A", value="76.76.21.21"),
            DnsRecord(name=f"www.{domain}", type="CNAME", value="cname.vercel-dns.com"),
        )
    return (DnsRecord(name=domain, type="CNAME", value="cname.vercel-dns.com"),)


def _looks_like_apex_domain(domain: str) -> bool:
    return domain.count(".") == 1


def _is_custom_domain_candidate(domain: str) -> bool:
    blocked = ("localhost", "127.0.0.1")
    provider_suffixes = (
        ".vercel.app",
        ".github.com",
        ".github.io",
        ".supabase.co",
        ".stripe.com",
        ".plaid.com",
        ".resend.com",
    )
    return domain not in blocked and not any(
        domain.endswith(suffix) for suffix in provider_suffixes
    )


def _webhook_requirements(
    webhook_routes: tuple[str, ...],
    env_names: list[str],
) -> list[WebhookRequirement]:
    secret_name = next((name for name in env_names if "WEBHOOK" in name and "SECRET" in name), "")
    if not secret_name and webhook_routes:
        secret_name = "WEBHOOK_SECRET"
    webhooks = [
        WebhookRequirement(
            name=_webhook_name(route),
            target_url=route,
            events=_events_for_webhook(route),
            secret_name=secret_name or "WEBHOOK_SECRET",
        )
        for route in webhook_routes
    ]
    if not webhooks and any("WEBHOOK" in name for name in env_names):
        webhooks.append(
            WebhookRequirement(
                name="app-webhook",
                target_url="/api/webhooks",
                events=("provider-event",),
                secret_name=secret_name or "WEBHOOK_SECRET",
            )
        )
    return webhooks


def _webhook_name(route: str) -> str:
    parts = [part for part in route.split("/") if part]
    return "-".join(parts[-2:]) if len(parts) >= 2 else "app-webhook"


def _events_for_webhook(route: str) -> tuple[str, ...]:
    lowered = route.lower()
    if "stripe" in lowered:
        return ("payment", "subscription")
    if "github" in lowered:
        return ("push", "deployment")
    if "vercel" in lowered:
        return ("deployment",)
    return ("provider-event",)


def _detect_providers(
    root: Path,
    package: dict[str, object],
    env_names: list[str],
) -> tuple[ServiceRequirement, ...]:
    deps = _dependencies(package)
    services: list[ServiceRequirement] = []
    if "@vercel" in " ".join(deps) or (root / "vercel.json").exists():
        services.append(
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web-deployment",
                capabilities=("project", "env", "deploy", "verify", "capability_pack"),
                secrets=("VERCEL_TOKEN",),
                settings={
                    "capability_pack": str(pack_default_path(root, "vercel").relative_to(root)),
                    "setup_lane": "pack-runtime",
                },
            )
        )
    if "stripe" in deps:
        services.append(
            ServiceRequirement(
                provider="stripe",
                kind="payments",
                name="payments",
                capabilities=(
                    "webhook_secret",
                    "capability_pack",
                    "computer_use_setup",
                    "vault_secret_capture",
                    "verify",
                ),
                secrets=("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"),
                settings={
                    "capability_pack": str(pack_default_path(root, "stripe").relative_to(root)),
                    "setup_lane": "openclaw-inferred-ui",
                },
            )
        )
    if "@supabase/supabase-js" in deps or "supabase" in deps:
        services.append(
            ServiceRequirement(
                provider="supabase",
                kind="database",
                name="database",
                capabilities=(
                    "project",
                    "api_keys",
                    "capability_pack",
                    "computer_use_setup",
                    "vault_secret_capture",
                    "verify",
                ),
                secrets=("SUPABASE_SERVICE_ROLE_KEY",),
                settings={
                    "capability_pack": str(pack_default_path(root, "supabase").relative_to(root)),
                    "setup_lane": "openclaw-inferred-ui",
                },
            )
        )
    if "resend" in deps or "@react-email" in " ".join(deps):
        services.append(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="transactional-email",
                capabilities=(
                    "api_key",
                    "domain_verification",
                    "send_test",
                    "capability_pack",
                    "verify",
                ),
                secrets=("RESEND_API_KEY",),
                settings={
                    "capability_pack": str(pack_default_path(root, "resend").relative_to(root)),
                    "setup_lane": "openclaw-inferred-ui",
                },
            )
        )
    evidence = ProviderEvidence(dependencies=tuple(sorted(deps)), env_names=tuple(env_names))
    existing = {service.provider for service in services}
    for provider in infer_provider_candidates(evidence):
        if provider in existing:
            continue
        secrets = tuple(name for name in env_names if name.startswith(f"{provider.upper()}_"))
        if provider == "plaid":
            secrets = tuple(
                name
                for name in ("PLAID_CLIENT_ID", "PLAID_SECRET", "PLAID_ENV")
                if name in env_names or name == "PLAID_ENV"
            )
        services.append(
            ServiceRequirement(
                provider=provider,
                kind="provider-pack",
                name=f"{provider}-integration",
                capabilities=(
                    "capability_pack",
                    "computer_use_setup",
                    "vault_secret_capture",
                    "verify",
                ),
                secrets=secrets or (f"{provider.upper()}_API_KEY",),
                settings={
                    "capability_pack": str(pack_default_path(root, provider).relative_to(root)),
                    "setup_lane": "openclaw-inferred-ui",
                },
            )
        )
    return tuple(services)


def _dependencies(package: dict[str, object]) -> set[str]:
    result: set[str] = set()
    for key in ("dependencies", "devDependencies"):
        raw = package.get(key)
        if isinstance(raw, dict):
            result.update(str(name) for name in raw)
    return result


def _config_files(root: Path) -> tuple[str, ...]:
    return tuple(name for name in CONFIG_FILES if (root / name).exists())


def _walk_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.is_file() and (path.suffix in TEXT_EXTENSIONS or path.name.startswith(".env")):
            files.append(path)
    return files
