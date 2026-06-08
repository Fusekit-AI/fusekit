"""Executable verification recipes for provider capability packs."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from importlib import import_module
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fusekit.audit import redact
from fusekit.errors import FuseKitError, ProviderError
from fusekit.providers.capability_pack import ProviderCapabilityPack, VerificationRecipe
from fusekit.security.url import require_safe_url
from fusekit.vault import Vault

TEMPLATE_REF_RE = re.compile(r"\$\{(secret|env):([A-Z][A-Z0-9_]+)\}")


@dataclass(frozen=True)
class VerificationResult:
    """A redacted result for one verification recipe."""

    provider: str
    kind: str
    target: str
    status: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize a redacted verification result."""

        return {
            "provider": self.provider,
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "details": redact(self.details),
        }


def verify_provider_pack(
    pack: ProviderCapabilityPack,
    vault: Vault,
    *,
    live_url: str = "",
    inputs: dict[str, str] | None = None,
    attempts: int = 1,
    retry_seconds: float = 0.0,
) -> list[VerificationResult]:
    """Run every executable recipe in a provider pack."""

    results: list[VerificationResult] = []
    for recipe in pack.verification:
        results.append(
            verify_recipe_with_retries(
                pack,
                recipe,
                vault,
                live_url=live_url,
                inputs=inputs,
                attempts=attempts,
                retry_seconds=retry_seconds,
            )
        )
    return results


def verify_recipe_with_retries(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    *,
    live_url: str = "",
    inputs: dict[str, str] | None = None,
    attempts: int = 1,
    retry_seconds: float = 0.0,
) -> VerificationResult:
    """Run a recipe with polling/retry semantics."""

    attempts = max(1, attempts)
    last = verify_recipe(pack, recipe, vault, live_url=live_url, inputs=inputs)
    for _attempt in range(1, attempts):
        if _verification_result_is_terminal(last, retry_seconds=retry_seconds):
            return last
        if retry_seconds > 0:
            time.sleep(retry_seconds)
        last = verify_recipe(pack, recipe, vault, live_url=live_url, inputs=inputs)
    if last.status == "failed" and attempts > 1:
        return VerificationResult(
            provider=last.provider,
            kind=last.kind,
            target=last.target,
            status="pending",
            details={**last.details, "attempts": attempts},
        )
    return last


def _verification_result_is_terminal(
    result: VerificationResult,
    *,
    retry_seconds: float,
) -> bool:
    if result.status in {"ok", "skipped", "needs_human_gate"}:
        return True
    return (
        retry_seconds > 0
        and result.status == "pending"
        and bool(result.details.get("pending_safe"))
    )


def verify_recipe(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    *,
    live_url: str = "",
    inputs: dict[str, str] | None = None,
) -> VerificationResult:
    """Run one provider-pack verification recipe."""

    try:
        if recipe.kind == "env-present":
            return _verify_env_present(pack, recipe, vault)
        if recipe.kind == "http-json":
            return _verify_http_json(pack, recipe, vault)
        if recipe.kind == "url-health":
            return _verify_url_health(pack, recipe, vault, live_url=live_url, inputs=inputs or {})
        if recipe.kind == "dns-record":
            return _verify_dns_record(pack, recipe)
        if recipe.kind == "dns-records":
            return _verify_dns_records(pack, recipe, _resolved_inputs(recipe, inputs))
        if recipe.kind == "github-repo-secret":
            return _verify_github_repo_secret(pack, recipe, vault, inputs or {})
        if recipe.kind == "github-deploy-key":
            return _verify_github_deploy_key(pack, recipe, vault, inputs or {})
        if recipe.kind == "vercel-project":
            return _verify_vercel_project(pack, recipe, vault, inputs or {})
        if recipe.kind == "vercel-env":
            return _verify_vercel_env(pack, recipe, vault, inputs or {})
        if recipe.kind == "vercel-deployment-url":
            return _verify_vercel_deployment(pack, recipe, vault, live_url, inputs or {})
        if recipe.kind == "cloudflare-dns-api":
            return _verify_cloudflare_dns_api(pack, recipe, vault, inputs or {})
        if recipe.kind == "resend-domain":
            return _verify_resend_domain(pack, recipe, vault, inputs or {})
        if recipe.kind == "webhook-secret":
            return _verify_env_present(pack, recipe, vault)
    except ProviderError as exc:
        return VerificationResult(
            provider=pack.provider,
            kind=recipe.kind,
            target=recipe.target,
            status="failed",
            details={"error": str(exc)},
        )
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status="skipped" if recipe.optional else "failed",
        details={"reason": "unsupported recipe kind", "expected": recipe.expected},
    )


def _verify_env_present(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
) -> VerificationResult:
    names = recipe.secret_refs or tuple(
        name.strip() for name in recipe.target.split(",") if name.strip()
    )
    present: list[str] = []
    missing: list[str] = []
    for name in names:
        if _secret_available(vault, pack.provider, name):
            present.append(name)
        else:
            missing.append(name)
    status = "ok" if not missing else "missing"
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status=status,
        details={"present": present, "missing": missing, "expected": recipe.expected},
    )


def _verify_http_json(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
) -> VerificationResult:
    method = recipe.inputs.get("method", "GET").upper()
    expected_status = int(recipe.inputs.get("expected_status", "200"))
    headers = _json_mapping(recipe.inputs.get("headers_json", "{}"))
    auth_secret = recipe.inputs.get("auth_secret", "")
    if auth_secret:
        token = _secret_value(vault, pack.provider, auth_secret)
        scheme = recipe.inputs.get("auth_scheme", "Bearer")
        headers["Authorization"] = f"{scheme} {token}"
    body: bytes | None = None
    if "body_json" in recipe.inputs:
        resolved = _resolve_template_refs(recipe.inputs["body_json"], vault, pack.provider)
        body = resolved.encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json")
    headers.setdefault("User-Agent", "FuseKit provider verification")
    target = require_safe_url(recipe.target, label="HTTP verification target")
    request = Request(target, data=body, method=method, headers=headers)
    status_code = 0
    text = ""
    try:
        with urlopen(request, timeout=30) as response:  # nosec B310
            status_code = int(response.status)
            text = response.read().decode("utf-8")
    except HTTPError as exc:
        status_code = int(exc.code)
        text = ""
    except URLError as exc:
        raise ProviderError(f"HTTP verification failed: {exc.reason}") from exc
    data: Any = {}
    if text:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProviderError("HTTP verification returned non-JSON content.") from exc
    response_path = recipe.inputs.get("response_path", "")
    path_present = True
    if response_path:
        path_present = _path_exists(data, response_path)
    if auth_secret and status_code in {401, 403}:
        return _needs_gate(
            pack,
            recipe,
            (
                f"{pack.display_name} rejected the captured credential with HTTP "
                f"{status_code}. Create or capture a token that includes the required "
                "provider access for this check."
            ),
        )
    ok = status_code == expected_status and path_present
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status="ok" if ok else "failed",
        details={
            "method": method,
            "status_code": status_code,
            "expected_status": expected_status,
            "response_path": response_path,
            "response_path_present": path_present,
            "expected": recipe.expected,
        },
    )


def _verify_url_health(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    *,
    live_url: str,
    inputs: dict[str, str],
) -> VerificationResult:
    del vault
    url = recipe.target or live_url
    is_live_url_target = url == "$live_url"
    if url == "$live_url":
        url = live_url
    if not url:
        return VerificationResult(
            provider=pack.provider,
            kind=recipe.kind,
            target=recipe.target,
            status="skipped",
            details={"reason": "no live URL supplied"},
        )
    url = require_safe_url(url, label="URL health target", allow_http_loopback=True)
    try:
        with urlopen(Request(url, method="GET"), timeout=30) as response:  # nosec B310
            status_code = int(response.status)
    except HTTPError as exc:
        status_code = int(exc.code)
    except URLError as exc:
        if is_live_url_target and inputs.get("live_url_dns_pending_safe") == "true":
            return VerificationResult(
                provider=pack.provider,
                kind=recipe.kind,
                target=url,
                status="pending",
                details={
                    "error": str(exc.reason),
                    "expected": recipe.expected or "2xx/3xx",
                    "pending_safe": True,
                    "reason": "custom DNS apply is waiting for approval or propagation",
                },
            )
        raise ProviderError(f"URL health verification failed: {exc.reason}") from exc
    ok = 200 <= status_code < 400
    if not ok and is_live_url_target and inputs.get("live_url_dns_pending_safe") == "true":
        return VerificationResult(
            provider=pack.provider,
            kind=recipe.kind,
            target=url,
            status="pending",
            details={
                "status_code": status_code,
                "expected": recipe.expected or "2xx/3xx",
                "pending_safe": True,
                "reason": "custom DNS apply is waiting for approval or propagation",
            },
        )
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=url,
        status="ok" if ok else "failed",
        details={"status_code": status_code, "expected": recipe.expected or "2xx/3xx"},
    )


def _verify_dns_record(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
) -> VerificationResult:
    try:
        resolver = import_module("dns.resolver")
    except ImportError as exc:
        raise ProviderError("dnspython is required for DNS verification.") from exc
    record_type = recipe.inputs.get("type", "A").upper()
    name = recipe.inputs.get("name", recipe.target)
    expected_value = _normalize_dns_value(recipe.inputs.get("value", ""), record_type)
    try:
        answers = resolver.resolve(name, record_type)
    except Exception as exc:
        raise ProviderError(f"DNS verification failed for {name} {record_type}: {exc}") from exc
    values = sorted(_normalize_dns_value(str(answer), record_type) for answer in answers)
    ok = bool(values)
    if expected_value:
        ok = expected_value in values
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=name,
        status="ok" if ok else "pending",
        details={
            "type": record_type,
            "records": values,
            "expected_value_present": bool(expected_value and expected_value in values),
            "pending_safe": True,
        },
    )


def _verify_dns_records(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    inputs: dict[str, str],
) -> VerificationResult:
    records = _records_from_inputs(inputs.get("records_json", "[]"))
    if not records:
        return _skipped(pack, recipe, "no DNS records supplied")
    try:
        resolver = import_module("dns.resolver")
    except ImportError as exc:
        raise ProviderError("dnspython is required for DNS verification.") from exc
    missing: list[dict[str, str]] = []
    observed: list[dict[str, object]] = []
    for record in records:
        name = str(record.get("name", ""))
        record_type = str(record.get("type", "A")).upper()
        expected_value = _normalize_dns_value(str(record.get("value", "")), record_type)
        try:
            answers = resolver.resolve(name, record_type)
            values = sorted(_normalize_dns_value(str(answer), record_type) for answer in answers)
        except Exception:
            values = []
        expected_present = bool(expected_value and expected_value in values)
        observed.append(
            {
                "name": name,
                "type": record_type,
                "records": values,
                "expected_value_present": expected_present,
            }
        )
        if not values or (expected_value and not expected_present):
            missing.append({"name": name, "type": record_type})
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status="ok" if not missing else "pending",
        details={
            "checked": observed,
            "missing": missing,
            "pending_safe": True,
            "expected": recipe.expected,
        },
    )


def _normalize_dns_value(value: str, record_type: str) -> str:
    normalized = value.strip().strip('"')
    if record_type.upper() in {"CNAME", "NS", "PTR"}:
        normalized = normalized.rstrip(".").lower()
    return normalized


def _verify_github_repo_secret(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    repo = _resolve_template(recipe.target, inputs)
    names = _csv(_resolve_template(recipe.inputs.get("names", ""), inputs))
    if not repo:
        return _needs_gate(pack, recipe, "GitHub repository is not known yet.")
    if not names:
        return _skipped(pack, recipe, "no GitHub repo secret names supplied")
    token = _token_or_gate(pack, recipe, vault, "GITHUB_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    missing: list[str] = []
    for name in names:
        status, _data = _api_json(
            "https://api.github.com",
            token,
            f"/repos/{_repo_path(repo)}/actions/secrets/{quote(name)}",
        )
        if status == 404:
            missing.append(name)
        elif status >= 400:
            raise ProviderError(f"GitHub secret verification returned HTTP {status}.")
    unavailable = [name for name in missing if not _secret_available_any_provider(vault, name)]
    if unavailable:
        return _needs_gate(
            pack,
            recipe,
            (
                "GitHub repository secrets are waiting on provider values FuseKit has not "
                "captured yet: "
            )
            + ", ".join(unavailable)
            + ".",
        )
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=repo,
        status="ok" if not missing else "failed",
        details={"repo": repo, "checked": names, "missing": missing},
    )


def _verify_github_deploy_key(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    repo = _resolve_template(recipe.target, inputs)
    title = recipe.inputs.get("title", "FuseKit deploy key")
    if not repo:
        return _needs_gate(pack, recipe, "GitHub repository is not known yet.")
    token = _token_or_gate(pack, recipe, vault, "GITHUB_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    status, data = _api_json(
        "https://api.github.com",
        token,
        f"/repos/{_repo_path(repo)}/keys?per_page=100",
    )
    if status >= 400:
        raise ProviderError(f"GitHub deploy key verification returned HTTP {status}.")
    keys = data if isinstance(data, list) else []
    matched = [
        str(item.get("id", ""))
        for item in keys
        if isinstance(item, dict) and str(item.get("title", "")) == title
    ]
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=repo,
        status="ok" if matched else "failed",
        details={"repo": repo, "title": title, "matched_key_ids": matched},
    )


def _verify_vercel_project(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    project = _resolve_template(recipe.target, inputs)
    if not project:
        return _needs_gate(pack, recipe, "Vercel project name is not known yet.")
    token = _token_or_gate(pack, recipe, vault, "VERCEL_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    status, data = _api_json("https://api.vercel.com", token, f"/v9/projects/{quote(project)}")
    ok = status == 200 and isinstance(data, dict)
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=project,
        status="ok" if ok else "failed",
        details={"project": project, "status_code": status},
    )


def _verify_vercel_env(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    project = _resolve_template(recipe.target, inputs)
    names = _csv(_resolve_template(recipe.inputs.get("names", ""), inputs))
    if not project:
        return _needs_gate(pack, recipe, "Vercel project name is not known yet.")
    if not names:
        return _skipped(pack, recipe, "no Vercel env var names supplied")
    token = _token_or_gate(pack, recipe, vault, "VERCEL_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    status, data = _api_json("https://api.vercel.com", token, f"/v9/projects/{quote(project)}/env")
    if status >= 400:
        raise ProviderError(f"Vercel env verification returned HTTP {status}.")
    envs_raw = data.get("envs", data.get("data", [])) if isinstance(data, dict) else []
    envs = envs_raw if isinstance(envs_raw, list) else []
    present = {
        str(item.get("key", ""))
        for item in envs
        if isinstance(item, dict) and item.get("key")
    }
    missing = [name for name in names if name not in present]
    if missing:
        return _needs_gate(
            pack,
            recipe,
            (
                "Vercel is missing required app runtime environment variables: "
                + ", ".join(missing)
                + ". Capture or derive these values before verifying the deployment."
            ),
        )
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=project,
        status="ok",
        details={"project": project, "checked": names, "missing": missing},
    )


def _verify_vercel_deployment(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    live_url: str,
    inputs: dict[str, str],
) -> VerificationResult:
    project = _resolve_template(recipe.target, inputs)
    token = _token_or_gate(pack, recipe, vault, "VERCEL_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    query = (
        urlencode({"projectId": project, "limit": "1"})
        if project
        else urlencode({"limit": "1"})
    )
    status, data = _api_json("https://api.vercel.com", token, f"/v6/deployments?{query}")
    if status >= 400:
        raise ProviderError(f"Vercel deployment verification returned HTTP {status}.")
    deployments = data.get("deployments", []) if isinstance(data, dict) else []
    latest = deployments[0] if deployments and isinstance(deployments[0], dict) else {}
    deployment_url = str(latest.get("url", ""))
    ready = str(
        latest.get("readyState") or latest.get("state") or latest.get("readySubstate") or ""
    ).upper() in {"READY", "ALIASED", "PROMOTED"}
    live_url_ready = _url_is_healthy(live_url) if live_url and not ready else False
    ready = ready or live_url_ready
    ok = bool(live_url or deployment_url) and ready
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=project or live_url,
        status="ok" if ok else "pending",
        details={
            "project": project,
            "deployment_url_present": bool(live_url or deployment_url),
            "ready": ready,
            "live_url_ready": live_url_ready,
            "pending_safe": True,
        },
    )


def _url_is_healthy(url: str) -> bool:
    try:
        safe_url = require_safe_url(url, label="URL health target", allow_http_loopback=True)
        with urlopen(Request(safe_url, method="GET"), timeout=30) as response:  # nosec B310
            return 200 <= int(response.status) < 400
    except (HTTPError, URLError):
        return False


def _verify_cloudflare_dns_api(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    resolved = _resolved_inputs(recipe, inputs)
    zone = _resolve_template(recipe.target, inputs) or resolved.get("zone", "")
    records = _records_from_inputs(resolved.get("records_json", "[]"))
    if not zone or not records:
        return _skipped(pack, recipe, "no Cloudflare zone or DNS records supplied")
    token = _token_or_gate(pack, recipe, vault, "CLOUDFLARE_API_TOKEN")
    if isinstance(token, VerificationResult):
        return token
    zone_status, zone_data = _api_json(
        "https://api.cloudflare.com/client/v4",
        token,
        f"/zones?{urlencode({'name': zone})}",
    )
    if zone_status >= 400:
        raise ProviderError(f"Cloudflare zone lookup returned HTTP {zone_status}.")
    zones = zone_data.get("result", []) if isinstance(zone_data, dict) else []
    zone_id = str(zones[0].get("id", "")) if zones and isinstance(zones[0], dict) else ""
    if not zone_id:
        return VerificationResult(
            provider=pack.provider,
            kind=recipe.kind,
            target=zone,
            status="failed",
            details={"zone": zone, "missing_zone": True},
        )
    missing: list[dict[str, str]] = []
    for record in records:
        name = str(record.get("name", ""))
        record_type = str(record.get("type", "A")).upper()
        value = str(record.get("value", ""))
        params = urlencode({"type": record_type, "name": name})
        status, data = _api_json(
            "https://api.cloudflare.com/client/v4",
            token,
            f"/zones/{zone_id}/dns_records?{params}",
        )
        if status >= 400:
            raise ProviderError(f"Cloudflare DNS lookup returned HTTP {status}.")
        items = data.get("result", []) if isinstance(data, dict) else []
        priority = record.get("priority")
        if not any(
            isinstance(item, dict)
            and str(item.get("content", "")) == value
            and (
                priority is None
                or str(item.get("priority", "")) == str(priority)
            )
            for item in items
        ):
            missing.append({"name": name, "type": record_type})
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=zone,
        status="ok" if not missing else "pending",
        details={
            "zone": zone,
            "checked": len(records),
            "missing": missing,
            "pending_safe": True,
        },
    )


def _verify_resend_domain(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    inputs: dict[str, str],
) -> VerificationResult:
    domain = _resolve_template(recipe.target, inputs)
    if not domain:
        return _skipped(pack, recipe, "no Resend domain supplied")
    token = _token_or_gate(pack, recipe, vault, "RESEND_API_KEY")
    if isinstance(token, VerificationResult):
        return token
    status, data = _api_json("https://api.resend.com", token, "/domains")
    if status in {401, 403}:
        return _needs_gate(
            pack,
            recipe,
            (
                "Resend rejected the captured setup key. Create or capture a Resend API key "
                "with Full access for the first setup so FuseKit can create or reuse domains "
                "and audiences."
            ),
        )
    if status >= 400:
        raise ProviderError(f"Resend domain verification returned HTTP {status}.")
    domains = data.get("data", []) if isinstance(data, dict) else []
    match = next(
        (
            item
            for item in domains
            if isinstance(item, dict) and str(item.get("name", "")) == domain
        ),
        None,
    )
    if not match:
        return VerificationResult(
            provider=pack.provider,
            kind=recipe.kind,
            target=domain,
            status="failed",
            details={
                "domain": domain,
                "missing": True,
                "repair": "rerun_resend_domain_setup",
                "reason": (
                    "Resend has a valid setup key, but the sending domain does not exist yet. "
                    "FuseKit should create or reuse the domain through Resend's API before DNS "
                    "is applied."
                ),
            },
        )
    domain_status = str(match.get("status", "")).lower()
    ok = domain_status in {"verified", "success", "active"}
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=domain,
        status="ok" if ok else "pending",
        details={"domain": domain, "domain_status": domain_status, "pending_safe": True},
    )


def _secret_available(vault: Vault, provider: str, name: str) -> bool:
    if os.environ.get(name):
        return True
    try:
        _secret_value(vault, provider, name)
    except ProviderError:
        return False
    return True


def _secret_available_any_provider(vault: Vault, name: str) -> bool:
    if os.environ.get(name):
        return True
    return any(record.label == name for record in vault.records.values())


def _secret_value(vault: Vault, provider: str, name: str) -> str:
    env_value = os.environ.get(name)
    if env_value:
        return env_value
    candidates = (
        name,
        f"provider.{provider}.{name.lower()}",
        f"provider.{provider}.token",
    )
    for record_id in candidates:
        try:
            return vault.require(record_id).value
        except FuseKitError:
            continue
    raise ProviderError(f"Required secret is not available: {name}")


def _token_or_gate(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    name: str,
) -> str | VerificationResult:
    try:
        return _secret_value(vault, pack.provider, name)
    except ProviderError:
        return _needs_gate(
            pack,
            recipe,
            f"{pack.display_name} authorization is not available yet.",
        )


def _resolve_template_refs(text: str, vault: Vault, provider: str) -> str:
    def replace(match: re.Match[str]) -> str:
        source, name = match.groups()
        if source == "env":
            value = os.environ.get(name)
            if value is None:
                raise ProviderError(f"Required env value is not available: {name}")
            return value
        return _secret_value(vault, provider, name)

    return TEMPLATE_REF_RE.sub(replace, text)


def _json_mapping(text: str) -> dict[str, str]:
    data = json.loads(text or "{}")
    if not isinstance(data, dict):
        raise ProviderError("headers_json must be a JSON object.")
    return {str(key): str(value) for key, value in data.items()}


def _api_json(
    api_base: str,
    token: str,
    path: str,
) -> tuple[int, Any]:
    request = Request(
        f"{api_base}{path}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "FuseKit provider verification",
        },
        method="GET",
    )
    text = ""
    try:
        with urlopen(request, timeout=30) as response:  # nosec B310
            status = int(response.status)
            text = response.read().decode("utf-8")
    except HTTPError as exc:
        status = int(exc.code)
        text = exc.read().decode("utf-8") if exc.fp else ""
    except URLError as exc:
        raise ProviderError(f"Provider API verification failed: {exc.reason}") from exc
    if not text:
        return status, {}
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {}


def _resolve_template(value: str, inputs: dict[str, str]) -> str:
    resolved = value
    for key, replacement in inputs.items():
        resolved = resolved.replace(f"${{input:{key}}}", replacement)
    return resolved if "${input:" not in resolved else ""


def _resolved_inputs(
    recipe: VerificationRecipe,
    inputs: dict[str, str] | None,
) -> dict[str, str]:
    source = inputs or {}
    return {key: _resolve_template(value, source) for key, value in recipe.inputs.items()}


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _records_from_inputs(value: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise ProviderError("records_json must be a JSON list.") from exc
    if not isinstance(data, list):
        raise ProviderError("records_json must be a JSON list.")
    return [item for item in data if isinstance(item, dict)]


def _repo_path(repo: str) -> str:
    stripped = repo.strip().removeprefix("https://github.com/").removesuffix(".git")
    if stripped.count("/") != 1:
        raise ProviderError("GitHub repo must be owner/name.")
    return "/".join(quote(part) for part in stripped.split("/", 1))


def _needs_gate(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    reason: str,
) -> VerificationResult:
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status="needs_human_gate",
        details={"reason": reason, "service_gate": True},
    )


def _skipped(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    reason: str,
) -> VerificationResult:
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=recipe.target,
        status="skipped",
        details={"reason": reason},
    )


def _path_exists(data: Any, dotted_path: str) -> bool:
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return False
    return current is not None
