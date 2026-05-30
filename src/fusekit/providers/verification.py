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
from urllib.request import Request, urlopen

from fusekit.audit import redact
from fusekit.errors import ProviderError
from fusekit.providers.capability_pack import ProviderCapabilityPack, VerificationRecipe
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
    attempts: int = 1,
    retry_seconds: float = 0.0,
) -> VerificationResult:
    """Run a recipe with polling/retry semantics."""

    attempts = max(1, attempts)
    last = verify_recipe(pack, recipe, vault, live_url=live_url)
    for _attempt in range(1, attempts):
        if last.status in {"ok", "skipped"}:
            return last
        if retry_seconds > 0:
            time.sleep(retry_seconds)
        last = verify_recipe(pack, recipe, vault, live_url=live_url)
    if last.status == "failed" and attempts > 1:
        return VerificationResult(
            provider=last.provider,
            kind=last.kind,
            target=last.target,
            status="pending",
            details={**last.details, "attempts": attempts},
        )
    return last


def verify_recipe(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
    vault: Vault,
    *,
    live_url: str = "",
) -> VerificationResult:
    """Run one provider-pack verification recipe."""

    try:
        if recipe.kind == "env-present":
            return _verify_env_present(pack, recipe, vault)
        if recipe.kind == "http-json":
            return _verify_http_json(pack, recipe, vault)
        if recipe.kind == "url-health":
            return _verify_url_health(pack, recipe, vault, live_url=live_url)
        if recipe.kind == "dns-record":
            return _verify_dns_record(pack, recipe)
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
    request = Request(recipe.target, data=body, method=method, headers=headers)
    status_code = 0
    text = ""
    try:
        with urlopen(request, timeout=30) as response:
            status_code = int(response.status)
            text = response.read().decode("utf-8")
    except HTTPError as exc:
        status_code = int(exc.code)
        text = exc.read().decode("utf-8", errors="replace")
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
) -> VerificationResult:
    del vault
    url = recipe.target or live_url
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
    try:
        with urlopen(Request(url, method="GET"), timeout=30) as response:
            status_code = int(response.status)
    except HTTPError as exc:
        status_code = int(exc.code)
    except URLError as exc:
        raise ProviderError(f"URL health verification failed: {exc.reason}") from exc
    ok = 200 <= status_code < 400
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
    expected_value = recipe.inputs.get("value", "")
    try:
        answers = resolver.resolve(name, record_type)
    except Exception as exc:
        raise ProviderError(f"DNS verification failed for {name} {record_type}: {exc}") from exc
    values = sorted(str(answer).strip('"') for answer in answers)
    ok = bool(values)
    if expected_value:
        ok = expected_value in values
    return VerificationResult(
        provider=pack.provider,
        kind=recipe.kind,
        target=name,
        status="ok" if ok else "failed",
        details={
            "type": record_type,
            "records": values,
            "expected_value_present": bool(expected_value and expected_value in values),
        },
    )


def _secret_available(vault: Vault, provider: str, name: str) -> bool:
    if os.environ.get(name):
        return True
    try:
        _secret_value(vault, provider, name)
    except ProviderError:
        return False
    return True


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
        except Exception:
            continue
    raise ProviderError(f"Required secret is not available: {name}")


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


def _path_exists(data: Any, dotted_path: str) -> bool:
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return False
    return current is not None
