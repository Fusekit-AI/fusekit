"""Typed setup manifest model and parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from fusekit.errors import ManifestError


@dataclass(frozen=True)
class ServiceRequirement:
    """A service FuseKit may need to configure."""

    provider: str
    kind: str
    name: str
    capabilities: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    settings: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DnsRecord:
    """A DNS record proposed by FuseKit."""

    name: str
    type: str
    value: str
    ttl: int = 300
    proxied: bool = False
    priority: int | None = None


@dataclass(frozen=True)
class DomainRequirement:
    """DNS/domain configuration requested by the app."""

    domain: str
    provider: str
    records: tuple[DnsRecord, ...] = ()


@dataclass(frozen=True)
class WebhookRequirement:
    """Webhook configuration requested by the app."""

    name: str
    target_url: str
    events: tuple[str, ...] = ()
    secret_name: str = "WEBHOOK_SECRET"


@dataclass(frozen=True)
class SetupManifest:
    """FuseKit setup manifest."""

    app_name: str
    app_path: str = "."
    required_env: tuple[str, ...] = ()
    services: tuple[ServiceRequirement, ...] = ()
    domains: tuple[DomainRequirement, ...] = ()
    webhooks: tuple[WebhookRequirement, ...] = ()
    approvals: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the manifest as plain data."""

        return {
            "app_name": self.app_name,
            "app_path": self.app_path,
            "required_env": list(self.required_env),
            "services": [
                {
                    "provider": service.provider,
                    "kind": service.kind,
                    "name": service.name,
                    "capabilities": list(service.capabilities),
                    "secrets": list(service.secrets),
                    "env": dict(service.env),
                    "settings": dict(service.settings),
                }
                for service in self.services
            ],
            "domains": [
                {
                    "domain": domain.domain,
                    "provider": domain.provider,
                    "records": [
                        {
                            "name": record.name,
                            "type": record.type,
                            "value": record.value,
                            "ttl": record.ttl,
                            "proxied": record.proxied,
                            "priority": record.priority,
                        }
                        for record in domain.records
                    ],
                }
                for domain in self.domains
            ],
            "webhooks": [
                {
                    "name": webhook.name,
                    "target_url": webhook.target_url,
                    "events": list(webhook.events),
                    "secret_name": webhook.secret_name,
                }
                for webhook in self.webhooks
            ],
            "approvals": list(self.approvals),
            "metadata": dict(self.metadata),
        }


def load_manifest(path: Path) -> SetupManifest:
    """Load a FuseKit manifest from YAML or JSON-compatible YAML."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"Cannot read manifest: {path}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"Cannot parse manifest YAML: {path}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("Manifest must be a mapping.")
    return manifest_from_dict(raw)


def write_manifest(manifest: SetupManifest, path: Path) -> None:
    """Write a manifest to YAML."""

    path.write_text(yaml.safe_dump(manifest.to_dict(), sort_keys=False), encoding="utf-8")


def manifest_from_dict(raw: dict[str, Any]) -> SetupManifest:
    """Validate and normalize a manifest mapping."""

    app_name = _string(raw, "app_name")
    app_path = str(raw.get("app_path", "."))
    required_env = _tuple_of_strings(raw.get("required_env", ()), "required_env")
    services = tuple(_service(item) for item in _list(raw.get("services", ()), "services"))
    domains = tuple(_domain(item) for item in _list(raw.get("domains", ()), "domains"))
    webhooks = tuple(_webhook(item) for item in _list(raw.get("webhooks", ()), "webhooks"))
    approvals = _tuple_of_strings(raw.get("approvals", ()), "approvals")
    metadata_raw = raw.get("metadata", {})
    if not isinstance(metadata_raw, dict):
        raise ManifestError("metadata must be a mapping.")
    metadata = {str(key): str(value) for key, value in metadata_raw.items()}
    return SetupManifest(
        app_name=app_name,
        app_path=app_path,
        required_env=required_env,
        services=services,
        domains=domains,
        webhooks=webhooks,
        approvals=approvals,
        metadata=metadata,
    )


def _service(raw: Any) -> ServiceRequirement:
    if not isinstance(raw, dict):
        raise ManifestError("Each service must be a mapping.")
    env_raw = raw.get("env", {})
    settings_raw = raw.get("settings", {})
    if not isinstance(env_raw, dict) or not isinstance(settings_raw, dict):
        raise ManifestError("service env and settings must be mappings.")
    return ServiceRequirement(
        provider=_string(raw, "provider"),
        kind=_string(raw, "kind"),
        name=str(raw.get("name", raw.get("provider", "service"))),
        capabilities=_tuple_of_strings(raw.get("capabilities", ()), "service.capabilities"),
        secrets=_tuple_of_strings(raw.get("secrets", ()), "service.secrets"),
        env={str(key): str(value) for key, value in env_raw.items()},
        settings={str(key): str(value) for key, value in settings_raw.items()},
    )


def _domain(raw: Any) -> DomainRequirement:
    if not isinstance(raw, dict):
        raise ManifestError("Each domain must be a mapping.")
    records = tuple(_dns_record(item) for item in _list(raw.get("records", ()), "domain.records"))
    return DomainRequirement(
        domain=_string(raw, "domain"),
        provider=str(raw.get("provider", "cloudflare")),
        records=records,
    )


def _dns_record(raw: Any) -> DnsRecord:
    if not isinstance(raw, dict):
        raise ManifestError("Each DNS record must be a mapping.")
    return DnsRecord(
        name=_string(raw, "name"),
        type=_string(raw, "type").upper(),
        value=_string(raw, "value"),
        ttl=int(raw.get("ttl", 300)),
        proxied=bool(raw.get("proxied", False)),
        priority=int(raw["priority"]) if raw.get("priority") is not None else None,
    )


def _webhook(raw: Any) -> WebhookRequirement:
    if not isinstance(raw, dict):
        raise ManifestError("Each webhook must be a mapping.")
    return WebhookRequirement(
        name=_string(raw, "name"),
        target_url=_string(raw, "target_url"),
        events=_tuple_of_strings(raw.get("events", ()), "webhook.events"),
        secret_name=str(raw.get("secret_name", "WEBHOOK_SECRET")),
    )


def _string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{key} must be a non-empty string.")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be a list.")
    return value


def _tuple_of_strings(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be a list of strings.")
    if not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{label} must be a list of strings.")
    return tuple(value)
