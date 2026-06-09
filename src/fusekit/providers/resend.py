"""Resend API adapter for deterministic email setup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fusekit.errors import ProviderError
from fusekit.manifest import DnsRecord
from fusekit.providers.http import JsonHttpClient

RESEND_ALLOWED_REGIONS = frozenset(
    {"us-east-1", "eu-west-1", "sa-east-1", "ap-northeast-1"}
)
RESEND_DEFAULT_REGION = "us-east-1"


@dataclass(frozen=True)
class ResendDomain:
    """Resend domain state plus DNS records required for verification."""

    id: str
    name: str
    status: str
    records: tuple[DnsRecord, ...]
    region: str = RESEND_DEFAULT_REGION
    reused: bool = False


@dataclass(frozen=True)
class ResendAudience:
    """Resend audience state."""

    id: str
    name: str
    reused: bool = False


@dataclass(frozen=True)
class ResendProvider:
    """Small Resend API adapter."""

    token: str
    api_base: str = "https://api.resend.com"

    def _client(self) -> JsonHttpClient:
        return JsonHttpClient(self.api_base, self.token, auth_header="Bearer")

    def contract_health(self) -> dict[str, Any]:
        """Check the token-backed Resend API contract before setup mutations."""

        response = self._client().request("GET", "/domains")
        return {"route": "/domains", "ok": True, "domain_count": len(_data_items(response))}

    def ensure_domain(self, domain: str, *, region: str = RESEND_DEFAULT_REGION) -> ResendDomain:
        """Create or reuse a Resend sending domain."""

        region = _normalize_region(region)
        existing = self._find_domain(domain)
        if existing:
            domain_id = _required_id(existing, "domain")
            data = self._get_domain(domain_id)
            return _domain_from_response(data or existing, domain, reused=True, region=region)
        created = self._client().request(
            "POST",
            "/domains",
            {
                "name": domain,
                "region": region,
                "capabilities": {"sending": "enabled", "receiving": "disabled"},
            },
        )
        domain_data = _payload_object(created, "domain")
        return _domain_from_response(domain_data, domain, reused=False, region=region)

    def verify_domain(self, domain_id: str) -> dict[str, Any]:
        """Ask Resend to verify a domain after DNS records have been applied."""

        return self._client().request("POST", f"/domains/{domain_id}/verify")

    def ensure_audience(self, name: str) -> ResendAudience:
        """Create or reuse a Resend audience."""

        existing = self._find_audience(name)
        if existing:
            return ResendAudience(id=_required_id(existing, "audience"), name=name, reused=True)
        created = self._client().request("POST", "/audiences", {"name": name})
        audience_data = _payload_object(created, "audience")
        return ResendAudience(
            id=_required_id(audience_data, "audience"),
            name=str(audience_data.get("name") or name),
            reused=False,
        )

    def _find_domain(self, domain: str) -> dict[str, Any] | None:
        response = self._client().request("GET", "/domains")
        for item in _data_items(response):
            if str(item.get("name", "")).lower() == domain.lower():
                return item
        return None

    def _get_domain(self, domain_id: str) -> dict[str, Any]:
        response = self._client().request("GET", f"/domains/{domain_id}")
        return _payload_object(response, "domain")

    def _find_audience(self, name: str) -> dict[str, Any] | None:
        response = self._client().request("GET", "/audiences")
        for item in _data_items(response):
            if str(item.get("name", "")).lower() == name.lower():
                return item
        return None


def _payload_object(response: dict[str, Any], label: str) -> dict[str, Any]:
    """Extract a provider object from common Resend response shapes."""

    data = response.get("data", response)
    if isinstance(data, dict):
        return data
    raise ProviderError(f"Resend {label} response was malformed.")


def _data_items(response: dict[str, Any]) -> list[dict[str, Any]]:
    data = response.get("data", [])
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _required_id(data: dict[str, Any], label: str) -> str:
    value = str(data.get("id", "")).strip()
    if not value:
        raise ProviderError(f"Resend {label} response did not include an id.")
    return value


def _normalize_region(region: str) -> str:
    value = region.strip().lower() or RESEND_DEFAULT_REGION
    if value not in RESEND_ALLOWED_REGIONS:
        allowed = ", ".join(sorted(RESEND_ALLOWED_REGIONS))
        raise ProviderError(f"Resend region must be one of: {allowed}.")
    return value


def _domain_from_response(
    data: dict[str, Any],
    domain: str,
    *,
    reused: bool,
    region: str,
) -> ResendDomain:
    domain_id = _required_id(data, "domain")
    records = tuple(_record_from_resend(item, domain) for item in _verification_records(data))
    return ResendDomain(
        id=domain_id,
        name=str(data.get("name") or domain),
        status=str(data.get("status", "")),
        records=records,
        region=str(data.get("region") or region),
        reused=reused,
    )


def _verification_records(data: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("records", "dns_records", "verification_records"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _record_from_resend(raw: dict[str, Any], domain: str) -> DnsRecord:
    record_type = str(raw.get("type", "TXT")).upper()
    name = _fqdn(str(raw.get("name", "") or raw.get("host", "")), domain)
    value = str(raw.get("value", "") or raw.get("content", "")).strip().strip('"')
    ttl = _ttl_from_resend(raw.get("ttl"))
    priority = raw.get("priority")
    return DnsRecord(
        name=name,
        type=record_type,
        value=value,
        ttl=ttl,
        proxied=False,
        priority=int(priority) if priority is not None else None,
    )


def _ttl_from_resend(value: Any) -> int:
    if value in (None, ""):
        return 300
    if isinstance(value, str) and value.strip().lower() == "auto":
        return 300
    try:
        return int(value)
    except (TypeError, ValueError):
        return 300


def _fqdn(name: str, domain: str) -> str:
    cleaned = name.strip().rstrip(".")
    if not cleaned or cleaned == "@":
        return domain
    if cleaned == domain or cleaned.endswith(f".{domain}"):
        return cleaned
    return f"{cleaned}.{domain}"
