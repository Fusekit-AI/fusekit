"""Cloudflare DNS adapter with proposal, apply, verify, and rollback metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fusekit.errors import ProviderError
from fusekit.manifest import DnsRecord
from fusekit.providers.http import JsonHttpClient


@dataclass(frozen=True)
class DnsChange:
    """DNS change proposal with rollback metadata."""

    zone_id: str
    record: DnsRecord
    existing: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the proposal without secrets."""

        return {
            "zone_id": self.zone_id,
            "record": {
                "name": self.record.name,
                "type": self.record.type,
                "value": self.record.value,
                "ttl": self.record.ttl,
                "proxied": self.record.proxied,
            },
            "rollback": self.existing or {"delete_created_record": True},
        }


@dataclass(frozen=True)
class CloudflareDnsProvider:
    """Real Cloudflare DNS adapter."""

    token: str
    api_base: str = "https://api.cloudflare.com/client/v4"

    def _client(self) -> JsonHttpClient:
        return JsonHttpClient(self.api_base, self.token, auth_header="Bearer")

    def propose(self, zone_name: str, records: tuple[DnsRecord, ...]) -> list[DnsChange]:
        """Create DNS change proposals with rollback metadata."""

        zone_id = self._zone_id(zone_name)
        changes: list[DnsChange] = []
        for record in records:
            existing = self._find_record(zone_id, record)
            changes.append(DnsChange(zone_id=zone_id, record=record, existing=existing))
        return changes

    def apply(self, changes: list[DnsChange]) -> list[dict[str, Any]]:
        """Apply DNS changes. Caller must enforce approval before this is called."""

        applied: list[dict[str, Any]] = []
        for change in changes:
            payload = {
                "type": change.record.type,
                "name": change.record.name,
                "content": change.record.value,
                "ttl": change.record.ttl,
                "proxied": change.record.proxied,
            }
            if change.existing and change.existing.get("id"):
                record_id = str(change.existing["id"])
                result = self._client().request(
                    "PUT",
                    f"/zones/{change.zone_id}/dns_records/{record_id}",
                    payload,
                )
            else:
                result = self._client().request(
                    "POST",
                    f"/zones/{change.zone_id}/dns_records",
                    payload,
                )
            applied.append(
                {"id": str(result.get("result", {}).get("id", "")), "name": change.record.name}
            )
        return applied

    def verify(self, zone_name: str, records: tuple[DnsRecord, ...]) -> list[dict[str, Any]]:
        """Verify records through Cloudflare's API state."""

        zone_id = self._zone_id(zone_name)
        results: list[dict[str, Any]] = []
        for record in records:
            existing = self._find_record(zone_id, record)
            results.append(
                {
                    "name": record.name,
                    "type": record.type,
                    "expected": record.value,
                    "ok": bool(existing and existing.get("content") == record.value),
                }
            )
        return results

    def rollback_proposals(self, proposals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Restore or delete DNS records from proposal rollback metadata."""

        results: list[dict[str, Any]] = []
        for proposal in proposals:
            zone_id = str(proposal.get("zone_id", ""))
            record_raw = proposal.get("record", {})
            rollback = proposal.get("rollback", {})
            if not zone_id or not isinstance(record_raw, dict) or not isinstance(rollback, dict):
                continue
            record = DnsRecord(
                name=str(record_raw.get("name", "")),
                type=str(record_raw.get("type", "A")),
                value=str(record_raw.get("value", "")),
                ttl=int(record_raw.get("ttl", 300)),
                proxied=bool(record_raw.get("proxied", False)),
            )
            if rollback.get("delete_created_record"):
                existing = self._find_record(zone_id, record)
                record_id = str(existing.get("id", "")) if existing else ""
                if record_id:
                    self._client().request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
                results.append({"name": record.name, "deleted": bool(record_id)})
                continue
            record_id = str(rollback.get("id", ""))
            if record_id:
                payload = {
                    "type": str(rollback.get("type", record.type)),
                    "name": str(rollback.get("name", record.name)),
                    "content": str(rollback.get("content", record.value)),
                    "ttl": int(rollback.get("ttl", record.ttl)),
                    "proxied": bool(rollback.get("proxied", record.proxied)),
                }
                self._client().request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", payload)
                results.append({"name": payload["name"], "restored": True})
        return results

    def _zone_id(self, zone_name: str) -> str:
        response = self._client().request("GET", f"/zones?name={zone_name}")
        result = response.get("result")
        if not isinstance(result, list) or not result:
            raise ProviderError(f"Cloudflare zone not found: {zone_name}")
        zone = result[0]
        if not isinstance(zone, dict):
            raise ProviderError("Cloudflare zone response was malformed.")
        return str(zone["id"])

    def _find_record(self, zone_id: str, record: DnsRecord) -> dict[str, Any] | None:
        response = self._client().request(
            "GET", f"/zones/{zone_id}/dns_records?type={record.type}&name={record.name}"
        )
        result = response.get("result")
        if not isinstance(result, list) or not result:
            return None
        item = result[0]
        if not isinstance(item, dict):
            return None
        return item
