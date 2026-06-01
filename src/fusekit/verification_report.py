"""Redacted verification report artifacts for launch trust checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fusekit.audit import redact
from fusekit.providers.verification import VerificationResult


@dataclass(frozen=True)
class VerificationCheck:
    """One redacted trust check."""

    provider: str
    check: str
    status: str
    summary: str
    repair: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize a redacted verification check."""

        return {
            "provider": self.provider,
            "check": self.check,
            "status": self.status,
            "summary": self.summary,
            "repair": self.repair,
            "details": redact(self.details),
        }


@dataclass
class VerificationReport:
    """A public, redacted report describing whether setup truly works."""

    app_name: str
    live_url: str = ""
    checks: list[VerificationCheck] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_live_url(self, result: dict[str, Any]) -> None:
        """Add a live URL health check."""

        ok = bool(result.get("ok"))
        status = "passed" if ok else "failed"
        self.checks.append(
            VerificationCheck(
                provider="live_app",
                check="live_url_healthy",
                status=status,
                summary=(
                    "The deployed app answered successfully."
                    if ok
                    else "The deployed app did not answer successfully yet."
                ),
                repair=(
                    "Nothing needed."
                    if ok
                    else (
                        "FuseKit should retry health checks, inspect deployment logs, "
                        "and redeploy after provider repair."
                    )
                ),
                details=result,
            )
        )

    def add_provider_results(
        self,
        provider: str,
        results: list[VerificationResult],
        *,
        repaired: bool = False,
    ) -> None:
        """Add provider recipe results."""

        for result in results:
            self.checks.append(_check_from_result(provider, result, repaired=repaired))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        counts = {
            "passed": 0,
            "pending": 0,
            "repairing": 0,
            "failed": 0,
            "skipped": 0,
        }
        for check in self.checks:
            if check.status in counts:
                counts[check.status] += 1
        overall = "pending" if not self.checks else "passed"
        if counts["failed"]:
            overall = "failed"
        elif counts["repairing"]:
            overall = "repairing"
        elif counts["pending"]:
            overall = "pending"
        return {
            "schema_version": "fusekit.verification-report.v1",
            "app_name": self.app_name,
            "live_url": self.live_url,
            "generated_at": self.generated_at,
            "overall": overall,
            "counts": counts,
            "checks": [check.to_dict() for check in self.checks],
        }

    def write(self, path: Path) -> None:
        """Write the redacted report."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            "utf-8",
        )


def _check_from_result(
    provider: str,
    result: VerificationResult,
    *,
    repaired: bool,
) -> VerificationCheck:
    status = _report_status(result.status, repaired=repaired)
    check = _check_name(result.kind)
    return VerificationCheck(
        provider=provider,
        check=check,
        status=status,
        summary=_summary(provider, check, status),
        repair=_repair(provider, check, status),
        details=result.to_dict(),
    )


def _report_status(status: str, *, repaired: bool) -> str:
    if status == "ok":
        return "passed"
    if status == "skipped":
        return "skipped"
    if status == "pending":
        return "pending"
    if repaired:
        return "repairing"
    return "failed"


def _check_name(kind: str) -> str:
    return {
        "env-present": "configured",
        "http-json": "auth_valid",
        "dns-record": "dns_verified",
        "url-health": "live_url_healthy",
    }.get(kind, "resource_exists")


def _summary(provider: str, check: str, status: str) -> str:
    readable = _readable_check(check)
    if status == "passed":
        return f"{provider} {readable} passed."
    if status == "pending":
        return f"{provider} {readable} is still pending."
    if status == "repairing":
        return f"{provider} {readable} needs a repair pass."
    if status == "skipped":
        return f"{provider} {readable} was skipped as optional."
    return f"{provider} {readable} failed."


def _repair(provider: str, check: str, status: str) -> str:
    if status == "passed":
        return "Nothing needed. Snowman gives this check a tiny approving nod."
    if status == "skipped":
        return "No action needed unless this optional check matters for launch proof."
    if status == "pending":
        return _pending_repair(provider, check)
    if status == "repairing":
        return (
            "FuseKit should reopen the provider page, repair the missing setup, "
            "and rerun this check."
        )
    return _failed_repair(provider, check)


def _pending_repair(provider: str, check: str) -> str:
    if check == "dns_verified":
        return (
            "Keep waiting for DNS propagation; FuseKit should recheck until the "
            "provider confirms it."
        )
    if check == "live_url_healthy":
        return "Wait for deployment warmup, then retry the live URL health check."
    return f"Keep the {provider} gate alive and rerun verification after the provider finishes."


def _failed_repair(provider: str, check: str) -> str:
    if check == "configured":
        return f"Reapply {provider} environment variables/secrets and rerun verification."
    if check == "auth_valid":
        return f"Create or recapture the approved {provider} token, then rerun verification."
    if check == "dns_verified":
        return (
            "Compare expected DNS records to provider records, reapply missing "
            "records, then retry."
        )
    if check == "live_url_healthy":
        return "Inspect deployment/provider status, redeploy if needed, then retry health checks."
    return f"Confirm the {provider} resource exists, repair through provider UI/API, and retry."


def _readable_check(check: str) -> str:
    return check.replace("_", " ")
