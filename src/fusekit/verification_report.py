"""Redacted verification report artifacts for launch trust checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fusekit.audit import redact
from fusekit.providers.verification import VerificationResult

CAPTURE_TARGET_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|API_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|TOKEN|SECRET)\b"
)
DEFAULT_CAPTURE_TARGETS_BY_PROVIDER = {
    "cloudflare": ("CLOUDFLARE_API_TOKEN",),
    "dns": ("CLOUDFLARE_API_TOKEN",),
    "github": ("GITHUB_TOKEN",),
    "openai": ("OPENAI_API_KEY",),
    "resend": ("RESEND_API_KEY",),
    "vercel": ("VERCEL_TOKEN",),
}


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
        pending_safe = bool(result.get("pending_safe"))
        status = "passed" if ok else "pending" if pending_safe else "failed"
        self.checks.append(
            VerificationCheck(
                provider="live_app",
                check="live_url_healthy",
                status=status,
                summary=(
                    "The deployed app answered successfully."
                    if status == "passed"
                    else "The live URL has not become reachable yet."
                    if status == "pending"
                    else "The deployed app did not answer successfully yet."
                ),
                repair=(
                    "Nothing needed."
                    if status == "passed"
                    else (
                        "Keep the control room open while FuseKit retries DNS and deployment "
                        "health checks; any provider-owned blocker will resurface as a guided "
                        "launcher gate."
                    )
                    if status == "pending"
                    else (
                        "FuseKit will retry the live URL health check, reapply provider setup "
                        "through API routes where possible, and surface a guided control-room "
                        "gate if a provider needs human approval."
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
            "needs_human_gate": 0,
        }
        for check in self.checks:
            if check.status in counts:
                counts[check.status] += 1
        overall = "pending" if not self.checks else "passed"
        if counts["failed"]:
            overall = "failed"
        elif counts["repairing"]:
            overall = "repairing"
        elif counts["needs_human_gate"]:
            overall = "needs_human_gate"
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
        repair=_repair(
            provider,
            check,
            status,
            target=result.target,
            details=result.details,
        ),
        details=result.to_dict(),
    )


def _report_status(status: str, *, repaired: bool) -> str:
    if status == "ok":
        return "passed"
    if status == "skipped":
        return "skipped"
    if status == "pending":
        return "pending"
    if status == "needs_human_gate":
        return "needs_human_gate"
    if repaired:
        return "repairing"
    return "failed"


def _check_name(kind: str) -> str:
    return {
        "env-present": "configured",
        "http-json": "auth_valid",
        "dns-record": "dns_propagated",
        "dns-records": "dns_propagated",
        "url-health": "live_url_healthy",
        "github-repo-secret": "repo_secret_exists",
        "github-deploy-key": "deploy_key_exists",
        "vercel-project": "project_exists",
        "vercel-env": "env_vars_configured",
        "vercel-deployment-url": "deployment_url_exists",
        "cloudflare-dns-api": "dns_record_exists",
        "resend-domain": "domain_verified",
        "webhook-secret": "webhook_secret_present",
        "provider-gate": "provider_gate",
    }.get(kind, "resource_exists")


def _summary(provider: str, check: str, status: str) -> str:
    readable = _readable_check(check)
    if status == "passed":
        return f"{provider} {readable} passed."
    if status == "pending":
        return f"{provider} {readable} is still pending."
    if status == "repairing":
        return f"{provider} {readable} needs a repair pass."
    if status == "needs_human_gate":
        return f"{provider} {readable} needs your provider verification step."
    if status == "skipped":
        return f"{provider} {readable} was skipped as optional."
    return f"{provider} {readable} failed."


def _repair(
    provider: str,
    check: str,
    status: str,
    *,
    target: str = "",
    details: dict[str, Any] | None = None,
) -> str:
    if status == "passed":
        return "Nothing needed."
    if status == "skipped":
        return "No action needed unless this optional check matters for launch proof."
    if status == "pending":
        return _pending_repair(provider, check, target=target, details=details)
    if status == "needs_human_gate":
        return _human_gate_repair(provider, check, target=target, details=details)
    if status == "repairing":
        return (
            "Keep the control room open while FuseKit reruns the repair pass. "
            "Provider-owned approvals will resurface as guided launcher gates, and "
            "deterministic routes will retry through provider APIs."
        )
    return _failed_repair(provider, check, target=target, details=details)


def _pending_repair(
    provider: str,
    check: str,
    *,
    target: str = "",
    details: dict[str, Any] | None = None,
) -> str:
    if check == "provider_gate":
        capture_action = _capture_recovery_action(provider, target, details)
        return (
            "Finish the active upstream provider gate in the control room. Click "
            "Open provider gate in VM, complete the provider-owned step in that VM "
            f"browser, then click {capture_action} or I finished this step for "
            f"non-secret gates so FuseKit can verify {provider}."
        )
    if check == "dns_record_exists":
        return (
            "Cloudflare DNS record exists in Cloudflare but has not propagated yet. "
            "Keep waiting."
        )
    if check == "dns_propagated":
        return (
            "Keep waiting for DNS propagation; FuseKit should recheck until the "
            "provider confirms it."
        )
    if provider == "resend" and check == "domain_verified":
        return "Resend domain is pending. FuseKit will recheck DNS every 30 seconds."
    if provider == "vercel" and check == "deployment_url_exists":
        return "Vercel deployment is still warming up. FuseKit will keep checking."
    if check == "live_url_healthy":
        return (
            "Keep the control room open while FuseKit waits for deployment warmup "
            "and keeps retrying the live URL health check."
        )
    return (
        f"Keep the control room open for {provider}. FuseKit will recheck after the "
        "visible provider gate is captured or marked finished."
    )


def _human_gate_repair(
    provider: str,
    check: str,
    *,
    target: str = "",
    details: dict[str, Any] | None = None,
) -> str:
    capture_action = _capture_recovery_action(provider, target, details)
    return (
        f"FuseKit is waiting for the {provider} screen that controls {check.replace('_', ' ')}. "
        "Click Open provider gate in VM, complete only the provider-owned prompt, "
        f"then click {capture_action} or I finished this step for non-secret "
        "confirmation gates."
    )


def _failed_repair(
    provider: str,
    check: str,
    *,
    target: str = "",
    details: dict[str, Any] | None = None,
) -> str:
    if check == "configured":
        return (
            f"FuseKit will reapply {provider} environment variables or secrets through "
            "the provider API after any missing provider gate is captured."
        )
    if provider == "github" and check == "repo_secret_exists":
        return "GitHub repo secret is missing. FuseKit will reapply the missing secret."
    if provider == "github" and check == "deploy_key_exists":
        return "GitHub deploy key is missing. FuseKit will create a new deploy key."
    if provider == "vercel" and check == "env_vars_configured":
        return (
            "Vercel runtime env is missing after deploy. FuseKit will reapply the "
            "required env vars through Vercel's API, trigger the needed deployment "
            "refresh, and surface a guided launcher gate if Vercel needs human approval."
        )
    if provider == "vercel" and check == "project_exists":
        return "Vercel project is missing. FuseKit will recreate or reconnect the project."
    if provider == "cloudflare" and check == "dns_record_exists":
        return "Cloudflare DNS record is missing. FuseKit will reapply the DNS record."
    if provider == "resend" and check == "domain_verified":
        return (
            "Resend domain is missing. FuseKit will rerun Resend domain setup first, "
            "then apply the DNS records Resend returns."
        )
    if check == "webhook_secret_present":
        return "Webhook signature secret is missing. FuseKit will regenerate and store it."
    if check == "auth_valid":
        capture_action = _capture_recovery_action(provider, target, details)
        return (
            f"Create or recapture the approved {provider} token inside the VM browser, "
            f"then click {capture_action}."
        )
    if check == "dns_propagated":
        return (
            "Keep the control room open while FuseKit compares the approved DNS plan "
            "to provider records, reapplies missing records through the DNS API, and "
            "keeps checking propagation."
        )
    if check == "live_url_healthy":
        return (
            "Keep the control room open. FuseKit will retry the live URL health check, "
            "reapply provider setup through API routes where possible, and surface a "
            "guided launcher gate if a provider needs human approval."
        )
    return (
        f"FuseKit will reopen {provider} through the launcher or retry the provider API; "
        "use only the visible control-room gate if the provider asks for human approval."
    )


def _capture_recovery_action(
    provider: str,
    target: str,
    details: dict[str, Any] | None,
) -> str:
    targets = _capture_targets(provider, target, details)
    if not targets:
        return "the target-specific Capture from VM clipboard button for copy-once values"
    labels = [f"Capture {candidate} from VM clipboard" for candidate in targets]
    if len(labels) == 1:
        return labels[0]
    return "each target-specific Capture button: " + ", ".join(labels)


def _capture_targets(
    provider: str,
    target: str,
    details: dict[str, Any] | None,
) -> tuple[str, ...]:
    found: list[str] = []
    _collect_capture_targets(target, found)
    _collect_capture_targets(details or {}, found)
    if not found:
        found.extend(DEFAULT_CAPTURE_TARGETS_BY_PROVIDER.get(provider.lower(), ()))
    unique: list[str] = []
    for candidate in found:
        upper = candidate.strip().upper()
        if upper and upper not in unique:
            unique.append(upper)
    return tuple(unique)


def _collect_capture_targets(value: Any, found: list[str]) -> None:
    if isinstance(value, str):
        found.extend(CAPTURE_TARGET_RE.findall(value))
        return
    if isinstance(value, dict):
        for key, child in value.items():
            _collect_capture_targets(key, found)
            _collect_capture_targets(child, found)
        return
    if isinstance(value, (list, tuple, set)):
        for child in value:
            _collect_capture_targets(child, found)


def _readable_check(check: str) -> str:
    return check.replace("_", " ")
