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
VERIFICATION_REPORT_SCHEMA_VERSION = "fusekit.verification-report.v1"
VERIFICATION_REPORT_PROVIDER_FIELD = "provider"
VERIFICATION_REPORT_CHECK_FIELD = "check"
VERIFICATION_REPORT_STATUS_FIELD = "status"
VERIFICATION_REPORT_SUMMARY_FIELD = "summary"
VERIFICATION_REPORT_REPAIR_FIELD = "repair"
VERIFICATION_REPORT_DETAILS_FIELD = "details"
VERIFICATION_REPORT_CHECK_FIELDS = (
    VERIFICATION_REPORT_PROVIDER_FIELD,
    VERIFICATION_REPORT_CHECK_FIELD,
    VERIFICATION_REPORT_STATUS_FIELD,
    VERIFICATION_REPORT_SUMMARY_FIELD,
    VERIFICATION_REPORT_REPAIR_FIELD,
    VERIFICATION_REPORT_DETAILS_FIELD,
)
VERIFICATION_REPORT_CHECK_KEYS = frozenset(VERIFICATION_REPORT_CHECK_FIELDS)
VERIFICATION_REPORT_REQUIRED_TEXT_FIELDS = (
    VERIFICATION_REPORT_PROVIDER_FIELD,
    VERIFICATION_REPORT_CHECK_FIELD,
    VERIFICATION_REPORT_STATUS_FIELD,
)
VERIFICATION_REPORT_OPTIONAL_TEXT_FIELDS = (
    VERIFICATION_REPORT_SUMMARY_FIELD,
    VERIFICATION_REPORT_REPAIR_FIELD,
)
VERIFICATION_STATUS_PASSED = "passed"
VERIFICATION_STATUS_PENDING = "pending"
VERIFICATION_STATUS_REPAIRING = "repairing"
VERIFICATION_STATUS_FAILED = "failed"
VERIFICATION_STATUS_SKIPPED = "skipped"
VERIFICATION_STATUS_NEEDS_HUMAN_GATE = "needs_human_gate"
VERIFICATION_REPORT_STATUS_FIELDS = (
    VERIFICATION_STATUS_PASSED,
    VERIFICATION_STATUS_PENDING,
    VERIFICATION_STATUS_REPAIRING,
    VERIFICATION_STATUS_FAILED,
    VERIFICATION_STATUS_SKIPPED,
    VERIFICATION_STATUS_NEEDS_HUMAN_GATE,
)
VERIFICATION_REPORT_SAFE_STATUSES = frozenset(
    {VERIFICATION_STATUS_PASSED, VERIFICATION_STATUS_SKIPPED}
)
VERIFICATION_REPORT_PENDING_SAFE_CHECKS = frozenset(
    {
        "dns_propagated",
        "dns_record_exists",
        "domain_verified",
        "deployment_url_exists",
    }
)


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
            VERIFICATION_REPORT_PROVIDER_FIELD: self.provider,
            VERIFICATION_REPORT_CHECK_FIELD: self.check,
            VERIFICATION_REPORT_STATUS_FIELD: self.status,
            VERIFICATION_REPORT_SUMMARY_FIELD: self.summary,
            VERIFICATION_REPORT_REPAIR_FIELD: self.repair,
            VERIFICATION_REPORT_DETAILS_FIELD: redact(self.details),
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
        status = (
            VERIFICATION_STATUS_PASSED
            if ok
            else VERIFICATION_STATUS_PENDING
            if pending_safe
            else VERIFICATION_STATUS_FAILED
        )
        self.checks.append(
            VerificationCheck(
                provider="live_app",
                check="live_url_healthy",
                status=status,
                summary=(
                    "The deployed app answered successfully."
                    if status == VERIFICATION_STATUS_PASSED
                    else "The live URL has not become reachable yet."
                    if status == VERIFICATION_STATUS_PENDING
                    else "The deployed app did not answer successfully yet."
                ),
                repair=(
                    "Nothing needed."
                    if status == VERIFICATION_STATUS_PASSED
                    else (
                        "Keep the control room open while FuseKit retries DNS and deployment "
                        "health checks; any provider-owned blocker will resurface as a guided "
                        "launcher gate."
                    )
                    if status == VERIFICATION_STATUS_PENDING
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

        counts = {status: 0 for status in VERIFICATION_REPORT_STATUS_FIELDS}
        for check in self.checks:
            if check.status in counts:
                counts[check.status] += 1
        overall = VERIFICATION_STATUS_PENDING if not self.checks else VERIFICATION_STATUS_PASSED
        if counts[VERIFICATION_STATUS_FAILED]:
            overall = VERIFICATION_STATUS_FAILED
        elif counts[VERIFICATION_STATUS_REPAIRING]:
            overall = VERIFICATION_STATUS_REPAIRING
        elif counts[VERIFICATION_STATUS_NEEDS_HUMAN_GATE]:
            overall = VERIFICATION_STATUS_NEEDS_HUMAN_GATE
        elif counts[VERIFICATION_STATUS_PENDING]:
            overall = VERIFICATION_STATUS_PENDING
        return {
            "schema_version": VERIFICATION_REPORT_SCHEMA_VERSION,
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
        return VERIFICATION_STATUS_PASSED
    if status == "skipped":
        return VERIFICATION_STATUS_SKIPPED
    if status == "pending":
        return VERIFICATION_STATUS_PENDING
    if status == "needs_human_gate":
        return VERIFICATION_STATUS_NEEDS_HUMAN_GATE
    if repaired:
        return VERIFICATION_STATUS_REPAIRING
    return VERIFICATION_STATUS_FAILED


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
        return (
            "This optional proof check was skipped. Keep going unless the launch "
            "plan explicitly marks this proof as required."
        )
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
        completion_action = _provider_gate_completion_action(provider, target, details)
        return (
            "Finish the active upstream provider gate in the control room. Click "
            "Open provider gate in VM, complete the provider-owned step in that VM "
            f"browser, then {completion_action} so FuseKit can verify {provider}."
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
    completion_action = _provider_gate_completion_action(provider, target, details)
    return (
        f"FuseKit is waiting for the {provider} screen that controls {check.replace('_', ' ')}. "
        "Click Open provider gate in VM, complete only the provider-owned prompt, "
        f"then {completion_action}."
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
        return (
            "the exact Capture button named on the active launcher gate. If no "
            "Capture button is visible, keep the control room open while FuseKit "
            "rebuilds the provider proof and surfaces one highlighted next action"
        )
    labels = [f"Capture {candidate} from VM clipboard" for candidate in targets]
    if len(labels) == 1:
        return labels[0]
    return "these exact Capture buttons: " + ", ".join(labels)


def _provider_gate_completion_action(
    provider: str,
    target: str,
    details: dict[str, Any] | None,
) -> str:
    """Return one visible control path for the provider gate repair."""

    targets = _capture_targets(provider, target, details, include_defaults=False)
    if not targets and _looks_like_token_gate_target(target):
        targets = _capture_targets(provider, "", details, include_defaults=True)
    if targets:
        labels = [f"Capture {candidate} from VM clipboard" for candidate in targets]
        if len(labels) == 1:
            return f"copy the provider value inside the VM browser and click {labels[0]}"
        return (
            "copy each provider value inside the VM browser and click these exact "
            "Capture buttons: "
            + ", ".join(labels)
        )
    return (
        "follow the single highlighted next action on the active launcher gate. "
        "Click I finished this step only after the provider confirms; if the gate "
        "names an env-specific Capture button for a copy-once value, use that "
        "exact Capture button instead"
    )


def _looks_like_token_gate_target(target: str) -> bool:
    normalized = target.strip().lower().replace("_", "-")
    return normalized.endswith(".token") or any(
        marker in normalized for marker in (".api-key", "-api-key", ".api-token", "-api-token")
    )


def _capture_targets(
    provider: str,
    target: str,
    details: dict[str, Any] | None,
    *,
    include_defaults: bool = True,
) -> tuple[str, ...]:
    found: list[str] = []
    _collect_capture_targets(target, found)
    _collect_capture_targets(details or {}, found)
    if not found and include_defaults:
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
