"""Setup planning engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from fusekit.manifest import SetupManifest

ActionKind = Literal["automatic", "user_required", "approval_required"]


@dataclass(frozen=True)
class SetupAction:
    """One planned setup action."""

    id: str
    kind: ActionKind
    provider: str
    summary: str
    risk: str = "low"


@dataclass(frozen=True)
class SetupPlan:
    """A setup plan generated from a manifest."""

    app_name: str
    actions: tuple[SetupAction, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the setup plan."""

        return {
            "app_name": self.app_name,
            "actions": [
                {
                    "id": action.id,
                    "kind": action.kind,
                    "provider": action.provider,
                    "summary": action.summary,
                    "risk": action.risk,
                }
                for action in self.actions
            ],
        }


def build_plan(manifest: SetupManifest) -> SetupPlan:
    """Build a fail-closed setup plan."""

    actions: list[SetupAction] = []
    actions.append(
        SetupAction(
            id="vault.create",
            kind="automatic",
            provider="fusekit",
            summary="Create or unlock the encrypted FuseKit vault.",
        )
    )
    for service in manifest.services:
        provider = service.provider.lower()
        if service.kind == "provider-pack" or "capability_pack" in service.capabilities:
            pack_path = service.settings.get("capability_pack", "")
            actions.append(
                SetupAction(
                    id=f"{provider}.capability_pack.synthesize",
                    kind="automatic",
                    provider=provider,
                    summary=(
                        f"Synthesize and validate a provider capability pack"
                        f"{f' at {pack_path}' if pack_path else ''}."
                    ),
                )
            )
            if provider == "github":
                actions.extend(
                    (
                        SetupAction(
                            id="github.authorize",
                            kind="user_required",
                            provider="github",
                            summary="Authorize GitHub through pack-driven handoff.",
                        ),
                        SetupAction(
                            id="github.configure_repo",
                            kind="automatic",
                            provider="github",
                            summary="Run GitHub pack recipes for deploy keys and repo secrets.",
                        ),
                    )
                )
            elif provider == "vercel":
                actions.extend(
                    (
                        SetupAction(
                            id="vercel.authorize",
                            kind="user_required",
                            provider="vercel",
                            summary="Authorize Vercel through pack-driven handoff.",
                        ),
                        SetupAction(
                            id="vercel.configure_project",
                            kind="automatic",
                            provider="vercel",
                            summary="Run Vercel pack recipes for project and env setup.",
                        ),
                        SetupAction(
                            id="vercel.deploy_verify",
                            kind="automatic",
                            provider="vercel",
                            summary="Run Vercel pack deployment and live URL verification recipes.",
                        ),
                    )
                )
            else:
                actions.extend(
                    (
                        SetupAction(
                            id=f"{provider}.authorize",
                            kind="user_required",
                            provider=provider,
                            summary=(
                                f"Use OpenClaw guided browser setup for {provider}; wait "
                                "durably at provider login, MFA, CAPTCHA, payment, consent, "
                                "or secret gates."
                            ),
                            risk="medium",
                        ),
                        SetupAction(
                            id=f"{provider}.configure_verify",
                            kind="automatic",
                            provider=provider,
                            summary=(
                                f"Run {provider} pack setup and verification recipes without "
                                "exposing raw secrets."
                            ),
                        ),
                    )
                )
        elif provider == "github":
            actions.extend(
                (
                    SetupAction(
                        id="github.authorize",
                        kind="user_required",
                        provider="github",
                        summary="Authorize GitHub with a scoped token or app installation.",
                    ),
                    SetupAction(
                        id="github.configure_repo",
                        kind="automatic",
                        provider="github",
                        summary=(
                            "Configure repo secrets and deploy keys without exposing raw values."
                        ),
                    ),
                )
            )
        elif provider == "vercel":
            actions.extend(
                (
                    SetupAction(
                        id="vercel.authorize",
                        kind="user_required",
                        provider="vercel",
                        summary="Authorize Vercel with a scoped token after any login or MFA.",
                    ),
                    SetupAction(
                        id="vercel.configure_project",
                        kind="automatic",
                        provider="vercel",
                        summary=(
                            "Create or connect the Vercel project and set environment variables."
                        ),
                    ),
                    SetupAction(
                        id="vercel.deploy_verify",
                        kind="automatic",
                        provider="vercel",
                        summary="Deploy the app and verify the live URL.",
                    ),
                )
            )
        elif provider in {"cloudflare", "dns"}:
            actions.append(
                SetupAction(
                    id="dns.propose",
                    kind="automatic",
                    provider=provider,
                    summary="Propose DNS records and rollback metadata.",
                )
            )
            actions.append(
                SetupAction(
                    id="dns.apply",
                    kind="approval_required",
                    provider=provider,
                    summary="Apply DNS records only after explicit approval.",
                    risk="high",
                )
            )
        elif provider == "hosting" and service.kind == "deployment-choice":
            actions.append(
                SetupAction(
                    id="hosting.select_provider",
                    kind="user_required",
                    provider="hosting",
                    summary=(
                        "Select the deployment host before FuseKit proposes provider-specific "
                        "setup, DNS, or rollback steps."
                    ),
                    risk="medium",
                )
            )
        else:
            actions.append(
                SetupAction(
                    id=f"{provider}.authorize",
                    kind="user_required",
                    provider=provider,
                    summary=(
                        f"Authorize {provider}; synthesize a capability pack or install an adapter "
                        "before applying real setup."
                    ),
                    risk="medium",
                )
            )
    for domain in manifest.domains:
        actions.append(
            SetupAction(
                id=f"dns.propose.{domain.domain}",
                kind="automatic",
                provider=domain.provider,
                summary=f"Propose DNS records for {domain.domain}.",
            )
        )
        actions.append(
            SetupAction(
                id=f"dns.apply.{domain.domain}",
                kind="approval_required",
                provider=domain.provider,
                summary=f"Apply DNS records for {domain.domain} after approval.",
                risk="high",
            )
        )
    for webhook in manifest.webhooks:
        actions.append(
            SetupAction(
                id=f"webhook.secret.{webhook.name}",
                kind="automatic",
                provider="fusekit",
                summary=f"Generate and store webhook secret for {webhook.name}.",
            )
        )
    actions.append(
        SetupAction(
            id="receipt.write",
            kind="automatic",
            provider="fusekit",
            summary="Write redacted audit log and setup receipt.",
        )
    )
    actions.append(
        SetupAction(
            id="detonate.worker_state",
            kind="automatic",
            provider="fusekit",
            summary="Destroy plaintext worker state while preserving encrypted vault artifacts.",
        )
    )
    return SetupPlan(app_name=manifest.app_name, actions=tuple(actions))
