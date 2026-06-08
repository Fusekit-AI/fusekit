"""Provider UI setup playbooks for computer-use spines."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fusekit.providers.handoff import ProviderHandoff, handoff_for
from fusekit.spine.playbooks import BrowserPlaybookEvent


class ComputerUseSpine(Protocol):
    """Computer-use actions FuseKit needs for provider UI automation."""

    def start(self) -> object:
        """Start browser control."""

    def open(self, url: str) -> object:
        """Open a URL."""

    def snapshot(self) -> object:
        """Capture page state."""

    def click_text(self, text: str) -> object:
        """Click visible text or button."""

    def wait_for_text(self, text: str) -> object:
        """Wait for visible text."""


@dataclass(frozen=True)
class ProviderUiStep:
    """One non-secret UI automation step."""

    action: str
    target: str = ""
    url: str = ""
    optional: bool = True
    service_gate: bool = False
    note: str = ""


@dataclass(frozen=True)
class ProviderUiPlaybook:
    """Provider UI setup playbook."""

    provider: str
    steps: tuple[ProviderUiStep, ...]


def provider_ui_playbook(provider: str, include_project: bool = False) -> ProviderUiPlaybook:
    """Return a provider-specific UI playbook."""

    provider_key = provider.strip().lower()
    handoff = handoff_for(provider_key)
    common = _common_steps(
        handoff,
        include_project=include_project and provider_key != "resend",
    )
    specific: tuple[ProviderUiStep, ...]
    if provider_key == "github":
        specific = (
            ProviderUiStep("click_text", "Generate new token", note="Start token creation."),
            ProviderUiStep("click_text", "Repository permissions", note="Open repo permissions."),
            ProviderUiStep(
                "click_text",
                "Secrets",
                note="Grant the highlighted secrets permission.",
            ),
            ProviderUiStep(
                "click_text",
                "Deploy keys",
                note="Grant the highlighted deploy-key access.",
            ),
        )
    elif provider_key == "vercel":
        specific = (
            ProviderUiStep("click_text", "Add New", note="Start project import if needed."),
            ProviderUiStep("click_text", "Import", note="Import selected Git repository."),
            ProviderUiStep("click_text", "Environment Variables", note="Open env settings."),
            ProviderUiStep("click_text", "Deploy", note="Trigger deployment if project is ready."),
        )
    elif provider_key == "cloudflare":
        specific = (
            ProviderUiStep("click_text", "Websites", note="Open zone list."),
            ProviderUiStep("click_text", "DNS", note="Open DNS records."),
            ProviderUiStep("click_text", "Create Token", note="Start scoped DNS token flow."),
        )
    elif provider_key == "resend":
        specific = (
            ProviderUiStep("click_text", "API Keys", note="Open Resend API key page."),
            ProviderUiStep(
                "click_text",
                "Create API Key",
                note=(
                    "Create a Full access setup key only. Do not create Resend domains "
                    "or audiences here; FuseKit creates or reuses them through Resend's "
                    "API after Capture succeeds."
                ),
            ),
        )
    else:
        specific = ()
    return ProviderUiPlaybook(
        provider=provider_key,
        steps=common + specific + _capture_steps(handoff),
    )


def execute_provider_ui_playbook(
    playbook: ProviderUiPlaybook,
    spine: ComputerUseSpine,
) -> list[BrowserPlaybookEvent]:
    """Execute a provider UI playbook as far as service gates allow."""

    events = [
        BrowserPlaybookEvent(
            provider=playbook.provider,
            action="policy.boundary",
            status="service-gates-required",
            note=(
                "FuseKit may click, type, copy, and navigate like a human, but the user "
                "must complete provider login, MFA, CAPTCHA, payment, fraud checks, and consent."
            ),
        )
    ]
    spine.start()
    for step in playbook.steps:
        try:
            if step.action == "open":
                spine.open(step.url)
                spine.snapshot()
            elif step.action == "click_text":
                spine.click_text(step.target)
                spine.snapshot()
            elif step.action == "wait_for_text":
                spine.wait_for_text(step.target)
                spine.snapshot()
            elif step.action == "service_gate":
                events.append(
                    BrowserPlaybookEvent(
                        provider=playbook.provider,
                        action=step.action,
                        status="waiting",
                        url=step.url,
                        note=step.note,
                    )
                )
                continue
            else:
                continue
        except Exception as exc:
            status = "skipped" if step.optional else "blocked"
            events.append(
                BrowserPlaybookEvent(
                    provider=playbook.provider,
                    action=step.action,
                    status=status,
                    url=step.url,
                    note=f"{step.note} ({type(exc).__name__})",
                )
            )
            if not step.optional:
                break
            continue
        events.append(
            BrowserPlaybookEvent(
                provider=playbook.provider,
                action=step.action,
                status="ok",
                url=step.url,
                note=step.note,
            )
        )
    return events


def _common_steps(
    handoff: ProviderHandoff,
    *,
    include_project: bool,
) -> tuple[ProviderUiStep, ...]:
    steps = [
        ProviderUiStep("open", url=handoff.signup_url, optional=False, note="Open signup/login."),
        ProviderUiStep(
            "service_gate",
            url=handoff.signup_url,
            service_gate=True,
            note="Complete only the highlighted provider login/MFA/CAPTCHA/account gate.",
        ),
        ProviderUiStep(
            "open",
            url=handoff.token_url,
            optional=False,
            note="Open token/API key page.",
        ),
    ]
    if include_project:
        steps.append(
            ProviderUiStep(
                "open",
                url=handoff.project_url,
                optional=True,
                note="Open project/resource creation page.",
            )
        )
    return tuple(steps)


def _capture_steps(handoff: ProviderHandoff) -> tuple[ProviderUiStep, ...]:
    return (
        ProviderUiStep(
            "service_gate",
            service_gate=True,
            note=(
                f"After the provider reveals the approved secret, copy {handoff.token_env} "
                "inside the VM browser and use the matching Capture button so FuseKit "
                "saves it directly into the encrypted vault."
            ),
        ),
    )
