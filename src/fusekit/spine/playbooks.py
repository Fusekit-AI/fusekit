"""Provider authorization playbooks executed through a browser spine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fusekit.providers.handoff import ProviderHandoff, handoff_for


class BrowserSpine(Protocol):
    """Browser automation surface FuseKit needs from a spine."""

    def start(self) -> object:
        """Start browser control."""

    def open(self, url: str) -> object:
        """Open a URL."""

    def snapshot(self) -> object:
        """Capture a browser snapshot."""


@dataclass(frozen=True)
class BrowserPlaybookEvent:
    """One non-secret playbook event."""

    provider: str
    action: str
    status: str
    url: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize the event."""

        return {
            "provider": self.provider,
            "action": self.action,
            "status": self.status,
            "url": self.url,
            "note": self.note,
        }


def provider_authorization_playbook(
    provider: str,
    spine: BrowserSpine,
    include_project: bool = False,
) -> list[BrowserPlaybookEvent]:
    """Run a supervised provider authorization playbook."""

    handoff = handoff_for(provider)
    return provider_handoff_playbook(handoff, spine, include_project=include_project)


def provider_handoff_playbook(
    handoff: ProviderHandoff,
    spine: BrowserSpine,
    include_project: bool = False,
) -> list[BrowserPlaybookEvent]:
    """Run a supervised handoff playbook from handoff metadata."""

    events = [
        BrowserPlaybookEvent(
            provider=handoff.provider,
            action="policy.boundary",
            status="manual-gates-required",
            note=(
                "FuseKit may navigate provider pages; the human only completes highlighted "
                "login, MFA, CAPTCHA, billing, fraud-check, or consent prompts."
            ),
        )
    ]
    spine.start()
    for url in handoff.urls(include_project=include_project):
        spine.open(url)
        spine.snapshot()
        events.append(
            BrowserPlaybookEvent(
                provider=handoff.provider,
                action="open",
                status="ok",
                url=url,
                note=_note_for_url(handoff, url),
            )
        )
    events.append(
        BrowserPlaybookEvent(
            provider=handoff.provider,
            action="capture",
            status="awaiting-approved-secret",
            note=(
                f"After creating the scoped token, copy {handoff.token_env} inside the "
                f"VM browser and click Capture {handoff.token_env} from VM clipboard so "
                "FuseKit saves it directly into the encrypted vault."
            ),
        )
    )
    return events


def _note_for_url(handoff: ProviderHandoff, url: str) -> str:
    if url == handoff.signup_url:
        return "Create or sign in to the provider account."
    if url == handoff.token_url:
        return "Create a scoped provider token or API credential."
    if url == handoff.project_url:
        return "Create or connect the provider project/resource."
    return "Provider handoff URL."
