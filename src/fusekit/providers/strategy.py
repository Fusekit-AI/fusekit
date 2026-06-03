"""Provider setup strategy selection.

FuseKit's public lane should feel like one magic path, but internally each
provider action needs a ranked strategy graph: API when proven available,
official CLI when supported, then guided browser and human follow-me gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fusekit.providers.capability_pack import ProviderCapabilityPack, SetupRecipe

API_SETUP_KINDS = {
    "github-deploy-key",
    "github-repo-secrets",
    "vercel-project",
    "vercel-env",
    "vercel-git-deployment",
    "cloudflare-dns",
}
LOCAL_SETUP_KINDS = {"vault-capture-env"}
CLI_BY_PROVIDER = {
    "github": "gh",
    "vercel": "vercel",
    "cloudflare": "wrangler",
}


@dataclass(frozen=True)
class StrategySignal:
    """Runtime facts used to select a provider setup route."""

    token_available: bool = False
    cli_tools: frozenset[str] = frozenset()
    browser_available: bool = True
    human_gate_allowed: bool = True
    approve_dns: bool = False


@dataclass(frozen=True)
class ProviderStrategy:
    """One possible way to accomplish a provider setup recipe."""

    kind: str
    label: str
    priority: int
    status: str
    deterministic: bool
    implemented: bool
    reason: str
    evidence: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize strategy evidence for receipts and audits."""

        return {
            "kind": self.kind,
            "label": self.label,
            "priority": self.priority,
            "status": self.status,
            "deterministic": self.deterministic,
            "implemented": self.implemented,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class ProviderStrategyDecision:
    """Selected strategy plus the alternatives FuseKit considered."""

    provider: str
    recipe_kind: str
    selected: ProviderStrategy
    candidates: tuple[ProviderStrategy, ...]

    @property
    def executable(self) -> bool:
        """Whether FuseKit can execute the selected route in this process."""

        return self.selected.implemented and self.selected.status == "available"

    def to_dict(self) -> dict[str, object]:
        """Serialize the decision without secrets."""

        return {
            "provider": self.provider,
            "recipe_kind": self.recipe_kind,
            "selected": self.selected.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def choose_provider_strategy(
    pack: ProviderCapabilityPack,
    recipe: SetupRecipe,
    signal: StrategySignal,
) -> ProviderStrategyDecision:
    """Choose the most reliable available route for a provider recipe."""

    provider = pack.provider.lower()
    if recipe.kind in LOCAL_SETUP_KINDS:
        local_candidates = (
            ProviderStrategy(
                kind="local_vault",
                label="Local encrypted vault capture",
                priority=0,
                status="available",
                deterministic=True,
                implemented=True,
                reason="This recipe only moves already-approved values into the vault.",
            ),
        )
        return ProviderStrategyDecision(
            provider,
            recipe.kind,
            local_candidates[0],
            local_candidates,
        )

    candidates = _candidate_strategies(pack, recipe, signal)
    selected = _select_candidate(candidates)
    return ProviderStrategyDecision(provider, recipe.kind, selected, tuple(candidates))


def _candidate_strategies(
    pack: ProviderCapabilityPack,
    recipe: SetupRecipe,
    signal: StrategySignal,
) -> list[ProviderStrategy]:
    provider = pack.provider.lower()
    candidates: list[ProviderStrategy] = []
    if recipe.kind in API_SETUP_KINDS:
        candidates.append(
            ProviderStrategy(
                kind="api",
                label="Provider-native API",
                priority=10,
                status="available" if signal.token_available else "blocked",
                deterministic=True,
                implemented=True,
                reason=(
                    "Provider token is available for deterministic setup."
                    if signal.token_available
                    else "Provider token is missing; a human authorization gate must run first."
                ),
                evidence={"token_available": str(signal.token_available).lower()},
            )
        )

    cli_tool = CLI_BY_PROVIDER.get(provider, "")
    if cli_tool:
        cli_available = cli_tool in signal.cli_tools
        candidates.append(
            ProviderStrategy(
                kind="official_cli",
                label=f"Official {cli_tool} CLI",
                priority=20,
                status="available" if cli_available else "unavailable",
                deterministic=True,
                implemented=False,
                reason=(
                    f"{cli_tool} is installed, but CLI execution is not enabled "
                    "for this recipe yet."
                    if cli_available
                    else f"{cli_tool} is not installed in the runner."
                ),
                evidence={"tool": cli_tool, "installed": str(cli_available).lower()},
            )
        )

    handoff_url = _handoff_url(pack)
    candidates.append(
        ProviderStrategy(
            kind="browser_guided",
            label="Guided provider browser",
            priority=30,
            status="available" if signal.browser_available and handoff_url else "unavailable",
            deterministic=False,
            implemented=False,
            reason=(
                "Provider handoff URL is available; FuseKit can guide the user through gates."
                if signal.browser_available and handoff_url
                else "No usable provider handoff URL/browser surface is available."
            ),
            evidence={"handoff_url": handoff_url},
        )
    )
    candidates.append(
        ProviderStrategy(
            kind="human_follow_me",
            label="Human follow-me",
            priority=40,
            status="available" if signal.human_gate_allowed and handoff_url else "unavailable",
            deterministic=False,
            implemented=False,
            reason=(
                "The user can complete provider-owned gates with step-by-step guidance."
                if signal.human_gate_allowed and handoff_url
                else "No human-gate route is available for this provider."
            ),
            evidence={"handoff_url": handoff_url},
        )
    )
    if not candidates:
        candidates.append(
            ProviderStrategy(
                kind="unsupported",
                label="Unsupported recipe",
                priority=100,
                status="blocked",
                deterministic=False,
                implemented=False,
                reason=f"No setup strategy is registered for recipe kind: {recipe.kind}",
            )
        )
    return candidates


def _select_candidate(candidates: list[ProviderStrategy]) -> ProviderStrategy:
    executable = [
        candidate
        for candidate in candidates
        if candidate.status == "available" and candidate.implemented
    ]
    if executable:
        return sorted(executable, key=lambda candidate: candidate.priority)[0]
    available = [candidate for candidate in candidates if candidate.status == "available"]
    if available:
        return sorted(available, key=lambda candidate: candidate.priority)[0]
    return sorted(candidates, key=lambda candidate: candidate.priority)[0]


def _handoff_url(pack: ProviderCapabilityPack) -> str:
    for value in (
        pack.handoff.project_url,
        pack.handoff.token_url,
        pack.handoff.login_url,
        pack.handoff.signup_url,
    ):
        if value:
            return value
    return ""


def summarize_strategy_action(decision: ProviderStrategyDecision) -> dict[str, Any]:
    """Return a compact next-action payload for blocked provider setup."""

    selected = decision.selected
    return {
        "provider": decision.provider,
        "recipe": decision.recipe_kind,
        "strategy": selected.kind,
        "status": "needs_human_gate"
        if selected.kind in {"browser_guided", "human_follow_me"}
        else selected.status,
        "reason": selected.reason,
        "next_action": (
            "Open the provider gate, complete login/MFA/CAPTCHA/consent/token creation, "
            "then let FuseKit capture the approved capability."
            if selected.kind in {"browser_guided", "human_follow_me"}
            else "Install or authorize a deterministic provider route, then retry."
        ),
    }
