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
    "resend-domain",
    "resend-audience",
}
API_ACCOUNT_CREATION_SETUP_KINDS: set[str] = set()
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


def choose_account_creation_strategy(
    pack: ProviderCapabilityPack,
    signal: StrategySignal,
) -> ProviderStrategyDecision:
    """Choose the safest available route for creating or connecting a provider account."""

    provider = pack.provider.lower()
    mode = pack.handoff.account_creation
    recipe_kind = pack.handoff.account_creation_recipe or "account.creation"
    candidates: list[ProviderStrategy] = []
    if mode == "api":
        implemented = recipe_kind in API_ACCOUNT_CREATION_SETUP_KINDS
        candidates.append(
            ProviderStrategy(
                kind="api",
                label="Provider account API",
                priority=10,
                status="available" if signal.token_available else "blocked",
                deterministic=True,
                implemented=implemented,
                reason=(
                    "Provider pack declares an API account creation recipe."
                    if implemented
                    else (
                        "Provider pack declares API account creation, "
                        "but no executor is registered."
                    )
                ),
                evidence={"recipe": recipe_kind},
            )
        )
    elif mode == "none":
        candidates.append(
            ProviderStrategy(
                kind="unsupported",
                label="Account creation unavailable",
                priority=100,
                status="blocked",
                deterministic=False,
                implemented=False,
                reason=pack.handoff.account_creation_reason,
            )
        )
    else:
        handoff_url = _account_handoff_url(pack)
        candidates.append(
            ProviderStrategy(
                kind="browser_guided",
                label="Guided provider signup",
                priority=30,
                status="available" if signal.browser_available and handoff_url else "unavailable",
                deterministic=False,
                implemented=False,
                reason=pack.handoff.account_creation_reason,
                evidence={"handoff_url": handoff_url},
            )
        )
        candidates.append(
            ProviderStrategy(
                kind="human_follow_me",
                label="Human follow-me signup",
                priority=40,
                status="available" if signal.human_gate_allowed and handoff_url else "unavailable",
                deterministic=False,
                implemented=False,
                reason="The user can complete provider-owned signup gates with guidance.",
                evidence={"handoff_url": handoff_url},
            )
        )
    selected = _select_candidate(candidates)
    return ProviderStrategyDecision(provider, "account.creation", selected, tuple(candidates))


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
                reason=_api_strategy_reason(provider, recipe.kind, signal),
                evidence=_api_strategy_evidence(provider, recipe.kind, signal),
            )
        )

    cli_tool = CLI_BY_PROVIDER.get(provider, "")
    if cli_tool:
        cli_available = cli_tool in signal.cli_tools
        cli_implemented = False
        candidates.append(
            ProviderStrategy(
                kind="official_cli",
                label=f"Official {cli_tool} CLI",
                priority=20,
                status="available" if cli_available and cli_implemented else "unavailable",
                deterministic=True,
                implemented=cli_implemented,
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
                else "No usable provider handoff URL or VM browser is available."
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


def _api_strategy_reason(provider: str, recipe_kind: str, signal: StrategySignal) -> str:
    if provider == "resend":
        if recipe_kind == "resend-domain":
            if signal.token_available:
                return (
                    "RESEND_API_KEY is available; FuseKit will create or reuse the "
                    "sending domain through Resend's API and hand DNS records to DNS."
                )
            return (
                "RESEND_API_KEY is missing; capture a Full access setup key before "
                "FuseKit creates or reuses the Resend sending domain."
            )
        if recipe_kind == "resend-audience":
            if signal.token_available:
                return (
                    "RESEND_API_KEY is available; FuseKit will create or reuse a "
                    "Resend audience only if the app requires one."
                )
            return (
                "RESEND_API_KEY is missing; capture the setup key before FuseKit can "
                "create or reuse a required Resend audience."
            )
    return (
        "Provider token is available for deterministic setup."
        if signal.token_available
        else "Provider token is missing; a human authorization gate must run first."
    )


def _api_strategy_evidence(
    provider: str,
    recipe_kind: str,
    signal: StrategySignal,
) -> dict[str, str]:
    evidence = {"token_available": str(signal.token_available).lower()}
    if provider == "resend" and recipe_kind == "resend-domain":
        evidence.update(
            {
                "api_owns": "domain",
                "user_manual_domain_step": "false",
                "downstream_order": "before_dns_apply",
            }
        )
    elif provider == "resend" and recipe_kind == "resend-audience":
        evidence.update(
            {
                "api_owns": "audience",
                "user_manual_audience_step": "false",
                "conditional": "only_when_app_requires_audience",
            }
        )
    return evidence


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
        pack.handoff.token_url,
        pack.handoff.login_url,
        pack.handoff.signup_url,
        pack.handoff.project_url,
    ):
        if value:
            return value
    return ""


def _account_handoff_url(pack: ProviderCapabilityPack) -> str:
    for value in (pack.handoff.signup_url, pack.handoff.login_url, pack.handoff.project_url):
        if value:
            return value
    return ""


def summarize_strategy_action(
    decision: ProviderStrategyDecision,
    pack: ProviderCapabilityPack | None = None,
) -> dict[str, Any]:
    """Return a compact next-action payload for blocked provider setup."""

    selected = decision.selected
    resume_url = selected.evidence.get("handoff_url", "")
    needs_human_gate = selected.kind in {"browser_guided", "human_follow_me"}
    target = pack.handoff.token_env if pack is not None else ""
    action = {
        "provider": decision.provider,
        "recipe": decision.recipe_kind,
        "strategy": selected.kind,
        "status": "needs_human_gate" if needs_human_gate else selected.status,
        "reason": selected.reason,
        "resume_url": resume_url,
        "next_action": (
            "Click Open provider gate in VM, complete login/MFA/CAPTCHA/consent/token "
            "creation in the VM browser, then copy any revealed token and click the "
            "matching Capture from VM clipboard button. Do not paste it into your "
            "computer; Capture reads the VM clipboard directly."
            if needs_human_gate
            else "Install or authorize a deterministic provider route, then retry."
        ),
        "follow_steps": _strategy_follow_steps(pack) if needs_human_gate else (),
        "resume_hint": (
            "FuseKit will retry this provider route after the visible gate is finished "
            "or every requested value is captured."
            if needs_human_gate
            else "FuseKit will choose the deterministic route once it is available."
        ),
    }
    if needs_human_gate and target:
        action["target"] = target
    return action


def _strategy_follow_steps(pack: ProviderCapabilityPack | None) -> tuple[str, ...]:
    if pack is not None:
        steps = tuple(
            step
            for step in (*pack.handoff.account_steps, *pack.handoff.secret_steps)
            if step.strip()
        )
        if steps:
            return steps
    return (
        "Click Open provider gate in VM so the provider opens in the observed VM browser.",
        "Complete only provider-owned login, MFA, CAPTCHA, consent, billing, or token prompts.",
        (
            "If the provider reveals a copy-once token, copy it inside the VM browser and "
            "click the matching Capture from VM clipboard button. Do not paste it into "
            "your computer; Capture reads the VM clipboard directly."
        ),
        (
            "For non-secret confirmation gates, click the visible I finished this step "
            "button in the control room after the provider confirms."
        ),
    )
