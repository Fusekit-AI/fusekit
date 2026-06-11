from __future__ import annotations

from dataclasses import replace

from fusekit.providers.capability_pack import SetupRecipe, synthesize_provider_pack
from fusekit.providers.strategy import (
    StrategySignal,
    choose_account_creation_strategy,
    choose_provider_strategy,
    summarize_strategy_action,
)


def test_provider_strategy_prefers_api_when_token_is_available(tmp_path) -> None:
    pack = synthesize_provider_pack("vercel", tmp_path)
    recipe = SetupRecipe(kind="vercel-project", target="${input:vercel_project}")

    decision = choose_provider_strategy(
        pack,
        recipe,
        StrategySignal(token_available=True, cli_tools=frozenset({"vercel"})),
    )

    assert decision.selected.kind == "api"
    assert decision.executable
    assert decision.selected.deterministic is True
    assert any(candidate.kind == "official_cli" for candidate in decision.candidates)
    assert any(candidate.kind == "browser_guided" for candidate in decision.candidates)


def test_provider_strategy_marks_resend_audience_as_conditional_api_owned(
    tmp_path,
) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    recipe = SetupRecipe(kind="resend-audience", target="${input:resend_audience_name}")

    decision = choose_provider_strategy(
        pack,
        recipe,
        StrategySignal(token_available=True),
    )

    assert decision.selected.kind == "api"
    assert decision.executable
    assert decision.selected.evidence["api_owns"] == "audience"
    assert decision.selected.evidence["conditional"] == "only_when_app_requires_audience"
    assert "only if the app requires one" in decision.selected.reason


def test_provider_strategy_selects_browser_gate_when_api_token_is_missing(tmp_path) -> None:
    pack = synthesize_provider_pack("github", tmp_path)
    recipe = SetupRecipe(kind="github-deploy-key", target="${input:github_repo}")

    decision = choose_provider_strategy(pack, recipe, StrategySignal(token_available=False))

    assert decision.selected.kind == "browser_guided"
    assert not decision.executable
    assert decision.selected.status == "available"
    assert decision.selected.evidence["handoff_url"].startswith("https://")


def test_provider_strategy_handoff_prefers_token_url_for_authorization(tmp_path) -> None:
    vercel = synthesize_provider_pack("vercel", tmp_path)
    vercel_recipe = SetupRecipe(kind="vercel-project", target="${input:vercel_project}")
    resend = synthesize_provider_pack("resend", tmp_path)
    resend_recipe = SetupRecipe(kind="resend-domain", target="${input:resend_domain}")

    vercel_decision = choose_provider_strategy(
        vercel,
        vercel_recipe,
        StrategySignal(token_available=False),
    )
    resend_decision = choose_provider_strategy(
        resend,
        resend_recipe,
        StrategySignal(token_available=False),
    )

    assert vercel_decision.selected.evidence["handoff_url"] == (
        "https://vercel.com/account/tokens"
    )
    assert summarize_strategy_action(vercel_decision)["resume_url"] == (
        "https://vercel.com/account/tokens"
    )
    assert resend_decision.selected.evidence["handoff_url"] == "https://resend.com/api-keys"
    assert summarize_strategy_action(resend_decision)["resume_url"] == (
        "https://resend.com/api-keys"
    )


def test_provider_strategy_does_not_dead_end_on_unimplemented_cli(tmp_path) -> None:
    pack = synthesize_provider_pack("github", tmp_path)
    recipe = SetupRecipe(kind="github-deploy-key", target="${input:github_repo}")

    decision = choose_provider_strategy(
        pack,
        recipe,
        StrategySignal(token_available=False, cli_tools=frozenset({"gh"})),
    )

    cli_candidate = next(
        candidate for candidate in decision.candidates if candidate.kind == "official_cli"
    )
    action = summarize_strategy_action(decision)
    assert cli_candidate.status == "unavailable"
    assert cli_candidate.implemented is False
    assert decision.selected.kind == "browser_guided"
    assert action["status"] == "needs_human_gate"
    assert "Click Open provider gate in VM" in action["next_action"]
    assert "Capture GITHUB_TOKEN from VM clipboard" in action["next_action"]
    assert "Capture reads the VM clipboard directly" in action["next_action"]
    assert (
        "visible I finished this step button in the control room"
        in " ".join(action["follow_steps"])
    )
    assert action["resume_url"] == "https://github.com/settings/tokens?type=beta"
    assert "visible gate is finished" in action["resume_hint"]


def test_provider_strategy_action_can_carry_pack_follow_steps(tmp_path) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    recipe = SetupRecipe(kind="resend-domain", target="${input:resend_domain}")
    decision = choose_provider_strategy(pack, recipe, StrategySignal(token_available=False))

    action = summarize_strategy_action(decision, pack)
    steps = " ".join(action["follow_steps"])

    assert action["resume_url"] == "https://resend.com/api-keys"
    assert action["target"] == "RESEND_API_KEY"
    assert "Open provider gate in VM" in steps
    assert "Resend opens in the VM browser" in steps
    assert "Full access for this first setup" in steps
    assert "does not reveal old key secrets again" in steps
    assert "creates or reuses the sending domain through Resend's API" in steps
    assert "encrypted vault" in steps
    assert "Capture reads the VM clipboard directly" in steps
    assert "Capture RESEND_API_KEY from VM clipboard" in action["next_action"]


def test_provider_strategy_summary_uses_evidence_token_env_without_pack(tmp_path) -> None:
    pack = synthesize_provider_pack("newpay", tmp_path)
    recipe = SetupRecipe(kind="newpay-project", target="${input:newpay_project}")

    decision = choose_provider_strategy(pack, recipe, StrategySignal(token_available=False))
    action = summarize_strategy_action(decision)

    assert decision.selected.kind == "browser_guided"
    assert decision.selected.evidence["token_env"] == "NEWPAY_API_KEY"
    assert action["target"] == "NEWPAY_API_KEY"
    assert "Capture NEWPAY_API_KEY from VM clipboard" in action["next_action"]
    assert "target-specific Capture from VM clipboard button" not in action["next_action"]


def test_provider_strategy_uses_local_vault_for_capture_recipes(tmp_path) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    recipe = SetupRecipe(
        kind="vault-capture-env",
        target="RESEND_API_KEY",
        secret_refs=("RESEND_API_KEY",),
    )

    decision = choose_provider_strategy(pack, recipe, StrategySignal())

    assert decision.selected.kind == "local_vault"
    assert decision.executable


def test_provider_strategy_uses_api_for_resend_domain_when_token_exists(tmp_path) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    recipe = SetupRecipe(kind="resend-domain", target="${input:resend_domain}")

    decision = choose_provider_strategy(
        pack,
        recipe,
        StrategySignal(token_available=True),
    )

    assert decision.selected.kind == "api"
    assert decision.executable
    assert decision.selected.evidence["api_owns"] == "domain"
    assert decision.selected.evidence["downstream_order"] == "before_dns_apply"
    assert "create or reuse the sending domain" in decision.selected.reason


def test_account_creation_strategy_uses_supervised_gate(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)

    decision = choose_account_creation_strategy(pack, StrategySignal())

    assert decision.recipe_kind == "account.creation"
    assert decision.selected.kind == "browser_guided"
    assert not decision.executable
    assert decision.selected.status == "available"
    assert decision.selected.evidence["handoff_url"].startswith("https://")


def test_account_creation_strategy_blocks_when_pack_declares_none(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    pack = replace(
        pack,
        handoff=replace(
            pack.handoff,
            account_creation="none",
            account_creation_reason="Provider account creation is unavailable.",
        ),
    )

    decision = choose_account_creation_strategy(pack, StrategySignal())

    assert decision.selected.kind == "unsupported"
    assert decision.selected.status == "blocked"
    assert not decision.executable
