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


def test_provider_strategy_selects_browser_gate_when_api_token_is_missing(tmp_path) -> None:
    pack = synthesize_provider_pack("github", tmp_path)
    recipe = SetupRecipe(kind="github-deploy-key", target="${input:github_repo}")

    decision = choose_provider_strategy(pack, recipe, StrategySignal(token_available=False))

    assert decision.selected.kind == "browser_guided"
    assert not decision.executable
    assert decision.selected.status == "available"
    assert decision.selected.evidence["handoff_url"].startswith("https://")


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
    assert "Open the provider gate" in action["next_action"]


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
