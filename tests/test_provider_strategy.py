from __future__ import annotations

from fusekit.providers.capability_pack import SetupRecipe, synthesize_provider_pack
from fusekit.providers.strategy import StrategySignal, choose_provider_strategy


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
