from __future__ import annotations

import subprocess

from fusekit.llm import (
    LLM_CONTRACT_KEYS,
    LLM_CONTRACT_LANE_KEYS,
    LLM_CONTRACT_SECURITY_KEYS,
    MODEL_INFERENCE_KEYS,
    LlmConfig,
    build_llm_contract,
    capture_llm_config,
)
from fusekit.llm.openclaw_auth import authorize_openclaw_llm
from fusekit.runtime.bootstrap import openclaw_state_home
from fusekit.vault import Vault


def test_capture_llm_config_stores_key_in_vault_without_public_value(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-test-key")
    vault = Vault.empty()
    config = LlmConfig()

    assert capture_llm_config(vault, config)

    record = vault.require("llm.openai.api_key")
    assert record.value == "fake-openai-test-key"
    assert record.metadata["model"] == "gpt-5.5"
    assert "fake-openai-test-key" not in str(vault.public_index())


def test_llm_contract_explains_default_openclaw_fallback_without_secret() -> None:
    contract = build_llm_contract(
        LlmConfig(),
        auth_mode="auto",
        required=True,
        environ={},
    )

    assert contract["schema_version"] == "fusekit.llm-contract.v1"
    assert contract["provider"] == "openai"
    assert contract["model"] == "gpt-5.5"
    assert contract["api_key_env"] == "OPENAI_API_KEY"
    assert contract["status"] == "needs_openclaw_or_api_key"
    assert contract["can_proceed_without_api_key"] is True
    assert contract["default_lane"] == "openclaw-openai"
    lanes = {str(lane["id"]): lane for lane in contract["lanes"]}
    assert lanes["api-key"]["requires_user_action"] is True
    assert lanes["openclaw-openai"]["requires_user_action"] is True
    assert "OpenClaw/OpenAI" in str(contract["next_action"])
    assert "raw_secret_export" in contract["security"]
    assert "sk-" not in str(contract)


def test_llm_contract_defaults_to_ready_api_key_lane_when_key_is_encrypted() -> None:
    vault = Vault.empty()
    vault.put(
        "llm.openai.api_key",
        "llm_api_key",
        "openai",
        "OpenAI API key",
        "sk-test-secret-value",
    )

    contract = build_llm_contract(
        LlmConfig(),
        auth_mode="auto",
        required=True,
        vault=vault,
        environ={},
    )

    assert contract["status"] == "api_key_encrypted"
    assert contract["default_lane"] == "api-key"
    lanes = {str(lane["id"]): lane for lane in contract["lanes"]}
    assert lanes["api-key"]["available"] is True
    assert lanes["api-key"]["requires_user_action"] is False
    assert lanes["openclaw-openai"]["available"] is True
    assert lanes["openclaw-openai"]["requires_user_action"] is True


def test_llm_contract_defaults_to_ready_openclaw_lane_when_profile_is_encrypted() -> None:
    vault = Vault.empty()
    vault.put(
        "llm.openai.openclaw_profile",
        "llm_openclaw_profile",
        "openai",
        "OpenClaw OpenAI profile",
        '{"profile":"encrypted"}',
    )

    contract = build_llm_contract(
        LlmConfig(),
        auth_mode="auto",
        required=True,
        vault=vault,
        environ={},
    )

    assert contract["status"] == "openclaw_profile_encrypted"
    assert contract["default_lane"] == "openclaw-openai"
    lanes = {str(lane["id"]): lane for lane in contract["lanes"]}
    assert lanes["api-key"]["available"] is True
    assert lanes["api-key"]["requires_user_action"] is True
    assert lanes["openclaw-openai"]["available"] is True
    assert lanes["openclaw-openai"]["requires_user_action"] is False


def test_llm_contract_requires_api_key_for_custom_provider() -> None:
    contract = build_llm_contract(
        LlmConfig(
            provider="runpod",
            model="custom-model",
            base_url="https://api.runpod.ai/v2/openai/v1",
            api_key_env="RUNPOD_API_KEY",
        ),
        auth_mode="auto",
        required=True,
        environ={},
    )

    assert contract["status"] == "needs_api_key"
    assert contract["can_proceed_without_api_key"] is False
    assert "RUNPOD_API_KEY" in str(contract["next_action"])
    assert "default OpenAI API lane" in str(contract["next_action"])


def test_llm_contract_gate_surfaces_share_canonical_shape() -> None:
    from fusekit.detonation import preflight
    from fusekit.harness import acceptance
    from fusekit.runner import run_record

    assert run_record.MODEL_INFERENCE_KEYS is MODEL_INFERENCE_KEYS
    assert run_record.LLM_CONTRACT_KEYS is LLM_CONTRACT_KEYS
    assert run_record.LLM_CONTRACT_SECURITY_KEYS is LLM_CONTRACT_SECURITY_KEYS
    assert run_record.LLM_CONTRACT_LANE_KEYS is LLM_CONTRACT_LANE_KEYS
    assert acceptance._MODEL_INFERENCE_KEYS is MODEL_INFERENCE_KEYS
    assert acceptance._LLM_CONTRACT_KEYS is LLM_CONTRACT_KEYS
    assert acceptance._LLM_CONTRACT_SECURITY_KEYS is LLM_CONTRACT_SECURITY_KEYS
    assert acceptance._LLM_CONTRACT_LANE_KEYS is LLM_CONTRACT_LANE_KEYS
    assert preflight.MODEL_INFERENCE_KEYS is MODEL_INFERENCE_KEYS
    assert preflight.LLM_CONTRACT_KEYS is LLM_CONTRACT_KEYS
    assert preflight.LLM_CONTRACT_SECURITY_KEYS is LLM_CONTRACT_SECURITY_KEYS
    assert preflight.LLM_CONTRACT_LANE_KEYS is LLM_CONTRACT_LANE_KEYS


def test_openclaw_llm_auth_captures_auth_state_in_vault(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("FUSEKIT_HOME", str(tmp_path / "runtime"))
    monkeypatch.setenv("FUSEKIT_OPENCLAW_BIN", str(tmp_path / "openclaw"))
    state = openclaw_state_home()
    auth_state = state / "agents" / "default" / "agent" / "auth-profiles.json"
    secret_oauth_material = '{"access_token":"secret-openclaw-token"}'
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        auth_state.parent.mkdir(parents=True, exist_ok=True)
        auth_state.write_text(secret_oauth_material, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    vault = Vault.empty()
    result = authorize_openclaw_llm(vault, LlmConfig(), runner=runner)

    assert result.auth_provider == "openai"
    assert result.model_ref == "openai/gpt-5.5"
    assert calls[0] == [
        "env",
        f"OPENCLAW_HOME={state}",
        str(tmp_path / "openclaw"),
        "config",
        "set",
        "agents.defaults.model.primary",
        "openai/gpt-5.5",
    ]
    assert calls[2] == [
        "env",
        f"OPENCLAW_HOME={state}",
        str(tmp_path / "openclaw"),
        "models",
        "auth",
        "login",
        "--provider",
        "openai",
        "--set-default",
    ]
    profile = vault.require("llm.openai.openclaw_profile")
    assert profile.metadata["model_ref"] == "openai/gpt-5.5"
    snapshot = next(
        record for record in vault.records.values() if record.kind == "llm_openclaw_auth_state"
    )
    assert snapshot.metadata["path"] == "agents/default/agent/auth-profiles.json"
    assert "secret-openclaw-token" not in str(vault.public_index())


def test_openclaw_llm_auth_reuses_existing_profile_without_login(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("FUSEKIT_HOME", str(tmp_path / "runtime"))
    monkeypatch.setenv("FUSEKIT_OPENCLAW_BIN", str(tmp_path / "openclaw"))
    state = openclaw_state_home()
    auth_state = state / "agents" / "default" / "agent" / "auth-profiles.json"
    auth_state.parent.mkdir(parents=True, exist_ok=True)
    auth_state.write_text('{"access_token":"existing-token"}', encoding="utf-8")
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        stdout = ""
        if command[-1] == "--json":
            stdout = '{"profiles":[{"provider":"openai","type":"oauth"}]}'
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    vault = Vault.empty()
    result = authorize_openclaw_llm(vault, LlmConfig(model="gpt-5"), runner=runner)

    assert result.model_ref == "openai/gpt-5"
    flattened = [" ".join(call) for call in calls]
    assert not any("models auth login" in call for call in flattened)
    assert flattened[0].endswith("config set agents.defaults.model.primary openai/gpt-5")
    assert any("models status --check" in call for call in flattened)
