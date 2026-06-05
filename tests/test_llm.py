from __future__ import annotations

import subprocess

from fusekit.llm import LlmConfig, capture_llm_config
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
