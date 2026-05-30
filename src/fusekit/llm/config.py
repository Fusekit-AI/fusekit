"""Provider-agnostic LLM configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass

from fusekit.vault import Vault


@dataclass(frozen=True)
class LlmConfig:
    """LLM configuration stored without exposing the API key."""

    provider: str = "openai"
    model: str = "gpt-5.5"
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"

    @property
    def record_id(self) -> str:
        """Vault record id for the provider key."""

        return f"llm.{self.provider}.api_key"

    def metadata(self) -> dict[str, str]:
        """Non-secret metadata."""

        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
        }

    def can_use_openclaw_auth(self) -> bool:
        """Return true when OpenClaw can authorize this LLM lane."""

        return self.provider == "openai" and self.base_url == "https://api.openai.com/v1"

    def openclaw_model_ref(self) -> str:
        """Return the OpenClaw model reference for this config."""

        if self.model.startswith("openai/"):
            return self.model
        return f"openai/{self.model}"


def capture_llm_config(vault: Vault, config: LlmConfig, api_key: str | None = None) -> bool:
    """Capture an LLM API key into the encrypted vault when available."""

    key = api_key or os.environ.get(config.api_key_env)
    if not key:
        return False
    vault.put(
        config.record_id,
        "llm_api_key",
        config.provider,
        f"{config.provider} API key",
        key,
        config.metadata(),
    )
    return True
