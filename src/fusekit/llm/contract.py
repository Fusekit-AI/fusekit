"""Non-secret model/inference contract for launch surfaces."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

from fusekit.llm.config import LlmConfig
from fusekit.vault import Vault

LLM_CONTRACT_SCHEMA_VERSION = "fusekit.llm-contract.v1"
MODEL_INFERENCE_KEYS = frozenset(
    {
        "api_key_env",
        "auth_mode",
        "base_url",
        "can_proceed_without_api_key",
        "default_lane",
        "lane_count",
        "model",
        "next_action",
        "provider",
        "ready",
        "required",
        "schema_version",
        "statement",
        "status",
    }
)
LLM_CONTRACT_KEYS = frozenset(
    {
        "api_key_env",
        "auth_mode",
        "base_url",
        "can_proceed_without_api_key",
        "default_lane",
        "lanes",
        "model",
        "next_action",
        "provider",
        "record_id",
        "required",
        "schema_version",
        "security",
        "status",
    }
)
LLM_CONTRACT_SECURITY_KEYS = frozenset(
    {
        "detonation",
        "public_surfaces",
        "raw_secret_export",
        "storage",
    }
)
LLM_CONTRACT_LANE_KEYS = frozenset(
    {
        "available",
        "description",
        "id",
        "label",
        "requires_user_action",
    }
)


def build_llm_contract(
    config: LlmConfig,
    *,
    auth_mode: str = "auto",
    required: bool = True,
    vault: Vault | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Build the public model/inference contract without exposing credentials."""

    env = environ if environ is not None else os.environ
    api_key_in_env = bool(env.get(config.api_key_env))
    api_key_in_vault = vault is not None and config.record_id in vault.records
    openclaw_profile_in_vault = (
        vault is not None
        and config.can_use_openclaw_auth()
        and "llm.openai.openclaw_profile" in vault.records
    )
    openclaw_available = config.can_use_openclaw_auth() and auth_mode in {"auto", "openclaw"}
    api_key_ready = api_key_in_vault or api_key_in_env
    if api_key_in_vault:
        status = "api_key_encrypted"
        next_action = (
            "FuseKit has an encrypted LLM API key and can use it internally for "
            "provider-page reasoning."
        )
    elif openclaw_profile_in_vault:
        status = "openclaw_profile_encrypted"
        next_action = (
            "FuseKit has encrypted OpenClaw authorization state and can continue "
            "without a raw LLM API key."
        )
    elif api_key_in_env:
        status = "api_key_env_available"
        next_action = (
            f"FuseKit will capture {config.api_key_env} into the encrypted vault "
            "before provider automation starts."
        )
    elif not required:
        status = "optional_for_rehearsal"
        next_action = (
            "This rehearsal can continue without live model inference. A public "
            "launch still needs an API key or the OpenClaw authorization lane."
        )
    elif openclaw_available:
        status = "needs_openclaw_or_api_key"
        next_action = (
            "Use the OpenClaw/OpenAI human-gated authorization step, or provide "
            f"{config.api_key_env} through env or supervised capture."
        )
    else:
        status = "needs_api_key"
        next_action = (
            f"Provide {config.api_key_env} for this custom LLM lane. OpenClaw "
            "authorization fallback only supports the default OpenAI API lane."
        )
    lanes = [
        {
            "id": "api-key",
            "label": "Encrypted API key",
            "available": True,
            "requires_user_action": not (api_key_in_vault or api_key_in_env),
            "description": (
                f"Set {config.api_key_env} or use supervised capture. FuseKit "
                "stores the key only inside the encrypted vault and resolves it "
                "in memory when provider-page reasoning is needed."
            ),
        }
    ]
    lanes.append(
        {
            "id": "openclaw-openai",
            "label": "OpenClaw OpenAI authorization",
            "available": openclaw_available,
            "requires_user_action": openclaw_available and not openclaw_profile_in_vault,
            "description": (
                "Default OpenAI lane only. The user signs in and completes MFA, CAPTCHA, "
                "or consent gates in the VM/browser. FuseKit encrypts captured OpenClaw "
                "auth-state metadata and detonates plaintext worker state later."
                if openclaw_available
                else "Unavailable for this custom provider/base URL; use the API-key lane."
            ),
        }
    )
    if openclaw_profile_in_vault:
        default_lane = "openclaw-openai"
    elif api_key_ready:
        default_lane = "api-key"
    elif openclaw_available:
        default_lane = "openclaw-openai"
    else:
        default_lane = "api-key"
    return {
        "schema_version": LLM_CONTRACT_SCHEMA_VERSION,
        "provider": config.provider,
        "model": config.model,
        "base_url": config.base_url,
        "api_key_env": config.api_key_env,
        "record_id": config.record_id,
        "auth_mode": auth_mode,
        "required": required,
        "status": status,
        "can_proceed_without_api_key": bool(openclaw_available),
        "default_lane": default_lane,
        "next_action": next_action,
        "lanes": lanes,
        "security": {
            "raw_secret_export": "denied",
            "storage": "encrypted vault only",
            "public_surfaces": "metadata and redacted status only",
            "detonation": "plaintext OpenClaw/browser auth state is a worker cleanup target",
        },
    }


def write_llm_contract(path: Path, contract: dict[str, object]) -> None:
    """Write a non-secret LLM contract artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
