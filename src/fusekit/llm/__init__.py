"""LLM provider configuration for FuseKit."""

from fusekit.llm.config import LlmConfig, capture_llm_config
from fusekit.llm.contract import (
    LLM_CONTRACT_KEYS,
    LLM_CONTRACT_LANE_KEYS,
    LLM_CONTRACT_SCHEMA_VERSION,
    LLM_CONTRACT_SECURITY_KEYS,
    MODEL_INFERENCE_KEYS,
    build_llm_contract,
    write_llm_contract,
)
from fusekit.llm.openclaw_auth import OpenClawLlmAuthResult, authorize_openclaw_llm

__all__ = [
    "LLM_CONTRACT_KEYS",
    "LLM_CONTRACT_LANE_KEYS",
    "LLM_CONTRACT_SCHEMA_VERSION",
    "LLM_CONTRACT_SECURITY_KEYS",
    "LlmConfig",
    "MODEL_INFERENCE_KEYS",
    "OpenClawLlmAuthResult",
    "authorize_openclaw_llm",
    "build_llm_contract",
    "capture_llm_config",
    "write_llm_contract",
]
