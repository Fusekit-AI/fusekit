"""OpenClaw-backed LLM authorization for FuseKit."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fusekit.errors import FuseKitError
from fusekit.llm.config import LlmConfig
from fusekit.runtime.bootstrap import openclaw_binary, openclaw_state_home
from fusekit.vault import Vault

DEFAULT_OPENCLAW_AUTH_PROVIDER = "openai"


class CommandRunner(Protocol):
    """Command runner used by OpenClaw LLM auth."""

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a command."""


@dataclass(frozen=True)
class OpenClawLlmAuthResult:
    """Non-secret result of an OpenClaw LLM authorization run."""

    auth_provider: str
    model_ref: str
    state_home: Path
    captured_state_files: tuple[str, ...]


def authorize_openclaw_llm(
    vault: Vault,
    config: LlmConfig,
    *,
    device_code: bool = False,
    runner: CommandRunner | None = None,
) -> OpenClawLlmAuthResult:
    """Authorize OpenAI through OpenClaw and record encrypted auth-state evidence."""

    if not config.can_use_openclaw_auth():
        raise FuseKitError(
            "OpenClaw LLM fallback supports the default OpenAI lane only. "
            "Use --llm-provider openai with the default OpenAI base URL, or provide "
            "an API key for your custom LLM lane."
        )
    command_runner = runner or _default_runner
    auth_provider = os.environ.get(
        "FUSEKIT_OPENCLAW_LLM_AUTH_PROVIDER",
        DEFAULT_OPENCLAW_AUTH_PROVIDER,
    )
    model_ref = config.openclaw_model_ref()
    set_model = _openclaw_command(["config", "set", "agents.defaults.model.primary", model_ref])
    completed = command_runner(set_model)
    if completed.returncode != 0:
        raise FuseKitError(_openclaw_failure_message(completed, set_model))

    login_args = ["models", "auth", "login", "--provider", auth_provider, "--set-default"]
    if device_code:
        login_args.append("--device-code")
    if not _openclaw_auth_ready(command_runner, auth_provider):
        _run_openclaw_checked(command_runner, _openclaw_command(login_args))
    _run_openclaw_checked(
        command_runner,
        _openclaw_command(["models", "auth", "list", "--provider", auth_provider, "--json"]),
    )
    _run_openclaw_checked(command_runner, _openclaw_command(["models", "status", "--check"]))
    captured = _capture_sensitive_openclaw_state(vault, auth_provider)
    vault.put(
        "llm.openai.openclaw_profile",
        "llm_openclaw_profile",
        "openclaw",
        "OpenClaw OpenAI authorization profile",
        f"{auth_provider}:{model_ref}",
        {
            "auth_provider": auth_provider,
            "model_ref": model_ref,
            "state_home": str(openclaw_state_home()),
            "captured_state_files": str(len(captured)),
        },
    )
    return OpenClawLlmAuthResult(
        auth_provider=auth_provider,
        model_ref=model_ref,
        state_home=openclaw_state_home(),
        captured_state_files=tuple(captured),
    )


def _openclaw_auth_ready(command_runner: CommandRunner, auth_provider: str) -> bool:
    auth_list = command_runner(
        _openclaw_command(["models", "auth", "list", "--provider", auth_provider, "--json"])
    )
    if auth_list.returncode != 0 or not _auth_list_has_profiles(auth_list.stdout):
        return False
    status = command_runner(_openclaw_command(["models", "status", "--check"]))
    return status.returncode == 0


def _auth_list_has_profiles(stdout: str) -> bool:
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return False
    profiles = payload.get("profiles")
    return isinstance(profiles, list) and bool(profiles)


def _run_openclaw_checked(command_runner: CommandRunner, command: list[str]) -> None:
    completed = command_runner(command)
    if completed.returncode != 0:
        raise FuseKitError(_openclaw_failure_message(completed, command))


def _openclaw_failure_message(
    completed: subprocess.CompletedProcess[str],
    command: list[str],
) -> str:
    return (
        completed.stderr
        or completed.stdout
        or f"OpenClaw LLM authorization failed: {' '.join(command)}"
    )


def _capture_sensitive_openclaw_state(vault: Vault, auth_provider: str) -> list[str]:
    captured: list[str] = []
    root = openclaw_state_home()
    if not root.exists():
        return captured
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not _is_sensitive_state_file(path):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        record_id = f"llm.openai.openclaw_state.{digest[:16]}"
        vault.put(
            record_id,
            "llm_openclaw_auth_state",
            "openclaw",
            path.name,
            base64.b64encode(data).decode("ascii"),
            {
                "auth_provider": auth_provider,
                "path": str(path.relative_to(root)),
                "sha256": digest,
                "encoding": "base64",
            },
        )
        captured.append(str(path.relative_to(root)))
    return captured


def _is_sensitive_state_file(path: Path) -> bool:
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}
    if name in {"auth-profiles.json", "oauth.json", "tokens.json", "credentials.json"}:
        return True
    return "credentials" in parts and name.endswith(".json")


def _openclaw_command(args: list[str]) -> list[str]:
    return ["env", f"OPENCLAW_HOME={openclaw_state_home()}", openclaw_binary(), *args]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, check=False, text=True, timeout=900)
