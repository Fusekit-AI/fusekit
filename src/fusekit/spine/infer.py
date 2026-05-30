"""Inferred provider UI navigation loop."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.llm import LlmConfig
from fusekit.spine.openclaw import SpineResult
from fusekit.spine.playbooks import BrowserPlaybookEvent
from fusekit.vault import Vault

ALLOWED_ACTIONS = {"open", "click_text", "fill_label", "press", "wait_for_text", "stop", "gate"}
SENSITIVE_WORDS = ("password", "passcode", "mfa", "captcha", "payment", "card", "passkey")


class InferenceSpine(Protocol):
    """Computer-use surface needed by inferred navigation."""

    def open(self, url: str) -> SpineResult:
        """Open a URL."""

    def snapshot(self) -> SpineResult:
        """Capture page state."""

    def click_text(self, text: str) -> SpineResult:
        """Click visible text."""

    def fill_label(self, label: str, value: str) -> SpineResult:
        """Fill a label."""

    def press(self, key: str) -> SpineResult:
        """Press a key."""

    def wait_for_text(self, text: str) -> SpineResult:
        """Wait for visible text."""


@dataclass(frozen=True)
class InferredUiAction:
    """One LLM-proposed UI action."""

    action: str
    target: str = ""
    value: str = ""
    url: str = ""
    reason: str = ""


class UiNavigator(Protocol):
    """Planner that proposes the next UI action."""

    def next_action(
        self,
        *,
        provider: str,
        goal: str,
        snapshot: str,
        history: list[InferredUiAction],
    ) -> InferredUiAction:
        """Choose the next UI action."""


@dataclass
class StaticUiNavigator:
    """Deterministic navigator for tests and fallback recipes."""

    actions: list[InferredUiAction]

    def next_action(
        self,
        *,
        provider: str,
        goal: str,
        snapshot: str,
        history: list[InferredUiAction],
    ) -> InferredUiAction:
        """Return actions in order."""

        if not self.actions:
            return InferredUiAction("stop", reason="static plan exhausted")
        return self.actions.pop(0)


@dataclass(frozen=True)
class OpenAiUiNavigator:
    """OpenAI-compatible UI action planner."""

    config: LlmConfig
    vault: Vault

    def next_action(
        self,
        *,
        provider: str,
        goal: str,
        snapshot: str,
        history: list[InferredUiAction],
    ) -> InferredUiAction:
        """Ask the configured LLM for the next safe UI action."""

        token = self.vault.require(self.config.record_id).value
        payload = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are FuseKit's provider UI navigator. Return one JSON object "
                        "with action,target,value,url,reason. Allowed actions are open, "
                        "click_text, fill_label, press, wait_for_text, gate, stop. Do not "
                        "enter passwords, payment cards, MFA codes, passkeys, CAPTCHA, or "
                        "unapproved secrets. Use gate when the human must pass a service gate."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "provider": provider,
                            "goal": goal,
                            "snapshot": snapshot[:6000],
                            "history": [action.__dict__ for action in history[-12:]],
                        },
                        sort_keys=True,
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        request = Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProviderError(f"UI inference failed with HTTP {exc.code}: {detail}") from exc
        except (URLError, json.JSONDecodeError, KeyError) as exc:
            raise ProviderError(f"UI inference failed: {exc}") from exc
        content = str(data["choices"][0]["message"]["content"])
        try:
            action = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ProviderError("UI inference returned non-JSON content.") from exc
        return _coerce_action(action)


def run_inferred_navigation(
    *,
    provider: str,
    goal: str,
    start_url: str,
    spine: InferenceSpine,
    navigator: UiNavigator,
    max_steps: int = 25,
    gate_retry_seconds: float = 300.0,
    max_gate_attempts: int = 0,
    sleeper: Callable[[float], None] = time.sleep,
) -> list[BrowserPlaybookEvent]:
    """Observe, infer, act, and wait durably at provider gates."""

    events = [
        BrowserPlaybookEvent(
            provider=provider,
            action="policy.boundary",
            status="service-gates-required",
            note=(
                "FuseKit can infer UI navigation, click, type, copy, and verify. Human "
                "login, MFA, CAPTCHA, passkeys, payment, fraud checks, and consent remain gates."
            ),
        )
    ]
    history: list[InferredUiAction] = []
    gate_attempts = 0
    action_steps = 0
    spine.open(start_url)
    while action_steps < max_steps:
        snapshot = spine.snapshot().stdout
        proposed = navigator.next_action(
            provider=provider,
            goal=goal,
            snapshot=snapshot,
            history=history,
        )
        action = _validate_action(proposed)
        history.append(action)
        if action.action == "stop":
            events.append(
                BrowserPlaybookEvent(
                    provider=provider,
                    action=action.action,
                    status="done",
                    url=action.url,
                    note=action.reason,
                )
            )
            break
        if action.action == "gate":
            gate_attempts += 1
            events.append(
                BrowserPlaybookEvent(
                    provider=provider,
                    action=action.action,
                    status="waiting",
                    url=action.url,
                    note=action.reason,
                )
            )
            if max_gate_attempts and gate_attempts >= max_gate_attempts:
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="gate",
                        status="max-attempts",
                        url=action.url,
                        note="Service gate was not passed before the configured attempt limit.",
                    )
                )
                break
            if gate_retry_seconds > 0:
                sleeper(gate_retry_seconds)
            continue
        gate_attempts = 0
        action_steps += 1
        result = _execute_action(spine, action)
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action=action.action,
                status=result.status,
                url=action.url,
                note=action.reason,
            )
        )
    if action_steps >= max_steps:
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="stop",
                status="max-steps",
                note="Inferred navigation reached the max step limit.",
            )
        )
    return events


def _execute_action(spine: InferenceSpine, action: InferredUiAction) -> SpineResult:
    if action.action == "open":
        return spine.open(action.url)
    if action.action == "click_text":
        return spine.click_text(action.target)
    if action.action == "fill_label":
        return spine.fill_label(action.target, action.value)
    if action.action == "press":
        return spine.press(action.target)
    if action.action == "wait_for_text":
        return spine.wait_for_text(action.target)
    raise ProviderError(f"Unsupported inferred UI action: {action.action}")


def _coerce_action(raw: object) -> InferredUiAction:
    if not isinstance(raw, dict):
        raise ProviderError("UI inference action must be a JSON object.")
    return InferredUiAction(
        action=str(raw.get("action", "")),
        target=str(raw.get("target", "")),
        value=str(raw.get("value", "")),
        url=str(raw.get("url", "")),
        reason=str(raw.get("reason", "")),
    )


def _validate_action(action: InferredUiAction) -> InferredUiAction:
    if action.action not in ALLOWED_ACTIONS:
        raise ProviderError(f"UI inference proposed unsupported action: {action.action}")
    sensitive_blob = " ".join([action.target, action.value, action.reason]).lower()
    if action.action == "fill_label" and any(word in sensitive_blob for word in SENSITIVE_WORDS):
        return InferredUiAction(
            "gate",
            reason="Sensitive provider field requires a human service gate.",
        )
    if action.action == "fill_label" and action.value and _looks_like_raw_secret(action.value):
        return InferredUiAction("gate", reason="Raw secret entry requires approved capture flow.")
    return action


def _looks_like_raw_secret(value: str) -> bool:
    lowered = value.lower()
    return (
        len(value) >= 24
        and not value.startswith("env:")
        and any(prefix in lowered for prefix in ("sk_", "ghp_", "whsec_", "rk_"))
    )
