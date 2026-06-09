"""Inferred provider UI navigation loop."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.llm import LlmConfig
from fusekit.security.url import require_safe_url
from fusekit.spine.openclaw import SpineResult
from fusekit.spine.playbooks import BrowserPlaybookEvent
from fusekit.vault import Vault

ALLOWED_ACTIONS = {
    "open",
    "click_text",
    "fill_label",
    "press",
    "wait",
    "wait_for_text",
    "stop",
    "gate",
}
SENSITIVE_WORDS = ("password", "passcode", "mfa", "captcha", "payment", "card", "passkey")
SAFE_KEYS = {
    "Enter",
    "Tab",
    "Escape",
    "Backspace",
    "ArrowUp",
    "ArrowDown",
    "ArrowLeft",
    "ArrowRight",
}
GateRecorder = Callable[[str, str, str, str, str, tuple[str, ...], str], str]
GatePassedChecker = Callable[[str], bool]


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

    def highlight(self, target: str) -> SpineResult:
        """Highlight a target for human attention."""

    def trace_start(self) -> SpineResult:
        """Start a browser trace if supported."""

    def trace_stop(self) -> SpineResult:
        """Stop a browser trace if supported."""


@dataclass(frozen=True)
class InferredUiAction:
    """One LLM-proposed UI action."""

    action: str
    target: str = ""
    value: str = ""
    url: str = ""
    reason: str = ""

    def redacted(self) -> dict[str, str]:
        """Serialize without exposing secret-looking typed values."""

        value = (
            "[redacted]"
            if self.value and _looks_like_sensitive_value(self.value)
            else _redact_public_text(self.value)
        )
        return {
            "action": self.action,
            "target": _redact_public_text(self.target),
            "value": value,
            "url": _redact_url(self.url),
            "reason": _redact_public_text(self.reason),
        }


@dataclass(frozen=True)
class StumpClassification:
    """Why the provider UI needs a human or alternate setup path."""

    kind: str
    confidence: str
    reason: str
    target: str = ""
    follow_steps: tuple[str, ...] = ()


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
                        "click_text, fill_label, press, wait, wait_for_text, gate, stop. "
                        "For wait, use target for a selector, url for a URL glob, and value "
                        "for a load state such as networkidle. Do not "
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
                            "snapshot": _redact_public_text(snapshot)[:6000],
                            "history": [action.redacted() for action in history[-12:]],
                        },
                        sort_keys=True,
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        base_url = require_safe_url(
            self.config.base_url,
            label="UI inference LLM base URL",
            allow_http_loopback=True,
        )
        request = Request(
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=60) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise ProviderError(f"UI inference failed with HTTP {exc.code}.") from exc
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
    allowed_domains: tuple[str, ...] = (),
    gate_recorder: GateRecorder | None = None,
    gate_passed: GatePassedChecker | None = None,
    provider_memory_path: Path | None = None,
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
    trace_running = _try_spine(spine, "trace_start") is not None
    spine.open(start_url)
    navigation_domains = allowed_domains or (_root_domain(start_url),)
    while action_steps < max_steps:
        snapshot_result = spine.snapshot()
        snapshot = snapshot_result.stdout
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="observe",
                status="ok",
                url=_snapshot_url(snapshot),
                note=_snapshot_summary(snapshot),
            )
        )
        proposed = navigator.next_action(
            provider=provider,
            goal=goal,
            snapshot=snapshot,
            history=history,
        )
        try:
            action = _validate_action(proposed, allowed_domains=navigation_domains)
        except ProviderError as exc:
            if _is_terminal_policy_error(str(exc)):
                trace = _stop_trace_if_needed(spine, trace_running)
                events.extend(_diagnostic_events(provider, spine, exc, trace))
                break
            gate_attempts += 1
            gate_id = _record_stump_gate(
                events,
                provider=provider,
                spine=spine,
                snapshot=snapshot,
                reason=str(exc),
                url=_snapshot_url(snapshot) or start_url,
                target=proposed.target,
                gate_recorder=gate_recorder,
            )
            if _gate_completed(gate_passed, gate_id):
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="human.resume",
                        status="passed",
                        url=_snapshot_url(snapshot),
                        note=(
                            "Human takeover was marked done; verification will be the "
                            "source of truth."
                        ),
                    )
                )
                gate_attempts = 0
                continue
            if max_gate_attempts and gate_attempts >= max_gate_attempts:
                _stop_trace_if_needed(spine, trace_running)
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="gate",
                        status="max-attempts",
                        url=_snapshot_url(snapshot),
                        note="Service gate was not passed before the configured attempt limit.",
                    )
                )
                break
            if gate_retry_seconds > 0:
                sleeper(gate_retry_seconds)
            _resurface_gate(spine, _snapshot_url(snapshot) or start_url)
            continue
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
            _write_provider_memory(provider_memory_path, provider, goal, history, events)
            break
        if action.action == "gate":
            gate_attempts += 1
            classification = classify_ui_stump(
                provider=provider,
                snapshot=snapshot,
                reason=action.reason,
                target=action.target,
            )
            _append_stump_events(
                events,
                provider=provider,
                spine=spine,
                classification=classification,
                url=action.url or _snapshot_url(snapshot),
            )
            gate_id = _record_gate(
                gate_recorder,
                provider=provider,
                classification=classification,
                reason=action.reason,
                url=action.url or _snapshot_url(snapshot) or start_url,
            )
            events.append(
                BrowserPlaybookEvent(
                    provider=provider,
                    action=action.action,
                    status="waiting",
                    url=action.url,
                    note=action.reason,
                )
            )
            if _gate_completed(gate_passed, gate_id):
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="human.resume",
                        status="passed",
                        url=action.url,
                        note="Human gate was marked done; FuseKit will continue and verify.",
                    )
                )
                gate_attempts = 0
                continue
            if max_gate_attempts and gate_attempts >= max_gate_attempts:
                _stop_trace_if_needed(spine, trace_running)
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
            _resurface_gate(spine, action.url or start_url)
            continue
        gate_attempts = 0
        try:
            result = _execute_action(spine, action)
        except Exception as exc:
            provider_error = exc if isinstance(exc, ProviderError) else ProviderError(str(exc))
            gate_attempts += 1
            gate_id = _record_stump_gate(
                events,
                provider=provider,
                spine=spine,
                snapshot=_safe_snapshot(spine) or snapshot,
                reason=str(provider_error),
                url=action.url or _snapshot_url(snapshot) or start_url,
                target=action.target,
                gate_recorder=gate_recorder,
            )
            if _gate_completed(gate_passed, gate_id):
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="human.resume",
                        status="passed",
                        url=action.url,
                        note=(
                            "Human takeover was marked done after UI drift; FuseKit "
                            "will re-observe."
                        ),
                    )
                )
                gate_attempts = 0
                continue
            if max_gate_attempts and gate_attempts >= max_gate_attempts:
                trace = _stop_trace_if_needed(spine, trace_running)
                events.extend(_diagnostic_events(provider, spine, provider_error, trace))
                break
            if gate_retry_seconds > 0:
                sleeper(gate_retry_seconds)
            _resurface_gate(spine, action.url or _snapshot_url(snapshot) or start_url)
            continue
        action_steps += 1
        after = _safe_snapshot(spine)
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action=action.action,
                status=result.status,
                url=action.url,
                note=action.reason,
            )
        )
        if after:
            events.append(
                BrowserPlaybookEvent(
                    provider=provider,
                    action="observe.after",
                    status="ok",
                    url=_snapshot_url(after),
                    note=_snapshot_summary(after),
                )
            )
    if action_steps >= max_steps:
        _stop_trace_if_needed(spine, trace_running)
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="stop",
                status="max-steps",
                note="Inferred navigation reached the max step limit.",
            )
        )
    else:
        _write_provider_memory(provider_memory_path, provider, goal, history, events)
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
    if action.action == "wait":
        wait_for_state = getattr(spine, "wait_for_state", None)
        if callable(wait_for_state):
            result = wait_for_state(
                selector=action.target,
                url=action.url,
                load=action.value or "networkidle",
            )
            if isinstance(result, SpineResult):
                return result
            raise ProviderError("Browser spine returned an invalid rich wait result.")
        if action.target:
            return spine.wait_for_text(action.target)
        raise ProviderError("Browser spine does not support rich wait conditions.")
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


def _validate_action(
    action: InferredUiAction,
    *,
    allowed_domains: tuple[str, ...] = (),
) -> InferredUiAction:
    if action.action not in ALLOWED_ACTIONS:
        raise ProviderError(f"UI inference proposed unsupported action: {action.action}")
    sensitive_blob = " ".join([action.target, action.value, action.reason]).lower()
    if action.action == "open" and not _safe_https_url(action.url):
        raise ProviderError("UI inference proposed a non-HTTPS or unsupported navigation URL.")
    if action.action == "open" and not _allowed_navigation_url(action.url, allowed_domains):
        raise ProviderError("UI inference proposed navigation outside the provider domain.")
    if action.action in {"click_text", "fill_label", "wait_for_text"} and not action.target.strip():
        raise ProviderError(f"UI inference proposed {action.action} without a target.")
    if action.action == "wait" and not any(
        part.strip() for part in (action.target, action.url, action.value)
    ):
        raise ProviderError("UI inference proposed wait without selector, URL, or load state.")
    if (
        action.action == "wait"
        and action.url
        and not _allowed_wait_url(action.url, allowed_domains)
    ):
        raise ProviderError("UI inference proposed waiting outside the provider domain.")
    if action.action == "fill_label" and not action.value:
        raise ProviderError("UI inference proposed fill_label without a value.")
    if action.action == "press" and action.target not in SAFE_KEYS:
        raise ProviderError(f"UI inference proposed an unsafe keypress: {action.target}")
    if action.action == "fill_label" and any(word in sensitive_blob for word in SENSITIVE_WORDS):
        return InferredUiAction(
            "gate",
            reason="Sensitive provider field requires a human service gate.",
        )
    if action.action == "fill_label" and action.value and _looks_like_sensitive_value(action.value):
        return InferredUiAction("gate", reason="Raw secret entry requires approved capture flow.")
    return action


def classify_ui_stump(
    *,
    provider: str,
    snapshot: str,
    reason: str = "",
    error: str = "",
    target: str = "",
) -> StumpClassification:
    """Classify a confusing provider UI state into a durable handoff reason."""

    haystack = " ".join(
        [provider, reason, error, target, _snapshot_text(snapshot)]
    ).lower()
    target_hint = _public_target_hint(target) or _best_target_hint(snapshot, haystack)
    checks = (
        (
            "captcha",
            ("captcha", "recaptcha", "turnstile", "verify you are human", "human verification"),
            "The provider is asking for a human verification challenge.",
        ),
        (
            "mfa",
            (
                "mfa",
                "2fa",
                "two-factor",
                "two factor",
                "authenticator",
                "verification code",
                "passkey",
                "security key",
            ),
            "The provider is asking for MFA, passkey, or a verification code.",
        ),
        (
            "billing",
            (
                "billing",
                "payment",
                "credit card",
                "card number",
                "invoice",
                "checkout",
                "upgrade",
            ),
            "The provider is asking for billing or account verification.",
        ),
        (
            "consent",
            ("authorize", "consent", "approve", "permission", "install app", "grant access"),
            "The provider is asking you to approve access or permissions.",
        ),
        (
            "login",
            ("sign in", "signin", "log in", "login", "email address", "password"),
            "The provider is asking for account login or signup.",
        ),
        (
            "missing_token",
            (
                "api key",
                "token",
                "secret key",
                "create key",
                "copy key",
                "reveal",
                "personal access token",
            ),
            "The provider token or API key still needs to be created or captured.",
        ),
        (
            "api_error",
            (
                "http 401",
                "http 403",
                "http 429",
                "http 500",
                "api error",
                "rate limit",
                "forbidden",
            ),
            "The provider API returned an error, so FuseKit will try another safe path.",
        ),
        (
            "page_loading",
            ("loading", "please wait", "spinner", "networkidle", "timed out", "timeout"),
            "The provider page appears to still be loading or waiting on the network.",
        ),
        (
            "changed_navigation",
            (
                "not found",
                "vanished",
                "without a target",
                "unsupported action",
                "does not support",
                "could not click",
                "could not find",
                "selector",
            ),
            "The provider UI looks different from the expected path.",
        ),
    )
    if not _snapshot_text(snapshot).strip() and not reason.strip() and not error.strip():
        return _classification(
            "page_loading",
            "medium",
            "The browser snapshot is empty, so FuseKit will keep waiting and recheck.",
            provider,
            target_hint,
        )
    for kind, needles, explanation in checks:
        if any(needle in haystack for needle in needles):
            return _classification(kind, "high", explanation, provider, target_hint)
    return _classification(
        "unknown_ui_drift",
        "low",
        "The provider screen changed in a way FuseKit cannot safely infer yet.",
        provider,
        target_hint,
    )


def _classification(
    kind: str,
    confidence: str,
    reason: str,
    provider: str,
    target: str,
) -> StumpClassification:
    return StumpClassification(
        kind=kind,
        confidence=confidence,
        reason=reason,
        target=target,
        follow_steps=_follow_me_steps(provider, kind, target),
    )


def _follow_me_steps(provider: str, kind: str, target: str) -> tuple[str, ...]:
    safe_target = _public_target_hint(target)
    target_step = f"Use the highlighted provider control: {safe_target}." if safe_target else ""
    templates = {
        "login": (
            f"FuseKit opened the {provider} sign-in screen for you.",
            "Enter account credentials only on the provider page FuseKit opened.",
            "Click I finished this step after the provider accepts the sign-in.",
        ),
        "mfa": (
            "Complete the highlighted MFA, passkey, email, or SMS-code prompt.",
            "Do not paste MFA codes into FuseKit; enter them only on the provider page.",
            "Click I finished this step after the provider accepts the challenge.",
        ),
        "captcha": (
            "Solve the provider's human check in the browser.",
            "Leave the browser tab open after the challenge clears.",
            "Click I finished this step when the page continues.",
        ),
        "consent": (
            "Review the highlighted provider permission screen.",
            "Approve only the account, repo, domain, or project access named by FuseKit.",
            "Click I finished this step after the provider confirms approval.",
        ),
        "billing": (
            "Complete the highlighted billing or account-verification prompt on the provider page.",
            "Do not put card details into FuseKit; use only the provider page.",
            "Click I finished this step after the provider unlocks the next screen.",
        ),
        "missing_token": (
            "Open the provider's API key or token page.",
            "Create a scoped token/key for this app when the provider asks.",
            (
                "Copy the approved token inside the VM browser, then click the matching "
                "Capture from VM clipboard button."
            ),
        ),
        "api_error": (
            "Keep the provider page open while FuseKit checks for an API fallback.",
            "If the provider asks you to reauthorize, complete that provider prompt.",
            "FuseKit will verify again after repair or API fallback finishes.",
        ),
        "page_loading": (
            "Keep the provider tab open while FuseKit waits for the page to finish loading.",
            "FuseKit will reopen and resnapshot this page automatically.",
            "Use I finished this step only after FuseKit shows a highlighted provider prompt.",
        ),
        "changed_navigation": (
            "FuseKit detected that this provider screen changed from the expected path.",
            "Complete only the highlighted provider control or prompt FuseKit points at.",
            "Click I finished this step; FuseKit will verify rather than trusting the UI.",
        ),
        "unknown_ui_drift": (
            "FuseKit is in guided takeover because this provider screen is new.",
            "Complete only highlighted provider prompts or provider-owned account checks.",
            (
                "Do not enter secrets anywhere except provider pages or Capture from VM "
                "clipboard buttons."
            ),
            "Click I finished this step so FuseKit can re-verify the setup.",
        ),
    }
    steps = templates.get(kind, templates["unknown_ui_drift"])
    return tuple(step for step in ((target_step,) if target_step else ()) + steps if step)


def _append_stump_events(
    events: list[BrowserPlaybookEvent],
    *,
    provider: str,
    spine: InferenceSpine,
    classification: StumpClassification,
    url: str,
) -> None:
    events.append(
        BrowserPlaybookEvent(
            provider=provider,
            action="stump.classify",
            status=classification.kind,
            url=url,
            note=f"{classification.reason} Confidence: {classification.confidence}.",
        )
    )
    attention = _highlight_attention(spine, classification.target)
    if attention is not None:
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="attention.highlight",
                status=attention.status,
                url=url,
                note="Highlighted the provider screen area that appears to need human attention.",
            )
        )
    for index, step in enumerate(classification.follow_steps, start=1):
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="follow.step",
                status="guided",
                url=_redact_url(url),
                note=f"{index}. {_redact_public_text(step)}",
            )
        )


def _record_stump_gate(
    events: list[BrowserPlaybookEvent],
    *,
    provider: str,
    spine: InferenceSpine,
    snapshot: str,
    reason: str,
    url: str,
    target: str,
    gate_recorder: GateRecorder | None,
) -> str:
    classification = classify_ui_stump(
        provider=provider,
        snapshot=snapshot,
        reason=reason,
        target=target,
    )
    _append_stump_events(
        events,
        provider=provider,
        spine=spine,
        classification=classification,
        url=url,
    )
    gate_id = _record_gate(
        gate_recorder,
        provider=provider,
        classification=classification,
        reason=reason,
        url=url,
    )
    events.append(
        BrowserPlaybookEvent(
            provider=provider,
            action="human.takeover",
            status="waiting",
            url=url,
            note="Guided provider takeover is available; FuseKit will resume from verification.",
        )
    )
    return gate_id


def _record_gate(
    gate_recorder: GateRecorder | None,
    *,
    provider: str,
    classification: StumpClassification,
    reason: str,
    url: str,
) -> str:
    gate_id = _gate_id(provider, classification.kind, reason or classification.reason)
    if gate_recorder is not None:
        return gate_recorder(
            gate_id,
            provider,
            reason or classification.reason,
            _redact_url(url),
            _public_target_hint(classification.target),
            classification.follow_steps,
            classification.kind,
        )
    return gate_id


def _gate_completed(gate_passed: GatePassedChecker | None, gate_id: str) -> bool:
    if gate_passed is None:
        return False
    try:
        return gate_passed(gate_id)
    except Exception:
        return False


def _gate_id(provider: str, kind: str, reason: str) -> str:
    safe_provider = re.sub(r"[^a-z0-9_-]+", "-", provider.lower()).strip("-") or "provider"
    digest = hashlib.sha256(_redact_error(reason).encode("utf-8")).hexdigest()[:10]
    return f"provider.{safe_provider}.{kind}.{digest}"


def _is_terminal_policy_error(message: str) -> bool:
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "non-https",
            "outside the provider domain",
            "unsafe keypress",
            "raw secret entry",
        )
    )


def _snapshot_text(snapshot: str) -> str:
    if not snapshot:
        return ""
    try:
        data = json.loads(snapshot)
    except json.JSONDecodeError:
        return snapshot[:4000]
    values: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, str):
            values.append(_redact_public_text(value))
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)
    return " ".join(values)[:8000]


def _best_target_hint(snapshot: str, haystack: str) -> str:
    try:
        data = json.loads(snapshot)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    candidates = data.get("refs") or data.get("elements") or []
    if not isinstance(candidates, list):
        return ""
    keywords = (
        "continue",
        "approve",
        "authorize",
        "create",
        "api key",
        "settings",
        "token",
        "verify",
        "sign in",
        "login",
    )
    for item in candidates:
        text = (
            json.dumps(item, sort_keys=True).lower()
            if isinstance(item, dict)
            else str(item).lower()
        )
        if any(keyword in text or keyword in haystack for keyword in keywords):
            if isinstance(item, dict):
                for key in ("ref", "id", "selector", "text", "name", "label"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        return _public_target_hint(value)
            return _public_target_hint(str(item))
    return ""


def _write_provider_memory(
    path: Path | None,
    provider: str,
    goal: str,
    history: list[InferredUiAction],
    events: list[BrowserPlaybookEvent],
) -> None:
    if path is None:
        return
    useful_actions = [
        action.redacted()
        for action in history
        if action.action not in {"gate"} and action.action in ALLOWED_ACTIONS
    ]
    if not useful_actions or not any(event.status == "done" for event in events):
        return
    payload = {
        "schema_version": "fusekit.provider-memory.v1",
        "provider": provider,
        "goal": _redact_public_text(goal),
        "actions": useful_actions,
        "events": [
            {
                "action": event.action,
                "status": event.status,
                "note": _redact_public_text(event.note)[:240],
            }
            for event in events
            if event.action in {"stump.classify", "follow.step", "stop", "observe.after"}
        ],
        "updated_at": int(time.time()),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_private(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError:
        return


def _looks_like_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return (
        len(value) >= 24
        and not value.startswith("env:")
        and any(prefix in lowered for prefix in ("sk_", "ghp_", "whsec_", "rk_"))
    )


def _public_target_hint(value: str) -> str:
    """Return a UI target hint only when it is safe to persist."""

    text = _redact_public_text(value).strip()
    if not text or "[redacted]" in text.lower():
        return ""
    if len(text) > 120:
        return ""
    return text


def _redact_public_text(text: str) -> str:
    return _redact_error(_redact_url(text))


def _redact_url(text: str) -> str:
    if not text:
        return ""
    return re.sub(
        r"([?&](?:token|key|secret|code|password|passphrase|signature)=)[^&#\s]+",
        r"\1[redacted]",
        text,
        flags=re.IGNORECASE,
    )


def _atomic_write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp, path)
        path.chmod(0o600)
    except Exception:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _safe_https_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _allowed_navigation_url(url: str, allowed_domains: tuple[str, ...]) -> bool:
    if not allowed_domains:
        return True
    host = (urlparse(url).hostname or "").lower()
    return any(
        host == domain or host.endswith(f".{domain}")
        for domain in allowed_domains
        if domain
    )


def _allowed_wait_url(url: str, allowed_domains: tuple[str, ...]) -> bool:
    if not allowed_domains:
        return True
    if not url:
        return True
    parsed = urlparse(url.replace("*", "placeholder"))
    host = (parsed.hostname or "").lower()
    return not host or any(
        host == domain or host.endswith(f".{domain}")
        for domain in allowed_domains
        if domain
    )


def _root_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().strip(".")
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def _try_spine(spine: InferenceSpine, method: str) -> SpineResult | None:
    candidate = getattr(spine, method, None)
    if not callable(candidate):
        return None
    try:
        result = candidate()
        return result if isinstance(result, SpineResult) else None
    except Exception:
        return None


def _stop_trace_if_needed(spine: InferenceSpine, trace_running: bool) -> SpineResult | None:
    return _try_spine(spine, "trace_stop") if trace_running else None


def _safe_snapshot(spine: InferenceSpine) -> str:
    try:
        return spine.snapshot().stdout
    except Exception:
        return ""


def _resurface_gate(spine: InferenceSpine, url: str) -> None:
    try:
        if url and _safe_https_url(url):
            spine.open(url)
        spine.snapshot()
    except Exception:
        return


def _highlight_attention(spine: InferenceSpine, target: str) -> SpineResult | None:
    target = target.strip()
    if not target:
        return None
    scroller = getattr(spine, "scroll_into_view", None)
    if callable(scroller):
        try:
            scroller(target)
        except Exception:
            return None
    candidate = getattr(spine, "highlight", None)
    if not callable(candidate):
        return None
    try:
        result = candidate(target)
        return result if isinstance(result, SpineResult) else None
    except Exception:
        return None


def _diagnostic_events(
    provider: str,
    spine: InferenceSpine,
    exc: ProviderError,
    trace: SpineResult | None,
) -> list[BrowserPlaybookEvent]:
    events = [
        BrowserPlaybookEvent(
            provider=provider,
            action="recover",
            status="blocked",
            note=f"Computer-use action needs recovery: {_redact_error(str(exc))}",
        )
    ]
    if trace and trace.stdout:
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="trace",
                status="captured",
                note=_redact_error(trace.stdout.strip()[:400]),
            )
        )
    for method, action in (
        ("console_errors", "console.errors"),
        ("network_requests", "network.requests"),
    ):
        result = _try_spine(spine, method)
        if result and result.stdout:
            events.append(
                BrowserPlaybookEvent(
                    provider=provider,
                    action=action,
                    status="captured",
                    note=_redact_error(result.stdout.strip()[:400]),
                )
            )
    snapshot = _safe_snapshot(spine)
    if snapshot:
        events.append(
            BrowserPlaybookEvent(
                provider=provider,
                action="observe.recovery",
                status="ok",
                url=_snapshot_url(snapshot),
                note=_snapshot_summary(snapshot),
            )
        )
    return events


def _snapshot_url(snapshot: str) -> str:
    try:
        data = json.loads(snapshot)
    except json.JSONDecodeError:
        return ""
    if isinstance(data, dict):
        page = data.get("page")
        page_url = page.get("url") if isinstance(page, dict) else ""
        return str(data.get("url") or page_url or "")
    return ""


def _snapshot_summary(snapshot: str) -> str:
    if not snapshot:
        return "No browser snapshot was available."
    try:
        data = json.loads(snapshot)
    except json.JSONDecodeError:
        return f"Observed browser state ({min(len(snapshot), 600)} chars)."
    if not isinstance(data, dict):
        return "Observed browser state."
    refs = data.get("refs")
    stats = data.get("stats")
    elements = data.get("elements")
    if isinstance(stats, dict):
        return (
            f"Observed page snapshot with {stats.get('refs', 'unknown')} refs "
            f"and {stats.get('chars', 'unknown')} chars."
        )
    if isinstance(refs, list):
        return f"Observed page snapshot with {len(refs)} refs."
    if isinstance(elements, list):
        return f"Observed page snapshot with {len(elements)} visible controls."
    return "Observed browser state."


def _redact_error(text: str) -> str:
    patterns = [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        r"sk-[A-Za-z0-9_-]{12,}",
        r"sk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"pk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"gh[pousr]_[A-Za-z0-9_]{12,}",
        r"github_pat_[A-Za-z0-9_]{12,}",
        r"whsec_[A-Za-z0-9_]{12,}",
        r"rk_[A-Za-z0-9_-]{12,}",
        r"re_[A-Za-z0-9_-]{12,}",
        r"plaid-[A-Za-z0-9_-]{12,}",
        r"xox[baprs]-[A-Za-z0-9-]{12,}",
        r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}",
        r"\b[A-Fa-f0-9]{48,}\b",
        r"\b[A-Za-z0-9_-]{36,}\b",
    ]
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[redacted]", redacted, flags=re.DOTALL)
    return redacted
