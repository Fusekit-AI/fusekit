"""Inferred provider UI navigation loop."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
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
            else self.value
        )
        return {
            "action": self.action,
            "target": self.target,
            "value": value,
            "url": self.url,
            "reason": self.reason,
        }


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
                            "snapshot": snapshot[:6000],
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
            trace = _stop_trace_if_needed(spine, trace_running)
            events.extend(_diagnostic_events(provider, spine, exc, trace))
            break
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
            attention = _highlight_attention(spine, action.target)
            if attention is not None:
                events.append(
                    BrowserPlaybookEvent(
                        provider=provider,
                        action="attention.highlight",
                        status=attention.status,
                        url=action.url,
                        note=(
                            "Highlighted the provider screen area that appears to need "
                            "human attention."
                        ),
                    )
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
        action_steps += 1
        try:
            result = _execute_action(spine, action)
        except Exception as exc:
            trace = _stop_trace_if_needed(spine, trace_running)
            provider_error = exc if isinstance(exc, ProviderError) else ProviderError(str(exc))
            events.extend(_diagnostic_events(provider, spine, provider_error, trace))
            break
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


def _looks_like_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return (
        len(value) >= 24
        and not value.startswith("env:")
        and any(prefix in lowered for prefix in ("sk_", "ghp_", "whsec_", "rk_"))
    )


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
            pass
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
        r"sk-[A-Za-z0-9_-]{12,}",
        r"gh[pousr]_[A-Za-z0-9_]{12,}",
        r"whsec_[A-Za-z0-9_]{12,}",
        r"rk_[A-Za-z0-9_]{12,}",
    ]
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[redacted]", redacted)
    return redacted
