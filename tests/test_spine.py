from __future__ import annotations

import subprocess

import fusekit.runtime.bootstrap as bootstrap
from fusekit.spine import (
    InferredUiAction,
    OpenClawBrowserSpine,
    PlaywrightBrowserSpine,
    StaticUiNavigator,
    execute_provider_ui_playbook,
    provider_authorization_playbook,
    provider_ui_playbook,
    run_inferred_navigation,
)


def test_openclaw_spine_builds_browser_commands() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    spine = OpenClawBrowserSpine(profile="work", runner=runner)
    result = spine.open("https://example.com")

    assert result.status == "ok"
    assert calls == [
        [
            "env",
            f"OPENCLAW_HOME={bootstrap.openclaw_state_home()}",
            "openclaw",
            "browser",
            "--browser-profile",
            "work",
            "open",
            "https://example.com",
        ]
    ]


def test_openclaw_spine_supports_inferred_action_surface() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    spine = OpenClawBrowserSpine(profile="work", runner=runner)

    assert spine.click_text("ref-1").status == "ok"
    assert spine.fill_label("ref-2", "redacted").status == "ok"
    assert spine.press("Enter").status == "ok"
    assert spine.wait_for_text("Ready").status == "ok"

    assert calls[0][-2:] == ["click", "ref-1"]
    assert calls[1][-3:] == ["type", "ref-2", "redacted"]
    assert calls[2][-2:] == ["press", "Enter"]
    assert calls[3][-1:] == ["snapshot"]


def test_provider_playbook_uses_openclaw_spine_without_secrets() -> None:
    spine = OpenClawBrowserSpine(profile="openclaw", dry_run=True)

    events = provider_authorization_playbook("vercel", spine, include_project=True)

    assert [event.action for event in events] == [
        "policy.boundary",
        "open",
        "open",
        "open",
        "capture",
    ]
    assert events[1].url == "https://vercel.com/signup"
    assert events[-1].status == "awaiting-approved-secret"


def test_playwright_spine_dry_run_does_not_need_local_browser() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)

    assert spine.start().status == "dry-run"
    assert spine.open("https://resend.com/api-keys").status == "dry-run"
    assert spine.click_text("Create API Key").command[-1] == "Create API Key"


def test_resend_ui_playbook_uses_computer_actions_without_secrets() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    playbook = provider_ui_playbook("resend", include_project=True)

    events = execute_provider_ui_playbook(playbook, spine)

    assert any(event.action == "click_text" for event in events)
    assert any("DNS" in event.note for event in events)
    assert "RESEND_API_KEY" in events[-1].note


def test_inferred_navigation_waits_at_gate_then_resumes() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("click_text", target="API Keys", reason="Open key page"),
            InferredUiAction(
                "fill_label",
                target="Password",
                value="not-written",
                reason="Password is required",
            ),
            InferredUiAction("click_text", target="Create API Key", reason="Gate passed"),
            InferredUiAction("stop", reason="API key page reached"),
        ]
    )

    events = run_inferred_navigation(
        provider="resend",
        goal="create an API key",
        start_url="https://resend.com/api-keys",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
    )

    assert any(event.action == "gate" and event.status == "waiting" for event in events)
    assert events[-1].action == "stop"
    assert events[-1].status == "done"


def test_inferred_navigation_gate_attempt_limit_is_for_ci() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("gate", reason="MFA required"),
            InferredUiAction("gate", reason="MFA still required"),
        ]
    )

    events = run_inferred_navigation(
        provider="github",
        goal="create a token",
        start_url="https://github.com/settings/tokens",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
        max_gate_attempts=2,
    )

    assert events[-1].action == "gate"
    assert events[-1].status == "max-attempts"
