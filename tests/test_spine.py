from __future__ import annotations

import json
import subprocess

import fusekit.runtime.bootstrap as bootstrap
from fusekit.llm import LlmConfig
from fusekit.spine import (
    InferredUiAction,
    OpenAiUiNavigator,
    OpenClawBrowserSpine,
    PlaywrightBrowserSpine,
    StaticUiNavigator,
    classify_ui_stump,
    execute_provider_ui_playbook,
    provider_authorization_playbook,
    provider_ui_playbook,
    run_inferred_navigation,
)
from fusekit.vault import Vault


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


def test_openclaw_spine_can_use_default_openclaw_home(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv("FUSEKIT_OPENCLAW_HOME_MODE", "default")

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    spine = OpenClawBrowserSpine(profile="work", runner=runner)
    result = spine.open("https://example.com")

    assert result.status == "ok"
    assert calls == [
        [
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
    assert spine.highlight("ref-3").status == "ok"
    assert spine.scroll_into_view("ref-3").status == "ok"
    assert spine.wait_for_state(selector="#main", url="**/dashboard").status == "ok"

    assert calls[0][-2:] == ["click", "ref-1"]
    assert calls[1][-3:] == ["type", "ref-2", "redacted"]
    assert calls[2][-2:] == ["press", "Enter"]
    assert calls[3][-3:] == ["wait", "--text", "Ready"]
    assert calls[4][-2:] == ["highlight", "ref-3"]
    assert calls[5][-2:] == ["scrollintoview", "ref-3"]
    assert calls[6][-7:] == [
        "#main",
        "--url",
        "**/dashboard",
        "--load",
        "networkidle",
        "--timeout-ms",
        "15000",
    ]


def test_openclaw_spine_uses_interactive_json_snapshots_and_trace() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"stats":{"refs":2}}', stderr="")

    spine = OpenClawBrowserSpine(profile="work", runner=runner)

    assert spine.snapshot().status == "ok"
    assert spine.trace_start().status == "ok"
    assert spine.trace_stop().status == "ok"

    assert calls[0][-7:] == [
        "snapshot",
        "--interactive",
        "--compact",
        "--depth",
        "6",
        "--efficient",
        "--json",
    ]
    assert calls[1][-2:] == ["trace", "start"]
    assert calls[2][-2:] == ["trace", "stop"]


def test_openclaw_spine_can_request_labelled_snapshots_and_fresh_diagnostics() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    spine = OpenClawBrowserSpine(profile="work", label_snapshots=True, runner=runner)

    assert spine.snapshot().status == "ok"
    assert spine.console_errors().status == "ok"
    assert spine.network_requests().status == "ok"

    assert "--labels" in calls[0]
    assert calls[1][-3:] == ["errors", "--clear", "--json"]
    assert calls[2][-5:] == ["requests", "--filter", "api", "--clear", "--json"]


def test_openclaw_spine_public_serialization_redacts_browser_output_and_typed_text() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[-1] == "secret-token-value":
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"text":"secret-token-value"}',
            stderr="",
        )

    spine = OpenClawBrowserSpine(profile="work", runner=runner)

    typed = spine.fill_label("ref-2", "secret-token-value").to_dict()
    snapshot = spine.snapshot().to_dict()

    assert "secret-token-value" not in str(typed)
    assert typed["command"][-1] == "[REDACTED]"
    assert "secret-token-value" not in str(snapshot)
    assert str(snapshot["stdout"]).startswith("[REDACTED_BROWSER_OUTPUT")


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
    assert spine.highlight("ref=1").status == "dry-run"


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
    assert any(event.action == "observe" for event in events)
    assert any(event.action == "observe.after" for event in events)
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


def test_inferred_navigation_highlights_gate_target() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("gate", target="ref=7", reason="MFA required"),
            InferredUiAction("stop", reason="done"),
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

    assert any(event.action == "attention.highlight" for event in events)


def test_inferred_navigation_uses_openclaw_rich_wait_and_scrolls_gate_target() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    spine = OpenClawBrowserSpine(profile="work", runner=runner)
    navigator = StaticUiNavigator(
        [
            InferredUiAction(
                "wait",
                target="#ready",
                url="**/settings",
                value="networkidle",
                reason="wait for account settings",
            ),
            InferredUiAction("gate", target="e12", reason="MFA required"),
            InferredUiAction("stop", reason="done"),
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

    assert any(event.action == "wait" for event in events)
    assert any(
        command[-8:]
        == [
            "wait",
            "#ready",
            "--url",
            "**/settings",
            "--load",
            "networkidle",
            "--timeout-ms",
            "15000",
        ]
        for command in calls
    )
    assert any(command[-2:] == ["scrollintoview", "e12"] for command in calls)
    assert any(command[-2:] == ["highlight", "e12"] for command in calls)


def test_inferred_navigation_rejects_non_https_navigation() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("open", url="javascript:alert(1)", reason="unsafe nav"),
        ]
    )

    events = run_inferred_navigation(
        provider="github",
        goal="create a token",
        start_url="https://github.com/settings/tokens",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
    )

    recovery = [event for event in events if event.action == "recover"]
    assert recovery
    assert "non-HTTPS" in recovery[0].note


def test_inferred_navigation_rejects_cross_provider_navigation() -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("open", url="https://evil.example/phish", reason="leave provider"),
        ]
    )

    events = run_inferred_navigation(
        provider="github",
        goal="create a token",
        start_url="https://github.com/settings/tokens",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
    )

    recovery = [event for event in events if event.action == "recover"]
    assert recovery
    assert "outside the provider domain" in recovery[0].note


def test_inferred_navigation_captures_recovery_event_on_action_failure() -> None:
    class FailingSpine(PlaywrightBrowserSpine):
        def click_text(self, text: str):  # type: ignore[no-untyped-def]
            raise RuntimeError("button vanished redaction-sentinel-123456789012")

    spine = FailingSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("click_text", target="Create API Key", reason="open key form"),
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

    takeover = [event for event in events if event.action == "human.takeover"]
    assert takeover
    assert takeover[0].status == "waiting"
    assert "redaction-sentinel" not in takeover[0].note
    assert any(event.action == "stump.classify" for event in events)


def test_stump_classifier_covers_provider_gate_types() -> None:
    samples = {
        "login": "Sign in with email address and password",
        "mfa": "Enter two-factor verification code from authenticator",
        "captcha": "Verify you are human with CAPTCHA",
        "consent": "Authorize app permissions and grant access",
        "billing": "Add payment card to continue billing verification",
        "missing_token": "Create API key and copy token",
        "api_error": "HTTP 403 provider API error",
        "page_loading": "Loading spinner please wait",
        "changed_navigation": "Could not find selector because button vanished",
    }
    for expected, text in samples.items():
        snapshot = json.dumps({"elements": [{"text": text, "ref": "ref-1"}]})
        result = classify_ui_stump(provider="resend", snapshot=snapshot)
        assert result.kind == expected
        assert result.follow_steps


def test_stump_follow_me_steps_do_not_delegate_interpretation() -> None:
    forbidden = ("look at", "figure", "yourself", "manually", "if shown")
    for kind in (
        "login",
        "mfa",
        "captcha",
        "consent",
        "billing",
        "missing_token",
        "api_error",
        "page_loading",
        "changed_navigation",
        "unknown_ui_drift",
    ):
        result = classify_ui_stump(
            provider="resend",
            snapshot=json.dumps({"elements": [{"text": "Continue", "ref": "ref-1"}]}),
            reason=kind.replace("_", " "),
        )
        text = " ".join(result.follow_steps).lower()
        assert all(phrase not in text for phrase in forbidden)
        assert any(anchor in text for anchor in ("highlighted", "fusekit", "provider"))


def test_inferred_navigation_records_follow_me_gate_details(tmp_path) -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("gate", target="ref=7", reason="MFA required"),
            InferredUiAction("stop", reason="done"),
        ]
    )
    recorded: list[tuple[str, str, str, str, str, tuple[str, ...], str]] = []

    def recorder(
        gate_id: str,
        provider: str,
        reason: str,
        resume_url: str,
        target: str,
        follow_steps: tuple[str, ...],
        classification: str,
    ) -> str:
        recorded.append(
            (gate_id, provider, reason, resume_url, target, follow_steps, classification)
        )
        return gate_id

    events = run_inferred_navigation(
        provider="github",
        goal="create a token",
        start_url="https://github.com/settings/tokens",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
        max_gate_attempts=1,
        gate_recorder=recorder,
        provider_memory_path=tmp_path / "memory.json",
    )

    assert recorded
    assert recorded[0][-1] == "mfa"
    assert recorded[0][4] == "ref=7"
    assert any(event.action == "follow.step" for event in events)


def test_inferred_navigation_writes_redacted_provider_memory(tmp_path) -> None:
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction("click_text", target="API Keys", reason="open key form"),
            InferredUiAction("stop", reason="done"),
        ]
    )
    memory = tmp_path / "provider-memory" / "resend.json"

    events = run_inferred_navigation(
        provider="resend",
        goal="create API key redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456",
        start_url="https://resend.com/api-keys",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
        provider_memory_path=memory,
    )

    assert events[-1].status == "done"
    text = memory.read_text("utf-8")
    assert "API Keys" in text
    assert "redaction_sentinel" not in text


def test_stump_classifier_does_not_persist_secret_text_as_target() -> None:
    secret = "redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456"
    snapshot = json.dumps({"elements": [{"text": f"Copy {secret}", "label": secret}]})

    result = classify_ui_stump(
        provider="resend",
        snapshot=snapshot,
        reason="Create API key",
    )

    assert result.kind == "missing_token"
    assert result.target == ""
    assert secret not in " ".join(result.follow_steps)


def test_provider_memory_redacts_reasons_urls_and_targets(tmp_path) -> None:
    secret = "redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456"
    spine = PlaywrightBrowserSpine(dry_run=True)
    navigator = StaticUiNavigator(
        [
            InferredUiAction(
                "open",
                url=f"https://resend.com/api-keys?token={secret}",
                reason=f"open token {secret}",
            ),
            InferredUiAction("click_text", target=f"Copy {secret}", reason="click key"),
            InferredUiAction("stop", reason=f"done {secret}"),
        ]
    )
    memory = tmp_path / "provider-memory" / "resend.json"

    run_inferred_navigation(
        provider="resend",
        goal=f"create API key {secret}",
        start_url="https://resend.com/api-keys",
        spine=spine,
        navigator=navigator,
        gate_retry_seconds=0,
        provider_memory_path=memory,
    )

    text = memory.read_text("utf-8")
    assert secret not in text
    assert "[redacted]" in text
    assert oct(memory.stat().st_mode & 0o777) == "0o600"


def test_openai_ui_navigator_redacts_snapshot_before_llm(monkeypatch) -> None:
    secret = "redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456"
    captured: dict[str, object] = {}
    vault = Vault.empty()
    vault.put("llm.openai.api_key", "provider_token", "openai", "api key", "llm-token")

    class Response:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"choices": [{"message": {"content": '{"action":"stop","reason":"done"}'}}]}
            ).encode("utf-8")

    def fake_urlopen(request, timeout=60):  # type: ignore[no-untyped-def]
        captured["body"] = request.data.decode("utf-8")
        return Response()

    monkeypatch.setattr("fusekit.spine.infer.urlopen", fake_urlopen)

    navigator = OpenAiUiNavigator(
        LlmConfig(
            provider="openai",
            model="gpt-test",
            base_url="https://api.openai.com/v1",
            api_key_env="OPENAI_API_KEY",
        ),
        vault,
    )
    navigator.next_action(
        provider="resend",
        goal="create key",
        snapshot=json.dumps({"elements": [{"text": secret}]}),
        history=[],
    )

    assert secret not in str(captured["body"])
