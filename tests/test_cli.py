from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.error import URLError

import pytest

from fusekit.audit import AuditLog, Receipt, assert_no_secret_text
from fusekit.cli import (
    _attempt_provider_api_fallback,
    _authorize_provider,
    _await_dns_approval,
    _await_provider_token,
    _capture_llm,
    _capture_manifest_provider_env,
    _capture_provider_tokens,
    _github_source_handoff,
    _has_pack_provider_token,
    _local_verification_job_result,
    _ordered_provider_services,
    _playwright_headless,
    _provider_verification_acceptable,
    _provider_verification_attempt_config,
    _rebase_setup_artifacts,
    _record_provider_verification_gates,
    _repair_navigation_completed,
    _run_handoff,
    _run_manifest_provider_pack_setup,
    _runtime_env_secrets,
    _sleep_for_gate,
    _start_openclaw_auth_terminal,
    _ui_navigator_from_vault,
    _verify_apply_live_url,
    _verify_provider_packs,
    main,
)
from fusekit.detonation.preflight import verification_report_allows_detonation
from fusekit.errors import ApprovalRequired, FuseKitError, ProviderError
from fusekit.manifest import (
    DnsRecord,
    DomainRequirement,
    ServiceRequirement,
    SetupManifest,
    write_manifest,
)
from fusekit.providers.automation import ProviderSetupContext
from fusekit.providers.capability_pack import (
    PackHandoff,
    VerificationRecipe,
    synthesize_provider_pack,
    write_provider_pack,
)
from fusekit.providers.handoff import handoff_for
from fusekit.providers.verification import VerificationResult
from fusekit.runner.gates import GateService
from fusekit.runner.oci_live import OciWorkspace
from fusekit.spine.playbooks import BrowserPlaybookEvent
from fusekit.vault import Vault
from fusekit.verification_report import VerificationReport


def test_rebase_setup_artifacts_rebases_report_and_rollback(tmp_path) -> None:
    args = argparse.Namespace(
        vault=Path(".fusekit/fusekit.vault.json"),
        audit_log=Path(".fusekit/audit.jsonl"),
        receipt_json=Path(".fusekit/setup_receipt.json"),
        receipt_md=Path(".fusekit/setup_receipt.md"),
        rollback_json=Path(".fusekit/rollback_plan.json"),
        verification_report=Path(".fusekit/verification_report.json"),
        plan_json=Path(".fusekit/setup_plan.json"),
        job_state=Path(".fusekit/job.json"),
    )
    app = tmp_path / "app"

    _rebase_setup_artifacts(args, app)

    assert args.verification_report == app / ".fusekit" / "verification_report.json"
    assert args.rollback_json == app / ".fusekit" / "rollback_plan.json"


def test_install_writes_one_click_entrypoint(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    assert main(["install", str(app)]) == 0

    assert (app / "fusekit.yaml").exists()
    setup_script = app / ".fusekit" / "setup.sh"
    assert setup_script.exists()
    assert "fusekit launch . --manifest fusekit.yaml" in setup_script.read_text(encoding="utf-8")
    gitignore = (app / ".gitignore").read_text(encoding="utf-8")
    assert ".fusekit/*.vault.json" in gitignore


def test_runtime_env_secrets_derive_live_url_and_use_matching_vault_records() -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_token",
        "resend",
        "RESEND_API_KEY",
        "resend-runtime-key",
        {"env": "RESEND_API_KEY"},
    )
    manifest = SetupManifest(
        app_name="app",
        required_env=("NEXT_PUBLIC_APP_URL", "RESEND_API_KEY", "RESEND_FROM_EMAIL"),
        services=(ServiceRequirement(provider="resend", kind="email", name="email"),),
    )
    args = argparse.Namespace(live_url="https://moonlite.rsvp", secret=[])

    secrets = _runtime_env_secrets(args, manifest, vault)

    assert secrets["NEXT_PUBLIC_APP_URL"] == "https://moonlite.rsvp"
    assert secrets["RESEND_API_KEY"] == "resend-runtime-key"
    assert "RESEND_FROM_EMAIL" not in secrets


def test_runtime_env_secrets_use_provider_generated_resend_settings() -> None:
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_from_email",
        "provider_setting",
        "resend",
        "RESEND_FROM_EMAIL",
        "rsvp@moonlite.rsvp",
        {"domain": "moonlite.rsvp"},
    )
    vault.put(
        "provider.resend.resend_audience_id",
        "provider_setting",
        "resend",
        "RESEND_AUDIENCE_ID",
        "audience-123",
        {"name": "Moonlite RSVP audience"},
    )
    manifest = SetupManifest(
        app_name="app",
        required_env=("RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"),
        services=(ServiceRequirement(provider="resend", kind="email", name="email"),),
    )
    args = argparse.Namespace(live_url="", secret=[])

    secrets = _runtime_env_secrets(args, manifest, vault)

    assert secrets["RESEND_FROM_EMAIL"] == "rsvp@moonlite.rsvp"
    assert secrets["RESEND_AUDIENCE_ID"] == "audience-123"


def test_runtime_env_secrets_collect_required_env_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RESEND_FROM_EMAIL", "rsvp@moonlite.rsvp")
    manifest = SetupManifest(
        app_name="app",
        required_env=("RESEND_FROM_EMAIL",),
        services=(ServiceRequirement(provider="resend", kind="email", name="email"),),
    )
    args = argparse.Namespace(live_url="", secret=[])

    secrets = _runtime_env_secrets(args, manifest, Vault.empty())

    assert secrets["RESEND_FROM_EMAIL"] == "rsvp@moonlite.rsvp"


def test_capture_manifest_provider_env_includes_service_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RESEND_FROM_EMAIL", "rsvp@moonlite.rsvp")
    vault = Vault.empty()
    manifest = SetupManifest(
        app_name="app",
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                env=("RESEND_FROM_EMAIL",),
            ),
        ),
    )

    _capture_manifest_provider_env(vault, manifest)

    record = vault.require("provider.resend.resend_from_email")
    assert record.value == "rsvp@moonlite.rsvp"
    assert record.metadata["source"] == "env:RESEND_FROM_EMAIL"


def test_provider_setup_orders_resend_before_dns() -> None:
    services = {
        "cloudflare": ServiceRequirement(provider="cloudflare", kind="dns", name="dns"),
        "resend": ServiceRequirement(provider="resend", kind="email", name="email"),
        "vercel": ServiceRequirement(provider="vercel", kind="hosting", name="hosting"),
        "github": ServiceRequirement(provider="github", kind="source", name="source"),
    }

    ordered = [provider for provider, _service in _ordered_provider_services(services)]

    assert ordered == ["github", "resend", "vercel", "cloudflare"]


def test_provider_setup_pauses_dns_behind_resend_human_gate(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    calls: list[str] = []

    def fake_run_provider_pack_setup(pack, context):  # type: ignore[no-untyped-def]
        del context
        calls.append(pack.provider)
        if pack.provider == "resend":
            return {
                "provider": "resend",
                "setup": [
                    {
                        "kind": "resend-domain",
                        "status": "needs_human_gate",
                        "strategy": "browser_guided",
                        "reason": "Resend API key is required before DNS records exist.",
                        "strategy_decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "needs_human_gate",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Provider token is missing.",
                            },
                            "candidates": [{"kind": "browser_guided"}],
                        },
                    }
                ],
            }
        raise AssertionError(f"{pack.provider} should wait for the Resend gate")

    monkeypatch.setattr("fusekit.cli.run_provider_pack_setup", fake_run_provider_pack_setup)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(provider="resend", kind="email", name="email"),
            ServiceRequirement(provider="cloudflare", kind="dns", name="dns"),
        ),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    args = argparse.Namespace(
        app=app,
        vault=app / ".fusekit" / "fusekit.vault.json",
        allow_incomplete=False,
        fusekit_gates="service-only",
        github_repo="",
        vercel_project="",
        vercel_framework="",
        vercel_git_repo_id="",
        vercel_git_ref="main",
        dns_zone="moonlite.rsvp",
    )
    context = ProviderSetupContext(
        manifest=manifest,
        vault=Vault.empty(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"resend", "cloudflare"},
        inputs={"dns_zone": "moonlite.rsvp"},
    )

    _run_manifest_provider_pack_setup(args, manifest, context)

    assert calls == ["resend"]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.resend-domain"
    ]
    assert gate.provider == "resend"
    assert "before DNS records exist" in gate.reason
    actions = context.receipt.to_dict()["actions"]
    assert actions[-1]["action"] == "provider_pack.setup.paused"
    assert actions[-1]["status"] == "needs_human_gate"
    assert actions[-1]["details"]["provider"] == "resend"


def test_manifest_setup_feeds_resend_dns_records_to_cloudflare(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    (app / ".fusekit").mkdir(parents=True)
    vault_path = app / ".fusekit" / "fusekit.vault.json"
    vault_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    def fake_run_provider_pack_setup(pack, context):  # type: ignore[no-untyped-def]
        calls.append(pack.provider)
        if pack.provider == "resend":
            context.generated_dns_records.setdefault("moonlite.rsvp", []).append(
                DnsRecord(
                    name="send.moonlite.rsvp",
                    type="MX",
                    value="feedback-smtp.us-east-1.amazonses.com",
                    priority=10,
                )
            )
            return {
                "provider": "resend",
                "setup": [
                    {
                        "kind": "resend-domain",
                        "status": "ok",
                        "strategy": "api",
                        "strategy_decision": {"selected": {"kind": "api"}},
                    }
                ],
            }
        if pack.provider == "cloudflare":
            generated = context.generated_dns_records.get("moonlite.rsvp", [])
            assert [(record.name, record.type, record.priority) for record in generated] == [
                ("send.moonlite.rsvp", "MX", 10)
            ]
            return {
                "provider": "cloudflare",
                "setup": [
                    {
                        "kind": "cloudflare-dns",
                        "status": "ok",
                        "strategy": "api",
                        "strategy_decision": {"selected": {"kind": "api"}},
                    }
                ],
            }
        raise AssertionError(f"unexpected provider {pack.provider}")

    monkeypatch.setattr("fusekit.cli.run_provider_pack_setup", fake_run_provider_pack_setup)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(provider="resend", kind="email", name="email"),
            ServiceRequirement(provider="cloudflare", kind="dns", name="dns"),
        ),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    args = argparse.Namespace(
        app=app,
        vault=vault_path,
        allow_incomplete=False,
        fusekit_gates="service-only",
        github_repo="",
        vercel_project="",
        vercel_framework="",
        vercel_git_repo_id="",
        vercel_git_ref="main",
        dns_zone="moonlite.rsvp",
    )
    context = ProviderSetupContext(
        manifest=manifest,
        vault=Vault.empty(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"resend", "cloudflare"},
        inputs={"dns_zone": "moonlite.rsvp"},
    )

    _run_manifest_provider_pack_setup(args, manifest, context)

    assert calls == ["resend", "cloudflare"]


def test_control_room_dns_approval_waits_after_resend_records_before_cloudflare(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    (app / ".fusekit").mkdir(parents=True)
    vault_path = app / ".fusekit" / "fusekit.vault.json"
    vault_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    def fake_run_provider_pack_setup(pack, context):  # type: ignore[no-untyped-def]
        calls.append(pack.provider)
        if pack.provider == "resend":
            context.generated_dns_records.setdefault("moonlite.rsvp", []).append(
                DnsRecord(
                    name="send.moonlite.rsvp",
                    type="MX",
                    value="feedback-smtp.us-east-1.amazonses.com",
                    priority=10,
                )
            )
            return {
                "provider": "resend",
                "setup": [
                    {
                        "kind": "resend-domain",
                        "status": "ok",
                        "strategy": "api",
                        "strategy_decision": {"selected": {"kind": "api"}},
                    }
                ],
            }
        if pack.provider == "cloudflare":
            assert context.approve_dns is True
            return {
                "provider": "cloudflare",
                "setup": [
                    {
                        "kind": "cloudflare-dns",
                        "status": "ok",
                        "strategy": "api",
                        "strategy_decision": {"selected": {"kind": "api"}},
                    }
                ],
            }
        raise AssertionError(f"unexpected provider {pack.provider}")

    monkeypatch.setattr("fusekit.cli.run_provider_pack_setup", fake_run_provider_pack_setup)
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "")

    gate_id = "dns.moonlite.rsvp.approval"

    def approve_from_control_room(_seconds: float) -> None:
        GateService.load(app / ".fusekit" / "gates.json").request_resume(gate_id)

    monkeypatch.setattr("fusekit.cli.time.sleep", approve_from_control_room)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(provider="resend", kind="email", name="email"),
            ServiceRequirement(provider="cloudflare", kind="dns", name="dns"),
        ),
        domains=(
            DomainRequirement(
                provider="cloudflare",
                domain="moonlite.rsvp",
                records=(DnsRecord(name="moonlite.rsvp", type="A", value="76.76.21.21"),),
            ),
        ),
    )
    args = argparse.Namespace(
        app=app,
        vault=vault_path,
        allow_incomplete=False,
        fusekit_gates="service-only",
        github_repo="",
        vercel_project="",
        vercel_framework="",
        vercel_git_repo_id="",
        vercel_git_ref="main",
        dns_zone="moonlite.rsvp",
        approve_dns=False,
        control_room=True,
        gate_retry_seconds=10,
        gate_max_attempts=3,
    )
    context = ProviderSetupContext(
        manifest=manifest,
        vault=Vault.empty(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        receipt=Receipt(app_name="app"),
        secrets={},
        provider_names={"resend", "cloudflare"},
        inputs={"dns_zone": "moonlite.rsvp"},
    )

    _run_manifest_provider_pack_setup(args, manifest, context)

    assert calls == ["resend", "cloudflare"]
    assert args.approve_dns is True
    gate = GateService.load(app / ".fusekit" / "gates.json").records[gate_id]
    assert gate.status == "passed"
    steps = " ".join(gate.follow_steps)
    assert "App DNS records: A moonlite.rsvp -> 76.76.21.21" in steps
    assert "Provider-generated DNS records from Resend/API setup" in steps
    assert "MX send.moonlite.rsvp -> feedback-smtp.us-east-1.amazonses.com priority 10" in steps
    assert gate.next_action == "No action needed."


def test_gate_sleep_wakes_when_control_room_requests_resume(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    gate_path = app / ".fusekit" / "gates.json"
    gate_id = "provider.resend.authorization"
    GateService.load(gate_path).wait(
        gate_id,
        provider="resend",
        reason="Resend API key capture",
    )
    args = argparse.Namespace(app=app, gate_retry_seconds=300.0)
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        GateService.load(gate_path).request_resume(gate_id)

    monkeypatch.setattr("fusekit.cli.time.sleep", fake_sleep)

    _sleep_for_gate(args, gate_id=gate_id)

    assert sleeps == [1.0]


def test_dns_approval_accepts_control_room_resume(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    gate_id = "dns.moonlite.rsvp.approval"
    gate_path = app / ".fusekit" / "gates.json"
    service = GateService.load(gate_path)
    service.wait(
        gate_id,
        provider="dns",
        reason="explicit DNS apply approval for moonlite.rsvp",
    )
    service.request_resume(gate_id)
    args = argparse.Namespace(
        app=app,
        approve_dns=False,
        gate_max_attempts=1,
        gate_retry_seconds=0,
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda *args, **kwargs: pytest.fail("control-room approval should not reprompt"),
    )

    _await_dns_approval(args, "moonlite.rsvp")

    assert args.approve_dns is True
    gate = GateService.load(gate_path).records[gate_id]
    assert gate.status == "passed"


def test_playwright_fallback_is_headless_without_display(monkeypatch) -> None:
    args = argparse.Namespace(spine="openclaw", headless_browser=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr("fusekit.cli._openclaw_browser_available", lambda args: False)

    assert _playwright_headless(args) is True


def test_playwright_fallback_preserves_visible_local_browser(monkeypatch) -> None:
    args = argparse.Namespace(spine="openclaw", headless_browser=False)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr("fusekit.cli._openclaw_browser_available", lambda args: False)

    assert _playwright_headless(args) is False


def test_openclaw_auth_terminal_requires_visual_display(monkeypatch) -> None:
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr("fusekit.cli.shutil.which", lambda name: f"/usr/bin/{name}")

    assert _start_openclaw_auth_terminal(provider="openai", device_code=False) is False


def test_openclaw_auth_terminal_launches_visible_login(monkeypatch, tmp_path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setenv("DISPLAY", ":99")
    monkeypatch.setenv("FUSEKIT_HOME", str(tmp_path / "runtime"))
    monkeypatch.setenv("FUSEKIT_VISUAL_STATE_DIR", str(tmp_path / "visual"))
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "browsers"))
    chrome = tmp_path / "browsers" / "chromium-1" / "chrome-linux64" / "chrome"
    chrome.parent.mkdir(parents=True)
    chrome.write_text("#!/bin/sh\n", encoding="utf-8")
    chrome.chmod(0o755)
    monkeypatch.setattr(
        "fusekit.cli.shutil.which",
        lambda name: {
            "script": "/usr/bin/script",
            "xterm": "/usr/bin/xterm",
            "openclaw": "/opt/openclaw/bin/openclaw",
        }.get(name),
    )
    monkeypatch.setattr("fusekit.cli.subprocess.Popen", fake_popen)
    log = tmp_path / "visual" / "openclaw-auth-pty.log"

    def fake_read_text(*args, **kwargs):  # type: ignore[no-untyped-def]
        return (
            "Open this URL in your LOCAL browser:\n"
            "https://auth.openai.com/oauth/authorize?response_type=code"
        )

    monkeypatch.setattr("pathlib.Path.read_text", fake_read_text)

    assert _start_openclaw_auth_terminal(provider="openai", device_code=True) is True

    assert calls[0]["command"] == [
        "/usr/bin/script",
        "-qfec",
        calls[0]["command"][2],
        str(log),
    ]
    script_command = calls[0]["command"][2]
    assert f"OPENCLAW_HOME='{tmp_path / 'runtime' / 'openclaw-state'}'" in script_command
    assert "'/opt/openclaw/bin/openclaw' models auth login" in script_command
    assert "--provider 'openai' --set-default --device-code" in script_command
    assert calls[1]["command"][-1].startswith("https://auth.openai.com/oauth/authorize")
    assert calls[2]["command"][:2] == ["/usr/bin/xterm", "-geometry"]
    assert calls[0]["env"]["DISPLAY"] == ":99"


def test_ui_navigator_uses_openclaw_gate_fallback_without_api_key() -> None:
    args = argparse.Namespace(
        llm_provider="openai",
        llm_model="gpt-5.5",
        llm_base_url="https://api.openai.com/v1",
        llm_api_key_env="OPENAI_API_KEY",
    )
    vault = Vault.empty()
    vault.put(
        "llm.openai.openclaw_profile",
        "llm_openclaw_profile",
        "openclaw",
        "OpenClaw OpenAI authorization profile",
        "openai:openai/gpt-5.5",
    )

    navigator = _ui_navigator_from_vault(args, vault)
    action = navigator.next_action(provider="resend", goal="create key", snapshot="{}", history=[])

    assert action.action == "gate"
    assert "OpenClaw/OpenAI OAuth is authorized" in action.reason


def test_capture_llm_reuses_openclaw_profile_without_reauth(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(
        "fusekit.cli._await_openclaw_llm_authorization",
        lambda *args, **kwargs: pytest.fail("OpenClaw auth should not restart"),
    )
    args = argparse.Namespace(
        capture_llm_key=False,
        llm_api_key_env="OPENAI_API_KEY",
        llm_auth_mode="auto",
        llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-5.5",
        llm_provider="openai",
    )
    vault = Vault.empty()
    vault.put(
        "llm.openai.openclaw_profile",
        "llm_openclaw_profile",
        "openclaw",
        "OpenClaw OpenAI authorization profile",
        "openai:openai/gpt-5.5",
    )

    _capture_llm(args, vault, require=True)


def test_install_can_write_local_cloud_shell_launcher(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    assert (
        main(
            [
                "install",
                str(app),
                "--web-launcher",
                "--app-source",
                "https://github.com/example/app.git",
                "--fusekit-package",
                "git+https://github.com/example/fusekit.git",
            ]
        )
        == 0
    )

    launcher = app / ".fusekit" / "launcher.html"
    assert launcher.exists()
    text = launcher.read_text(encoding="utf-8")
    assert "Snowman FuseKit Launcher" in text
    assert "https://github.com/example/app.git" in text


def test_launcher_derives_no_code_live_context_and_snowman_surface(tmp_path) -> None:
    app = tmp_path / "moonlite"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    (app / "vercel.json").write_text(
        json.dumps({"domains": ["moonlite.rsvp"]}),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "launcher",
                str(app),
                "--app-source",
                "https://github.com/fusekitdemo/moonlight-rsvp-demo.git",
                "--fusekit-package",
                "git+https://github.com/xpxpxp-coder/fusekit.git",
                "--approve-dns",
                "--oci-region",
                "us-ashburn-1",
            ]
        )
        == 0
    )

    launcher = app / ".fusekit" / "launcher.html"
    text = launcher.read_text(encoding="utf-8")
    assert "SnowmanAI / FuseKit" in text
    assert "Open OCI Cloud Shell" in text
    assert "Privacy mode" in text
    assert "--github-repo fusekitdemo/moonlight-rsvp-demo" in text
    assert "--vercel-project moonlight-rsvp-demo" in text
    assert "--dns-zone moonlite.rsvp" in text
    assert "--live-url https://moonlite.rsvp" in text
    assert "--approve-dns" in text
    assert "--oci-compartment-mode root" in text
    assert "--oci-region us-ashburn-1" in text
    assert "--verify-attempts 10" in text
    assert "--verify-retry-seconds 30.0" in text
    assert "--gate-max-attempts 0" in text
    assert "--infer-ui" in text
    assert "--capture-stdin" in text
    assert "--visual-runner novnc" in text
    assert "&quot;$candidate&quot; - 2&gt;/dev/null" in text
    payload_text = text.split('<script type="application/json" id="payload">', 1)[1].split(
        "</script>",
        1,
    )[0]
    payload = json.loads(payload_text)
    assert payload["launch_args"][-2:] == ["--visual-runner", "novnc"]
    assert "clipboard write timed out" in text


def test_oci_auth_for_plan_region_overrides_sdk_region() -> None:
    from fusekit.cli import _oci_auth_for_plan_region
    from fusekit.runner.oci import build_oci_runner_plan
    from fusekit.runner.oci_live import OciAuth

    signer = object()
    auth = OciAuth({"region": "us-phoenix-1", "tenancy": "ocid1.tenancy.example"}, signer)
    plan = build_oci_runner_plan(runner="oci-existing", region="us-ashburn-1")

    updated = _oci_auth_for_plan_region(auth, plan)

    assert updated.config["region"] == "us-ashburn-1"
    assert updated.signer is signer
    assert auth.config["region"] == "us-phoenix-1"


def test_cli_scan_validate_plan_unlock_request(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    manifest = tmp_path / "fusekit.yaml"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    vault = tmp_path / "vault.json"

    assert main(["scan", str(app), "-o", str(manifest)]) == 0
    assert main(["validate", str(manifest)]) == 0
    assert main(["plan", str(manifest), "--json"]) == 0

    assert (
        main(
            [
                "apply",
                str(manifest),
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--allow-incomplete",
            ]
        )
        == 0
    )
    assert main(["unlock", "--vault", str(vault), "--passphrase-file", str(passphrase)]) == 0
    output = capsys.readouterr().out
    assert "WEBHOOK_SECRET" not in vault.read_text(encoding="utf-8")
    assert "WEBHOOK_SECRET" in output

    assert (
        main(
            [
                "request",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "secret.raw",
            ]
        )
        == 2
    )
    capsys.readouterr()

    session_file = tmp_path / "vault.session.json"
    assert (
        main(
            [
                "unlock",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--session-ttl",
                "60",
                "--session-file",
                str(session_file),
            ]
        )
        == 0
    )
    session_payload = json.loads(capsys.readouterr().out)
    session_token = session_payload["session"]["session_token"]
    token_file = tmp_path / "session-token"
    token_file.write_text(session_token, encoding="utf-8")

    assert session_token not in session_file.read_text(encoding="utf-8")
    assert "passphrase" not in session_file.read_text(encoding="utf-8")
    assert (
        main(
            [
                "request",
                "--vault",
                str(vault),
                "--session-token-file",
                str(token_file),
                "--session-file",
                str(session_file),
                "health",
            ]
        )
        == 0
    )
    request_payload = json.loads(capsys.readouterr().out)
    assert request_payload["ok"] is True


def test_cli_provider_synthesize_validate_and_authorize_pack(monkeypatch, tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"plaid": "latest"}}),
        encoding="utf-8",
    )
    (app / "plaid.ts").write_text(
        "process.env.PLAID_CLIENT_ID; process.env.PLAID_SECRET; process.env.PLAID_ENV;",
        encoding="utf-8",
    )
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    token = "plaid-approved-secret"
    monkeypatch.setattr("getpass.getpass", lambda prompt: token)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    assert (
        main(
            [
                "provider",
                "synthesize",
                "plaid",
                "--app",
                str(app),
                "--vault",
                str(tmp_path / "synth-vault.json"),
            ]
        )
        == 0
    )
    pack = app / ".fusekit" / "provider-packs" / "plaid.json"
    assert pack.exists()
    assert main(["provider", "validate", str(pack)]) == 0
    assert (
        main(
            [
                "authorize",
                "plaid",
                "--app",
                str(app),
                "--capability-pack",
                str(pack),
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--handoff",
                "--spine",
                "openclaw",
                "--dry-run-spine",
                "--capture-stdin",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "https://dashboard.plaid.com/signup" in output
    assert_no_secret_text(output, [token])
    assert_no_secret_text(vault.read_text(encoding="utf-8"), [token])
    opened = Vault.open(vault, "passphrase")
    assert opened.require("provider.plaid.token").value == token


def test_cli_provider_list_reports_account_creation_mode(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"stripe": "latest"}}),
        encoding="utf-8",
    )
    (app / "checkout.ts").write_text(
        "process.env.STRIPE_SECRET_KEY;",
        encoding="utf-8",
    )

    assert main(["provider", "list", "--app", str(app), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    provider = payload["providers"][0]
    assert provider["provider"] == "stripe"
    assert provider["account_creation"] == "supervised"
    assert "supervised" in provider["account_creation_reason"].lower()


def test_provider_synthesize_refuses_silent_vault_downgrade(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    vault_path = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    wrong_passphrase = tmp_path / "wrong-passphrase.txt"
    passphrase.write_text("correct-passphrase\n", encoding="utf-8")
    wrong_passphrase.write_text("wrong-passphrase\n", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "llm.openai.api_key",
        "api_key",
        "openai",
        "OpenAI API key",
        "test-openai-key",
    )
    vault.save(vault_path, "correct-passphrase")

    assert (
        main(
            [
                "provider",
                "synthesize",
                "resend",
                "--app",
                str(app),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(wrong_passphrase),
            ]
        )
        == 2
    )

    err = capsys.readouterr().err
    assert "refusing to downgrade" in err
    assert not (app / ".fusekit" / "provider-packs" / "resend.json").exists()


def test_cli_provider_verify_runs_pack_recipes(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    vault_path = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_secret",
        "resend",
        "RESEND_API_KEY",
        "re_hidden_secret",
    )
    vault.save(vault_path, "passphrase")

    assert (
        main(
            [
                "provider",
                "synthesize",
                "resend",
                "--app",
                str(app),
                "--vault",
                str(tmp_path / "synth-vault.json"),
            ]
        )
        == 0
    )
    pack = app / ".fusekit" / "provider-packs" / "resend.json"
    data = json.loads(pack.read_text(encoding="utf-8"))
    data["verification"] = [item for item in data["verification"] if item["kind"] == "env-present"]
    pack.write_text(json.dumps(data), encoding="utf-8")

    assert (
        main(
            [
                "provider",
                "verify",
                str(pack),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
                "--json",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert '"status": "ok"' in output
    assert_no_secret_text(output, ["re_hidden_secret"])


def test_cli_provider_verify_pending_is_not_success(monkeypatch, tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    vault_path = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")

    assert (
        main(
            [
                "provider",
                "synthesize",
                "resend",
                "--app",
                str(app),
                "--vault",
                str(tmp_path / "synth-vault.json"),
            ]
        )
        == 0
    )
    pack = app / ".fusekit" / "provider-packs" / "resend.json"
    data = json.loads(pack.read_text(encoding="utf-8"))
    data["verification"] = [
        {
            "kind": "http-json",
            "target": "https://api.resend.com/domains",
            "inputs": {"purpose": "verify-resource"},
        }
    ]
    pack.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(
        "fusekit.providers.verification.urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(URLError("offline")),
    )

    assert (
        main(
            [
                "provider",
                "verify",
                str(pack),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
                "--verify-attempts",
                "2",
                "--json",
            ]
        )
        == 1
    )
    output = capsys.readouterr().out
    assert '"status": "pending"' in output


def test_apply_repairs_failed_provider_verification_with_inferred_ui(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    pack_dir = app / ".fusekit" / "provider-packs"
    pack_dir.mkdir(parents=True)
    pack_path = pack_dir / "resend.json"
    repaired_pack = synthesize_provider_pack(
        "resend",
        app,
    )
    object.__setattr__(repaired_pack, "setup", ())
    object.__setattr__(
        repaired_pack,
        "verification",
        (VerificationRecipe("env-present", "RESEND_API_KEY"),),
    )
    write_provider_pack(repaired_pack, pack_path)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                secrets=("RESEND_API_KEY",),
                settings={"capability_pack": str(pack_path.relative_to(app))},
            ),
        ),
    )
    manifest_path = tmp_path / "fusekit.yaml"
    write_manifest(manifest, manifest_path)
    passphrase = tmp_path / "passphrase.txt"
    vault_path = tmp_path / "vault.json"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    def fake_repair(args, pack, vault, start_url, goal):  # type: ignore[no-untyped-def]
        del args, start_url, goal
        vault.put(
            "provider.resend.resend_api_key",
            "provider_secret",
            pack.provider,
            "RESEND_API_KEY",
            "repaired-secret-value",
        )
        return [
            BrowserPlaybookEvent(
                provider=pack.provider,
                action="stop",
                status="done",
                note="dry repair",
            )
        ]

    monkeypatch.setattr("fusekit.cli._run_provider_repair_navigation", fake_repair)

    assert (
        main(
            [
                "apply",
                str(manifest_path),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
                "--infer-ui",
                "--dry-run-spine",
                "--receipt-json",
                str(app / ".fusekit" / "setup_receipt.json"),
                "--receipt-md",
                str(app / ".fusekit" / "setup_receipt.md"),
                "--audit-log",
                str(app / ".fusekit" / "audit.jsonl"),
            ]
        )
        == 0
    )

    receipt = json.loads((app / ".fusekit" / "setup_receipt.json").read_text("utf-8"))
    actions = receipt["actions"]
    assert any(action["action"] == "provider_pack.repair" for action in actions)
    assert actions[-1]["action"] == "provider_pack.verify"
    assert actions[-1]["status"] == "ok"
    assert "repaired-secret-value" not in json.dumps(receipt)


def test_provider_api_fallback_runs_pack_setup_when_token_exists(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    pack = synthesize_provider_pack("resend", app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                secrets=("RESEND_API_KEY",),
            ),
        ),
    )
    vault = Vault.empty()
    vault.put(
        "provider.resend.token",
        "provider_token",
        "resend",
        "resend API token",
        "provider-token-hidden",
    )
    monkeypatch.setenv("RESEND_API_KEY", "fallback-secret-hidden")
    args = argparse.Namespace(
        secret=[],
        approve_dns=False,
        allow_incomplete=False,
        fusekit_gates="service-only",
        app_source="",
        github_repo="",
        vercel_project="",
        vercel_framework="",
        vercel_git_repo_id="",
        vercel_git_ref="main",
        dns_zone="",
    )
    receipt = Receipt(app_name="app", vault_path=str(tmp_path / "vault.json"))

    assert _attempt_provider_api_fallback(
        args,
        manifest,
        pack,
        [],
        vault,
        AuditLog(tmp_path / "audit.jsonl"),
        receipt,
    )

    assert vault.require("provider.resend.resend_api_key").value == "fallback-secret-hidden"
    public = json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["provider-token-hidden", "fallback-secret-hidden"])


def test_provider_api_fallback_regenerates_resend_values_before_downstream_retry(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    resend_pack = synthesize_provider_pack("resend", app)
    vercel_pack = synthesize_provider_pack("vercel", app)
    write_provider_pack(resend_pack, app / ".fusekit" / "provider-packs" / "resend.json")
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        required_env=("RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"),
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                secrets=("RESEND_API_KEY",),
            ),
            ServiceRequirement(
                provider="vercel",
                kind="hosting",
                name="hosting",
                capabilities=("capability_pack",),
                secrets=("VERCEL_TOKEN",),
            ),
        ),
    )
    vault = Vault.empty()
    vault.put("provider.resend.token", "provider_token", "resend", "RESEND_API_KEY", "resend-token")
    vault.put("provider.vercel.token", "provider_token", "vercel", "VERCEL_TOKEN", "vercel-token")
    args = argparse.Namespace(
        secret=[],
        approve_dns=False,
        allow_incomplete=False,
        fusekit_gates="service-only",
        app_source="",
        github_repo="",
        vercel_project="moonlite-rsvp",
        vercel_framework="",
        vercel_git_repo_id="",
        vercel_git_ref="main",
        dns_zone="moonlite.rsvp",
    )
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_run_provider_pack_setup(pack, context):  # type: ignore[no-untyped-def]
        calls.append((pack.provider, dict(context.secrets)))
        if pack.provider == "resend":
            context.secrets["RESEND_FROM_EMAIL"] = "rsvp@moonlite.rsvp"
            context.secrets["RESEND_AUDIENCE_ID"] = "audience-123"
            context.vault.put(
                "provider.resend.resend_from_email",
                "provider_setting",
                "resend",
                "RESEND_FROM_EMAIL",
                "rsvp@moonlite.rsvp",
            )
            context.vault.put(
                "provider.resend.resend_audience_id",
                "provider_setting",
                "resend",
                "RESEND_AUDIENCE_ID",
                "audience-123",
            )
        if pack.provider == "vercel":
            assert context.secrets["RESEND_FROM_EMAIL"] == "rsvp@moonlite.rsvp"
            assert context.secrets["RESEND_AUDIENCE_ID"] == "audience-123"
        return {"provider": pack.provider, "setup": [{"kind": "setup", "status": "ok"}]}

    monkeypatch.setattr("fusekit.cli.run_provider_pack_setup", fake_run_provider_pack_setup)
    results = [
        VerificationResult(
            provider="vercel",
            kind="vercel-env",
            target="moonlite-rsvp",
            status="needs_human_gate",
            details={
                "reason": (
                    "Vercel is missing required app runtime environment variables: "
                    "RESEND_FROM_EMAIL, RESEND_AUDIENCE_ID. Capture or derive these values "
                    "before verifying the deployment."
                )
            },
        )
    ]
    receipt = Receipt(app_name="app", vault_path=str(tmp_path / "vault.json"))

    assert _attempt_provider_api_fallback(
        args,
        manifest,
        vercel_pack,
        results,
        vault,
        AuditLog(tmp_path / "audit.jsonl"),
        receipt,
    )

    assert [provider for provider, _secrets in calls] == ["resend", "vercel"]
    actions = receipt.to_dict()["actions"]
    assert any(
        action["action"] == "provider_pack.resend_runtime_regeneration"
        and action["status"] == "attempted"
        for action in actions
    )
    assert any(
        action["action"] == "provider_pack.api_fallback"
        and action["details"]["upstream_resend_runtime_regenerated"] is True
        for action in actions
    )
    public = json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["resend-token", "vercel-token"])


def test_catalog_pack_env_token_counts_as_provider_token(monkeypatch, tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    vault = Vault.empty()
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe-token-hidden")

    assert _has_pack_provider_token(pack, vault)


def test_capture_provider_tokens_uses_catalog_handoff_env(monkeypatch, tmp_path) -> None:
    manifest = SetupManifest(
        app_name="app",
        app_path=str(tmp_path),
        services=(
            ServiceRequirement(
                provider="supabase",
                kind="database",
                name="database",
                capabilities=("capability_pack",),
                secrets=("SUPABASE_SERVICE_ROLE_KEY", "WEBHOOK_SECRET"),
            ),
        ),
    )
    vault = Vault.empty()
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "supabase-token-hidden")
    monkeypatch.setenv("WEBHOOK_SECRET", "webhook-secret-not-provider-token")

    _capture_provider_tokens(vault, manifest)

    assert vault.require("provider.supabase.token").value == "supabase-token-hidden"
    with pytest.raises(FuseKitError):
        vault.require("provider.webhook.token")


def test_repair_navigation_waiting_gate_is_not_treated_as_complete() -> None:
    assert not _repair_navigation_completed(
        [
            BrowserPlaybookEvent(
                provider="resend",
                action="human.takeover",
                status="waiting",
                note="MFA required",
            )
        ]
    )
    assert _repair_navigation_completed(
        [
            BrowserPlaybookEvent(
                provider="resend",
                action="stop",
                status="done",
                note="verified UI step reached",
            )
        ]
    )


def test_apply_accepts_pending_safe_provider_verification(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    pack_dir = app / ".fusekit" / "provider-packs"
    pack_dir.mkdir(parents=True)
    pack_path = pack_dir / "resend.json"
    pack = synthesize_provider_pack("resend", app)
    object.__setattr__(pack, "setup", ())
    object.__setattr__(
        pack,
        "verification",
        (VerificationRecipe(kind="resend-domain", target="moonlite.rsvp"),),
    )
    write_provider_pack(pack, pack_path)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                settings={"capability_pack": str(pack_path.relative_to(app))},
            ),
        ),
    )
    manifest_path = tmp_path / "fusekit.yaml"
    passphrase = tmp_path / "passphrase.txt"
    vault_path = tmp_path / "vault.json"
    report_path = app / ".fusekit" / "verification_report.json"
    write_manifest(manifest, manifest_path)
    passphrase.write_text("passphrase\n", encoding="utf-8")
    vault = Vault.empty()
    vault.put("provider.resend.token", "provider_token", "resend", "token", "token-hidden")
    vault.save(vault_path, "passphrase")

    class Response:
        status = 200

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"data":[{"name":"moonlite.rsvp","status":"pending"}]}'

    monkeypatch.setattr(
        "fusekit.providers.verification.urlopen",
        lambda *args, **kwargs: Response(),
    )

    assert (
        main(
            [
                "apply",
                str(manifest_path),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
                "--receipt-json",
                str(app / ".fusekit" / "setup_receipt.json"),
                "--receipt-md",
                str(app / ".fusekit" / "setup_receipt.md"),
                "--audit-log",
                str(app / ".fusekit" / "audit.jsonl"),
                "--verification-report",
                str(report_path),
            ]
        )
        == 0
    )

    receipt = json.loads((app / ".fusekit" / "setup_receipt.json").read_text("utf-8"))
    assert receipt["actions"][-1]["status"] == "pending-safe"
    assert json.loads(report_path.read_text("utf-8"))["overall"] == "pending"


def test_apply_records_provider_strategy_gate_when_token_is_missing(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    app = tmp_path / "app"
    app.mkdir()
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="github",
                kind="source",
                name="source",
                capabilities=("capability_pack",),
                secrets=("GITHUB_TOKEN",),
            ),
        ),
    )
    manifest_path = tmp_path / "fusekit.yaml"
    write_manifest(manifest, manifest_path)
    fusekit_dir = app / ".fusekit"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "apply",
                str(manifest_path),
                "--vault",
                str(fusekit_dir / "fusekit.vault.json"),
                "--passphrase-file",
                str(passphrase),
                "--github-repo",
                "owner/repo",
                "--allow-incomplete",
                "--receipt-json",
                str(fusekit_dir / "setup_receipt.json"),
                "--receipt-md",
                str(fusekit_dir / "setup_receipt.md"),
                "--audit-log",
                str(fusekit_dir / "audit.jsonl"),
                "--verification-report",
                str(fusekit_dir / "verification_report.json"),
            ]
        )
        == 0
    )

    gates = GateService.load(fusekit_dir / "gates.json").records
    gate = gates["provider.github.github-deploy-key"]
    assert gate.provider == "github"
    assert gate.resume_url == "https://github.com/settings/tokens?type=beta"
    assert gate.classification == "provider-authorization"
    assert "fine-grained token" in " ".join(gate.follow_steps)
    assert "Click Open provider gate in VM" in gate.next_action
    assert "matching Capture from VM clipboard button" in gate.next_action
    assert "retry this provider route" in gate.resume_hint

    strategies = json.loads((fusekit_dir / "provider_strategies.json").read_text("utf-8"))
    assert strategies["providers"][0]["provider"] == "github"
    strategy = strategies["providers"][0]["strategies"][0]
    assert strategy["strategy"] == "browser_guided"
    assert strategy["status"] == "needs_human_gate"
    assert strategy["resume_url"] == "https://github.com/settings/tokens?type=beta"
    assert "fine-grained token" in " ".join(strategy["follow_steps"])
    assert "Resource owner" in " ".join(strategy["follow_steps"])
    assert "matching Capture from VM clipboard button" in strategy["next_action"]
    assert "visible gate is finished" in strategy["resume_hint"]


def test_apply_writes_verification_report_when_provider_check_fails(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    pack_dir = app / ".fusekit" / "provider-packs"
    pack_dir.mkdir(parents=True)
    pack_path = pack_dir / "resend.json"
    pack = synthesize_provider_pack("resend", app)
    object.__setattr__(pack, "setup", ())
    object.__setattr__(
        pack,
        "verification",
        (VerificationRecipe("env-present", "RESEND_API_KEY"),),
    )
    write_provider_pack(pack, pack_path)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                secrets=("RESEND_API_KEY",),
                settings={"capability_pack": str(pack_path.relative_to(app))},
            ),
        ),
    )
    manifest_path = tmp_path / "fusekit.yaml"
    passphrase = tmp_path / "passphrase.txt"
    vault_path = tmp_path / "vault.json"
    report_path = app / ".fusekit" / "verification_report.json"
    write_manifest(manifest, manifest_path)
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "apply",
                str(manifest_path),
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
                "--receipt-json",
                str(app / ".fusekit" / "setup_receipt.json"),
                "--receipt-md",
                str(app / ".fusekit" / "setup_receipt.md"),
                "--audit-log",
                str(app / ".fusekit" / "audit.jsonl"),
                "--verification-report",
                str(report_path),
            ]
        )
        == 2
    )

    report = json.loads(report_path.read_text("utf-8"))
    assert report["overall"] == "failed"
    assert report["counts"]["failed"] == 1
    assert report["checks"][0]["status"] == "failed"
    assert "provider API after any missing provider gate is captured" in report["checks"][0][
        "repair"
    ]


def test_verification_gate_records_resend_api_key_follow_me(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    pack = synthesize_provider_pack("resend", app)
    result = VerificationResult(
        provider="resend",
        kind="http-json",
        target="https://api.resend.com/domains",
        status="needs_human_gate",
        details={
            "reason": (
                "Resend rejected the captured setup key. Create or capture a Resend API key "
                "with Full access for the first setup so FuseKit can create or reuse domains "
                "and audiences."
            ),
            "service_gate": True,
        },
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.resend.api-key-domain-access",
            "provider": "resend",
            "classification": "provider-authorization",
            "target": "RESEND_API_KEY",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.resume_url == "https://resend.com/api-keys"
    assert "live VM browser" in " ".join(gate.follow_steps)
    assert "Full access" in " ".join(gate.follow_steps)
    assert "sending domain and audience for moonlite.rsvp" in " ".join(gate.follow_steps)
    assert "raw value" in " ".join(gate.follow_steps)
    assert "does not reveal old key secrets again" in " ".join(gate.follow_steps)
    assert "No domains yet" in " ".join(gate.follow_steps)
    assert "do not click Add domain" in " ".join(gate.follow_steps)
    assert "resumes automatically" in " ".join(gate.follow_steps)
    assert "Capture RESEND_API_KEY" in gate.next_action
    assert "copy-once secrets" in gate.next_action
    assert "creates or reuses the Resend sending domain" in gate.resume_hint
    assert "Cloudflare DNS" in gate.resume_hint
    assert "I finished this step" not in " ".join(gate.follow_steps)


def test_verification_gate_fallback_names_exact_launcher_controls(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(app_name="app", app_path=str(app))
    pack = synthesize_provider_pack("stripe", app)
    object.__setattr__(
        pack,
        "handoff",
        PackHandoff(
            signup_url="https://dashboard.stripe.com/register",
            token_url="https://dashboard.stripe.com/apikeys",
            login_url="https://dashboard.stripe.com/login",
        ),
    )
    result = VerificationResult(
        provider="stripe",
        kind="http-json",
        target="https://api.stripe.com/v1/account",
        status="needs_human_gate",
        details={"reason": "Stripe needs a provider-owned verification step."},
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.stripe.http-json",
            "provider": "stripe",
            "classification": "provider-verification",
            "target": "https://api.stripe.com/v1/account",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.stripe.http-json"
    ]
    steps = " ".join(gate.follow_steps)
    assert "Click Open provider gate in VM" in steps
    assert "VM browser" in steps
    assert "If FuseKit shows Capture buttons for named values" in steps
    assert "Capture from VM clipboard button" in steps
    assert "I finished this step" in steps
    assert "If no secret is revealed" not in steps
    assert "Click Open provider gate in VM" in gate.next_action
    assert "provider-owned verification" in gate.next_action
    assert "when FuseKit shows that button" in gate.next_action
    assert "I finished this step" in gate.next_action


def test_verification_gate_routes_missing_resend_domain_to_api_retry(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    pack = synthesize_provider_pack("resend", app)
    result = VerificationResult(
        provider="resend",
        kind="resend-domain",
        target="moonlite.rsvp",
        status="failed",
        details={
            "reason": (
                "Resend has a valid setup key, but the sending domain does not exist yet. "
                "FuseKit should create or reuse the domain through Resend's API before DNS "
                "is applied."
            ),
            "missing": True,
            "repair": "rerun_resend_domain_setup",
        },
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.resend.domain-setup-retry",
            "provider": "resend",
            "classification": "provider-setup-retry",
            "target": "",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.domain-setup-retry"
    ]
    steps = " ".join(gate.follow_steps)
    assert gate.resume_url == "https://resend.com/api-keys"
    assert gate.target == ""
    assert "No manual Resend domain or DNS step" in steps
    assert "Do not manually create moonlite.rsvp" in steps
    assert "Click I finished this step" in steps
    assert "Resend API setup" in gate.resume_hint
    assert "Cloudflare DNS" in gate.resume_hint
    assert "Click I finished this step" in gate.next_action
    assert "Capture" not in steps


def test_verification_gate_guides_resend_domain_verification(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    pack = synthesize_provider_pack("resend", app)
    result = VerificationResult(
        provider="resend",
        kind="resend-domain",
        target="moonlite.rsvp",
        status="needs_human_gate",
        details={
            "reason": "Resend domain moonlite.rsvp is pending provider verification.",
            "service_gate": True,
        },
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.resend.domain-verification",
            "provider": "resend",
            "classification": "provider-domain",
            "target": "moonlite.rsvp",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.domain-verification"
    ]
    assert gate.resume_url == "https://resend.com/domains"
    assert gate.target == "moonlite.rsvp"
    steps = " ".join(gate.follow_steps)
    assert "Open Resend Domains only to review the existing moonlite.rsvp domain" in steps
    assert "Do not create the domain or DNS records by hand" in steps
    assert "keeps Cloudflare DNS behind it" in steps
    assert "add or open" not in steps
    assert "I finished this step" in gate.next_action
    assert "read any DNS records returned by the API" in gate.resume_hint
    assert "Cloudflare DNS behind Resend" in gate.resume_hint


def test_verification_gate_routes_resend_runtime_values_from_vercel(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    pack = synthesize_provider_pack("vercel", app)
    result = VerificationResult(
        provider="vercel",
        kind="vercel-env",
        target="moonlite-rsvp-demo",
        status="needs_human_gate",
        details={
            "reason": (
                "Vercel is missing runtime values RESEND_AUDIENCE_ID, "
                "RESEND_FROM_EMAIL."
            ),
            "service_gate": True,
        },
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.resend.runtime-values",
            "provider": "resend",
            "classification": "provider-runtime-values",
            "target": "RESEND_AUDIENCE_ID,RESEND_FROM_EMAIL",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.runtime-values"
    ]
    assert gate.resume_url == "https://resend.com/audiences"
    steps = " ".join(gate.follow_steps)
    assert "RESEND_AUDIENCE_ID" in steps
    assert "rsvp@moonlite.rsvp" in steps
    assert "normally created or reused by FuseKit through Resend's API" in steps
    assert "copy the existing audience ID" in steps
    assert "do not create unrelated audiences" in steps
    assert "Capture button" in steps
    assert "resumes automatically" in steps
    assert "Capture RESEND_AUDIENCE_ID, RESEND_FROM_EMAIL" in gate.next_action
    assert "Vercel and GitHub" in gate.resume_hint
    assert "I finished this step" not in steps


def test_verification_gate_routes_only_missing_resend_runtime_values(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(app=app)
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    pack = synthesize_provider_pack("vercel", app)
    result = VerificationResult(
        provider="vercel",
        kind="vercel-env",
        target="moonlite-rsvp-demo",
        status="needs_human_gate",
        details={
            "reason": (
                "Vercel is missing runtime values WEBHOOK_SECRET, "
                "RESEND_FROM_EMAIL."
            ),
            "service_gate": True,
        },
    )

    recorded = _record_provider_verification_gates(args, manifest, pack, [result])

    assert recorded == [
        {
            "id": "provider.resend.runtime-values",
            "provider": "resend",
            "classification": "provider-runtime-values",
            "target": "RESEND_FROM_EMAIL",
        }
    ]
    gate = GateService.load(app / ".fusekit" / "gates.json").records[
        "provider.resend.runtime-values"
    ]
    assert gate.resume_url == "https://resend.com/domains"
    assert gate.target == "RESEND_FROM_EMAIL"
    assert "WEBHOOK_SECRET" not in gate.target
    steps = " ".join(gate.follow_steps)
    assert "RESEND_FROM_EMAIL is normally generated by FuseKit" in steps
    assert "rsvp@moonlite.rsvp" in steps
    assert "Do not create moonlite.rsvp by hand" in steps
    assert "open Resend Domains only to copy an already-verified sender address" in steps
    assert "Open Resend Audiences" not in steps
    assert "unless RESEND_AUDIENCE_ID is listed" in steps
    assert "Capture RESEND_FROM_EMAIL" in gate.next_action
    assert "every requested Resend value" in gate.resume_hint


def test_cli_refuses_raw_secret_argument(tmp_path) -> None:
    manifest = tmp_path / "fusekit.yaml"
    manifest.write_text(
        json.dumps({"app_name": "app", "services": [], "webhooks": [], "domains": []}),
        encoding="utf-8",
    )
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "apply",
                str(manifest),
                "--passphrase-file",
                str(passphrase),
                "--secret",
                "API_KEY=raw-value",
            ]
        )
        == 2
    )


def test_detonate_command_uses_paths_argument(tmp_path, capsys) -> None:
    worker = tmp_path / "worker"
    worker.mkdir()
    (worker / "state.txt").write_text("temporary", encoding="utf-8")

    assert main(["detonate", str(worker)]) == 0

    output = capsys.readouterr().out
    assert "detonated" in output
    assert not worker.exists()


def test_authorize_handoff_captures_hidden_token(monkeypatch, tmp_path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    token = "test-supervised-github-token-value"

    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))
    monkeypatch.setattr("getpass.getpass", lambda prompt: token)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    assert (
        main(
            [
                "authorize",
                "github",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--handoff",
                "--spine",
                "system",
                "--open-browser",
                "--capture-stdin",
                "--include-project-page",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "https://github.com/signup" in output
    assert "https://github.com/new" in opened
    assert_no_secret_text(output, [token])
    assert_no_secret_text(vault.read_text(encoding="utf-8"), [token])
    opened_vault = Vault.open(vault, "passphrase")
    assert opened_vault.require("provider.github.token").value == token


def test_source_fetch_private_repo_stores_env_token_in_vault(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    token = "github-private-source-token"
    calls: list[str] = []

    def fake_fetch(source: str, dest: object, *, token: str = "", **kwargs: object) -> object:
        calls.append(token)
        if not token:
            raise FuseKitError("private")
        (tmp_path / "app").mkdir(exist_ok=True)

        class Result:
            def to_dict(self) -> dict[str, object]:
                return {
                    "source": source,
                    "dest": str(dest),
                    "provider": "github",
                    "repo": "owner/private",
                    "default_branch": "main",
                    "auth_source": "github-token",
                    "private": True,
                }

        return Result()

    monkeypatch.setenv("GITHUB_TOKEN", token)
    monkeypatch.setattr("fusekit.cli.fetch_github_source_archive", fake_fetch)

    assert (
        main(
            [
                "source",
                "fetch",
                "https://github.com/owner/private.git",
                "--dest",
                str(tmp_path / "app"),
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--github-auth",
                "auto",
                "--spine",
                "system",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert calls == ["", token]
    assert_no_secret_text(output, [token])
    assert_no_secret_text(vault.read_text(encoding="utf-8"), [token])
    assert Vault.open(vault, "passphrase").require("provider.github.token").value == token


def test_source_fetch_guides_private_repo_with_inferred_github_goal(
    monkeypatch,
    tmp_path,
) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    goals: list[str] = []

    def fake_fetch(source: str, dest: object, *, token: str = "", **kwargs: object) -> object:
        if not token:
            raise FuseKitError("private")

        class Result:
            def to_dict(self) -> dict[str, object]:
                return {
                    "source": source,
                    "dest": str(dest),
                    "provider": "github",
                    "repo": "owner/private",
                    "default_branch": "main",
                    "auth_source": "github-token",
                    "private": True,
                }

        return Result()

    def fake_handoff(*args: object, **kwargs: object) -> None:
        goals.append(str(kwargs.get("goal", "")))

    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setattr("fusekit.cli.fetch_github_source_archive", fake_fetch)
    monkeypatch.setattr("fusekit.cli._run_handoff", fake_handoff)
    monkeypatch.setattr(
        "fusekit.cli._await_provider_token",
        lambda *args, **kwargs: ("github-private-token", "supervised-hidden-prompt"),
    )

    assert (
        main(
            [
                "source",
                "fetch",
                "https://github.com/owner/private.git",
                "--dest",
                str(tmp_path / "app"),
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--handoff",
                "--capture-stdin",
                "--infer-ui",
                "--spine",
                "openclaw",
            ]
        )
        == 0
    )

    assert goals
    assert "owner/private" in goals[0]
    assert "Highlight each provider-screen element" in goals[0]
    assert "Use the gate action with a target" in goals[0]


def test_source_fetch_waiting_token_writes_guided_control_room(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    args = argparse.Namespace(
        source="https://github.com/owner/private.git",
        dest=tmp_path / "app",
        capture_stdin=False,
        gate_max_attempts=1,
        gate_retry_seconds=0,
        github_token_env="GITHUB_TOKEN",
        passphrase_file=passphrase,
        token_env="",
        vault=vault_path,
    )

    with pytest.raises(ApprovalRequired):
        _await_provider_token(
            args,
            "github",
            handoff_for("github"),
            include_project=False,
        )

    control_room = tmp_path / "control-room.html"
    job_state = tmp_path / "source-fetch-job.json"
    gates = GateService.load(tmp_path / "gates.json").records
    html = control_room.read_text(encoding="utf-8")
    output = capsys.readouterr().out

    assert control_room.exists()
    assert job_state.exists()
    job_payload = json.loads(job_state.read_text(encoding="utf-8"))
    assert job_payload["artifacts"]["vault"] == str(vault_path)
    assert job_payload["artifacts"]["passphrase_file"] == str(passphrase)
    assert gates["provider.github.authorization"].target == "GITHUB_TOKEN"
    assert "Fetch app source" in html
    assert "GitHub authorization is required before FuseKit can fetch" in html
    assert "Open provider gate in VM" in html
    assert "Capture GITHUB_TOKEN from VM clipboard" in html
    assert "full setup worker has not started yet" in html
    assert f"Guided source-fetch control room: {control_room}" in output
    assert "Open this file for exact steps" in output
    assert "fusekit control-room --serve --job-state" in output
    assert str(job_state) in output
    assert "live VM-browser open and Capture controls" in output


def test_github_app_source_handoff_uses_launcher_capture_copy() -> None:
    handoff = _github_source_handoff(
        argparse.Namespace(
            github_auth="app",
            github_app_install_url="https://github.com/apps/fusekit/installations/new",
        )
    )

    steps = " ".join(handoff.secret_steps)
    assert "inside the VM browser" in steps
    assert "Capture button in FuseKit" in steps
    assert "encrypted vault" in steps
    assert "hidden prompt" not in steps
    assert "environment variable" not in steps


def test_await_provider_token_picks_up_token_saved_to_vault(
    monkeypatch,
    tmp_path,
) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "provider.cloudflare.token",
        "provider_token",
        "cloudflare",
        "Cloudflare API token",
        "cfut_live_token_from_vm_clipboard",
    )
    vault.save(vault_path, "passphrase")
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.setattr(
        "fusekit.cli._run_handoff",
        lambda *args, **kwargs: pytest.fail("handoff should not run when vault has token"),
    )

    args = argparse.Namespace(
        app=tmp_path,
        capture_stdin=False,
        gate_max_attempts=0,
        gate_retry_seconds=0,
        job_state=tmp_path / "job.json",
        passphrase_file=passphrase,
        token_env="",
        vault=vault_path,
    )

    token, source = _await_provider_token(
        args,
        "cloudflare",
        handoff_for("cloudflare"),
        include_project=False,
    )

    assert token == "cfut_live_token_from_vm_clipboard"
    assert source == "vault:provider.cloudflare.token"
    gates = GateService.load(tmp_path / ".fusekit" / "gates.json")
    assert gates.records["provider.cloudflare.authorization"].status == "passed"


def test_await_provider_token_presents_handoff_only_once(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    calls: list[str] = []
    monkeypatch.setattr(
        "fusekit.cli._run_handoff",
        lambda *args, **kwargs: calls.append(str(args[1])),
    )
    args = argparse.Namespace(
        app=tmp_path,
        capture_stdin=False,
        gate_max_attempts=2,
        gate_retry_seconds=0,
        job_state=tmp_path / "job.json",
        passphrase_file=tmp_path / "passphrase.txt",
        token_env="",
        vault=tmp_path / "missing.vault.json",
    )

    with pytest.raises(FuseKitError):
        _await_provider_token(
            args,
            "github",
            handoff_for("github"),
            include_project=False,
        )

    assert calls == ["github"]
    gate = GateService.load(tmp_path / ".fusekit" / "gates.json").records[
        "provider.github.authorization"
    ]
    assert gate.classification == "provider-authorization"
    assert gate.target == "GITHUB_TOKEN"
    assert any("Capture GITHUB_TOKEN from VM clipboard" in step for step in gate.follow_steps)


def test_await_provider_token_does_not_represent_existing_handoff(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        "fusekit.cli._run_handoff",
        lambda *args, **kwargs: pytest.fail("handoff was already presented"),
    )
    args = argparse.Namespace(
        app=tmp_path,
        capture_stdin=False,
        gate_max_attempts=1,
        gate_retry_seconds=0,
        job_state=tmp_path / "job.json",
        passphrase_file=tmp_path / "passphrase.txt",
        token_env="",
        vault=tmp_path / "missing.vault.json",
    )

    with pytest.raises(FuseKitError):
        _await_provider_token(
            args,
            "github",
            handoff_for("github"),
            include_project=False,
            handoff_presented=True,
        )


def test_await_provider_token_skips_hidden_prompt_without_tty(
    monkeypatch,
    tmp_path,
) -> None:
    class NoTty:
        def isatty(self) -> bool:
            return False

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr("sys.stdin", NoTty())
    monkeypatch.setattr(
        "fusekit.cli.getpass.getpass",
        lambda *args, **kwargs: pytest.fail("detached worker should not prompt"),
    )
    args = argparse.Namespace(
        app=tmp_path,
        capture_stdin=True,
        gate_max_attempts=1,
        gate_retry_seconds=0,
        job_state=tmp_path / "job.json",
        passphrase_file=tmp_path / "passphrase.txt",
        token_env="",
        vault=tmp_path / "missing.vault.json",
    )

    with pytest.raises(FuseKitError):
        _await_provider_token(
            args,
            "github",
            handoff_for("github"),
            include_project=False,
            handoff_presented=True,
        )


def test_authorize_provider_does_not_reopen_existing_gate(
    monkeypatch,
    tmp_path,
) -> None:
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    GateService.load(tmp_path / ".fusekit" / "gates.json").wait(
        "provider.github.authorization",
        provider="github",
        reason="existing gate",
        resume_url="https://github.com/settings/tokens?type=beta",
    )
    monkeypatch.setattr(
        "fusekit.cli._run_handoff",
        lambda *args, **kwargs: pytest.fail("existing gate should not reopen handoff"),
    )
    monkeypatch.setattr(
        "fusekit.cli._await_provider_token",
        lambda *args, **kwargs: ("github_token_value", "vault:provider.github.token"),
    )
    args = argparse.Namespace(
        app=tmp_path,
        job_state=tmp_path / ".fusekit" / "job.json",
        handoff=True,
        passphrase_file=passphrase,
        vault=tmp_path / "fusekit.vault.json",
    )

    _authorize_provider(args, "github", handoff=handoff_for("github"))

    assert Vault.open(args.vault, "passphrase").require("provider.github.token").value == (
        "github_token_value"
    )


def test_run_handoff_uses_shared_visual_browser_profile(monkeypatch, tmp_path) -> None:
    calls: list[dict[str, object]] = []
    browser = tmp_path / "chrome"
    browser.write_text("#!/bin/sh\n", encoding="utf-8")
    browser.chmod(0o755)
    monkeypatch.setenv("FUSEKIT_VISUAL_DISPLAY", ":99")
    monkeypatch.setattr("fusekit.cli._visual_chrome_binary", lambda: browser)
    monkeypatch.setattr(
        "fusekit.cli.subprocess.Popen",
        lambda command, **kwargs: calls.append({"command": command, **kwargs}),
    )
    args = argparse.Namespace(
        dry_run_spine=False,
        job_state=tmp_path / ".fusekit" / "job.json",
    )

    _run_handoff(args, "resend", handoff_for("resend"), include_project=False)

    assert calls
    command = calls[0]["command"]
    assert command[0] == str(browser)
    assert f"--user-data-dir={tmp_path / 'visual' / 'chrome-provider-profile'}" in command
    assert "https://resend.com/signup" in command
    assert calls[0]["env"]["DISPLAY"] == ":99"


def test_authorize_can_use_openclaw_spine_dry_run(monkeypatch, tmp_path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    token = "vercel_supervised_token_value"

    monkeypatch.setattr("getpass.getpass", lambda prompt: token)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    assert (
        main(
            [
                "authorize",
                "vercel",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--handoff",
                "--spine",
                "openclaw",
                "--dry-run-spine",
                "--capture-stdin",
                "--include-project-page",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "OpenClaw spine events:" in output
    assert "https://vercel.com/signup" in output
    assert_no_secret_text(output, [token])
    assert_no_secret_text(vault.read_text(encoding="utf-8"), [token])
    opened_vault = Vault.open(vault, "passphrase")
    assert opened_vault.require("provider.vercel.token").value == token


def test_launch_rejects_dry_run_spine_without_allow_incomplete(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "launch",
                str(app),
                "--runner",
                "local",
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--yes",
                "--spine",
                "openclaw",
                "--dry-run-spine",
            ]
        )
        == 2
    )


def test_apply_requires_real_provider_targets_by_default(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    manifest = tmp_path / "fusekit.yaml"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert main(["scan", str(app), "-o", str(manifest)]) == 0
    assert (
        main(
            [
                "apply",
                str(manifest),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == 2
    )


def test_setup_runs_one_command_rehearsal_and_detonates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    worker = tmp_path / "worker"
    worker.mkdir()
    (worker / "scratch.txt").write_text("temporary state", encoding="utf-8")

    assert (
        main(
            [
                "setup",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--allow-incomplete",
                "--no-bootstrap",
                "--yes",
            ]
        )
        == 0
    )

    assert (app / "fusekit.yaml").exists()
    assert (app / ".fusekit" / "setup_plan.json").exists()
    assert (app / ".fusekit" / "fusekit.vault.json").exists()
    assert (app / ".fusekit" / "setup_receipt.json").exists()
    job = json.loads((app / ".fusekit" / "job.json").read_text("utf-8"))
    assert job["runner"] == "local"
    assert any(step["id"] == "setup.execute" and step["status"] == "done" for step in job["steps"])
    assert any(step["id"] == "verify.live" and step["status"] == "failed" for step in job["steps"])
    run_state = json.loads((app / ".fusekit" / "run_state.json").read_text("utf-8"))
    assert run_state["app_repo_known"] is True
    assert run_state["runner_selected"] is True
    assert run_state["vault_created"] is True


def test_local_launch_control_room_has_truth_artifacts(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "launch",
                str(app),
                "--runner",
                "local",
                "--passphrase-file",
                str(passphrase),
                "--allow-incomplete",
                "--no-bootstrap",
                "--yes",
                "--control-room",
            ]
        )
        == 0
    )

    html = (app / ".fusekit" / "control-room.html").read_text("utf-8")
    job = json.loads((app / ".fusekit" / "job.json").read_text("utf-8"))
    assert "Launch contract" in html
    assert "local runner selected" in json.dumps(job)
    assert "verification report contains failed or blocked checks" in html
    assert job["artifacts"]["verification_report"].endswith("verification_report.json")
    assert job["artifacts"]["rollback_plan"].endswith("rollback_plan.json")
    assert job["artifacts"]["vault"].endswith("fusekit.vault.json")


def test_launch_requires_plan_approval(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")

    assert (
        main(
            [
                "launch",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--allow-incomplete",
                "--no-bootstrap",
                "--fusekit-gates",
                "explicit",
                "--gate-retry-seconds",
                "0",
                "--gate-max-attempts",
                "1",
            ]
        )
        == 2
    )


def test_launch_auto_runner_creates_cloud_shell_launcher(tmp_path, monkeypatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))

    assert (
        main(
            [
                "launch",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--control-room",
                "--app-source",
                "https://github.com/example/app.git",
                "--fusekit-package",
                "git+https://github.com/example/fusekit.git",
                "--github-repo",
                "example/app",
                "--dns-zone",
                "example.com",
                "--live-url",
                "https://example.com",
                "--approve-dns",
                "--infer-ui",
            ]
        )
        == 0
    )

    job = json.loads((app / ".fusekit" / "job.json").read_text(encoding="utf-8"))
    assert job["runner"] == "oci-cloud-shell"
    assert job["status"] == "waiting"
    plan = json.loads((app / ".fusekit" / "cloud_shell_plan.json").read_text("utf-8"))
    assert plan["fusekit_package"] == "git+https://github.com/example/fusekit.git"
    command = plan["bootstrap_command"]
    assert "--fusekit-package git+https://github.com/example/fusekit.git" in command
    assert "--github-repo example/app" in command
    assert "--dns-zone example.com" in command
    assert "--live-url https://example.com" in command
    assert "--approve-dns" in command
    assert "--infer-ui" in command
    assert (app / ".fusekit" / "launcher.html").exists()
    assert opened and "cloud.oracle.com" in opened[0]


def test_launch_cloud_shell_resumes_existing_waiting_job(tmp_path, monkeypatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log('launch')", encoding="utf-8")
    (app / ".git").mkdir()
    (app / ".git" / "config").write_text(
        "[remote \"origin\"]\n\turl = https://github.com/example/app.git\n",
        encoding="utf-8",
    )
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    job_state = app / ".fusekit" / "job.json"
    from fusekit.runner.job import JobState

    existing = JobState.create("fk-existing", app.resolve(), "oci-cloud-shell")
    existing.mark("oci.authorize", "waiting", "OCI Cloud Shell service gate is open")
    existing.save(job_state)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)
    monkeypatch.setattr("webbrowser.open", lambda url: None)

    assert (
        main(
            [
                "launch",
                str(app),
                "--runner",
                "auto",
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--job-state",
                str(job_state),
            ]
        )
        == 0
    )

    resumed = json.loads(job_state.read_text("utf-8"))
    run_state = json.loads((app / ".fusekit" / "run_state.json").read_text("utf-8"))
    assert resumed["id"] == "fk-existing"
    assert "resumed from state" in resumed["steps"][0]["detail"]
    assert run_state["app_repo_known"] is True
    assert run_state["runner_selected"] is True
    assert run_state["provider_sessions_known"] is True


def test_launch_cloud_shell_does_not_claim_unknown_app_repo(tmp_path, monkeypatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log('launch')", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    job_state = app / ".fusekit" / "job.json"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)
    monkeypatch.setattr("webbrowser.open", lambda url: None)

    assert (
        main(
            [
                "launch",
                str(app),
                "--runner",
                "auto",
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--job-state",
                str(job_state),
                "--no-open-launcher",
            ]
        )
        == 0
    )

    run_state = json.loads((app / ".fusekit" / "run_state.json").read_text("utf-8"))
    assert run_state["app_repo_known"] is False
    assert run_state["runner_selected"] is True


def test_launch_cloud_shell_derives_provider_inputs_for_zero_knowledge_user(
    tmp_path,
    monkeypatch,
) -> None:
    app = tmp_path / "moonlite"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    (app / "vercel.json").write_text(
        json.dumps({"domains": ["rsvp.moonlite.test"]}),
        encoding="utf-8",
    )
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)
    monkeypatch.setattr("webbrowser.open", lambda url: None)

    assert (
        main(
            [
                "launch",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--app-source",
                "https://github.com/fusekitdemo/moonlite-rsvp-demo.git",
                "--fusekit-package",
                "git+https://github.com/example/fusekit.git",
            ]
        )
        == 0
    )

    plan = json.loads((app / ".fusekit" / "cloud_shell_plan.json").read_text("utf-8"))
    command = plan["bootstrap_command"]
    assert "--github-repo fusekitdemo/moonlite-rsvp-demo" in command
    assert "--fusekit-package git+https://github.com/example/fusekit.git" in command
    assert "--vercel-project moonlite-rsvp-demo" in command
    assert "--dns-zone moonlite.test" in command
    assert "--live-url https://rsvp.moonlite.test" in command


def test_launch_inline_oci_auth_continues_to_remote_setup(tmp_path, monkeypatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)

    def local_oci_auth(**kwargs) -> None:
        config_file = kwargs["config_file"]
        profile = kwargs["profile"]
        token = tmp_path / "security-token"
        key = tmp_path / "session.pem"
        token.write_text("security-token", encoding="utf-8")
        key.write_text("session-private-key", encoding="utf-8")
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(
            (
                f"[{profile}]\n"
                "tenancy=ocid1.tenancy.oc1..example\n"
                "user=ocid1.user.oc1..example\n"
                "fingerprint=aa:bb:cc\n"
                f"key_file={key}\n"
                f"security_token_file={token}\n"
                "region=us-ashburn-1\n"
            ),
            encoding="utf-8",
        )

    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="ad-1",
        shape="VM.Standard.E2.1.Micro",
        public_ip="203.0.113.10",
        resource_ids={"instance": "ocid1.instance.oc1..example"},
    )
    monkeypatch.setattr("fusekit.cli.authorize_oci_browser_session", local_oci_auth)
    monkeypatch.setattr("fusekit.cli._provision_oci_workspace", lambda args, vault, plan: workspace)
    remote_artifacts = tmp_path / "remote-artifacts"
    remote_fusekit = remote_artifacts / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    (remote_fusekit / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"ok"}\n', encoding="utf-8")
    (remote_fusekit / "setup_receipt.json").write_text('{"actions":[]}', encoding="utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
        encoding="utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        '{"providers":[]}',
        encoding="utf-8",
    )

    def fake_remote_setup(**kwargs):  # type: ignore[no-untyped-def]
        return {"artifact_archive": "artifacts.tar.gz", "output_dir": str(remote_artifacts)}

    monkeypatch.setattr("fusekit.cli.execute_remote_setup", fake_remote_setup)
    monkeypatch.setattr("fusekit.cli.detonate_remote_worker", lambda **kwargs: None)
    monkeypatch.setattr(
        "fusekit.cli.load_oci_auth_from_vault_or_config",
        lambda *args, **kwargs: object(),
    )

    class FakeProvisioner:
        def __init__(self, auth) -> None:
            self.auth = auth

        def detonate(self, workspace) -> dict[str, str]:
            return {"instance": "deleted"}

    monkeypatch.setattr("fusekit.cli.OciProvisioner", FakeProvisioner)

    assert (
        main(
            [
                "launch",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--runner",
                "oci-free",
                "--yes",
                "--spine",
                "system",
            ]
        )
        == 0
    )

    vault = Vault.open(app / ".fusekit" / "fusekit.vault.json", "passphrase")
    assert vault.require("runner.oci.profile").metadata["auth_mode"] == "browser-session"
    job = json.loads((app / ".fusekit" / "job.json").read_text(encoding="utf-8"))
    assert job["status"] == "done"
    assert job["steps"][1]["status"] == "done"
    run_state = json.loads((app / ".fusekit" / "run_state.json").read_text(encoding="utf-8"))
    assert run_state["provider_checks_passed_or_pending_safe"] is True
    assert run_state["receipt_written"] is True
    assert run_state["detonation_safe"] is True
    checkpoints = json.loads((app / ".fusekit" / "checkpoints.json").read_text(encoding="utf-8"))
    assert checkpoints["job_id"] == job["id"]
    assert any(item["id"] == "detonate.workspace" for item in checkpoints["checkpoints"])


def test_remote_verification_path_must_be_passed_or_pending_safe(tmp_path) -> None:
    from fusekit.cli import (
        _verification_report_path_allows_detonation,
        _verification_report_path_allows_launch_progress,
    )

    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "failed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert _verification_report_path_allows_detonation(report) is False

    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "cloudflare",
                        "check": "dns_propagated",
                        "status": "pending",
                        "details": {"pending_safe": True},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert _verification_report_path_allows_detonation(report) is True
    assert _verification_report_path_allows_launch_progress(report) is True


def test_local_verification_job_result_pauses_for_human_gate_report(tmp_path) -> None:
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "vercel",
                        "check": "project_exists",
                        "status": "needs_human_gate",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert _local_verification_job_result(report) == (
        "pending",
        "verification is waiting on provider human gates",
    )
    from fusekit.cli import (
        _verification_report_path_allows_detonation,
        _verification_report_path_allows_launch_progress,
    )

    assert _verification_report_path_allows_detonation(report) is False
    assert _verification_report_path_allows_launch_progress(report) is True


def test_local_verification_job_result_reflects_failed_report(tmp_path) -> None:
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "vercel",
                        "check": "project_exists",
                        "status": "failed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert _local_verification_job_result(report) == (
        "failed",
        "verification report contains failed or blocked checks",
    )


def test_local_verification_job_result_allows_pending_safe_report(tmp_path) -> None:
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "pending",
                        "details": {"pending_safe": True},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert _local_verification_job_result(report) == (
        "done",
        "verification is passed or pending-safe",
    )


def test_local_verification_job_result_skips_missing_rehearsal_report(tmp_path) -> None:
    assert _local_verification_job_result(tmp_path / "missing.json") == (
        "skipped",
        "local rehearsal did not produce a verification report",
    )


def test_allow_incomplete_live_url_failure_is_pending_safe(monkeypatch, tmp_path) -> None:
    args = argparse.Namespace(live_url="https://moonlite.rsvp", allow_incomplete=True)
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app", vault_path="vault.json")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    def fail_live_url(url: str) -> dict[str, object]:
        raise ProviderError(f"Live URL verification failed: {url}")

    monkeypatch.setattr("fusekit.cli.verify_live_url", fail_live_url)

    _verify_apply_live_url(args, audit, receipt, report)

    payload = report.to_dict()
    assert payload["checks"][0]["status"] == "pending"
    assert payload["checks"][0]["details"]["pending_safe"] is True
    assert verification_report_allows_detonation(payload) is True
    assert receipt.actions[0]["status"] == "pending"


def test_pending_provider_gate_makes_live_url_failure_pending_safe(
    monkeypatch,
    tmp_path,
) -> None:
    args = argparse.Namespace(
        app=tmp_path,
        live_url="https://moonlite.rsvp",
        allow_incomplete=False,
    )
    GateService.load(tmp_path / ".fusekit" / "gates.json").wait(
        "provider.vercel.vercel-project",
        provider="vercel",
        reason="Vercel needs GitHub connected",
        resume_url="https://vercel.com/account/settings/login-connections",
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app", vault_path="vault.json")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    def fail_live_url(url: str) -> dict[str, object]:
        raise ProviderError(f"Live URL verification failed: {url}")

    monkeypatch.setattr("fusekit.cli.verify_live_url", fail_live_url)

    _verify_apply_live_url(args, audit, receipt, report)

    payload = report.to_dict()
    assert payload["checks"][0]["status"] == "pending"
    assert payload["checks"][0]["details"]["pending_safe"] is True
    assert receipt.actions[0]["status"] == "pending"


def test_custom_domain_without_dns_approval_makes_live_url_failure_pending_safe(
    monkeypatch,
    tmp_path,
) -> None:
    args = argparse.Namespace(
        app=tmp_path,
        live_url="https://moonlite.rsvp",
        allow_incomplete=False,
        approve_dns=False,
    )
    manifest = SetupManifest(
        app_name="app",
        domains=(DomainRequirement(domain="moonlite.rsvp", provider="cloudflare"),),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app", vault_path="vault.json")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    def fail_live_url(url: str) -> dict[str, object]:
        raise ProviderError(f"Live URL verification failed: {url}")

    monkeypatch.setattr("fusekit.cli.verify_live_url", fail_live_url)

    _verify_apply_live_url(args, audit, receipt, report, manifest=manifest)

    payload = report.to_dict()
    assert payload["checks"][0]["status"] == "pending"
    assert payload["checks"][0]["details"]["pending_safe"] is True
    assert receipt.actions[0]["status"] == "pending"


def test_custom_domain_with_dns_approval_keeps_live_url_failure_strict(
    monkeypatch,
    tmp_path,
) -> None:
    args = argparse.Namespace(
        app=tmp_path,
        live_url="https://moonlite.rsvp",
        allow_incomplete=False,
        approve_dns=True,
    )
    manifest = SetupManifest(
        app_name="app",
        domains=(DomainRequirement(domain="moonlite.rsvp", provider="cloudflare"),),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app", vault_path="vault.json")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    def fail_live_url(url: str) -> dict[str, object]:
        raise ProviderError(f"Live URL verification failed: {url}")

    monkeypatch.setattr("fusekit.cli.verify_live_url", fail_live_url)

    with pytest.raises(ProviderError):
        _verify_apply_live_url(args, audit, receipt, report, manifest=manifest)


def test_pending_provider_gate_disables_verification_retries(tmp_path) -> None:
    args = argparse.Namespace(
        app=tmp_path,
        verify_attempts=10,
        verify_retry_seconds=30,
    )
    GateService.load(tmp_path / ".fusekit" / "gates.json").wait(
        "provider.vercel.vercel-project",
        provider="vercel",
        reason="Vercel needs GitHub connected",
        resume_url="https://vercel.com/account/settings/login-connections",
    )

    assert _provider_verification_attempt_config(args) == (1, 0.0)


def test_provider_verification_accepts_human_gate_as_parked_state() -> None:
    assert _provider_verification_acceptable(
        [
            VerificationResult(
                provider="vercel",
                kind="vercel-project",
                target="moonlight-rsvp-demo",
                status="needs_human_gate",
                details={"service_gate": True},
            )
        ]
    )


def test_provider_verification_parks_provider_with_pending_gate(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(
        app=app,
        live_url="https://moonlite.rsvp",
        verify_attempts=10,
        verify_retry_seconds=30,
    )
    GateService.load(app / ".fusekit" / "gates.json").wait(
        "provider.vercel.vercel-project",
        provider="vercel",
        reason="Vercel needs GitHub connected",
        resume_url="https://vercel.com/account/settings/login-connections",
    )
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web",
                capabilities=("capability_pack",),
                secrets=("VERCEL_TOKEN",),
            ),
        ),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    monkeypatch.setattr(
        "fusekit.cli.verify_provider_pack",
        lambda *args, **kwargs: pytest.fail("pending provider gate should park verification"),
    )

    _verify_provider_packs(args, manifest, Vault.empty(), audit, receipt, report)

    assert receipt.actions[0]["status"] == "needs_human_gate"
    payload = report.to_dict()
    assert payload["overall"] == "needs_human_gate"
    assert payload["counts"]["needs_human_gate"] == 1


def test_provider_verification_parks_downstream_dns_behind_resend_gate(
    monkeypatch,
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    args = argparse.Namespace(
        app=app,
        live_url="https://moonlite.rsvp",
        verify_attempts=10,
        verify_retry_seconds=30,
    )
    GateService.load(app / ".fusekit" / "gates.json").wait(
        "provider.resend.resend-domain",
        provider="resend",
        reason="Resend API key is required before DNS records exist.",
        resume_url="https://resend.com/api-keys",
    )
    manifest = SetupManifest(
        app_name="app",
        app_path=str(app),
        services=(
            ServiceRequirement(
                provider="cloudflare",
                kind="dns",
                name="dns",
                capabilities=("capability_pack",),
                secrets=("CLOUDFLARE_API_TOKEN",),
            ),
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("capability_pack",),
                secrets=("RESEND_API_KEY",),
            ),
        ),
        domains=(DomainRequirement(provider="cloudflare", domain="moonlite.rsvp"),),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    monkeypatch.setattr(
        "fusekit.cli.verify_provider_pack",
        lambda *args, **kwargs: pytest.fail("downstream DNS should wait for Resend gate"),
    )

    _verify_provider_packs(args, manifest, Vault.empty(), audit, receipt, report)

    actions = receipt.to_dict()["actions"]
    assert [action["details"]["provider"] for action in actions] == ["resend", "cloudflare"]
    assert [action["status"] for action in actions] == ["needs_human_gate", "pending-safe"]
    payload = report.to_dict()
    assert payload["overall"] == "needs_human_gate"
    checks = {(check["provider"], check["check"]): check for check in payload["checks"]}
    assert checks[("resend", "provider_gate")]["status"] == "needs_human_gate"
    cloudflare = checks[("cloudflare", "provider_gate")]
    assert cloudflare["status"] == "pending"
    details = cloudflare["details"]["details"]
    assert details["pending_safe"] is True
    assert details["blocked_by_provider"] == "resend"
    assert "active upstream provider gate" in cloudflare["repair"]


def test_strict_live_url_failure_still_fails(monkeypatch, tmp_path) -> None:
    args = argparse.Namespace(live_url="https://moonlite.rsvp", allow_incomplete=False)
    audit = AuditLog(tmp_path / "audit.jsonl")
    receipt = Receipt(app_name="app", vault_path="vault.json")
    report = VerificationReport(app_name="app", live_url=args.live_url)

    def fail_live_url(url: str) -> dict[str, object]:
        raise ProviderError(f"Live URL verification failed: {url}")

    monkeypatch.setattr("fusekit.cli.verify_live_url", fail_live_url)

    try:
        _verify_apply_live_url(args, audit, receipt, report)
    except ProviderError:
        pass
    else:
        raise AssertionError("strict live URL verification should fail")


def test_launch_detonates_oci_workspace_after_remote_failure(tmp_path, monkeypatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log('launch')", encoding="utf-8")
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)

    def local_oci_auth(**kwargs) -> None:
        config_file = kwargs["config_file"]
        profile = kwargs["profile"]
        token = tmp_path / "security-token"
        key = tmp_path / "session.pem"
        token.write_text("security-token", encoding="utf-8")
        key.write_text("session-private-key", encoding="utf-8")
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(
            (
                f"[{profile}]\n"
                "tenancy=ocid1.tenancy.oc1..example\n"
                "user=ocid1.user.oc1..example\n"
                "fingerprint=aa:bb:cc\n"
                f"key_file={key}\n"
                f"security_token_file={token}\n"
                "region=us-ashburn-1\n"
            ),
            encoding="utf-8",
        )

    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="ad-1",
        shape="VM.Standard.E2.1.Micro",
        public_ip="203.0.113.10",
        resource_ids={"instance": "ocid1.instance.oc1..example"},
    )
    detonated: list[str] = []
    monkeypatch.setattr("fusekit.cli.authorize_oci_browser_session", local_oci_auth)
    monkeypatch.setattr("fusekit.cli._provision_oci_workspace", lambda args, vault, plan: workspace)

    def fail_remote_setup(**kwargs):  # type: ignore[no-untyped-def]
        raise FuseKitError("remote setup failed")

    monkeypatch.setattr("fusekit.cli.execute_remote_setup", fail_remote_setup)
    monkeypatch.setattr(
        "fusekit.cli.detonate_remote_worker",
        lambda **kwargs: detonated.append("worker"),
    )
    monkeypatch.setattr(
        "fusekit.cli.load_oci_auth_from_vault_or_config",
        lambda *args, **kwargs: object(),
    )

    class LocalProvisioner:
        def __init__(self, auth) -> None:
            self.auth = auth

        def detonate(self, workspace) -> dict[str, str]:
            detonated.append("workspace")
            return {"instance": "deleted"}

    monkeypatch.setattr("fusekit.cli.OciProvisioner", LocalProvisioner)

    assert (
        main(
            [
                "launch",
                str(app),
                "--passphrase-file",
                str(passphrase),
                "--no-bootstrap",
                "--runner",
                "oci-free",
                "--yes",
                "--spine",
                "system",
            ]
        )
        == 2
    )

    assert detonated == ["worker", "workspace"]
    job = json.loads((app / ".fusekit" / "job.json").read_text(encoding="utf-8"))
    assert job["status"] == "failed"
    assert any(
        step["id"] == "setup.execute" and step["status"] == "failed"
        for step in job["steps"]
    )
    assert any(
        step["id"] == "detonate.workspace" and step["status"] == "done"
        for step in job["steps"]
    )


def test_runner_authorize_oci_prepares_public_key(monkeypatch, tmp_path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    monkeypatch.setattr("webbrowser.open", lambda url: None)

    assert (
        main(
            [
                "runner",
                "authorize",
                "oci",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--oci-auth-mode",
                "api-key-upload",
                "--spine",
                "system",
            ]
        )
        == 2
    )

    output = capsys.readouterr().out
    assert "BEGIN PUBLIC KEY" in output
    opened = Vault.open(vault, "passphrase")
    assert opened.require("runner.oci.api_signing_key.private").kind == (
        "oci_api_signing_private_key"
    )
    assert "BEGIN RSA PRIVATE KEY" not in vault.read_text(encoding="utf-8")


def test_leak_scan_and_start_over_commands(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    fusekit = app / ".fusekit"
    fusekit.mkdir(parents=True)
    (app / "config.txt").write_text("SECRET=plaintextvalue\n", encoding="utf-8")
    (fusekit / "job.json").write_text("{}", encoding="utf-8")
    (fusekit / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")

    assert main(["leak-scan", str(app)]) == 1
    assert "config.txt:1" in capsys.readouterr().out
    assert main(["start-over", str(app)]) == 0
    assert not (fusekit / "job.json").exists()
    assert (fusekit / "fusekit.vault.json").exists()


def test_authorize_retries_handoff_until_gate_attempt_limit(monkeypatch, tmp_path) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    opened: list[str] = []

    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))

    assert (
        main(
            [
                "authorize",
                "github",
                "--vault",
                str(vault),
                "--passphrase-file",
                str(passphrase),
                "--handoff",
                "--spine",
                "system",
                "--open-browser",
                "--gate-retry-seconds",
                "0",
                "--gate-max-attempts",
                "2",
            ]
        )
        == 2
    )
    assert opened.count("https://github.com/signup") == 1
