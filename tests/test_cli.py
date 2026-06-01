from __future__ import annotations

import argparse
import json
from urllib.error import URLError

from fusekit.audit import AuditLog, Receipt, assert_no_secret_text
from fusekit.cli import _attempt_provider_api_fallback, _repair_navigation_completed, main
from fusekit.errors import FuseKitError
from fusekit.manifest import ServiceRequirement, SetupManifest, write_manifest
from fusekit.providers.capability_pack import (
    VerificationRecipe,
    synthesize_provider_pack,
    write_provider_pack,
)
from fusekit.runner.oci_live import OciWorkspace
from fusekit.spine.playbooks import BrowserPlaybookEvent
from fusekit.vault import Vault


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
    assert "--verify-attempts 10" in text
    assert "--verify-retry-seconds 30.0" in text
    assert "--gate-max-attempts 0" in text
    assert "--infer-ui" in text
    assert "--capture-stdin" in text


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
        vault,
        AuditLog(tmp_path / "audit.jsonl"),
        receipt,
    )

    assert vault.require("provider.resend.resend_api_key").value == "fallback-secret-hidden"
    public = json.dumps(receipt.to_dict())
    assert_no_secret_text(public, ["provider-token-hidden", "fallback-secret-hidden"])


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
    assert "rerun verification" in report["checks"][0]["repair"]


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


def test_authorize_can_use_openclaw_spine_dry_run(monkeypatch, tmp_path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    token = "vercel_supervised_token_value"

    monkeypatch.setattr("getpass.getpass", lambda prompt: token)

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
    assert any(step["id"] == "verify.live" and step["status"] == "skipped" for step in job["steps"])
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
    assert "local rehearsal did not require live verification" in html
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
    from fusekit.cli import _verification_report_path_allows_detonation

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
    assert opened.count("https://github.com/signup") == 2
