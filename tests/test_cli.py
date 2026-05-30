from __future__ import annotations

import json
from urllib.error import URLError

from fusekit.audit import assert_no_secret_text
from fusekit.cli import main
from fusekit.runner.oci_live import OciWorkspace
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
    assert "FuseKit OCI Launcher" in text
    assert "https://github.com/example/app.git" in text


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

    assert main(["provider", "synthesize", "plaid", "--app", str(app)]) == 0
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

    assert main(["provider", "synthesize", "resend", "--app", str(app)]) == 0
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

    assert main(["provider", "synthesize", "resend", "--app", str(app)]) == 0
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
    monkeypatch.setattr(
        "fusekit.cli.execute_remote_setup",
        lambda **kwargs: {"artifact_archive": "artifacts.tar.gz", "output_dir": "remote-artifacts"},
    )
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
