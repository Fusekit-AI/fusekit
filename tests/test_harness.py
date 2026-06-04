from __future__ import annotations

import json

from fusekit.cli import main
from fusekit.harness import run_acceptance
from fusekit.vault import Vault


def test_acceptance_rehearsal_writes_ledger_and_report(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="rehearsal")

    assert report.launch_ready is True
    assert (app / "fusekit.yaml").exists()
    assert (app / ".fusekit" / "acceptance" / "ledger.jsonl").exists()
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert any(check["id"] == "manifest.scanned" for check in report_json["checks"])


def test_acceptance_live_requires_real_provider_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="live")

    assert report.launch_ready is False
    assert "encrypted vault" in report.missing
    assert "redacted setup receipt" in report.missing
    assert "safe verification report" in report.missing
    assert "rollback metadata" in report.missing
    assert "provider strategy decisions" in report.missing


def test_acceptance_live_ingests_retrieved_oci_artifacts(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "GitHub token",
        "ghp_secret_for_harness",
    )
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [{"provider": "github", "action": "secret.upsert"}],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "github",
                        "check": "repo_secret_exists",
                        "status": "passed",
                    },
                    {
                        "provider": "vercel",
                        "check": "deployment_ready",
                        "status": "passed",
                    },
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.github.secret", "status": "planned"},
                    {"action": "rollback.vercel.env", "status": "planned"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    "selected": {"kind": "api", "status": "available"},
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    assert report.launch_ready is True
    check_ids = {check.id for check in report.checks}
    assert "remote_artifacts.loaded" in check_ids
    assert "verification_report.safe" in check_ids
    assert "provider_strategies.recorded" in check_ids
    assert report.missing == ()
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert any(check["id"] == "remote_artifacts.loaded" for check in report_json["checks"])


def test_acceptance_cli_checks_vault_without_leaking_secret(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    (app / "mail.ts").write_text("process.env.RESEND_API_KEY", encoding="utf-8")
    vault_path = app / ".fusekit" / "fusekit.vault.json"
    vault_path.parent.mkdir(parents=True)
    passphrase = tmp_path / "pass.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    secret = "re_super_secret_value"
    vault = Vault.empty()
    vault.put("provider.resend.token", "provider_token", "resend", "Resend token", secret)
    vault.save(vault_path, "passphrase")

    assert (
        main(
            [
                "acceptance",
                "run",
                str(app),
                "--mode",
                "rehearsal",
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "vault.unlock" in output
    assert "vault.wrong_passphrase" in output
    assert secret not in output
    assert secret not in (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )
