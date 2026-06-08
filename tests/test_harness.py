from __future__ import annotations

import json
from pathlib import Path

from fusekit.cli import main
from fusekit.harness import run_acceptance
from fusekit.harness.acceptance import AcceptanceCheck, AcceptanceReport, _acceptance_blockers
from fusekit.harness.ledger import HarnessLedger
from fusekit.vault import Vault


def _strategy_decision(kind: str = "api", status: str = "available") -> dict[str, object]:
    return {
        "selected": {
            "kind": kind,
            "status": status,
            "deterministic": True,
            "implemented": True,
            "reason": "deterministic provider API is available",
        },
        "candidates": [
            {
                "kind": kind,
                "status": status,
                "deterministic": True,
                "implemented": True,
                "reason": "deterministic provider API is available",
            }
        ],
    }


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
    assert report_json["blockers"] == []
    assert any(check["id"] == "manifest.scanned" for check in report_json["checks"])


def test_acceptance_report_serializes_public_paths(tmp_path) -> None:
    app = tmp_path / "app"
    artifact = app / ".fusekit" / "acceptance" / "artifacts" / "gates.json"
    report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=False,
        checks=(AcceptanceCheck("gates.resolved", "failed", "Needs repair.", str(artifact)),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert str(tmp_path) not in text
    assert payload["app_path"] == "app"
    assert payload["ledger_path"] == ".fusekit/acceptance/ledger.jsonl"
    assert payload["report_path"] == ".fusekit/acceptance/report.json"
    assert payload["checks"][0]["artifact"] == ".fusekit/acceptance/artifacts/gates.json"


def test_harness_ledger_records_public_artifact_paths(tmp_path) -> None:
    ledger = HarnessLedger.create(tmp_path / "app" / ".fusekit" / "acceptance")

    artifact = ledger.snapshot_json("provider proof", {"ok": True})
    ledger_text = (tmp_path / "app" / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )

    assert artifact.exists()
    assert str(tmp_path) not in ledger_text
    assert ".fusekit/acceptance/artifacts/provider-proof" in ledger_text


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
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["encrypted vault"]["category"] == "Vault"
    assert "vault capture enabled" in blockers["encrypted vault"]["next_action"]
    assert blockers["provider strategy decisions"]["category"] == "Provider routes"
    assert "strategy recorder" in blockers["provider strategy decisions"]["next_action"]


def test_acceptance_report_redacts_check_and_blocker_details(tmp_path) -> None:
    raw_code = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    check = AcceptanceCheck(
        "provider.callback",
        "failed",
        f"Provider callback failed: https://provider.example/callback?code={raw_code}&state=ok",
    )
    blockers = _acceptance_blockers([check], [])
    report = AcceptanceReport(
        mode="live",
        app_path=str(tmp_path),
        launch_ready=False,
        checks=(check,),
        ledger_path=str(tmp_path / "ledger.jsonl"),
        report_path=str(tmp_path / "report.json"),
        blockers=(
            *blockers,
            {
                "item": "provider callback",
                "category": "Provider",
                "next_action": "Rerun the provider gate.",
                "detail": (
                    "Raw callback detail: "
                    f"https://provider.example/callback?code={raw_code}&state=ok"
                ),
            },
        ),
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert raw_code not in text
    assert "code=[redacted]" in text
    assert payload["checks"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][1]["detail"].endswith("?code=[redacted]&state=ok")


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
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "status": "passed",
                            "target": "OPENAI_API_KEY",
                            "record_id": "provider.openai.token",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
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
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-deploy",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "vercel",
                                    "recipe_kind": "vercel-deploy",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI auth complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "attempts": 1,
                        "follow_steps": ["Complete login."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "resume_url": "http://localhost:1455/auth/callback?code=secret-code",
                        "last_opened_url": "https://provider.example/?token=secret-token",
                    }
                ]
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
    assert "gates.resolved" in check_ids
    assert "gates.audited" in check_ids
    assert report.missing == ()
    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    gates_artifact = gates_check.artifact
    gates_text = Path(gates_artifact).read_text(encoding="utf-8")
    assert "secret-code" not in gates_text
    assert "secret-token" not in gates_text
    assert "has_resume_url" in gates_text
    assert "captured_count" in gates_text
    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    audit_text = Path(audit_check.artifact).read_text(encoding="utf-8")
    assert "secret-code" not in audit_text
    assert "secret-token" not in audit_text
    assert "provider.openai.authorization" in audit_text
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["blockers"] == []
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


def test_live_acceptance_requires_resend_before_dns_when_both_are_present(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps({"actions": [], "raw_secrets_exposed": 0, "live_url": "https://moonlite.rsvp"}),
        encoding="utf-8",
    )
    (remote_fusekit / "audit.jsonl").write_text("{}", encoding="utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    order_check = next(check for check in report.checks if check.id == "provider_strategies.order")
    assert report.launch_ready is False
    assert order_check.status == "failed"
    assert "Resend-before-DNS provider setup order" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend-before-DNS provider setup order"]["category"] == "Provider order"
    assert "Run Resend domain setup before Cloudflare/DNS" in blockers[
        "Resend-before-DNS provider setup order"
    ]["next_action"]


def test_live_acceptance_requires_complete_provider_strategy_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
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
                                "decision": {"selected": {"kind": "api"}},
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "selected.status is missing" in strategy_check.detail
    assert "complete provider strategy evidence" in report.missing


def test_live_acceptance_requires_strategy_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "provider_strategies.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider strategy coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider strategy coverage"]["category"] == "Provider routes"
    assert "every provider declared by the manifest" in blockers[
        "complete provider strategy coverage"
    ]["next_action"]


def test_live_acceptance_requires_verification_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    }
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "verification_report.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider verification coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider verification coverage"]["category"] == "Verification"
    assert "every provider declared by the manifest" in blockers[
        "complete provider verification coverage"
    ]["next_action"]


def test_live_acceptance_requires_rollback_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    },
                    {
                        "provider": "cloudflare",
                        "check": "dns_record_exists",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "rollback_metadata.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete rollback coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete rollback coverage"]["category"] == "Rollback"
    assert "every provider declared by the manifest" in blockers[
        "complete rollback coverage"
    ]["next_action"]


def test_live_acceptance_requires_guided_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
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
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                    }
                ]
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

    guided_check = next(check for check in report.checks if check.id == "gates.guided")
    assert report.launch_ready is False
    assert guided_check.status == "failed"
    assert "provider.github.authorization missing next_action, resume_hint" in guided_check.detail
    assert "guided human gates" in report.missing


def test_live_acceptance_requires_audited_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
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
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
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

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.github.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["audited human gate interventions"]["category"] == "Human gates"
    assert "through the launcher" in blockers["audited human gate interventions"]["next_action"]


def test_live_acceptance_requires_clipboard_capture_for_secret_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.openai.token", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "openai",
                        "strategies": [
                            {
                                "recipe": "openai-token",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI token captured",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
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

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.clipboard_capture" in audit_check.detail
    assert "provider.openai.authorization:OPENAI_API_KEY" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_all_multi_value_gate_captures(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "target": "RESEND_AUDIENCE_ID",
                            "record_id": "app.resend.resend_audience_id",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.env", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-runtime-values",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.resend.runtime-values",
                        "provider": "resend",
                        "reason": "Resend runtime values captured",
                        "status": "passed",
                        "classification": "provider-runtime-values",
                        "target": "RESEND_AUDIENCE_ID,RESEND_FROM_EMAIL",
                        "captured_targets": ["RESEND_AUDIENCE_ID"],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
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

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.resend.runtime-values:RESEND_FROM_EMAIL" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_provider_gate_open_audit(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns-records",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare authorization complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
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

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.gate_open" in audit_check.detail
    assert "provider.cloudflare.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_resolved_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.vercel.env", "status": "planned"}]}),
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
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare token creation",
                        "status": "waiting",
                        "next_action": "Finish Cloudflare login in the VM browser.",
                        "resume_hint": "FuseKit will retry verification after resume.",
                    }
                ]
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

    gate_check = next(check for check in report.checks if check.id == "gates.resolved")
    assert report.launch_ready is False
    assert gate_check.status == "failed"
    assert "provider.cloudflare.authorization:waiting" in gate_check.detail
    assert "resolved human gates" in report.missing
