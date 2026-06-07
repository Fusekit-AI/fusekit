from __future__ import annotations

import json

from fusekit.detonation.preflight import run_detonation_preflight


def test_detonation_preflight_allows_passed_and_pending_safe_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {"provider": "github", "check": "repo_secret_exists", "status": "passed"},
                    {
                        "provider": "cloudflare",
                        "check": "dns_propagated",
                        "status": "pending",
                        "details": {"pending_safe": True},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
    )

    assert result.ok


def test_detonation_preflight_blocks_human_gate_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
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
    rollback.write_text(
        '{"rollback":[{"action":"rollback.vercel.project","status":"planned"}]}',
        encoding="utf-8",
    )

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
    )

    assert not result.ok


def test_detonation_preflight_blocks_failed_checks_and_missing_rollback(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"vercel","check":"env_vars_configured","status":"failed"}]}',
        encoding="utf-8",
    )

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
    )

    assert not result.ok
    assert any("missing rollback metadata" in failure for failure in result.failures)
    assert any("vercel.env_vars_configured is failed" in failure for failure in result.failures)
