from __future__ import annotations

import json
from pathlib import Path

from fusekit.detonation.preflight import (
    run_detonation_preflight,
    verification_report_allows_launch_progress,
)
from fusekit.runner.control_room.surfaces import public_control_room_security_surface
from fusekit.runner.worker_replacement import build_passed_worker_replacement_drill


def _run_record_payload(
    *,
    host_machine_state_required: bool = False,
) -> dict[str, object]:
    return {
        "schema_version": "fusekit.run-record.v1",
        "id": "fk-test",
        "durable_state": {
            "detonation_scope": {
                "host_machine_state_required": host_machine_state_required,
            }
        },
        "provider_gates": {"records": []},
        "audit_trail": {"entries": []},
        "control_room_security": public_control_room_security_surface(),
        "detonation": {"workspace_detonated": False},
        "recording_contract": {"recording_ready": False},
    }


def _write_run_record(path: Path, *, host_machine_state_required: bool = False) -> None:
    path.write_text(
        json.dumps(_run_record_payload(host_machine_state_required=host_machine_state_required)),
        encoding="utf-8",
    )


def _write_preflight_survivors(fusekit: Path) -> dict[str, Path]:
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    worker_replacement_drill = fusekit / "worker_replacement_drill.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record)
    worker_replacement_drill.write_text(
        json.dumps(build_passed_worker_replacement_drill()),
        encoding="utf-8",
    )
    return {
        "vault": vault,
        "audit": audit,
        "receipt": receipt,
        "verification_report": report,
        "rollback_metadata": rollback,
        "run_record": run_record,
        "worker_replacement_drill": worker_replacement_drill,
    }


def test_detonation_preflight_allows_passed_and_pending_safe_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
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
    _write_run_record(run_record)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert result.ok


def test_detonation_preflight_requires_central_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
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
        run_record=run_record,
    )

    assert not result.ok
    assert any("missing central run record" in failure for failure in result.failures)


def test_detonation_preflight_requires_worker_replacement_drill_when_requested(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    drill = survivors.pop("worker_replacement_drill")
    drill.unlink()

    result = run_detonation_preflight(
        root=tmp_path,
        worker_replacement_drill=drill,
        **survivors,
    )

    assert not result.ok
    assert any("worker replacement drill" in failure for failure in result.failures)


def test_detonation_preflight_rejects_host_machine_state_dependency(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record, host_machine_state_required=True)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok
    assert any("requires host-machine state" in failure for failure in result.failures)


def test_detonation_preflight_requires_control_room_security_proof(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["control_room_security"] = {
        "schema_version": "fusekit.control-room-security-surface.v1",
        "routes": [],
        "state_changing_routes": [],
        "state_changing_route_count": 0,
        "required_post_protection": "action-token",
        "statement": "protected",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "missing protected control-room mutation routes" in failure
        for failure in result.failures
    )
    assert any(
        "control-room POST protection is incomplete" in failure
        for failure in result.failures
    )
    assert any(
        "control-room no-CORS/action-token proof is incomplete" in failure
        for failure in result.failures
    )


def test_detonation_preflight_rejects_secret_text_in_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["errors"] = [
        {
            "id": "provider.callback",
            "detail": "Callback failed at https://provider.example/callback?code=secret-code",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("credential-looking text" in failure for failure in result.failures)


def test_detonation_preflight_allows_redacted_run_record_text(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["errors"] = [
        {
            "id": "provider.callback",
            "detail": "Callback failed at https://provider.example/callback?code=[redacted]",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert result.ok


def test_launch_progress_allows_nested_pending_safe_checks() -> None:
    assert verification_report_allows_launch_progress(
        {
            "checks": [
                {
                    "provider": "vercel",
                    "check": "live_url_healthy",
                    "status": "pending",
                    "details": {"details": {"pending_safe": True}},
                },
                {
                    "provider": "vercel",
                    "check": "env_vars_configured",
                    "status": "needs_human_gate",
                    "details": {"details": {"service_gate": True}},
                },
            ]
        }
    )


def test_detonation_preflight_blocks_human_gate_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
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
    _write_run_record(run_record)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
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
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[]}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"vercel","check":"env_vars_configured","status":"failed"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok
    assert any("missing rollback metadata" in failure for failure in result.failures)
    assert any("vercel.env_vars_configured is failed" in failure for failure in result.failures)
