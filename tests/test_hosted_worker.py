from __future__ import annotations

import io
import json
import shutil
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import GitHubAppConfig
from fusekit.hosted.job import (
    advance_hosted_launch_job,
    build_hosted_launch_job,
    claim_hosted_launch_job,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.hosted.worker import (
    build_hosted_worker_launch_invocation,
    build_hosted_worker_maintenance_invocation,
    build_hosted_worker_proof_payload,
    build_hosted_worker_workspace_proof_payload,
    prepare_hosted_worker_execution,
)
from fusekit.runner.remote_survivors import REMOTE_REQUIRED_SURVIVOR_FILES
from fusekit.scanner import scan_repo


class FakeResponse:
    def __init__(self, payload: dict[str, object] | bytes) -> None:
        self.status = 200
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self._payload, bytes):
            return self._payload
        return json.dumps(self._payload).encode("utf-8")


class SequenceOpener:
    def __init__(self, payloads: list[dict[str, object] | bytes]) -> None:
        self.payloads = payloads
        self.requests: list[urllib.request.Request] = []
        self.bodies: list[dict[str, Any]] = []

    def __call__(
        self,
        request: urllib.request.Request,
        timeout: float | None = None,
    ) -> FakeResponse:
        self.requests.append(request)
        self.bodies.append(json.loads((request.data or b"{}").decode("utf-8")))
        assert timeout in {30.0, 90.0}
        return FakeResponse(self.payloads.pop(0))


def test_prepare_hosted_worker_execution_fetches_source_without_leaking_tokens(
    tmp_path: Path,
) -> None:
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = claim_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(
                plan,
                github_installation_id=42,
                job_id="hosted-test",
                now=1_700_000_000,
            ),
            "start",
        ),
        worker_id="worker-01",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T06:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"default_branch": "main"},
            _github_zip(dependency='"resend": "latest"'),
        ]
    )

    execution = prepare_hosted_worker_execution(
        job,
        github_config=_github_config(),
        workspace=tmp_path / "worker",
        opener=opener,
    )
    payload = execution.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-worker-execution.v1"
    assert payload["job_id"] == "hosted-test"
    assert payload["github_installation_id"] == 42
    assert payload["source"] == {
        "provider": "github",
        "repo": "example/hosted-demo",
        "default_branch": "main",
        "auth_source": "github-token",
        "private": True,
        "workspace_label": "hosted-worker-source",
    }
    assert payload["acceptance_gate"] == {
        "mode": "live",
        "remote_artifacts": ".fusekit/remote-artifacts",
        "require_recording": True,
        "command": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
    }
    assert execution.source_dir.exists()
    assert opener.bodies[0] == {"permissions": {"contents": "read"}}
    assert opener.requests[1].headers["Authorization"] == "Bearer ghs_fake_installation_token"
    assert opener.requests[2].headers["Authorization"] == "Bearer ghs_fake_installation_token"
    assert "ghs_fake_installation_token" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert str(tmp_path) not in serialized


def test_hosted_worker_launch_invocation_is_private_but_public_redacted(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)

    invocation = build_hosted_worker_launch_invocation(execution)
    payload = invocation.to_dict()
    serialized = json.dumps(payload)

    assert invocation.launch_args[:3] == (
        "fusekit",
        "launch",
        str(execution.source_dir),
    )
    assert "--runner" in invocation.launch_args
    assert "local" in invocation.launch_args
    assert "--yes" in invocation.launch_args
    assert "--control-room" in invocation.launch_args
    assert "--no-open-launcher" in invocation.launch_args
    assert "--app-source" in invocation.launch_args
    assert "https://github.com/example/hosted-demo" in invocation.launch_args
    assert "--visual-runner" in invocation.launch_args
    assert "novnc" in invocation.launch_args
    assert invocation.artifact_paths["job_state"] == execution.source_dir / ".fusekit/job.json"
    assert invocation.acceptance_args[:4] == (
        "fusekit",
        "acceptance",
        "run",
        str(execution.source_dir),
    )
    assert "--mode" in invocation.acceptance_args
    assert "live" in invocation.acceptance_args
    assert "--remote-artifacts" in invocation.acceptance_args
    assert "--require-recording" in invocation.acceptance_args
    assert payload["schema_version"] == "fusekit.hosted-worker-invocation.v1"
    assert payload["source_workspace"] == "<hosted-worker-source>"
    assert payload["artifact_labels"]["setup_receipt"] == ".fusekit/setup_receipt.json"
    assert payload["launch_args"][2] == "<hosted-worker-source>"
    assert "<hosted-worker-source>/.fusekit/job.json" in payload["launch_args"]
    assert "<hosted-worker-source>/.fusekit/remote-artifacts" in payload["acceptance_args"]
    assert "FUSEKIT_PASSPHRASE" in payload["env_contract"]
    assert payload["completion_gate"] == {
        "worker_proof_endpoint": "/api/hosted/jobs/<job>/worker-proof",
        "proof_schema_version": "fusekit.hosted-worker-proof.v1",
        "requires_live_acceptance": True,
        "requires_recording": True,
    }
    assert str(tmp_path) not in serialized
    assert "ghs_fake_installation_token" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_launch_invocation_rejects_invalid_retry_settings(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)

    with pytest.raises(FuseKitError, match="verify attempts"):
        build_hosted_worker_launch_invocation(execution, verify_attempts=0)
    with pytest.raises(FuseKitError, match="retry settings"):
        build_hosted_worker_launch_invocation(execution, gate_retry_seconds=-1)


def test_hosted_worker_maintenance_invocation_uses_existing_cli_surfaces(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    job = build_hosted_launch_job(
        build_hosted_launch_plan(
            scan_repo(execution.source_dir),
            github_source="https://github.com/example/hosted-demo",
        ),
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(
        job,
        "start",
        now=1_700_000_001,
    )
    rollback_job = advance_hosted_launch_job(
        started,
        "rollback",
        now=1_700_000_002,
    )

    invocation = build_hosted_worker_maintenance_invocation(
        rollback_job,
        workspace=tmp_path / "worker",
    )
    payload = invocation.to_dict()
    serialized = json.dumps(payload)

    assert invocation.action == "rollback"
    assert invocation.rollback_args[:2] == ("fusekit", "rollback")
    assert "--execute" in invocation.rollback_args
    assert str(invocation.artifact_paths["setup_receipt"]) in invocation.rollback_args
    assert str(invocation.artifact_paths["vault"]) in invocation.rollback_args
    assert invocation.detonation_args[:2] == ("fusekit", "detonate")
    assert "--workspace-root" in invocation.detonation_args
    assert payload["schema_version"] == "fusekit.hosted-worker-maintenance.v1"
    assert payload["source_workspace"] == "<hosted-worker-source>"
    assert "<hosted-worker-source>/.fusekit/setup_receipt.json" in payload["rollback_args"]
    assert "<hosted-worker-source>/.fusekit/worker" in payload["detonation_args"]
    assert "FUSEKIT_PASSPHRASE" in payload["env_contract"]
    assert str(tmp_path) not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_proof_payload_stays_partial_without_artifacts(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)

    bundle = build_hosted_worker_proof_payload(invocation)
    payload = bundle.payload

    assert payload["schema_version"] == "fusekit.hosted-worker-proof.v1"
    assert payload["completed_artifacts"] == []
    assert ".fusekit/run_record.json" in bundle.missing_artifacts
    assert all(value is False for value in payload["evidence"].values())
    assert payload["note"] == (
        "Hosted worker proof is partial; required artifact labels are still missing."
    )
    assert str(tmp_path) not in json.dumps(bundle.to_dict())


def test_hosted_worker_proof_payload_requires_real_recording_ready_report(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=False)

    bundle = build_hosted_worker_proof_payload(invocation)
    evidence = bundle.payload["evidence"]

    assert bundle.missing_artifacts == ()
    assert evidence["live_url"] is True
    assert evidence["provider_verifiers"] is True
    assert evidence["dns_propagation"] is True
    assert evidence["retrieved_remote_artifacts"] is True
    assert evidence["run_record"] is True
    assert evidence["detonation_receipt"] is True
    assert evidence["live_acceptance_report"] is True
    assert evidence["recording"] is False
    assert bundle.payload["note"] == (
        "Hosted worker proof is partial; live acceptance is not recording-ready yet."
    )


def test_hosted_worker_proof_payload_requires_explicit_dns_propagation_check(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True, include_dns_check=False)

    bundle = build_hosted_worker_proof_payload(invocation)
    evidence = bundle.payload["evidence"]

    assert bundle.missing_artifacts == ()
    assert evidence["dns_propagation"] is False
    assert evidence["recording"] is True
    assert evidence["live_acceptance_report"] is True
    assert bundle.payload["note"] == (
        "Hosted worker proof is partial; DNS propagation proof is missing."
    )


def test_hosted_worker_proof_payload_rejects_blocked_public_acceptance_report(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(
        invocation,
        recording_ready=True,
        public_launch_ready=False,
        blockers=["dns_propagation"],
    )

    bundle = build_hosted_worker_proof_payload(invocation)
    evidence = bundle.payload["evidence"]

    assert bundle.missing_artifacts == ()
    assert evidence["live_acceptance_report"] is False
    assert evidence["recording"] is True
    assert bundle.payload["note"] == (
        "Hosted worker proof is partial; acceptance blockers remain."
    )


def test_hosted_worker_proof_payload_rejects_secret_text_in_acceptance_output(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    report_path = invocation.artifact_paths["acceptance_output"] / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["debug_token"] = "Bearer ghs_rawacceptancetoken123"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(FuseKitError, match="contains secret-looking text"):
        build_hosted_worker_proof_payload(invocation)


def test_hosted_worker_proof_payload_rejects_symlinked_acceptance_output(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    report_path = invocation.artifact_paths["acceptance_output"] / "report.json"
    report_path.unlink()
    report_path.symlink_to(invocation.execution.source_dir / ".fusekit/run_record.json")

    with pytest.raises(FuseKitError, match="must be a regular file"):
        build_hosted_worker_proof_payload(invocation)


def test_hosted_worker_proof_payload_rejects_symlinked_proof_parent(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    fusekit_dir = invocation.execution.source_dir / ".fusekit"
    moved_fusekit_dir = tmp_path / "moved-fusekit"
    shutil.move(str(fusekit_dir), moved_fusekit_dir)
    fusekit_dir.symlink_to(moved_fusekit_dir, target_is_directory=True)

    with pytest.raises(FuseKitError, match="must not use symlinked parents"):
        build_hosted_worker_proof_payload(invocation)


def test_hosted_worker_proof_payload_rejects_artifact_directory_placeholder(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    run_record = invocation.execution.source_dir / ".fusekit/run_record.json"
    run_record.unlink()
    run_record.mkdir()

    bundle = build_hosted_worker_proof_payload(invocation)
    evidence = bundle.payload["evidence"]

    assert ".fusekit/run_record.json" in bundle.missing_artifacts
    assert ".fusekit/run_record.json" not in bundle.completed_artifacts
    assert evidence["run_record"] is False
    assert evidence["live_acceptance_report"] is False


def test_hosted_worker_proof_payload_rejects_empty_artifact_placeholder(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    receipt = invocation.execution.source_dir / ".fusekit/setup_receipt.json"
    receipt.write_text("", encoding="utf-8")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert ".fusekit/setup_receipt.json" in bundle.missing_artifacts
    assert ".fusekit/setup_receipt.json" not in bundle.completed_artifacts
    assert bundle.payload["evidence"]["live_acceptance_report"] is False


def test_hosted_worker_proof_payload_rejects_secret_text_in_public_artifact(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    receipt = invocation.execution.source_dir / ".fusekit/setup_receipt.json"
    receipt.write_text(
        '{"status":"ok","provider_token":"Bearer ghs_rawinstallationtoken123"}\n',
        encoding="utf-8",
    )

    bundle = build_hosted_worker_proof_payload(invocation)

    assert ".fusekit/setup_receipt.json" in bundle.missing_artifacts
    assert ".fusekit/setup_receipt.json" not in bundle.completed_artifacts
    assert bundle.payload["evidence"]["live_acceptance_report"] is False


def test_hosted_worker_proof_payload_allows_empty_gate_event_stream(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    gate_events = invocation.execution.source_dir / ".fusekit/gate_events.jsonl"
    gate_events.write_text("", encoding="utf-8")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert ".fusekit/gate_events.jsonl" in bundle.completed_artifacts
    assert ".fusekit/gate_events.jsonl" not in bundle.missing_artifacts
    assert bundle.payload["evidence"]["live_acceptance_report"] is True


def test_hosted_worker_proof_payload_rejects_placeholder_rollback_metadata(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    rollback = invocation.execution.source_dir / ".fusekit/rollback_plan.json"
    rollback.write_text('{"ok":true}\n', encoding="utf-8")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert ".fusekit/rollback_plan.json" in bundle.completed_artifacts
    assert ".fusekit/rollback_plan.json" not in bundle.missing_artifacts
    assert bundle.payload["evidence"]["rollback_metadata"] is False
    assert bundle.payload["evidence"]["live_acceptance_report"] is True
    assert bundle.payload["note"] == (
        "Hosted worker proof is partial; rollback metadata has no provider rollback actions."
    )


def test_hosted_worker_proof_payload_rejects_empty_remote_artifact_bundle(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_artifacts = invocation.artifact_paths["remote_artifacts"]
    shutil.rmtree(remote_artifacts)
    remote_artifacts.mkdir()

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False
    assert bundle.payload["evidence"]["live_acceptance_report"] is True
    assert bundle.payload["note"] == (
        "Hosted worker proof is partial; retrieved remote artifact bundle is not ready."
    )


def test_hosted_worker_proof_payload_rejects_remote_artifact_file_placeholder(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_artifacts = invocation.artifact_paths["remote_artifacts"]
    shutil.rmtree(remote_artifacts)
    remote_artifacts.write_text('{"ok":true}\n', encoding="utf-8")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False


def test_hosted_worker_proof_payload_rejects_incomplete_remote_survivor_bundle(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_fusekit = invocation.artifact_paths["remote_artifacts"] / ".fusekit"
    (remote_fusekit / "setup_receipt.json").unlink()

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False


def test_hosted_worker_proof_payload_rejects_unexpected_remote_survivor(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_fusekit = invocation.artifact_paths["remote_artifacts"] / ".fusekit"
    (remote_fusekit / ".env").write_text("SECRET=value\n", encoding="utf-8")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False


def test_hosted_worker_proof_payload_rejects_secret_text_in_remote_survivor(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_fusekit = invocation.artifact_paths["remote_artifacts"] / ".fusekit"
    (remote_fusekit / "setup_receipt.json").write_text(
        '{"status":"ok","api_key":"sk-live-rawproviderkey12345"}\n',
        encoding="utf-8",
    )

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False


def test_hosted_worker_proof_payload_rejects_secret_text_in_optional_remote_survivor(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    remote_fusekit = invocation.artifact_paths["remote_artifacts"] / ".fusekit"
    (remote_fusekit / "setup_receipt.md").write_text(
        "provider token: Bearer ghs_optionalremotesurvivor123\n",
        encoding="utf-8",
    )

    bundle = build_hosted_worker_proof_payload(invocation)

    assert bundle.payload["evidence"]["retrieved_remote_artifacts"] is False


def test_hosted_worker_proof_payload_rejects_symlinked_public_artifact(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)
    receipt = invocation.execution.source_dir / ".fusekit/setup_receipt.json"
    receipt.unlink()
    receipt.symlink_to(invocation.execution.source_dir / ".fusekit/run_record.json")

    bundle = build_hosted_worker_proof_payload(invocation)

    assert ".fusekit/setup_receipt.json" in bundle.missing_artifacts
    assert ".fusekit/setup_receipt.json" not in bundle.completed_artifacts
    assert bundle.payload["evidence"]["live_acceptance_report"] is False


def test_hosted_worker_proof_payload_marks_complete_only_from_live_artifacts(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)

    bundle = build_hosted_worker_proof_payload(invocation)
    serialized = json.dumps(bundle.to_dict())

    assert bundle.missing_artifacts == ()
    assert tuple(bundle.payload["completed_artifacts"]) == execution.required_artifacts
    assert all(value is True for value in bundle.payload["evidence"].values())
    assert bundle.payload["note"] == (
        "Hosted worker produced live acceptance, remote artifacts, rollback, and detonation proof."
    )
    assert bundle.to_dict()["acceptance_report"] == {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": True,
        "remote_artifacts_ready": True,
        "recording_proof_ready": True,
        "recording_ready": True,
        "check_count": 4,
    }
    assert str(tmp_path) not in serialized
    assert "ghs_fake_installation_token" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_rollback_proof_requires_post_rollback_verification(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True, rollback_post_verified=False)

    bundle = build_hosted_worker_workspace_proof_payload(
        source_dir=invocation.execution.source_dir,
        artifact_paths=invocation.artifact_paths,
        required_artifacts=invocation.execution.required_artifacts,
        maintenance_action="rollback",
        maintenance_returncode=0,
    )
    evidence = bundle.payload["evidence"]

    assert evidence["rollback_execution_receipt"] is True
    assert evidence["post_rollback_verification"] is False


def test_hosted_worker_rollback_proof_marks_post_rollback_verification(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True, rollback_post_verified=True)

    bundle = build_hosted_worker_workspace_proof_payload(
        source_dir=invocation.execution.source_dir,
        artifact_paths=invocation.artifact_paths,
        required_artifacts=invocation.execution.required_artifacts,
        maintenance_action="rollback",
        maintenance_returncode=0,
    )
    evidence = bundle.payload["evidence"]

    assert evidence["rollback_execution_receipt"] is True
    assert evidence["post_rollback_verification"] is True


def test_hosted_worker_detonation_proof_requires_successful_maintenance(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)

    bundle = build_hosted_worker_workspace_proof_payload(
        source_dir=invocation.execution.source_dir,
        artifact_paths=invocation.artifact_paths,
        required_artifacts=invocation.execution.required_artifacts,
        maintenance_action="detonate",
        maintenance_returncode=7,
    )
    evidence = bundle.payload["evidence"]

    assert evidence["workspace_detonation_receipt"] is False
    assert evidence["scratch_state_destroyed"] is False
    assert evidence["provider_auth_session_closed"] is False
    assert evidence["redacted_public_proof_preserved"] is False


def test_hosted_worker_detonation_proof_marks_preserved_public_proof(
    tmp_path: Path,
) -> None:
    execution = _prepared_execution(tmp_path)
    invocation = build_hosted_worker_launch_invocation(execution)
    _write_required_artifacts(invocation)
    _write_acceptance_report(invocation, recording_ready=True)

    bundle = build_hosted_worker_workspace_proof_payload(
        source_dir=invocation.execution.source_dir,
        artifact_paths=invocation.artifact_paths,
        required_artifacts=invocation.execution.required_artifacts,
        maintenance_action="detonate",
        maintenance_returncode=0,
    )
    evidence = bundle.payload["evidence"]

    assert evidence["workspace_detonation_receipt"] is True
    assert evidence["scratch_state_destroyed"] is True
    assert evidence["provider_auth_session_closed"] is True
    assert evidence["redacted_public_proof_preserved"] is True


def test_prepare_hosted_worker_execution_requires_claimed_job(tmp_path: Path) -> None:
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = build_hosted_launch_job(
        plan,
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )

    with pytest.raises(FuseKitError, match="requires a claimed job"):
        prepare_hosted_worker_execution(
            job,
            github_config=_github_config(),
            workspace=tmp_path / "worker",
            opener=SequenceOpener([]),
        )


def test_prepare_hosted_worker_execution_requires_installation_id(tmp_path: Path) -> None:
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = claim_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(plan, job_id="hosted-test", now=1_700_000_000),
            "start",
        ),
        worker_id="worker-01",
    )

    with pytest.raises(FuseKitError, match="requires a GitHub installation id"):
        prepare_hosted_worker_execution(
            job,
            github_config=_github_config(),
            workspace=tmp_path / "worker",
            opener=SequenceOpener([]),
        )


def test_prepare_hosted_worker_execution_rejects_broad_github_token(tmp_path: Path) -> None:
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = claim_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(
                plan,
                github_installation_id=42,
                job_id="hosted-test",
                now=1_700_000_000,
            ),
            "start",
        ),
        worker_id="worker-01",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T06:00:00Z",
                "permissions": {"contents": "read", "secrets": "write"},
                "repository_selection": "selected",
            },
        ]
    )

    with pytest.raises(FuseKitError, match="unsupported permissions"):
        prepare_hosted_worker_execution(
            job,
            github_config=_github_config(),
            workspace=tmp_path / "worker",
            opener=opener,
        )
    assert len(opener.requests) == 1


def test_prepare_hosted_worker_execution_rejects_plan_drift(tmp_path: Path) -> None:
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = claim_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(
                plan,
                github_installation_id=42,
                job_id="hosted-test",
                now=1_700_000_000,
            ),
            "start",
        ),
        worker_id="worker-01",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T06:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"default_branch": "main"},
            _github_zip(dependency='"@supabase/supabase-js": "latest"'),
        ]
    )

    with pytest.raises(FuseKitError, match="plan changed after approval"):
        prepare_hosted_worker_execution(
            job,
            github_config=_github_config(),
            workspace=tmp_path / "worker",
            opener=opener,
        )


def _prepared_execution(tmp_path: Path):
    source = tmp_path / "approved"
    _write_demo_app(source, dependency='"resend": "latest"')
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = claim_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(
                plan,
                github_installation_id=42,
                job_id="hosted-test",
                now=1_700_000_000,
            ),
            "start",
        ),
        worker_id="worker-01",
    )
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T06:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"default_branch": "main"},
            _github_zip(dependency='"resend": "latest"'),
        ]
    )
    return prepare_hosted_worker_execution(
        job,
        github_config=_github_config(),
        workspace=tmp_path / "worker",
        opener=opener,
    )


def _write_required_artifacts(invocation) -> None:
    for label in invocation.execution.required_artifacts:
        path = invocation.execution.source_dir / label
        path.parent.mkdir(parents=True, exist_ok=True)
        if label.endswith("/remote-artifacts"):
            path.mkdir(exist_ok=True)
        elif label.endswith(".jsonl"):
            path.write_text('{"event":"redacted"}\n', encoding="utf-8")
        elif label.endswith("rollback_plan.json"):
            path.write_text(
                json.dumps(
                    {
                        "rollback": [
                            {
                                "action": "rollback.cloudflare.dns",
                                "status": "planned",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
        else:
            path.write_text('{"ok":true}\n', encoding="utf-8")


def _write_acceptance_report(
    invocation,
    *,
    recording_ready: bool,
    rollback_post_verified: bool = False,
    include_dns_check: bool = True,
    public_launch_ready: bool = True,
    blockers: list[str] | None = None,
) -> None:
    invocation.artifact_paths["remote_artifacts"].mkdir(parents=True, exist_ok=True)
    report = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": public_launch_ready,
        "remote_artifacts_ready": True,
        "recording_proof_ready": recording_ready,
        "recording_ready": recording_ready,
        "checks": [
            {"id": "receipt.live_url", "status": "ok", "detail": "redacted"},
            {"id": "verification_report.safe", "status": "ok", "detail": "redacted"},
            {"id": "verification_report.coverage", "status": "ok", "detail": "redacted"},
        ],
        "missing": [],
        "blockers": blockers or [],
    }
    if include_dns_check:
        report["checks"].append(
            {"id": "cloudflare.dns_propagation", "status": "ok", "detail": "redacted"}
        )
    if rollback_post_verified:
        report["checks"].append(
            {"id": "rollback.post_verification", "status": "ok", "detail": "redacted"}
        )
    _write_remote_survivors(invocation.artifact_paths["remote_artifacts"])
    output = invocation.artifact_paths["acceptance_output"]
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report), encoding="utf-8")
    acceptance_label = invocation.execution.source_dir / ".fusekit/acceptance_report.json"
    acceptance_label.write_text(json.dumps(report), encoding="utf-8")


def _write_remote_survivors(remote_artifacts: Path) -> None:
    remote_fusekit = remote_artifacts / ".fusekit"
    remote_fusekit.mkdir(parents=True, exist_ok=True)
    for filename in REMOTE_REQUIRED_SURVIVOR_FILES:
        path = remote_fusekit / filename
        if filename == "gate_events.jsonl":
            path.write_text("", encoding="utf-8")
        elif filename.endswith(".jsonl"):
            path.write_text('{"event":"redacted"}\n', encoding="utf-8")
        else:
            path.write_text('{"ok":true}\n', encoding="utf-8")


def _write_demo_app(path: Path, *, dependency: str) -> None:
    path.mkdir(parents=True)
    (path / "package.json").write_text(
        '{"name": "hosted-demo", "dependencies": {' + dependency + "}}",
        encoding="utf-8",
    )
    src = path / "src"
    src.mkdir()
    (src / "mail.ts").write_text(
        "const key = process.env.RESEND_API_KEY; const hook = process.env.WEBHOOK_SECRET;",
        encoding="utf-8",
    )


def _github_zip(*, dependency: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "demo-main/package.json",
            '{"name": "hosted-demo", "dependencies": {' + dependency + "}}",
        )
        archive.writestr(
            "demo-main/src/mail.ts",
            "const key = process.env.RESEND_API_KEY; const hook = process.env.WEBHOOK_SECRET;",
        )
    return buffer.getvalue()


def _github_config() -> GitHubAppConfig:
    return GitHubAppConfig(
        app_id="12345",
        app_slug="fusekit-launcher",
        private_key_pem=_private_key_pem(),
    )


def _private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
