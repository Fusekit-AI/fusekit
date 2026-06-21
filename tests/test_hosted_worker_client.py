from __future__ import annotations

import io
import json
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
    hosted_worker_claim_receipt,
    hosted_worker_request,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.hosted.worker_client import run_hosted_worker_once
from fusekit.scanner import scan_repo

WORKER_SECRET = "hosted-worker-secret"


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

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        assert timeout in {30.0, 90.0}
        return FakeResponse(self.payloads.pop(0))


class FakeHostedApi:
    def __init__(self, claim: dict[str, object]) -> None:
        self.claim = claim
        self.calls: list[tuple[str, dict[str, str], dict[str, object] | None]] = []

    def __call__(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, object] | None,
    ) -> dict[str, Any]:
        self.calls.append((url, dict(headers), payload))
        assert headers["Authorization"] == f"Bearer {WORKER_SECRET}"
        if url.endswith("/worker-claims?job=initial-job-token"):
            return dict(self.claim)
        assert "/worker-proof?job=claimed-job-token" in url
        return {
            "proof_receipt": {
                "schema_version": "fusekit.hosted-worker-proof-receipt.v1",
                "completion_ready": bool(
                    payload
                    and isinstance(payload.get("evidence"), dict)
                    and all(payload["evidence"].values())
                ),
            }
        }


class FakeHostedGet:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> dict[str, Any]:
        self.calls.append((url, dict(headers)))
        assert headers["Authorization"] == f"Bearer {WORKER_SECRET}"
        return dict(self.payload)


class FakeMaintenanceApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], dict[str, object] | None]] = []

    def __call__(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, object] | None,
    ) -> dict[str, Any]:
        self.calls.append((url, dict(headers), payload))
        assert "/worker-proof?job=maintenance-job-token" in url
        assert headers["Authorization"] == f"Bearer {WORKER_SECRET}"
        return {
            "proof_receipt": {
                "schema_version": "fusekit.hosted-worker-proof-receipt.v1",
                "completion_ready": bool(
                    payload
                    and isinstance(payload.get("evidence"), dict)
                    and payload["evidence"].get("detonation_receipt") is True
                ),
            }
        }


def test_run_hosted_worker_once_claims_runs_and_submits_redacted_proof(
    tmp_path: Path,
) -> None:
    claim = _claim_payload(tmp_path)
    api = FakeHostedApi(claim)
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T07:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    command_calls: list[tuple[str, ...]] = []

    def run_command(args: tuple[str, ...]) -> int:
        command_calls.append(args)
        if args[:2] == ("fusekit", "launch"):
            source = Path(args[2])
            _write_required_artifacts(source)
        if args[:3] == ("fusekit", "acceptance", "run"):
            source = Path(args[3])
            _write_acceptance_report(source, recording_ready=True)
        return 0

    result = run_hosted_worker_once(
        origin="https://fusekit.snowmanai.org",
        job_id="hosted-test",
        job_token="initial-job-token",
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        github_config=_github_config(),
        workspace=tmp_path / "worker",
        post_json=api,
        command_runner=run_command,
        opener=opener,
    )
    serialized = json.dumps(result.to_dict())

    assert result.launch_returncode == 0
    assert result.acceptance_returncode == 0
    assert len(command_calls) == 2
    assert api.calls[0][0] == (
        "https://fusekit.snowmanai.org/api/hosted/jobs/hosted-test/"
        "worker-claims?job=initial-job-token"
    )
    assert "/worker-proof?job=claimed-job-token" in api.calls[1][0]
    assert api.calls[1][2]["schema_version"] == "fusekit.hosted-worker-proof.v1"
    assert all(api.calls[1][2]["evidence"].values())
    assert result.to_dict()["proof_receipt"]["completion_ready"] is True
    assert str(tmp_path) not in serialized
    assert WORKER_SECRET not in serialized
    assert "ghs_fake_installation_token" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_run_hosted_worker_once_submits_partial_proof_when_launch_fails(
    tmp_path: Path,
) -> None:
    claim = _claim_payload(tmp_path)
    api = FakeHostedApi(claim)
    opener = SequenceOpener(
        [
            {
                "token": "ghs_fake_installation_token",
                "expires_at": "2026-06-21T07:00:00Z",
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
            },
            {"default_branch": "main"},
            _github_zip(),
        ]
    )
    command_calls: list[tuple[str, ...]] = []

    def fail_launch(args: tuple[str, ...]) -> int:
        command_calls.append(args)
        return 7

    result = run_hosted_worker_once(
        origin="https://fusekit.snowmanai.org",
        job_id="hosted-test",
        job_token="initial-job-token",
        worker_secret=WORKER_SECRET,
        github_config=_github_config(),
        workspace=tmp_path / "worker",
        post_json=api,
        command_runner=fail_launch,
        opener=opener,
    )
    proof = api.calls[1][2]

    assert result.launch_returncode == 7
    assert result.acceptance_returncode is None
    assert len(command_calls) == 1
    assert proof["schema_version"] == "fusekit.hosted-worker-proof.v1"
    assert all(value is False for value in proof["evidence"].values())
    assert proof["completed_artifacts"] == []
    assert result.to_dict()["proof_receipt"]["completion_ready"] is False


def test_run_hosted_worker_once_handles_detonation_request_from_signed_job(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker/hosted-test/source"
    _write_demo_app(source)
    _write_required_artifacts(source)
    _write_acceptance_report(source, recording_ready=True)
    plan = build_hosted_launch_plan(
        scan_repo(source),
        github_source="https://github.com/example/hosted-demo",
    )
    job = advance_hosted_launch_job(
        advance_hosted_launch_job(
            build_hosted_launch_job(
                plan,
                github_installation_id=42,
                job_id="hosted-test",
                now=1_700_000_000,
            ),
            "start",
        ),
        "detonate",
    )
    get = FakeHostedGet(job.to_dict())
    api = FakeMaintenanceApi()
    command_calls: list[tuple[str, ...]] = []

    def run_command(args: tuple[str, ...]) -> int:
        command_calls.append(args)
        return 0

    result = run_hosted_worker_once(
        origin="https://fusekit.snowmanai.org",
        job_id="hosted-test",
        job_token="maintenance-job-token",
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        action="detonate",
        github_config=_github_config(),
        workspace=tmp_path / "worker",
        get_json=get,
        post_json=api,
        command_runner=run_command,
    )
    serialized = json.dumps(result.to_dict())

    assert get.calls[0][0] == (
        "https://fusekit.snowmanai.org/api/hosted/jobs/hosted-test?"
        "job=maintenance-job-token"
    )
    assert result.action == "detonate"
    assert result.detonation_returncode == 0
    assert command_calls == [result.maintenance_invocation.detonation_args]
    assert command_calls[0][:2] == ("fusekit", "detonate")
    assert api.calls[0][2]["schema_version"] == "fusekit.hosted-worker-proof.v1"
    assert api.calls[0][2]["evidence"]["detonation_receipt"] is True
    assert result.to_dict()["proof_receipt"]["completion_ready"] is True
    assert str(tmp_path) not in serialized
    assert WORKER_SECRET not in serialized
    assert "maintenance-job-token" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_run_hosted_worker_once_rejects_missing_inputs(tmp_path: Path) -> None:
    with pytest.raises(FuseKitError, match="https URL"):
        run_hosted_worker_once(
            origin="http://fusekit.snowmanai.org",
            job_id="hosted-test",
            job_token="job-token",
            worker_secret=WORKER_SECRET,
            github_config=_github_config(),
            workspace=tmp_path,
        )


def _claim_payload(tmp_path: Path) -> dict[str, object]:
    source = tmp_path / "approved"
    _write_demo_app(source)
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
    return {
        "job": job.to_dict(),
        "job_token": "claimed-job-token",
        "worker_request": hosted_worker_request(job),
        "claim_receipt": hosted_worker_claim_receipt(job, worker_id="worker-01"),
    }


def _write_required_artifacts(source: Path) -> None:
    required = (
        ".fusekit/job.json",
        ".fusekit/run_record.json",
        ".fusekit/verification_report.json",
        ".fusekit/rollback_plan.json",
        ".fusekit/setup_receipt.json",
        ".fusekit/audit.jsonl",
        ".fusekit/provider_strategies.json",
        ".fusekit/runner_readiness.json",
        ".fusekit/gates.json",
        ".fusekit/gate_events.jsonl",
        ".fusekit/llm_contract.json",
        ".fusekit/workspace_detonation.json",
        ".fusekit/acceptance_report.json",
    )
    for label in required:
        path = source / label
        path.parent.mkdir(parents=True, exist_ok=True)
        if label.endswith(".jsonl"):
            path.write_text('{"event":"redacted"}\n', encoding="utf-8")
        else:
            path.write_text('{"ok":true}\n', encoding="utf-8")


def _write_acceptance_report(source: Path, *, recording_ready: bool) -> None:
    report = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": True,
        "remote_artifacts_ready": True,
        "recording_proof_ready": recording_ready,
        "recording_ready": recording_ready,
        "checks": [
            {"id": "receipt.live_url", "status": "ok", "detail": "redacted"},
            {"id": "verification_report.safe", "status": "ok", "detail": "redacted"},
            {"id": "verification_report.coverage", "status": "ok", "detail": "redacted"},
            {"id": "cloudflare.dns_propagation", "status": "ok", "detail": "redacted"},
        ],
        "missing": [],
        "blockers": [],
    }
    remote = source / ".fusekit/remote-artifacts/.fusekit"
    remote.mkdir(parents=True, exist_ok=True)
    (remote / "run_record.json").write_text('{"ok":true}\n', encoding="utf-8")
    output = source / ".fusekit/acceptance"
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (source / ".fusekit/acceptance_report.json").write_text(
        json.dumps(report),
        encoding="utf-8",
    )


def _write_demo_app(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "package.json").write_text(
        json.dumps({"name": "hosted-demo", "dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    src = path / "src"
    src.mkdir()
    (src / "mail.ts").write_text(
        "const key = process.env.RESEND_API_KEY; const hook = process.env.WEBHOOK_SECRET;",
        encoding="utf-8",
    )


def _github_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "demo-main/package.json",
            json.dumps({"name": "hosted-demo", "dependencies": {"resend": "latest"}}),
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
