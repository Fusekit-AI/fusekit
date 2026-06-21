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
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.hosted.worker import (
    build_hosted_worker_launch_invocation,
    prepare_hosted_worker_execution,
)
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
