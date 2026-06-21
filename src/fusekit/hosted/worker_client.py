"""Hosted worker client for claiming, running, and proving launch jobs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import GitHubAppConfig, UrlOpener
from fusekit.hosted.job import hosted_launch_job_from_dict
from fusekit.hosted.worker import (
    HostedWorkerLaunchInvocation,
    build_hosted_worker_launch_invocation,
    build_hosted_worker_proof_payload,
    prepare_hosted_worker_execution,
)

JsonPost = Callable[[str, Mapping[str, str], dict[str, object] | None], dict[str, Any]]
CommandRunner = Callable[[tuple[str, ...]], int]


@dataclass(frozen=True)
class HostedWorkerRunResult:
    """Redacted hosted worker run result."""

    job_id: str
    launch_returncode: int
    acceptance_returncode: int | None
    invocation: HostedWorkerLaunchInvocation
    proof_payload: dict[str, object]
    proof_response: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        """Serialize without worker secrets, provider credentials, or local paths."""

        proof_receipt = self.proof_response.get("proof_receipt", {})
        return {
            "job_id": self.job_id,
            "launch_returncode": self.launch_returncode,
            "acceptance_returncode": self.acceptance_returncode,
            "invocation": self.invocation.to_dict(),
            "proof_payload": self.proof_payload,
            "proof_receipt": proof_receipt if isinstance(proof_receipt, dict) else {},
        }


def run_hosted_worker_once(
    *,
    origin: str,
    job_id: str,
    job_token: str,
    worker_secret: str,
    github_config: GitHubAppConfig,
    workspace: Path,
    worker_id: str = "hosted-worker",
    post_json: JsonPost | None = None,
    command_runner: CommandRunner | None = None,
    opener: UrlOpener | None = None,
) -> HostedWorkerRunResult:
    """Claim one hosted job, run local worker commands, and submit redacted proof."""

    _require_inputs(origin=origin, job_id=job_id, job_token=job_token, worker_secret=worker_secret)
    post = post_json or _post_json
    run_command = command_runner or _run_command
    headers = _worker_headers(worker_secret=worker_secret, worker_id=worker_id)
    claim = post(_job_url(origin, job_id, "worker-claims", job_token), headers, None)
    job_payload = claim.get("job")
    if not isinstance(job_payload, dict):
        raise FuseKitError("Hosted worker claim response did not include a job.")
    claimed_job = hosted_launch_job_from_dict(job_payload)
    claimed_token = str(claim.get("job_token") or job_token)
    execution = prepare_hosted_worker_execution(
        claimed_job,
        github_config=github_config,
        workspace=workspace,
        opener=opener,
    )
    invocation = build_hosted_worker_launch_invocation(execution)
    launch_returncode = run_command(invocation.launch_args)
    acceptance_returncode: int | None = None
    if launch_returncode == 0:
        acceptance_returncode = run_command(invocation.acceptance_args)
    proof_bundle = build_hosted_worker_proof_payload(invocation)
    proof_response = post(
        _job_url(origin, job_id, "worker-proof", claimed_token),
        headers,
        proof_bundle.payload,
    )
    return HostedWorkerRunResult(
        job_id=job_id,
        launch_returncode=launch_returncode,
        acceptance_returncode=acceptance_returncode,
        invocation=invocation,
        proof_payload=proof_bundle.payload,
        proof_response=proof_response,
    )


def main(argv: list[str] | None = None) -> int:
    """Run one hosted worker job from environment-backed configuration."""

    args = _parser().parse_args(argv)
    workspace = args.workspace or Path(tempfile.mkdtemp(prefix="fusekit-hosted-worker-"))
    result = run_hosted_worker_once(
        origin=args.origin or os.environ.get("FUSEKIT_HOSTED_ORIGIN", ""),
        job_id=args.job_id or os.environ.get("FUSEKIT_HOSTED_JOB_ID", ""),
        job_token=args.job_token or os.environ.get("FUSEKIT_HOSTED_JOB_TOKEN", ""),
        worker_secret=args.worker_secret or os.environ.get("FUSEKIT_HOSTED_WORKER_SECRET", ""),
        github_config=GitHubAppConfig(
            app_id=os.environ.get("FUSEKIT_GITHUB_APP_ID", ""),
            app_slug=os.environ.get("FUSEKIT_GITHUB_APP_SLUG", "fusekit-launcher"),
            private_key_pem=os.environ.get("FUSEKIT_GITHUB_APP_PRIVATE_KEY", ""),
        ),
        workspace=workspace,
        worker_id=args.worker_id,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.acceptance_returncode == 0 else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one hosted FuseKit worker job")
    parser.add_argument("--origin", default="")
    parser.add_argument("--job-id", default="")
    parser.add_argument("--job-token", default="")
    parser.add_argument("--worker-secret", default="")
    parser.add_argument("--worker-id", default="hosted-worker")
    parser.add_argument("--workspace", type=Path, default=None)
    return parser


def _require_inputs(
    *,
    origin: str,
    job_id: str,
    job_token: str,
    worker_secret: str,
) -> None:
    if not origin.startswith("https://"):
        raise FuseKitError("Hosted worker origin must be an https URL.")
    if not job_id.startswith("hosted-"):
        raise FuseKitError("Hosted worker job id is required.")
    if not job_token:
        raise FuseKitError("Hosted worker job token is required.")
    if len(worker_secret) < 16:
        raise FuseKitError("Hosted worker secret is required.")


def _job_url(origin: str, job_id: str, action: str, job_token: str) -> str:
    base = origin.rstrip("/")
    quoted_job = urllib.parse.quote(job_id, safe="")
    query = urllib.parse.urlencode({"job": job_token})
    return f"{base}/api/hosted/jobs/{quoted_job}/{action}?{query}"


def _worker_headers(*, worker_secret: str, worker_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {worker_secret}",
        "Content-Type": "application/json",
        "X-FuseKit-Worker-Id": worker_id,
    }


def _post_json(
    url: str,
    headers: Mapping[str, str],
    payload: dict[str, object] | None,
) -> dict[str, Any]:
    data = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers=dict(headers),
    )
    with urllib.request.urlopen(request, timeout=90.0) as response:
        status = int(getattr(response, "status", 200))
        body = response.read()
    if status >= 400:
        raise FuseKitError(f"Hosted worker API returned HTTP {status}.")
    raw = json.loads(body.decode("utf-8"))
    if not isinstance(raw, dict):
        raise FuseKitError("Hosted worker API response must be a JSON object.")
    return raw


def _run_command(args: tuple[str, ...]) -> int:
    completed = subprocess.run(args, check=False)
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
