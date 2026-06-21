"""Backend-only hosted worker preparation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import GitHubAppConfig, UrlOpener, exchange_installation_token
from fusekit.hosted.job import (
    HostedLaunchJob,
    HostedWorkerContract,
    build_hosted_worker_contract,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.scanner import scan_repo
from fusekit.source import (
    SourceFetchResult,
    fetch_github_source_archive,
)
from fusekit.source import (
    UrlOpener as SourceUrlOpener,
)

HOSTED_WORKER_EXECUTION_SCHEMA_VERSION = "fusekit.hosted-worker-execution.v1"


@dataclass(frozen=True)
class HostedWorkerExecutionPlan:
    """Redacted backend execution plan after source is prepared."""

    job_id: str
    app_name: str
    github_source: str
    github_installation_id: int
    source_dir: Path
    source_result: SourceFetchResult
    providers: tuple[str, ...]
    required_env: tuple[str, ...]
    approved_actions: tuple[str, ...]
    required_artifacts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize without tokens, private keys, or host filesystem paths."""

        return {
            "schema_version": HOSTED_WORKER_EXECUTION_SCHEMA_VERSION,
            "job_id": self.job_id,
            "app_name": self.app_name,
            "github_source": self.github_source,
            "github_installation_id": self.github_installation_id,
            "source": {
                "provider": self.source_result.provider,
                "repo": self.source_result.repo,
                "default_branch": self.source_result.default_branch,
                "auth_source": self.source_result.auth_source,
                "private": self.source_result.private,
                "workspace_label": "hosted-worker-source",
            },
            "source_token_policy": (
                "GitHub App installation token was exchanged inside the backend worker. "
                "It is not included in this plan, public job tokens, receipts, or proof."
            ),
            "providers": list(self.providers),
            "required_env": list(self.required_env),
            "approved_actions": list(self.approved_actions),
            "required_artifacts": list(self.required_artifacts),
            "acceptance_gate": {
                "mode": "live",
                "remote_artifacts": ".fusekit/remote-artifacts",
                "require_recording": True,
                "command": (
                    "fusekit acceptance run <app> --mode live "
                    "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
                ),
            },
            "secret_boundary": (
                "Only the backend worker may hold the installation token and provider "
                "credentials. Browser pages and public proof receive redacted metadata only."
            ),
        }


def prepare_hosted_worker_execution(
    job: HostedLaunchJob,
    *,
    github_config: GitHubAppConfig,
    workspace: Path,
    opener: UrlOpener | None = None,
) -> HostedWorkerExecutionPlan:
    """Fetch and re-scan approved source for a claimed hosted worker job."""

    if job.status != "worker_claimed":
        raise FuseKitError("Hosted worker execution requires a claimed job.")
    installation_id = job.worker_contract.github_installation_id
    if installation_id is None or installation_id <= 0:
        raise FuseKitError("Hosted worker execution requires a GitHub installation id.")
    token = exchange_installation_token(
        github_config,
        installation_id=installation_id,
        permissions={"contents": "read"},
        opener=opener,
    )
    source_dir = workspace / job.job_id / "source"
    source_result = fetch_github_source_archive(
        job.github_source,
        source_dir,
        token=token.token,
        opener=cast(SourceUrlOpener | None, opener),
    )
    manifest = scan_repo(source_result.dest)
    refreshed_plan = build_hosted_launch_plan(manifest, github_source=job.github_source)
    refreshed_contract = build_hosted_worker_contract(
        refreshed_plan,
        github_installation_id=installation_id,
    )
    _require_approved_contract(job, refreshed_contract)
    return HostedWorkerExecutionPlan(
        job_id=job.job_id,
        app_name=job.app_name,
        github_source=job.github_source,
        github_installation_id=installation_id,
        source_dir=source_result.dest,
        source_result=source_result,
        providers=job.worker_contract.providers,
        required_env=job.worker_contract.required_env,
        approved_actions=job.worker_contract.approved_actions,
        required_artifacts=job.worker_contract.required_artifacts,
    )


def _require_approved_contract(
    job: HostedLaunchJob,
    refreshed_contract: HostedWorkerContract,
) -> None:
    expected = job.worker_contract
    if (
        job.github_source != refreshed_contract.github_source
        or expected.providers != refreshed_contract.providers
        or expected.required_env != refreshed_contract.required_env
        or expected.approved_actions != refreshed_contract.approved_actions
        or expected.required_artifacts != refreshed_contract.required_artifacts
        or expected.gates != refreshed_contract.gates
        or expected.guarantees != refreshed_contract.guarantees
    ):
        raise FuseKitError("Hosted source plan changed after approval; restart hosted launch.")
