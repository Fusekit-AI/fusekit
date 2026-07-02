"""Backend-only hosted worker preparation helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import (
    GitHubAppConfig,
    UrlOpener,
    exchange_installation_token,
    require_hosted_installation_token_boundary,
)
from fusekit.hosted.job import (
    HOSTED_WORKER_PROOF_KEYS,
    HOSTED_WORKER_PROOF_SCHEMA_VERSION,
    HostedLaunchJob,
    HostedWorkerContract,
    build_hosted_worker_contract,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.runner.remote_survivors import (
    REMOTE_ALLOWED_SURVIVOR_FILE_SET,
    REMOTE_REQUIRED_SURVIVOR_FILES,
)
from fusekit.scanner import scan_repo
from fusekit.security.redaction import contains_durable_secret_text
from fusekit.source import (
    SourceFetchResult,
    fetch_github_source_archive,
)
from fusekit.source import (
    UrlOpener as SourceUrlOpener,
)

HOSTED_WORKER_EXECUTION_SCHEMA_VERSION = "fusekit.hosted-worker-execution.v1"
HOSTED_WORKER_INVOCATION_SCHEMA_VERSION = "fusekit.hosted-worker-invocation.v1"
HOSTED_WORKER_MAINTENANCE_SCHEMA_VERSION = "fusekit.hosted-worker-maintenance.v1"

HOSTED_WORKER_ARTIFACTS = {
    "job_state": ".fusekit/job.json",
    "vault": ".fusekit/fusekit.vault.json",
    "audit_log": ".fusekit/audit.jsonl",
    "setup_plan": ".fusekit/setup_plan.json",
    "setup_receipt": ".fusekit/setup_receipt.json",
    "setup_receipt_markdown": ".fusekit/setup_receipt.md",
    "verification_report": ".fusekit/verification_report.json",
    "rollback_plan": ".fusekit/rollback_plan.json",
    "remote_artifacts": ".fusekit/remote-artifacts",
    "acceptance_output": ".fusekit/acceptance",
}
PUBLIC_PROOF_ARTIFACT_MAX_BYTES = 1_000_000
ENCRYPTED_VAULT_ARTIFACT_LABELS = {
    ".fusekit/fusekit.vault.json",
    "fusekit.vault.json",
}


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


@dataclass(frozen=True)
class HostedWorkerLaunchInvocation:
    """Private worker commands plus public-safe labels for hosted execution."""

    execution: HostedWorkerExecutionPlan
    artifact_paths: Mapping[str, Path]
    launch_args: tuple[str, ...]
    acceptance_args: tuple[str, ...]
    env_contract: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the invocation without host paths or secret values."""

        return {
            "schema_version": HOSTED_WORKER_INVOCATION_SCHEMA_VERSION,
            "job_id": self.execution.job_id,
            "app_name": self.execution.app_name,
            "github_source": self.execution.github_source,
            "source_workspace": "<hosted-worker-source>",
            "artifact_labels": dict(HOSTED_WORKER_ARTIFACTS),
            "launch_args": _redacted_args(self.launch_args, self.execution.source_dir),
            "acceptance_args": _redacted_args(
                self.acceptance_args,
                self.execution.source_dir,
            ),
            "env_contract": list(self.env_contract),
            "secret_boundary": (
                "The real argv contains worker-local paths and reads passphrases/provider "
                "credentials from the backend worker environment or vault only. Public "
                "serialization redacts paths and never includes secret values."
            ),
            "completion_gate": {
                "worker_proof_endpoint": "/api/hosted/jobs/<job>/worker-proof",
                "proof_schema_version": "fusekit.hosted-worker-proof.v1",
                "requires_live_acceptance": True,
                "requires_recording": True,
            },
        }


@dataclass(frozen=True)
class HostedWorkerMaintenanceInvocation:
    """Private rollback/detonation commands for an existing hosted worker workspace."""

    job: HostedLaunchJob
    action: str
    source_dir: Path
    artifact_paths: Mapping[str, Path]
    rollback_args: tuple[str, ...]
    detonation_args: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize maintenance commands without worker-local paths or secret values."""

        return {
            "schema_version": HOSTED_WORKER_MAINTENANCE_SCHEMA_VERSION,
            "job_id": self.job.job_id,
            "action": self.action,
            "status": self.job.status,
            "source_workspace": "<hosted-worker-source>",
            "artifact_labels": dict(HOSTED_WORKER_ARTIFACTS),
            "rollback_args": _redacted_args(self.rollback_args, self.source_dir),
            "detonation_args": _redacted_args(self.detonation_args, self.source_dir),
            "env_contract": [
                "FUSEKIT_PASSPHRASE",
                "provider credentials remain inside the encrypted FuseKit vault",
            ],
            "secret_boundary": (
                "The real argv uses worker-local paths and reads passphrases/provider "
                "credentials from the backend worker environment or vault only. Public "
                "serialization redacts paths and never includes secret values."
            ),
        }


@dataclass(frozen=True)
class HostedWorkerProofBundle:
    """Redacted proof payload derived from worker artifacts."""

    payload: dict[str, object]
    acceptance_report: dict[str, Any]
    completed_artifacts: tuple[str, ...]
    missing_artifacts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the proof bundle without local worker paths."""

        return {
            "payload": self.payload,
            "acceptance_report": _redacted_acceptance_summary(self.acceptance_report),
            "completed_artifacts": list(self.completed_artifacts),
            "missing_artifacts": list(self.missing_artifacts),
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
    require_hosted_installation_token_boundary(token)
    source_dir = (workspace / job.job_id / "source").resolve()
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


def build_hosted_worker_proof_payload(
    invocation: HostedWorkerLaunchInvocation,
) -> HostedWorkerProofBundle:
    """Build the worker-proof payload from real hosted worker artifacts."""

    return build_hosted_worker_workspace_proof_payload(
        source_dir=invocation.execution.source_dir,
        artifact_paths=invocation.artifact_paths,
        required_artifacts=invocation.execution.required_artifacts,
    )


def build_hosted_worker_workspace_proof_payload(
    *,
    source_dir: Path,
    artifact_paths: Mapping[str, Path],
    required_artifacts: tuple[str, ...],
    maintenance_action: str = "",
    maintenance_returncode: int | None = None,
) -> HostedWorkerProofBundle:
    """Build worker proof from an existing hosted worker workspace."""

    report_path = artifact_paths["acceptance_output"] / "report.json"
    acceptance = _read_acceptance_report(report_path)
    completed, missing = _artifact_completion(
        source_dir=source_dir,
        required_artifacts=required_artifacts,
    )
    checks = _check_statuses(acceptance)
    evidence = {
        "live_url": checks.get("receipt.live_url") == "ok",
        "provider_verifiers": checks.get("verification_report.coverage") == "ok"
        and checks.get("verification_report.safe") == "ok",
        "dns_propagation": _dns_evidence_ready(checks),
        "rollback_metadata": _rollback_metadata_ready(
            invocation_source_dir=source_dir,
            completed_artifacts=completed,
        ),
        "retrieved_remote_artifacts": acceptance.get("remote_artifacts_ready") is True
        and _remote_artifacts_bundle_present(artifact_paths["remote_artifacts"]),
        "run_record": ".fusekit/run_record.json" in completed,
        "detonation_receipt": ".fusekit/workspace_detonation.json" in completed,
        "live_acceptance_report": _live_acceptance_report_ready(
            acceptance=acceptance,
            report_path=report_path,
            missing_artifacts=missing,
        ),
        "recording": acceptance.get("recording_ready") is True,
    }
    if maintenance_action == "rollback":
        evidence["rollback_execution_receipt"] = (
            maintenance_returncode == 0 and evidence["rollback_metadata"] is True
        )
        evidence["post_rollback_verification"] = checks.get("rollback.post_verification") == "ok"
    if maintenance_action == "detonate":
        detonation_verified = maintenance_returncode == 0 and evidence["detonation_receipt"] is True
        evidence["workspace_detonation_receipt"] = detonation_verified
        evidence["scratch_state_destroyed"] = detonation_verified
        evidence["provider_auth_session_closed"] = detonation_verified
        evidence["redacted_public_proof_preserved"] = detonation_verified and (
            evidence["run_record"] is True
            and evidence["retrieved_remote_artifacts"] is True
            and evidence["live_acceptance_report"] is True
        )
    payload: dict[str, object] = {
        "schema_version": HOSTED_WORKER_PROOF_SCHEMA_VERSION,
        "evidence": evidence,
        "completed_artifacts": list(completed),
        "note": _proof_note(evidence, missing, acceptance),
    }
    return HostedWorkerProofBundle(
        payload=payload,
        acceptance_report=acceptance,
        completed_artifacts=completed,
        missing_artifacts=missing,
    )


def build_hosted_worker_launch_invocation(
    execution: HostedWorkerExecutionPlan,
    *,
    verify_attempts: int = 10,
    verify_retry_seconds: float = 30.0,
    gate_retry_seconds: float = 300.0,
    gate_max_attempts: int = 0,
) -> HostedWorkerLaunchInvocation:
    """Build private launch and live-acceptance commands for the hosted worker."""

    if verify_attempts <= 0:
        raise FuseKitError("Hosted worker verify attempts must be positive.")
    if verify_retry_seconds < 0 or gate_retry_seconds < 0 or gate_max_attempts < 0:
        raise FuseKitError("Hosted worker retry settings must be non-negative.")
    source_dir = execution.source_dir.resolve()
    artifacts = _artifact_paths(source_dir)
    launch_args = (
        "fusekit",
        "launch",
        str(source_dir),
        "--runner",
        "local",
        "--yes",
        "--control-room",
        "--no-open-launcher",
        "--app-source",
        execution.github_source,
        "--job-state",
        str(artifacts["job_state"]),
        "--vault",
        str(artifacts["vault"]),
        "--audit-log",
        str(artifacts["audit_log"]),
        "--plan-json",
        str(artifacts["setup_plan"]),
        "--receipt-json",
        str(artifacts["setup_receipt"]),
        "--receipt-md",
        str(artifacts["setup_receipt_markdown"]),
        "--rollback-json",
        str(artifacts["rollback_plan"]),
        "--verification-report",
        str(artifacts["verification_report"]),
        "--verify-attempts",
        str(verify_attempts),
        "--verify-retry-seconds",
        _number_arg(verify_retry_seconds),
        "--gate-retry-seconds",
        _number_arg(gate_retry_seconds),
        "--gate-max-attempts",
        str(gate_max_attempts),
        "--visual-runner",
        "novnc",
        "--llm-provider",
        "openai",
        "--llm-model",
        "gpt-5.5",
        "--llm-auth-mode",
        "auto",
    )
    acceptance_args = (
        "fusekit",
        "acceptance",
        "run",
        str(source_dir),
        "--mode",
        "live",
        "--vault",
        str(artifacts["vault"]),
        "--receipt",
        str(artifacts["setup_receipt"]),
        "--audit-log",
        str(artifacts["audit_log"]),
        "--remote-artifacts",
        str(artifacts["remote_artifacts"]),
        "--output-dir",
        str(artifacts["acceptance_output"]),
        "--require-recording",
        "--json",
    )
    return HostedWorkerLaunchInvocation(
        execution=execution,
        artifact_paths=artifacts,
        launch_args=launch_args,
        acceptance_args=acceptance_args,
        env_contract=(
            "FUSEKIT_PASSPHRASE",
            "provider credentials captured into the encrypted FuseKit vault",
            "provider-owned human gates through visible hosted/worker controls",
        ),
    )


def build_hosted_worker_maintenance_invocation(
    job: HostedLaunchJob,
    *,
    workspace: Path,
) -> HostedWorkerMaintenanceInvocation:
    """Build rollback/detonation commands for a previously prepared hosted workspace."""

    if job.status not in {"rollback_requested", "detonation_requested"}:
        raise FuseKitError("Hosted worker maintenance requires rollback or detonation request.")
    action = "rollback" if job.status == "rollback_requested" else "detonate"
    source_dir = (workspace / job.job_id / "source").resolve()
    artifacts = _artifact_paths(source_dir)
    rollback_args = (
        "fusekit",
        "rollback",
        "--receipt",
        str(artifacts["setup_receipt"]),
        "--vault",
        str(artifacts["vault"]),
        "--execute",
    )
    detonation_args = (
        "fusekit",
        "detonate",
        str(source_dir / ".fusekit/worker"),
        str(source_dir / ".fusekit/tmp"),
        "--workspace-root",
        str(source_dir),
    )
    return HostedWorkerMaintenanceInvocation(
        job=job,
        action=action,
        source_dir=source_dir,
        artifact_paths=artifacts,
        rollback_args=rollback_args,
        detonation_args=detonation_args,
    )


def _require_approved_contract(
    job: HostedLaunchJob,
    refreshed_contract: HostedWorkerContract,
) -> None:
    expected = job.worker_contract
    if (
        job.github_source != refreshed_contract.github_source
        or expected.plan_fingerprint != refreshed_contract.plan_fingerprint
        or expected.providers != refreshed_contract.providers
        or expected.required_env != refreshed_contract.required_env
        or expected.approved_actions != refreshed_contract.approved_actions
        or expected.required_artifacts != refreshed_contract.required_artifacts
        or expected.gates != refreshed_contract.gates
        or expected.guarantees != refreshed_contract.guarantees
    ):
        raise FuseKitError("Hosted source plan changed after approval; restart hosted launch.")


def _artifact_paths(source_dir: Path) -> dict[str, Path]:
    return {key: source_dir / label for key, label in HOSTED_WORKER_ARTIFACTS.items()}


def _redacted_args(args: tuple[str, ...], source_dir: Path) -> list[str]:
    source = source_dir.resolve()
    redacted: list[str] = []
    for arg in args:
        redacted.append(_redacted_arg(arg, source))
    return redacted


def _redacted_arg(arg: str, source_dir: Path) -> str:
    if "://" in arg or not arg.startswith(("/", ".", "~")):
        return arg
    try:
        path = Path(arg).resolve()
    except OSError:
        return arg
    if path == source_dir:
        return "<hosted-worker-source>"
    try:
        relative = path.relative_to(source_dir)
    except ValueError:
        return arg
    return f"<hosted-worker-source>/{relative.as_posix()}"


def _number_arg(value: float) -> str:
    return str(int(value)) if value.is_integer() else str(value)


def _read_acceptance_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if _path_has_symlink_parent(path, path.parent.parent):
        raise FuseKitError("Hosted worker acceptance report must not use symlinked parents.")
    if path.is_symlink() or not path.is_file():
        raise FuseKitError("Hosted worker acceptance report must be a regular file.")
    try:
        if path.stat().st_size > PUBLIC_PROOF_ARTIFACT_MAX_BYTES:
            raise FuseKitError("Hosted worker acceptance report is too large.")
    except OSError as exc:
        raise FuseKitError("Hosted worker acceptance report could not be inspected.") from exc
    try:
        content = path.read_text(encoding="utf-8")
        raw = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise FuseKitError("Hosted worker acceptance report could not be read.") from exc
    except UnicodeDecodeError as exc:
        raise FuseKitError("Hosted worker acceptance report must be UTF-8 JSON.") from exc
    if not isinstance(raw, dict):
        raise FuseKitError("Hosted worker acceptance report must be a JSON object.")
    if _json_contains_secret_text(raw):
        raise FuseKitError("Hosted worker acceptance report contains secret-looking text.")
    return raw


def _artifact_completion(
    *,
    source_dir: Path,
    required_artifacts: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    labels = required_artifacts
    completed: list[str] = []
    missing: list[str] = []
    for label in labels:
        path = source_dir / label
        if _required_artifact_present(label, path, root=source_dir):
            completed.append(label)
        else:
            missing.append(label)
    return tuple(completed), tuple(missing)


def _required_artifact_present(
    label: str,
    path: Path,
    *,
    allow_encrypted_vault: bool = False,
    root: Path | None = None,
) -> bool:
    if root is not None and _path_has_symlink_parent(path, root):
        return False
    if path.is_symlink() or not path.is_file():
        return False
    if allow_encrypted_vault and label in ENCRYPTED_VAULT_ARTIFACT_LABELS:
        try:
            return path.stat().st_size > 0
        except OSError:
            return False
    if label.endswith("gate_events.jsonl"):
        return _public_proof_artifact_safe(path, allow_empty=True)
    return _public_proof_artifact_safe(path)


def _public_proof_artifact_safe(path: Path, *, allow_empty: bool = False) -> bool:
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0:
        return allow_empty
    if size > PUBLIC_PROOF_ARTIFACT_MAX_BYTES:
        return False
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False
    except UnicodeDecodeError:
        return False
    return not contains_durable_secret_text(content)


def _remote_artifacts_bundle_present(path: Path) -> bool:
    if _path_has_symlink_parent(path, path.parent):
        return False
    if path.is_symlink() or not path.is_dir():
        return False
    remote_fusekit_dir = path if path.name == ".fusekit" else path / ".fusekit"
    if _path_has_symlink_parent(remote_fusekit_dir, path):
        return False
    if remote_fusekit_dir.is_symlink() or not remote_fusekit_dir.is_dir():
        return False
    try:
        children = list(remote_fusekit_dir.iterdir())
    except OSError:
        return False
    unexpected = [
        child
        for child in children
        if child.name not in REMOTE_ALLOWED_SURVIVOR_FILE_SET
    ]
    if unexpected:
        return False
    if not all(
        _required_artifact_present(
            child.name,
            child,
            allow_encrypted_vault=True,
            root=remote_fusekit_dir,
        )
        for child in children
    ):
        return False
    return all(
        _required_artifact_present(
            filename,
            remote_fusekit_dir / filename,
            allow_encrypted_vault=True,
            root=remote_fusekit_dir,
        )
        for filename in REMOTE_REQUIRED_SURVIVOR_FILES
    )


def _path_has_symlink_parent(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    if root.is_symlink():
        return True
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _check_statuses(acceptance: dict[str, Any]) -> dict[str, str]:
    checks = acceptance.get("checks", [])
    if not isinstance(checks, list):
        return {}
    result: dict[str, str] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        check_id = item.get("id")
        status = item.get("status")
        if isinstance(check_id, str) and isinstance(status, str):
            result[check_id] = status
    return result


def _dns_evidence_ready(checks: dict[str, str]) -> bool:
    dns_checks = {
        key: status
        for key, status in checks.items()
        if "dns" in key or "domain" in key or "cloudflare" in key
    }
    return bool(dns_checks) and all(status == "ok" for status in dns_checks.values())


def _live_acceptance_report_ready(
    *,
    acceptance: dict[str, Any],
    report_path: Path,
    missing_artifacts: tuple[str, ...],
) -> bool:
    return (
        acceptance.get("mode") == "live"
        and report_path.exists()
        and not missing_artifacts
        and acceptance.get("launch_ready") is True
        and acceptance.get("public_launch_ready") is True
        and _acceptance_list_empty(acceptance.get("missing"))
        and _acceptance_list_empty(acceptance.get("blockers"))
    )


def _acceptance_list_empty(value: object) -> bool:
    return isinstance(value, list) and not value


def _rollback_metadata_ready(
    *,
    invocation_source_dir: Path,
    completed_artifacts: tuple[str, ...],
) -> bool:
    if ".fusekit/rollback_plan.json" not in completed_artifacts:
        return False
    path = invocation_source_dir / ".fusekit/rollback_plan.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or _json_contains_secret_text(raw):
        return False
    actions = raw.get("rollback", raw.get("actions", []))
    if not isinstance(actions, list):
        return False
    return any(_provider_rollback_action_ready(action) for action in actions)


def _provider_rollback_action_ready(action: object) -> bool:
    if not isinstance(action, Mapping):
        return False
    name = str(action.get("action") or "").strip()
    status = str(action.get("status") or "").strip().lower()
    is_provider_rollback = (
        name.startswith("rollback.")
        or name.endswith(".rollback")
        or ".rollback." in name
    )
    return is_provider_rollback and status in {"planned", "done"}


def _json_contains_secret_text(value: object) -> bool:
    return contains_durable_secret_text(json.dumps(value, sort_keys=True))


def _proof_note(
    evidence: dict[str, bool],
    missing: tuple[str, ...],
    acceptance: dict[str, Any],
) -> str:
    if all(evidence[key] for key in HOSTED_WORKER_PROOF_KEYS) and not missing:
        return (
            "Hosted worker produced live acceptance, remote artifacts, rollback, "
            "and detonation proof."
        )
    blockers = acceptance.get("blockers", [])
    if isinstance(blockers, list) and blockers:
        return "Hosted worker proof is partial; acceptance blockers remain."
    if missing:
        return "Hosted worker proof is partial; required artifact labels are still missing."
    if not evidence["dns_propagation"]:
        return "Hosted worker proof is partial; DNS propagation proof is missing."
    if not evidence["rollback_metadata"]:
        return "Hosted worker proof is partial; rollback metadata has no provider rollback actions."
    if not evidence["retrieved_remote_artifacts"]:
        return "Hosted worker proof is partial; retrieved remote artifact bundle is not ready."
    return "Hosted worker proof is partial; live acceptance is not recording-ready yet."


def _redacted_acceptance_summary(acceptance: dict[str, Any]) -> dict[str, object]:
    return {
        "mode": acceptance.get("mode"),
        "launch_ready": acceptance.get("launch_ready") is True,
        "public_launch_ready": acceptance.get("public_launch_ready") is True,
        "remote_artifacts_ready": acceptance.get("remote_artifacts_ready") is True,
        "recording_proof_ready": acceptance.get("recording_proof_ready") is True,
        "recording_ready": acceptance.get("recording_ready") is True,
        "check_count": len(acceptance.get("checks", []))
        if isinstance(acceptance.get("checks"), list)
        else 0,
    }
