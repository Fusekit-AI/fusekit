"""Checkpointed runner job state."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class JobStep:
    """One visible runner step."""

    id: str
    label: str
    status: str = "pending"
    detail: str = ""
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, str | float]:
        """Serialize the step."""

        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "detail": self.detail,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class JobCheckpoint:
    """Durable user-facing recovery state for one launch phase."""

    id: str
    label: str
    status: str = "pending"
    detail: str = ""
    next_action: str = ""
    resume_hint: str = ""
    mascot_state: str = "launch"
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, str | float]:
        """Serialize the checkpoint."""

        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "detail": self.detail,
            "next_action": self.next_action,
            "resume_hint": self.resume_hint,
            "mascot_state": self.mascot_state,
            "updated_at": self.updated_at,
        }


@dataclass
class JobState:
    """Resumable runner job state with no raw secrets."""

    id: str
    app_path: str
    runner: str
    status: str = "created"
    steps: list[JobStep] = field(default_factory=list)
    checkpoints: list[JobCheckpoint] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @classmethod
    def create(cls, job_id: str, app_path: Path, runner: str) -> JobState:
        """Create a new job with the standard one-click control-room steps."""

        steps = [
            JobStep("runner.resolve", "Select execution runner", "pending"),
            JobStep("oci.authorize", "Authorize OCI runner", "pending"),
            JobStep("oci.provision", "Provision disposable VM workspace", "pending"),
            JobStep("remote.bootstrap", "Bootstrap FuseKit and OpenClaw remotely", "pending"),
            JobStep("app.upload", "Upload app without secret files", "pending"),
            JobStep("setup.execute", "Run setup worker", "pending"),
            JobStep("verify.live", "Verify live app", "pending"),
            JobStep("artifacts.retrieve", "Retrieve encrypted/redacted artifacts", "pending"),
            JobStep("detonate.workspace", "Detonate runner workspace", "pending"),
        ]
        return cls(
            id=job_id,
            app_path=str(app_path),
            runner=runner,
            steps=steps,
            checkpoints=[_checkpoint_from_step(step) for step in steps],
        )

    @classmethod
    def load(cls, path: Path) -> JobState:
        """Load a job state file."""

        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JobState:
        """Deserialize a job state."""

        steps = [
            JobStep(
                id=str(item["id"]),
                label=str(item["label"]),
                status=str(item.get("status", "pending")),
                detail=str(item.get("detail", "")),
                updated_at=float(item.get("updated_at", time.time())),
            )
            for item in list(data.get("steps", []))
            if isinstance(item, dict)
        ]
        checkpoints = [
            JobCheckpoint(
                id=str(item["id"]),
                label=str(item["label"]),
                status=str(item.get("status", "pending")),
                detail=str(item.get("detail", "")),
                next_action=str(item.get("next_action", "")),
                resume_hint=str(item.get("resume_hint", "")),
                mascot_state=str(item.get("mascot_state", "launch")),
                updated_at=float(item.get("updated_at", time.time())),
            )
            for item in list(data.get("checkpoints", []))
            if isinstance(item, dict)
        ]
        if not checkpoints:
            checkpoints = [_checkpoint_from_step(step) for step in steps]
        return cls(
            id=str(data["id"]),
            app_path=str(data["app_path"]),
            runner=str(data["runner"]),
            status=str(data.get("status", "created")),
            steps=steps,
            checkpoints=checkpoints,
            artifacts={str(k): str(v) for k, v in dict(data.get("artifacts", {})).items()},
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )

    def mark(self, step_id: str, status: str, detail: str = "") -> None:
        """Mark a step status."""

        updated: list[JobStep] = []
        found = False
        for step in self.steps:
            if step.id == step_id:
                updated.append(
                    JobStep(step.id, step.label, status, detail or step.detail, time.time())
                )
                found = True
            else:
                updated.append(step)
        if not found:
            updated.append(JobStep(step_id, step_id, status, detail, time.time()))
        self.steps = updated
        step = next(item for item in self.steps if item.id == step_id)
        self._mark_checkpoint(step)
        self.updated_at = time.time()
        statuses = {step.status for step in self.steps}
        if "failed" in statuses:
            self.status = "failed"
        elif "waiting" in statuses:
            self.status = "waiting"
        elif all(step.status in {"done", "skipped"} for step in self.steps):
            self.status = "done"
        else:
            self.status = "running"

    def add_artifact(self, name: str, path: Path) -> None:
        """Record a non-secret artifact path."""

        self.artifacts[name] = str(path)
        self.updated_at = time.time()

    def upsert_checkpoint(
        self,
        checkpoint_id: str,
        label: str,
        *,
        status: str,
        detail: str,
        next_action: str,
        resume_hint: str,
        mascot_state: str = "launch",
    ) -> None:
        """Add or replace a durable user-facing checkpoint."""

        checkpoint = JobCheckpoint(
            id=checkpoint_id,
            label=label,
            status=status,
            detail=detail,
            next_action=next_action,
            resume_hint=resume_hint,
            mascot_state=mascot_state,
            updated_at=time.time(),
        )
        updated: list[JobCheckpoint] = []
        found = False
        for existing in self.checkpoints:
            if existing.id == checkpoint_id:
                updated.append(checkpoint)
                found = True
            else:
                updated.append(existing)
        if not found:
            updated.append(checkpoint)
        self.checkpoints = updated
        self.updated_at = time.time()

    def _mark_checkpoint(self, step: JobStep) -> None:
        checkpoint = _checkpoint_from_step(step)
        updated: list[JobCheckpoint] = []
        found = False
        for existing in self.checkpoints:
            if existing.id == step.id:
                updated.append(checkpoint)
                found = True
            else:
                updated.append(existing)
        if not found:
            updated.append(checkpoint)
        self.checkpoints = updated

    def to_dict(self) -> dict[str, Any]:
        """Serialize the job state."""

        return {
            "id": self.id,
            "app_path": self.app_path,
            "runner": self.runner,
            "status": self.status,
            "steps": [step.to_dict() for step in self.steps],
            "checkpoints": [checkpoint.to_dict() for checkpoint in self.checkpoints],
            "artifacts": self.artifacts,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def save(self, path: Path) -> None:
        """Write the job state file."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
        checkpoint_path = path.with_name("checkpoints.json")
        checkpoint_payload = {
            "job_id": self.id,
            "status": self.status,
            "updated_at": self.updated_at,
            "checkpoints": [checkpoint.to_dict() for checkpoint in self.checkpoints],
        }
        checkpoint_path.write_text(
            json.dumps(checkpoint_payload, indent=2, sort_keys=True) + "\n",
            "utf-8",
        )


def _checkpoint_from_step(step: JobStep) -> JobCheckpoint:
    next_action, resume_hint, mascot_state = _checkpoint_guidance(step)
    return JobCheckpoint(
        id=step.id,
        label=step.label,
        status=step.status,
        detail=step.detail or "Queued and ready for the worker.",
        next_action=next_action,
        resume_hint=resume_hint,
        mascot_state=mascot_state,
        updated_at=step.updated_at,
    )


def _checkpoint_guidance(step: JobStep) -> tuple[str, str, str]:
    status = step.status
    step_id = step.id
    if status == "waiting":
        return (
            "Complete the provider-owned gate shown in the browser.",
            "FuseKit keeps this checkpoint open and resurfaces it until the service accepts it.",
            "privacy" if _privacy_detail(step) else "gate",
        )
    if status == "failed":
        return (
            "Open the control room and follow the repair note for this checkpoint.",
            "Retry the launch after the provider or runner issue is corrected.",
            "repair",
        )
    if status == "done":
        return (
            "Nothing needed for this checkpoint.",
            "FuseKit has a durable record of this completed phase.",
            "done" if step_id == "detonate.workspace" else _mascot_for_step(step),
        )
    if status == "skipped":
        return (
            "Nothing needed for this checkpoint.",
            "FuseKit skipped this phase because the launch options requested it.",
            "done",
        )
    if status == "running":
        return _running_guidance(step)
    return (
        "Nothing needed yet.",
        "FuseKit will start this checkpoint after the current phase completes.",
        _mascot_for_step(step),
    )


def _running_guidance(step: JobStep) -> tuple[str, str, str]:
    step_id = step.id
    if step_id == "oci.provision":
        return (
            "Wait while OCI capacity is selected and the clean-room VM is created.",
            "If capacity is unavailable, FuseKit retries alternate availability domains/shapes.",
            "working",
        )
    if step_id == "remote.bootstrap":
        return (
            "Wait while the VM installs FuseKit, OpenClaw, browser tools, and dependencies.",
            "If setup fails, rerun from the same encrypted vault and job state.",
            "working",
        )
    if step_id == "app.upload":
        return (
            "Wait while FuseKit uploads only safe app files into the clean room.",
            "Secret files, vaults, caches, and local credentials are excluded from upload.",
            "working",
        )
    if step_id == "setup.execute":
        return (
            "Watch for provider gates while FuseKit connects services and configures secrets.",
            "Human gates wait forever unless a service itself refuses the step.",
            "privacy" if _privacy_detail(step) else "working",
        )
    if step_id == "verify.live":
        return (
            "Wait while FuseKit checks provider APIs, DNS, and the live app.",
            "Pending provider checks are retried with clear recovery notes.",
            "verify",
        )
    if step_id == "artifacts.retrieve":
        return (
            "Wait while encrypted vault and redacted audit artifacts are copied back.",
            "FuseKit fails loudly if required artifacts are missing or unsafe.",
            "verify",
        )
    if step_id == "detonate.workspace":
        return (
            "Wait while plaintext worker state and temporary access are removed.",
            "Only encrypted and redacted survivor artifacts should remain.",
            "detonate",
        )
    return (
        "Wait while FuseKit completes this phase.",
        "The control room updates this checkpoint as soon as progress changes.",
        _mascot_for_step(step),
    )


def _mascot_for_step(step: JobStep) -> str:
    if step.id == "detonate.workspace":
        return "detonate"
    if "verify" in step.id:
        return "verify"
    if any(part in step.id for part in ("provision", "bootstrap", "upload", "setup")):
        return "working"
    return "launch"


def _privacy_detail(step: JobStep) -> bool:
    text = f"{step.id} {step.label} {step.detail}".lower()
    return any(
        marker in text
        for marker in (
            "api key",
            "captcha",
            "credential",
            "hidden prompt",
            "mfa",
            "passphrase",
            "payment",
            "private key",
            "secret",
            "token",
            "vault",
        )
    )
