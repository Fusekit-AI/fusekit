"""Hosted launch job and public control-room rendering."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.launcher import HOSTED_COMPLETION_EVIDENCE_KEYS, HostedLaunchPlan
from fusekit.security.redaction import contains_durable_secret_text, redact_public_text

HOSTED_JOB_SCHEMA_VERSION = "fusekit.hosted-job.v1"
HOSTED_JOB_TOKEN_SCHEMA_VERSION = "fusekit.hosted-job-token.v1"
HOSTED_JOB_TOKEN_TTL_SECONDS = 86_400
HOSTED_PROOF_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-proof-receipt.v1"
HOSTED_WORKER_CONTRACT_SCHEMA_VERSION = "fusekit.hosted-worker-contract.v1"
HOSTED_WORKER_REQUEST_SCHEMA_VERSION = "fusekit.hosted-worker-request.v1"
HOSTED_JOB_ACTION_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-job-action-receipt.v1"
HOSTED_WORKER_CLAIM_SCHEMA_VERSION = "fusekit.hosted-worker-claim.v1"
HOSTED_WORKER_PROOF_SCHEMA_VERSION = "fusekit.hosted-worker-proof.v1"
HOSTED_WORKER_PROOF_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-worker-proof-receipt.v1"

HOSTED_WORKER_PROOF_KEYS = HOSTED_COMPLETION_EVIDENCE_KEYS
HOSTED_WORKER_MAINTENANCE_PROOF_KEYS = (
    "rollback_execution_receipt",
    "post_rollback_verification",
    "workspace_detonation_receipt",
    "scratch_state_destroyed",
    "provider_auth_session_closed",
    "redacted_public_proof_preserved",
)


@dataclass(frozen=True)
class HostedWorkerContract:
    """Public, non-secret contract the hosted worker must satisfy."""

    lane: str
    github_source: str
    github_installation_id: int | None
    providers: tuple[str, ...]
    required_env: tuple[str, ...]
    permission_boundary: tuple[str, ...]
    approved_actions: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    gates: tuple[str, ...]
    guarantees: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the public hosted worker contract."""

        return {
            "schema_version": HOSTED_WORKER_CONTRACT_SCHEMA_VERSION,
            "lane": self.lane,
            "github_source": self.github_source,
            "github_installation_id": self.github_installation_id,
            "source_token_policy": (
                "Exchange GitHub App installation tokens inside the FuseKit backend worker only. "
                "Installation tokens are never embedded in browser pages, job tokens, receipts, "
                "or public proof."
            ),
            "providers": list(self.providers),
            "required_env": list(self.required_env),
            "permission_boundary": list(self.permission_boundary),
            "approved_actions": list(self.approved_actions),
            "required_artifacts": list(self.required_artifacts),
            "gates": list(self.gates),
            "guarantees": list(self.guarantees),
        }


@dataclass(frozen=True)
class HostedLaunchJobStep:
    """One hosted launch control-room step."""

    id: str
    label: str
    owner: str
    status: str
    proof: str

    def to_dict(self) -> dict[str, str]:
        """Serialize a browser-safe job step."""

        return {
            "id": self.id,
            "label": self.label,
            "owner": self.owner,
            "status": self.status,
            "proof": self.proof,
        }


@dataclass(frozen=True)
class HostedLaunchJob:
    """Public hosted launch job contract before real runner execution starts."""

    job_id: str
    app_name: str
    github_source: str
    status: str
    created_at: int
    steps: tuple[HostedLaunchJobStep, ...]
    proof: tuple[str, ...]
    rollback: tuple[str, ...]
    detonation: tuple[str, ...]
    worker_contract: HostedWorkerContract

    def to_dict(self) -> dict[str, object]:
        """Serialize a browser-safe hosted job."""

        return {
            "schema_version": HOSTED_JOB_SCHEMA_VERSION,
            "job_id": self.job_id,
            "app_name": self.app_name,
            "github_source": self.github_source,
            "status": self.status,
            "created_at": self.created_at,
            "steps": [step.to_dict() for step in self.steps],
            "proof": list(self.proof),
            "rollback": list(self.rollback),
            "detonation": list(self.detonation),
            "worker_contract": self.worker_contract.to_dict(),
        }


def build_hosted_launch_job(
    plan: HostedLaunchPlan,
    *,
    github_installation_id: int | None = None,
    job_id: str | None = None,
    now: int | None = None,
) -> HostedLaunchJob:
    """Create the public control-room job contract for an approved hosted plan."""

    worker_contract = build_hosted_worker_contract(
        plan,
        github_installation_id=github_installation_id,
    )
    return HostedLaunchJob(
        job_id=job_id or f"hosted-{secrets.token_urlsafe(12)}",
        app_name=plan.app_name,
        github_source=plan.github_source,
        status="waiting_for_worker",
        created_at=int(time.time() if now is None else now),
        steps=(
            HostedLaunchJobStep(
                "plan.approved",
                "Visible plan approved",
                "user",
                "done",
                "Hosted plan JSON and trust contract are available in this session.",
            ),
            HostedLaunchJobStep(
                "worker.prepare",
                "Prepare hosted setup worker",
                "fusekit",
                "pending",
                "Worker identity, runner, and vault session proof will appear here.",
            ),
            HostedLaunchJobStep(
                "provider.gates",
                "Complete provider-owned gates",
                "user",
                "pending",
                "MFA, billing, consent, CAPTCHA, and copy-once secret screens stay provider-owned.",
            ),
            HostedLaunchJobStep(
                "setup.execute",
                "Run approved setup plan",
                "fusekit",
                "pending",
                "Only approved provider actions from the visible plan may run.",
            ),
            HostedLaunchJobStep(
                "proof.collect",
                "Collect redacted proof",
                "fusekit",
                "pending",
                "Live URL, verifiers, DNS propagation, Run Record, and receipts remain redacted.",
            ),
            HostedLaunchJobStep(
                "rollback.ready",
                "Prepare reversible setup metadata",
                "fusekit",
                "pending",
                "Rollback actions for created provider resources will be listed before completion.",
            ),
            HostedLaunchJobStep(
                "detonate.worker",
                "Detonate hosted worker state",
                "fusekit",
                "pending",
                "Plaintext worker, auth, browser, and scratch state must be destroyed.",
            ),
        ),
        proof=plan.trust.proof,
        rollback=plan.trust.rollback,
        detonation=(
            "Destroy hosted worker scratch directory.",
            "Close browser and provider auth session state.",
            "Preserve only encrypted vault material and redacted public proof.",
            "Write detonation receipt before launch is considered complete.",
        ),
        worker_contract=worker_contract,
    )


def create_hosted_job_token(
    secret: str,
    job: HostedLaunchJob,
    *,
    now: int | None = None,
) -> str:
    """Create a signed public job token for stateless hosted control rooms."""

    if not secret:
        raise FuseKitError("Hosted launcher job token secret is required.")
    payload = _base64url_json(
        {
            "schema_version": HOSTED_JOB_TOKEN_SCHEMA_VERSION,
            "issued_at": int(time.time() if now is None else now),
            "job": job.to_dict(),
        }
    )
    signature = _sign(secret, payload)
    return f"{payload}.{signature}"


def verify_hosted_job_token(
    secret: str,
    token: str,
    *,
    now: int | None = None,
    ttl_seconds: int = HOSTED_JOB_TOKEN_TTL_SECONDS,
) -> HostedLaunchJob:
    """Verify and decode a signed public hosted job token."""

    if not secret:
        raise FuseKitError("Hosted launcher job token secret is required.")
    if ttl_seconds <= 0:
        raise FuseKitError("Hosted launcher job token ttl must be positive.")
    try:
        payload, signature = token.split(".", 1)
    except ValueError:
        raise FuseKitError("Hosted launcher job token is malformed.") from None
    expected = _sign(secret, payload)
    if not hmac.compare_digest(signature, expected):
        raise FuseKitError("Hosted launcher job token signature is invalid.")
    raw = _decode_json(payload)
    if raw.get("schema_version") != HOSTED_JOB_TOKEN_SCHEMA_VERSION:
        raise FuseKitError("Hosted launcher job token schema is unsupported.")
    issued_at = raw.get("issued_at")
    if not isinstance(issued_at, int):
        raise FuseKitError("Hosted launcher job token timestamp is invalid.")
    current = int(time.time() if now is None else now)
    if issued_at > current + 60:
        raise FuseKitError("Hosted launcher job token timestamp is in the future.")
    if current - issued_at > ttl_seconds:
        raise FuseKitError("Hosted launcher job token expired.")
    job = raw.get("job")
    if not isinstance(job, dict):
        raise FuseKitError("Hosted launcher job token payload is invalid.")
    return hosted_launch_job_from_dict(job)


def hosted_launch_job_from_dict(payload: dict[str, Any]) -> HostedLaunchJob:
    """Decode a public hosted job payload into dataclasses."""

    if payload.get("schema_version") != HOSTED_JOB_SCHEMA_VERSION:
        raise FuseKitError("Hosted launch job schema is unsupported.")
    job_id = _required_str(payload, "job_id")
    if not job_id.startswith("hosted-"):
        raise FuseKitError("Hosted launch job id is invalid.")
    steps = payload.get("steps")
    proof = payload.get("proof")
    rollback = payload.get("rollback")
    detonation = payload.get("detonation")
    worker_contract = payload.get("worker_contract")
    if not isinstance(steps, list) or not isinstance(worker_contract, dict):
        raise FuseKitError("Hosted launch job payload is invalid.")
    return HostedLaunchJob(
        job_id=job_id,
        app_name=_required_str(payload, "app_name"),
        github_source=_required_str(payload, "github_source"),
        status=_required_str(payload, "status"),
        created_at=_required_int(payload, "created_at"),
        steps=tuple(_job_step_from_dict(step) for step in steps),
        proof=_str_tuple(proof, "proof"),
        rollback=_str_tuple(rollback, "rollback"),
        detonation=_str_tuple(detonation, "detonation"),
        worker_contract=_worker_contract_from_dict(worker_contract),
    )


def build_hosted_worker_contract(
    plan: HostedLaunchPlan,
    *,
    github_installation_id: int | None = None,
) -> HostedWorkerContract:
    """Build the redacted execution contract for the hosted setup worker."""

    return HostedWorkerContract(
        lane="hosted-fusekit-worker",
        github_source=plan.github_source,
        github_installation_id=github_installation_id,
        providers=plan.providers,
        required_env=plan.required_env,
        permission_boundary=(
            "GitHub App installation is limited to one selected repository.",
            "GitHub repository permission is contents:read for source intake.",
            "GitHub installation tokens are exchanged only inside the backend worker.",
            "Provider credentials stay inside the FuseKit vault or provider-native secret stores.",
            "Worker dispatch uses an HMAC envelope; worker secrets are never sent to browsers.",
        ),
        approved_actions=tuple(action.id for action in plan.actions),
        required_artifacts=(
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
        ),
        gates=plan.trust.user_gates,
        guarantees=(
            "Only actions from the visible plan may run.",
            (
                "Provider-owned login, MFA, billing, consent, and copy-once "
                "secret screens remain human-owned."
            ),
            "DNS changes require explicit approval before provider mutation.",
            "Raw secrets must remain inside the encrypted FuseKit vault runtime.",
            "Public proof must be redacted before it is rendered or downloaded.",
            "Rollback metadata must exist before risky provider changes are considered complete.",
            "Hosted worker scratch, browser, auth, and plaintext setup state must be detonated.",
            "Live acceptance must require retrieved remote artifacts and recording proof.",
        ),
    )


def advance_hosted_launch_job(
    job: HostedLaunchJob,
    action: str,
    *,
    now: int | None = None,
) -> HostedLaunchJob:
    """Return an updated hosted job after a protected control-room action."""

    current = int(time.time() if now is None else now)
    if action == "start":
        if job.status != "waiting_for_worker":
            raise ValueError("Hosted launch can only start once before worker handoff.")
        return _replace_job(
            job,
            status="waiting_for_provider_gates",
            created_at=job.created_at,
            steps=_update_steps(
                job.steps,
                {
                    "worker.prepare": (
                        "waiting",
                        (
                            "Hosted worker contract queued; runner identity, vault unlock, "
                            "remote-artifact, and recording proof are still pending."
                        ),
                    ),
                    "provider.gates": (
                        "waiting",
                        (
                            "Waiting for the next provider-owned login, MFA, billing, "
                            "consent, or secret gate."
                        ),
                    ),
                },
            ),
        )
    if action == "stop":
        if job.status != "waiting_for_worker":
            raise ValueError("Hosted launch can only be stopped before worker start.")
        return _replace_job(
            job,
            status="stopped",
            created_at=job.created_at,
            steps=_update_steps(
                job.steps,
                {
                    "worker.prepare": (
                        "waiting",
                        "Launch stopped before hosted worker start; no worker claim is allowed.",
                    ),
                    "provider.gates": (
                        "waiting",
                        "Launch stopped before provider mutation; no provider gate is pending.",
                    ),
                },
            ),
        )
    if action == "rollback":
        if job.status not in {
            "waiting_for_provider_gates",
            "worker_claimed",
            "proof_submitted",
            "complete",
        }:
            raise ValueError("Hosted rollback requires a started worker or submitted proof.")
        return _replace_job(
            job,
            status="rollback_requested",
            created_at=job.created_at or current,
            steps=_update_steps(
                job.steps,
                {
                    "rollback.ready": (
                        "waiting",
                        (
                            "Rollback requested; FuseKit will list provider resources "
                            "before changing them."
                        ),
                    )
                },
            ),
        )
    if action == "detonate":
        if job.status not in {
            "waiting_for_provider_gates",
            "worker_claimed",
            "proof_submitted",
            "complete",
            "rollback_requested",
        }:
            raise ValueError("Hosted detonation requires a started worker or rollback request.")
        return _replace_job(
            job,
            status="detonation_requested",
            created_at=job.created_at or current,
            steps=_update_steps(
                job.steps,
                {
                    "detonate.worker": (
                        "waiting",
                        "Detonation requested; FuseKit is waiting for worker cleanup proof.",
                    )
                },
            ),
        )
    raise ValueError(f"Unsupported hosted job action: {action}")


def claim_hosted_launch_job(
    job: HostedLaunchJob,
    *,
    worker_id: str,
    now: int | None = None,
) -> HostedLaunchJob:
    """Return an updated hosted job after a worker claims the request."""

    current = int(time.time() if now is None else now)
    if job.status == "waiting_for_worker":
        raise ValueError("Hosted worker request has not been started.")
    if job.status in {"stopped", "rollback_requested", "detonation_requested", "complete"}:
        raise ValueError("Hosted worker request cannot be claimed in its current state.")
    worker_label = _public_worker_id(worker_id)
    return _replace_job(
        job,
        status="worker_claimed",
        created_at=job.created_at or current,
        steps=_update_steps(
            job.steps,
            {
                "worker.prepare": (
                    "done",
                    f"Hosted worker {worker_label} claimed the redacted request.",
                ),
                "provider.gates": (
                    "waiting",
                    (
                        "Waiting for provider-owned login, MFA, billing, consent, "
                        "domain, or copy-once secret gates."
                    ),
                ),
                "setup.execute": (
                    "waiting",
                    "Worker may run only the approved visible-plan actions after gates clear.",
                ),
            },
        ),
    )


def apply_hosted_worker_proof(
    job: HostedLaunchJob,
    payload: dict[str, object],
    *,
    worker_id: str,
    now: int | None = None,
) -> tuple[HostedLaunchJob, dict[str, object]]:
    """Apply a redacted worker proof snapshot and return the updated job plus receipt."""

    if job.status not in {
        "worker_claimed",
        "rollback_requested",
        "detonation_requested",
        "proof_submitted",
    }:
        raise ValueError("Hosted worker proof requires an active worker or maintenance request.")
    receipt = hosted_worker_proof_receipt(job, payload, worker_id=worker_id, now=now)
    evidence = receipt["evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("Hosted worker proof evidence is invalid.")
    completion_ready = receipt["completion_ready"] is True
    rollback_execution_required = job.status == "rollback_requested"
    detonation_execution_required = job.status == "detonation_requested"
    updated = _replace_job(
        job,
        status="complete" if completion_ready else "proof_submitted",
        created_at=job.created_at,
        steps=_update_steps(
            job.steps,
            {
                "provider.gates": _provider_gate_step(evidence),
                "setup.execute": _setup_execute_step(completion_ready),
                "proof.collect": _proof_collect_step(evidence),
                "rollback.ready": _rollback_step(
                    evidence,
                    execution_required=rollback_execution_required,
                ),
                "detonate.worker": _detonation_step(
                    evidence,
                    execution_required=detonation_execution_required,
                ),
            },
        ),
    )
    receipt["status"] = updated.status
    return updated, receipt


def render_hosted_control_room(
    job: HostedLaunchJob,
    *,
    control_token: str = "",
    job_token: str = "",
    action_receipt: dict[str, object] | None = None,
    dispatch_receipt: dict[str, object] | None = None,
) -> str:
    """Render the public no-terminal hosted control-room shell."""

    payload_dict = job.to_dict()
    payload_dict["reversal_playbook"] = hosted_reversal_playbook(job)
    if action_receipt is not None:
        payload_dict["latest_action_receipt"] = action_receipt
    if dispatch_receipt is not None:
        payload_dict["worker_dispatch"] = dispatch_receipt
    payload = html.escape(json.dumps(payload_dict, sort_keys=True))
    rows = "\n".join(_step_card(step) for step in job.steps)
    controls = _control_forms(job, control_token=control_token, job_token=job_token)
    action_outcome = _action_receipt_section(action_receipt, dispatch_receipt)
    proof_link = _proof_link(job, job_token=job_token)
    worker_request_link = _worker_request_link(job, job_token=job_token)
    proof = _list(job.proof)
    rollback = _list(job.rollback)
    detonation = _list(job.detonation)
    reversal_playbook = _reversal_playbook_section(hosted_reversal_playbook(job))
    worker_contract = _worker_contract_section(job.worker_contract)
    app_name = html.escape(job.app_name)
    github_source = html.escape(job.github_source)
    job_id = html.escape(job.job_id)
    status = html.escape(job.status.replace("_", " "))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit hosted control room</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #536476;
      --line: #cfd9e2;
      --blue: #0077cc;
      --green: #167a4a;
      --amber: #8a5a00;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    main {{
      width: min(1120px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 30px 0 48px;
      display: grid;
      gap: 18px;
    }}
    header {{
      border-bottom: 2px solid var(--ink);
      padding-bottom: 20px;
      display: grid;
      gap: 10px;
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{ font-size: clamp(36px, 5vw, 64px); line-height: 1; letter-spacing: 0; }}
    p {{ color: #31465c; line-height: 1.5; }}
    .source {{
      overflow-wrap: anywhere;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 18px;
      align-items: start;
    }}
    section, aside {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 14px;
    }}
    .step {{
      border: 1px solid var(--line);
      border-left: 4px solid var(--amber);
      border-radius: 6px;
      padding: 10px 12px;
      display: grid;
      gap: 4px;
    }}
    .step.done {{ border-left-color: var(--green); }}
    .step small {{ color: var(--muted); }}
    button,
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 42px;
      width: fit-content;
      border-radius: 6px;
      background: var(--blue);
      color: white;
      padding: 0 14px;
      font-weight: 850;
      text-decoration: none;
      border: 1px solid var(--blue);
      cursor: pointer;
    }}
    button[disabled],
    .button.disabled {{
      background: #d8e1ea;
      border-color: #aebcca;
      color: #52616f;
      cursor: not-allowed;
    }}
    ul {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    li + li {{ margin-top: 6px; }}
    script[type="application/json"] {{ display: none; }}
    @media (max-width: 880px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="source">{job_id} / {status}</p>
      <h1>Hosted launch control room.</h1>
      <p>
        {app_name} is queued for FuseKit-owned setup. Human gates stay visible,
        provider-owned, and reversible; raw secrets stay out of public pages.
      </p>
      <p class="source">{github_source}</p>
    </header>
    <div class="grid">
      <section aria-label="Launch steps">
        <h2>Launch steps</h2>
        {action_outcome}
        {controls}
        {proof_link}
        {worker_request_link}
        {rows}
      </section>
      <aside aria-label="Proof and rollback">
        {worker_contract}
        <h2>Redacted proof</h2>
        {proof}
        <h2>Reversible setup</h2>
        {rollback}
        {reversal_playbook}
        <h2>Detonation</h2>
        {detonation}
      </aside>
    </div>
    <script id="fusekit-hosted-job" type="application/json">{payload}</script>
  </main>
</body>
</html>
"""


def hosted_proof_receipt(job: HostedLaunchJob) -> dict[str, object]:
    """Build a public redacted proof receipt for a hosted job."""

    completion_ready = _completion_ready(job)
    return {
        "schema_version": HOSTED_PROOF_RECEIPT_SCHEMA_VERSION,
        "job_id": job.job_id,
        "app_name": job.app_name,
        "github_source": job.github_source,
        "status": job.status,
        "completion_ready": completion_ready,
        "completion_statement": (
            "Completion is proven by live proof artifacts and worker detonation."
            if completion_ready
            else "Completion is not yet proven; required live proof artifacts are still pending."
        ),
        "redacted_proof": list(job.proof),
        "rollback": list(job.rollback),
        "detonation": list(job.detonation),
        "completion_requires": list(HOSTED_WORKER_PROOF_KEYS),
        "reversal_playbook": hosted_reversal_playbook(job),
        "provider_gates": list(job.worker_contract.gates),
        "permission_boundary": list(job.worker_contract.permission_boundary),
        "approved_actions": list(job.worker_contract.approved_actions),
        "required_artifacts": list(job.worker_contract.required_artifacts),
        "steps": [step.to_dict() for step in job.steps],
    }


def hosted_reversal_playbook(job: HostedLaunchJob) -> list[dict[str, str]]:
    """Return public browser-safe recovery controls for a hosted launch."""

    revoke_url = _github_installation_settings_url(job.worker_contract.github_installation_id)
    playbook = [
        {
            "control": "Stop launch before worker start",
            "proof": (
                "Use the protected control-room stop button before worker start. FuseKit "
                "freezes the job before worker claim or provider mutation and preserves "
                "the redacted public proof trail."
            ),
        },
        {
            "control": "Revoke GitHub App installation",
            "proof": (
                "Remove or narrow the GitHub App installation in GitHub settings. "
                "FuseKit never renders installation tokens in the browser, job token, "
                "proof receipt, or public logs."
            ),
        },
        {
            "control": "Request rollback",
            "proof": (
                "Use the protected control-room rollback button. Completion then requires "
                "rollback plan, provider resource inventory, rollback execution receipt, "
                "and post-rollback verification."
            ),
        },
        {
            "control": "Request detonation",
            "proof": (
                "Use the protected control-room detonation button. FuseKit must preserve "
                "redacted public proof and destroy hosted worker scratch state, provider "
                "auth sessions, and plaintext vault material."
            ),
        },
    ]
    if revoke_url:
        playbook[1]["action_url"] = revoke_url
    return playbook


def _github_installation_settings_url(installation_id: int | None) -> str:
    if installation_id is None or installation_id <= 0:
        return ""
    return f"https://github.com/settings/installations/{installation_id}"


def hosted_worker_request(job: HostedLaunchJob, *, now: int | None = None) -> dict[str, object]:
    """Build the redacted machine handoff a hosted worker may claim."""

    requested_at = int(time.time() if now is None else now)
    return {
        "schema_version": HOSTED_WORKER_REQUEST_SCHEMA_VERSION,
        "job_id": job.job_id,
        "app_name": job.app_name,
        "github_source": job.github_source,
        "status": job.status,
        "requested_at": requested_at,
        "claim_policy": {
            "runner": job.worker_contract.lane,
            "source_intake": "github-app-selected-repository-archive",
            "github_installation_id": job.worker_contract.github_installation_id,
            "mode": "live",
            "remote_artifacts_required": True,
            "recording_required": True,
            "human_gates_required": list(job.worker_contract.gates),
        },
        "approved_actions": list(job.worker_contract.approved_actions),
        "required_artifacts": list(job.worker_contract.required_artifacts),
        "acceptance_gate": {
            "mode": "live",
            "remote_artifacts": ".fusekit/remote-artifacts",
            "require_recording": True,
            "command": (
                "fusekit acceptance run <app> --mode live "
                "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
            ),
        },
        "completion_requires": list(HOSTED_WORKER_PROOF_KEYS),
        "prohibited": [
            "Do not bypass MFA, CAPTCHA, passkeys, billing, fraud, or consent gates.",
            (
                "Do not render or return raw provider credentials, installation tokens, "
                "or vault secrets."
            ),
            "Do not mutate DNS or paid provider resources without explicit visible approval.",
            "Do not claim completion before live acceptance and detonation proof pass.",
        ],
        "worker_contract": job.worker_contract.to_dict(),
    }


def hosted_job_action_receipt(
    job: HostedLaunchJob,
    *,
    action: str,
    now: int | None = None,
) -> dict[str, object]:
    """Build a public redacted receipt for a protected hosted job action."""

    action_id = _public_action(action)
    return {
        "schema_version": HOSTED_JOB_ACTION_RECEIPT_SCHEMA_VERSION,
        "job_id": job.job_id,
        "action": action_id,
        "status": job.status,
        "requested_at": int(time.time() if now is None else now),
        "receipt_statement": _action_receipt_statement(action_id),
        "next_required_proof": _action_next_required_proof(action_id),
        "safeguards": [
            (
                "Provider-owned MFA, CAPTCHA, billing, fraud, consent, and "
                "passkey gates remain human-owned."
            ),
            "Rollback and detonation requests do not erase public proof requirements.",
            (
                "Completion still requires live acceptance, retrieved remote "
                "artifacts, rollback metadata, Run Record, detonation receipt, "
                "and recording proof."
            ),
        ],
        "secret_boundary": (
            "Hosted action receipts contain action names, job status, and public proof "
            "requirements only. They never include worker secrets, provider tokens, "
            "GitHub installation tokens, vault material, or copy-once credentials."
        ),
    }


def hosted_worker_claim_receipt(
    job: HostedLaunchJob,
    *,
    worker_id: str,
    now: int | None = None,
) -> dict[str, object]:
    """Build a redacted receipt for a hosted worker claim."""

    claimed_at = int(time.time() if now is None else now)
    return {
        "schema_version": HOSTED_WORKER_CLAIM_SCHEMA_VERSION,
        "job_id": job.job_id,
        "worker_id": _public_worker_id(worker_id),
        "claimed_at": claimed_at,
        "status": job.status,
        "secret_boundary": (
            "The worker claim proves a configured backend worker authenticated. "
            "It never includes worker secrets, provider tokens, vault material, "
            "GitHub installation tokens, or copy-once credentials."
        ),
        "next_required_proof": [
            "provider_gate_events",
            *HOSTED_WORKER_PROOF_KEYS,
        ],
    }


def hosted_worker_proof_receipt(
    job: HostedLaunchJob,
    payload: dict[str, object],
    *,
    worker_id: str,
    now: int | None = None,
) -> dict[str, object]:
    """Build a redacted receipt for hosted worker proof submission."""

    if payload.get("schema_version") != HOSTED_WORKER_PROOF_SCHEMA_VERSION:
        raise ValueError("Hosted worker proof schema is unsupported.")
    evidence = _proof_evidence(payload.get("evidence"))
    completed_artifacts = _completed_artifacts(
        payload.get("completed_artifacts"),
        required_artifacts=job.worker_contract.required_artifacts,
    )
    note = _public_note(payload.get("note"))
    missing_artifacts = tuple(
        artifact
        for artifact in job.worker_contract.required_artifacts
        if artifact not in completed_artifacts
    )
    maintenance_ready = _maintenance_ready(job, evidence)
    completion_ready = (
        all(evidence[key] for key in HOSTED_WORKER_PROOF_KEYS)
        and not missing_artifacts
        and maintenance_ready
    )
    return {
        "schema_version": HOSTED_WORKER_PROOF_RECEIPT_SCHEMA_VERSION,
        "job_id": job.job_id,
        "worker_id": _public_worker_id(worker_id),
        "received_at": int(time.time() if now is None else now),
        "status": job.status,
        "completion_ready": completion_ready,
        "maintenance_ready": maintenance_ready,
        "completion_statement": (
            "Hosted completion proof is present."
            if completion_ready
            else "Hosted completion is still waiting on live proof artifacts."
        ),
        "evidence": evidence,
        "completed_artifacts": list(completed_artifacts),
        "missing_artifacts": list(missing_artifacts),
        "maintenance_required_proof": _maintenance_required_proof(job),
        "note": note,
        "secret_boundary": (
            "Worker proof accepts only redacted evidence flags, public artifact labels, "
            "and public notes. Raw provider credentials, vault contents, GitHub tokens, "
            "and worker secrets are rejected before receipt rendering."
        ),
    }


def render_hosted_proof_receipt(job: HostedLaunchJob, *, job_token: str = "") -> str:
    """Render the browser-facing hosted proof receipt."""

    receipt = hosted_proof_receipt(job)
    payload = html.escape(json.dumps(receipt, sort_keys=True))
    app_name = html.escape(job.app_name)
    github_source = html.escape(job.github_source)
    job_id = html.escape(job.job_id)
    status = html.escape(job.status.replace("_", " "))
    completion = html.escape(str(receipt["completion_statement"]))
    completion_requires = _list(HOSTED_WORKER_PROOF_KEYS)
    proof = _list(job.proof)
    rollback = _list(job.rollback)
    detonation = _list(job.detonation)
    reversal_playbook = _reversal_playbook_section(hosted_reversal_playbook(job))
    artifacts = _list(job.worker_contract.required_artifacts)
    gates = _list(job.worker_contract.gates)
    permissions = _list(job.worker_contract.permission_boundary)
    actions = _list(job.worker_contract.approved_actions)
    back = _control_room_link(job, job_token=job_token)
    proof_json = _proof_json_link(job, job_token=job_token)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit proof receipt</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #536476;
      --line: #cfd9e2;
      --blue: #0077cc;
      --amber: #8a5a00;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    main {{
      width: min(1040px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 30px 0 48px;
      display: grid;
      gap: 18px;
    }}
    header {{
      border-bottom: 2px solid var(--ink);
      padding-bottom: 20px;
      display: grid;
      gap: 10px;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(36px, 5vw, 64px); line-height: 1; letter-spacing: 0; }}
    p {{ color: #31465c; line-height: 1.5; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 12px;
    }}
    .source {{
      overflow-wrap: anywhere;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
    }}
    .warning {{ border-left: 4px solid var(--amber); }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 42px;
      width: fit-content;
      border-radius: 6px;
      background: var(--blue);
      color: white;
      padding: 0 14px;
      font-weight: 850;
      text-decoration: none;
    }}
    ul {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    li + li {{ margin-top: 6px; }}
    script[type="application/json"] {{ display: none; }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="source">{job_id} / {status}</p>
      <h1>Proof receipt.</h1>
      <p>{completion}</p>
      <p class="source">{app_name} / {github_source}</p>
      {back}
      {proof_json}
    </header>
    <section class="warning" aria-label="Completion status">
      <h2>Completion status</h2>
      <p>
        This receipt is public and redacted. It is not a launch-success claim
        until live URL, provider verifier, DNS, Run Record, rollback, acceptance,
        and detonation proof are present.
      </p>
      <h3>Completion requires</h3>
      {completion_requires}
    </section>
    <section aria-label="Redacted proof">
      <h2>Redacted proof</h2>
      {proof}
    </section>
    <section aria-label="Required artifacts">
      <h2>Required artifacts</h2>
      {artifacts}
    </section>
    <section aria-label="Approved actions">
      <h2>Approved actions</h2>
      <p>
        FuseKit workers may run only these plan actions. New or drifted actions
        require a fresh visible plan before execution.
      </p>
      {actions}
    </section>
    <section aria-label="Provider gates">
      <h2>Provider gates</h2>
      <p>
        These gates stay provider-owned and human-approved. FuseKit must pause
        instead of bypassing MFA, CAPTCHA, billing, fraud, consent, or domain
        ownership checks.
      </p>
      {gates}
    </section>
    <section aria-label="Permission boundary">
      <h2>Permission boundary</h2>
      {permissions}
    </section>
    <section aria-label="Reversible setup">
      <h2>Reversible setup</h2>
      {rollback}
    </section>
    <section aria-label="Reversal playbook">
      <h2>Reversal playbook</h2>
      {reversal_playbook}
    </section>
    <section aria-label="Detonation">
      <h2>Detonation</h2>
      {detonation}
    </section>
    <script id="fusekit-hosted-proof" type="application/json">{payload}</script>
  </main>
</body>
</html>
"""


def _step_card(step: HostedLaunchJobStep) -> str:
    status = html.escape(step.status)
    return (
        f'<article class="step {status}">'
        f"<h3>{html.escape(step.label)}</h3>"
        f"<small>{html.escape(step.owner)} / {status}</small>"
        f"<p>{html.escape(step.proof)}</p>"
        "</article>"
    )


def _action_receipt_section(
    action_receipt: dict[str, object] | None,
    dispatch_receipt: dict[str, object] | None,
) -> str:
    if action_receipt is None:
        return ""
    action = html.escape(str(action_receipt.get("action", "action")))
    statement = html.escape(str(action_receipt.get("receipt_statement", "")))
    next_required = action_receipt.get("next_required_proof")
    proof_items = (
        tuple(str(item) for item in next_required)
        if isinstance(next_required, list)
        else ()
    )
    dispatch = ""
    if dispatch_receipt is not None:
        dispatched = dispatch_receipt.get("dispatched")
        dispatch_status = "accepted" if dispatched is True else "not configured"
        reason = dispatch_receipt.get("reason")
        reason_label = f" ({html.escape(str(reason))})" if isinstance(reason, str) else ""
        dispatch = (
            f"<p>Worker dispatch: {html.escape(dispatch_status)}{reason_label}.</p>"
        )
    return f"""
        <article class="step done" aria-label="Latest protected action receipt">
          <h3>Latest protected action: {action}</h3>
          <p>{statement}</p>
          {dispatch}
          <small>Next proof required</small>
          {_list(proof_items)}
        </article>
"""


def _control_forms(
    job: HostedLaunchJob,
    *,
    control_token: str,
    job_token: str,
) -> str:
    if not control_token:
        return """
        <article class="step" aria-label="Protected controls unavailable">
          <h3>Protected controls unavailable</h3>
          <p>
            Start, stop, rollback, and detonation controls require a short-lived
            route-bound control token. FuseKit renders them disabled instead of
            pretending an unsafe or expired control can run.
          </p>
          <button type="button" disabled aria-disabled="true">Start worker</button>
          <button type="button" disabled aria-disabled="true">Stop launch</button>
          <button type="button" disabled aria-disabled="true">Request rollback</button>
          <button type="button" disabled aria-disabled="true">Request detonation</button>
        </article>
"""
    job_id = html.escape(job.job_id, quote=True)
    token = html.escape(control_token, quote=True)
    job_param = (
        "&amp;" + urllib.parse.urlencode({"job": job_token})
        if job_token
        else ""
    )
    start_action = f"/api/hosted/jobs/{job_id}/actions/start?control={token}{job_param}"
    stop_action = f"/api/hosted/jobs/{job_id}/actions/stop?control={token}{job_param}"
    rollback_action = f"/api/hosted/jobs/{job_id}/actions/rollback?control={token}{job_param}"
    detonate_action = f"/api/hosted/jobs/{job_id}/actions/detonate?control={token}{job_param}"
    if job.status == "waiting_for_worker":
        return f"""
        <form method="post" action="{start_action}">
          <button type="submit">Start worker</button>
        </form>
        <form method="post" action="{stop_action}">
          <button type="submit">Stop launch</button>
        </form>
"""
    if job.status == "stopped":
        return ""
    return f"""
        <form method="post" action="{rollback_action}">
          <button type="submit">Request rollback</button>
        </form>
        <form method="post" action="{detonate_action}">
          <button type="submit">Request detonation</button>
        </form>
"""


def _proof_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token:
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}/proof?"
        + urllib.parse.urlencode({"job": job_token}),
        quote=True,
    )
    return f'<a class="button" href="{href}">View proof receipt</a>'


def _proof_json_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token:
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}/proof?"
        + urllib.parse.urlencode({"job": job_token, "format": "json"}),
        quote=True,
    )
    return f'<a class="button" href="{href}">Download proof JSON</a>'


def _worker_request_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token or job.status == "waiting_for_worker":
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}/worker-request?"
        + urllib.parse.urlencode({"job": job_token}),
        quote=True,
    )
    return f'<a class="button" href="{href}">View worker request</a>'


def _control_room_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token:
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}?"
        + urllib.parse.urlencode({"job": job_token}),
        quote=True,
    )
    return f'<a class="button" href="{href}">Back to control room</a>'


def _replace_job(
    job: HostedLaunchJob,
    *,
    status: str,
    created_at: int,
    steps: tuple[HostedLaunchJobStep, ...],
) -> HostedLaunchJob:
    return HostedLaunchJob(
        job_id=job.job_id,
        app_name=job.app_name,
        github_source=job.github_source,
        status=status,
        created_at=created_at,
        steps=steps,
        proof=job.proof,
        rollback=job.rollback,
        detonation=job.detonation,
        worker_contract=job.worker_contract,
    )


def _update_steps(
    steps: tuple[HostedLaunchJobStep, ...],
    updates: dict[str, tuple[str, str]],
) -> tuple[HostedLaunchJobStep, ...]:
    result: list[HostedLaunchJobStep] = []
    for step in steps:
        if step.id not in updates:
            result.append(step)
            continue
        status, proof = updates[step.id]
        result.append(
            HostedLaunchJobStep(
                id=step.id,
                label=step.label,
                owner=step.owner,
                status=status,
                proof=proof,
            )
        )
    return tuple(result)


def _list(items: tuple[str, ...]) -> str:
    return "<ul>" + "\n".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"


def _worker_contract_section(contract: HostedWorkerContract) -> str:
    providers = _list(contract.providers or ("No providers detected yet",))
    permissions = _list(contract.permission_boundary)
    actions = _list(contract.approved_actions)
    gates = _list(contract.gates)
    artifacts = _list(contract.required_artifacts)
    guarantees = _list(contract.guarantees)
    return f"""
        <h2>Worker contract</h2>
        <p>
          FuseKit may not call this launch complete until the hosted worker produces
          the required redacted artifacts and keeps these guarantees.
        </p>
        <h3>Providers</h3>
        {providers}
        <h3>Permission boundary</h3>
        {permissions}
        <h3>Approved actions</h3>
        <p>
          Workers may run only these visible plan actions; drift requires a fresh approval.
        </p>
        {actions}
        <h3>Provider gates</h3>
        <p>
          These checkpoints remain human-owned; FuseKit must not bypass MFA,
          CAPTCHA, billing, fraud, consent, or domain ownership verification.
        </p>
        {gates}
        <h3>Required artifacts</h3>
        {artifacts}
        <h3>Guarantees</h3>
        {guarantees}
"""


def _reversal_playbook_section(playbook: list[dict[str, str]]) -> str:
    items = []
    for item in playbook:
        control = html.escape(item["control"])
        proof = html.escape(item["proof"])
        action_url = item.get("action_url", "")
        action = (
            f' <a href="{html.escape(action_url, quote=True)}">Open settings</a>'
            if action_url
            else ""
        )
        items.append(f"<li><strong>{control}:</strong> {proof}{action}</li>")
    return "<ul>" + "".join(items) + "</ul>"


def _completion_ready(job: HostedLaunchJob) -> bool:
    steps = {step.id: step.status for step in job.steps}
    return (
        job.status == "complete"
        and steps.get("proof.collect") == "done"
        and steps.get("rollback.ready") == "done"
        and steps.get("detonate.worker") == "done"
    )


def _proof_evidence(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("Hosted worker proof evidence is invalid.")
    evidence: dict[str, bool] = {}
    for key in HOSTED_WORKER_PROOF_KEYS:
        item = value.get(key)
        if not isinstance(item, bool):
            raise ValueError(f"Hosted worker proof evidence {key} must be boolean.")
        evidence[key] = item
    for key in HOSTED_WORKER_MAINTENANCE_PROOF_KEYS:
        item = value.get(key, False)
        if not isinstance(item, bool):
            raise ValueError(f"Hosted worker proof evidence {key} must be boolean.")
        evidence[key] = item
    allowed = set(HOSTED_WORKER_PROOF_KEYS) | set(HOSTED_WORKER_MAINTENANCE_PROOF_KEYS)
    unexpected = sorted(str(key) for key in value if key not in allowed)
    if unexpected:
        raise ValueError("Hosted worker proof evidence contains unsupported keys.")
    return evidence


def _maintenance_ready(job: HostedLaunchJob, evidence: dict[str, bool]) -> bool:
    if job.status == "rollback_requested":
        return (
            evidence["rollback_execution_receipt"]
            and evidence["post_rollback_verification"]
        )
    if job.status == "detonation_requested":
        return (
            evidence["workspace_detonation_receipt"]
            and evidence["scratch_state_destroyed"]
            and evidence["provider_auth_session_closed"]
            and evidence["redacted_public_proof_preserved"]
        )
    return True


def _maintenance_required_proof(job: HostedLaunchJob) -> list[str]:
    if job.status == "rollback_requested":
        return [
            "rollback_execution_receipt",
            "post_rollback_verification",
        ]
    if job.status == "detonation_requested":
        return [
            "workspace_detonation_receipt",
            "scratch_state_destroyed",
            "provider_auth_session_closed",
            "redacted_public_proof_preserved",
        ]
    return []


def _completed_artifacts(
    value: object,
    *,
    required_artifacts: tuple[str, ...],
) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Hosted worker proof completed_artifacts must be a list of strings.")
    required = set(required_artifacts)
    result: list[str] = []
    for item in value:
        artifact = item.strip()
        if artifact not in required:
            raise ValueError("Hosted worker proof includes an unsupported artifact.")
        if contains_durable_secret_text(artifact):
            raise ValueError("Hosted worker proof artifact contains credential-looking text.")
        if artifact not in result:
            result.append(artifact)
    return tuple(result)


def _public_note(value: object) -> str:
    raw = str(value or "")[:400]
    if contains_durable_secret_text(raw):
        raise ValueError("Hosted worker proof note contains credential-looking text.")
    note = redact_public_text(raw)
    if contains_durable_secret_text(note):
        raise ValueError("Hosted worker proof note contains credential-looking text.")
    return note


def _provider_gate_step(evidence: dict[str, bool]) -> tuple[str, str]:
    if evidence["retrieved_remote_artifacts"] and evidence["run_record"]:
        return (
            "done",
            "Provider gate records and wake events are present in retrieved remote artifacts.",
        )
    return (
        "waiting",
        "Waiting for provider-owned gates and retrieved gate-event proof.",
    )


def _setup_execute_step(completion_ready: bool) -> tuple[str, str]:
    if completion_ready:
        return ("done", "Approved setup plan completed with live proof and acceptance.")
    return (
        "running",
        "Worker submitted redacted proof; remaining live proof is still pending.",
    )


def _proof_collect_step(evidence: dict[str, bool]) -> tuple[str, str]:
    required = (
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "retrieved_remote_artifacts",
        "run_record",
        "live_acceptance_report",
        "recording",
    )
    if all(evidence[key] for key in required):
        return (
            "done",
            "Live URL, verifiers, DNS, remote artifacts, Run Record, and recording proof passed.",
        )
    return (
        "waiting",
        "Waiting for live URL, verifiers, DNS, remote artifacts, Run Record, and recording proof.",
    )


def _rollback_step(
    evidence: dict[str, bool],
    *,
    execution_required: bool = False,
) -> tuple[str, str]:
    if execution_required and (
        not evidence["rollback_execution_receipt"]
        or not evidence["post_rollback_verification"]
    ):
        return (
            "waiting",
            "Waiting for rollback execution receipt and post-rollback verification.",
        )
    if evidence["rollback_metadata"]:
        return ("done", "Rollback metadata is present in the redacted proof bundle.")
    return ("waiting", "Waiting for rollback metadata before completion can be claimed.")


def _detonation_step(
    evidence: dict[str, bool],
    *,
    execution_required: bool = False,
) -> tuple[str, str]:
    if execution_required and (
        not evidence["workspace_detonation_receipt"]
        or not evidence["scratch_state_destroyed"]
        or not evidence["provider_auth_session_closed"]
        or not evidence["redacted_public_proof_preserved"]
    ):
        return (
            "waiting",
            "Waiting for workspace detonation receipt, scratch cleanup, "
            "auth-session closure, and preserved public proof.",
        )
    if evidence["detonation_receipt"]:
        return ("done", "Hosted worker detonation receipt is present.")
    return ("waiting", "Waiting for hosted worker detonation receipt.")


def _public_worker_id(value: str) -> str:
    sanitized = "".join(
        character for character in value.strip()[:80] if character.isalnum() or character in "-_"
    )
    return sanitized or "hosted-worker"


def _public_action(action: str) -> str:
    if action in {"start", "stop", "rollback", "detonate"}:
        return action
    return "unsupported"


def _action_receipt_statement(action: str) -> str:
    if action == "start":
        return "Hosted worker start was requested; public proof is still pending."
    if action == "stop":
        return "Hosted launch was stopped before worker start; no provider mutation is approved."
    if action == "rollback":
        return "Rollback was requested; FuseKit must use rollback metadata before provider cleanup."
    if action == "detonate":
        return (
            "Detonation was requested; FuseKit must preserve redacted proof and "
            "destroy plaintext worker state."
        )
    return "Unsupported hosted action was rejected."


def _action_next_required_proof(action: str) -> list[str]:
    if action == "start":
        return [
            "worker_claim",
            "provider_gate_events",
            *HOSTED_WORKER_PROOF_KEYS,
        ]
    if action == "stop":
        return [
            "stop_receipt",
            "no_worker_claim_after_stop",
            "no_provider_mutation_after_stop",
            "redacted_public_proof_preserved",
        ]
    if action == "rollback":
        return [
            "rollback_plan",
            "provider_resource_inventory",
            "rollback_execution_receipt",
            "post_rollback_verification",
        ]
    if action == "detonate":
        return [
            "workspace_detonation_receipt",
            "scratch_state_destroyed",
            "provider_auth_session_closed",
            "redacted_public_proof_preserved",
        ]
    return []


def _worker_contract_from_dict(payload: dict[str, Any]) -> HostedWorkerContract:
    if payload.get("schema_version") != HOSTED_WORKER_CONTRACT_SCHEMA_VERSION:
        raise FuseKitError("Hosted worker contract schema is unsupported.")
    github_installation_id = payload.get("github_installation_id")
    if github_installation_id is not None and not isinstance(github_installation_id, int):
        raise FuseKitError("Hosted worker contract github_installation_id is invalid.")
    return HostedWorkerContract(
        lane=_required_str(payload, "lane"),
        github_source=_required_str(payload, "github_source"),
        github_installation_id=github_installation_id,
        providers=_str_tuple(payload.get("providers"), "providers"),
        required_env=_str_tuple(payload.get("required_env"), "required_env"),
        permission_boundary=_str_tuple(
            payload.get("permission_boundary", []),
            "permission_boundary",
        ),
        approved_actions=_str_tuple(payload.get("approved_actions"), "approved_actions"),
        required_artifacts=_str_tuple(payload.get("required_artifacts"), "required_artifacts"),
        gates=_str_tuple(payload.get("gates"), "gates"),
        guarantees=_str_tuple(payload.get("guarantees"), "guarantees"),
    )


def _job_step_from_dict(payload: object) -> HostedLaunchJobStep:
    if not isinstance(payload, dict):
        raise FuseKitError("Hosted launch job step payload is invalid.")
    return HostedLaunchJobStep(
        id=_required_str(payload, "id"),
        label=_required_str(payload, "label"),
        owner=_required_str(payload, "owner"),
        status=_required_str(payload, "status"),
        proof=_required_str(payload, "proof"),
    )


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise FuseKitError(f"Hosted launch job {key} is invalid.")
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise FuseKitError(f"Hosted launch job {key} is invalid.")
    return value


def _str_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise FuseKitError(f"Hosted launch job {key} list is invalid.")
    return tuple(value)


def _sign(secret: str, payload: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return _base64url(digest)


def _base64url_json(value: dict[str, object]) -> str:
    return _base64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _decode_json(value: str) -> dict[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("Hosted launcher job token payload is invalid.") from exc
    if not isinstance(decoded, dict):
        raise FuseKitError("Hosted launcher job token payload must be an object.")
    return decoded


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
