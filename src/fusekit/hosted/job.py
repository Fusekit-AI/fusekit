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
from typing import Any, cast

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_PAYMENT_SCHEMA_VERSION,
    STRIPE_CHECKOUT_METADATA_KEYS,
    STRIPE_CHECKOUT_PROVIDER,
    _valid_price_label,
)
from fusekit.hosted.evidence import HOSTED_COMPLETION_EVIDENCE_KEYS
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    BYO_OCI_RUNNER_PROFILE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_runner_shape_guard,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
    hosted_launch_lane,
    valid_hosted_launch_lane,
)
from fusekit.hosted.launcher import (
    HOSTED_PROHIBITED_ACTIONS,
    HostedLaunchPlan,
    public_hosted_action_id,
    public_hosted_app_name,
    public_hosted_env_name,
    public_hosted_github_source,
    public_hosted_provider_name,
)
from fusekit.hosted.script_json import json_script_payload
from fusekit.runner.cloud_shell import build_cloud_shell_launch_plan
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
HOSTED_BYO_OCI_BOOTSTRAP_SCHEMA_VERSION = "fusekit.hosted-byo-oci-bootstrap.v1"
HOSTED_BYO_OCI_FUSEKIT_PACKAGE = "fusekit"
HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION = "fusekit.hosted-byo-oci-preflight.v1"
HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION = "fusekit.hosted-byo-oci-reversibility.v1"
HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION = "fusekit.hosted-byo-oci-proof-manifest.v1"
HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION = "fusekit.hosted-byo-oci-proof-bundle.v1"
HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION = "fusekit.hosted-byo-oci-proof-verify.v1"
HOSTED_BYO_ZERO_BYTE_ALLOWED_ARTIFACTS = frozenset({".fusekit/gate_events.jsonl"})

HOSTED_WORKER_PROOF_KEYS = HOSTED_COMPLETION_EVIDENCE_KEYS
HOSTED_WORKER_MAINTENANCE_PROOF_KEYS = (
    "rollback_execution_receipt",
    "post_rollback_verification",
    "workspace_detonation_receipt",
    "scratch_state_destroyed",
    "provider_auth_session_closed",
    "redacted_public_proof_preserved",
)
HOSTED_BYO_OCI_HANDOFF_PREFLIGHT = (
    {
        "id": "review_oracle_billing",
        "label": "Review Oracle Cloud billing status before opening Cloud Shell.",
        "required": True,
        "proof": "The bootstrap states that OCI spend belongs to the user's tenancy.",
    },
    {
        "id": "confirm_amd_shape",
        "label": "Confirm the bootstrap uses the AMD/x86_64 runner profile.",
        "required": True,
        "proof": "The Cloud Shell command includes the exact non-ARM OCI shape.",
    },
    {
        "id": "keep_human_gates_human",
        "label": "Pass Oracle, GitHub, billing, consent, CAPTCHA, and MFA gates yourself.",
        "required": True,
        "proof": "FuseKit records provider gates as human-owned instead of bypassed.",
    },
    {
        "id": "return_redacted_proof",
        "label": "Return only the encrypted/redacted remote artifact bundle after the run.",
        "required": True,
        "proof": (
            "Completion waits for remote artifacts, Run Record, detonation, acceptance, "
            "and recording proof."
        ),
    },
)
HOSTED_BYO_OCI_REVERSIBILITY_TARGETS = (
    "remote plaintext worker state",
    "disposable OCI compute instance",
    "boot volume",
    "FuseKit-created network resources",
)
HOSTED_BYO_OCI_REVERSIBILITY_SURVIVORS = (
    "encrypted vault",
    "redacted audit log",
    "redacted setup receipt",
    "Run Record",
    "workspace detonation receipt",
)
HOSTED_BYO_OCI_PROOF_ARTIFACT_LABELS = {
    ".fusekit/job.json": "durable hosted job snapshot",
    ".fusekit/run_record.json": "central Run Record",
    ".fusekit/verification_report.json": "provider verifier report",
    ".fusekit/rollback_plan.json": "rollback metadata",
    ".fusekit/setup_receipt.json": "redacted setup receipt",
    ".fusekit/audit.jsonl": "redacted audit log",
    ".fusekit/provider_strategies.json": "provider strategy proof",
    ".fusekit/runner_readiness.json": "runner readiness proof",
    ".fusekit/gates.json": "provider gate state",
    ".fusekit/gate_events.jsonl": "provider gate event stream",
    ".fusekit/llm_contract.json": "LLM/model contract",
    ".fusekit/workspace_detonation.json": "workspace detonation receipt",
    ".fusekit/acceptance_report.json": "live acceptance report",
}
HOSTED_PLAN_INTEGRITY_COVERAGE = (
    "app_name",
    "github_source",
    "providers",
    "required_env",
    "approved_actions",
    "required_artifacts",
    "provider_gates",
    "worker_guarantees",
)
HOSTED_WORKER_REQUIRED_ARTIFACTS = (
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
HOSTED_JOB_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "app_name",
        "github_source",
        "status",
        "created_at",
        "steps",
        "proof",
        "rollback",
        "detonation",
        "launch_lane",
        "lane_contract",
        "payment",
        "worker_contract",
    }
)
HOSTED_JOB_TOKEN_KEYS = frozenset({"schema_version", "issued_at", "job"})
HOSTED_JOB_STEP_KEYS = frozenset({"id", "label", "owner", "status", "proof"})
HOSTED_PLAN_INTEGRITY_KEYS = frozenset(
    {"algorithm", "fingerprint", "covers", "secret_boundary"}
)
HOSTED_WORKER_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "lane",
        "github_source",
        "github_installation_id",
        "plan_integrity",
        "source_token_policy",
        "providers",
        "required_env",
        "permission_boundary",
        "approved_actions",
        "required_artifacts",
        "gates",
        "guarantees",
    }
)
HOSTED_WORKER_GUARANTEES = (
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
)


@dataclass(frozen=True)
class HostedWorkerContract:
    """Public, non-secret contract the hosted worker must satisfy."""

    lane: str
    github_source: str
    github_installation_id: int | None
    plan_fingerprint: str
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
            "plan_integrity": self.plan_integrity(),
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

    def plan_integrity(self) -> dict[str, object]:
        """Return public integrity metadata for the approved hosted plan."""

        return {
            "algorithm": "sha256",
            "fingerprint": self.plan_fingerprint,
            "covers": list(HOSTED_PLAN_INTEGRITY_COVERAGE),
            "secret_boundary": (
                "Plan integrity covers only non-secret approved-plan metadata: app name, "
                "source repository URL, provider names, environment variable names, action "
                "ids, artifact labels, human-gate labels, and worker guarantees."
            ),
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
    launch_lane: str = MANAGED_FUSEKIT_RUN_LANE
    payment_status: str = "not_required"
    payment_price_label: str = ""
    payment_price_id_hash: str = ""
    payment_receipt: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize a browser-safe hosted job."""

        payload: dict[str, object] = {
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
            "launch_lane": self.launch_lane,
            "lane_contract": hosted_launch_lane(self.launch_lane).to_dict(),
            "payment": hosted_job_payment_status(self),
            "worker_contract": self.worker_contract.to_dict(),
        }
        _assert_public_hosted_job(payload)
        return payload


def build_hosted_launch_job(
    plan: HostedLaunchPlan,
    *,
    github_installation_id: int | None = None,
    launch_lane: str = MANAGED_FUSEKIT_RUN_LANE,
    payment_required: bool = False,
    payment_price_label: str = "",
    payment_price_id_hash: str = "",
    job_id: str | None = None,
    now: int | None = None,
) -> HostedLaunchJob:
    """Create the public control-room job contract for an approved hosted plan."""

    lane = hosted_launch_lane(launch_lane).lane_id
    public_app_name = public_hosted_app_name(plan.app_name)
    public_source = public_hosted_github_source(plan.github_source)
    worker_contract = build_hosted_worker_contract(
        plan,
        github_installation_id=github_installation_id,
        launch_lane=lane,
    )
    payment_status = (
        "payment_required"
        if payment_required and lane == MANAGED_FUSEKIT_RUN_LANE
        else "not_required"
    )
    if payment_status == "payment_required" and not _valid_price_label(payment_price_label):
        raise FuseKitError("Hosted launch payment price label is required.")
    if payment_status == "payment_required" and not _valid_sha256_label(payment_price_id_hash):
        raise FuseKitError("Hosted launch payment price id hash is required.")
    if payment_price_id_hash and not _valid_sha256_label(payment_price_id_hash):
        raise FuseKitError("Hosted launch payment price id hash is invalid.")
    worker_prepare_proof = (
        "Stripe Checkout authorization must complete before FuseKit-managed worker dispatch."
        if payment_status == "payment_required"
        else "Worker identity, runner, and vault session proof will appear here."
    )
    provider_gate_proof = (
        (
            "Oracle Cloud login, tenancy, compartment, and billing gates stay in "
            "the user's OCI account."
        )
        if lane == BYO_OCI_LANE
        else "MFA, billing, consent, CAPTCHA, and copy-once secret screens stay provider-owned."
    )
    return HostedLaunchJob(
        job_id=job_id or f"hosted-{secrets.token_urlsafe(12)}",
        app_name=public_app_name,
        github_source=public_source,
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
                worker_prepare_proof,
            ),
            HostedLaunchJobStep(
                "provider.gates",
                "Complete provider-owned gates",
                "user",
                "pending",
                provider_gate_proof,
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
        launch_lane=lane,
        payment_status=payment_status,
        payment_price_label=payment_price_label if payment_status == "payment_required" else "",
        payment_price_id_hash=(
            payment_price_id_hash
            if payment_status == "payment_required"
            else ""
        ),
    )


def hosted_job_payment_status(job: HostedLaunchJob) -> dict[str, object]:
    """Return browser-safe payment status for a hosted job."""

    status = job.payment_status
    if not isinstance(status, str):
        raise FuseKitError("Hosted launch payment status is invalid.")
    if status not in {"not_required", "payment_required", "checkout_pending", "paid"}:
        raise FuseKitError("Hosted launch payment status is unsupported.")
    if job.launch_lane != MANAGED_FUSEKIT_RUN_LANE and status != "not_required":
        raise FuseKitError("Hosted launch payment status is invalid for lane.")
    if job.payment_price_label and not _valid_price_label(job.payment_price_label):
        raise FuseKitError("Hosted launch payment price label is invalid.")
    if job.payment_price_id_hash and not _valid_sha256_label(job.payment_price_id_hash):
        raise FuseKitError("Hosted launch payment price id hash is invalid.")
    if status != "not_required" and not job.payment_price_label:
        raise FuseKitError("Hosted launch payment price label is required.")
    if status != "not_required" and not job.payment_price_id_hash:
        raise FuseKitError("Hosted launch payment price id hash is required.")
    if status == "not_required" and (job.payment_price_label or job.payment_price_id_hash):
        raise FuseKitError("Hosted launch payment price is invalid for status.")
    if job.payment_receipt is None:
        receipt: dict[str, object] = {}
    elif not isinstance(job.payment_receipt, dict):
        raise FuseKitError("Hosted launch payment receipt is invalid.")
    else:
        receipt = _public_payment_receipt(job.payment_receipt)
    if status == "paid":
        if not _payment_receipt_is_paid_checkout(receipt):
            raise FuseKitError("Hosted launch paid payment receipt is invalid.")
        if not _payment_receipt_matches_job(job, receipt):
            raise FuseKitError("Hosted launch paid payment receipt does not match this job.")
    elif _payment_receipt_is_paid_checkout(receipt):
        raise FuseKitError("Hosted launch payment status does not match receipt.")
    if status == "not_required" and receipt:
        raise FuseKitError("Hosted launch payment receipt is invalid for status.")
    return {
        "required": job.launch_lane == MANAGED_FUSEKIT_RUN_LANE
        and status != "not_required",
        "status": status,
        "price_label": job.payment_price_label,
        "price_id_hash": job.payment_price_id_hash,
        "receipt": receipt,
        "secret_boundary": (
            "Payment status contains only public Checkout Session state and never card "
            "numbers, CVC, payment method ids, billing details, Stripe secret keys, or "
            "client secrets."
        ),
    }


def with_hosted_job_payment_receipt(
    job: HostedLaunchJob,
    receipt: dict[str, object],
) -> HostedLaunchJob:
    """Return a job updated with a redacted payment receipt."""

    public_receipt = _public_payment_receipt(receipt)
    paid_checkout = _payment_receipt_is_paid_checkout(public_receipt)
    if paid_checkout and not _payment_receipt_matches_job(job, public_receipt):
        raise FuseKitError("Hosted launch paid payment receipt does not match this job.")
    status = "paid" if paid_checkout else "checkout_pending"
    return _replace_job(
        job,
        status=job.status,
        created_at=job.created_at,
        steps=_update_steps(
            job.steps,
            {
                "worker.prepare": (
                    "pending" if status != "paid" else "waiting",
                    _payment_step_proof(status),
                )
            },
        ),
        payment_status=status,
        payment_receipt=public_receipt,
    )


def hosted_byo_oci_bootstrap(job: HostedLaunchJob) -> dict[str, object]:
    """Return a redacted BYO OCI bootstrap contract for a user-owned worker lane."""

    cloud_shell_plan = build_cloud_shell_launch_plan(
        app_source=job.github_source,
        fusekit_package=HOSTED_BYO_OCI_FUSEKIT_PACKAGE,
        runner="oci-existing",
        launch_args=_byo_oci_launch_args(job),
    )
    payload: dict[str, object] = {
        "schema_version": HOSTED_BYO_OCI_BOOTSTRAP_SCHEMA_VERSION,
        "job_id": job.job_id,
        "lane": BYO_OCI_LANE,
        "worker_dispatch": "not_applicable_user_owned_oci",
        "runner_shape_policy": "AMD/x86_64 only; ARM images are not allowed.",
        "runner_shape_guard": byo_oci_runner_shape_guard(),
        "runner_profile": dict(BYO_OCI_RUNNER_PROFILE),
        "open_core_execution": {
            "mode": "user-owned-oci-cloud-shell",
            "fusekit_package": HOSTED_BYO_OCI_FUSEKIT_PACKAGE,
            "app_source": job.github_source,
            "github_source_policy": (
                "Cloud Shell fetches the selected GitHub source through FuseKit source "
                "handoff. Private source access is approved by the user inside provider-owned "
                "GitHub gates, not by exposing hosted GitHub installation tokens."
            ),
            "worker_secret_required": False,
            "hosted_github_private_key_required": False,
        },
        "user_owned_cost_boundary": byo_oci_user_owned_cost_boundary(),
        "byo_security_contract": byo_oci_security_contract(),
        "handoff_preflight": {
            "schema_version": HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION,
            "must_be_visible_before_cloud_shell": True,
            "checks": [dict(check) for check in HOSTED_BYO_OCI_HANDOFF_PREFLIGHT],
            "cost_acknowledgement": {
                "required": True,
                "spend_owner": "user_oci_tenancy",
                "fusekit_fee": "none_for_byo_oci",
                "oracle_billing_gate_owner": "oracle_cloud",
                "statement": (
                    "Starting BYO OCI can create Oracle Cloud resources in the user's "
                    "tenancy; FuseKit-managed infrastructure spend remains zero."
                ),
            },
            "secret_boundary": (
                "BYO preflight contains public review labels only. It does not contain OCI "
                "credentials, payment methods, GitHub installation tokens, or vault material."
            ),
        },
        "cloud_shell": {
            "provider": "oci-cloud-shell",
            "requires_user_oci_account": True,
            "deeplink_url": cloud_shell_plan.deeplink_url,
            "bootstrap_command": cloud_shell_plan.bootstrap_command,
            "fallback_steps": list(cloud_shell_plan.fallback_steps),
            "human_gates": [
                "Oracle Cloud sign-in, MFA, tenancy selection, and billing gates",
                "Compartment and region selection",
            ],
            "bootstrap_intent": (
                "Open Oracle Cloud Shell and run open-core FuseKit from the selected source "
                "inside the user's tenancy. Hosted worker secrets and hosted GitHub App "
                "private keys are not exported to BYO OCI."
            ),
        },
        "proof_return": {
            "mode": "user_downloads_or_shares_redacted_artifacts",
            "required_artifacts": list(job.worker_contract.required_artifacts),
            "acceptance_command": (
                "fusekit acceptance run <app> --mode live "
                "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
            ),
            "not_hosted_complete_until": list(HOSTED_WORKER_PROOF_KEYS),
            "verifier_contract": {
                "input_schema": HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION,
                "output_schema": HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION,
                "requires_job_binding": True,
                "job_binding_fields": [
                    "job_id",
                    "lane",
                    "github_source_hash",
                    "plan_fingerprint",
                ],
                "requires_redacted_artifacts": True,
                "requires_completion_evidence": list(HOSTED_WORKER_PROOF_KEYS),
            },
        },
        "proof_manifest": _byo_oci_proof_manifest(job),
        "reversibility": {
            "schema_version": HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION,
            "detonation_required": True,
            "rollback_metadata_required": True,
            "delete_targets": list(HOSTED_BYO_OCI_REVERSIBILITY_TARGETS),
            "survivors": list(HOSTED_BYO_OCI_REVERSIBILITY_SURVIVORS),
            "completion_receipt": ".fusekit/workspace_detonation.json",
            "post_run_acceptance_required": (
                "fusekit acceptance run <app> --mode live "
                "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
            ),
            "statement": (
                "A BYO OCI run is not considered complete until reversible setup proof, "
                "retrieved redacted artifacts, and workspace detonation proof are present."
            ),
        },
        "worker_request": hosted_worker_request(job),
        "secret_boundary": (
            "The BYO OCI bootstrap contains open-core launch instructions, public source "
            "labels, and proof labels only. It does not contain Oracle credentials, GitHub "
            "installation tokens, hosted worker secrets, hosted GitHub private keys, API keys, "
            "vault material, or provider secrets."
        ),
    }
    _assert_public_byo_oci_bootstrap(payload)
    return payload


def render_hosted_byo_oci_bootstrap(job: HostedLaunchJob, *, job_token: str = "") -> str:
    """Render the BYO OCI bootstrap as a browser-readable handoff page."""

    bootstrap = hosted_byo_oci_bootstrap(job)
    cloud_shell = bootstrap.get("cloud_shell")
    proof_return = bootstrap.get("proof_return")
    proof_manifest = bootstrap.get("proof_manifest")
    handoff = bootstrap.get("handoff_preflight")
    reversibility = bootstrap.get("reversibility")
    cloud_shell_data = cloud_shell if isinstance(cloud_shell, dict) else {}
    proof_data = proof_return if isinstance(proof_return, dict) else {}
    proof_manifest_data = proof_manifest if isinstance(proof_manifest, dict) else {}
    handoff_data = handoff if isinstance(handoff, dict) else {}
    reversibility_data = reversibility if isinstance(reversibility, dict) else {}
    deeplink = _safe_cloud_shell_url(cloud_shell_data.get("deeplink_url"))
    command = str(cloud_shell_data.get("bootstrap_command", ""))
    payload = json_script_payload(bootstrap)
    fallback = _list(_string_tuple(cloud_shell_data.get("fallback_steps")))
    human_gates = _list(_string_tuple(cloud_shell_data.get("human_gates")))
    required_artifacts = _list(_string_tuple(proof_data.get("required_artifacts")))
    not_complete_until = _list(_string_tuple(proof_data.get("not_hosted_complete_until")))
    manifest_artifacts = _proof_artifact_cards(
        proof_manifest_data.get("required_remote_artifacts")
    )
    manifest_evidence = _list(
        _string_tuple(proof_manifest_data.get("required_completion_evidence"))
    )
    proof_bundle_root = html.escape(str(proof_manifest_data.get("proof_bundle_root", "")))
    preflight = _preflight_cards(handoff_data.get("checks"))
    cost_acknowledgement = _cost_acknowledgement_section(
        handoff_data.get("cost_acknowledgement")
    )
    delete_targets = _list(_string_tuple(reversibility_data.get("delete_targets")))
    survivors = _list(_string_tuple(reversibility_data.get("survivors")))
    acceptance_command = html.escape(str(proof_data.get("acceptance_command", "")))
    json_link = _byo_oci_json_link(job, job_token=job_token)
    control_room_link = _control_room_link(job, job_token=job_token)
    app_name = html.escape(job.app_name)
    github_source = html.escape(job.github_source)
    job_id = html.escape(job.job_id)
    command_block = (
        f"<pre>{html.escape(command)}</pre>"
        if command
        else "<p>Bootstrap command is unavailable for this job.</p>"
    )
    cloud_shell_button = (
        f'<a class="button" href="{html.escape(deeplink, quote=True)}">'
        "Open Oracle Cloud Shell</a>"
        if deeplink
        else (
            '<span class="button disabled" aria-disabled="true">'
            "Oracle Cloud Shell unavailable</span>"
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit BYO OCI bootstrap</title>
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
    h1 {{ font-size: clamp(34px, 5vw, 58px); line-height: 1; letter-spacing: 0; }}
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
    article {{
      border: 1px solid var(--line);
      border-left: 4px solid var(--amber);
      border-radius: 6px;
      padding: 10px 12px;
      display: grid;
      gap: 4px;
    }}
    article.done {{ border-left-color: var(--green); }}
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
    }}
    .button.disabled {{
      background: #d8e1ea;
      border-color: #aebcca;
      color: #52616f;
    }}
    ul {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    li + li {{ margin-top: 6px; }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #0f1720;
      color: #f8fbff;
      border-radius: 6px;
      padding: 12px;
      font-size: 13px;
      line-height: 1.45;
    }}
    script[type="application/json"] {{ display: none; }}
    @media (max-width: 880px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="source">{job_id} / bring your own OCI</p>
      <h1>BYO OCI handoff.</h1>
      <p>
        {app_name} will run in your Oracle Cloud tenancy. FuseKit charges no managed-run
        fee for this lane, does not dispatch FuseKit-owned worker infrastructure, and
        keeps hosted worker secrets out of this handoff.
      </p>
      <p class="source">{github_source}</p>
    </header>
    <div class="grid">
      <section aria-label="Before opening Cloud Shell">
        <h2>Before Opening Cloud Shell</h2>
        {cost_acknowledgement}
        {preflight}
      </section>
      <aside aria-label="Cloud Shell launch">
        <h2>Cloud Shell Launch</h2>
        {cloud_shell_button}
        <h3>Fallback Command</h3>
        {command_block}
        <h3>Fallback Steps</h3>
        {fallback}
        <h3>Human Gates</h3>
        {human_gates}
      </aside>
    </div>
    <div class="grid">
      <section aria-label="Proof return">
        <h2>Proof Return</h2>
        <p>Hosted completion waits for these redacted artifacts and proof labels.</p>
        <h3>Required Artifacts</h3>
        {required_artifacts}
        <h3>Not Complete Until</h3>
        {not_complete_until}
        <h3>Acceptance Command</h3>
        <pre>{acceptance_command}</pre>
        <h3>Proof Manifest</h3>
        <p>Bundle root: {proof_bundle_root}</p>
        {manifest_artifacts}
        <h3>Completion Evidence</h3>
        {manifest_evidence}
      </section>
      <aside aria-label="Reversible setup">
        <h2>Reversible Setup</h2>
        <p>{html.escape(str(reversibility_data.get("statement", "")))}</p>
        <h3>Delete Targets</h3>
        {delete_targets}
        <h3>Survivors</h3>
        {survivors}
      </aside>
    </div>
    <section aria-label="Boundary">
      <h2>Secret Boundary</h2>
      <p>{html.escape(str(bootstrap.get("secret_boundary", "")))}</p>
      {json_link}
      {control_room_link}
    </section>
    <script id="fusekit-byo-oci-bootstrap" type="application/json">{payload}</script>
  </main>
</body>
</html>
"""


def _byo_oci_proof_manifest(job: HostedLaunchJob) -> dict[str, object]:
    return {
        "schema_version": HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION,
        "job_binding": _byo_oci_proof_job_binding(job),
        "user_owned_cost_boundary": byo_oci_user_owned_cost_boundary(),
        "byo_security_contract": byo_oci_security_contract(),
        "runner_shape_guard": byo_oci_runner_shape_guard(),
        "proof_bundle_root": ".fusekit/remote-artifacts",
        "required_completion_evidence": list(HOSTED_WORKER_PROOF_KEYS),
        "required_remote_artifacts": [
            {
                "path": artifact,
                "label": HOSTED_BYO_OCI_PROOF_ARTIFACT_LABELS.get(
                    artifact,
                    "redacted FuseKit survivor artifact",
                ),
                "required": True,
                "secret_boundary": "redacted_public_artifact_only",
            }
            for artifact in job.worker_contract.required_artifacts
        ],
        "acceptance_gate": {
            "mode": "live",
            "remote_artifacts": ".fusekit/remote-artifacts",
            "require_recording": True,
            "command": (
                "fusekit acceptance run <app> --mode live "
                "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
            ),
        },
        "completion_claim_policy": (
            "BYO OCI completion cannot be claimed until every required artifact is "
            "retrieved from the user-owned worker, the live acceptance report passes with "
            "remote artifacts and recording proof, and detonation proof is preserved."
        ),
        "secret_boundary": (
            "The proof manifest contains public labels and artifact paths only; raw "
            "provider credentials, session cookies, payment details, tokens, vault "
            "plaintext, browser profiles, and worker-local paths are not allowed."
        ),
    }


def verify_hosted_byo_oci_proof_bundle(
    job: HostedLaunchJob,
    bundle: dict[str, object],
) -> dict[str, object]:
    """Verify a returned BYO OCI artifact inventory without exposing contents."""

    manifest = _byo_oci_proof_manifest(job)
    required_artifacts = _manifest_artifact_labels(manifest)
    blockers: list[str] = []
    allowed_bundle_fields = {
        "schema_version",
        "job_binding",
        "user_owned_cost_boundary",
        "byo_security_contract",
        "runner_shape_guard",
        "proof_bundle_root",
        "artifacts",
        "completion_evidence",
    }
    unexpected_bundle_fields = sorted(
        _public_byo_sidecar_field_name(key) for key in bundle if key not in allowed_bundle_fields
    )
    blockers.extend(
        f"byo_oci_proof_bundle_unexpected_field:{key}" for key in unexpected_bundle_fields
    )
    if job.launch_lane != BYO_OCI_LANE:
        blockers.append("byo_oci_proof_bundle_job_lane_mismatch")
    if bundle.get("schema_version") != HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION:
        blockers.append("byo_oci_proof_bundle_schema_invalid")
    expected_binding = _byo_oci_proof_job_binding(job)
    binding = _public_byo_job_binding(bundle.get("job_binding"), blockers=blockers)
    for key, expected_value in expected_binding.items():
        if binding.get(key) != expected_value:
            blockers.append(f"byo_oci_proof_bundle_{key}_mismatch")
    if bundle.get("proof_bundle_root") != manifest["proof_bundle_root"]:
        blockers.append("byo_oci_proof_bundle_root_mismatch")
    user_owned_cost_boundary = _public_byo_contract(
        bundle.get("user_owned_cost_boundary"),
        expected=byo_oci_user_owned_cost_boundary(),
        name="user_owned_cost_boundary",
        blockers=blockers,
    )
    byo_security_contract = _public_byo_contract(
        bundle.get("byo_security_contract"),
        expected=byo_oci_security_contract(),
        name="byo_security_contract",
        blockers=blockers,
    )
    runner_shape_guard = _public_byo_contract(
        bundle.get("runner_shape_guard"),
        expected=byo_oci_runner_shape_guard(),
        name="runner_shape_guard",
        blockers=blockers,
    )
    artifacts = _public_byo_artifact_inventory(bundle.get("artifacts"), blockers=blockers)
    present_paths = {str(artifact["path"]) for artifact in artifacts}
    missing = [path for path in required_artifacts if path not in present_paths]
    unexpected = [path for path in present_paths if path not in required_artifacts]
    blockers.extend(f"missing_artifact:{path}" for path in missing)
    blockers.extend(f"unexpected_artifact:{path}" for path in unexpected)
    for artifact in artifacts:
        path = str(artifact["path"])
        expected_label = required_artifacts.get(path)
        if expected_label is None:
            artifact["label"] = ""
        elif artifact.get("label") != expected_label:
            blockers.append(f"artifact_label_mismatch:{path}")
            artifact["label"] = ""
        if artifact.get("redacted") is not True:
            blockers.append(f"artifact_not_marked_redacted:{path}")
        if not _valid_sha256_label(str(artifact.get("sha256", ""))):
            blockers.append(f"artifact_sha256_invalid:{path}")
            artifact["sha256"] = ""
        if path in required_artifacts and artifact.get("size_bytes") == 0:
            if path not in HOSTED_BYO_ZERO_BYTE_ALLOWED_ARTIFACTS:
                blockers.append(f"artifact_empty:{path}")
    evidence = _public_completion_evidence(bundle.get("completion_evidence"), blockers=blockers)
    missing_evidence = [key for key in HOSTED_WORKER_PROOF_KEYS if evidence.get(key) is not True]
    blockers.extend(f"missing_completion_evidence:{key}" for key in missing_evidence)
    invalid_required_artifacts = _invalid_required_artifacts(
        required_artifacts,
        present_paths=present_paths,
        blockers=blockers,
    )
    report = {
        "schema_version": HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION,
        "input_schema_version": bundle.get("schema_version")
        if isinstance(bundle.get("schema_version"), str)
        else "",
        "job_id": job.job_id,
        "lane": job.launch_lane,
        "job_binding": binding,
        "ready": not blockers,
        "blockers": blockers,
        "proof_bundle_root": manifest["proof_bundle_root"],
        "user_owned_cost_boundary": user_owned_cost_boundary,
        "byo_security_contract": byo_security_contract,
        "runner_shape_guard": runner_shape_guard,
        "artifact_summary": {
            "required_count": len(required_artifacts),
            "present_required_count": (
                len(required_artifacts) - len(missing) - len(invalid_required_artifacts)
            ),
            "missing": missing,
            "unexpected": unexpected,
            "invalid_required": invalid_required_artifacts,
            "artifacts": artifacts,
        },
        "completion_evidence": {
            key: evidence.get(key) is True for key in HOSTED_WORKER_PROOF_KEYS
        },
        "acceptance_gate": manifest["acceptance_gate"],
        "secret_boundary": (
            "BYO OCI proof verification reads only a redacted artifact inventory, public "
            "paths, labels, hashes, sizes, and completion booleans. It must not include "
            "OCI credentials, provider secrets, GitHub tokens, payment details, vault "
            "plaintext, browser profiles, raw logs, worker-local paths, or artifact contents."
        ),
    }
    _assert_public_byo_proof_report(report)
    return report


def _byo_oci_proof_job_binding(job: HostedLaunchJob) -> dict[str, str]:
    return {
        "job_id": job.job_id,
        "lane": job.launch_lane,
        "github_source_hash": _github_source_hash(job.github_source),
        "plan_fingerprint": job.worker_contract.plan_fingerprint,
    }


def _public_byo_job_binding(
    value: object,
    *,
    blockers: list[str],
) -> dict[str, str]:
    allowed = {"job_id", "lane", "github_source_hash", "plan_fingerprint"}
    hash_keys = {"github_source_hash", "plan_fingerprint"}
    if not isinstance(value, dict):
        blockers.append("byo_oci_proof_bundle_job_binding_invalid")
        return {}
    unexpected = sorted(_public_byo_sidecar_field_name(key) for key in value if key not in allowed)
    blockers.extend(
        f"byo_oci_proof_bundle_job_binding_unexpected_field:{key}" for key in unexpected
    )
    binding: dict[str, str] = {}
    for key in allowed:
        raw = value.get(key)
        if not isinstance(raw, str) or not raw:
            blockers.append(f"byo_oci_proof_bundle_{key}_missing")
            continue
        if contains_durable_secret_text(raw) or len(raw) > 256:
            blockers.append(f"byo_oci_proof_bundle_{key}_unsafe")
            continue
        if key in hash_keys and not _valid_sha256_label(raw):
            blockers.append(f"byo_oci_proof_bundle_{key}_invalid")
            continue
        binding[key] = raw
    return binding


def _public_byo_contract(
    value: object,
    *,
    expected: dict[str, object],
    name: str,
    blockers: list[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        blockers.append(f"byo_oci_proof_bundle_{name}_invalid")
        return {}
    if contains_durable_secret_text(json.dumps(value, sort_keys=True)):
        blockers.append(f"byo_oci_proof_bundle_{name}_unsafe")
        return {}
    unexpected = sorted(_public_byo_sidecar_field_name(key) for key in value if key not in expected)
    blockers.extend(
        f"byo_oci_proof_bundle_{name}_unexpected_field:{key}" for key in unexpected
    )
    public_value = {key: value.get(key) for key in expected}
    if public_value != expected:
        blockers.append(f"byo_oci_proof_bundle_{name}_mismatch")
        return {}
    return dict(public_value)


def _manifest_artifact_labels(manifest: dict[str, object]) -> dict[str, str]:
    raw = manifest.get("required_remote_artifacts")
    if not isinstance(raw, list):
        return {}
    labels: dict[str, str] = {}
    for artifact in raw:
        if not isinstance(artifact, dict):
            continue
        path = artifact.get("path")
        label = artifact.get("label")
        if isinstance(path, str) and isinstance(label, str):
            labels[path] = label
    return labels


def _public_byo_artifact_inventory(
    value: object,
    *,
    blockers: list[str],
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        blockers.append("byo_oci_proof_bundle_artifacts_invalid")
        return []
    artifacts: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            blockers.append(f"artifact_row_invalid:{index}")
            continue
        allowed = {"path", "label", "sha256", "size_bytes", "redacted"}
        unexpected = sorted(
            _public_byo_sidecar_field_name(key) for key in row if key not in allowed
        )
        blockers.extend(f"artifact_row_unexpected_field:{index}:{key}" for key in unexpected)
        path = str(row.get("path", ""))
        if (
            not _safe_byo_artifact_path(path)
            or contains_durable_secret_text(path)
            or _contains_byo_private_marker(path)
        ):
            blockers.append(f"artifact_path_invalid:{index}")
            continue
        if path in seen:
            blockers.append(f"duplicate_artifact:{path}")
            continue
        seen.add(path)
        label = str(row.get("label", ""))
        sha256 = str(row.get("sha256", ""))
        size_bytes = row.get("size_bytes")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            blockers.append(f"artifact_size_invalid:{path}")
            size_bytes = 0
        if contains_durable_secret_text(label) or _contains_byo_private_marker(label):
            blockers.append(f"artifact_label_unsafe:{path}")
            label = ""
        if contains_durable_secret_text(sha256) or _contains_byo_private_marker(sha256):
            blockers.append(f"artifact_sha256_unsafe:{path}")
            sha256 = ""
        artifacts.append(
            {
                "path": path,
                "label": label,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "redacted": row.get("redacted") is True,
            }
        )
    return artifacts


def _public_completion_evidence(value: object, *, blockers: list[str]) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    unexpected = sorted(
        _public_byo_sidecar_field_name(key) for key in value if key not in HOSTED_WORKER_PROOF_KEYS
    )
    blockers.extend(f"completion_evidence_unexpected_field:{key}" for key in unexpected)
    return {key: value.get(key) is True for key in HOSTED_WORKER_PROOF_KEYS}


def _public_byo_sidecar_field_name(value: object) -> str:
    raw = str(value)
    if (
        not raw
        or len(raw) > 80
        or contains_durable_secret_text(raw)
        or _contains_byo_private_marker(raw)
    ):
        return "redacted"
    cleaned = "".join(
        character if character.isalnum() or character in {"_", "-", "."} else "_"
        for character in raw
    )
    return cleaned or "redacted"


def _contains_byo_private_marker(value: str) -> bool:
    forbidden = (
        "ghs_",
        "ghp_",
        "github_pat_",
        "sk_live",
        "sk_test",
        "-----BEGIN",
        "PRIVATE KEY-----",
        "ocid1.",
        "AKIA",
    )
    return any(token.lower() in value.lower() for token in forbidden)


def _safe_byo_artifact_path(path: str) -> bool:
    if not path.startswith(".fusekit/"):
        return False
    if path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(part and part not in {".", ".."} for part in parts)


def _valid_sha256_label(value: str) -> bool:
    digest = value.removeprefix("sha256:")
    return (
        value.startswith("sha256:")
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


def _invalid_required_artifacts(
    required_artifacts: dict[str, str],
    *,
    present_paths: set[str],
    blockers: list[str],
) -> list[str]:
    invalid_prefixes = (
        "artifact_label_mismatch:",
        "artifact_not_marked_redacted:",
        "artifact_sha256_invalid:",
        "artifact_empty:",
        "artifact_label_unsafe:",
        "artifact_sha256_unsafe:",
        "artifact_size_invalid:",
        "duplicate_artifact:",
    )
    invalid_paths: set[str] = set()
    for blocker in blockers:
        for prefix in invalid_prefixes:
            if blocker.startswith(prefix):
                path = blocker.removeprefix(prefix)
                if path in required_artifacts:
                    invalid_paths.add(path)
    return [
        path
        for path in required_artifacts
        if path in present_paths and path in invalid_paths
    ]


def _github_source_hash(github_source: str) -> str:
    return "sha256:" + hashlib.sha256(github_source.encode("utf-8")).hexdigest()


def _assert_public_byo_proof_report(report: dict[str, object]) -> None:
    serialized = json.dumps(report, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("Hosted BYO OCI proof report contains secret-looking text.")
    if _contains_byo_private_marker(serialized):
        raise FuseKitError("Hosted BYO OCI proof report contains private material.")


def _assert_public_byo_oci_bootstrap(payload: dict[str, object]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    forbidden = (
        "ghs_",
        "ghp_",
        "github_pat_",
        "sk_live",
        "sk_test",
        "-----BEGIN",
        "PRIVATE KEY-----",
        "ocid1.",
        "AKIA",
    )
    if any(token.lower() in serialized.lower() for token in forbidden):
        raise FuseKitError("Hosted BYO OCI bootstrap contains private material.")
    _assert_byo_oci_cloud_shell_handoff(
        payload.get("cloud_shell"),
        open_core_execution=payload.get("open_core_execution"),
    )


def _assert_byo_oci_cloud_shell_handoff(
    value: object,
    *,
    open_core_execution: object,
) -> None:
    if not isinstance(value, dict):
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if not isinstance(open_core_execution, dict):
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    command = str(value.get("bootstrap_command") or "")
    deeplink_url = str(value.get("deeplink_url") or "")
    fallback_steps = value.get("fallback_steps")
    fusekit_package = str(open_core_execution.get("fusekit_package") or "")
    app_source = str(open_core_execution.get("app_source") or "")
    repo_slug = _github_repo_slug_from_url(app_source)
    required_fragments = (
        "fusekit launch",
        "--runner oci-existing",
        f"--oci-shape {BYO_OCI_RUNNER_PROFILE['shape']}",
        "--visual-runner novnc",
        "--fusekit-gates service-only",
        "--control-room --no-bootstrap",
        f"fusekit_package={fusekit_package}",
    )
    forbidden_fragments = (
        "fusekit-hosted-worker",
        "--require-recording",
        "FUSEKIT_HOSTED_WORKER",
        "FUSEKIT_GITHUB_APP_PRIVATE_KEY",
        "FUSEKIT_STRIPE_SECRET_KEY",
        "sk_live",
        "ghs_",
        "ocid1.",
    )
    if value.get("provider") != "oci-cloud-shell":
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if value.get("requires_user_oci_account") is not True:
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if deeplink_url != "https://cloud.oracle.com/?cloudshell=true":
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if fusekit_package != HOSTED_BYO_OCI_FUSEKIT_PACKAGE or not repo_slug:
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if not command or any(fragment not in command for fragment in required_fragments):
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if f"--github-repo {repo_slug}" not in command:
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if any(fragment.lower() in command.lower() for fragment in forbidden_fragments):
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")
    if not isinstance(fallback_steps, list) or not fallback_steps:
        raise FuseKitError("Hosted BYO OCI bootstrap Cloud Shell handoff is invalid.")


def _assert_public_hosted_job(payload: dict[str, object]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if contains_durable_secret_text(serialized) or _contains_byo_private_marker(serialized):
        raise FuseKitError("Hosted launch job contains private material.")


def _assert_public_worker_request(payload: dict[str, object]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if contains_durable_secret_text(serialized) or _contains_byo_private_marker(serialized):
        raise FuseKitError("Hosted worker request contains private material.")


def _assert_public_proof_receipt(payload: dict[str, object]) -> None:
    _assert_public_hosted_receipt(payload, "Hosted proof receipt")


def _assert_public_hosted_receipt(payload: dict[str, object], label: str) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if contains_durable_secret_text(serialized) or _contains_byo_private_marker(serialized):
        raise FuseKitError(f"{label} contains private material.")


def _byo_oci_launch_args(job: HostedLaunchJob) -> tuple[str, ...]:
    args = [
        "--oci-shape",
        str(BYO_OCI_RUNNER_PROFILE["shape"]),
        "--visual-runner",
        "novnc",
        "--infer-ui",
    ]
    repo = _github_repo_slug_from_url(job.github_source)
    if repo:
        args.extend(["--github-repo", repo])
    return tuple(args)


def _github_repo_slug_from_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return ""
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    candidate = f"{owner}/{repo}"
    allowed_slug_chars = {"-", "_", "."}
    if all(
        part and all(ch.isalnum() or ch in allowed_slug_chars for ch in part)
        for part in (owner, repo)
    ):
        return candidate
    return ""


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
    _reject_unexpected_payload_keys(
        raw,
        HOSTED_JOB_TOKEN_KEYS,
        "Hosted launcher job token payload",
    )
    issued_at = raw.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int):
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
    _reject_unexpected_payload_keys(
        payload,
        HOSTED_JOB_PAYLOAD_KEYS,
        "Hosted launch job payload",
    )
    job_id = _required_str(payload, "job_id")
    if not job_id.startswith("hosted-"):
        raise FuseKitError("Hosted launch job id is invalid.")
    steps = payload.get("steps")
    proof = payload.get("proof")
    rollback = payload.get("rollback")
    detonation = payload.get("detonation")
    worker_contract = payload.get("worker_contract")
    launch_lane = _hosted_lane_from_payload(payload.get("launch_lane"))
    _validate_public_lane_contract(payload.get("lane_contract"), launch_lane)
    payment = payload.get("payment")
    if not isinstance(steps, list) or not isinstance(worker_contract, dict):
        raise FuseKitError("Hosted launch job payload is invalid.")
    app_name = public_hosted_app_name(_required_str(payload, "app_name"))
    github_source = public_hosted_github_source(_required_str(payload, "github_source"))
    worker_contract_payload = _worker_contract_from_dict(worker_contract)
    payment_price_label = _payment_price_label_from_payload(payment)
    payment_price_id_hash = _payment_price_id_hash_from_payload(payment)
    payment_status, payment_receipt = _payment_from_payload(
        payment,
        job_id=job_id,
        launch_lane=launch_lane,
        github_source=github_source,
        plan_fingerprint=worker_contract_payload.plan_fingerprint,
        price_label=payment_price_label,
        price_id_hash=payment_price_id_hash,
    )
    return HostedLaunchJob(
        job_id=job_id,
        app_name=app_name,
        github_source=github_source,
        status=_required_str(payload, "status"),
        created_at=_required_int(payload, "created_at"),
        steps=tuple(_job_step_from_dict(step) for step in steps),
        proof=_str_tuple(proof, "proof"),
        rollback=_str_tuple(rollback, "rollback"),
        detonation=_str_tuple(detonation, "detonation"),
        worker_contract=worker_contract_payload,
        launch_lane=launch_lane,
        payment_status=payment_status,
        payment_price_label=payment_price_label,
        payment_price_id_hash=payment_price_id_hash,
        payment_receipt=payment_receipt,
    )


def build_hosted_worker_contract(
    plan: HostedLaunchPlan,
    *,
    github_installation_id: int | None = None,
    launch_lane: str = MANAGED_FUSEKIT_RUN_LANE,
) -> HostedWorkerContract:
    """Build the redacted execution contract for the hosted setup worker."""

    lane = hosted_launch_lane(launch_lane).lane_id
    public_app_name = public_hosted_app_name(plan.app_name)
    public_source = public_hosted_github_source(plan.github_source)
    providers = plan.providers
    required_env = plan.required_env
    approved_actions = tuple(action.id for action in plan.actions)
    required_artifacts = HOSTED_WORKER_REQUIRED_ARTIFACTS
    gates = plan.trust.user_gates
    guarantees = HOSTED_WORKER_GUARANTEES
    safe_github_installation_id = _public_github_installation_id(github_installation_id)
    return HostedWorkerContract(
        lane=lane,
        github_source=public_source,
        github_installation_id=safe_github_installation_id,
        plan_fingerprint=_approved_plan_fingerprint(
            app_name=public_app_name,
            github_source=public_source,
            providers=providers,
            required_env=required_env,
            approved_actions=approved_actions,
            required_artifacts=required_artifacts,
            gates=gates,
            guarantees=guarantees,
        ),
        providers=providers,
        required_env=required_env,
        permission_boundary=(
            "GitHub App installation is limited to one selected repository.",
            "GitHub repository permission is contents:read for source intake.",
            "GitHub installation tokens are exchanged only inside the backend worker.",
            "Provider credentials stay inside the FuseKit vault or provider-native secret stores.",
            "Worker dispatch uses an HMAC envelope; worker secrets are never sent to browsers.",
            _lane_permission_boundary(lane),
        ),
        approved_actions=approved_actions,
        required_artifacts=required_artifacts,
        gates=gates,
        guarantees=guarantees,
    )


def _public_github_installation_id(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FuseKitError("Hosted worker contract github_installation_id is invalid.")
    return value


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
    control_tokens: dict[str, str] | None = None,
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
    payload = json_script_payload(payload_dict)
    rows = "\n".join(_step_card(step) for step in job.steps)
    controls = _control_forms(job, control_tokens=control_tokens or {}, job_token=job_token)
    action_outcome = _action_receipt_section(action_receipt, dispatch_receipt)
    proof_link = _proof_link(job, job_token=job_token)
    worker_request_link = _worker_request_link(job, job_token=job_token)
    byo_oci_link = _byo_oci_bootstrap_link(job, job_token=job_token)
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
        {app_name} is queued for {html.escape(hosted_launch_lane(job.launch_lane).label)}.
        Human gates stay visible, provider-owned, and reversible; raw secrets stay out
        of public pages.
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
        {byo_oci_link}
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
    receipt = {
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
        "launch_lane": job.launch_lane,
        "lane_contract": hosted_launch_lane(job.launch_lane).to_dict(),
        "plan_integrity": job.worker_contract.plan_integrity(),
        "trust_evidence": {
            "open_core": "Hosted source and public contracts remain reviewable before launch.",
            "narrow_permissions": list(job.worker_contract.permission_boundary),
            "visible_plan_fingerprint": job.worker_contract.plan_fingerprint,
            "approved_actions": list(job.worker_contract.approved_actions),
            "redacted_proof": "Receipt exposes proof labels, statuses, and public artifacts only.",
            "reversible_setup": (
                "Rollback metadata is required before completion; rollback requests require "
                "execution receipt and post-rollback verification."
            ),
            "not_proven_until": list(HOSTED_WORKER_PROOF_KEYS),
            "fusekit_cannot_do": list(HOSTED_PROHIBITED_ACTIONS),
        },
        "reversal_playbook": hosted_reversal_playbook(job),
        "provider_gates": list(job.worker_contract.gates),
        "permission_boundary": list(job.worker_contract.permission_boundary),
        "approved_actions": list(job.worker_contract.approved_actions),
        "required_artifacts": list(job.worker_contract.required_artifacts),
        "steps": [step.to_dict() for step in job.steps],
    }
    _assert_public_proof_receipt(receipt)
    return receipt


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
    request = {
        "schema_version": HOSTED_WORKER_REQUEST_SCHEMA_VERSION,
        "job_id": job.job_id,
        "app_name": job.app_name,
        "github_source": job.github_source,
        "status": job.status,
        "requested_at": requested_at,
        "plan_integrity": job.worker_contract.plan_integrity(),
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
        "prohibited": list(HOSTED_PROHIBITED_ACTIONS),
        "worker_contract": job.worker_contract.to_dict(),
        "secret_boundary": (
            "Hosted worker requests contain public job labels, approved plan fingerprints, "
            "human-gate labels, artifact labels, and a non-secret GitHub installation id only. "
            "They never include worker secrets, GitHub installation tokens, provider "
            "credentials, Stripe keys, payment method details, vault material, or copy-once "
            "credentials."
        ),
    }
    _assert_public_worker_request(request)
    return request


def hosted_job_action_receipt(
    job: HostedLaunchJob,
    *,
    action: str,
    now: int | None = None,
) -> dict[str, object]:
    """Build a public redacted receipt for a protected hosted job action."""

    action_id = _public_action(action)
    receipt = {
        "schema_version": HOSTED_JOB_ACTION_RECEIPT_SCHEMA_VERSION,
        "job_id": job.job_id,
        "action": action_id,
        "status": job.status,
        "requested_at": int(time.time() if now is None else now),
        "plan_integrity": job.worker_contract.plan_integrity(),
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
    _assert_public_hosted_receipt(receipt, "Hosted action receipt")
    return receipt


def hosted_worker_claim_receipt(
    job: HostedLaunchJob,
    *,
    worker_id: str,
    now: int | None = None,
) -> dict[str, object]:
    """Build a redacted receipt for a hosted worker claim."""

    claimed_at = int(time.time() if now is None else now)
    receipt = {
        "schema_version": HOSTED_WORKER_CLAIM_SCHEMA_VERSION,
        "job_id": job.job_id,
        "worker_id": _public_worker_id(worker_id),
        "claimed_at": claimed_at,
        "status": job.status,
        "plan_integrity": job.worker_contract.plan_integrity(),
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
    _assert_public_hosted_receipt(receipt, "Hosted worker claim receipt")
    return receipt


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
    _validate_worker_proof_payload_shape(job, payload)
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
    byo_oci_proof = _byo_oci_worker_proof_report(job, payload.get("byo_oci_proof_bundle"))
    byo_oci_proof_ready = (
        job.launch_lane != BYO_OCI_LANE or byo_oci_proof.get("ready") is True
    )
    completion_ready = (
        all(evidence[key] for key in HOSTED_WORKER_PROOF_KEYS)
        and not missing_artifacts
        and maintenance_ready
        and byo_oci_proof_ready
    )
    receipt = {
        "schema_version": HOSTED_WORKER_PROOF_RECEIPT_SCHEMA_VERSION,
        "job_id": job.job_id,
        "worker_id": _public_worker_id(worker_id),
        "received_at": int(time.time() if now is None else now),
        "status": job.status,
        "completion_ready": completion_ready,
        "maintenance_ready": maintenance_ready,
        "launch_lane": job.launch_lane,
        "lane_contract": hosted_launch_lane(job.launch_lane).to_dict(),
        "plan_integrity": job.worker_contract.plan_integrity(),
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
    if byo_oci_proof:
        receipt["byo_oci_proof_bundle"] = byo_oci_proof
    _assert_public_hosted_receipt(receipt, "Hosted worker proof receipt")
    return receipt


def _validate_worker_proof_payload_shape(
    job: HostedLaunchJob,
    payload: dict[str, object],
) -> None:
    allowed = {"schema_version", "evidence", "completed_artifacts", "note"}
    if job.launch_lane == BYO_OCI_LANE:
        allowed.add("byo_oci_proof_bundle")
    unexpected = sorted(str(key) for key in payload if key not in allowed)
    if unexpected:
        raise ValueError("Hosted worker proof payload contains unsupported keys.")


def render_hosted_proof_receipt(job: HostedLaunchJob, *, job_token: str = "") -> str:
    """Render the browser-facing hosted proof receipt."""

    receipt = hosted_proof_receipt(job)
    payload = json_script_payload(receipt)
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
    trust_evidence = _trust_evidence_section(cast(dict[str, object], receipt["trust_evidence"]))
    plan_integrity = _plan_integrity_section(job.worker_contract)
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
    {plan_integrity}
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
    {trust_evidence}
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
    control_tokens: dict[str, str],
    job_token: str,
) -> str:
    if not control_tokens:
        return """
        <article class="step" aria-label="Protected controls unavailable">
          <h3>Protected controls unavailable</h3>
          <p>
            Start, stop, rollback, and detonation controls require a short-lived
            action-bound control token. FuseKit renders them disabled instead of
            pretending an unsafe or expired control can run.
          </p>
          <button type="button" disabled aria-disabled="true">Start worker</button>
          <button type="button" disabled aria-disabled="true">Stop launch</button>
          <button type="button" disabled aria-disabled="true">Request rollback</button>
          <button type="button" disabled aria-disabled="true">Request detonation</button>
        </article>
"""
    job_id = html.escape(job.job_id, quote=True)
    job_param = (
        "&amp;" + urllib.parse.urlencode({"job": job_token})
        if job_token
        else ""
    )
    start_action = _protected_action_url(
        job_id=job_id,
        action="start",
        control_tokens=control_tokens,
        job_param=job_param,
    )
    stop_action = _protected_action_url(
        job_id=job_id,
        action="stop",
        control_tokens=control_tokens,
        job_param=job_param,
    )
    rollback_action = _protected_action_url(
        job_id=job_id,
        action="rollback",
        control_tokens=control_tokens,
        job_param=job_param,
    )
    detonate_action = _protected_action_url(
        job_id=job_id,
        action="detonate",
        control_tokens=control_tokens,
        job_param=job_param,
    )
    checkout_action = _protected_action_url(
        job_id=job_id,
        action="checkout",
        control_tokens=control_tokens,
        job_param=job_param,
        route_group="payments",
    )
    if not start_action or not stop_action or not rollback_action or not detonate_action:
        return """
        <article class="step" aria-label="Protected controls unavailable">
          <h3>Protected controls unavailable</h3>
          <p>
            FuseKit could not mint every action-bound control token, so protected
            controls are disabled instead of sharing one approval across actions.
          </p>
          <button type="button" disabled aria-disabled="true">Start worker</button>
          <button type="button" disabled aria-disabled="true">Stop launch</button>
          <button type="button" disabled aria-disabled="true">Request rollback</button>
          <button type="button" disabled aria-disabled="true">Request detonation</button>
        </article>
"""
    if job.status == "waiting_for_worker":
        if job.payment_status in {"payment_required", "checkout_pending"}:
            payment_label = (
                "Payment authorization is pending"
                if job.payment_status == "checkout_pending"
                else "Authorize managed run payment"
            )
            price_line = (
                f"<p>Managed run price: {html.escape(job.payment_price_label)}</p>"
                if job.payment_price_label
                else ""
            )
            if not checkout_action:
                return f"""
        <article class="step" aria-label="Payment authorization unavailable">
          <h3>Payment authorization unavailable</h3>
          {price_line}
          <p>Managed worker dispatch is blocked until payment authorization is available.</p>
          <button type="button" disabled aria-disabled="true">Authorize payment</button>
        </article>
"""
            return f"""
        {price_line}
        <form method="post" enctype="application/x-www-form-urlencoded" action="{checkout_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "checkout")}">
          <button type="submit">{html.escape(payment_label)}</button>
        </form>
        <form method="post" enctype="application/x-www-form-urlencoded" action="{stop_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "stop")}">
          <button type="submit">Stop launch</button>
        </form>
"""
        return f"""
        <form method="post" enctype="application/x-www-form-urlencoded" action="{start_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "start")}">
          <button type="submit">Start worker</button>
        </form>
        <form method="post" enctype="application/x-www-form-urlencoded" action="{stop_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "stop")}">
          <button type="submit">Stop launch</button>
        </form>
"""
    if job.status == "stopped":
        return ""
    return f"""
        <form method="post" enctype="application/x-www-form-urlencoded" action="{rollback_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "rollback")}">
          <button type="submit">Request rollback</button>
        </form>
        <form method="post" enctype="application/x-www-form-urlencoded" action="{detonate_action}">
          <input type="hidden" name="control" value="{_control_value(control_tokens, "detonate")}">
          <button type="submit">Request detonation</button>
        </form>
"""


def _protected_action_url(
    *,
    job_id: str,
    action: str,
    control_tokens: dict[str, str],
    job_param: str,
    route_group: str = "actions",
) -> str:
    control_token = control_tokens.get(action)
    if not control_token:
        return ""
    suffix = f"?{job_param.removeprefix('&amp;')}" if job_param else ""
    return f"/api/hosted/jobs/{job_id}/{route_group}/{action}{suffix}"


def _control_value(control_tokens: dict[str, str], action: str) -> str:
    return html.escape(control_tokens[action], quote=True)


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


def _byo_oci_bootstrap_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token or job.status == "waiting_for_worker" or job.launch_lane != BYO_OCI_LANE:
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}/byo-oci-bootstrap?"
        + urllib.parse.urlencode({"job": job_token}),
        quote=True,
    )
    return f'<a class="button" href="{href}">Open BYO OCI bootstrap</a>'


def _byo_oci_json_link(job: HostedLaunchJob, *, job_token: str) -> str:
    if not job_token:
        return ""
    href = html.escape(
        f"/api/hosted/jobs/{urllib.parse.quote(job.job_id)}/byo-oci-bootstrap?"
        + urllib.parse.urlencode({"job": job_token, "format": "json"}),
        quote=True,
    )
    return f'<a class="button" href="{href}">Download bootstrap JSON</a>'


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
    payment_status: str | None = None,
    payment_receipt: dict[str, object] | None = None,
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
        launch_lane=job.launch_lane,
        payment_status=payment_status or job.payment_status,
        payment_price_label=job.payment_price_label,
        payment_price_id_hash=job.payment_price_id_hash,
        payment_receipt=payment_receipt if payment_receipt is not None else job.payment_receipt,
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


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


def _safe_cloud_shell_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() != "cloud.oracle.com":
        return ""
    return value


def _preflight_cards(value: object) -> str:
    if not isinstance(value, list):
        return ""
    cards: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        label = html.escape(str(item.get("label", "")))
        proof = html.escape(str(item.get("proof", "")))
        check_id = html.escape(str(item.get("id", "preflight")))
        required = "required" if item.get("required") is True else "optional"
        cards.append(
            f"""
        <article class="done" aria-label="{check_id}">
          <h3>{label}</h3>
          <small>{html.escape(required)}</small>
          <p>{proof}</p>
        </article>
"""
        )
    return "\n".join(cards)


def _cost_acknowledgement_section(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    statement = html.escape(str(value.get("statement", "")))
    spend_owner = html.escape(str(value.get("spend_owner", "")))
    fusekit_fee = html.escape(str(value.get("fusekit_fee", "")))
    billing_owner = html.escape(str(value.get("oracle_billing_gate_owner", "")))
    return f"""
        <article class="done" aria-label="Cost acknowledgement">
          <h3>Cost acknowledgement</h3>
          <p>{statement}</p>
          <small>Spend owner: {spend_owner}</small>
          <small>FuseKit fee: {fusekit_fee}</small>
          <small>Billing gate owner: {billing_owner}</small>
        </article>
"""


def _proof_artifact_cards(value: object) -> str:
    if not isinstance(value, list):
        return ""
    cards: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        path = html.escape(str(item.get("path", "")))
        label = html.escape(str(item.get("label", "")))
        boundary = html.escape(str(item.get("secret_boundary", "")))
        required = "required" if item.get("required") is True else "optional"
        cards.append(
            f"""
        <article class="done" aria-label="{path}">
          <h3>{label}</h3>
          <small>{html.escape(required)} / {path}</small>
          <p>{boundary}</p>
        </article>
"""
        )
    return "\n".join(cards)


def _worker_contract_section(contract: HostedWorkerContract) -> str:
    lane = hosted_launch_lane(contract.lane)
    providers = _list(contract.providers or ("No providers detected yet",))
    permissions = _list(contract.permission_boundary)
    actions = _list(contract.approved_actions)
    gates = _list(contract.gates)
    artifacts = _list(contract.required_artifacts)
    guarantees = _list(contract.guarantees)
    plan_integrity = _plan_integrity_section(contract, heading_level=3)
    return f"""
        <h2>Worker contract</h2>
        <p>
          Lane: {html.escape(lane.label)}. FuseKit may not call this launch
          complete until the hosted worker produces the required redacted
          artifacts and keeps these guarantees.
        </p>
        {plan_integrity}
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


def _plan_integrity_section(
    contract: HostedWorkerContract,
    *,
    heading_level: int = 2,
) -> str:
    heading = f"h{heading_level}"
    integrity = contract.plan_integrity()
    fingerprint = html.escape(str(integrity["fingerprint"]))
    coverage = _list(tuple(str(item) for item in cast(list[object], integrity["covers"])))
    wrapper = "section" if heading_level == 2 else "div"
    return f"""
    <{wrapper} aria-label="Approved plan integrity">
      <{heading}>Approved plan integrity</{heading}>
      <p class="source">{fingerprint}</p>
      <p>
        This fingerprint covers the non-secret plan shape the user approved.
        Provider, action, gate, artifact, source, or env-name drift requires a
        fresh visible plan before execution.
      </p>
      {coverage}
    </{wrapper}>
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


def _trust_evidence_section(evidence: dict[str, object]) -> str:
    rows: list[str] = []
    for key in (
        "open_core",
        "visible_plan_fingerprint",
        "redacted_proof",
        "reversible_setup",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            rows.append(f"<li><strong>{html.escape(key)}</strong>: {html.escape(value)}</li>")
    cannot = evidence.get("fusekit_cannot_do")
    if isinstance(cannot, list):
        labels = ", ".join(str(item) for item in cannot if isinstance(item, str))
        if labels:
            rows.append(
                "<li><strong>fusekit_cannot_do</strong>: "
                f"{html.escape(labels)}</li>"
            )
    return f"""
    <section aria-label="Trust evidence">
      <h2>Trust evidence</h2>
      <ul>{"".join(rows)}</ul>
    </section>
"""


def _completion_ready(job: HostedLaunchJob) -> bool:
    steps = {step.id: step.status for step in job.steps}
    return (
        job.status == "complete"
        and steps.get("proof.collect") == "done"
        and steps.get("rollback.ready") == "done"
        and steps.get("detonate.worker") == "done"
    )


def _byo_oci_worker_proof_report(
    job: HostedLaunchJob,
    value: object,
) -> dict[str, object]:
    if job.launch_lane != BYO_OCI_LANE:
        return {}
    if not isinstance(value, dict):
        report = {
            "schema_version": HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION,
            "input_schema_version": "",
            "job_id": job.job_id,
            "lane": job.launch_lane,
            "ready": False,
            "blockers": ["byo_oci_proof_bundle_required_for_completion"],
            "proof_bundle_root": ".fusekit/remote-artifacts",
            "artifact_summary": {
                "required_count": len(job.worker_contract.required_artifacts),
                "present_required_count": 0,
                "missing": list(job.worker_contract.required_artifacts),
                "unexpected": [],
                "invalid_required": [],
                "artifacts": [],
            },
            "completion_evidence": {key: False for key in HOSTED_WORKER_PROOF_KEYS},
            "acceptance_gate": _byo_oci_proof_manifest(job)["acceptance_gate"],
            "secret_boundary": (
                "BYO OCI completion requires a redacted proof-bundle inventory. Missing "
                "bundle reports contain only public artifact labels and blocker codes."
            ),
        }
        _assert_public_byo_proof_report(report)
        return report
    return verify_hosted_byo_oci_proof_bundle(job, value)


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
    if contains_durable_secret_text(value) or _contains_byo_private_marker(value):
        return "hosted-worker"
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


def _approved_plan_fingerprint(
    *,
    app_name: str,
    github_source: str,
    providers: tuple[str, ...],
    required_env: tuple[str, ...],
    approved_actions: tuple[str, ...],
    required_artifacts: tuple[str, ...],
    gates: tuple[str, ...],
    guarantees: tuple[str, ...],
) -> str:
    payload = {
        "app_name": app_name,
        "github_source": github_source,
        "providers": list(providers),
        "required_env": list(required_env),
        "approved_actions": list(approved_actions),
        "required_artifacts": list(required_artifacts),
        "provider_gates": list(gates),
        "worker_guarantees": list(guarantees),
    }
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def _worker_contract_from_dict(payload: dict[str, Any]) -> HostedWorkerContract:
    if payload.get("schema_version") != HOSTED_WORKER_CONTRACT_SCHEMA_VERSION:
        raise FuseKitError("Hosted worker contract schema is unsupported.")
    _reject_unexpected_payload_keys(
        payload,
        HOSTED_WORKER_CONTRACT_KEYS,
        "Hosted worker contract payload",
    )
    github_installation_id = _public_github_installation_id(
        payload.get("github_installation_id")
    )
    plan_fingerprint = _plan_fingerprint_from_payload(payload)
    return HostedWorkerContract(
        lane=_required_str(payload, "lane"),
        github_source=public_hosted_github_source(_required_str(payload, "github_source")),
        github_installation_id=github_installation_id,
        plan_fingerprint=plan_fingerprint,
        providers=tuple(
            public_hosted_provider_name(provider)
            for provider in _str_tuple(payload.get("providers"), "providers")
        ),
        required_env=tuple(
            public_hosted_env_name(name)
            for name in _str_tuple(payload.get("required_env"), "required_env")
        ),
        permission_boundary=_str_tuple(
            payload.get("permission_boundary", []),
            "permission_boundary",
        ),
        approved_actions=tuple(
            public_hosted_action_id(action)
            for action in _str_tuple(payload.get("approved_actions"), "approved_actions")
        ),
        required_artifacts=_str_tuple(payload.get("required_artifacts"), "required_artifacts"),
        gates=_str_tuple(payload.get("gates"), "gates"),
        guarantees=_str_tuple(payload.get("guarantees"), "guarantees"),
    )


def _hosted_lane_from_payload(value: object) -> str:
    if value is None:
        return MANAGED_FUSEKIT_RUN_LANE
    if not isinstance(value, str) or not valid_hosted_launch_lane(value):
        raise FuseKitError("Hosted launch lane is invalid.")
    return hosted_launch_lane(value).lane_id


def _payment_from_payload(
    value: object,
    *,
    job_id: str,
    launch_lane: str,
    github_source: str,
    plan_fingerprint: str,
    price_label: str,
    price_id_hash: str,
) -> tuple[str, dict[str, object] | None]:
    if value is None:
        return "not_required", None
    if not isinstance(value, dict):
        raise FuseKitError("Hosted launch payment payload is invalid.")
    status = value.get("status")
    if not isinstance(status, str):
        raise FuseKitError("Hosted launch payment status is invalid.")
    if status not in {"not_required", "payment_required", "checkout_pending", "paid"}:
        raise FuseKitError("Hosted launch payment status is unsupported.")
    if status != "not_required":
        if not price_label:
            raise FuseKitError("Hosted launch payment price label is required.")
        if not price_id_hash:
            raise FuseKitError("Hosted launch payment price id hash is required.")
    elif price_label or price_id_hash:
        raise FuseKitError("Hosted launch payment price is invalid for status.")
    receipt = value.get("receipt")
    if receipt in (None, {}):
        if status == "paid":
            raise FuseKitError("Hosted launch paid payment receipt is invalid.")
        return status, None
    if not isinstance(receipt, dict):
        raise FuseKitError("Hosted launch payment receipt is invalid.")
    public_receipt = _public_payment_receipt(receipt)
    if status == "paid":
        if not _payment_receipt_is_paid_checkout(public_receipt):
            raise FuseKitError("Hosted launch paid payment receipt is invalid.")
        if not _payment_receipt_matches_public_job(
            public_receipt,
            job_id=job_id,
            launch_lane=launch_lane,
            github_source=github_source,
            plan_fingerprint=plan_fingerprint,
            price_label=price_label,
            price_id_hash=price_id_hash,
        ):
            raise FuseKitError("Hosted launch paid payment receipt does not match this job.")
    return status, public_receipt


def _payment_price_label_from_payload(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    price_label = value.get("price_label")
    if not isinstance(price_label, str):
        return ""
    if price_label == "":
        return ""
    if not _valid_price_label(price_label):
        raise FuseKitError("Hosted launch payment price label is invalid.")
    return price_label


def _payment_price_id_hash_from_payload(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    price_id_hash = value.get("price_id_hash")
    if not isinstance(price_id_hash, str) or price_id_hash == "":
        return ""
    if not _valid_sha256_label(price_id_hash):
        raise FuseKitError("Hosted launch payment price id hash is invalid.")
    return price_id_hash


def _public_payment_receipt(receipt: dict[str, object]) -> dict[str, object]:
    allowed = {
        "schema_version",
        "provider",
        "checkout_session_id",
        "checkout_url",
        "status",
        "payment_status",
        "mode",
        "client_reference_id",
        "metadata",
        "amount_total",
        "currency",
        "paid",
        "price_label",
        "secret_boundary",
    }
    unexpected = sorted(str(key) for key in receipt if key not in allowed)
    if unexpected:
        raise FuseKitError("Hosted launch payment receipt contains unexpected field.")
    result: dict[str, object] = {}
    for key in allowed:
        value = receipt.get(key)
        if key == "amount_total":
            if isinstance(value, bool):
                result[key] = None
            elif isinstance(value, int) and value >= 0:
                result[key] = value
            elif value is None:
                result[key] = None
            continue
        if isinstance(value, str):
            if contains_durable_secret_text(value) or len(value) > 2048:
                raise FuseKitError("Hosted launch payment receipt contains secret-looking text.")
            if key == "price_label" and value and not _valid_price_label(value):
                raise FuseKitError("Hosted launch payment receipt price label is invalid.")
            result[key] = value
        elif isinstance(value, bool) or isinstance(value, int) or value is None:
            result[key] = value
        elif key == "metadata" and isinstance(value, dict):
            result[key] = _public_payment_metadata(value)
    if result.get("paid") is True and not _payment_receipt_is_paid_checkout(result):
        result["paid"] = False
    return result


def _payment_receipt_is_paid_checkout(receipt: dict[str, object]) -> bool:
    session_id = receipt.get("checkout_session_id")
    amount_total = receipt.get("amount_total")
    currency = receipt.get("currency")
    metadata = receipt.get("metadata")
    hash_keys = {
        "github_source_hash",
        "plan_fingerprint",
        "stripe_price_id_hash",
        "price_label_hash",
    }
    return (
        receipt.get("schema_version") == HOSTED_PAYMENT_SCHEMA_VERSION
        and receipt.get("provider") == STRIPE_CHECKOUT_PROVIDER
        and receipt.get("mode") == "payment"
        and receipt.get("status") == "complete"
        and receipt.get("payment_status") == "paid"
        and receipt.get("paid") is True
        and isinstance(session_id, str)
        and session_id.startswith("cs_")
        and isinstance(amount_total, int)
        and not isinstance(amount_total, bool)
        and amount_total > 0
        and isinstance(currency, str)
        and currency.isalpha()
        and len(currency) == 3
        and isinstance(metadata, dict)
        and all(
            isinstance(metadata.get(key), str) and metadata.get(key)
            for key in STRIPE_CHECKOUT_METADATA_KEYS
        )
        and all(_valid_sha256_label(metadata[key]) for key in hash_keys)
    )


def _payment_receipt_matches_job(job: HostedLaunchJob, receipt: dict[str, object]) -> bool:
    return _payment_receipt_matches_public_job(
        receipt,
        job_id=job.job_id,
        launch_lane=job.launch_lane,
        github_source=job.github_source,
        plan_fingerprint=job.worker_contract.plan_fingerprint,
        price_label=job.payment_price_label,
        price_id_hash=job.payment_price_id_hash,
    )


def _payment_receipt_matches_public_job(
    receipt: dict[str, object],
    *,
    job_id: str,
    launch_lane: str,
    github_source: str,
    plan_fingerprint: str,
    price_label: str,
    price_id_hash: str,
) -> bool:
    if receipt.get("client_reference_id") != job_id:
        return False
    if receipt.get("price_label") != price_label:
        return False
    metadata = receipt.get("metadata")
    if not isinstance(metadata, dict):
        return False
    expected = {
        "job_id": job_id,
        "lane": launch_lane,
        "github_source_hash": _github_source_hash(github_source),
        "plan_fingerprint": plan_fingerprint,
        "price_label_hash": _public_hash(price_label),
    }
    if price_id_hash:
        expected["stripe_price_id_hash"] = price_id_hash
    return all(metadata.get(key) == expected_value for key, expected_value in expected.items())


def _lane_permission_boundary(lane: str) -> str:
    if lane == BYO_OCI_LANE:
        return (
            "BYO OCI uses user-owned Oracle Cloud infrastructure; FuseKit-managed worker "
            "dispatch is not allowed for this lane."
        )
    return (
        "Managed FuseKit runs require payment authorization before FuseKit-owned worker "
        "infrastructure can be dispatched."
    )


def _payment_step_proof(status: str) -> str:
    if status == "paid":
        return (
            "Stripe Checkout authorization receipt is present; managed worker dispatch may "
            "proceed only within the approved visible plan."
        )
    return (
        "Stripe Checkout session is pending; FuseKit-managed worker dispatch remains blocked "
        "until payment authorization is confirmed server-side."
    )


def _public_payment_metadata(metadata: dict[str, object]) -> dict[str, str]:
    allowed = {
        "job_id",
        "lane",
        "github_source_hash",
        "plan_fingerprint",
        "stripe_price_id_hash",
        "price_label_hash",
    }
    hash_keys = {
        "github_source_hash",
        "plan_fingerprint",
        "stripe_price_id_hash",
        "price_label_hash",
    }
    unexpected = sorted(str(key) for key in metadata if key not in allowed)
    if unexpected:
        raise FuseKitError("Hosted launch payment metadata contains unexpected field.")
    result: dict[str, str] = {}
    for key in allowed:
        value = metadata.get(key)
        if not isinstance(value, str):
            continue
        if contains_durable_secret_text(value) or len(value) > 256:
            raise FuseKitError("Hosted launch payment metadata contains secret-looking text.")
        if key in hash_keys and not _valid_sha256_label(value):
            raise FuseKitError("Hosted launch payment metadata hash is invalid.")
        result[key] = value
    return result


def _public_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _plan_fingerprint_from_payload(payload: dict[str, Any]) -> str:
    plan_integrity = payload.get("plan_integrity")
    if not isinstance(plan_integrity, dict):
        raise FuseKitError("Hosted worker contract plan_integrity is invalid.")
    _reject_unexpected_payload_keys(
        plan_integrity,
        HOSTED_PLAN_INTEGRITY_KEYS,
        "Hosted worker contract plan_integrity",
    )
    if plan_integrity.get("algorithm") != "sha256":
        raise FuseKitError("Hosted worker contract plan_integrity algorithm is invalid.")
    if plan_integrity.get("covers") != list(HOSTED_PLAN_INTEGRITY_COVERAGE):
        raise FuseKitError("Hosted worker contract plan_integrity coverage is invalid.")
    fingerprint = plan_integrity.get("fingerprint")
    if not isinstance(fingerprint, str) or not _valid_plan_fingerprint(fingerprint):
        raise FuseKitError("Hosted worker contract plan_integrity fingerprint is invalid.")
    boundary = plan_integrity.get("secret_boundary")
    if not isinstance(boundary, str) or "non-secret approved-plan metadata" not in boundary:
        raise FuseKitError("Hosted worker contract plan_integrity boundary is invalid.")
    return fingerprint


def _valid_plan_fingerprint(value: str) -> bool:
    prefix = "sha256:"
    digest = value.removeprefix(prefix)
    return (
        value.startswith(prefix)
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


def _job_step_from_dict(payload: object) -> HostedLaunchJobStep:
    if not isinstance(payload, dict):
        raise FuseKitError("Hosted launch job step payload is invalid.")
    _reject_unexpected_payload_keys(
        payload,
        HOSTED_JOB_STEP_KEYS,
        "Hosted launch job step payload",
    )
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


def _validate_public_lane_contract(value: object, launch_lane: str) -> None:
    if value != hosted_launch_lane(launch_lane).to_dict():
        raise FuseKitError("Hosted launch lane contract is invalid.")


def _reject_unexpected_payload_keys(
    payload: dict[str, Any],
    allowed: frozenset[str],
    label: str,
) -> None:
    unexpected = sorted(str(key) for key in payload if str(key) not in allowed)
    if unexpected:
        joined = ", ".join(unexpected)
        raise FuseKitError(f"{label} has unexpected fields: {joined}.")


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
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
