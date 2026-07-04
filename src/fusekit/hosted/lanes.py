"""Hosted launch lane contracts for managed and bring-your-own runs."""

from __future__ import annotations

from dataclasses import dataclass

from fusekit.errors import FuseKitError
from fusekit.hosted.evidence import HOSTED_COMPLETION_EVIDENCE_KEYS

HOSTED_LAUNCH_LANES_SCHEMA_VERSION = "fusekit.hosted-launch-lanes.v1"
MANAGED_FUSEKIT_RUN_LANE = "managed-fusekit-run"
BYO_OCI_LANE = "bring-your-own-oci"
HOSTED_LAUNCH_LANES = (MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE)
BYO_OCI_RUNNER_PROFILE = {
    "provider": "oracle-cloud-infrastructure",
    "runner": "oci-existing",
    "shape": "VM.Standard.E5.Flex",
    "shape_family": "standard-e5",
    "architecture": "amd64/x86_64",
    "arm_allowed": False,
    "visual_runner": "novnc",
}
BYO_OCI_ALLOWED_SHAPE_PREFIXES = ("VM.Standard.E",)
BYO_OCI_FORBIDDEN_ARCHITECTURES = ("arm64", "aarch64")
BYO_OCI_FORBIDDEN_SHAPE_PREFIXES = ("VM.Standard.A",)


@dataclass(frozen=True)
class HostedLaunchLane:
    """Browser-safe hosted launch lane metadata."""

    lane_id: str
    label: str
    cost_owner: str
    worker_owner: str
    requires_payment: bool
    requires_user_cloud_account: bool
    managed_worker_dispatch_allowed: bool
    summary: str
    gates: tuple[str, ...]
    proof: tuple[str, ...]
    cost_controls: tuple[str, ...]
    user_owned_cost_boundary: dict[str, object] | None = None
    security_contract: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize browser-safe lane metadata."""

        payload: dict[str, object] = {
            "id": self.lane_id,
            "label": self.label,
            "cost_owner": self.cost_owner,
            "worker_owner": self.worker_owner,
            "requires_payment": self.requires_payment,
            "requires_user_cloud_account": self.requires_user_cloud_account,
            "managed_worker_dispatch_allowed": self.managed_worker_dispatch_allowed,
            "summary": self.summary,
            "gates": list(self.gates),
            "proof": list(self.proof),
            "cost_controls": list(self.cost_controls),
            "secret_boundary": (
                "Lane contracts expose ownership, gates, and proof labels only. They never "
                "include cloud credentials, payment method details, provider tokens, or vault "
                "material."
            ),
        }
        if self.user_owned_cost_boundary is not None:
            payload["user_owned_cost_boundary"] = dict(self.user_owned_cost_boundary)
        if self.security_contract is not None:
            payload["security_contract"] = dict(self.security_contract)
        return payload


def byo_oci_user_owned_cost_boundary() -> dict[str, object]:
    """Return the public BYO OCI cost boundary."""

    return {
        "spend_owner": "user_oci_tenancy",
        "fusekit_managed_infrastructure_spend": False,
        "payment_required_by_fusekit": False,
        "billing_gate_owner": "oracle_cloud",
        "review_before_run": [
            "Oracle Cloud account billing status",
            "selected region capacity",
            "AMD/x86_64 disposable worker shape",
            "resources created by the user's Cloud Shell session",
        ],
        "statement": (
            "BYO OCI launches run in the user's Oracle Cloud tenancy. FuseKit does not "
            "charge a managed-run fee and does not dispatch FuseKit-owned workers for "
            "this lane."
        ),
    }


def byo_oci_security_contract() -> dict[str, object]:
    """Return the public BYO OCI security boundary."""

    return {
        "managed_worker_dispatch_allowed": False,
        "hosted_worker_secret_exported": False,
        "hosted_github_private_key_exported": False,
        "hosted_github_installation_token_exported": False,
        "raw_provider_secrets_exported": False,
        "runner_architecture": "amd_x86_64_only",
        "runner_profile": dict(BYO_OCI_RUNNER_PROFILE),
        "runner_shape_guard": byo_oci_runner_shape_guard(),
        "human_gate_bypass_allowed": False,
        "completion_claim_requires": list(HOSTED_COMPLETION_EVIDENCE_KEYS),
    }


def byo_oci_runner_shape_guard() -> dict[str, object]:
    """Return the machine-checkable AMD-only BYO OCI runner guard."""

    shape = str(BYO_OCI_RUNNER_PROFILE.get("shape", ""))
    architecture = str(BYO_OCI_RUNNER_PROFILE.get("architecture", "")).lower()
    arm_allowed = BYO_OCI_RUNNER_PROFILE.get("arm_allowed")
    if (
        not shape.startswith(BYO_OCI_ALLOWED_SHAPE_PREFIXES)
        or shape.startswith(BYO_OCI_FORBIDDEN_SHAPE_PREFIXES)
        or any(token in architecture for token in BYO_OCI_FORBIDDEN_ARCHITECTURES)
        or arm_allowed is not False
    ):
        raise FuseKitError("BYO OCI runner profile must be AMD/x86_64 only.")
    return {
        "required_architecture": "amd64/x86_64",
        "allowed_shape_prefixes": list(BYO_OCI_ALLOWED_SHAPE_PREFIXES),
        "forbidden_shape_prefixes": list(BYO_OCI_FORBIDDEN_SHAPE_PREFIXES),
        "forbidden_architectures": list(BYO_OCI_FORBIDDEN_ARCHITECTURES),
        "arm_allowed": False,
        "verified_shape": shape,
    }


def hosted_launch_lane_contract() -> dict[str, object]:
    """Return the public dual-lane launch contract."""

    return {
        "schema_version": HOSTED_LAUNCH_LANES_SCHEMA_VERSION,
        "default_lane": MANAGED_FUSEKIT_RUN_LANE,
        "lanes": [lane.to_dict() for lane in hosted_launch_lanes()],
        "cost_policy": (
            "Managed FuseKit runs must capture payment authorization before FuseKit-owned "
            "infrastructure dispatch. Bring-your-own OCI runs keep compute cost in the user's "
            "own tenancy and do not dispatch a FuseKit-managed worker."
        ),
    }


def hosted_launch_lanes() -> tuple[HostedLaunchLane, ...]:
    """Return supported hosted launch lanes."""

    return (
        HostedLaunchLane(
            lane_id=MANAGED_FUSEKIT_RUN_LANE,
            label="Managed FuseKit run",
            cost_owner="user-pays-fusekit",
            worker_owner="fusekit-managed-infrastructure",
            requires_payment=True,
            requires_user_cloud_account=False,
            managed_worker_dispatch_allowed=True,
            summary=(
                "FuseKit captures payment authorization, then dispatches a managed worker "
                "for users who do not want to run cloud setup themselves."
            ),
            gates=(
                "Stripe Checkout payment authorization",
                "GitHub App selected-repository consent",
                "Provider-owned login, MFA, billing, fraud, CAPTCHA, and consent gates",
            ),
            proof=(
                "Redacted Stripe Checkout session receipt",
                "Managed worker dispatch receipt",
                "Run Record, remote artifacts, rollback metadata, and detonation receipt",
            ),
            cost_controls=(
                "Zero unverified FuseKit-managed infrastructure spend is allowed.",
                "Worker dispatch requires a paid Stripe Checkout Session.",
                "Payment receipts must bind to the same job id, lane, and plan fingerprint.",
                "Checkout sessions cannot be reused across launches.",
            ),
        ),
        HostedLaunchLane(
            lane_id=BYO_OCI_LANE,
            label="Bring your own OCI",
            cost_owner="user-pays-oracle-directly",
            worker_owner="user-owned-oci-tenancy",
            requires_payment=False,
            requires_user_cloud_account=True,
            managed_worker_dispatch_allowed=False,
            summary=(
                "FuseKit gives the user a browser-first OCI Cloud Shell bootstrap so the "
                "disposable AMD worker runs inside their tenancy."
            ),
            gates=(
                "Oracle Cloud login, MFA, tenancy/compartment selection, and billing gates",
                "GitHub App selected-repository consent",
                "Provider-owned login, MFA, billing, fraud, CAPTCHA, and consent gates",
            ),
            proof=(
                "OCI Cloud Shell bootstrap receipt",
                "User-tenancy worker request",
                "Run Record, remote artifacts, rollback metadata, and detonation receipt",
            ),
            cost_controls=(
                "FuseKit-managed worker dispatch is disabled.",
                "Compute spend stays in the user's Oracle Cloud tenancy.",
                "Disposable workers must use AMD/x86_64 shapes; ARM images are not allowed.",
                "Human-owned Oracle billing and quota gates must not be bypassed.",
            ),
            user_owned_cost_boundary=byo_oci_user_owned_cost_boundary(),
            security_contract=byo_oci_security_contract(),
        ),
    )


def hosted_launch_lane(lane_id: str) -> HostedLaunchLane:
    """Return one supported lane, failing closed on unknown lane ids."""

    normalized = lane_id.strip().lower()
    for lane in hosted_launch_lanes():
        if lane.lane_id == normalized:
            return lane
    raise FuseKitError("Hosted launch lane is invalid.")


def valid_hosted_launch_lane(lane_id: str) -> bool:
    """Return whether a lane id is supported."""

    return lane_id.strip().lower() in HOSTED_LAUNCH_LANES
