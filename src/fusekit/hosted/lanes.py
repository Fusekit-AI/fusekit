"""Hosted launch lane contracts for managed and bring-your-own runs."""

from __future__ import annotations

from dataclasses import dataclass

HOSTED_LAUNCH_LANES_SCHEMA_VERSION = "fusekit.hosted-launch-lanes.v1"
MANAGED_FUSEKIT_RUN_LANE = "managed-fusekit-run"
BYO_OCI_LANE = "bring-your-own-oci"
HOSTED_LAUNCH_LANES = (MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE)


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

    def to_dict(self) -> dict[str, object]:
        """Serialize browser-safe lane metadata."""

        return {
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
            "secret_boundary": (
                "Lane contracts expose ownership, gates, and proof labels only. They never "
                "include cloud credentials, payment method details, provider tokens, or vault "
                "material."
            ),
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
        ),
    )


def hosted_launch_lane(lane_id: str) -> HostedLaunchLane:
    """Return one supported lane, falling back to the managed lane."""

    normalized = lane_id.strip().lower()
    for lane in hosted_launch_lanes():
        if lane.lane_id == normalized:
            return lane
    return hosted_launch_lanes()[0]


def valid_hosted_launch_lane(lane_id: str) -> bool:
    """Return whether a lane id is supported."""

    return lane_id.strip().lower() in HOSTED_LAUNCH_LANES
