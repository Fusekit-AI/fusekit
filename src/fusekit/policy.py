"""Default-deny policy decisions for setup actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from fusekit.errors import ApprovalRequired, PolicyError

Decision = Literal["allow", "deny", "approval_required"]


APPROVAL_PATTERNS = (
    "dns.apply",
    "billing.",
    "payment.",
    "destructive.",
    "ssh.exec",
)

ALLOW_PATTERNS = (
    "vault.",
    "scan.",
    "validate.",
    "plan.",
    "github.configure_repo",
    "github.authorize",
    "vercel.authorize",
    "vercel.configure_project",
    "vercel.deploy_verify",
    "dns.propose",
    "webhook.secret",
    "receipt.",
    "detonate.",
)


@dataclass(frozen=True)
class PolicyDecision:
    """A policy decision for an action."""

    action_id: str
    decision: Decision
    reason: str


def decide(action_id: str, approved: bool = False) -> PolicyDecision:
    """Return the fail-closed decision for an action id."""

    if any(action_id.startswith(pattern) for pattern in APPROVAL_PATTERNS):
        if approved:
            return PolicyDecision(action_id, "allow", "explicitly approved")
        return PolicyDecision(action_id, "approval_required", "human approval required")
    if any(action_id.startswith(pattern) for pattern in ALLOW_PATTERNS):
        return PolicyDecision(action_id, "allow", "known safe setup action")
    return PolicyDecision(action_id, "deny", "unknown action denied by default")


def require_allowed(action_id: str, approved: bool = False) -> None:
    """Raise when an action is denied or missing approval."""

    decision = decide(action_id, approved=approved)
    if decision.decision == "approval_required":
        raise ApprovalRequired(f"{action_id} requires explicit approval.")
    if decision.decision == "deny":
        raise PolicyError(f"{action_id} is denied by default.")
