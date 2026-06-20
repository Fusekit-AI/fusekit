"""Shared automation-boundary proof shape for launch gates."""

from __future__ import annotations

from fusekit.runner.durable_state_proof import DURABLE_STATE_DETONATION_SCOPE_MODE

AUTOMATION_BOUNDARY_SCHEMA_VERSION = "fusekit.automation-boundary.v1"
AUTOMATION_BOUNDARY_READY_STATUS = "ready"
AUTOMATION_BOUNDARY_REPAIR_STATUS = "needs_route_repair"
AUTOMATION_BOUNDARY_DETONATION_SCOPE = DURABLE_STATE_DETONATION_SCOPE_MODE
AUTOMATION_BOUNDARY_STATEMENT_TERMS = ("vnc", "api", "detonate")
AUTOMATION_BOUNDARY_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "resume_after_worker_replace",
        "detonation_scope",
        "no_user_machine_state",
        "vnc_allowed_for",
        "routes",
        "counts",
        "post_gate_automation",
        "statement",
    }
)
AUTOMATION_BOUNDARY_ROUTE_KEYS = frozenset(
    {
        "provider",
        "recipe",
        "route",
        "owner",
        "deterministic",
        "implemented",
        "status",
    }
)
AUTOMATION_BOUNDARY_COUNTS_KEYS = frozenset(
    {
        "fusekit_owned",
        "human_gate",
        "blocked",
        "guided_human_actions",
    }
)
AUTOMATION_BOUNDARY_POST_GATE_KEYS = frozenset(
    {
        "api_or_cli_routes",
        "human_gate_routes",
    }
)
AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST = frozenset(
    {
        "login",
        "mfa",
        "captcha",
        "consent",
        "payment",
        "copy_once_secret",
    }
)
AUTOMATION_BOUNDARY_ROUTE_OWNERS = frozenset({"fusekit", "human_gate"})
AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS = frozenset(
    {"api", "official_cli", "local_vault"}
)
AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS = frozenset(
    {"browser_guided", "human_follow_me"}
)
