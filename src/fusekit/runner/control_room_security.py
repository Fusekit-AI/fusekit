"""Shared control-room security proof shape for launch gates."""

from __future__ import annotations

from typing import Any

CONTROL_ROOM_SECURITY_SCHEMA_VERSION = "fusekit.control-room-security-surface.v1"
CONTROL_ROOM_REQUIRED_POST_PROTECTION = (
    "control-room-header-origin-fetch-site-action-token"
)
CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION = "security-headers-no-cors-posts-auth-before-404"
CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS = frozenset(
    {"action-token", "origin", "fetch-site"}
)
CONTROL_ROOM_SECURITY_STATEMENT_TERMS = frozenset({"owner-only action token", "no cors"})
CONTROL_ROOM_PROTECTED_MUTATION_ROUTES = frozenset(
    {
        "/api/gates/<gate_id>/pass",
        "/api/gates/<gate_id>/open",
        "/api/gates/<gate_id>/capture-clipboard",
    }
)
CONTROL_ROOM_SECURITY_KEYS = frozenset(
    {
        "schema_version",
        "routes",
        "route_count",
        "state_changing_route_count",
        "state_changing_routes",
        "required_post_protection",
        "unknown_route_protection",
        "statement",
    }
)
CONTROL_ROOM_SECURITY_ROUTE_KEYS = frozenset(
    {
        "route",
        "methods",
        "state_change",
        "protection",
    }
)
CONTROL_ROOM_ROUTE_SURFACE: tuple[dict[str, Any], ...] = (
    {
        "route": "/",
        "methods": ("GET",),
        "state_change": False,
        "protection": "local-or-remote-token",
    },
    {
        "route": "/index.html",
        "methods": ("GET",),
        "state_change": False,
        "protection": "local-or-remote-token",
    },
    {
        "route": "/api/job",
        "methods": ("GET",),
        "state_change": False,
        "protection": "local-or-remote-token",
    },
    {
        "route": "/api/gates/<gate_id>/pass",
        "methods": ("POST",),
        "state_change": True,
        "protection": CONTROL_ROOM_REQUIRED_POST_PROTECTION,
    },
    {
        "route": "/api/gates/<gate_id>/open",
        "methods": ("POST",),
        "state_change": True,
        "protection": CONTROL_ROOM_REQUIRED_POST_PROTECTION,
    },
    {
        "route": "/api/gates/<gate_id>/capture-clipboard",
        "methods": ("POST",),
        "state_change": True,
        "protection": CONTROL_ROOM_REQUIRED_POST_PROTECTION,
    },
    {
        "route": "unknown",
        "methods": ("GET", "POST", "OPTIONS"),
        "state_change": False,
        "protection": CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION,
    },
)
