"""Browser-reachable control-room route inventory."""

from __future__ import annotations

from typing import Any

CONTROL_ROOM_ROUTE_SURFACE: tuple[dict[str, object], ...] = (
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
        "protection": "control-room-header-origin-fetch-site-action-token",
    },
    {
        "route": "/api/gates/<gate_id>/open",
        "methods": ("POST",),
        "state_change": True,
        "protection": "control-room-header-origin-fetch-site-action-token",
    },
    {
        "route": "/api/gates/<gate_id>/capture-clipboard",
        "methods": ("POST",),
        "state_change": True,
        "protection": "control-room-header-origin-fetch-site-action-token",
    },
    {
        "route": "unknown",
        "methods": ("GET", "POST", "OPTIONS"),
        "state_change": False,
        "protection": "security-headers-no-cors-posts-auth-before-404",
    },
)


def public_control_room_security_surface() -> dict[str, Any]:
    """Return the route inventory in a browser-safe product-proof shape."""

    routes: list[dict[str, Any]] = []
    for surface in CONTROL_ROOM_ROUTE_SURFACE:
        raw_methods = surface.get("methods", ())
        methods = (
            [str(method) for method in raw_methods]
            if isinstance(raw_methods, tuple)
            else []
        )
        routes.append(
            {
                "route": str(surface["route"]),
                "methods": methods,
                "state_change": surface["state_change"] is True,
                "protection": str(surface["protection"]),
            }
        )
    state_changing = [route for route in routes if route["state_change"] is True]
    return {
        "schema_version": "fusekit.control-room-security-surface.v1",
        "routes": routes,
        "route_count": len(routes),
        "state_changing_route_count": len(state_changing),
        "state_changing_routes": [route["route"] for route in state_changing],
        "required_post_protection": "control-room-header-origin-fetch-site-action-token",
        "unknown_route_protection": "security-headers-no-cors-posts-auth-before-404",
        "statement": (
            "The control room has three browser-reachable state-changing routes. "
            "Each one requires the explicit control-room header, trusted browser "
            "origin/fetch-site metadata when present, and the owner-only action token."
        ),
    }
