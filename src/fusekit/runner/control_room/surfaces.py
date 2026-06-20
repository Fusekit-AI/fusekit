"""Browser-reachable control-room route inventory."""

from __future__ import annotations

from typing import Any

from fusekit.runner.control_room_security import (
    CONTROL_ROOM_REQUIRED_POST_PROTECTION,
    CONTROL_ROOM_ROUTE_SURFACE,
    CONTROL_ROOM_SECURITY_SCHEMA_VERSION,
    CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION,
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
        "schema_version": CONTROL_ROOM_SECURITY_SCHEMA_VERSION,
        "routes": routes,
        "route_count": len(routes),
        "state_changing_route_count": len(state_changing),
        "state_changing_routes": [route["route"] for route in state_changing],
        "required_post_protection": CONTROL_ROOM_REQUIRED_POST_PROTECTION,
        "unknown_route_protection": CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION,
        "statement": (
            "The control room has three browser-reachable state-changing routes. "
            "Each one requires the explicit control-room header, trusted browser "
            "origin/fetch-site metadata when present, and the owner-only action token; "
            "responses emit no CORS allow headers."
        ),
    }
