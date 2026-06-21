"""Shared visual-session proof shape for launch gates."""

from __future__ import annotations

VISUAL_STATE_RUNNER = "novnc"
VISUAL_STATE_STATUS = "ready"
VISUAL_STATE_DISPLAY = ":99"
VISUAL_STATE_NOTES = (
    "The browser is running on the disposable OCI VM.",
    "Use the noVNC window to complete human gates in the same session FuseKit observes.",
)
VISUAL_TRANSPORT_FIELDS = frozenset(
    {
        "novnc_url",
        "control_room_url",
        "novnc_password",
        "provider_browser_profile",
    }
)
VISUAL_STATE_TEXT_FIELDS = (
    "runner",
    "status",
    "display",
    "novnc_url",
    "control_room_url",
    "novnc_password",
    "provider_browser_profile",
)
VISUAL_STATE_KEYS = frozenset(
    {
        *VISUAL_STATE_TEXT_FIELDS,
        "interactive",
        "notes",
    }
)
