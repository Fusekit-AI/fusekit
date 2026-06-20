"""Shared public provider-playbook shape for launch proof gates."""

from __future__ import annotations

PROVIDER_PLAYBOOK_FAMILIES = {
    "github": frozenset({"github"}),
    "resend": frozenset({"resend"}),
    "vercel": frozenset({"vercel"}),
    "dns": frozenset({"cloudflare", "dns"}),
}
PROVIDER_PLAYBOOK_STEP_FIELDS = (
    "id",
    "provider",
    "route",
    "actor",
    "control",
    "instruction",
    "human_action_required",
    "proof_source",
    "resume_event",
)
PROVIDER_PLAYBOOK_STEP_KEYS = frozenset(PROVIDER_PLAYBOOK_STEP_FIELDS)
