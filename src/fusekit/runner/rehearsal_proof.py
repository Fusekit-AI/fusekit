"""Shared human-action and rehearsal-review proof shapes for launch gates."""

from __future__ import annotations

HUMAN_ACTION_TRACE_SCHEMA_VERSION = "fusekit.human-action-trace.v1"
REHEARSAL_REVIEW_SCHEMA_VERSION = "fusekit.rehearsal-review.v1"

OPEN_PROVIDER_GATE_ACTION = "open_provider_gate"
CAPTURE_VM_CLIPBOARD_ACTION = "capture_vm_clipboard"
CONFIRM_GATE_FINISHED_ACTION = "confirm_gate_finished"
HUMAN_ACTION_COUNT_KEYS = frozenset(
    {
        OPEN_PROVIDER_GATE_ACTION,
        CAPTURE_VM_CLIPBOARD_ACTION,
        CONFIRM_GATE_FINISHED_ACTION,
    }
)

OPEN_PROVIDER_GATE_CONTROL = "Open provider gate in VM"
FINISH_VISIBLE_CONTROLS = frozenset(
    {
        "I finished this step",
        "Approve DNS apply",
        "Approve setup plan",
    }
)

HUMAN_ACTION_KEYS = frozenset(
    {
        "gate_id",
        "provider",
        "classification",
        "action",
        "visible_control",
        "target",
        "guided",
        "guidance_gap",
        "created_at",
    }
)
REHEARSAL_REVIEW_ACTION_KEYS = frozenset(
    {
        "gate_id",
        "action",
        "visible_control",
        "target",
        "matched",
        "proof_source",
    }
)

GATE_PROOF_SOURCE = "gates.json"
GATE_WAKE_PROOF_SOURCE = "gates.json + gate_events.jsonl"
UNKNOWN_PROOF_SOURCE = "unknown"


def capture_vm_clipboard_control(target: str) -> str:
    """Return the exact visible capture control for a known copy-once target."""

    return f"Capture {target} from VM clipboard"


def rehearsal_review_proof_source(action_name: str) -> str:
    """Return the non-secret survivor source expected for a human action."""

    if action_name == OPEN_PROVIDER_GATE_ACTION:
        return GATE_PROOF_SOURCE
    if action_name in {CAPTURE_VM_CLIPBOARD_ACTION, CONFIRM_GATE_FINISHED_ACTION}:
        return GATE_WAKE_PROOF_SOURCE
    return UNKNOWN_PROOF_SOURCE
