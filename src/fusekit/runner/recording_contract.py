"""Shared public recording-contract shape for Run Record consumers."""

from __future__ import annotations

RECORDING_CONTRACT_SCHEMA_VERSION = "fusekit.recording-contract.v1"
RECORDING_CONTRACT_FIELD_KEYS = frozenset(
    {
        "blockers",
        "checks",
        "recording_ready",
        "schema_version",
        "statement",
    }
)
RECORDING_CONTRACT_CHECK_KEYS = (
    "durable_state",
    "worker_replacement",
    "runner_profile",
    "provider_playbook",
    "model_inference",
    "timeline",
    "provider_gates",
    "vault",
    "wake_events",
    "human_actions",
    "rehearsal_review",
    "automation_boundary",
    "control_room_security",
    "verifiers",
    "audit_trail",
    "artifacts",
    "evidence",
    "detonation",
    "errors_empty",
)
RECORDING_CONTRACT_SECTION_KEYS: dict[str, tuple[str, ...]] = {
    "durable_state": ("durable_state",),
    "worker_replacement": ("durable_state", "worker_replacement_drill"),
    "runner_profile": ("runner_profile",),
    "provider_playbook": ("provider_playbook",),
    "model_inference": ("model_inference", "llm_contract"),
    "timeline": ("steps", "checkpoints"),
    "provider_gates": ("provider_gates",),
    "vault": ("vault",),
    "wake_events": ("wake_events",),
    "human_actions": ("human_actions",),
    "rehearsal_review": ("rehearsal_review",),
    "automation_boundary": ("automation_boundary",),
    "control_room_security": ("control_room_security",),
    "verifiers": ("verifiers",),
    "audit_trail": ("audit_trail",),
    "artifacts": ("artifacts",),
    "evidence": ("evidence",),
    "detonation": ("detonation",),
}
