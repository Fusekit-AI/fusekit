"""Shared control-room card helpers."""

from __future__ import annotations

from fusekit.runner.job import JobStep

STATUS_LABELS = {
    "created": "Created",
    "pending": "Pending",
    "running": "Running",
    "waiting": "Human gate",
    "done": "Done",
    "failed": "Needs repair",
    "skipped": "Skipped",
    "passed": "Passed",
    "repairing": "Repairing",
    "needs_human_gate": "Needs human gate",
    "resume_requested": "Retrying gate",
}

TERMINAL_STEP_STATUSES = {"done", "skipped"}


def status_label(status: str) -> str:
    """Return the human label for a job/check status."""

    return STATUS_LABELS.get(status, status.replace("_", " ").title())


def status_counts(steps: list[JobStep]) -> dict[str, int]:
    """Count visible timeline statuses for the progress card."""

    counts = {"running": 0, "waiting": 0, "done": 0, "failed": 0}
    for step in steps:
        if step.status in counts:
            counts[step.status] += 1
        elif step.status == "skipped":
            counts["done"] += 1
    return counts


def progress(steps: list[JobStep]) -> tuple[int, int, int]:
    """Return completed, total, and percent values for the progress meter."""

    total = max(len(steps), 1)
    done = sum(1 for step in steps if step.status in TERMINAL_STEP_STATUSES)
    return done, len(steps), round((done / total) * 100)
