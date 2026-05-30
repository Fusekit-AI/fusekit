"""Runner lane selection."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from fusekit.errors import FuseKitError

RUNNERS = ("auto", "local", "oci-cloud-shell", "oci-free", "oci-existing")


@dataclass(frozen=True)
class RunnerResolution:
    """Resolved runner lane."""

    requested: str
    selected: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        """Serialize the runner resolution."""

        return {
            "requested": self.requested,
            "selected": self.selected,
            "reason": self.reason,
        }


def resolve_runner(
    requested: str,
    *,
    allow_incomplete: bool = False,
    oci_config_file: Path | None = None,
    vault_has_oci_profile: bool = False,
) -> RunnerResolution:
    """Resolve the runner lane without performing side effects."""

    env_runner = os.environ.get("FUSEKIT_RUNNER", "").strip()
    effective = env_runner or requested
    if effective not in RUNNERS:
        raise FuseKitError(f"Unknown runner requested: {effective}")
    if effective == "local":
        return RunnerResolution(requested, "local", "local runner explicitly selected")
    if effective in {"oci-cloud-shell", "oci-free", "oci-existing"}:
        return RunnerResolution(requested, effective, f"{effective} explicitly selected")
    if allow_incomplete:
        return RunnerResolution(requested, "local", "explicit local rehearsal")
    if vault_has_oci_profile:
        return RunnerResolution(requested, "oci-existing", "encrypted OCI profile found")
    if _has_oci_config(oci_config_file):
        return RunnerResolution(requested, "oci-existing", "existing OCI config found")
    return RunnerResolution(
        requested,
        "oci-cloud-shell",
        "OCI Cloud Shell deeplink runner selected",
    )


def _has_oci_config(path: Path | None) -> bool:
    if path and path.exists():
        return True
    env_path = os.environ.get("OCI_CONFIG_FILE")
    if env_path and Path(env_path).exists():
        return True
    return (Path.home() / ".oci" / "config").exists()
