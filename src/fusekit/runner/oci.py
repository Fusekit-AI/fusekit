"""OCI clean-room runner planning and authorization."""

from __future__ import annotations

import configparser
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fusekit.crypto.oci_keys import generate_oci_signing_key_pair
from fusekit.errors import FuseKitError
from fusekit.runner.remote import render_cloud_init
from fusekit.runtime.bootstrap import OPENCLAW_INSTALL_URL
from fusekit.vault import Vault

OCI_SIGNUP_URL = "https://signup.cloud.oracle.com/"
OCI_CONSOLE_URL = "https://cloud.oracle.com/"
OCI_API_KEYS_URL = "https://cloud.oracle.com/identity/domains/my-profile/api-keys"
DEFAULT_X86_SHAPE = "VM.Standard.E5.Flex"
DEFAULT_X86_OCPUS = 2
DEFAULT_X86_MEMORY_GB = 24
FALLBACK_X86_SHAPES = ("VM.Standard.E4.Flex", "VM.Standard3.Flex")
ARM_SHAPE_FAMILIES = {"A1"}


class CommandRunner(Protocol):
    """Command runner for OCI auth helpers."""

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a command."""


@dataclass(frozen=True)
class OciRunnerPlan:
    """Non-secret OCI runner plan."""

    runner: str
    auth_mode: str
    account_mode: str
    compartment_mode: str
    region: str
    shape: str
    ocpus: int
    memory_gb: int
    fallback_shapes: tuple[str, ...]
    resources: tuple[str, ...]
    gates: tuple[str, ...]
    fusekit_package: str
    cloud_init_preview: str

    def to_dict(self) -> dict[str, object]:
        """Serialize the plan."""

        return {
            "runner": self.runner,
            "auth_mode": self.auth_mode,
            "account_mode": self.account_mode,
            "compartment_mode": self.compartment_mode,
            "region": self.region,
            "shape": self.shape,
            "ocpus": self.ocpus,
            "memory_gb": self.memory_gb,
            "fallback_shapes": list(self.fallback_shapes),
            "resources": list(self.resources),
            "gates": list(self.gates),
            "fusekit_package": self.fusekit_package,
            "cloud_init_preview": self.cloud_init_preview,
        }


def build_oci_runner_plan(
    *,
    runner: str,
    auth_mode: str = "auto",
    account_mode: str = "auto",
    compartment_mode: str = "root",
    region: str = "auto",
    shape: str = "auto",
    fusekit_package: str = "fusekit",
) -> OciRunnerPlan:
    """Build the non-secret OCI runner plan."""

    selected_shape = DEFAULT_X86_SHAPE if shape == "auto" else shape
    if is_arm_shape(selected_shape):
        raise FuseKitError(
            f"OCI runner shape {selected_shape} is ARM-based. FuseKit requires an x86_64 runner."
        )
    ocpus = DEFAULT_X86_OCPUS
    memory = DEFAULT_X86_MEMORY_GB
    if compartment_mode not in {"root", "isolated"}:
        raise FuseKitError(f"Unsupported OCI compartment mode: {compartment_mode}")
    resources = (
        "existing_root_compartment" if compartment_mode == "root" else "isolated_compartment",
        "vcn",
        "public_subnet",
        "internet_gateway",
        "route_rule",
        "network_security_group",
        "ephemeral_ssh_key",
        "compute_instance",
        "boot_volume_delete_on_terminate",
    )
    return OciRunnerPlan(
        runner=runner,
        auth_mode=auth_mode,
        account_mode=account_mode,
        compartment_mode=compartment_mode,
        region=region,
        shape=selected_shape,
        ocpus=ocpus,
        memory_gb=memory,
        fallback_shapes=(
            f"{DEFAULT_X86_SHAPE}:{DEFAULT_X86_OCPUS}:{DEFAULT_X86_MEMORY_GB}",
            *(
                f"{fallback}:{DEFAULT_X86_OCPUS}:{DEFAULT_X86_MEMORY_GB}"
                for fallback in FALLBACK_X86_SHAPES
            ),
        ),
        resources=resources,
        gates=(
            "OCI signup/login/MFA/card verification",
            "OCI API key upload or security-token login",
            "x86_64 Flex capacity availability",
        ),
        fusekit_package=fusekit_package,
        cloud_init_preview=render_cloud_init(
            fusekit_wheel_url=fusekit_package,
            openclaw_install_url=OPENCLAW_INSTALL_URL,
        ),
    )


def is_arm_shape(shape: str) -> bool:
    """Return true when an OCI shape is known to use Arm architecture."""

    return any(part in ARM_SHAPE_FAMILIES for part in shape.split("."))


def oci_runtime_status(config_file: Path | None = None) -> dict[str, object]:
    """Return non-secret OCI runner readiness."""

    config = config_file or Path(os.environ.get("OCI_CONFIG_FILE", Path.home() / ".oci/config"))
    return {
        "oci_cli": bool(shutil.which("oci")),
        "oci_config": config.exists(),
        "oci_config_path": str(config),
        "signup_url": OCI_SIGNUP_URL,
        "api_keys_url": OCI_API_KEYS_URL,
    }


def has_vault_oci_profile(vault: Vault) -> bool:
    """Return true when the encrypted vault has an OCI runner profile."""

    try:
        vault.require("runner.oci.profile")
    except FuseKitError:
        return False
    return True


def capture_oci_api_key_profile(
    vault: Vault,
    *,
    config_snippet: str,
    label: str = "default",
) -> str:
    """Generate and store an OCI API signing key plus config snippet in the vault."""

    if "tenancy" not in config_snippet or "user" not in config_snippet:
        raise FuseKitError("OCI config snippet must include tenancy and user values.")
    public_key = prepare_oci_api_signing_key(vault, label=label)
    fingerprint = vault.require("runner.oci.api_signing_key.private").metadata["fingerprint"]
    vault.put(
        "runner.oci.config",
        "oci_config",
        "oci",
        "OCI CLI/SDK config snippet",
        config_snippet,
        {"fingerprint": fingerprint, "label": label},
    )
    vault.put(
        "runner.oci.profile",
        "runner_profile",
        "oci",
        "OCI clean-room runner profile",
        f"oci:{label}",
        {"auth_mode": "api-key-upload", "fingerprint": fingerprint},
    )
    return public_key


def authorize_oci_browser_session(
    *,
    config_file: Path,
    profile: str,
    region: str,
    runner: CommandRunner | None = None,
) -> None:
    """Run OCI's browser-session authorization flow."""

    config_file.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "oci",
        "session",
        "authenticate",
        "--config-file",
        str(config_file),
        "--profile",
        profile,
        "--region",
        region,
    ]
    completed = (runner or _default_runner)(command)
    if completed.returncode != 0:
        raise FuseKitError(completed.stderr or completed.stdout or "OCI browser auth failed.")


def capture_oci_session_profile(
    vault: Vault,
    *,
    config_file: Path,
    profile: str,
) -> None:
    """Capture an OCI CLI browser-session profile into the encrypted vault."""

    parser = configparser.ConfigParser()
    parser.read(config_file)
    if profile not in parser:
        raise FuseKitError(f"OCI profile was not created: {profile}")
    section = parser[profile]
    config_payload = _section_to_config(profile, section)
    vault.put(
        "runner.oci.config",
        "oci_config",
        "oci",
        "OCI browser-session config",
        config_payload,
        {"profile": profile, "auth_mode": "browser-session"},
    )
    token_file = section.get("security_token_file", "")
    if token_file:
        token_path = Path(token_file).expanduser()
        vault.put(
            "runner.oci.session_token",
            "oci_security_token",
            "oci",
            "OCI browser-session security token",
            token_path.read_text(encoding="utf-8").strip(),
            {"profile": profile},
        )
    key_file = section.get("key_file", "")
    if key_file:
        key_path = Path(key_file).expanduser()
        vault.put(
            "runner.oci.session_private_key",
            "oci_session_private_key",
            "oci",
            "OCI browser-session private key",
            key_path.read_text(encoding="utf-8"),
            {"profile": profile},
        )
    vault.put(
        "runner.oci.profile",
        "runner_profile",
        "oci",
        "OCI clean-room runner profile",
        f"oci:{profile}",
        {"auth_mode": "browser-session", "profile": profile},
    )


def prepare_oci_api_signing_key(vault: Vault, *, label: str = "default") -> str:
    """Generate or return the public half of FuseKit's pending OCI signing key."""

    try:
        return vault.require("runner.oci.api_signing_key.public").value
    except FuseKitError:
        key_pair = generate_oci_signing_key_pair()
    vault.put(
        "runner.oci.api_signing_key.private",
        "oci_api_signing_private_key",
        "oci",
        "OCI API signing private key",
        key_pair.private_key_pem,
        {"fingerprint": key_pair.fingerprint, "label": label},
    )
    vault.put(
        "runner.oci.api_signing_key.public",
        "oci_api_signing_public_key",
        "oci",
        "OCI API signing public key",
        key_pair.public_key_pem,
        {"fingerprint": key_pair.fingerprint, "label": label},
    )
    return key_pair.public_key_pem


def _section_to_config(profile: str, section: configparser.SectionProxy) -> str:
    lines = [f"[{profile}]"]
    for key, value in section.items():
        if key in {"security_token_file", "key_file"}:
            continue
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, check=False, text=True, timeout=900)
    except FileNotFoundError as exc:
        raise FuseKitError("OCI CLI is not installed or not on PATH.") from exc
