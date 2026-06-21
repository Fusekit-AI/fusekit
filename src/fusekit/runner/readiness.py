"""Shared runner-readiness contract for OCI visual workers."""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from typing import Any

RUNNER_READINESS_SCHEMA_VERSION = "fusekit.runner-readiness.v1"
RUNNER_PROFILE_SCHEMA_VERSION = "fusekit.runner-profile.v1"
RUNNER_READINESS_READY_STATUS = "ready"
EXPECTED_PROVIDER_BROWSER_PROFILE = (
    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
)
REQUIRED_RUNNER_READINESS_CHECKS = (
    "x86_64_architecture",
    "runner_helpers",
    "visual_commands",
    "novnc",
    "openclaw",
    "playwright_chromium",
    "shared_provider_browser_profile",
)
EXPECTED_RUNNER_PROFILE = "oci-visual-browser-x86_64"
MIN_RUNNER_MEMORY_MIB = 15360
EXPECTED_RUNNER_PORTS = {
    "ssh": 22,
    "control_room": 8765,
    "novnc": 6080,
    "vnc_loopback": 5900,
    "openclaw_gateway_loopback": 19002,
}
REQUIRED_RUNNER_BINARIES = (
    "python",
    "fusekit",
    "fusekit_runner_verify",
    "fusekit_runner_loop_once",
    "fusekit_visual_start",
    "openclaw",
    "xvfb",
    "x11vnc",
    "fluxbox",
    "novnc_gateway",
    "playwright_chromium",
)
RUNNER_READINESS_KEYS = frozenset(
    {
        "architecture",
        "checks",
        "installed_binaries",
        "observed",
        "playwright_browsers_path",
        "profile_contract",
        "provider_browser_profile",
        "schema_version",
        "status",
    }
)
RUNNER_PROFILE_CONTRACT_KEYS = frozenset(
    {
        "architecture",
        "browser_stack",
        "min_memory_mib",
        "name",
        "os_family",
        "ports",
        "required_binaries",
        "required_health_checks",
        "schema_version",
        "supported_os_ids",
    }
)
RUNNER_BROWSER_STACK_KEYS = frozenset(
    {
        "automation",
        "browser",
        "shared_provider_profile",
        "spine",
    }
)
RUNNER_OBSERVED_KEYS = frozenset({"memory_mib", "os_id", "os_version", "python"})
RUNNER_BINARY_RECORD_KEYS = frozenset({"path", "present", "version"})


def runner_readiness_failures(readiness: dict[str, Any]) -> list[str]:
    """Return contract failures for a prepared disposable OCI browser runner."""

    failures: list[str] = []
    failures.extend(_runner_readiness_shape_failures(readiness))
    if str(readiness.get("schema_version", "")).strip() != (
        RUNNER_READINESS_SCHEMA_VERSION
    ):
        failures.append(f"schema_version must be {RUNNER_READINESS_SCHEMA_VERSION}")
    if str(readiness.get("status", "")).strip() != RUNNER_READINESS_READY_STATUS:
        failures.append("status must be ready")
    if str(readiness.get("architecture", "")).strip().lower() not in {"x86_64", "amd64"}:
        failures.append("architecture must be x86_64")
    checks = readiness.get("checks")
    if not isinstance(checks, dict):
        failures.append("checks must be a JSON object")
    else:
        for name in REQUIRED_RUNNER_READINESS_CHECKS:
            if checks.get(name) is not True:
                failures.append(f"{name} must be true")
    profile = readiness.get("profile_contract")
    if not isinstance(profile, dict):
        failures.append("profile_contract must be a JSON object")
    else:
        failures.extend(runner_profile_contract_failures(profile))
    observed = readiness.get("observed")
    if not isinstance(observed, dict):
        failures.append("observed runner facts must be a JSON object")
    else:
        memory_mib = _int_field(observed.get("memory_mib"), 0)
        if memory_mib < MIN_RUNNER_MEMORY_MIB:
            failures.append("observed memory must be at least 16 GB")
        if str(observed.get("os_id", "")).strip().lower() not in {"ubuntu", "ol"}:
            failures.append("observed OS must be Ubuntu or Oracle Linux")
    if str(readiness.get("provider_browser_profile", "")).strip() != (
        EXPECTED_PROVIDER_BROWSER_PROFILE
    ):
        failures.append("shared provider browser profile path is required")
    if not str(readiness.get("playwright_browsers_path", "")).strip():
        failures.append("Playwright browser cache path is required")
    failures.extend(_installed_binaries_failures(readiness.get("installed_binaries")))
    return failures


def runner_profile_contract_failures(profile: dict[str, Any]) -> list[str]:
    """Return contract failures for the runner profile embedded in readiness proof."""

    failures: list[str] = []
    failures.extend(_runner_profile_shape_failures(profile))
    if str(profile.get("schema_version", "")).strip() != RUNNER_PROFILE_SCHEMA_VERSION:
        failures.append(
            f"runner profile schema_version must be {RUNNER_PROFILE_SCHEMA_VERSION}"
        )
    if str(profile.get("name", "")).strip() != EXPECTED_RUNNER_PROFILE:
        failures.append(f"runner profile name must be {EXPECTED_RUNNER_PROFILE}")
    if str(profile.get("architecture", "")).strip().lower() not in {"x86_64", "amd64"}:
        failures.append("runner profile architecture must be x86_64")
    if str(profile.get("os_family", "")).strip().lower() != "linux":
        failures.append("runner profile OS family must be linux")
    supported_os = profile.get("supported_os_ids")
    if not isinstance(supported_os, list) or not {"ubuntu", "ol"}.issubset(
        {str(item).lower() for item in supported_os}
    ):
        failures.append("runner profile must support Ubuntu and Oracle Linux image ids")
    if _int_field(profile.get("min_memory_mib"), 0) < MIN_RUNNER_MEMORY_MIB:
        failures.append("runner profile min_memory_mib must be at least 16 GB")
    ports = profile.get("ports")
    if not isinstance(ports, dict):
        failures.append("runner profile ports must be a JSON object")
    else:
        for key, value in EXPECTED_RUNNER_PORTS.items():
            if _int_field(ports.get(key), -1) != value:
                failures.append(f"runner profile port {key} must be {value}")
    browser_stack = profile.get("browser_stack")
    if not isinstance(browser_stack, dict):
        failures.append("runner profile browser_stack must be a JSON object")
    else:
        expected_browser = {
            "spine": "openclaw",
            "automation": "playwright",
            "browser": "chromium",
            "shared_provider_profile": EXPECTED_PROVIDER_BROWSER_PROFILE,
        }
        for key, expected_value in expected_browser.items():
            if str(browser_stack.get(key, "")).strip() != expected_value:
                failures.append(
                    f"runner profile browser_stack.{key} must be {expected_value}"
                )
    health_checks = profile.get("required_health_checks")
    if not isinstance(health_checks, list):
        failures.append("runner profile required_health_checks must be a list")
    else:
        missing = [
            item
            for item in REQUIRED_RUNNER_READINESS_CHECKS
            if item not in {str(check) for check in health_checks}
        ]
        if missing:
            failures.append(
                "runner profile required_health_checks missing " + ", ".join(missing)
            )
    required_binaries = profile.get("required_binaries")
    if not isinstance(required_binaries, list):
        failures.append("runner profile required_binaries must be a list")
    else:
        missing = [
            item
            for item in REQUIRED_RUNNER_BINARIES
            if item not in {str(binary) for binary in required_binaries}
        ]
        if missing:
            failures.append("runner profile required_binaries missing " + ", ".join(missing))
    return failures


def _installed_binaries_failures(installed: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(installed, dict):
        return ["installed_binaries must be a JSON object"]
    unexpected_binaries = sorted(set(installed) - set(REQUIRED_RUNNER_BINARIES))
    if unexpected_binaries:
        failures.append(
            "installed_binaries has unexpected fields: "
            + ", ".join(unexpected_binaries)
        )
    for name in REQUIRED_RUNNER_BINARIES:
        raw = installed.get(name)
        if not isinstance(raw, dict):
            failures.append(f"installed_binaries.{name} must be a JSON object")
            continue
        unexpected = sorted(set(raw) - RUNNER_BINARY_RECORD_KEYS)
        if unexpected:
            failures.append(
                f"installed_binaries.{name} has unexpected fields: " + ", ".join(unexpected)
            )
        if raw.get("present") is not True:
            failures.append(f"installed_binaries.{name}.present must be true")
        path = raw.get("path", "")
        if not isinstance(path, str) or not path.strip():
            failures.append(f"installed_binaries.{name}.path is required")
        elif path != path.strip():
            failures.append(f"installed_binaries.{name}.path must be trimmed")
        version = raw.get("version", "")
        if version is not None:
            if not isinstance(version, str):
                failures.append(f"installed_binaries.{name}.version must be a string")
            elif version != version.strip():
                failures.append(f"installed_binaries.{name}.version must be trimmed")
    return failures


def _runner_readiness_shape_failures(readiness: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(readiness) - RUNNER_READINESS_KEYS)
    if unexpected:
        failures.append("artifact has unexpected fields: " + ", ".join(unexpected))
    for key in (
        "schema_version",
        "status",
        "architecture",
        "provider_browser_profile",
        "playwright_browsers_path",
    ):
        _append_trimmed_string_failure(failures, readiness.get(key), key)
    _append_boolean_map_shape_failures(
        failures,
        readiness.get("checks"),
        "checks",
        set(REQUIRED_RUNNER_READINESS_CHECKS),
    )
    observed = readiness.get("observed")
    if isinstance(observed, dict):
        unexpected_observed = sorted(set(observed) - RUNNER_OBSERVED_KEYS)
        if unexpected_observed:
            failures.append(
                "observed has unexpected fields: " + ", ".join(unexpected_observed)
            )
        for key in ("os_id", "os_version", "python"):
            _append_trimmed_string_failure(failures, observed.get(key), f"observed.{key}")
        _append_plain_int_failure(
            failures,
            observed.get("memory_mib"),
            "observed.memory_mib",
        )
    return failures


def _runner_profile_shape_failures(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(profile) - RUNNER_PROFILE_CONTRACT_KEYS)
    if unexpected:
        failures.append("runner profile has unexpected fields: " + ", ".join(unexpected))
    for key in ("schema_version", "name", "architecture", "os_family"):
        _append_trimmed_string_failure(failures, profile.get(key), f"runner profile {key}")
    _append_plain_int_failure(
        failures,
        profile.get("min_memory_mib"),
        "runner profile min_memory_mib",
    )
    _append_string_list_shape_failures(
        failures,
        profile.get("supported_os_ids"),
        "runner profile supported_os_ids",
    )
    ports = profile.get("ports")
    if isinstance(ports, dict):
        unexpected_ports = sorted(set(ports) - set(EXPECTED_RUNNER_PORTS))
        if unexpected_ports:
            failures.append(
                "runner profile ports has unexpected fields: "
                + ", ".join(unexpected_ports)
            )
        for key in EXPECTED_RUNNER_PORTS:
            _append_plain_int_failure(
                failures,
                ports.get(key),
                f"runner profile ports.{key}",
            )
    browser_stack = profile.get("browser_stack")
    if isinstance(browser_stack, dict):
        unexpected_browser = sorted(set(browser_stack) - RUNNER_BROWSER_STACK_KEYS)
        if unexpected_browser:
            failures.append(
                "runner profile browser_stack has unexpected fields: "
                + ", ".join(unexpected_browser)
            )
        for key in RUNNER_BROWSER_STACK_KEYS:
            _append_trimmed_string_failure(
                failures,
                browser_stack.get(key),
                f"runner profile browser_stack.{key}",
            )
    _append_string_list_shape_failures(
        failures,
        profile.get("required_health_checks"),
        "runner profile required_health_checks",
    )
    _append_string_list_shape_failures(
        failures,
        profile.get("required_binaries"),
        "runner profile required_binaries",
    )
    return failures


def _append_boolean_map_shape_failures(
    failures: list[str],
    raw: object,
    label: str,
    allowed: AbstractSet[str],
) -> None:
    if not isinstance(raw, dict):
        return
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected))
    for key, value in raw.items():
        if key != str(key).strip():
            failures.append(f"{label}.{key} must be trimmed")
        if not isinstance(value, bool):
            failures.append(f"{label}.{key} must be boolean")


def _append_string_list_shape_failures(
    failures: list[str],
    raw: object,
    label: str,
) -> None:
    if not isinstance(raw, list):
        return
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if not isinstance(item, str):
            failures.append(f"{item_label} must be a string")
        elif item != item.strip():
            failures.append(f"{item_label} must be trimmed")


def _append_trimmed_string_failure(
    failures: list[str],
    value: object,
    label: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        failures.append(f"{label} must be a string")
    elif value != value.strip():
        failures.append(f"{label} must be trimmed")


def _append_plain_int_failure(failures: list[str], value: object, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool):
        failures.append(f"{label} must be an integer")


def _int_field(value: object, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default
