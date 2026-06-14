"""Shared runner-readiness contract for OCI visual workers."""

from __future__ import annotations

from typing import Any

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


def runner_readiness_failures(readiness: dict[str, Any]) -> list[str]:
    """Return contract failures for a prepared disposable OCI browser runner."""

    failures: list[str] = []
    if str(readiness.get("schema_version", "")).strip() != "fusekit.runner-readiness.v1":
        failures.append("schema_version must be fusekit.runner-readiness.v1")
    if str(readiness.get("status", "")).strip() != "ready":
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
    if str(profile.get("schema_version", "")).strip() != "fusekit.runner-profile.v1":
        failures.append("runner profile schema_version must be fusekit.runner-profile.v1")
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
    for name in REQUIRED_RUNNER_BINARIES:
        raw = installed.get(name)
        if not isinstance(raw, dict):
            failures.append(f"installed_binaries.{name} must be a JSON object")
            continue
        if raw.get("present") is not True:
            failures.append(f"installed_binaries.{name}.present must be true")
        if not str(raw.get("path", "") or "").strip():
            failures.append(f"installed_binaries.{name}.path is required")
    return failures


def _int_field(value: object, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default
