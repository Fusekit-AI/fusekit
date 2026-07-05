"""Redacted posture validation for the permanent OCI hosted launcher."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_REQUIRED_FILE_ENV,
    HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION,
    HOSTED_RUNTIME_STRIPE_ENV,
)
from fusekit.hosted.verify import HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
from fusekit.security import contains_durable_secret_text, redact_public_text

OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION = "fusekit.oci-host-posture-evidence.v1"
OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION = "fusekit.oci-host-posture-report.v1"
OCI_HOST_POSTURE_REQUIRED_SERVICES = (
    "nginx",
    "fusekit-hosted",
    "fusekit-worker-dispatch",
)
OCI_HOST_POSTURE_SYSTEMD_UNITS = (
    "fusekit-hosted",
    "fusekit-worker-dispatch",
)
OCI_HOST_POSTURE_ALLOWED_PUBLIC_PORTS = (80, 443)
OCI_HOST_POSTURE_ALLOWED_WRITABLE_PATHS = (
    "/var/lib/fusekit",
    "/var/log/fusekit",
    "/run/fusekit",
)
OCI_HOST_POSTURE_WILDCARD_IPV4_BIND = ".".join(("0", "0", "0", "0"))
OCI_HOST_POSTURE_WILDCARD_IPV6_BIND = ":" * 2
OCI_HOST_POSTURE_SECRET_DIR = "/etc/fusekit"
OCI_HOST_POSTURE_SECRET_FILE = "/etc/fusekit/hosted-secrets.env"
OCI_HOST_POSTURE_ORIGIN = "https://fusekit.snowmanai.org"
OCI_HOST_POSTURE_DEFAULT_CIS_SUMMARY = "/var/lib/fusekit/posture/cis-summary.json"
OCI_HOST_POSTURE_DEFAULT_ROOTKIT_SUMMARY = "/var/lib/fusekit/posture/rootkit-summary.json"
OCI_HOST_POSTURE_MAX_JSON_BYTES = 1_048_576
OCI_HOST_POSTURE_OUTPUT_MODE = 0o600
OCI_HOST_POSTURE_ALLOWED_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "architecture",
        "shape",
        "running_services",
        "public_ports",
        "ssh_ingress",
        "runtime_secret_dir",
        "runtime_secret_file",
        "runtime_secret_verify",
        "patch_posture",
        "cis_baseline",
        "rootkit_scan",
        "systemd_units",
        "hosted_verify",
        "dns_propagation",
        "release_receipt",
        "rollback_metadata",
        "collection",
    }
)
OCI_HOST_POSTURE_RELEASE_RECEIPT_SCHEMA_VERSION = "fusekit.oci-hosted-release-receipt.v1"
OCI_HOST_POSTURE_RELEASE_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "target",
        "mutated_paths",
        "restarted_services",
        "before_commit_sha",
        "after_commit_sha",
        "release_dir",
        "rollback",
        "post_deploy_proof_command",
        "secret_boundary",
    }
)
OCI_HOST_POSTURE_RELEASE_ROLLBACK_KEYS = frozenset({"mode", "previous_commit_sha"})
OCI_HOST_POSTURE_RELEASE_MUTATED_PATHS = (
    "/opt/fusekit/current",
    "/etc/fusekit/hosted-provenance.env",
    "/var/lib/fusekit/release-receipts",
)
OCI_HOST_POSTURE_RELEASE_RESTARTED_SERVICES = (
    "fusekit-hosted.service",
    "fusekit-worker-dispatch.service",
)
OCI_HOST_POSTURE_PUBLIC_GIT_SHA_KEYS = frozenset(
    {
        "actual_commit_sha",
        "after_commit_sha",
        "before_commit_sha",
        "commit_sha",
        "expected_commit_sha",
        "previous_commit_sha",
    }
)
OCI_HOST_POSTURE_SECRET_METADATA_KEYS = frozenset({"path", "owner", "group", "mode"})
OCI_HOST_POSTURE_RUNTIME_SECRET_VERIFY_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "mutates_host",
        "mutates_provider",
        "ready",
        "ready_for_managed_payment_staging",
        "blockers",
        "secret_file",
        "required_runtime_env",
        "stripe_runtime_env",
        "key_inventory",
        "next_actions",
        "secret_boundary",
    }
)
OCI_HOST_POSTURE_RUNTIME_SECRET_VERIFY_FILE_KEYS = frozenset(
    {
        "path",
        "exists",
        "regular_file",
        "symlink",
        "mode",
        "owner_only",
        "parent_mode",
        "parent_private_enough",
        "root_owned_required",
        "root_owned",
    }
)
OCI_HOST_POSTURE_RUNTIME_SECRET_ENV_ROW_KEYS = frozenset({"present"})
OCI_HOST_POSTURE_RUNTIME_SECRET_KEY_INVENTORY_KEYS = frozenset(
    {"required_count", "present_required_count", "missing", "unexpected_keys"}
)
OCI_HOST_POSTURE_STRIPE_RUNTIME_ENV_KEYS = frozenset(HOSTED_RUNTIME_STRIPE_ENV)
OCI_HOST_POSTURE_STRIPE_RUNTIME_ENV_ROW_KEYS = {
    "FUSEKIT_STRIPE_SECRET_KEY": frozenset({"configured", "account_mode"}),
    "FUSEKIT_STRIPE_PRICE_ID": frozenset({"configured", "public_id"}),
    "FUSEKIT_MANAGED_RUN_PRICE_LABEL": frozenset({"configured", "public_label"}),
    "FUSEKIT_MANAGED_RUNS_ENABLED": frozenset(
        {"configured", "must_remain_disabled", "enabled"}
    ),
}
OCI_HOST_POSTURE_PATCH_POSTURE_KEYS = frozenset(
    {"pending_security_updates", "reboot_required"}
)
OCI_HOST_POSTURE_DNS_PROPAGATION_KEYS = frozenset(
    {"public_origin", "origin", "domain", "hostname", "status", "propagated", "ready"}
)
OCI_HOST_POSTURE_ROLLBACK_METADATA_KEYS = frozenset({"rollback", "actions"})
OCI_HOST_POSTURE_ROLLBACK_ACTION_KEYS = frozenset({"action", "status", "target"})
OCI_HOST_POSTURE_HOSTED_VERIFY_KEYS = frozenset(
    {
        "schema_version",
        "public_origin",
        "worker_dispatch_url",
        "ready",
        "blocking_checks",
        "readiness_summary",
        "next_actions",
        "checks",
        "secret_boundary",
        "source_provenance",
        "commit_sha",
        "error",
    }
)
OCI_HOST_POSTURE_HOSTED_VERIFY_SOURCE_PROVENANCE_KEYS = frozenset(
    {"actual", "expected"}
)
OCI_HOST_POSTURE_HOSTED_VERIFY_SOURCE_PROVENANCE_ROW_KEYS = frozenset(
    {"commit_sha"}
)
OCI_HOST_POSTURE_HOSTED_VERIFY_CHECK_KEYS = frozenset(
    {
        "id",
        "url",
        "status",
        "http_status",
        "schema_version",
        "failures",
        "hostname",
        "addresses",
        "expected_commit_sha",
        "actual_commit_sha",
        "diagnosis",
        "next_action",
    }
)
OCI_HOST_POSTURE_REQUIRED_HOSTED_VERIFY_CHECK_IDS = (
    "hosted.dns",
    "hosted.home",
    "hosted.health",
    "hosted.readiness",
    "hosted.deployment",
    "hosted.expected_commit",
    "hosted.github_intake",
    "worker_dispatch.dns",
    "worker_dispatch.health",
    "worker_dispatch.readiness",
)
OCI_HOST_POSTURE_HOSTED_VERIFY_READINESS_SUMMARY_KEYS = frozenset(
    {
        "launchable",
        "blocking_count",
        "blockers",
        "next_actions",
        "secret_boundary",
    }
)
OCI_HOST_POSTURE_HOSTED_VERIFY_READINESS_BLOCKER_KEYS = frozenset(
    {"check", "failures", "next_action"}
)
OCI_HOST_POSTURE_CIS_BASELINE_KEYS = frozenset(
    {"scanner", "status", "critical_findings", "high_findings"}
)
OCI_HOST_POSTURE_ROOTKIT_SCAN_KEYS = frozenset({"scanner", "status"})
OCI_HOST_POSTURE_COLLECTION_KEYS = frozenset(
    {"mode", "mutates_oci", "mutates_host", "secret_boundary"}
)
OCI_HOST_POSTURE_SYSTEMD_UNIT_KEYS = frozenset(
    {
        "user",
        "umask",
        "no_new_privileges",
        "private_tmp",
        "protect_system",
        "protect_home",
        "private_devices",
        "restrict_suid_sgid",
        "lock_personality",
        "system_call_architectures",
        "protect_kernel_tunables",
        "protect_kernel_modules",
        "protect_kernel_logs",
        "protect_control_groups",
        "restrict_namespaces",
        "restrict_realtime",
        "memory_deny_write_execute",
        "capability_bounding_set",
        "ambient_capabilities",
        "restrict_address_families",
        "state_directory",
        "state_directory_mode",
        "logs_directory",
        "logs_directory_mode",
        "runtime_directory",
        "runtime_directory_mode",
        "read_write_paths",
        "environment",
        "exec_start",
        "working_directory",
    }
)


@dataclass(frozen=True)
class CommandResult:
    """Captured read-only host command result."""

    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""


def collect_oci_host_posture_evidence(
    *,
    shape: str = "",
    ssh_ingress: str = "",
    hosted_verify_report: Mapping[str, object] | None = None,
    dns_report: Mapping[str, object] | None = None,
    release_receipt: Mapping[str, object] | None = None,
    runtime_secret_verify_report: Mapping[str, object] | None = None,
    rollback_metadata: Mapping[str, object] | None = None,
    cis_summary: Mapping[str, object] | None = None,
    rootkit_summary: Mapping[str, object] | None = None,
    command_runner: Callable[[Sequence[str]], CommandResult] | None = None,
    file_exists: Callable[[Path], bool] | None = None,
) -> dict[str, object]:
    """Collect a redacted, non-mutating posture evidence bundle from a host."""

    runner = command_runner or _run_command
    exists = file_exists or Path.exists
    running_services = _collect_running_services(runner)
    public_ports = _collect_public_ports(runner)
    return {
        "schema_version": OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION,
        "architecture": platform.machine(),
        "shape": redact_public_text(shape or os.getenv("FUSEKIT_OCI_SHAPE", "")),
        "running_services": running_services,
        "public_ports": public_ports,
        "ssh_ingress": redact_public_text(ssh_ingress or os.getenv("FUSEKIT_SSH_INGRESS", "")),
        "runtime_secret_dir": _collect_runtime_secret_dir(runner),
        "runtime_secret_file": _collect_runtime_secret_file(runner),
        "runtime_secret_verify": _sanitize_summary(runtime_secret_verify_report),
        "patch_posture": _collect_patch_posture(runner, exists),
        "cis_baseline": _sanitize_summary(cis_summary),
        "rootkit_scan": _sanitize_summary(rootkit_summary),
        "systemd_units": _collect_systemd_units(runner),
        "hosted_verify": _sanitize_posture_public_value(hosted_verify_report or {}),
        "dns_propagation": _sanitize_summary(dns_report),
        "release_receipt": _sanitize_release_receipt(release_receipt),
        "rollback_metadata": _sanitize_summary(rollback_metadata),
        "collection": {
            "mode": "read_only_local_host",
            "mutates_oci": False,
            "mutates_host": False,
            "secret_boundary": (
                "Collector records service names, ports, file metadata, systemd hardening, "
                "scanner summaries, and hosted verifier status only. It does not read secret "
                "file contents and does not request OCI credentials."
            ),
        },
    }


def evaluate_oci_host_posture(evidence: Mapping[str, object]) -> dict[str, object]:
    """Evaluate redacted OCI host posture evidence without touching infrastructure."""

    serialized = json.dumps(evidence, sort_keys=True)
    checks = [
        _schema_check(evidence),
        _evidence_shape_check(evidence),
        _architecture_check(evidence),
        _services_check(evidence),
        _public_ports_check(evidence),
        _runtime_secret_dir_check(evidence),
        _runtime_secret_file_check(evidence),
        _runtime_secret_verify_check(evidence),
        _patch_check(evidence),
        _baseline_check(evidence),
        _rootkit_check(evidence),
        _systemd_check(evidence),
        _web_verification_check(evidence),
        _dns_propagation_check(evidence),
        _release_receipt_check(evidence),
        _rollback_metadata_check(evidence),
        _collection_boundary_check(evidence),
    ]
    if contains_durable_secret_text(serialized):
        checks.append(
            _fail(
                "evidence.redaction",
                "evidence_contains_secret_text",
                "Remove raw secrets/tokens/keys from the posture evidence and rerun.",
            )
        )
    else:
        checks.append(_ok("evidence.redaction"))
    blockers = _blocking_check_ids(checks)
    return {
        "schema_version": OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION,
        "ready": not blockers,
        "blocking_checks": blockers,
        "checks": checks,
        "public_summary": {
            "origin": OCI_HOST_POSTURE_ORIGIN,
            "target": "permanent-oci-hosted-launcher",
            "architecture": _public_str(evidence.get("architecture")),
            "shape": _public_str(evidence.get("shape")),
            "secret_boundary": (
                "Posture evidence must contain only file ownership/mode, service, port, "
                "scanner, and hosted-verifier status. It must not contain OCI credentials, "
                "GitHub App private keys, provider credentials, HMAC secrets, vault material, "
                "or raw logs."
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    """Validate an OCI host posture evidence JSON file."""

    parser = argparse.ArgumentParser(
        description="Validate redacted OCI host posture evidence for hosted FuseKit."
    )
    parser.add_argument("--collect", action="store_true", help="Collect read-only host evidence")
    parser.add_argument("--evidence", help="Path to redacted posture JSON")
    parser.add_argument("--output", help="Write collected evidence JSON to this path")
    parser.add_argument("--shape", default="", help="Public OCI shape label, for example E5 Flex")
    parser.add_argument("--ssh-ingress", default="", help="Public SSH ingress posture label")
    parser.add_argument("--hosted-verify-report", default="", help="Path to hosted verifier JSON")
    parser.add_argument("--dns-report", default="", help="Path to redacted DNS propagation JSON")
    parser.add_argument("--release-receipt", default="", help="Path to OCI release receipt JSON")
    parser.add_argument(
        "--runtime-secret-verify-report",
        default="",
        help="Path to redacted fusekit-hosted-runtime-secret-plan --verify-file JSON",
    )
    parser.add_argument(
        "--rollback-metadata",
        default="",
        help="Path to redacted rollback metadata JSON",
    )
    parser.add_argument(
        "--cis-summary",
        default="",
        help="Path to redacted CIS/Lynis/OpenSCAP summary JSON",
    )
    parser.add_argument(
        "--rootkit-summary",
        default="",
        help="Path to redacted rkhunter/chkrootkit summary JSON",
    )
    args = parser.parse_args(argv)
    if args.collect:
        try:
            evidence = collect_oci_host_posture_evidence(
                shape=args.shape,
                ssh_ingress=args.ssh_ingress,
                hosted_verify_report=_read_optional_json(
                    args.hosted_verify_report,
                    required=bool(args.hosted_verify_report),
                ),
                dns_report=_read_optional_json(
                    args.dns_report,
                    required=bool(args.dns_report),
                ),
                release_receipt=_read_optional_json(
                    args.release_receipt,
                    required=bool(args.release_receipt),
                ),
                runtime_secret_verify_report=_read_optional_json(
                    args.runtime_secret_verify_report,
                    required=bool(args.runtime_secret_verify_report),
                ),
                rollback_metadata=_read_optional_json(
                    args.rollback_metadata,
                    required=bool(args.rollback_metadata),
                ),
                cis_summary=_read_optional_json(
                    args.cis_summary or OCI_HOST_POSTURE_DEFAULT_CIS_SUMMARY,
                    required=bool(args.cis_summary),
                ),
                rootkit_summary=_read_optional_json(
                    args.rootkit_summary or OCI_HOST_POSTURE_DEFAULT_ROOTKIT_SUMMARY,
                    required=bool(args.rootkit_summary),
                ),
            )
            if args.output:
                _write_json_output(args.output, _public_json(evidence))
            else:
                _emit_public_json(evidence)
        except (OSError, json.JSONDecodeError, FuseKitError) as exc:
            _emit_public_json(
                {
                    "schema_version": OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION,
                    "ready": False,
                    "error": redact_public_text(str(exc)),
                }
            )
            return 1
        return 0
    if not args.evidence:
        parser.error("--evidence is required unless --collect is used")
    try:
        raw = _read_json_object_file(args.evidence)
        report = evaluate_oci_host_posture(raw)
    except (OSError, json.JSONDecodeError, FuseKitError) as exc:
        report = {
            "schema_version": OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION,
            "ready": False,
            "error": redact_public_text(str(exc)),
        }
    _emit_public_json(report)
    return 0 if report.get("ready") is True else 1


def _run_command(args: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(  # noqa: S603
            list(args),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(tuple(str(item) for item in args), 127, "", str(exc))
    return CommandResult(
        tuple(str(item) for item in args),
        completed.returncode,
        completed.stdout,
        completed.stderr,
    )


def _read_optional_json(path: str, *, required: bool = False) -> dict[str, object]:
    if not path:
        return {}
    try:
        return _read_json_object_file(path, missing_ok=not required)
    except (OSError, json.JSONDecodeError, FuseKitError):
        if required:
            raise
        return {}


def _read_json_object_file(path: str, *, missing_ok: bool = False) -> dict[str, object]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise FuseKitError("posture_json_symlink")
    _reject_symlinked_parents(candidate, "posture_json_parent_symlink")
    if not candidate.exists():
        if missing_ok:
            return {}
        raise FuseKitError("posture_json_missing")
    raw = _read_json_no_follow(candidate)
    if not isinstance(raw, dict):
        raise FuseKitError("posture_json_not_object")
    return raw


def _write_json_output(path: str, payload: str) -> None:
    candidate = Path(path)
    _reject_symlinked_parents(candidate, "posture_output_parent_symlink")
    if candidate.is_symlink():
        raise FuseKitError("posture_output_symlink")
    if candidate.exists() and not candidate.is_file():
        raise FuseKitError("posture_output_not_file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(candidate, flags, OCI_HOST_POSTURE_OUTPUT_MODE)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"{payload}\n")
    finally:
        try:
            os.chmod(candidate, OCI_HOST_POSTURE_OUTPUT_MODE)
        except OSError:
            pass


def _reject_symlinked_parents(candidate: Path, error: str) -> None:
    for parent in candidate.parents:
        if parent == Path("."):
            continue
        if parent.is_symlink():
            raise FuseKitError(error)


def _read_json_no_follow(candidate: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(candidate, flags)
    try:
        file_status = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise FuseKitError("posture_json_not_file")
        if file_status.st_size > OCI_HOST_POSTURE_MAX_JSON_BYTES:
            raise FuseKitError("posture_json_too_large")
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            return json.load(handle)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _emit_public_json(value: Mapping[str, object]) -> None:
    os.write(1, f"{_public_json(value)}\n".encode())


def _public_json(value: Mapping[str, object]) -> str:
    return json.dumps(
        _sanitize_posture_public_value(value),
        indent=2,
        sort_keys=True,
    )


def _collect_running_services(
    runner: Callable[[Sequence[str]], CommandResult],
) -> list[str]:
    result = runner(
        [
            "systemctl",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ]
    )
    if result.returncode != 0:
        return []
    services: list[str] = []
    for line in result.stdout.splitlines():
        first = line.strip().split(maxsplit=1)[0] if line.strip() else ""
        if first.endswith(".service"):
            first = first.removesuffix(".service")
        if first and first not in services:
            services.append(redact_public_text(first))
    return sorted(services)


def _collect_public_ports(
    runner: Callable[[Sequence[str]], CommandResult],
) -> list[int]:
    result = runner(["ss", "-H", "-tuln"])
    if result.returncode != 0:
        return []
    ports: list[int] = []
    for line in result.stdout.splitlines():
        port = _port_from_ss_line(line)
        if port is not None and port not in ports:
            ports.append(port)
    return sorted(ports)


def _port_from_ss_line(line: str) -> int | None:
    fields = line.split()
    if len(fields) < 5:
        return None
    protocol = fields[0].lower()
    local = fields[4]
    host, port = _parse_ss_local_address(local)
    if port is None or not _is_externally_reachable_bind(host):
        return None
    if protocol == "udp" and port in {68, 546}:
        return None
    return port if 0 < port <= 65535 else None


def _parse_ss_local_address(local: str) -> tuple[str, int | None]:
    bracketed = re.match(r"^\[(?P<host>.*)]:(?P<port>\d+)$", local)
    if bracketed:
        return bracketed.group("host"), int(bracketed.group("port"))
    match = re.match(r"^(?P<host>.*):(?P<port>\d+)$", local)
    if not match:
        return "", None
    return match.group("host"), int(match.group("port"))


def _is_externally_reachable_bind(host: str) -> bool:
    normalized = host.strip().strip("[]").lower().split("%", 1)[0]
    if normalized in {"", "*"}:
        return True
    if normalized in {"localhost", "ip6-localhost"}:
        return False
    try:
        address = ip_address(normalized)
    except ValueError:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return not mapped.is_loopback
    if address.is_unspecified:
        return True
    return not address.is_loopback


def _collect_runtime_secret_dir(
    runner: Callable[[Sequence[str]], CommandResult],
) -> dict[str, object]:
    result = runner(["stat", "-c", "%U %G %a %n", OCI_HOST_POSTURE_SECRET_DIR])
    if result.returncode != 0:
        return {
            "path": OCI_HOST_POSTURE_SECRET_DIR,
            "owner": "",
            "group": "",
            "mode": "",
        }
    owner, group, mode = _parse_stat_output(result.stdout)
    return {
        "path": OCI_HOST_POSTURE_SECRET_DIR,
        "owner": owner,
        "group": group,
        "mode": mode.zfill(4) if mode else "",
    }


def _collect_runtime_secret_file(
    runner: Callable[[Sequence[str]], CommandResult],
) -> dict[str, object]:
    result = runner(["stat", "-c", "%U %G %a %n", OCI_HOST_POSTURE_SECRET_FILE])
    if result.returncode != 0:
        return {
            "path": OCI_HOST_POSTURE_SECRET_FILE,
            "owner": "",
            "group": "",
            "mode": "",
        }
    owner, group, mode = _parse_stat_output(result.stdout)
    return {
        "path": OCI_HOST_POSTURE_SECRET_FILE,
        "owner": owner,
        "group": group,
        "mode": mode.zfill(4) if mode else "",
    }


def _parse_stat_output(output: str) -> tuple[str, str, str]:
    fields = output.strip().split(maxsplit=3)
    if len(fields) < 3:
        return "", "", ""
    return (
        redact_public_text(fields[0]),
        redact_public_text(fields[1]),
        redact_public_text(fields[2]),
    )


def _collect_patch_posture(
    runner: Callable[[Sequence[str]], CommandResult],
    file_exists: Callable[[Path], bool],
) -> dict[str, object]:
    result = runner(["apt-get", "-s", "upgrade"])
    pending_security_updates = None
    if result.returncode == 0:
        pending_security_updates = sum(
            1
            for line in result.stdout.splitlines()
            if line.startswith("Inst ") and "security" in line.lower()
        )
    return {
        "pending_security_updates": pending_security_updates,
        "reboot_required": file_exists(Path("/var/run/reboot-required")),
    }


def _collect_systemd_units(
    runner: Callable[[Sequence[str]], CommandResult],
) -> dict[str, object]:
    units: dict[str, object] = {}
    for unit in OCI_HOST_POSTURE_SYSTEMD_UNITS:
        result = runner(
            [
                "systemctl",
                "show",
                f"{unit}.service",
                "--property=User,UMask,NoNewPrivileges,PrivateTmp,ProtectSystem,ProtectHome,"
                "PrivateDevices,RestrictSUIDSGID,LockPersonality,SystemCallArchitectures,"
                "ProtectKernelTunables,ProtectKernelModules,ProtectKernelLogs,"
                "ProtectControlGroups,RestrictNamespaces,RestrictRealtime,"
                "MemoryDenyWriteExecute,CapabilityBoundingSet,AmbientCapabilities,"
                "RestrictAddressFamilies,"
                "StateDirectory,StateDirectoryMode,LogsDirectory,LogsDirectoryMode,"
                "RuntimeDirectory,RuntimeDirectoryMode,"
                "ReadWritePaths,Environment,ExecStart,WorkingDirectory",
                "--no-pager",
            ]
        )
        units[unit] = _parse_systemd_show(result.stdout) if result.returncode == 0 else {}
    return units


def _parse_systemd_show(output: str) -> dict[str, object]:
    raw: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            raw[key] = value
    return {
        "user": redact_public_text(raw.get("User", "")),
        "umask": redact_public_text(raw.get("UMask", "")),
        "no_new_privileges": _systemd_bool(raw.get("NoNewPrivileges", "")),
        "private_tmp": _systemd_bool(raw.get("PrivateTmp", "")),
        "protect_system": redact_public_text(raw.get("ProtectSystem", "")),
        "protect_home": _systemd_bool(raw.get("ProtectHome", "")),
        "private_devices": _systemd_bool(raw.get("PrivateDevices", "")),
        "restrict_suid_sgid": _systemd_bool(raw.get("RestrictSUIDSGID", "")),
        "lock_personality": _systemd_bool(raw.get("LockPersonality", "")),
        "system_call_architectures": redact_public_text(
            raw.get("SystemCallArchitectures", "")
        ),
        "protect_kernel_tunables": _systemd_bool(raw.get("ProtectKernelTunables", "")),
        "protect_kernel_modules": _systemd_bool(raw.get("ProtectKernelModules", "")),
        "protect_kernel_logs": _systemd_bool(raw.get("ProtectKernelLogs", "")),
        "protect_control_groups": _systemd_bool(raw.get("ProtectControlGroups", "")),
        "restrict_namespaces": _systemd_bool(raw.get("RestrictNamespaces", "")),
        "restrict_realtime": _systemd_bool(raw.get("RestrictRealtime", "")),
        "memory_deny_write_execute": _systemd_bool(
            raw.get("MemoryDenyWriteExecute", "")
        ),
        "capability_bounding_set": redact_public_text(
            raw.get("CapabilityBoundingSet", "")
        ),
        "ambient_capabilities": redact_public_text(raw.get("AmbientCapabilities", "")),
        "restrict_address_families": [
            redact_public_text(family)
            for family in raw.get("RestrictAddressFamilies", "").split()
            if family.strip()
        ],
        "state_directory": _systemd_list(raw.get("StateDirectory", "")),
        "state_directory_mode": redact_public_text(raw.get("StateDirectoryMode", "")),
        "logs_directory": _systemd_list(raw.get("LogsDirectory", "")),
        "logs_directory_mode": redact_public_text(raw.get("LogsDirectoryMode", "")),
        "runtime_directory": _systemd_list(raw.get("RuntimeDirectory", "")),
        "runtime_directory_mode": redact_public_text(raw.get("RuntimeDirectoryMode", "")),
        "read_write_paths": [
            redact_public_text(path)
            for path in raw.get("ReadWritePaths", "").split()
            if path.strip()
        ],
        "environment": _systemd_list(raw.get("Environment", "")),
        "exec_start": redact_public_text(raw.get("ExecStart", "")),
        "working_directory": redact_public_text(raw.get("WorkingDirectory", "")),
    }


def _systemd_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"yes", "true", "1"}:
        return True
    if normalized in {"no", "false", "0"}:
        return False
    return None


def _systemd_list(value: str) -> list[str]:
    return [redact_public_text(item) for item in value.split() if item.strip()]


def _sanitize_summary(summary: Mapping[str, object] | None) -> dict[str, object]:
    sanitized = _sanitize_public_value(summary or {})
    return sanitized if isinstance(sanitized, dict) else {}


def _schema_check(evidence: Mapping[str, object]) -> dict[str, object]:
    if evidence.get("schema_version") != OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION:
        return _fail(
            "evidence.schema",
            "oci_host_posture_schema_invalid",
            "Collect posture evidence with schema fusekit.oci-host-posture-evidence.v1.",
        )
    return _ok("evidence.schema")


def _evidence_shape_check(evidence: Mapping[str, object]) -> dict[str, object]:
    unexpected = _unexpected_keys(evidence, OCI_HOST_POSTURE_ALLOWED_EVIDENCE_KEYS)
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "runtime_secret_dir",
            OCI_HOST_POSTURE_SECRET_METADATA_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "runtime_secret_file",
            OCI_HOST_POSTURE_SECRET_METADATA_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "runtime_secret_verify",
            OCI_HOST_POSTURE_RUNTIME_SECRET_VERIFY_KEYS,
        )
    )
    unexpected.extend(_unexpected_runtime_secret_verify_keys(evidence))
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "patch_posture",
            OCI_HOST_POSTURE_PATCH_POSTURE_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "hosted_verify",
            OCI_HOST_POSTURE_HOSTED_VERIFY_KEYS,
        )
    )
    unexpected.extend(_unexpected_hosted_verify_keys(evidence))
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "dns_propagation",
            OCI_HOST_POSTURE_DNS_PROPAGATION_KEYS,
        )
    )
    unexpected.extend(_unexpected_rollback_metadata_keys(evidence))
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "cis_baseline",
            OCI_HOST_POSTURE_CIS_BASELINE_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "rootkit_scan",
            OCI_HOST_POSTURE_ROOTKIT_SCAN_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "collection",
            OCI_HOST_POSTURE_COLLECTION_KEYS,
        )
    )
    unexpected.extend(
        _unexpected_nested_keys(
            evidence,
            "release_receipt",
            OCI_HOST_POSTURE_RELEASE_RECEIPT_KEYS,
        )
    )
    release_receipt = evidence.get("release_receipt")
    if isinstance(release_receipt, Mapping):
        unexpected.extend(
            _unexpected_nested_keys(
                release_receipt,
                "rollback",
                OCI_HOST_POSTURE_RELEASE_ROLLBACK_KEYS,
                prefix="release_receipt.rollback",
            )
        )
    unexpected.extend(_unexpected_systemd_unit_keys(evidence))
    unexpected = sorted(unexpected)
    if unexpected:
        return _fail(
            "evidence.shape",
            "oci_host_posture_evidence_has_unknown_fields",
            "Collect posture evidence with the bundled read-only collector and attach "
            "only the documented redacted proof fields.",
            unexpected_fields=unexpected,
        )
    return _ok("evidence.shape")


def _unexpected_keys(value: Mapping[str, object], allowed: frozenset[str]) -> list[str]:
    return sorted(redact_public_text(str(key)) for key in value if str(key) not in allowed)


def _unexpected_nested_keys(
    evidence: Mapping[str, object],
    section: str,
    allowed: frozenset[str],
    *,
    prefix: str = "",
) -> list[str]:
    value = evidence.get(section)
    if not isinstance(value, Mapping):
        return []
    label = prefix or section
    return [f"{label}.{key}" for key in _unexpected_keys(value, allowed)]


def _unexpected_runtime_secret_verify_keys(evidence: Mapping[str, object]) -> list[str]:
    report = evidence.get("runtime_secret_verify")
    if not isinstance(report, Mapping):
        return []
    unexpected: list[str] = []
    secret_file = report.get("secret_file")
    if isinstance(secret_file, Mapping):
        unexpected.extend(
            f"runtime_secret_verify.secret_file.{key}"
            for key in _unexpected_keys(
                secret_file,
                OCI_HOST_POSTURE_RUNTIME_SECRET_VERIFY_FILE_KEYS,
            )
        )
    key_inventory = report.get("key_inventory")
    if isinstance(key_inventory, Mapping):
        unexpected.extend(
            f"runtime_secret_verify.key_inventory.{key}"
            for key in _unexpected_keys(
                key_inventory,
                OCI_HOST_POSTURE_RUNTIME_SECRET_KEY_INVENTORY_KEYS,
            )
        )
    required_runtime_env = report.get("required_runtime_env")
    if isinstance(required_runtime_env, Mapping):
        unexpected.extend(
            f"runtime_secret_verify.required_runtime_env.{key}"
            for key in _unexpected_keys(
                required_runtime_env,
                frozenset(HOSTED_RUNTIME_REQUIRED_FILE_ENV),
            )
        )
        for key in HOSTED_RUNTIME_REQUIRED_FILE_ENV:
            row = required_runtime_env.get(key)
            if isinstance(row, Mapping):
                unexpected.extend(
                    f"runtime_secret_verify.required_runtime_env.{key}.{row_key}"
                    for row_key in _unexpected_keys(
                        row,
                        OCI_HOST_POSTURE_RUNTIME_SECRET_ENV_ROW_KEYS,
                    )
                )
    stripe_runtime_env = report.get("stripe_runtime_env")
    if isinstance(stripe_runtime_env, Mapping):
        unexpected.extend(
            f"runtime_secret_verify.stripe_runtime_env.{key}"
            for key in _unexpected_keys(
                stripe_runtime_env,
                OCI_HOST_POSTURE_STRIPE_RUNTIME_ENV_KEYS,
            )
        )
        for key, allowed in OCI_HOST_POSTURE_STRIPE_RUNTIME_ENV_ROW_KEYS.items():
            row = stripe_runtime_env.get(key)
            if isinstance(row, Mapping):
                unexpected.extend(
                    f"runtime_secret_verify.stripe_runtime_env.{key}.{row_key}"
                    for row_key in _unexpected_keys(row, allowed)
                )
    return unexpected


def _unexpected_rollback_metadata_keys(evidence: Mapping[str, object]) -> list[str]:
    metadata = evidence.get("rollback_metadata")
    if not isinstance(metadata, Mapping):
        return []
    unexpected = [
        f"rollback_metadata.{key}"
        for key in _unexpected_keys(metadata, OCI_HOST_POSTURE_ROLLBACK_METADATA_KEYS)
    ]
    for section in ("rollback", "actions"):
        rows = metadata.get(section)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                continue
            unexpected.extend(
                f"rollback_metadata.{section}[{index}].{key}"
                for key in _unexpected_keys(row, OCI_HOST_POSTURE_ROLLBACK_ACTION_KEYS)
            )
    return unexpected


def _unexpected_hosted_verify_keys(evidence: Mapping[str, object]) -> list[str]:
    report = evidence.get("hosted_verify")
    if not isinstance(report, Mapping):
        return []
    unexpected: list[str] = []
    checks = report.get("checks")
    if isinstance(checks, Sequence) and not isinstance(checks, (str, bytes)):
        for index, row in enumerate(checks):
            if not isinstance(row, Mapping):
                continue
            unexpected.extend(
                f"hosted_verify.checks[{index}].{key}"
                for key in _unexpected_keys(
                    row,
                    OCI_HOST_POSTURE_HOSTED_VERIFY_CHECK_KEYS,
                )
            )
    summary = report.get("readiness_summary")
    if isinstance(summary, Mapping):
        unexpected.extend(
            f"hosted_verify.readiness_summary.{key}"
            for key in _unexpected_keys(
                summary,
                OCI_HOST_POSTURE_HOSTED_VERIFY_READINESS_SUMMARY_KEYS,
            )
        )
        blockers = summary.get("blockers")
        if isinstance(blockers, Sequence) and not isinstance(blockers, (str, bytes)):
            for index, row in enumerate(blockers):
                if not isinstance(row, Mapping):
                    continue
                unexpected.extend(
                    f"hosted_verify.readiness_summary.blockers[{index}].{key}"
                    for key in _unexpected_keys(
                        row,
                        OCI_HOST_POSTURE_HOSTED_VERIFY_READINESS_BLOCKER_KEYS,
                    )
                )
    provenance = report.get("source_provenance")
    if not isinstance(provenance, Mapping):
        return unexpected
    unexpected.extend(
        f"hosted_verify.source_provenance.{key}"
        for key in _unexpected_keys(
            provenance,
            OCI_HOST_POSTURE_HOSTED_VERIFY_SOURCE_PROVENANCE_KEYS,
        )
    )
    for section in OCI_HOST_POSTURE_HOSTED_VERIFY_SOURCE_PROVENANCE_KEYS:
        row = provenance.get(section)
        if isinstance(row, Mapping):
            unexpected.extend(
                f"hosted_verify.source_provenance.{section}.{key}"
                for key in _unexpected_keys(
                    row,
                    OCI_HOST_POSTURE_HOSTED_VERIFY_SOURCE_PROVENANCE_ROW_KEYS,
                )
            )
    return unexpected


def _unexpected_systemd_unit_keys(evidence: Mapping[str, object]) -> list[str]:
    units = evidence.get("systemd_units")
    if not isinstance(units, Mapping):
        return []
    unexpected = [
        f"systemd_units.{unit}"
        for unit in _unexpected_keys(units, frozenset(OCI_HOST_POSTURE_SYSTEMD_UNITS))
    ]
    for unit in OCI_HOST_POSTURE_SYSTEMD_UNITS:
        config = units.get(unit)
        if isinstance(config, Mapping):
            unexpected.extend(
                f"systemd_units.{unit}.{key}"
                for key in _unexpected_keys(config, OCI_HOST_POSTURE_SYSTEMD_UNIT_KEYS)
            )
    return unexpected


def _architecture_check(evidence: Mapping[str, object]) -> dict[str, object]:
    architecture = _public_str(evidence.get("architecture")).lower()
    shape = _public_str(evidence.get("shape")).lower()
    failures: list[str] = []
    if architecture not in {"x86_64", "amd64"}:
        failures.append("oci_host_architecture_must_be_amd_x86_64")
    if shape and any(marker in shape for marker in ("a1", "arm", "ampere")):
        failures.append("oci_host_shape_must_not_be_arm")
    if failures:
        return _fail(
            "host.architecture",
            failures,
            "Move the hosted launcher to an AMD/x86_64 OCI shape before public launch.",
        )
    return _ok(
        "host.architecture",
        architecture=architecture,
        shape=_public_str(evidence.get("shape")),
    )


def _services_check(evidence: Mapping[str, object]) -> dict[str, object]:
    services = set(_string_list(evidence.get("running_services")))
    missing = [service for service in OCI_HOST_POSTURE_REQUIRED_SERVICES if service not in services]
    ssh_present = "ssh" in services or "sshd" in services
    failures = []
    if missing:
        failures.append("oci_host_required_services_missing")
    if not ssh_present:
        failures.append("oci_host_ssh_service_missing")
    if failures:
        return _fail(
            "host.services",
            failures,
            "Start only the required hosted launcher, worker dispatch, nginx, and SSH services.",
            missing=missing,
        )
    return _ok("host.services")


def _public_ports_check(evidence: Mapping[str, object]) -> dict[str, object]:
    ports = _port_list(evidence.get("public_ports"))
    ssh_ingress = _public_str(evidence.get("ssh_ingress")).lower()
    restricted_ssh = ssh_ingress in {"restricted", "operator-only", "vpn-only"}
    allowed_ports = set(OCI_HOST_POSTURE_ALLOWED_PUBLIC_PORTS)
    if restricted_ssh:
        allowed_ports.add(22)
    unexpected = [port for port in ports if port not in allowed_ports]
    failures = []
    if unexpected:
        failures.append("oci_host_public_ports_must_be_80_443_only")
    if ssh_ingress not in {"restricted", "operator-only", "vpn-only", "disabled"}:
        failures.append("oci_host_ssh_ingress_must_be_restricted")
    if failures:
        return _fail(
            "host.public_ports",
            failures,
            "Limit public ingress to 80/443 and keep SSH restricted to operator access.",
            unexpected_ports=unexpected,
        )
    return _ok("host.public_ports", public_ports=ports, ssh_ingress=ssh_ingress)


def _runtime_secret_dir_check(evidence: Mapping[str, object]) -> dict[str, object]:
    dir_info = _mapping(evidence.get("runtime_secret_dir"))
    failures = []
    if dir_info.get("path") != OCI_HOST_POSTURE_SECRET_DIR:
        failures.append("oci_host_secret_dir_path_invalid")
    if dir_info.get("owner") != "root" or dir_info.get("group") != "root":
        failures.append("oci_host_secret_dir_must_be_root_owned")
    if str(dir_info.get("mode") or "") not in {"0750", "750", "0700", "700"}:
        failures.append("oci_host_secret_dir_mode_must_be_0750_or_stricter")
    if failures:
        return _fail(
            "host.runtime_secret_dir",
            failures,
            "Keep /etc/fusekit root-owned with mode 0750 or stricter before loading "
            "hosted runtime secrets.",
        )
    return _ok("host.runtime_secret_dir")


def _runtime_secret_file_check(evidence: Mapping[str, object]) -> dict[str, object]:
    file_info = _mapping(evidence.get("runtime_secret_file"))
    failures = []
    if file_info.get("path") != OCI_HOST_POSTURE_SECRET_FILE:
        failures.append("oci_host_secret_file_path_invalid")
    if file_info.get("owner") != "root" or file_info.get("group") != "root":
        failures.append("oci_host_secret_file_must_be_root_owned")
    if str(file_info.get("mode") or "") not in {"0600", "600"}:
        failures.append("oci_host_secret_file_mode_must_be_0600")
    if failures:
        return _fail(
            "host.runtime_secret_file",
            failures,
            "Move runtime secrets to /etc/fusekit/hosted-secrets.env owned by root:root mode 0600.",
        )
    return _ok("host.runtime_secret_file")


def _runtime_secret_verify_check(evidence: Mapping[str, object]) -> dict[str, object]:
    report = _mapping(evidence.get("runtime_secret_verify"))
    key_inventory = _mapping(report.get("key_inventory"))
    secret_file = _mapping(report.get("secret_file"))
    required_runtime_env = _mapping(report.get("required_runtime_env"))
    stripe_runtime_env = _mapping(report.get("stripe_runtime_env"))
    missing_keys = _string_list(key_inventory.get("missing"))
    unexpected_keys = _string_list(key_inventory.get("unexpected_keys"))
    required_count = _literal_non_negative_int(key_inventory.get("required_count"))
    present_required_count = _literal_non_negative_int(
        key_inventory.get("present_required_count")
    )
    failures: list[str] = []
    if report.get("schema_version") != HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION:
        failures.append("oci_host_runtime_secret_verify_schema_invalid")
    if report.get("ready") is not True:
        failures.append("oci_host_runtime_secret_verify_not_ready")
    if report.get("ready_for_managed_payment_staging") is not True:
        failures.append("oci_host_runtime_secret_payment_staging_not_ready")
    if _string_list(report.get("blockers")):
        failures.append("oci_host_runtime_secret_verify_has_blockers")
    if missing_keys:
        failures.append("oci_host_runtime_secret_required_keys_missing")
    if unexpected_keys:
        failures.append("oci_host_runtime_secret_unexpected_keys")
    if (
        required_count is None
        or present_required_count is None
        or required_count != len(HOSTED_RUNTIME_REQUIRED_FILE_ENV)
        or present_required_count != required_count - len(missing_keys)
    ):
        failures.append("oci_host_runtime_secret_key_inventory_count_mismatch")
    if not _required_runtime_env_present(required_runtime_env):
        failures.append("oci_host_runtime_secret_required_env_presence_mismatch")
    if not _stripe_runtime_env_ready(stripe_runtime_env):
        failures.append("oci_host_runtime_secret_stripe_env_mismatch")
    if not _runtime_secret_verify_file_ready(secret_file):
        failures.append("oci_host_runtime_secret_verify_file_metadata_mismatch")
    boundary = _public_str(report.get("secret_boundary")).lower()
    if "emits no" not in boundary or "secret" not in boundary:
        failures.append("oci_host_runtime_secret_verify_secret_boundary_missing")
    if failures:
        return _fail(
            "host.runtime_secret_verify",
            failures,
            "Attach a ready redacted runtime secret verifier report with no missing or "
            "unexpected keys before DNS cutover.",
            runtime_secret_blockers=_public_string_list(report.get("blockers")),
            missing_keys=_public_string_list(missing_keys),
            unexpected_keys=_public_string_list(unexpected_keys),
        )
    return _ok("host.runtime_secret_verify")


def _patch_check(evidence: Mapping[str, object]) -> dict[str, object]:
    patch = _mapping(evidence.get("patch_posture"))
    security_updates = _non_negative_int(patch.get("pending_security_updates"))
    reboot_required = patch.get("reboot_required")
    failures = []
    if security_updates is None or security_updates > 0:
        failures.append("oci_host_security_updates_pending")
    if reboot_required is not False:
        failures.append("oci_host_reboot_state_not_clean")
    if failures:
        return _fail(
            "host.patch_posture",
            failures,
            "Apply security updates and reboot if required before publishing posture proof.",
        )
    return _ok("host.patch_posture")


def _baseline_check(evidence: Mapping[str, object]) -> dict[str, object]:
    baseline = _mapping(evidence.get("cis_baseline"))
    scanner = _public_str(baseline.get("scanner")).lower()
    status = _public_str(baseline.get("status")).lower()
    critical = _non_negative_int(baseline.get("critical_findings"))
    high = _non_negative_int(baseline.get("high_findings"))
    if scanner not in {"lynis", "openscap", "cis-cat", "oscap"} or status != "pass":
        return _fail(
            "host.cis_baseline",
            "oci_host_cis_baseline_missing_or_failed",
            "Run a CIS-style review such as Lynis or OpenSCAP and attach a redacted "
            "passing summary.",
        )
    if critical != 0 or high != 0:
        return _fail(
            "host.cis_baseline",
            "oci_host_cis_baseline_high_findings",
            "Resolve high/critical CIS baseline findings or document an explicit exception.",
        )
    return _ok("host.cis_baseline", scanner=scanner)


def _rootkit_check(evidence: Mapping[str, object]) -> dict[str, object]:
    scan = _mapping(evidence.get("rootkit_scan"))
    scanner = _public_str(scan.get("scanner")).lower()
    status = _public_str(scan.get("status")).lower()
    if scanner not in {"rkhunter", "chkrootkit"} or status != "pass":
        return _fail(
            "host.rootkit_scan",
            "oci_host_rootkit_scan_missing_or_failed",
            "Run rkhunter or chkrootkit and attach a redacted passing summary.",
        )
    return _ok("host.rootkit_scan", scanner=scanner)


def _systemd_check(evidence: Mapping[str, object]) -> dict[str, object]:
    units = _mapping(evidence.get("systemd_units"))
    failures: list[str] = []
    for unit in OCI_HOST_POSTURE_SYSTEMD_UNITS:
        unit_config = _mapping(units.get(unit))
        if unit_config.get("user") != "fusekit":
            failures.append(f"{unit}:user_must_be_fusekit")
        if str(unit_config.get("umask") or "") not in {"0077", "77"}:
            failures.append(f"{unit}:umask_must_be_0077")
        if unit_config.get("no_new_privileges") is not True:
            failures.append(f"{unit}:no_new_privileges_required")
        if unit_config.get("private_tmp") is not True:
            failures.append(f"{unit}:private_tmp_required")
        if str(unit_config.get("protect_system") or "").lower() not in {"full", "strict"}:
            failures.append(f"{unit}:protect_system_required")
        if unit_config.get("protect_home") is not True:
            failures.append(f"{unit}:protect_home_required")
        if unit_config.get("private_devices") is not True:
            failures.append(f"{unit}:private_devices_required")
        if unit_config.get("restrict_suid_sgid") is not True:
            failures.append(f"{unit}:restrict_suid_sgid_required")
        if unit_config.get("lock_personality") is not True:
            failures.append(f"{unit}:lock_personality_required")
        if str(unit_config.get("system_call_architectures") or "").lower() != "native":
            failures.append(f"{unit}:native_syscall_architecture_required")
        if unit_config.get("protect_kernel_tunables") is not True:
            failures.append(f"{unit}:protect_kernel_tunables_required")
        if unit_config.get("protect_kernel_modules") is not True:
            failures.append(f"{unit}:protect_kernel_modules_required")
        if unit_config.get("protect_kernel_logs") is not True:
            failures.append(f"{unit}:protect_kernel_logs_required")
        if unit_config.get("protect_control_groups") is not True:
            failures.append(f"{unit}:protect_control_groups_required")
        if unit_config.get("restrict_namespaces") is not True:
            failures.append(f"{unit}:restrict_namespaces_required")
        if unit_config.get("restrict_realtime") is not True:
            failures.append(f"{unit}:restrict_realtime_required")
        if unit_config.get("memory_deny_write_execute") is not True:
            failures.append(f"{unit}:memory_deny_write_execute_required")
        if str(unit_config.get("capability_bounding_set") or "").strip():
            failures.append(f"{unit}:capability_bounding_set_must_be_empty")
        if str(unit_config.get("ambient_capabilities") or "").strip():
            failures.append(f"{unit}:ambient_capabilities_must_be_empty")
        address_families = set(_string_list(unit_config.get("restrict_address_families")))
        if address_families != {"AF_UNIX", "AF_INET", "AF_INET6"}:
            failures.append(f"{unit}:restricted_address_families_required")
        if "fusekit" not in set(_string_list(unit_config.get("state_directory"))):
            failures.append(f"{unit}:state_directory_required")
        if str(unit_config.get("state_directory_mode") or "") not in {"0750", "750"}:
            failures.append(f"{unit}:state_directory_mode_must_be_0750")
        if "fusekit" not in set(_string_list(unit_config.get("logs_directory"))):
            failures.append(f"{unit}:logs_directory_required")
        if str(unit_config.get("logs_directory_mode") or "") not in {"0750", "750"}:
            failures.append(f"{unit}:logs_directory_mode_must_be_0750")
        if "fusekit" not in set(_string_list(unit_config.get("runtime_directory"))):
            failures.append(f"{unit}:runtime_directory_required")
        if str(unit_config.get("runtime_directory_mode") or "") not in {"0750", "750"}:
            failures.append(f"{unit}:runtime_directory_mode_must_be_0750")
        writable = _string_list(unit_config.get("read_write_paths"))
        if not writable:
            failures.append(f"{unit}:constrained_writable_paths_required")
        if any(path in {"/", "/etc", "/usr", "/var"} for path in writable):
            failures.append(f"{unit}:writable_paths_too_broad")
        unexpected_writable = [
            path for path in writable if not _is_allowed_systemd_writable_path(path)
        ]
        if unexpected_writable:
            failures.append(f"{unit}:writable_paths_must_stay_under_fusekit_state")
        environment = set(_string_list(unit_config.get("environment")))
        exec_start = _public_str(unit_config.get("exec_start"))
        working_directory = _public_str(unit_config.get("working_directory"))
        if working_directory != "/opt/fusekit/current":
            failures.append(f"{unit}:working_directory_must_use_current_symlink")
        if "/opt/fusekit/current/.venv/bin/" not in exec_start:
            failures.append(f"{unit}:exec_start_must_use_current_release_venv")
        if unit == "fusekit-hosted":
            if "FUSEKIT_HOSTED_BIND=127.0.0.1" not in environment:
                failures.append(f"{unit}:hosted_bind_must_be_loopback")
            if "FUSEKIT_HOSTED_PORT=8080" not in environment:
                failures.append(f"{unit}:hosted_port_must_be_internal_8080")
        if unit == "fusekit-worker-dispatch":
            if "--host 127.0.0.1" not in exec_start:
                failures.append(f"{unit}:dispatch_host_must_be_loopback")
            if "--port 8766" not in exec_start:
                failures.append(f"{unit}:dispatch_port_must_be_internal_8766")
        if (
            OCI_HOST_POSTURE_WILDCARD_IPV4_BIND in exec_start
            or OCI_HOST_POSTURE_WILDCARD_IPV6_BIND in exec_start
        ):
            failures.append(f"{unit}:exec_start_must_not_bind_wildcard")
    if failures:
        return _fail(
            "host.systemd_units",
            failures,
            "Harden hosted systemd units with fusekit user, NoNewPrivileges, PrivateTmp, "
            "ProtectSystem, and constrained writable paths.",
        )
    return _ok("host.systemd_units")


def _web_verification_check(evidence: Mapping[str, object]) -> dict[str, object]:
    report = _mapping(evidence.get("hosted_verify"))
    failures: list[str] = []
    if report.get("schema_version") != HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION:
        failures.append("oci_hosted_verify_schema_invalid")
    if report.get("public_origin") != OCI_HOST_POSTURE_ORIGIN:
        failures.append("oci_hosted_verify_origin_mismatch")
    if report.get("ready") is not True:
        failures.append("oci_hosted_verify_not_ready")
    if _string_list(report.get("blocking_checks")):
        failures.append("oci_hosted_verify_blocking_checks_not_empty")
    if not _hosted_verify_checks_ready(report):
        failures.append("oci_hosted_verify_checks_not_ready")
    check_ids = _hosted_verify_check_ids(report)
    missing_checks = [
        check_id
        for check_id in OCI_HOST_POSTURE_REQUIRED_HOSTED_VERIFY_CHECK_IDS
        if check_id not in check_ids
    ]
    duplicate_check_ids = _duplicate_hosted_verify_check_ids(report)
    if missing_checks:
        failures.append("oci_hosted_verify_required_checks_missing")
    if duplicate_check_ids:
        failures.append("oci_hosted_verify_duplicate_check_ids")
    summary = _mapping(report.get("readiness_summary"))
    blocking_count = _literal_non_negative_int(summary.get("blocking_count"))
    summary_blockers = _mapping_list(summary.get("blockers"))
    if (
        summary.get("launchable") is not True
        or blocking_count != 0
        or summary_blockers
        or _string_list(summary.get("next_actions"))
    ):
        failures.append("oci_hosted_verify_readiness_summary_mismatch")
    boundary = _public_str(report.get("secret_boundary")).lower()
    if (
        "public html/json endpoints only" not in boundary
        or "never" not in boundary
        or "provider credentials" not in boundary
    ):
        failures.append("oci_hosted_verify_secret_boundary_mismatch")
    if failures:
        hosted_blockers = _public_string_list(report.get("blocking_checks"))
        return _fail(
            "host.web_verification",
            failures,
            "Run fusekit-hosted-verify --origin https://fusekit.snowmanai.org "
            '--expected-commit-sha "$(git rev-parse HEAD)" and attach the redacted '
            "ready report.",
            hosted_verifier_blocking_checks=hosted_blockers,
            missing_hosted_verifier_checks=missing_checks,
            duplicate_hosted_verifier_check_ids=duplicate_check_ids,
        )
    return _ok("host.web_verification")


def _dns_propagation_check(evidence: Mapping[str, object]) -> dict[str, object]:
    report = _mapping(evidence.get("dns_propagation"))
    origin = _public_str(report.get("public_origin") or report.get("origin")).rstrip("/")
    domain = _public_str(report.get("domain") or report.get("hostname")).lower()
    status = _public_str(report.get("status")).lower()
    propagated = report.get("propagated") is True or report.get("ready") is True
    target_matches = origin == OCI_HOST_POSTURE_ORIGIN and domain == "fusekit.snowmanai.org"
    if not target_matches or not propagated or status not in {"ok", "pass", "propagated"}:
        return _fail(
            "host.dns_propagation",
            "oci_host_dns_propagation_proof_missing_or_failed",
            "Attach redacted DNS propagation proof for fusekit.snowmanai.org before "
            "publishing OCI host posture.",
        )
    return _ok("host.dns_propagation", domain=domain or "fusekit.snowmanai.org")


def _release_receipt_check(evidence: Mapping[str, object]) -> dict[str, object]:
    receipt = _mapping(evidence.get("release_receipt"))
    hosted_commit = _hosted_verify_commit_sha(_mapping(evidence.get("hosted_verify")))
    failures: list[str] = []
    if not receipt:
        failures.append("oci_host_release_receipt_missing")
    if receipt.get("schema_version") != OCI_HOST_POSTURE_RELEASE_RECEIPT_SCHEMA_VERSION:
        failures.append("oci_host_release_receipt_schema_invalid")
    if _public_str(receipt.get("target")) != "fusekit.snowmanai.org":
        failures.append("oci_host_release_receipt_target_mismatch")
    mutated_paths = _string_list(receipt.get("mutated_paths"))
    if mutated_paths != list(OCI_HOST_POSTURE_RELEASE_MUTATED_PATHS):
        failures.append("oci_host_release_receipt_mutated_paths_mismatch")
    restarted_services = _string_list(receipt.get("restarted_services"))
    if restarted_services != list(OCI_HOST_POSTURE_RELEASE_RESTARTED_SERVICES):
        failures.append("oci_host_release_receipt_restarted_services_mismatch")
    before_commit = _valid_git_sha(_raw_str(receipt.get("before_commit_sha")), allow_empty=True)
    after_commit = _valid_git_sha(_raw_str(receipt.get("after_commit_sha")))
    if before_commit is None:
        failures.append("oci_host_release_receipt_before_commit_invalid")
    if not after_commit:
        failures.append("oci_host_release_receipt_after_commit_invalid")
    if after_commit and hosted_commit and after_commit != hosted_commit:
        failures.append("oci_host_release_receipt_commit_does_not_match_hosted_verify")
    expected_release_dir = f"/opt/fusekit/releases/{after_commit}" if after_commit else ""
    if _raw_str(receipt.get("release_dir")) != expected_release_dir:
        failures.append("oci_host_release_receipt_release_dir_mismatch")
    rollback = _mapping(receipt.get("rollback"))
    if rollback.get("mode") != "current_symlink_restore":
        failures.append("oci_host_release_receipt_rollback_mode_mismatch")
    previous_commit = _valid_git_sha(
        _raw_str(rollback.get("previous_commit_sha")),
        allow_empty=True,
    )
    if previous_commit is None:
        failures.append("oci_host_release_receipt_previous_commit_invalid")
    proof_command = _raw_str(receipt.get("post_deploy_proof_command"))
    if after_commit and proof_command != (
        "fusekit-hosted-verify --origin https://fusekit.snowmanai.org "
        f"--expected-commit-sha {after_commit}"
    ):
        failures.append("oci_host_release_receipt_post_deploy_command_mismatch")
    boundary = _public_str(receipt.get("secret_boundary")).lower()
    if "hosted-secrets.env" not in boundary or "not read or emitted" not in boundary:
        failures.append("oci_host_release_receipt_secret_boundary_mismatch")
    if failures:
        return _fail(
            "host.release_receipt",
            failures,
            "Attach the redacted OCI hosted release receipt emitted by the bundled "
            "exact-commit release script after redeploy, and rerun hosted verification.",
        )
    return _ok("host.release_receipt", after_commit_sha=after_commit)


def _rollback_metadata_check(evidence: Mapping[str, object]) -> dict[str, object]:
    metadata = _mapping(evidence.get("rollback_metadata"))
    actions = metadata.get("rollback", metadata.get("actions", []))
    if not isinstance(actions, Sequence) or isinstance(actions, (str, bytes)):
        actions = []
    provider_actions = [
        action
        for action in actions
        if isinstance(action, Mapping)
        and _public_str(action.get("action")).startswith(
            ("rollback.", "cloudflare.", "github.", "vercel.", "resend.")
        )
        and _public_str(action.get("status")).lower() in {"planned", "done"}
        and _public_str(action.get("target")).lower() == "fusekit.snowmanai.org"
    ]
    if not provider_actions:
        return _fail(
            "host.rollback_metadata",
            "oci_host_rollback_metadata_provider_actions_missing",
            "Attach redacted rollback metadata with planned or completed provider rollback "
            "actions before publishing OCI host posture.",
        )
    return _ok("host.rollback_metadata", provider_action_count=len(provider_actions))


def _collection_boundary_check(evidence: Mapping[str, object]) -> dict[str, object]:
    collection = _mapping(evidence.get("collection"))
    boundary = _public_str(collection.get("secret_boundary")).lower()
    failures: list[str] = []
    if collection.get("mode") != "read_only_local_host":
        failures.append("oci_host_posture_collection_must_be_read_only")
    if collection.get("mutates_oci") is not False:
        failures.append("oci_host_posture_collection_must_not_mutate_oci")
    if collection.get("mutates_host") is not False:
        failures.append("oci_host_posture_collection_must_not_mutate_host")
    if "does not read secret file contents" not in boundary:
        failures.append("oci_host_posture_collection_must_not_read_secret_contents")
    if "does not request oci credentials" not in boundary:
        failures.append("oci_host_posture_collection_must_not_request_oci_credentials")
    if failures:
        return _fail(
            "evidence.collection_boundary",
            failures,
            "Collect posture with the read-only local-host collector and publish only "
            "redacted facts; do not use OCI credentials or read secret file contents.",
        )
    return _ok("evidence.collection_boundary")


def _blocking_check_ids(checks: Sequence[Mapping[str, object]]) -> list[str]:
    return [
        str(check["id"])
        for check in checks
        if check.get("status") != "ok" and isinstance(check.get("id"), str)
    ]


def _is_allowed_systemd_writable_path(path: str) -> bool:
    normalized = path.rstrip("/")
    return any(
        normalized == allowed or normalized.startswith(f"{allowed}/")
        for allowed in OCI_HOST_POSTURE_ALLOWED_WRITABLE_PATHS
    )


def _hosted_verify_commit_sha(report: Mapping[str, object]) -> str:
    for check in _mapping_list(report.get("checks")):
        if check.get("id") == "hosted.expected_commit":
            commit = _valid_git_sha(_raw_str(check.get("actual_commit_sha")))
            if commit:
                return commit
    provenance = _mapping(report.get("source_provenance"))
    actual = _mapping(provenance.get("actual"))
    commit = _valid_git_sha(_raw_str(actual.get("commit_sha")))
    if commit:
        return commit
    commit = _valid_git_sha(_raw_str(report.get("commit_sha")))
    return commit or ""


def _hosted_verify_checks_ready(report: Mapping[str, object]) -> bool:
    checks = _mapping_list(report.get("checks"))
    return bool(checks) and all(check.get("status") == "ok" for check in checks)


def _hosted_verify_check_ids(report: Mapping[str, object]) -> set[str]:
    return {
        _public_str(check.get("id"))
        for check in _mapping_list(report.get("checks"))
        if _public_str(check.get("id"))
    }


def _duplicate_hosted_verify_check_ids(report: Mapping[str, object]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for check in _mapping_list(report.get("checks")):
        check_id = _public_str(check.get("id"))
        if not check_id:
            continue
        if check_id in seen:
            duplicates.add(check_id)
        seen.add(check_id)
    return sorted(duplicates)


def _valid_git_sha(value: str, *, allow_empty: bool = False) -> str | None:
    cleaned = value.strip().lower()
    if allow_empty and not cleaned:
        return ""
    return cleaned if re.fullmatch(r"[0-9a-f]{40}", cleaned) else None


def _ok(check_id: str, **extra: object) -> dict[str, object]:
    result: dict[str, object] = {"id": check_id, "status": "ok"}
    result.update(extra)
    return result


def _fail(
    check_id: str,
    failures: str | Sequence[str],
    next_action: str,
    **extra: object,
) -> dict[str, object]:
    failure_list = [failures] if isinstance(failures, str) else list(failures)
    result: dict[str, object] = {
        "id": check_id,
        "status": "blocked",
        "failures": failure_list,
        "next_action": next_action,
    }
    result.update(extra)
    return result


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _public_string_list(value: object) -> list[str]:
    return [redact_public_text(item) for item in _string_list(value)]


def _port_list(value: object) -> list[int]:
    ports: list[int] = []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ports
    for item in value:
        if isinstance(item, Mapping):
            item = item.get("port")
        try:
            port = int(str(item))
        except ValueError:
            continue
        if 0 < port <= 65535 and port not in ports:
            ports.append(port)
    return sorted(ports)


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(str(value))
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _literal_non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _required_runtime_env_present(value: Mapping[str, object]) -> bool:
    for name in HOSTED_RUNTIME_REQUIRED_FILE_ENV:
        row = value.get(name)
        if not isinstance(row, Mapping) or row.get("present") is not True:
            return False
    return True


def _stripe_runtime_env_ready(value: Mapping[str, object]) -> bool:
    secret_key = _mapping(value.get("FUSEKIT_STRIPE_SECRET_KEY"))
    price_id = _mapping(value.get("FUSEKIT_STRIPE_PRICE_ID"))
    price_label = _mapping(value.get("FUSEKIT_MANAGED_RUN_PRICE_LABEL"))
    managed_runs = _mapping(value.get("FUSEKIT_MANAGED_RUNS_ENABLED"))
    return (
        secret_key.get("configured") is True
        and secret_key.get("account_mode") == "live"
        and price_id.get("configured") is True
        and _public_str(price_id.get("public_id")).startswith("price_")
        and price_label.get("configured") is True
        and bool(_public_str(price_label.get("public_label")))
        and managed_runs.get("configured") is True
        and managed_runs.get("must_remain_disabled") is True
        and managed_runs.get("enabled") is False
    )


def _runtime_secret_verify_file_ready(value: Mapping[str, object]) -> bool:
    return (
        value.get("path") == OCI_HOST_POSTURE_SECRET_FILE
        and value.get("exists") is True
        and value.get("regular_file") is True
        and value.get("symlink") is False
        and str(value.get("mode") or "") in {"0600", "600"}
        and value.get("owner_only") is True
        and str(value.get("parent_mode") or "") in {"0700", "700", "0750", "750"}
        and value.get("parent_private_enough") is True
        and value.get("root_owned_required") is True
        and value.get("root_owned") is True
    )


def _public_str(value: object) -> str:
    return redact_public_text(str(value or "").strip())


def _raw_str(value: object) -> str:
    return str(value or "").strip()


def _sanitize_release_receipt(receipt: Mapping[str, object] | None) -> dict[str, object]:
    if not receipt:
        return {}
    preserved_keys = {
        "before_commit_sha",
        "after_commit_sha",
        "post_deploy_proof_command",
        "release_dir",
        "rollback",
    }
    sanitized: dict[str, object] = {}
    for key, value in receipt.items():
        key_text = redact_public_text(str(key))
        if key in preserved_keys:
            sanitized[key_text] = _sanitize_posture_public_value(value, key=str(key))
        else:
            sanitized[key_text] = _sanitize_public_value(value)
    return sanitized


def _sanitize_posture_public_value(value: object, *, key: str = "") -> object:
    if isinstance(value, Mapping):
        return {
            redact_public_text(str(item_key)): _sanitize_posture_public_value(
                item,
                key=str(item_key),
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_posture_public_value(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_posture_public_value(item, key=key) for item in value]
    if isinstance(value, str):
        return _sanitize_posture_public_string(value, key=key)
    return value


def _sanitize_posture_public_string(value: str, *, key: str) -> str:
    stripped = value.strip()
    if key in OCI_HOST_POSTURE_PUBLIC_GIT_SHA_KEYS:
        if not stripped:
            return ""
        commit = _valid_git_sha(stripped)
        if commit:
            return commit
    if key == "release_dir":
        match = re.fullmatch(r"/opt/fusekit/releases/(?P<commit>[0-9a-fA-F]{40})", stripped)
        if match:
            return f"/opt/fusekit/releases/{match.group('commit').lower()}"
    if key == "post_deploy_proof_command":
        match = re.fullmatch(
            r"fusekit-hosted-verify --origin https://fusekit\.snowmanai\.org "
            r"--expected-commit-sha (?P<commit>[0-9a-fA-F]{40})",
            stripped,
        )
        if match:
            return (
                "fusekit-hosted-verify --origin https://fusekit.snowmanai.org "
                f"--expected-commit-sha {match.group('commit').lower()}"
            )
    return redact_public_text(value)


def _sanitize_public_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            redact_public_text(str(key)): _sanitize_public_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_public_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_public_value(item) for item in value]
    if isinstance(value, str):
        return redact_public_text(value)
    return value


if __name__ == "__main__":
    raise SystemExit(main())
