"""Plan-only OCI hosted launcher redeploy/access preflight."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from ipaddress import ip_address

from fusekit.errors import FuseKitError
from fusekit.hosted.server import HOSTED_CANONICAL_ORIGIN
from fusekit.security import contains_durable_secret_text, redact_public_text

HOSTED_OCI_ACCESS_PLAN_SCHEMA_VERSION = "fusekit.hosted-oci-access-plan.v1"
HOSTED_OCI_DEPLOY_ACCESS_REPAIR_SCHEMA_VERSION = "fusekit.hosted-oci-deploy-access-repair.v1"
HOSTED_OCI_ALLOWED_TARGET_TAGS = {
    "Application": "FuseKit",
    "Environment": "production",
    "DataBoundary": "fusekit-public-launcher",
    "ManagedBy": "FuseKit",
    "PiiData": "false",
    "Role": "hosted-launcher",
}
HOSTED_OCI_AMD_SHAPE_PREFIXES = (
    "VM.Standard.E2.",
    "VM.Standard.E3.",
    "VM.Standard.E4.",
    "VM.Standard.E5.",
    "VM.Standard.E6.",
)
HOSTED_OCI_FORBIDDEN_ARM_SHAPE_PREFIXES = ("VM.Standard.A1.",)
HOSTED_OCI_RUN_COMMAND_PLUGIN_NAMES = (
    "Compute Instance Run Command",
    "Run Command",
)
HOSTED_OCI_SSH_OK_STATUSES = {"ok", "reachable"}
HOSTED_OCI_SSH_BLOCKED_STATUSES = {
    "permission_denied",
    "unavailable",
    "timeout",
    "not_configured",
    "not_checked",
}


def build_hosted_oci_access_plan(
    *,
    instance: Mapping[str, object],
    vnic: Mapping[str, object] | None = None,
    plugins: Sequence[Mapping[str, object]] = (),
    hosted_verify_report: Mapping[str, object] | None = None,
    ssh_probe_status: str = "not_checked",
    expected_commit_sha: str = "",
) -> dict[str, object]:
    """Build a redacted, non-mutating OCI host redeploy/access plan."""

    tags = _normalize_tags(instance.get("freeform-tags") or instance.get("freeform_tags"))
    display_name = _public_str(instance.get("display-name") or instance.get("display_name"))
    shape = _public_str(instance.get("shape"))
    lifecycle_state = _public_str(
        instance.get("lifecycle-state") or instance.get("lifecycle_state")
    ).upper()
    public_ip = _public_ip(vnic.get("public-ip") if vnic else instance.get("public-ip"))
    plugin_statuses = _plugin_statuses(plugins)
    hosted_verify = hosted_verify_report or {}
    expected_commit = _valid_commit_sha(expected_commit_sha)
    actual_commit = _hosted_actual_commit_sha(hosted_verify)
    hosted_blockers = _public_string_list(hosted_verify.get("blocking_checks"))
    ssh_status = _normalized_ssh_probe_status(ssh_probe_status)
    run_command_ready = any(
        plugin_statuses.get(name, "").upper() == "RUNNING"
        for name in HOSTED_OCI_RUN_COMMAND_PLUGIN_NAMES
    )
    ssh_ready = ssh_status in HOSTED_OCI_SSH_OK_STATUSES
    release_action = _release_action(
        expected_commit=expected_commit,
        actual_commit=actual_commit,
        hosted_verify_ready=hosted_verify.get("ready") is True,
        ssh_ready=ssh_ready,
        run_command_ready=run_command_ready,
    )
    blockers: list[str] = []
    if not _target_tags_match(tags):
        blockers.append("oci_instance_tags_not_fusekit_hosted_launcher")
    if lifecycle_state != "RUNNING":
        blockers.append("oci_instance_not_running")
    if not _amd_shape(shape):
        blockers.append("oci_instance_shape_must_be_amd_x86_64")
    if not public_ip:
        blockers.append("oci_public_ip_missing")
    if hosted_verify.get("ready") is not True:
        blockers.append("hosted_verify_not_ready")
    if expected_commit and actual_commit and expected_commit != actual_commit:
        blockers.append("hosted_expected_commit_mismatch")
    if not ssh_ready and not run_command_ready:
        blockers.append("oci_deploy_access_unavailable")
    plan = {
        "schema_version": HOSTED_OCI_ACCESS_PLAN_SCHEMA_VERSION,
        "mode": "plan_only",
        "mutates_oci": False,
        "mutates_host": False,
        "ready_to_redeploy": not blockers,
        "blockers": blockers,
        "target": {
            "canonical_origin": HOSTED_CANONICAL_ORIGIN,
            "display_name": display_name,
            "instance_id": _redact_ocid(instance.get("id")),
            "lifecycle_state": lifecycle_state,
            "shape": shape,
            "public_ip": public_ip,
            "tags": {key: tags.get(key, "") for key in sorted(HOSTED_OCI_ALLOWED_TARGET_TAGS)},
        },
        "access": {
            "ssh_probe_status": ssh_status,
            "ssh_ready": ssh_ready,
            "oci_run_command_ready": run_command_ready,
            "plugin_statuses": plugin_statuses,
            "allowed_deploy_paths": _allowed_deploy_paths(
                ssh_ready=ssh_ready,
                run_command_ready=run_command_ready,
            ),
            "next_actions": _access_next_actions(
                ssh_ready=ssh_ready,
                run_command_ready=run_command_ready,
            ),
            "repair_contract": _deploy_access_repair_contract(
                ssh_ready=ssh_ready,
                run_command_ready=run_command_ready,
                ssh_status=ssh_status,
                plugin_statuses=plugin_statuses,
            ),
        },
        "release_proof": {
            "hosted_verify_ready": hosted_verify.get("ready") is True,
            "hosted_verifier_blocking_checks": hosted_blockers,
            "expected_commit_sha": expected_commit,
            "actual_commit_sha": actual_commit,
            "expected_commit_matches_live": bool(
                expected_commit and actual_commit and expected_commit == actual_commit
            ),
            "release_action": release_action,
        },
        "rollback_metadata": {
            "scope": "fusekit_permanent_oci_host_only",
            "reversible_operations": [
                "restore previous /opt/fusekit/current symlink",
                "restart only fusekit-hosted and fusekit-worker-dispatch services",
                "leave Cloudflare DNS unchanged unless a separate DNS dry-run is approved",
            ],
            "completion_requires": [
                "pre_deploy_expected_commit_check",
                "release_symlink_before_after",
                "systemd_restart_receipt",
                "post_deploy_expected_commit_check",
            ],
        },
        "secret_boundary": (
            "This preflight consumes redacted OCI inventory, plugin status, SSH probe "
            "status, and hosted verifier output only. It does not require OCI API keys, SSH "
            "private keys, GitHub App private keys, provider credentials, or vault material."
        ),
    }
    serialized = json.dumps(plan, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("hosted_oci_access_plan_contains_secret_text")
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    """Build a redacted, non-mutating OCI hosted launcher access plan."""

    parser = argparse.ArgumentParser(
        description="Build a redacted OCI hosted launcher redeploy/access preflight."
    )
    parser.add_argument("--instance-json", required=True)
    parser.add_argument("--vnic-json", default="")
    parser.add_argument("--plugins-json", default="")
    parser.add_argument("--hosted-verify-report", default="")
    parser.add_argument("--ssh-probe-status", default="not_checked")
    parser.add_argument("--expected-commit-sha", default="")
    args = parser.parse_args(argv)
    plan = build_hosted_oci_access_plan(
        instance=_read_mapping(args.instance_json),
        vnic=_read_optional_mapping(args.vnic_json),
        plugins=_read_sequence(args.plugins_json),
        hosted_verify_report=_read_optional_mapping(args.hosted_verify_report),
        ssh_probe_status=args.ssh_probe_status,
        expected_commit_sha=args.expected_commit_sha,
    )
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 2 if plan["blockers"] else 0


def _read_mapping(path: str) -> Mapping[str, object]:
    value = _read_json(path)
    if isinstance(value, Mapping):
        data = value.get("data")
        if isinstance(data, Mapping):
            return data
        return value
    raise FuseKitError("oci_access_input_must_be_json_object")


def _read_optional_mapping(path: str) -> Mapping[str, object]:
    if not path:
        return {}
    return _read_mapping(path)


def _read_sequence(path: str) -> Sequence[Mapping[str, object]]:
    if not path:
        return ()
    value = _read_json(path)
    if isinstance(value, Mapping):
        data = value.get("data", value.get("plugins"))
        if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
            return [item for item in data if isinstance(item, Mapping)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [item for item in value if isinstance(item, Mapping)]
    raise FuseKitError("oci_access_plugins_must_be_json_array")


def _read_json(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise FuseKitError("oci_access_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("oci_access_input_invalid_json") from exc


def _normalize_tags(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(tag_value) for key, tag_value in value.items()}


def _target_tags_match(tags: Mapping[str, str]) -> bool:
    return all(tags.get(key) == value for key, value in HOSTED_OCI_ALLOWED_TARGET_TAGS.items())


def _amd_shape(value: str) -> bool:
    if value.startswith(HOSTED_OCI_FORBIDDEN_ARM_SHAPE_PREFIXES):
        return False
    return value.startswith(HOSTED_OCI_AMD_SHAPE_PREFIXES)


def _public_ip(value: object) -> str:
    text = _public_str(value)
    if not text:
        return ""
    try:
        parsed = ip_address(text)
    except ValueError:
        return ""
    return text if parsed.version == 4 and not parsed.is_private else ""


def _plugin_statuses(plugins: Sequence[Mapping[str, object]]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for plugin in plugins:
        name = _public_str(plugin.get("name"))
        status = _public_str(plugin.get("status")).upper()
        if name and status:
            statuses[name] = status
    return statuses


def _allowed_deploy_paths(*, ssh_ready: bool, run_command_ready: bool) -> list[str]:
    paths: list[str] = []
    if ssh_ready:
        paths.append("ssh_release")
    if run_command_ready:
        paths.append("oci_run_command_release")
    return paths


def _access_next_actions(*, ssh_ready: bool, run_command_ready: bool) -> list[str]:
    if ssh_ready or run_command_ready:
        return [
            "Run the hosted release procedure, then rerun fusekit-hosted-verify with "
            "--expected-commit-sha and collect OCI posture evidence.",
        ]
    return [
        "Restore exactly one deployment path for the FuseKit hosted launcher: either "
        "install the approved SSH deploy key for the launcher host user, or enable OCI "
        "Compute Instance Run Command for this FuseKit-tagged instance only.",
        "Do not broaden Cloudflare DNS, MailPilot/AWS, or generated-app credentials while "
        "repairing deploy access.",
    ]


def _deploy_access_repair_contract(
    *,
    ssh_ready: bool,
    run_command_ready: bool,
    ssh_status: str,
    plugin_statuses: Mapping[str, str],
) -> dict[str, object]:
    deploy_paths = _allowed_deploy_paths(ssh_ready=ssh_ready, run_command_ready=run_command_ready)
    run_command_status = _run_command_plugin_status(plugin_statuses)
    return {
        "schema_version": HOSTED_OCI_DEPLOY_ACCESS_REPAIR_SCHEMA_VERSION,
        "repair_needed": not deploy_paths,
        "allowed_repairs": [
            {
                "id": "enable_oci_run_command_for_fusekit_host",
                "label": (
                    "Enable OCI Compute Instance Run Command only for the FuseKit-tagged "
                    "hosted launcher instance."
                ),
                "scope": "single_fusekit_tagged_oci_instance",
                "current_status": run_command_status,
            },
            {
                "id": "install_fusekit_host_ssh_deploy_key",
                "label": (
                    "Install the approved SSH deploy key only for the fusekit host user on "
                    "the FuseKit-tagged launcher."
                ),
                "scope": "single_fusekit_host_user",
                "current_status": ssh_status,
            },
        ],
        "forbidden_repairs": [
            "Do not change Cloudflare DNS while restoring deploy access.",
            "Do not add MailPilot, AWS, billing, generated-app, or provider credentials.",
            "Do not broaden OCI tenancy-wide admin policy for the hosted launcher.",
            "Do not switch to ARM/Ampere shapes.",
        ],
        "completion_requires": [
            "exactly_one_allowed_deploy_path_ready",
            "fusekit_hosted_release_receipt",
            "expected_commit_verifier_passes",
            "oci_host_posture_report_attaches_release_receipt",
        ],
        "secret_boundary": (
            "Deploy-access repair proof contains public status labels only. It must not "
            "include SSH private keys, OCI API keys, session tokens, provider credentials, "
            "vault material, or raw command output."
        ),
    }


def _run_command_plugin_status(plugin_statuses: Mapping[str, str]) -> str:
    for name in HOSTED_OCI_RUN_COMMAND_PLUGIN_NAMES:
        status = plugin_statuses.get(name)
        if status:
            return status
    return "not_present"


def _release_action(
    *,
    expected_commit: str,
    actual_commit: str,
    hosted_verify_ready: bool,
    ssh_ready: bool,
    run_command_ready: bool,
) -> dict[str, object]:
    deploy_paths = _allowed_deploy_paths(ssh_ready=ssh_ready, run_command_ready=run_command_ready)
    commit_state = "unknown"
    if expected_commit and actual_commit:
        commit_state = "current" if expected_commit == actual_commit else "stale"
    elif expected_commit and not actual_commit:
        commit_state = "missing_live_commit"
    return {
        "commit_state": commit_state,
        "live_commit_sha": actual_commit,
        "expected_commit_sha": expected_commit,
        "deploy_access_ready": bool(deploy_paths),
        "allowed_deploy_paths": deploy_paths,
        "safe_next_action": _release_safe_next_action(
            commit_state=commit_state,
            hosted_verify_ready=hosted_verify_ready,
            deploy_paths=deploy_paths,
        ),
        "post_deploy_proof_command": (
            "fusekit-hosted-verify --origin https://fusekit.snowmanai.org "
            "--expected-commit-sha <expected-commit-sha>"
        ),
        "completion_requires": [
            "hosted verifier ready",
            "expected commit matches live commit",
            "OCI posture evidence captured after redeploy",
            "rollback metadata preserved",
        ],
    }


def _release_safe_next_action(
    *,
    commit_state: str,
    hosted_verify_ready: bool,
    deploy_paths: Sequence[str],
) -> str:
    if not deploy_paths:
        return (
            "Restore one narrow deploy path for the FuseKit-tagged OCI launcher before "
            "redeploying: SSH release or OCI Run Command release."
        )
    if commit_state in {"stale", "missing_live_commit"}:
        return (
            "Redeploy only the FuseKit hosted launcher from the expected commit using an "
            "allowed deploy path, then rerun the expected-commit verifier."
        )
    if not hosted_verify_ready:
        return (
            "Keep the deployed commit in place and repair the hosted verifier blockers before "
            "claiming launch readiness."
        )
    return "No redeploy needed; preserve this release proof with OCI posture evidence."


def _hosted_actual_commit_sha(report: Mapping[str, object]) -> str:
    for check in _mapping_list(report.get("checks")):
        if check.get("id") == "hosted.expected_commit":
            commit = _valid_commit_sha(str(check.get("actual_commit_sha") or ""))
            if commit:
                return commit
    provenance = _mapping(report.get("source_provenance"))
    actual = _mapping(provenance.get("actual"))
    return _valid_commit_sha(str(actual.get("commit_sha") or ""))


def _valid_commit_sha(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned if re.fullmatch(r"[0-9a-f]{40}", cleaned) else ""


def _normalized_ssh_probe_status(value: str) -> str:
    cleaned = value.strip().lower().replace("-", "_")
    allowed = HOSTED_OCI_SSH_OK_STATUSES | HOSTED_OCI_SSH_BLOCKED_STATUSES
    return cleaned if cleaned in allowed else "not_checked"


def _redact_ocid(value: object) -> str:
    text = _public_str(value)
    if not text.startswith("ocid1."):
        return ""
    parts = text.split(".")
    resource = parts[1] if len(parts) > 1 else "resource"
    suffix = text[-8:] if len(text) >= 8 else "redacted"
    return f"ocid1.{resource}.<redacted:{suffix}>"


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _public_string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [redact_public_text(str(item).strip()) for item in value if str(item).strip()]


def _public_str(value: object) -> str:
    return redact_public_text(str(value or "").strip())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
