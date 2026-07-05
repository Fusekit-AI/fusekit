"""Plan-only replacement contract for the permanent OCI hosted launcher."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence

from fusekit.errors import FuseKitError
from fusekit.hosted.oci_access import (
    HOSTED_OCI_ALLOWED_TARGET_TAGS,
    HOSTED_OCI_AMD_SHAPE_PREFIXES,
    HOSTED_OCI_FORBIDDEN_ARM_SHAPE_PREFIXES,
)
from fusekit.hosted.oci_inventory import HOSTED_OCI_INVENTORY_SCHEMA_VERSION
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_INSTALL_SCHEMA_VERSION,
    HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION,
    HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION,
)
from fusekit.hosted.server import HOSTED_CANONICAL_ORIGIN
from fusekit.security import contains_durable_secret_text, redact_public_text

HOSTED_OCI_REPLACEMENT_PLAN_SCHEMA_VERSION = "fusekit.hosted-oci-replacement-plan.v1"
HOSTED_OCI_REPLACEMENT_DEFAULT_SHAPE = "VM.Standard.E5.Flex"
HOSTED_OCI_REPLACEMENT_SUPPORTED_OS = ("Canonical Ubuntu", "Ubuntu")
HOSTED_OCI_REPLACEMENT_SUPPORTED_OS_VERSIONS = ("24.04", "22.04")
HOSTED_OCI_REPLACEMENT_RUN_COMMAND_OK = {
    "running",
    "available_not_installed",
}
HOSTED_OCI_REPLACEMENT_SSH_OK = {"ok", "reachable"}


def build_hosted_oci_replacement_plan(
    *,
    inventory_report: Mapping[str, object],
    replacement_shape: str = HOSTED_OCI_REPLACEMENT_DEFAULT_SHAPE,
    replacement_os: str = "Canonical Ubuntu",
    replacement_os_version: str = "24.04",
    replacement_run_command_availability: str = "unknown",
    replacement_ssh_probe_status: str = "not_checked",
    expected_commit_sha: str = "",
    runtime_secret_report: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a redacted, non-mutating replacement-host plan."""

    inventory_blockers = _inventory_blockers(inventory_report)
    access_plan = _mapping(inventory_report.get("access_plan"))
    current_access = _mapping(access_plan.get("access"))
    current_target = _mapping(_mapping(inventory_report.get("target")).get("instance"))
    current_release = _mapping(access_plan.get("release_proof"))
    replacement_shape_public = _public_str(replacement_shape)
    replacement_os_public = _public_str(replacement_os)
    replacement_os_version_public = _public_str(replacement_os_version)
    run_command_availability = _normalized_run_command_availability(
        replacement_run_command_availability
    )
    ssh_probe_status = _normalized_ssh_probe_status(replacement_ssh_probe_status)
    expected_commit = _valid_commit_sha(expected_commit_sha) or _public_str(
        current_release.get("expected_commit_sha")
    )
    blockers = [*inventory_blockers]
    if "oci_deploy_access_unavailable" not in _public_string_list(access_plan.get("blockers")):
        blockers.append("current_host_deploy_access_unavailable_not_proven")
    if not _amd_shape(replacement_shape_public):
        blockers.append("replacement_shape_must_be_amd_x86_64")
    if replacement_os_public not in HOSTED_OCI_REPLACEMENT_SUPPORTED_OS:
        blockers.append("replacement_os_must_be_supported_ubuntu")
    if replacement_os_version_public not in HOSTED_OCI_REPLACEMENT_SUPPORTED_OS_VERSIONS:
        blockers.append("replacement_os_version_must_be_supported")
    replacement_deploy_paths = _replacement_deploy_paths(
        run_command_availability=run_command_availability,
        ssh_probe_status=ssh_probe_status,
    )
    if not replacement_deploy_paths:
        blockers.append("replacement_deploy_access_not_proven")
    if not expected_commit:
        blockers.append("expected_commit_sha_required")
    runtime = _runtime_secret_readiness(runtime_secret_report)
    cutover_blockers = [*blockers, *_code_string_list(runtime.get("blockers"))]
    plan = {
        "schema_version": HOSTED_OCI_REPLACEMENT_PLAN_SCHEMA_VERSION,
        "mode": "plan_only",
        "mutates_oci": False,
        "mutates_host": False,
        "mutates_dns": False,
        "ready_to_create_replacement": not blockers,
        "ready_for_dns_cutover": not cutover_blockers,
        "blockers": blockers,
        "cutover_blockers": cutover_blockers,
        "canonical_origin": HOSTED_CANONICAL_ORIGIN,
        "current_host": {
            "status": "kept_live_until_replacement_proof_passes",
            "display_name": _public_str(current_target.get("display-name")),
            "shape": _public_str(current_target.get("shape")),
            "run_command_availability": _public_str(
                current_access.get("oci_run_command_availability")
            ),
            "allowed_deploy_paths": _public_string_list(
                current_access.get("allowed_deploy_paths")
            ),
            "release_commit_state": _public_str(
                _mapping(current_release.get("release_action")).get("commit_state")
            ),
            "live_commit_sha": _valid_commit_sha(
                _public_str(current_release.get("actual_commit_sha"))
            ),
        },
        "replacement_candidate": {
            "shape": replacement_shape_public,
            "shape_policy": {
                "architecture": "amd64_x86_64_only",
                "allowed_prefixes": list(HOSTED_OCI_AMD_SHAPE_PREFIXES),
                "forbidden_prefixes": list(HOSTED_OCI_FORBIDDEN_ARM_SHAPE_PREFIXES),
            },
            "image": {
                "operating_system": replacement_os_public,
                "operating_system_version": replacement_os_version_public,
                "must_support_cloud_init": True,
                "must_support_oci_run_command_or_approved_ssh": True,
            },
            "required_tags": dict(sorted(HOSTED_OCI_ALLOWED_TARGET_TAGS.items())),
            "deploy_access": {
                "oci_run_command_availability": run_command_availability,
                "ssh_probe_status": ssh_probe_status,
                "allowed_deploy_paths": replacement_deploy_paths,
            },
        },
        "runtime_secret_readiness": runtime,
        "cutover_gates": [
            "create_replacement_without_changing_cloudflare_dns",
            "install_deploy_oci_templates_and_nonsecret_provenance",
            "place_runtime_secrets_only_in_root_owned_hosted_secrets_env",
            "release_expected_commit_on_replacement",
            "verify_replacement_origin_before_dns_cutover",
            "collect_replacement_oci_inventory_and_host_posture",
            "prepare_one_record_cloudflare_dns_dry_run",
            "move_dns_only_after_replacement_verifier_and_posture_pass",
            "preserve_old_host_until_post_cutover_expected_commit_verifier_passes",
        ],
        "rollback": {
            "mode": "old_host_dns_restore",
            "old_host_stays_running": True,
            "reversible_operations": [
                "restore Cloudflare record to previous hosted launcher IP or CNAME",
                "stop or terminate only the replacement FuseKit-tagged host after proof export",
                "keep old host release receipt and provenance evidence",
            ],
        },
        "forbidden_actions": [
            "do_not_modify_mailpilot_or_aws_resources",
            "do_not_change_stripe_products_prices_customers_or_webhooks",
            "do_not_add_generated_app_or_provider_credentials_to_plan_output",
            "do_not_broaden_oci_tenancy_admin_policy",
            "do_not_use_arm_or_ampere_shapes",
            "do_not_move_cloudflare_dns_before_replacement_verifier_and_posture_pass",
            "do_not_claim_launch_ready_before_live_expected_commit_matches",
        ],
        "required_public_proof": [
            "old_host_inventory_report",
            "replacement_host_inventory_report",
            "replacement_host_posture_report",
            "release_receipt_for_expected_commit",
            "outside_in_hosted_verify_expected_commit_pass",
            "cloudflare_one_record_dns_dry_run",
            "post_cutover_hosted_verify_expected_commit_pass",
            "rollback_metadata",
        ],
        "expected_commit_sha": expected_commit,
        "operator_summary": _operator_summary(blockers=blockers),
        "secret_boundary": (
            "This replacement plan contains public shape, image, tag, deploy-path, proof, "
            "and rollback labels only. It must not include OCI API keys, SSH private keys, "
            "GitHub App private keys, Stripe secrets, provider credentials, vault material, "
            "hosted runtime secret values, or raw logs."
        ),
    }
    _assert_public_plan(plan)
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    """Build a redacted, non-mutating OCI hosted launcher replacement plan."""

    parser = argparse.ArgumentParser(
        description="Build a redacted plan-only replacement contract for the OCI launcher."
    )
    parser.add_argument("--inventory-report", required=True)
    parser.add_argument("--replacement-shape", default=HOSTED_OCI_REPLACEMENT_DEFAULT_SHAPE)
    parser.add_argument("--replacement-os", default="Canonical Ubuntu")
    parser.add_argument("--replacement-os-version", default="24.04")
    parser.add_argument("--replacement-run-command-availability", default="unknown")
    parser.add_argument("--replacement-ssh-probe-status", default="not_checked")
    parser.add_argument("--expected-commit-sha", default="")
    parser.add_argument("--runtime-secret-report", default="")
    args = parser.parse_args(argv)
    try:
        plan = build_hosted_oci_replacement_plan(
            inventory_report=_read_mapping(args.inventory_report),
            replacement_shape=args.replacement_shape,
            replacement_os=args.replacement_os,
            replacement_os_version=args.replacement_os_version,
            replacement_run_command_availability=args.replacement_run_command_availability,
            replacement_ssh_probe_status=args.replacement_ssh_probe_status,
            expected_commit_sha=args.expected_commit_sha,
            runtime_secret_report=_read_optional_mapping(args.runtime_secret_report),
        )
    except FuseKitError as exc:
        plan = {
            "schema_version": HOSTED_OCI_REPLACEMENT_PLAN_SCHEMA_VERSION,
            "mode": "plan_only",
            "ready_to_create_replacement": False,
            "ready_for_dns_cutover": False,
            "mutates_oci": False,
            "mutates_host": False,
            "mutates_dns": False,
            "error": str(exc),
            "secret_boundary": (
                "Replacement planning errors are reported as redacted error codes only."
            ),
        }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0 if plan.get("ready_to_create_replacement") is True else 2


def _read_optional_mapping(path: str) -> Mapping[str, object] | None:
    if not path:
        return None
    return _read_mapping(path)


def _read_mapping(path: str) -> Mapping[str, object]:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except OSError as exc:
        raise FuseKitError("oci_replacement_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("oci_replacement_input_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("oci_replacement_input_must_be_json_object")
    return value


def _inventory_blockers(inventory_report: Mapping[str, object]) -> list[str]:
    blockers: list[str] = []
    if inventory_report.get("schema_version") != HOSTED_OCI_INVENTORY_SCHEMA_VERSION:
        blockers.append("inventory_report_schema_invalid")
    if inventory_report.get("mutates_oci") is not False:
        blockers.append("inventory_report_must_not_mutate_oci")
    if inventory_report.get("mutates_host") is not False:
        blockers.append("inventory_report_must_not_mutate_host")
    if inventory_report.get("inventory_ready") is not True:
        blockers.append("inventory_report_not_ready")
    target_match_count = inventory_report.get("target_match_count")
    if (
        isinstance(target_match_count, bool)
        or not isinstance(target_match_count, int)
        or target_match_count != 1
    ):
        blockers.append("inventory_report_target_must_be_unique")
    if inventory_report.get("collection_failures") not in ([], ()):
        blockers.append("inventory_report_collection_failures_present")
    return blockers


def _runtime_secret_readiness(
    runtime_secret_report: Mapping[str, object] | None,
) -> dict[str, object]:
    if runtime_secret_report is None:
        return {
            "attached": False,
            "ready_to_write_secret_file": False,
            "ready_for_managed_payment_staging": False,
            "blockers": ["runtime_secret_report_required_for_cutover"],
        }
    blockers: list[str] = []
    schema = runtime_secret_report.get("schema_version")
    plan_schema = runtime_secret_report.get("plan_schema_version")
    install_report = schema == HOSTED_RUNTIME_SECRET_INSTALL_SCHEMA_VERSION
    plan_report = schema == HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION
    verify_report = schema == HOSTED_RUNTIME_SECRET_VERIFY_SCHEMA_VERSION
    if not verify_report and not plan_report and not (
        install_report and plan_schema == HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION
    ):
        blockers.append("runtime_secret_report_schema_invalid")
    if runtime_secret_report.get("mutates_provider") is not False:
        blockers.append("runtime_secret_report_must_not_mutate_provider")
    if verify_report:
        if runtime_secret_report.get("mutates_host") is not False:
            blockers.append("runtime_secret_verify_report_must_not_mutate_host")
        if runtime_secret_report.get("ready") is not True:
            blockers.append("runtime_secret_verify_report_not_ready")
    elif runtime_secret_report.get("ready_to_write_secret_file") is not True:
        blockers.append("runtime_secret_report_not_ready")
    if runtime_secret_report.get("ready_for_managed_payment_staging") is not True:
        blockers.append("runtime_secret_report_payment_staging_not_ready")
    if verify_report:
        pass
    elif install_report:
        if runtime_secret_report.get("written") is not True:
            blockers.append("runtime_secret_file_not_written")
        blockers.append("runtime_secret_verify_report_required_for_cutover")
    else:
        blockers.append("runtime_secret_verify_report_required_for_cutover")
    return {
        "attached": True,
        "install_receipt": install_report,
        "verify_report": verify_report,
        "written": runtime_secret_report.get("written") is True,
        "verified": verify_report and runtime_secret_report.get("ready") is True,
        "ready_to_write_secret_file": runtime_secret_report.get("ready_to_write_secret_file")
        is True,
        "ready_for_managed_payment_staging": runtime_secret_report.get(
            "ready_for_managed_payment_staging"
        )
        is True,
        "blockers": blockers,
    }


def _replacement_deploy_paths(
    *,
    run_command_availability: str,
    ssh_probe_status: str,
) -> list[str]:
    paths: list[str] = []
    if run_command_availability in HOSTED_OCI_REPLACEMENT_RUN_COMMAND_OK:
        paths.append("oci_run_command_release")
    if ssh_probe_status in HOSTED_OCI_REPLACEMENT_SSH_OK:
        paths.append("ssh_release")
    return paths


def _operator_summary(*, blockers: Sequence[str]) -> str:
    if blockers:
        return (
            "Replacement is not ready to request. Resolve the named blockers without "
            "changing Cloudflare DNS, Stripe, MailPilot/AWS, generated-app credentials, or "
            "provider accounts."
        )
    return (
        "Replacement can be requested as a narrow FuseKit-only OCI host operation. Keep the "
        "old host live and DNS unchanged until replacement verifier, posture, release "
        "receipt, and rollback proof all pass."
    )


def _normalized_run_command_availability(value: str) -> str:
    cleaned = value.strip().lower().replace("-", "_")
    allowed = {
        "unknown",
        "running",
        "installed_not_running",
        "available_not_installed",
        "not_available_for_image",
    }
    return cleaned if cleaned in allowed else "unknown"


def _normalized_ssh_probe_status(value: str) -> str:
    cleaned = value.strip().lower().replace("-", "_")
    allowed = {"ok", "reachable", "permission_denied", "unavailable", "timeout", "not_checked"}
    return cleaned if cleaned in allowed else "not_checked"


def _amd_shape(value: str) -> bool:
    if value.startswith(HOSTED_OCI_FORBIDDEN_ARM_SHAPE_PREFIXES):
        return False
    return value.startswith(HOSTED_OCI_AMD_SHAPE_PREFIXES)


def _valid_commit_sha(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned if re.fullmatch(r"[0-9a-f]{40}", cleaned) else ""


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _public_string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [redact_public_text(str(item).strip()) for item in value if str(item).strip()]


def _code_string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    codes: list[str] = []
    for item in value:
        code = str(item).strip()
        if re.fullmatch(r"[a-z0-9_]+", code):
            codes.append(code)
    return codes


def _public_str(value: object) -> str:
    return redact_public_text(str(value or "").strip())


def _assert_public_plan(plan: Mapping[str, object]) -> None:
    serialized = json.dumps(plan, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("hosted_oci_replacement_plan_contains_secret_text")
    forbidden_patterns = [
        r"ocid1\.(?:tenancy|user|compartment|vnic|image)\.",
        r"ocid1_",
        r"rk_live",
        r"rk_test",
        r"\bASIA",
        r"aws_secret_access_key",
        r"-----BEGIN ",
        r"\bfingerprints?\b",
    ]
    if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in forbidden_patterns):
        raise FuseKitError("hosted_oci_replacement_plan_contains_nonpublic_identifier")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
