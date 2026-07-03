from __future__ import annotations

import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.oci_access import build_hosted_oci_access_plan
from fusekit.hosted.oci_inventory import build_hosted_oci_inventory_report
from fusekit.hosted.oci_replacement import (
    HOSTED_OCI_REPLACEMENT_PLAN_SCHEMA_VERSION,
    build_hosted_oci_replacement_plan,
    main,
)
from fusekit.security import contains_durable_secret_text

EXPECTED_COMMIT = "04cdf22c57842f5516f9fb90acfcd706cb8e5952"
ACTUAL_COMMIT = "df448c5982306823887c505d30335af7d02ffd2e"


def _instance(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "ocid1.instance.oc1.phx.rawinstanceidentifier",
        "display-name": "fusekit-hosted-launcher-amd",
        "lifecycle-state": "RUNNING",
        "shape": "VM.Standard.E2.1.Micro",
        "freeform-tags": {
            "Application": "FuseKit",
            "DataBoundary": "fusekit-public-launcher",
            "Environment": "production",
            "ManagedBy": "FuseKit",
            "PiiData": "false",
            "Role": "hosted-launcher",
        },
    }
    value.update(overrides)
    return value


def _hosted_verify_not_ready() -> dict[str, object]:
    return {
        "public_origin": "https://fusekit.snowmanai.org",
        "ready": False,
        "blocking_checks": ["hosted.home", "hosted.readiness", "hosted.expected_commit"],
        "checks": [
            {
                "id": "hosted.expected_commit",
                "status": "failed",
                "actual_commit_sha": ACTUAL_COMMIT,
                "expected_commit_sha": EXPECTED_COMMIT,
            }
        ],
    }


def _inventory_report() -> dict[str, object]:
    return build_hosted_oci_inventory_report(
        target_match_count=1,
        instance=_instance(),
        vnic={"public-ip": "129.153.118.11"},
        plugins=[
            {"name": "Vulnerability Scanning", "status": "STOPPED"},
            {"name": "Bastion", "status": "STOPPED"},
        ],
        available_plugins=[
            {"name": "Vulnerability Scanning"},
            {"name": "Bastion"},
            {"name": "Compute Instance Monitoring"},
        ],
        image={
            "display-name": "Canonical-Ubuntu-24.04-Minimal",
            "operating-system": "Canonical Ubuntu",
            "operating-system-version": "24.04",
        },
        hosted_verify_report=_hosted_verify_not_ready(),
        ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )


def test_oci_replacement_plan_allows_narrow_amd_candidate_with_deploy_path() -> None:
    plan = build_hosted_oci_replacement_plan(
        inventory_report=_inventory_report(),
        replacement_shape="VM.Standard.E5.Flex",
        replacement_os="Canonical Ubuntu",
        replacement_os_version="24.04",
        replacement_run_command_availability="available_not_installed",
        replacement_ssh_probe_status="not_checked",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    serialized = json.dumps(plan, sort_keys=True)
    assert plan["schema_version"] == HOSTED_OCI_REPLACEMENT_PLAN_SCHEMA_VERSION
    assert plan["mode"] == "plan_only"
    assert plan["mutates_oci"] is False
    assert plan["mutates_host"] is False
    assert plan["mutates_dns"] is False
    assert plan["ready_to_create_replacement"] is True
    assert plan["blockers"] == []
    assert plan["current_host"]["status"] == "kept_live_until_replacement_proof_passes"
    assert plan["current_host"]["run_command_availability"] == "not_available_for_image"
    assert plan["current_host"]["allowed_deploy_paths"] == []
    assert plan["replacement_candidate"]["shape_policy"]["architecture"] == "amd64_x86_64_only"
    assert plan["replacement_candidate"]["deploy_access"]["allowed_deploy_paths"] == [
        "oci_run_command_release"
    ]
    assert "move_dns_only_after_replacement_verifier_and_posture_pass" in plan["cutover_gates"]
    assert "do_not_move_cloudflare_dns_before_replacement_verifier_and_posture_pass" in plan[
        "forbidden_actions"
    ]
    assert plan["rollback"]["old_host_stays_running"] is True
    assert "outside_in_hosted_verify_expected_commit_pass" in plan["required_public_proof"]
    assert EXPECTED_COMMIT in serialized
    assert "rawinstanceidentifier" not in serialized
    assert not contains_durable_secret_text(serialized)


def test_oci_replacement_plan_blocks_arm_and_missing_replacement_deploy_access() -> None:
    plan = build_hosted_oci_replacement_plan(
        inventory_report=_inventory_report(),
        replacement_shape="VM.Standard.A1.Flex",
        replacement_run_command_availability="not_available_for_image",
        replacement_ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert plan["ready_to_create_replacement"] is False
    assert plan["blockers"] == [
        "replacement_shape_must_be_amd_x86_64",
        "replacement_deploy_access_not_proven",
    ]
    assert plan["replacement_candidate"]["deploy_access"]["allowed_deploy_paths"] == []


def test_oci_replacement_plan_requires_current_access_blocker_evidence() -> None:
    current_plan = build_hosted_oci_access_plan(
        instance=_instance(),
        vnic={"public-ip": "129.153.118.11"},
        plugins=[{"name": "Compute Instance Run Command", "status": "RUNNING"}],
        hosted_verify_report={
            "ready": True,
            "source_provenance": {"actual": {"commit_sha": EXPECTED_COMMIT}},
        },
        ssh_probe_status="not_checked",
        expected_commit_sha=EXPECTED_COMMIT,
    )
    inventory = _inventory_report()
    inventory["access_plan"] = current_plan

    plan = build_hosted_oci_replacement_plan(
        inventory_report=inventory,
        replacement_run_command_availability="running",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert plan["ready_to_create_replacement"] is False
    assert plan["blockers"] == ["current_host_deploy_access_unavailable_not_proven"]


def test_oci_replacement_plan_blocks_ambiguous_inventory() -> None:
    inventory = _inventory_report()
    inventory["target_match_count"] = 2
    inventory["inventory_ready"] = False

    plan = build_hosted_oci_replacement_plan(
        inventory_report=inventory,
        replacement_run_command_availability="running",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert plan["ready_to_create_replacement"] is False
    assert "inventory_report_not_ready" in plan["blockers"]
    assert "inventory_report_target_must_be_unique" in plan["blockers"]


def test_oci_replacement_plan_rejects_nonpublic_identifiers() -> None:
    inventory = _inventory_report()
    inventory["target"]["instance"]["display-name"] = "ocid1.tenancy.oc1..do-not-emit"

    with pytest.raises(FuseKitError, match="hosted_oci_replacement_plan_contains"):
        build_hosted_oci_replacement_plan(
            inventory_report=inventory,
            replacement_run_command_availability="running",
            expected_commit_sha=EXPECTED_COMMIT,
        )


def test_oci_replacement_plan_cli_reads_inventory(tmp_path, capfd) -> None:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(_inventory_report()), encoding="utf-8")

    exit_code = main(
        [
            "--inventory-report",
            str(inventory_path),
            "--replacement-run-command-availability",
            "available_not_installed",
            "--expected-commit-sha",
            EXPECTED_COMMIT,
        ]
    )
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 0
    assert output["ready_to_create_replacement"] is True
    assert output["replacement_candidate"]["deploy_access"]["allowed_deploy_paths"] == [
        "oci_run_command_release"
    ]
