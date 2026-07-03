from __future__ import annotations

import json

from fusekit.hosted.oci_access import (
    HOSTED_OCI_ACCESS_PLAN_SCHEMA_VERSION,
    HOSTED_OCI_DEPLOY_ACCESS_REPAIR_SCHEMA_VERSION,
    build_hosted_oci_access_plan,
    main,
)
from fusekit.security import contains_durable_secret_text

INSTANCE_ID = "ocid1.instance.oc1.phx.anyhqljt5tdfylacdjqchfkhnj22hvpbrfhcx5stmk6ahxe5h6cyvhpsxojq"
EXPECTED_COMMIT = "b7c0fd4c6d4745f9411c07ad20d707240bc1e46a"
ACTUAL_COMMIT = "df448c5982306823887c505d30335af7d02ffd2e"


def _instance(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": INSTANCE_ID,
        "display-name": "fusekit-hosted-launcher-amd",
        "lifecycle-state": "RUNNING",
        "shape": "VM.Standard.E2.1.Micro",
        "freeform-tags": {
            "Application": "FuseKit",
            "Architecture": "amd64",
            "DataBoundary": "fusekit-public-launcher",
            "Environment": "production",
            "ManagedBy": "FuseKit",
            "PiiData": "false",
            "Role": "hosted-launcher",
        },
    }
    value.update(overrides)
    return value


def _vnic(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {"public-ip": "129.153.118.11"}
    value.update(overrides)
    return value


def _hosted_verify(*, ready: bool = True) -> dict[str, object]:
    if ready:
        return {
            "public_origin": "https://fusekit.snowmanai.org",
            "ready": True,
            "source_provenance": {"actual": {"commit_sha": EXPECTED_COMMIT}},
        }
    return {
        "public_origin": "https://fusekit.snowmanai.org",
        "ready": False,
        "blocking_checks": ["hosted.expected_commit"],
        "checks": [
            {
                "id": "hosted.expected_commit",
                "status": "failed",
                "actual_commit_sha": ACTUAL_COMMIT,
                "expected_commit_sha": EXPECTED_COMMIT,
                "failures": ["expected_commit_sha_mismatch"],
            }
        ],
    }


def test_hosted_oci_access_plan_blocks_stale_commit_and_missing_access() -> None:
    plan = build_hosted_oci_access_plan(
        instance=_instance(),
        vnic=_vnic(),
        plugins=[
            {"name": "Vulnerability Scanning", "status": "STOPPED"},
            {"name": "Bastion", "status": "STOPPED"},
        ],
        hosted_verify_report=_hosted_verify(ready=False),
        ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    serialized = json.dumps(plan)
    assert plan["schema_version"] == HOSTED_OCI_ACCESS_PLAN_SCHEMA_VERSION
    assert plan["mode"] == "plan_only"
    assert plan["mutates_oci"] is False
    assert plan["mutates_host"] is False
    assert plan["ready_to_redeploy"] is False
    assert plan["blockers"] == [
        "hosted_verify_not_ready",
        "hosted_expected_commit_mismatch",
        "oci_deploy_access_unavailable",
    ]
    assert plan["access"]["allowed_deploy_paths"] == []
    assert plan["access"]["oci_run_command_availability"] == "unknown"
    assert plan["access"]["available_plugin_names"] == []
    assert plan["access"]["repair_contract"] == {
        "schema_version": HOSTED_OCI_DEPLOY_ACCESS_REPAIR_SCHEMA_VERSION,
        "repair_needed": True,
        "run_command_availability": "unknown",
        "allowed_repairs": [
            {
                "id": "enable_oci_run_command_for_fusekit_host",
                "label": (
                    "Enable OCI Compute Instance Run Command only for the FuseKit-tagged "
                    "hosted launcher instance."
                ),
                "scope": "single_fusekit_tagged_oci_instance",
                "current_status": "not_present",
            },
            {
                "id": "install_fusekit_host_ssh_deploy_key",
                "label": (
                    "Install the approved SSH deploy key only for the fusekit host user on "
                    "the FuseKit-tagged launcher."
                ),
                "scope": "single_fusekit_host_user",
                "current_status": "permission_denied",
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
    assert plan["release_proof"]["hosted_verifier_blocking_checks"] == [
        "hosted.expected_commit"
    ]
    assert plan["release_proof"]["actual_commit_sha"] == ACTUAL_COMMIT
    assert plan["release_proof"]["expected_commit_sha"] == EXPECTED_COMMIT
    assert plan["release_proof"]["release_action"] == {
        "commit_state": "stale",
        "live_commit_sha": ACTUAL_COMMIT,
        "expected_commit_sha": EXPECTED_COMMIT,
        "deploy_access_ready": False,
        "allowed_deploy_paths": [],
        "safe_next_action": (
            "Restore one narrow deploy path for the FuseKit-tagged OCI launcher before "
            "redeploying: SSH release or OCI Run Command release."
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
    assert INSTANCE_ID not in serialized
    assert "ocid1.instance.<redacted:" in serialized
    assert not contains_durable_secret_text(serialized)


def test_hosted_oci_access_plan_allows_redeploy_when_run_command_ready() -> None:
    plan = build_hosted_oci_access_plan(
        instance=_instance(),
        vnic=_vnic(),
        plugins=[{"name": "Compute Instance Run Command", "status": "RUNNING"}],
        hosted_verify_report=_hosted_verify(),
        ssh_probe_status="not_checked",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert plan["ready_to_redeploy"] is True
    assert plan["blockers"] == []
    assert plan["access"]["ssh_ready"] is False
    assert plan["access"]["oci_run_command_ready"] is True
    assert plan["access"]["oci_run_command_availability"] == "running"
    assert plan["access"]["allowed_deploy_paths"] == ["oci_run_command_release"]
    assert plan["access"]["repair_contract"]["repair_needed"] is False
    assert plan["access"]["repair_contract"]["run_command_availability"] == "running"
    assert plan["access"]["repair_contract"]["allowed_repairs"][0]["current_status"] == "RUNNING"
    assert "Do not broaden OCI tenancy-wide admin policy" in " ".join(
        plan["access"]["repair_contract"]["forbidden_repairs"]
    )
    assert plan["release_proof"]["expected_commit_matches_live"] is True
    assert plan["release_proof"]["release_action"]["commit_state"] == "current"
    assert plan["release_proof"]["release_action"]["deploy_access_ready"] is True
    assert plan["release_proof"]["release_action"]["allowed_deploy_paths"] == [
        "oci_run_command_release"
    ]
    assert plan["release_proof"]["release_action"]["safe_next_action"] == (
        "No redeploy needed; preserve this release proof with OCI posture evidence."
    )


def test_hosted_oci_access_plan_marks_run_command_unavailable_for_image() -> None:
    plan = build_hosted_oci_access_plan(
        instance=_instance(),
        vnic=_vnic(),
        plugins=[
            {"name": "Vulnerability Scanning", "status": "STOPPED"},
            {"name": "Bastion", "status": "STOPPED"},
        ],
        available_plugins=[
            {"name": "Vulnerability Scanning"},
            {"name": "Bastion"},
            {"name": "Compute Instance Monitoring"},
        ],
        hosted_verify_report=_hosted_verify(ready=False),
        ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    repair = plan["access"]["repair_contract"]
    assert plan["access"]["oci_run_command_ready"] is False
    assert plan["access"]["oci_run_command_availability"] == "not_available_for_image"
    assert plan["access"]["available_plugin_names"] == [
        "Bastion",
        "Compute Instance Monitoring",
        "Vulnerability Scanning",
    ]
    assert repair["run_command_availability"] == "not_available_for_image"
    assert repair["allowed_repairs"] == [
        {
            "id": "install_fusekit_host_ssh_deploy_key",
            "label": (
                "Install the approved SSH deploy key only for the fusekit host user on "
                "the FuseKit-tagged launcher."
            ),
            "scope": "single_fusekit_host_user",
            "current_status": "permission_denied",
        },
        {
            "id": "replace_with_supported_amd_fusekit_host",
            "label": (
                "Plan a replacement FuseKit-tagged AMD hosted launcher image that "
                "supports OCI Run Command before moving traffic."
            ),
            "scope": "single_fusekit_tagged_oci_instance",
            "current_status": "not_available_for_image",
        },
    ]
    assert "plan a replacement FuseKit-tagged AMD hosted launcher image" in (
        plan["access"]["next_actions"][0]
    )
    assert "enable_oci_run_command_for_fusekit_host" not in json.dumps(repair)


def test_hosted_oci_access_plan_allows_redeploy_when_ssh_ready() -> None:
    plan = build_hosted_oci_access_plan(
        instance=_instance(),
        vnic=_vnic(),
        plugins=[],
        hosted_verify_report=_hosted_verify(),
        ssh_probe_status="ok",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert plan["ready_to_redeploy"] is True
    assert plan["access"]["allowed_deploy_paths"] == ["ssh_release"]


def test_hosted_oci_access_plan_blocks_wrong_target_and_arm_shape() -> None:
    plan = build_hosted_oci_access_plan(
        instance=_instance(
            **{
                "lifecycle-state": "STOPPED",
                "shape": "VM.Standard.A1.Flex",
                "freeform-tags": {"Application": "Other"},
            }
        ),
        vnic=_vnic(**{"public-ip": ""}),
        hosted_verify_report={},
        ssh_probe_status="timeout",
    )

    assert plan["ready_to_redeploy"] is False
    assert plan["blockers"] == [
        "oci_instance_tags_not_fusekit_hosted_launcher",
        "oci_instance_not_running",
        "oci_instance_shape_must_be_amd_x86_64",
        "oci_public_ip_missing",
        "hosted_verify_not_ready",
        "oci_deploy_access_unavailable",
    ]


def test_hosted_oci_access_plan_cli_reads_wrapped_oci_exports(tmp_path, capfd) -> None:
    instance_path = tmp_path / "instance.json"
    vnic_path = tmp_path / "vnic.json"
    plugins_path = tmp_path / "plugins.json"
    available_plugins_path = tmp_path / "available-plugins.json"
    hosted_verify_path = tmp_path / "hosted-verify.json"
    instance_path.write_text(json.dumps({"data": _instance()}), encoding="utf-8")
    vnic_path.write_text(json.dumps({"data": _vnic()}), encoding="utf-8")
    plugins_path.write_text(
        json.dumps({"data": [{"name": "Compute Instance Run Command", "status": "RUNNING"}]}),
        encoding="utf-8",
    )
    available_plugins_path.write_text(
        json.dumps({"data": [{"name": "Compute Instance Run Command"}]}),
        encoding="utf-8",
    )
    hosted_verify_path.write_text(json.dumps(_hosted_verify()), encoding="utf-8")

    exit_code = main(
        [
            "--instance-json",
            str(instance_path),
            "--vnic-json",
            str(vnic_path),
            "--plugins-json",
            str(plugins_path),
            "--available-plugins-json",
            str(available_plugins_path),
            "--hosted-verify-report",
            str(hosted_verify_path),
            "--ssh-probe-status",
            "not_checked",
            "--expected-commit-sha",
            EXPECTED_COMMIT,
        ]
    )
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 0
    assert output["ready_to_redeploy"] is True
    assert output["access"]["allowed_deploy_paths"] == ["oci_run_command_release"]
    assert output["access"]["oci_run_command_availability"] == "running"
