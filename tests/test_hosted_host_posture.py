from __future__ import annotations

import json
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from fusekit.hosted.host_posture import (
    OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION,
    OCI_HOST_POSTURE_MAX_JSON_BYTES,
    OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION,
    CommandResult,
    collect_oci_host_posture_evidence,
    evaluate_oci_host_posture,
    main,
)
from fusekit.security import contains_durable_secret_text


def _clean_evidence() -> dict[str, object]:
    return {
        "schema_version": OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION,
        "architecture": "x86_64",
        "shape": "VM.Standard.E5.Flex",
        "running_services": [
            "nginx",
            "fusekit-hosted",
            "fusekit-worker-dispatch",
            "ssh",
        ],
        "public_ports": [80, 443],
        "ssh_ingress": "restricted",
        "runtime_secret_dir": {
            "path": "/etc/fusekit",
            "owner": "root",
            "group": "root",
            "mode": "0750",
        },
        "runtime_secret_file": {
            "path": "/etc/fusekit/hosted-secrets.env",
            "owner": "root",
            "group": "root",
            "mode": "0600",
        },
        "patch_posture": {
            "pending_security_updates": 0,
            "reboot_required": False,
        },
        "cis_baseline": {
            "scanner": "lynis",
            "status": "pass",
            "critical_findings": 0,
            "high_findings": 0,
        },
        "rootkit_scan": {
            "scanner": "rkhunter",
            "status": "pass",
        },
        "systemd_units": {
            "fusekit-hosted": {
                "user": "fusekit",
                "umask": "0077",
                "no_new_privileges": True,
                "private_tmp": True,
                "protect_system": "full",
                "protect_home": True,
                "private_devices": True,
                "restrict_suid_sgid": True,
                "lock_personality": True,
                "system_call_architectures": "native",
                "protect_kernel_tunables": True,
                "protect_kernel_modules": True,
                "protect_kernel_logs": True,
                "protect_control_groups": True,
                "restrict_namespaces": True,
                "restrict_realtime": True,
                "memory_deny_write_execute": True,
                "capability_bounding_set": "",
                "ambient_capabilities": "",
                "restrict_address_families": ["AF_UNIX", "AF_INET", "AF_INET6"],
                "state_directory": ["fusekit"],
                "state_directory_mode": "0750",
                "logs_directory": ["fusekit"],
                "logs_directory_mode": "0750",
                "runtime_directory": ["fusekit"],
                "runtime_directory_mode": "0750",
                "read_write_paths": [
                    "/var/lib/fusekit",
                    "/var/log/fusekit",
                    "/run/fusekit",
                ],
                "environment": [
                    "FUSEKIT_HOSTED_BIND=127.0.0.1",
                    "FUSEKIT_HOSTED_PORT=8080",
                ],
                "exec_start": "/opt/fusekit/venv/bin/fusekit-hosted",
            },
            "fusekit-worker-dispatch": {
                "user": "fusekit",
                "umask": "0077",
                "no_new_privileges": True,
                "private_tmp": True,
                "protect_system": "strict",
                "protect_home": True,
                "private_devices": True,
                "restrict_suid_sgid": True,
                "lock_personality": True,
                "system_call_architectures": "native",
                "protect_kernel_tunables": True,
                "protect_kernel_modules": True,
                "protect_kernel_logs": True,
                "protect_control_groups": True,
                "restrict_namespaces": True,
                "restrict_realtime": True,
                "memory_deny_write_execute": True,
                "capability_bounding_set": "",
                "ambient_capabilities": "",
                "restrict_address_families": ["AF_UNIX", "AF_INET", "AF_INET6"],
                "state_directory": ["fusekit"],
                "state_directory_mode": "0750",
                "logs_directory": ["fusekit"],
                "logs_directory_mode": "0750",
                "runtime_directory": ["fusekit"],
                "runtime_directory_mode": "0750",
                "read_write_paths": [
                    "/var/lib/fusekit",
                    "/var/log/fusekit",
                    "/run/fusekit",
                ],
                "environment": [
                    "FUSEKIT_HOSTED_WORKER_ID=hosted-worker-dispatch",
                    "FUSEKIT_HOSTED_WORKER_WORKSPACE=/var/lib/fusekit/worker",
                    "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR=/var/lib/fusekit/dispatch-state",
                ],
                "exec_start": (
                    "/opt/fusekit/venv/bin/fusekit-hosted-worker-dispatch "
                    "--host 127.0.0.1 --port 8766"
                ),
            },
        },
        "hosted_verify": {
            "public_origin": "https://fusekit.snowmanai.org",
            "ready": True,
        },
        "dns_propagation": {
            "public_origin": "https://fusekit.snowmanai.org",
            "domain": "fusekit.snowmanai.org",
            "status": "propagated",
            "propagated": True,
        },
        "rollback_metadata": {
            "rollback": [
                {
                    "action": "rollback.cloudflare.dns",
                    "status": "planned",
                    "target": "fusekit.snowmanai.org",
                }
            ]
        },
        "collection": {
            "mode": "read_only_local_host",
            "mutates_oci": False,
            "mutates_host": False,
            "secret_boundary": (
                "Collector records posture facts only. It does not read secret file "
                "contents or request OCI credentials."
            ),
        },
    }


def _check(report: dict[str, object], check_id: str) -> dict[str, object]:
    checks = report["checks"]
    assert isinstance(checks, list)
    check = next(item for item in checks if item["id"] == check_id)
    assert isinstance(check, dict)
    return check


def test_oci_host_posture_accepts_redacted_amd_hardened_host_evidence() -> None:
    report = evaluate_oci_host_posture(_clean_evidence())

    assert report["schema_version"] == OCI_HOST_POSTURE_REPORT_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blocking_checks"] == []
    assert "OCI credentials" in report["public_summary"]["secret_boundary"]
    assert not contains_durable_secret_text(json.dumps(report))


def test_oci_host_posture_blocks_unknown_top_level_evidence_fields() -> None:
    evidence = _clean_evidence()
    evidence["raw_audit_excerpt"] = "public-looking log line that does not belong"

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["evidence.shape"]
    shape_check = _check(report, "evidence.shape")
    assert shape_check["failures"] == [
        "oci_host_posture_evidence_has_unknown_fields"
    ]
    assert shape_check["unexpected_fields"] == ["raw_audit_excerpt"]


def test_oci_host_posture_blocks_unknown_nested_secret_metadata_fields() -> None:
    evidence = _clean_evidence()
    runtime_secret_file = evidence["runtime_secret_file"]
    assert isinstance(runtime_secret_file, dict)
    runtime_secret_file["raw_stat_output"] = "root root 600 /etc/fusekit/hosted-secrets.env"

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["evidence.shape"]
    shape_check = _check(report, "evidence.shape")
    assert shape_check["failures"] == [
        "oci_host_posture_evidence_has_unknown_fields"
    ]
    assert shape_check["unexpected_fields"] == ["runtime_secret_file.raw_stat_output"]


def test_oci_host_posture_blocks_unknown_nested_systemd_fields() -> None:
    evidence = _clean_evidence()
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    hosted_unit = systemd_units["fusekit-hosted"]
    assert isinstance(hosted_unit, dict)
    hosted_unit["raw_systemctl_show"] = "Environment=FUSEKIT_HOSTED_SECRET=redacted"
    systemd_units["debug-helper"] = {"user": "fusekit"}

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["evidence.shape"]
    shape_check = _check(report, "evidence.shape")
    assert shape_check["failures"] == [
        "oci_host_posture_evidence_has_unknown_fields"
    ]
    assert shape_check["unexpected_fields"] == [
        "systemd_units.debug-helper",
        "systemd_units.fusekit-hosted.raw_systemctl_show",
    ]


def test_oci_host_posture_blocks_arm_public_ssh_and_weak_systemd() -> None:
    evidence = _clean_evidence()
    evidence["architecture"] = "aarch64"
    evidence["shape"] = "VM.Standard.A1.Flex"
    evidence["public_ports"] = [22, 80, 443]
    evidence["ssh_ingress"] = "0.0.0.0/0"
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    systemd_units["fusekit-hosted"] = {
        "user": "root",
        "no_new_privileges": False,
        "private_tmp": False,
        "protect_system": "no",
        "read_write_paths": ["/"],
    }

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == [
        "host.architecture",
        "host.public_ports",
        "host.systemd_units",
    ]
    assert _check(report, "host.architecture")["failures"] == [
        "oci_host_architecture_must_be_amd_x86_64",
        "oci_host_shape_must_not_be_arm",
    ]


def test_oci_host_posture_allows_restricted_operator_ssh() -> None:
    evidence = _clean_evidence()
    evidence["public_ports"] = [22, 80, 443]
    evidence["ssh_ingress"] = "operator-only"

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is True
    public_ports = _check(report, "host.public_ports")
    assert public_ports["public_ports"] == [22, 80, 443]
    assert public_ports["ssh_ingress"] == "operator-only"


def test_oci_host_posture_blocks_missing_extended_systemd_sandboxing() -> None:
    evidence = _clean_evidence()
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    systemd_units["fusekit-hosted"] = {
        "user": "fusekit",
        "umask": "0022",
        "no_new_privileges": True,
        "private_tmp": True,
        "protect_system": "full",
        "protect_home": False,
        "private_devices": False,
        "restrict_suid_sgid": False,
        "lock_personality": False,
        "system_call_architectures": "",
        "protect_kernel_tunables": False,
        "protect_kernel_modules": False,
        "protect_kernel_logs": False,
        "protect_control_groups": False,
        "restrict_namespaces": False,
        "restrict_realtime": False,
        "memory_deny_write_execute": False,
        "capability_bounding_set": "CAP_NET_ADMIN",
        "ambient_capabilities": "CAP_NET_BIND_SERVICE",
        "restrict_address_families": ["AF_UNIX", "AF_INET", "AF_INET6", "AF_PACKET"],
        "state_directory": [],
        "state_directory_mode": "0755",
        "logs_directory": [],
        "logs_directory_mode": "0755",
        "runtime_directory": [],
        "runtime_directory_mode": "0755",
        "read_write_paths": ["/var/lib/fusekit"],
    }

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["host.systemd_units"]
    systemd_check = next(
        check for check in report["checks"] if check["id"] == "host.systemd_units"
    )
    assert systemd_check["failures"] == [
        "fusekit-hosted:umask_must_be_0077",
        "fusekit-hosted:protect_home_required",
        "fusekit-hosted:private_devices_required",
        "fusekit-hosted:restrict_suid_sgid_required",
        "fusekit-hosted:lock_personality_required",
        "fusekit-hosted:native_syscall_architecture_required",
        "fusekit-hosted:protect_kernel_tunables_required",
        "fusekit-hosted:protect_kernel_modules_required",
        "fusekit-hosted:protect_kernel_logs_required",
        "fusekit-hosted:protect_control_groups_required",
        "fusekit-hosted:restrict_namespaces_required",
        "fusekit-hosted:restrict_realtime_required",
        "fusekit-hosted:memory_deny_write_execute_required",
        "fusekit-hosted:capability_bounding_set_must_be_empty",
        "fusekit-hosted:ambient_capabilities_must_be_empty",
        "fusekit-hosted:restricted_address_families_required",
        "fusekit-hosted:state_directory_required",
        "fusekit-hosted:state_directory_mode_must_be_0750",
        "fusekit-hosted:logs_directory_required",
        "fusekit-hosted:logs_directory_mode_must_be_0750",
        "fusekit-hosted:runtime_directory_required",
        "fusekit-hosted:runtime_directory_mode_must_be_0750",
        "fusekit-hosted:hosted_bind_must_be_loopback",
        "fusekit-hosted:hosted_port_must_be_internal_8080",
    ]


def test_oci_host_posture_blocks_writable_paths_outside_fusekit_state() -> None:
    evidence = _clean_evidence()
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    hosted_unit = systemd_units["fusekit-hosted"]
    dispatch_unit = systemd_units["fusekit-worker-dispatch"]
    assert isinstance(hosted_unit, dict)
    assert isinstance(dispatch_unit, dict)
    hosted_unit["read_write_paths"] = ["/var/lib/fusekit-worker"]
    dispatch_unit["read_write_paths"] = ["/tmp/fusekit"]

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["host.systemd_units"]
    systemd_check = next(
        check for check in report["checks"] if check["id"] == "host.systemd_units"
    )
    assert systemd_check["failures"] == [
        "fusekit-hosted:writable_paths_must_stay_under_fusekit_state",
        "fusekit-worker-dispatch:writable_paths_must_stay_under_fusekit_state",
    ]


def test_oci_host_posture_blocks_systemd_network_binding_drift() -> None:
    evidence = _clean_evidence()
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    hosted_unit = systemd_units["fusekit-hosted"]
    dispatch_unit = systemd_units["fusekit-worker-dispatch"]
    assert isinstance(hosted_unit, dict)
    assert isinstance(dispatch_unit, dict)
    hosted_unit["environment"] = [
        "FUSEKIT_HOSTED_BIND=0.0.0.0",
        "FUSEKIT_HOSTED_PORT=80",
    ]
    dispatch_unit["exec_start"] = (
        "/opt/fusekit/venv/bin/fusekit-hosted-worker-dispatch "
        "--host 0.0.0.0 --port 80"
    )

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["host.systemd_units"]
    systemd_check = next(
        check for check in report["checks"] if check["id"] == "host.systemd_units"
    )
    assert systemd_check["failures"] == [
        "fusekit-hosted:hosted_bind_must_be_loopback",
        "fusekit-hosted:hosted_port_must_be_internal_8080",
        "fusekit-worker-dispatch:dispatch_host_must_be_loopback",
        "fusekit-worker-dispatch:dispatch_port_must_be_internal_8766",
        "fusekit-worker-dispatch:exec_start_must_not_bind_wildcard",
    ]


def test_oci_host_posture_blocks_raw_secret_text_in_evidence() -> None:
    evidence = _clean_evidence()
    evidence["operator_note"] = "Authorization: Bearer ghp_aaaaaaaaaaaaaaaa"

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert "evidence.redaction" in report["blocking_checks"]
    assert "ghp_aaaaaaaaaaaaaaaa" not in json.dumps(report)


def test_oci_host_posture_blocks_missing_dns_and_rollback_proof() -> None:
    evidence = _clean_evidence()
    evidence["dns_propagation"] = {"domain": "wrong.example.com", "status": "pending"}
    evidence["rollback_metadata"] = {"rollback": [{"action": "note", "status": "skipped"}]}

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == [
        "host.dns_propagation",
        "host.rollback_metadata",
    ]


def test_oci_host_posture_blocks_mutating_collection_boundary() -> None:
    evidence = _clean_evidence()
    evidence["collection"] = {
        "mode": "oci_api_scan",
        "mutates_oci": True,
        "mutates_host": True,
        "secret_boundary": "Collector reads secret file contents during setup.",
    }

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["evidence.collection_boundary"]
    collection_check = next(
        check
        for check in report["checks"]
        if check["id"] == "evidence.collection_boundary"
    )
    assert collection_check["failures"] == [
        "oci_host_posture_collection_must_be_read_only",
        "oci_host_posture_collection_must_not_mutate_oci",
        "oci_host_posture_collection_must_not_mutate_host",
        "oci_host_posture_collection_must_not_read_secret_contents",
        "oci_host_posture_collection_must_not_request_oci_credentials",
    ]


def test_oci_host_posture_blocks_permissive_runtime_secret_dir() -> None:
    evidence = _clean_evidence()
    evidence["runtime_secret_dir"] = {
        "path": "/etc/fusekit",
        "owner": "fusekit",
        "group": "fusekit",
        "mode": "0755",
    }

    report = evaluate_oci_host_posture(evidence)

    assert report["ready"] is False
    assert report["blocking_checks"] == ["host.runtime_secret_dir"]
    directory_check = next(
        check for check in report["checks"] if check["id"] == "host.runtime_secret_dir"
    )
    assert directory_check["failures"] == [
        "oci_host_secret_dir_must_be_root_owned",
        "oci_host_secret_dir_mode_must_be_0750_or_stricter",
    ]


def test_oci_host_posture_cli_reads_evidence_and_sets_exit_code(tmp_path, capfd) -> None:
    evidence_path = tmp_path / "posture.json"
    evidence_path.write_text(json.dumps(_clean_evidence()), encoding="utf-8")

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 0
    assert output["ready"] is True

    evidence = _clean_evidence()
    evidence["patch_posture"] = {"pending_security_updates": 1, "reboot_required": True}
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["blocking_checks"] == ["host.patch_posture"]


def test_oci_host_posture_module_entrypoint_executes_cli(tmp_path) -> None:
    evidence_path = tmp_path / "posture.json"
    evidence_path.write_text(json.dumps(_clean_evidence()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fusekit.hosted.host_posture",
            "--evidence",
            str(evidence_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    output = json.loads(result.stdout)

    assert result.returncode == 0
    assert output["ready"] is True


def test_oci_host_posture_cli_rejects_symlinked_evidence(tmp_path, capfd) -> None:
    target = tmp_path / "posture.json"
    target.write_text(json.dumps(_clean_evidence()), encoding="utf-8")
    evidence_path = tmp_path / "linked-posture.json"
    evidence_path.symlink_to(target)

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_symlink"


def test_oci_host_posture_cli_rejects_broken_symlinked_evidence(
    tmp_path, capfd
) -> None:
    evidence_path = tmp_path / "linked-posture.json"
    evidence_path.symlink_to(tmp_path / "missing-posture.json")

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_symlink"


def test_oci_host_posture_cli_rejects_evidence_under_symlinked_parent(
    tmp_path, capfd
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    (real_parent / "posture.json").write_text(
        json.dumps(_clean_evidence()), encoding="utf-8"
    )
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    exit_code = main(["--evidence", str(linked_parent / "posture.json")])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_parent_symlink"


def test_oci_host_posture_cli_rejects_directory_evidence(tmp_path, capfd) -> None:
    evidence_path = tmp_path / "posture-dir"
    evidence_path.mkdir()

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_not_file"


def test_oci_host_posture_cli_rejects_oversized_evidence(tmp_path, capfd) -> None:
    evidence_path = tmp_path / "posture.json"
    evidence_path.write_text(" " * (OCI_HOST_POSTURE_MAX_JSON_BYTES + 1), encoding="utf-8")

    exit_code = main(["--evidence", str(evidence_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_too_large"


def test_oci_host_posture_collect_writes_output_without_following_symlink(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr("fusekit.hosted.host_posture.platform.machine", lambda: "x86_64")
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    output_path = tmp_path / "posture.json"

    exit_code = main(["--collect", "--output", str(output_path)])
    captured = capfd.readouterr()
    output = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert captured.out == ""
    assert output["schema_version"] == OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_oci_host_posture_collect_rejects_explicit_missing_attachment(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    missing_report = tmp_path / "missing-hosted-verify.json"

    exit_code = main(["--collect", "--hosted-verify-report", str(missing_report)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_missing"


def test_oci_host_posture_collect_rejects_explicit_symlinked_attachment(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    target = tmp_path / "hosted-verify.json"
    target.write_text(json.dumps({"ready": True}), encoding="utf-8")
    linked_report = tmp_path / "linked-hosted-verify.json"
    linked_report.symlink_to(target)

    exit_code = main(["--collect", "--hosted-verify-report", str(linked_report)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_json_symlink"


def test_oci_host_posture_collect_allows_absent_default_scanner_summaries(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    monkeypatch.setattr(
        "fusekit.hosted.host_posture.OCI_HOST_POSTURE_DEFAULT_CIS_SUMMARY",
        str(tmp_path / "missing-cis-summary.json"),
    )
    monkeypatch.setattr(
        "fusekit.hosted.host_posture.OCI_HOST_POSTURE_DEFAULT_ROOTKIT_SUMMARY",
        str(tmp_path / "missing-rootkit-summary.json"),
    )

    exit_code = main(["--collect"])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 0
    assert output["cis_baseline"] == {}
    assert output["rootkit_scan"] == {}


def test_oci_host_posture_collect_rejects_symlinked_output(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    target = tmp_path / "target.json"
    output_path = tmp_path / "posture.json"
    output_path.symlink_to(target)

    exit_code = main(["--collect", "--output", str(output_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_output_symlink"
    assert not target.exists()


def test_oci_host_posture_collect_rejects_symlinked_output_parent(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output_path = linked_parent / "posture.json"

    exit_code = main(["--collect", "--output", str(output_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_output_parent_symlink"
    assert not (real_parent / "posture.json").exists()


def test_oci_host_posture_collect_rejects_nested_symlinked_output_parent(
    tmp_path, capfd, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fusekit.hosted.host_posture._run_command",
        lambda args: CommandResult(tuple(args), 127, "", "not available"),
    )
    real_parent = tmp_path / "real"
    nested = real_parent / "nested"
    nested.mkdir(parents=True)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output_path = linked_parent / "nested" / "posture.json"

    exit_code = main(["--collect", "--output", str(output_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 1
    assert output["ready"] is False
    assert output["error"] == "posture_output_parent_symlink"
    assert not (nested / "posture.json").exists()


def test_oci_host_posture_collector_builds_validator_ready_redacted_evidence(
    monkeypatch,
) -> None:
    monkeypatch.setattr("fusekit.hosted.host_posture.platform.machine", lambda: "x86_64")

    def runner(args: Sequence[str]) -> CommandResult:
        command = tuple(args)
        if command[:4] == (
            "systemctl",
            "--type=service",
            "--state=running",
            "--no-legend",
        ):
            return CommandResult(
                command,
                0,
                "\n".join(
                    [
                        "nginx.service loaded active running nginx",
                        "fusekit-hosted.service loaded active running hosted",
                        "fusekit-worker-dispatch.service loaded active running worker",
                        "ssh.service loaded active running ssh",
                    ]
                ),
            )
        if command == ("ss", "-H", "-tuln"):
            return CommandResult(
                command,
                0,
                "\n".join(
                    [
                        "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*",
                        "tcp LISTEN 0 511 [::]:443 [::]:*",
                        "tcp LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*",
                        "tcp LISTEN 0 511 [::1]:8766 [::]:*",
                        "tcp LISTEN 0 511 [::ffff:127.0.0.1]:9000 [::]:*",
                        "tcp LISTEN 0 511 localhost:9100 0.0.0.0:*",
                    ]
                ),
            )
        if command[:2] == ("stat", "-c") and command[-1] == "/etc/fusekit":
            return CommandResult(
                command,
                0,
                "root root 750 /etc/fusekit\n",
            )
        if command[:2] == ("stat", "-c") and command[-1] == "/etc/fusekit/hosted-secrets.env":
            return CommandResult(
                command,
                0,
                "root root 600 /etc/fusekit/hosted-secrets.env\n",
            )
        if command == ("apt-get", "-s", "upgrade"):
            return CommandResult(command, 0, "0 upgraded, 0 newly installed\n")
        if command[:2] == ("systemctl", "show"):
            unit_name = command[2]
            unit_specific = (
                [
                    "Environment=FUSEKIT_HOSTED_BIND=127.0.0.1 FUSEKIT_HOSTED_PORT=8080",
                    "ExecStart=/opt/fusekit/venv/bin/fusekit-hosted",
                ]
                if unit_name == "fusekit-hosted.service"
                else [
                    "Environment=FUSEKIT_HOSTED_WORKER_ID=hosted-worker-dispatch",
                    (
                        "ExecStart=/opt/fusekit/venv/bin/fusekit-hosted-worker-dispatch "
                        "--host 127.0.0.1 --port 8766"
                    ),
                ]
            )
            return CommandResult(
                command,
                0,
                "\n".join(
                    [
                        "User=fusekit",
                        "UMask=0077",
                        "NoNewPrivileges=yes",
                        "PrivateTmp=yes",
                        "ProtectSystem=full",
                        "ProtectHome=yes",
                        "PrivateDevices=yes",
                        "RestrictSUIDSGID=yes",
                        "LockPersonality=yes",
                        "SystemCallArchitectures=native",
                        "ProtectKernelTunables=yes",
                        "ProtectKernelModules=yes",
                        "ProtectKernelLogs=yes",
                        "ProtectControlGroups=yes",
                        "RestrictNamespaces=yes",
                        "RestrictRealtime=yes",
                        "MemoryDenyWriteExecute=yes",
                        "CapabilityBoundingSet=",
                        "AmbientCapabilities=",
                        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                        "StateDirectory=fusekit",
                        "StateDirectoryMode=0750",
                        "LogsDirectory=fusekit",
                        "LogsDirectoryMode=0750",
                        "RuntimeDirectory=fusekit",
                        "RuntimeDirectoryMode=0750",
                        "ReadWritePaths=/var/lib/fusekit /var/log/fusekit /run/fusekit",
                        *unit_specific,
                    ]
                ),
            )
        return CommandResult(command, 127, "", "unexpected command")

    evidence = collect_oci_host_posture_evidence(
        shape="VM.Standard.E5.Flex",
        ssh_ingress="restricted",
        hosted_verify_report={
            "public_origin": "https://fusekit.snowmanai.org",
            "ready": True,
        },
        dns_report={
            "public_origin": "https://fusekit.snowmanai.org",
            "status": "ok",
        },
        rollback_metadata={
            "actions": [
                {
                    "action": "cloudflare.dns.rollback",
                    "status": "planned",
                }
            ]
        },
        cis_summary={
            "scanner": "lynis",
            "status": "pass",
            "critical_findings": 0,
            "high_findings": 0,
        },
        rootkit_summary={"scanner": "rkhunter", "status": "pass"},
        command_runner=runner,
        file_exists=lambda path: path == Path("/var/run/reboot-required") and False,
    )
    report = evaluate_oci_host_posture(evidence)

    assert evidence["schema_version"] == OCI_HOST_POSTURE_EVIDENCE_SCHEMA_VERSION
    assert evidence["public_ports"] == [80, 443]
    assert evidence["runtime_secret_dir"] == {
        "path": "/etc/fusekit",
        "owner": "root",
        "group": "root",
        "mode": "0750",
    }
    assert evidence["runtime_secret_file"] == {
        "path": "/etc/fusekit/hosted-secrets.env",
        "owner": "root",
        "group": "root",
        "mode": "0600",
    }
    systemd_units = evidence["systemd_units"]
    assert isinstance(systemd_units, dict)
    hosted_unit = systemd_units["fusekit-hosted"]
    assert isinstance(hosted_unit, dict)
    assert hosted_unit["protect_home"] is True
    assert hosted_unit["private_devices"] is True
    assert hosted_unit["restrict_suid_sgid"] is True
    assert hosted_unit["lock_personality"] is True
    assert hosted_unit["system_call_architectures"] == "native"
    assert hosted_unit["umask"] == "0077"
    assert hosted_unit["protect_kernel_tunables"] is True
    assert hosted_unit["protect_kernel_modules"] is True
    assert hosted_unit["protect_kernel_logs"] is True
    assert hosted_unit["protect_control_groups"] is True
    assert hosted_unit["restrict_namespaces"] is True
    assert hosted_unit["restrict_realtime"] is True
    assert hosted_unit["memory_deny_write_execute"] is True
    assert hosted_unit["capability_bounding_set"] == ""
    assert hosted_unit["ambient_capabilities"] == ""
    assert hosted_unit["restrict_address_families"] == [
        "AF_UNIX",
        "AF_INET",
        "AF_INET6",
    ]
    assert hosted_unit["state_directory"] == ["fusekit"]
    assert hosted_unit["state_directory_mode"] == "0750"
    assert hosted_unit["logs_directory"] == ["fusekit"]
    assert hosted_unit["logs_directory_mode"] == "0750"
    assert hosted_unit["runtime_directory"] == ["fusekit"]
    assert hosted_unit["runtime_directory_mode"] == "0750"
    assert hosted_unit["environment"] == [
        "FUSEKIT_HOSTED_BIND=127.0.0.1",
        "FUSEKIT_HOSTED_PORT=8080",
    ]
    assert hosted_unit["exec_start"] == "/opt/fusekit/venv/bin/fusekit-hosted"
    dispatch_unit = systemd_units["fusekit-worker-dispatch"]
    assert isinstance(dispatch_unit, dict)
    assert dispatch_unit["exec_start"].endswith("--host 127.0.0.1 --port 8766")
    assert evidence["dns_propagation"] == {
        "public_origin": "https://fusekit.snowmanai.org",
        "status": "ok",
    }
    assert evidence["rollback_metadata"] == {
        "actions": [{"action": "cloudflare.dns.rollback", "status": "planned"}]
    }
    assert report["ready"] is True
    assert not contains_durable_secret_text(json.dumps(evidence))


def test_oci_host_posture_collector_counts_non_loopback_listeners(
    monkeypatch,
) -> None:
    monkeypatch.setattr("fusekit.hosted.host_posture.platform.machine", lambda: "x86_64")

    def runner(args: Sequence[str]) -> CommandResult:
        command = tuple(args)
        if command == ("ss", "-H", "-tuln"):
            return CommandResult(
                command,
                0,
                "\n".join(
                    [
                        "tcp LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*",
                        "udp UNCONN 0 0 10.0.0.12:68 0.0.0.0:*",
                        "udp UNCONN 0 0 [fe80::1%ens3]:546 [::]:*",
                        "tcp LISTEN 0 511 10.0.0.12:8443 0.0.0.0:*",
                    ]
                ),
            )
        return CommandResult(command, 127, "", "not available")

    evidence = collect_oci_host_posture_evidence(command_runner=runner)

    assert evidence["public_ports"] == [8443]


def test_oci_host_posture_collector_sanitizes_attached_summaries(monkeypatch) -> None:
    monkeypatch.setattr("fusekit.hosted.host_posture.platform.machine", lambda: "x86_64")
    secret_key = "ghp_aaaaaaaaaaaaaaaa"

    def runner(args: Sequence[str]) -> CommandResult:
        return CommandResult(tuple(args), 127, "", "not available")

    evidence = collect_oci_host_posture_evidence(
        cis_summary={
            "scanner": "lynis",
            "status": "pass",
            "detail": "Authorization: Bearer ghp_aaaaaaaaaaaaaaaa",
            secret_key: {
                "nested": "visible",
                "token_key": {"sk-proj-aaaaaaaaaaaaaaaaaaaa": "nested-key"},
            },
        },
        command_runner=runner,
    )

    assert "ghp_aaaaaaaaaaaaaaaa" not in json.dumps(evidence)
    assert "sk-proj-aaaaaaaaaaaaaaaaaaaa" not in json.dumps(evidence)
    assert not contains_durable_secret_text(json.dumps(evidence))
    assert evidence["cis_baseline"] == {
        "scanner": "lynis",
        "status": "pass",
        "detail": "Authorization: Bearer [redacted]",
        "[redacted]": {
            "nested": "visible",
            "token_key": {"[redacted]": "nested-key"},
        },
    }
