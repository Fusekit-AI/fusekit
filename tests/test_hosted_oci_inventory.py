from __future__ import annotations

import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.oci_inventory import (
    HOSTED_OCI_INVENTORY_SCHEMA_VERSION,
    build_hosted_oci_inventory_report,
    collect_hosted_oci_inventory,
    main,
)
from fusekit.security import contains_durable_secret_text

INSTANCE_ID = "ocid1.instance.oc1.phx.anyhqljt5tdfylacdjqchfkhnj22hvpbrfhcx5stmk6ahxe5h6cyvhpsxojq"
VNIC_ID = "ocid1.vnic.oc1.phx.secretvnicidentifier"
TENANCY_ID = "ocid1.tenancy.oc1..rawtenancyidentifier"
COMPARTMENT_ID = "ocid1.compartment.oc1..rawcompartmentidentifier"
IMAGE_ID = "ocid1.image.oc1.phx.rawimageidentifier"
EXPECTED_COMMIT = "b7c0fd4c6d4745f9411c07ad20d707240bc1e46a"


def _instance(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": INSTANCE_ID,
        "display-name": "fusekit-hosted-launcher-amd",
        "lifecycle-state": "RUNNING",
        "shape": "VM.Standard.E2.1.Micro",
        "freeform-tags": {
            "Application": "FuseKit",
            "Architecture": "amd64",
            "Customer": "should-not-emit",
            "DataBoundary": "fusekit-public-launcher",
            "Environment": "production",
            "ManagedBy": "FuseKit",
            "PiiData": "false",
            "Role": "hosted-launcher",
        },
    }
    value.update(overrides)
    return value


def _hosted_verify() -> dict[str, object]:
    return {
        "public_origin": "https://fusekit.snowmanai.org",
        "ready": True,
        "source_provenance": {"actual": {"commit_sha": EXPECTED_COMMIT}},
    }


def test_hosted_oci_inventory_builds_redacted_access_plan() -> None:
    report = build_hosted_oci_inventory_report(
        target_match_count=1,
        compartments_scanned=3,
        instance=_instance(),
        vnic={"id": VNIC_ID, "public-ip": "129.153.118.11"},
        image={
            "id": "ocid1.image.oc1.phx.secretimageidentifier",
            "display-name": "Canonical-Ubuntu-24.04-Minimal",
            "operating-system": "Canonical Ubuntu",
            "operating-system-version": "24.04",
        },
        plugins=[{"name": "Compute Instance Run Command", "status": "RUNNING"}],
        available_plugins=[
            {"name": "Compute Instance Run Command"},
            {"name": "Vulnerability Scanning"},
        ],
        hosted_verify_report=_hosted_verify(),
        ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    serialized = json.dumps(report, sort_keys=True)
    assert report["schema_version"] == HOSTED_OCI_INVENTORY_SCHEMA_VERSION
    assert report["mode"] == "oci_sdk_read_only_inventory"
    assert report["mutates_oci"] is False
    assert report["mutates_host"] is False
    assert report["ready"] is True
    assert report["inventory_ready"] is True
    assert report["target_match_count"] == 1
    assert report["inventory_scope"] == {
        "scans_running_instances": True,
        "running_instances_seen": 1,
        "target_match_count": 1,
        "non_target_running_instances_seen": 0,
        "target_selector": {
            "Application": "FuseKit",
            "DataBoundary": "fusekit-public-launcher",
            "Environment": "production",
            "ManagedBy": "FuseKit",
            "PiiData": "false",
            "Role": "hosted-launcher",
        },
        "uniqueness_required": True,
        "cost_visibility": (
            "Inventory exposes running-instance counts only. Non-target running "
            "instances are not stopped, deleted, or remediated by this read-only "
            "collector and should be reviewed separately before broad cost claims."
        ),
    }
    assert report["compartments_scanned"] == 3
    assert report["collection_failures"] == []
    assert report["target"]["instance"]["freeform-tags"] == {
        "Application": "FuseKit",
        "DataBoundary": "fusekit-public-launcher",
        "Environment": "production",
        "ManagedBy": "FuseKit",
        "PiiData": "false",
        "Role": "hosted-launcher",
    }
    assert report["access_plan"]["ready_to_redeploy"] is True
    assert report["access_plan"]["access"]["allowed_deploy_paths"] == [
        "oci_run_command_release"
    ]
    assert INSTANCE_ID not in serialized
    assert VNIC_ID not in serialized
    assert "ocid1.instance.<redacted:" in serialized
    assert "should-not-emit" not in serialized
    assert "fingerprint" not in serialized.lower()
    assert not contains_durable_secret_text(serialized)


def test_hosted_oci_inventory_reports_non_target_running_instance_counts() -> None:
    report = build_hosted_oci_inventory_report(
        target_match_count=1,
        running_instance_count=3,
        instance=_instance(),
        vnic={"public-ip": "129.153.118.11"},
        image={
            "display-name": "Canonical-Ubuntu-24.04-Minimal",
            "operating-system": "Canonical Ubuntu",
            "operating-system-version": "24.04",
        },
        plugins=[{"name": "Compute Instance Run Command", "status": "RUNNING"}],
        available_plugins=[{"name": "Compute Instance Run Command"}],
        hosted_verify_report=_hosted_verify(),
        ssh_probe_status="permission_denied",
        expected_commit_sha=EXPECTED_COMMIT,
    )

    assert report["ready"] is True
    assert report["inventory_scope"]["running_instances_seen"] == 3
    assert report["inventory_scope"]["non_target_running_instances_seen"] == 2
    assert "not stopped, deleted, or remediated" in report["inventory_scope"][
        "cost_visibility"
    ]


def test_hosted_oci_inventory_reports_ambiguous_target_without_details() -> None:
    report = build_hosted_oci_inventory_report(
        target_match_count=2,
        compartments_scanned=4,
        collection_failures=[],
    )

    assert report["ready"] is False
    assert report["inventory_ready"] is False
    assert report["blockers"] == ["oci_hosted_launcher_target_not_unique"]
    assert report["access_plan"] == {}


def test_hosted_oci_inventory_blocks_raw_nonpublic_oci_identifiers() -> None:
    with pytest.raises(FuseKitError, match="hosted_oci_inventory_contains_nonpublic_identifier"):
        build_hosted_oci_inventory_report(
            target_match_count=1,
            instance=_instance(),
            vnic={"public-ip": "129.153.118.11"},
            plugins=[],
            available_plugins=[],
            image={"display-name": "ocid1.tenancy.oc1..do-not-emit"},
            hosted_verify_report=_hosted_verify(),
            ssh_probe_status="ok",
            expected_commit_sha=EXPECTED_COMMIT,
        )


def test_hosted_oci_inventory_cli_requires_config_before_collection(capfd) -> None:
    exit_code = main(["--config-file", "/definitely/not/a/config"])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 2
    assert output["ready"] is False
    assert output["error"] == "oci_config_unreadable"
    assert "secret_boundary" in output


def test_hosted_oci_inventory_uses_raw_ocids_only_inside_sdk_calls(monkeypatch) -> None:
    fake_oci = _FakeOci()
    monkeypatch.setattr("fusekit.hosted.oci_inventory._load_oci_sdk", lambda: fake_oci)
    monkeypatch.setattr(
        "fusekit.hosted.oci_inventory._load_oci_config",
        lambda _oci, *, config_file, profile: {"tenancy": TENANCY_ID},
    )

    report = collect_hosted_oci_inventory(
        hosted_verify_report=_hosted_verify(),
        ssh_probe_status="ok",
        expected_commit_sha=EXPECTED_COMMIT,
    )
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is True
    assert report["target_match_count"] == 1
    assert report["inventory_scope"]["running_instances_seen"] == 1
    assert report["inventory_scope"]["non_target_running_instances_seen"] == 0
    assert report["access_plan"]["access"]["allowed_deploy_paths"] == ["ssh_release"]
    assert TENANCY_ID not in serialized
    assert COMPARTMENT_ID not in serialized
    assert VNIC_ID not in serialized
    assert IMAGE_ID not in serialized
    assert INSTANCE_ID not in serialized
    assert fake_oci.raw_inputs_seen == {
        TENANCY_ID,
        COMPARTMENT_ID,
        INSTANCE_ID,
        VNIC_ID,
        IMAGE_ID,
    }


class _FakeResponse:
    def __init__(self, data: object) -> None:
        self.data = data


class _FakeModel:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class _FakePagination:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def list_call_get_all_results(
        self,
        method: object,
        *args: object,
        **kwargs: object,
    ) -> _FakeResponse:
        for value in [*args, *kwargs.values()]:
            if isinstance(value, str) and value.startswith("ocid1."):
                assert "<redacted:" not in value
                self._raw_inputs_seen.add(value)
        return method(*args, **kwargs)


class _FakeIdentityNamespace:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def IdentityClient(self, _config: object) -> _FakeIdentityClient:
        return _FakeIdentityClient(self._raw_inputs_seen)


class _FakeCoreNamespace:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def ComputeClient(self, _config: object) -> _FakeComputeClient:
        return _FakeComputeClient(self._raw_inputs_seen)

    def VirtualNetworkClient(self, _config: object) -> _FakeNetworkClient:
        return _FakeNetworkClient(self._raw_inputs_seen)


class _FakeAgentNamespace:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def PluginClient(self, _config: object) -> _FakePluginClient:
        return _FakePluginClient(self._raw_inputs_seen)

    def PluginconfigClient(self, _config: object) -> _FakePluginConfigClient:
        return _FakePluginConfigClient(self._raw_inputs_seen)


class _FakeOci:
    def __init__(self) -> None:
        self.raw_inputs_seen: set[str] = set()
        self.pagination = _FakePagination(self.raw_inputs_seen)
        self.identity = _FakeIdentityNamespace(self.raw_inputs_seen)
        self.core = _FakeCoreNamespace(self.raw_inputs_seen)
        self.compute_instance_agent = _FakeAgentNamespace(self.raw_inputs_seen)


class _FakeIdentityClient:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def list_compartments(self, compartment_id: str, **_kwargs: object) -> _FakeResponse:
        assert compartment_id == TENANCY_ID
        self._raw_inputs_seen.add(compartment_id)
        return _FakeResponse([_FakeModel(id=COMPARTMENT_ID)])


class _FakeComputeClient:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def list_instances(self, compartment_id: str, **_kwargs: object) -> _FakeResponse:
        assert compartment_id in {TENANCY_ID, COMPARTMENT_ID}
        self._raw_inputs_seen.add(compartment_id)
        if compartment_id == TENANCY_ID:
            return _FakeResponse([])
        return _FakeResponse(
            [
                _FakeModel(
                    id=INSTANCE_ID,
                    display_name="fusekit-hosted-launcher-amd",
                    lifecycle_state="RUNNING",
                    shape="VM.Standard.E2.1.Micro",
                    freeform_tags=_instance()["freeform-tags"],
                    image_id=IMAGE_ID,
                )
            ]
        )

    def list_vnic_attachments(
        self,
        compartment_id: str,
        *,
        instance_id: str,
        **_kwargs: object,
    ) -> _FakeResponse:
        assert compartment_id == COMPARTMENT_ID
        assert instance_id == INSTANCE_ID
        self._raw_inputs_seen.update({compartment_id, instance_id})
        return _FakeResponse([_FakeModel(vnic_id=VNIC_ID)])

    def get_image(self, image_id: str) -> _FakeResponse:
        assert image_id == IMAGE_ID
        self._raw_inputs_seen.add(image_id)
        return _FakeResponse(
            _FakeModel(
                display_name="Canonical-Ubuntu-24.04-Minimal",
                operating_system="Canonical Ubuntu",
                operating_system_version="24.04",
            )
        )


class _FakeNetworkClient:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def get_vnic(self, vnic_id: str) -> _FakeResponse:
        assert vnic_id == VNIC_ID
        self._raw_inputs_seen.add(vnic_id)
        return _FakeResponse(_FakeModel(public_ip="129.153.118.11", is_primary=True))


class _FakePluginClient:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def list_instance_agent_plugins(
        self,
        compartment_id: str,
        instanceagent_id: str,
        **_kwargs: object,
    ) -> _FakeResponse:
        assert compartment_id == COMPARTMENT_ID
        assert instanceagent_id == INSTANCE_ID
        self._raw_inputs_seen.update({compartment_id, instanceagent_id})
        return _FakeResponse([_FakeModel(name="Vulnerability Scanning", status="STOPPED")])


class _FakePluginConfigClient:
    def __init__(self, raw_inputs_seen: set[str]) -> None:
        self._raw_inputs_seen = raw_inputs_seen

    def list_instanceagent_available_plugins(
        self,
        compartment_id: str,
        os_name: str,
        os_version: str,
        **_kwargs: object,
    ) -> _FakeResponse:
        assert compartment_id == COMPARTMENT_ID
        assert os_name == "Canonical Ubuntu"
        assert os_version == "24.04"
        self._raw_inputs_seen.add(compartment_id)
        return _FakeResponse([_FakeModel(name="Vulnerability Scanning")])
