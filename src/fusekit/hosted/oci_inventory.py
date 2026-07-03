"""Read-only OCI inventory collector for the hosted FuseKit launcher."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.oci_access import (
    HOSTED_OCI_ALLOWED_TARGET_TAGS,
    build_hosted_oci_access_plan,
)
from fusekit.security import contains_durable_secret_text, redact_public_text

HOSTED_OCI_INVENTORY_SCHEMA_VERSION = "fusekit.hosted-oci-inventory.v1"
HOSTED_OCI_INVENTORY_MODE = "oci_sdk_read_only_inventory"


def build_hosted_oci_inventory_report(
    *,
    target_match_count: int,
    running_instance_count: int | None = None,
    instance: Mapping[str, object] | None = None,
    vnic: Mapping[str, object] | None = None,
    plugins: Sequence[Mapping[str, object]] = (),
    available_plugins: Sequence[Mapping[str, object]] = (),
    image: Mapping[str, object] | None = None,
    compartments_scanned: int = 0,
    collection_failures: Sequence[Mapping[str, object]] = (),
    hosted_verify_report: Mapping[str, object] | None = None,
    ssh_probe_status: str = "not_checked",
    expected_commit_sha: str = "",
) -> dict[str, object]:
    """Build redacted OCI inventory and optional access-plan evidence."""

    public_instance = _public_instance(instance or {})
    public_vnic = _public_vnic(vnic or {})
    public_plugins = [_public_plugin(plugin) for plugin in plugins]
    public_available_plugins = [_public_available_plugin(plugin) for plugin in available_plugins]
    running_instances_seen = max(
        target_match_count if running_instance_count is None else running_instance_count,
        0,
    )
    inventory_blockers = _inventory_blockers(
        target_match_count=target_match_count,
        instance=public_instance,
    )
    access_plan: dict[str, object] = {}
    if not inventory_blockers:
        access_plan = build_hosted_oci_access_plan(
            instance=public_instance,
            vnic=public_vnic,
            plugins=public_plugins,
            available_plugins=public_available_plugins,
            hosted_verify_report=hosted_verify_report,
            ssh_probe_status=ssh_probe_status,
            expected_commit_sha=expected_commit_sha,
        )
    report = {
        "schema_version": HOSTED_OCI_INVENTORY_SCHEMA_VERSION,
        "mode": HOSTED_OCI_INVENTORY_MODE,
        "mutates_oci": False,
        "mutates_host": False,
        "ready": not inventory_blockers
        and not collection_failures
        and not access_plan.get("blockers", []),
        "inventory_ready": not inventory_blockers,
        "blockers": inventory_blockers,
        "target_match_count": target_match_count,
        "inventory_scope": {
            "scans_running_instances": True,
            "running_instances_seen": running_instances_seen,
            "target_match_count": target_match_count,
            "non_target_running_instances_seen": max(
                running_instances_seen - target_match_count,
                0,
            ),
            "target_selector": dict(HOSTED_OCI_ALLOWED_TARGET_TAGS),
            "uniqueness_required": True,
            "cost_visibility": (
                "Inventory exposes running-instance counts only. Non-target running "
                "instances are not stopped, deleted, or remediated by this read-only "
                "collector and should be reviewed separately before broad cost claims."
            ),
        },
        "compartments_scanned": max(compartments_scanned, 0),
        "collection_failures": [_public_collection_failure(item) for item in collection_failures],
        "target": {
            "instance": public_instance,
            "vnic": public_vnic,
            "image": _public_image(image or {}),
        },
        "agent": {
            "plugins": public_plugins,
            "available_plugins": public_available_plugins,
        },
        "access_plan_inputs": {
            "instance": public_instance,
            "vnic": public_vnic,
            "plugins": public_plugins,
            "available_plugins": public_available_plugins,
        },
        "access_plan": access_plan,
        "collection_boundary": {
            "scope": "single_fusekit_tagged_oci_host_inventory",
            "api_mode": "read_only",
            "allowed_reads": [
                "identity.list_compartments",
                "core.list_instances",
                "core.list_vnic_attachments",
                "core.get_vnic",
                "core.get_image",
                "compute_instance_agent.list_instance_agent_plugins",
                "compute_instance_agent.list_instanceagent_available_plugins",
            ],
            "forbidden_mutations": [
                "create_update_or_delete_oci_resources",
                "change_cloudflare_dns",
                "change_billing_or_stripe_objects",
                "read_or_emit_secret_values",
                "open_ssh_sessions_or_run_host_commands",
            ],
        },
        "secret_boundary": (
            "The collector reads OCI SDK configuration only for OCI API authentication. "
            "It never emits OCI API keys, credential metadata, tenancy or user OCIDs, SSH "
            "keys, provider credentials, Stripe secrets, GitHub App private keys, or vault "
            "material."
        ),
    }
    _assert_public_inventory(report)
    return report


def collect_hosted_oci_inventory(
    *,
    config_file: str = "",
    profile: str = "DEFAULT",
    compartment_id: str = "",
    include_subcompartments: bool = True,
    hosted_verify_report: Mapping[str, object] | None = None,
    ssh_probe_status: str = "not_checked",
    expected_commit_sha: str = "",
) -> dict[str, object]:
    """Collect a redacted hosted launcher inventory from OCI SDK read APIs."""

    oci = _load_oci_sdk()
    config = _load_oci_config(oci, config_file=config_file, profile=profile)
    tenancy_id = _raw_str(config.get("tenancy"))
    root_compartment = compartment_id.strip() or tenancy_id
    if not root_compartment:
        raise FuseKitError("oci_inventory_tenancy_or_compartment_required")
    identity = oci.identity.IdentityClient(config)
    compute = oci.core.ComputeClient(config)
    network = oci.core.VirtualNetworkClient(config)
    plugin_client = oci.compute_instance_agent.PluginClient(config)
    pluginconfig_client = oci.compute_instance_agent.PluginconfigClient(config)
    failures: list[dict[str, object]] = []
    compartments = _collect_compartment_ids(
        oci,
        identity,
        root_compartment=root_compartment,
        include_subcompartments=include_subcompartments,
        failures=failures,
    )
    matches: list[dict[str, object]] = []
    running_instance_count = 0
    for candidate_compartment_id in compartments:
        for instance in _list_instances(
            oci,
            compute,
            compartment_id=candidate_compartment_id,
            failures=failures,
        ):
            running_instance_count += 1
            if _target_tags_match(_model_value(instance, "freeform_tags")):
                matches.append(
                    {
                        "compartment_id": candidate_compartment_id,
                        "instance": instance,
                    }
                )
    selected = matches[0] if len(matches) == 1 else {}
    instance_model = selected.get("instance")
    selected_compartment = _raw_str(selected.get("compartment_id"))
    instance = _instance_mapping(instance_model) if instance_model is not None else {}
    vnic = (
        _collect_public_vnic(
            oci,
            compute,
            network,
            compartment_id=selected_compartment,
            instance_id=_raw_str(instance.get("id")),
            failures=failures,
        )
        if instance
        else {}
    )
    image = (
        _collect_image(
            compute,
            image_id=_raw_str(_model_value(instance_model, "image_id")),
            failures=failures,
        )
        if instance_model is not None
        else {}
    )
    plugins = (
        _collect_instance_agent_plugins(
            oci,
            plugin_client,
            compartment_id=selected_compartment,
            instance_id=_raw_str(instance.get("id")),
            failures=failures,
        )
        if instance
        else []
    )
    available_plugins = (
        _collect_available_plugins(
            oci,
            pluginconfig_client,
            compartment_id=selected_compartment,
            image=image,
            failures=failures,
        )
        if image
        else []
    )
    return build_hosted_oci_inventory_report(
        target_match_count=len(matches),
        running_instance_count=running_instance_count,
        instance=instance,
        vnic=vnic,
        plugins=plugins,
        available_plugins=available_plugins,
        image=image,
        compartments_scanned=len(compartments),
        collection_failures=failures,
        hosted_verify_report=hosted_verify_report,
        ssh_probe_status=ssh_probe_status,
        expected_commit_sha=expected_commit_sha,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Collect redacted read-only OCI inventory for the hosted launcher."""

    parser = argparse.ArgumentParser(
        description="Collect redacted read-only OCI inventory for the FuseKit hosted launcher."
    )
    parser.add_argument("--config-file", default="")
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--compartment-id", default="")
    parser.add_argument(
        "--root-compartment-only",
        action="store_true",
        help="Do not scan active child compartments.",
    )
    parser.add_argument("--hosted-verify-report", default="")
    parser.add_argument("--ssh-probe-status", default="not_checked")
    parser.add_argument("--expected-commit-sha", default="")
    args = parser.parse_args(argv)
    try:
        report = collect_hosted_oci_inventory(
            config_file=args.config_file,
            profile=args.profile,
            compartment_id=args.compartment_id,
            include_subcompartments=not args.root_compartment_only,
            hosted_verify_report=_read_optional_mapping(args.hosted_verify_report),
            ssh_probe_status=args.ssh_probe_status,
            expected_commit_sha=args.expected_commit_sha,
        )
    except FuseKitError as exc:
        report = {
            "schema_version": HOSTED_OCI_INVENTORY_SCHEMA_VERSION,
            "mode": HOSTED_OCI_INVENTORY_MODE,
            "ready": False,
            "mutates_oci": False,
            "mutates_host": False,
            "error": str(exc),
            "secret_boundary": (
                "OCI SDK credentials and local config details are never emitted in "
                "inventory output."
            ),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ready") is True else 2


def _load_oci_sdk() -> Any:
    try:
        import oci
        import oci.compute_instance_agent  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on local optional install
        raise FuseKitError("oci_sdk_not_available") from exc
    return oci


def _load_oci_config(oci: Any, *, config_file: str, profile: str) -> Mapping[str, object]:
    try:
        if config_file:
            config = oci.config.from_file(file_location=config_file, profile_name=profile)
        else:
            config = oci.config.from_file(profile_name=profile)
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        raise FuseKitError("oci_config_unreadable") from exc
    if not isinstance(config, Mapping):
        raise FuseKitError("oci_config_invalid")
    return config


def _collect_compartment_ids(
    oci: Any,
    identity: Any,
    *,
    root_compartment: str,
    include_subcompartments: bool,
    failures: list[dict[str, object]],
) -> list[str]:
    compartments = [root_compartment]
    if not include_subcompartments:
        return compartments
    try:
        response = _sdk_list(
            oci,
            identity.list_compartments,
            root_compartment,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
            lifecycle_state="ACTIVE",
        )
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(_sdk_failure("identity.list_compartments", exc))
        return compartments
    for compartment in response:
        compartment_id = _raw_str(_model_value(compartment, "id"))
        if compartment_id and compartment_id not in compartments:
            compartments.append(compartment_id)
    return compartments


def _list_instances(
    oci: Any,
    compute: Any,
    *,
    compartment_id: str,
    failures: list[dict[str, object]],
) -> list[object]:
    try:
        return _sdk_list(
            oci,
            compute.list_instances,
            compartment_id,
            lifecycle_state="RUNNING",
        )
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(_sdk_failure("core.list_instances", exc))
        return []


def _collect_public_vnic(
    oci: Any,
    compute: Any,
    network: Any,
    *,
    compartment_id: str,
    instance_id: str,
    failures: list[dict[str, object]],
) -> dict[str, object]:
    try:
        attachments = _sdk_list(
            oci,
            compute.list_vnic_attachments,
            compartment_id,
            instance_id=instance_id,
        )
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(_sdk_failure("core.list_vnic_attachments", exc))
        return {}
    vnics: list[Mapping[str, object]] = []
    for attachment in attachments:
        vnic_id = _raw_str(_model_value(attachment, "vnic_id"))
        if not vnic_id:
            continue
        try:
            response = network.get_vnic(vnic_id)
        except Exception as exc:  # pragma: no cover - provider SDK error detail varies
            failures.append(_sdk_failure("core.get_vnic", exc))
            continue
        data = getattr(response, "data", None)
        public_ip = _public_str(_model_value(data, "public_ip"))
        if public_ip:
            vnics.append({"public-ip": public_ip, "is-primary": _model_value(data, "is_primary")})
    return dict(vnics[0]) if vnics else {}


def _collect_image(
    compute: Any,
    *,
    image_id: str,
    failures: list[dict[str, object]],
) -> dict[str, object]:
    if not image_id:
        return {}
    try:
        response = compute.get_image(image_id)
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(_sdk_failure("core.get_image", exc))
        return {}
    data = getattr(response, "data", None)
    return {
        "display-name": _model_value(data, "display_name"),
        "operating-system": _model_value(data, "operating_system"),
        "operating-system-version": _model_value(data, "operating_system_version"),
    }


def _collect_instance_agent_plugins(
    oci: Any,
    plugin_client: Any,
    *,
    compartment_id: str,
    instance_id: str,
    failures: list[dict[str, object]],
) -> list[Mapping[str, object]]:
    try:
        plugins = _sdk_list(
            oci,
            plugin_client.list_instance_agent_plugins,
            compartment_id,
            instance_id,
        )
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(_sdk_failure("compute_instance_agent.list_instance_agent_plugins", exc))
        return []
    return [
        {
            "name": _model_value(plugin, "name"),
            "status": _model_value(plugin, "status"),
        }
        for plugin in plugins
    ]


def _collect_available_plugins(
    oci: Any,
    pluginconfig_client: Any,
    *,
    compartment_id: str,
    image: Mapping[str, object],
    failures: list[dict[str, object]],
) -> list[Mapping[str, object]]:
    os_name = _public_str(image.get("operating-system"))
    os_version = _public_str(image.get("operating-system-version"))
    if not os_name or not os_version:
        return []
    try:
        plugins = _sdk_list(
            oci,
            pluginconfig_client.list_instanceagent_available_plugins,
            compartment_id,
            os_name,
            os_version,
        )
    except Exception as exc:  # pragma: no cover - provider SDK error detail varies
        failures.append(
            _sdk_failure("compute_instance_agent.list_instanceagent_available_plugins", exc)
        )
        return []
    return [{"name": _model_value(plugin, "name")} for plugin in plugins]


def _sdk_list(oci: Any, method: Any, *args: object, **kwargs: object) -> list[object]:
    response = oci.pagination.list_call_get_all_results(method, *args, **kwargs)
    data = getattr(response, "data", [])
    return list(data) if isinstance(data, Sequence) and not isinstance(data, (str, bytes)) else []


def _read_optional_mapping(path: str) -> Mapping[str, object]:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except OSError as exc:
        raise FuseKitError("oci_inventory_input_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise FuseKitError("oci_inventory_input_invalid_json") from exc
    if not isinstance(value, Mapping):
        raise FuseKitError("oci_inventory_input_must_be_json_object")
    return value


def _inventory_blockers(
    *,
    target_match_count: int,
    instance: Mapping[str, object],
) -> list[str]:
    if target_match_count == 0:
        return ["oci_hosted_launcher_target_not_found"]
    if target_match_count > 1:
        return ["oci_hosted_launcher_target_not_unique"]
    tags = instance.get("freeform-tags")
    if not _target_tags_match(tags):
        return ["oci_hosted_launcher_target_tags_invalid"]
    return []


def _instance_mapping(value: object) -> dict[str, object]:
    return {
        "id": _model_value(value, "id"),
        "display-name": _model_value(value, "display_name"),
        "lifecycle-state": _model_value(value, "lifecycle_state"),
        "shape": _model_value(value, "shape"),
        "freeform-tags": _model_value(value, "freeform_tags"),
    }


def _public_instance(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "id": _redact_ocid(value.get("id")),
        "display-name": _public_str(value.get("display-name") or value.get("display_name")),
        "lifecycle-state": _public_str(
            value.get("lifecycle-state") or value.get("lifecycle_state")
        ),
        "shape": _public_str(value.get("shape")),
        "freeform-tags": _allowed_target_tags(
            value.get("freeform-tags") or value.get("freeform_tags")
        ),
    }


def _public_vnic(value: Mapping[str, object]) -> dict[str, object]:
    public_ip = _public_str(value.get("public-ip") or value.get("public_ip"))
    return {"public-ip": public_ip} if public_ip else {}


def _public_plugin(value: Mapping[str, object]) -> dict[str, str]:
    return {
        "name": _public_str(value.get("name")),
        "status": _public_str(value.get("status")).upper(),
    }


def _public_available_plugin(value: Mapping[str, object]) -> dict[str, str]:
    return {"name": _public_str(value.get("name"))}


def _public_image(value: Mapping[str, object]) -> dict[str, str]:
    return {
        "display-name": _public_str(value.get("display-name") or value.get("display_name")),
        "operating-system": _public_str(
            value.get("operating-system") or value.get("operating_system")
        ),
        "operating-system-version": _public_str(
            value.get("operating-system-version") or value.get("operating_system_version")
        ),
    }


def _public_collection_failure(value: Mapping[str, object]) -> dict[str, str]:
    return {
        "operation": _public_str(value.get("operation")),
        "status": _public_str(value.get("status")),
        "code": _public_str(value.get("code")),
    }


def _sdk_failure(operation: str, exc: Exception) -> dict[str, object]:
    return {
        "operation": operation,
        "status": _public_str(getattr(exc, "status", "")),
        "code": _public_str(getattr(exc, "code", exc.__class__.__name__)),
    }


def _target_tags_match(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    return all(
        value.get(key) == tag_value
        for key, tag_value in HOSTED_OCI_ALLOWED_TARGET_TAGS.items()
    )


def _allowed_target_tags(value: object) -> dict[str, str]:
    tags = value if isinstance(value, Mapping) else {}
    return {
        key: _public_str(tags.get(key))
        for key in sorted(HOSTED_OCI_ALLOWED_TARGET_TAGS)
    }


def _model_value(value: object, attr: str) -> object:
    if isinstance(value, Mapping):
        return value.get(attr) or value.get(attr.replace("_", "-"))
    return getattr(value, attr, "")


def _redact_ocid(value: object) -> str:
    text = _public_str(value)
    if not text.startswith("ocid1."):
        return ""
    parts = text.split(".")
    resource = parts[1] if len(parts) > 1 else "resource"
    suffix = text[-8:] if len(text) >= 8 else "redacted"
    return f"ocid1.{resource}.<redacted:{suffix}>"


def _public_str(value: object) -> str:
    return redact_public_text(str(value or "").strip())


def _raw_str(value: object) -> str:
    return str(value or "").strip()


def _assert_public_inventory(report: Mapping[str, object]) -> None:
    serialized = json.dumps(report, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("hosted_oci_inventory_contains_secret_text")
    forbidden_patterns = [
        r"ocid1\.tenancy\.",
        r"ocid1\.user\.",
        r"ocid1\.compartment\.",
        r"ocid1\.vnic\.",
        r"ocid1\.image\.",
        r"-----BEGIN ",
        r"\bfingerprints?\b",
    ]
    if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in forbidden_patterns):
        raise FuseKitError("hosted_oci_inventory_contains_nonpublic_identifier")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
