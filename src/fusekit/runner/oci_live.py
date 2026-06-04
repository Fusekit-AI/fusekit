"""Live OCI workspace provisioning for the clean-room runner."""

from __future__ import annotations

import base64
import configparser
import http.client
import json
import logging
import os
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

from fusekit.crypto.sshkeys import generate_rsa_keypair
from fusekit.errors import FuseKitError
from fusekit.runner.oci import (
    DEFAULT_X86_MEMORY_GB,
    DEFAULT_X86_OCPUS,
    DEFAULT_X86_SHAPE,
    FALLBACK_X86_SHAPES,
    OciRunnerPlan,
    is_arm_shape,
)
from fusekit.runner.remote import CONTROL_ROOM_PORT, NOVNC_PORT, render_cloud_init
from fusekit.runtime.bootstrap import OPENCLAW_INSTALL_URL
from fusekit.vault import Vault


@dataclass(frozen=True)
class OciAuth:
    """OCI SDK auth material."""

    config: dict[str, str]
    signer: Any | None = None


@dataclass
class OciWorkspace:
    """Created OCI workspace metadata."""

    id: str
    compartment_id: str
    availability_domain: str
    shape: str
    ssh_user: str = "opc"
    public_ip: str = ""
    resource_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize non-secret workspace metadata."""

        return {
            "id": self.id,
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "shape": self.shape,
            "ssh_user": self.ssh_user,
            "public_ip": self.public_ip,
            "resource_ids": self.resource_ids,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> OciWorkspace:
        """Deserialize workspace metadata."""

        resource_ids_raw = data.get("resource_ids", {})
        resource_ids = cast(dict[str, object], resource_ids_raw)
        return cls(
            id=str(data["id"]),
            compartment_id=str(data["compartment_id"]),
            availability_domain=str(data["availability_domain"]),
            shape=str(data["shape"]),
            ssh_user=str(data.get("ssh_user", "opc")),
            public_ip=str(data.get("public_ip", "")),
            resource_ids={str(k): str(v) for k, v in resource_ids.items()},
        )


class OciProvisioner:
    """Live OCI provisioner using the official OCI Python SDK."""

    def __init__(
        self,
        auth: OciAuth,
        progress: Callable[[str], None] | None = None,
        *,
        identity_auth: OciAuth | None = None,
    ) -> None:
        suppress_oci_http_debug_logging()
        try:
            import oci
        except ImportError as exc:  # pragma: no cover - exercised by install checks.
            raise FuseKitError("OCI SDK is not installed. Run `pip install -e .`.") from exc
        self.oci = oci
        self.auth = auth
        self.identity = oci.identity.IdentityClient(auth.config, signer=auth.signer)
        home_auth = identity_auth or auth
        self.home_identity = oci.identity.IdentityClient(
            home_auth.config,
            signer=home_auth.signer,
        )
        self.network = oci.core.VirtualNetworkClient(auth.config, signer=auth.signer)
        self.compute = oci.core.ComputeClient(auth.config, signer=auth.signer)
        self._progress = progress or (lambda message: None)

    def provision(self, plan: OciRunnerPlan, vault: Vault) -> OciWorkspace:
        """Create a live OCI workspace."""

        run_id = f"fusekit-{int(time.time())}"
        if is_arm_shape(plan.shape):
            raise FuseKitError(
                f"OCI runner shape {plan.shape} is ARM-based. FuseKit requires an x86_64 runner."
            )
        ssh_key = generate_rsa_keypair(run_id)
        vault.put(
            f"runner.oci.{run_id}.ssh.private",
            "ssh_private_key",
            "oci",
            "OCI runner SSH private key",
            ssh_key.private_key,
            {"run_id": run_id, "fingerprint": ssh_key.fingerprint},
        )
        tenancy_id = _auth_tenancy_id(self.auth)
        tags = {"fusekit": "true", "fusekit_run": run_id}
        workspace: OciWorkspace | None = None
        try:
            if plan.compartment_mode == "isolated":
                self._emit_progress(f"OCI workspace {run_id}: creating isolated compartment")
                compartment = self._create_compartment(tenancy_id, run_id, tags)
                compartment_id = str(compartment.id)
                compartment_resource_key = "compartment"
            else:
                self._emit_progress(
                    f"OCI workspace {run_id}: using tenancy root compartment"
                )
                compartment_id = tenancy_id
                compartment_resource_key = "root_compartment"
            workspace = OciWorkspace(
                id=run_id,
                compartment_id=compartment_id,
                availability_domain="",
                shape=plan.shape,
            )
            workspace.resource_ids[compartment_resource_key] = compartment_id
            self._emit_progress("OCI workspace: selecting availability domains")
            availability_domains = self._availability_domains(tenancy_id)
            workspace.availability_domain = availability_domains[0]
            self._emit_progress("OCI workspace: checking compute capacity report")
            self._emit_capacity_report(tenancy_id, availability_domains, plan)
            self._emit_progress("OCI workspace: creating private network")
            vcn = self._create_vcn(compartment_id, run_id, tags)
            workspace.resource_ids["vcn"] = vcn.id
            self._emit_progress("OCI workspace: attaching internet gateway")
            gateway = self._create_internet_gateway(compartment_id, vcn.id, run_id, tags)
            workspace.resource_ids["internet_gateway"] = gateway.id
            self._emit_progress("OCI workspace: creating route table")
            route_table = self._create_route_table(compartment_id, vcn.id, gateway.id, run_id, tags)
            workspace.resource_ids["route_table"] = route_table.id
            self._emit_progress("OCI workspace: creating network security group")
            nsg = self._create_nsg(compartment_id, vcn.id, run_id, tags)
            workspace.resource_ids["network_security_group"] = nsg.id
            self._emit_progress("OCI workspace: creating public subnet")
            subnet = self._create_subnet(compartment_id, vcn.id, route_table.id, run_id, tags)
            workspace.resource_ids["subnet"] = subnet.id
            cloud_init = render_cloud_init(
                fusekit_wheel_url=plan.fusekit_package,
                openclaw_install_url=OPENCLAW_INSTALL_URL,
            )
            self._emit_progress(
                f"OCI workspace: launching VM shape {plan.shape} "
                f"({plan.ocpus} OCPU, {plan.memory_gb} GB)"
            )
            (
                instance,
                selected_plan,
                ssh_user,
                selected_domain,
            ) = self._launch_with_capacity_fallback(
                base_plan=plan,
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                subnet_id=subnet.id,
                nsg_id=nsg.id,
                run_id=run_id,
                ssh_public_key=ssh_key.public_key,
                cloud_init=cloud_init,
                tags=tags,
            )
            workspace.shape = selected_plan.shape
            workspace.availability_domain = selected_domain
            workspace.ssh_user = ssh_user
            workspace.resource_ids["instance"] = instance.id
            self._emit_progress(f"OCI workspace: VM is running on shape {selected_plan.shape}")
            self._emit_progress("OCI workspace: wiring public runner access")
            workspace.public_ip = self._public_ip(
                compartment_id,
                instance.id,
                nsg.id,
                run_id,
                tags,
            )
            if not workspace.public_ip:
                raise FuseKitError("OCI runner did not receive a public IP address.")
            self._emit_progress(f"OCI workspace: ready at {workspace.public_ip}")
            vault.put(
                f"runner.oci.{run_id}.workspace",
                "runner_workspace",
                "oci",
                "OCI clean-room runner workspace",
                json.dumps(workspace.to_dict(), sort_keys=True),
                {
                    "run_id": run_id,
                    "shape": workspace.shape,
                    "public_ip": workspace.public_ip,
                    "ssh_user": workspace.ssh_user,
                },
            )
            return workspace
        except Exception:
            if workspace is not None:
                self.detonate(workspace)
            raise

    def detonate(self, workspace: OciWorkspace) -> dict[str, str]:
        """Delete a FuseKit-created OCI workspace and report any provider failures."""

        deleted: dict[str, str] = {}
        instance_id = workspace.resource_ids.get("instance")
        if instance_id:
            try:
                self.compute.terminate_instance(instance_id, preserve_boot_volume=False)
                deleted["instance"] = instance_id
            except Exception as exc:  # pragma: no cover - exception type is SDK-defined.
                deleted["failed.instance"] = _safe_oci_error(exc)
        for key, method_name in (
            ("subnet", "delete_subnet"),
            ("network_security_group", "delete_network_security_group"),
            ("route_table", "delete_route_table"),
            ("internet_gateway", "delete_internet_gateway"),
            ("vcn", "delete_vcn"),
        ):
            resource_id = workspace.resource_ids.get(key)
            if not resource_id:
                continue
            try:
                getattr(self.network, method_name)(resource_id)
                deleted[key] = resource_id
            except Exception as exc:  # pragma: no cover - exception type is SDK-defined.
                deleted[f"failed.{key}"] = _safe_oci_error(exc)
        compartment_id = workspace.resource_ids.get("compartment")
        if compartment_id:
            try:
                self.identity.delete_compartment(compartment_id)
                deleted["compartment"] = compartment_id
            except Exception as exc:  # pragma: no cover - exception type is SDK-defined.
                deleted["failed.compartment"] = _safe_oci_error(exc)
        return deleted

    def _emit_progress(self, message: str) -> None:
        progress = getattr(self, "_progress", None)
        if progress is not None:
            progress(message)

    def _create_compartment(self, tenancy_id: str, run_id: str, tags: dict[str, str]) -> Any:
        details = self.oci.identity.models.CreateCompartmentDetails(
            compartment_id=tenancy_id,
            description=f"FuseKit clean-room runner workspace {run_id}",
            name=run_id.replace("-", "_"),
            freeform_tags=tags,
        )
        compartment = self.home_identity.create_compartment(details).data
        time.sleep(10)
        return compartment

    def _availability_domain(self, compartment_id: str) -> str:
        return self._availability_domains(compartment_id)[0]

    def _availability_domains(self, compartment_id: str) -> tuple[str, ...]:
        try:
            domains = self.identity.list_availability_domains(compartment_id).data
        except Exception as exc:
            if _is_oci_region_unavailable(exc):
                raise FuseKitError(_oci_region_unavailable_message(exc, self.auth)) from exc
            raise
        if not domains:
            raise FuseKitError("OCI account has no availability domains.")
        return tuple(str(domain.name) for domain in domains)

    def _create_vcn(self, compartment_id: str, run_id: str, tags: dict[str, str]) -> Any:
        details = self.oci.core.models.CreateVcnDetails(
            cidr_block="10.42.0.0/16",
            compartment_id=compartment_id,
            display_name=run_id,
            dns_label="fusekit",
            freeform_tags=tags,
        )
        return self.network.create_vcn(details).data

    def _create_internet_gateway(
        self,
        compartment_id: str,
        vcn_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> Any:
        details = self.oci.core.models.CreateInternetGatewayDetails(
            compartment_id=compartment_id,
            display_name=f"{run_id}-ig",
            is_enabled=True,
            vcn_id=vcn_id,
            freeform_tags=tags,
        )
        return self.network.create_internet_gateway(details).data

    def _create_route_table(
        self,
        compartment_id: str,
        vcn_id: str,
        gateway_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> Any:
        route_rule = self.oci.core.models.RouteRule(
            destination="0.0.0.0/0",
            destination_type="CIDR_BLOCK",
            network_entity_id=gateway_id,
        )
        details = self.oci.core.models.CreateRouteTableDetails(
            compartment_id=compartment_id,
            display_name=f"{run_id}-rt",
            route_rules=[route_rule],
            vcn_id=vcn_id,
            freeform_tags=tags,
        )
        return self.network.create_route_table(details).data

    def _create_nsg(
        self,
        compartment_id: str,
        vcn_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> Any:
        details = self.oci.core.models.CreateNetworkSecurityGroupDetails(
            compartment_id=compartment_id,
            display_name=f"{run_id}-nsg",
            vcn_id=vcn_id,
            freeform_tags=tags,
        )
        nsg = self.network.create_network_security_group(details).data
        ssh_rule = self._tcp_ingress_rule(22)
        control_room_rule = self._tcp_ingress_rule(CONTROL_ROOM_PORT)
        novnc_rule = self._tcp_ingress_rule(NOVNC_PORT)
        egress_rule = self.oci.core.models.AddSecurityRuleDetails(
            direction="EGRESS",
            protocol="all",
            destination="0.0.0.0/0",
            destination_type="CIDR_BLOCK",
        )
        security_rules = self.oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
            security_rules=[ssh_rule, control_room_rule, novnc_rule, egress_rule],
        )
        self.network.add_network_security_group_security_rules(nsg.id, security_rules)
        return nsg

    def _tcp_ingress_rule(self, port: int) -> Any:
        return self.oci.core.models.AddSecurityRuleDetails(
            direction="INGRESS",
            protocol="6",
            source="0.0.0.0/0",
            source_type="CIDR_BLOCK",
            tcp_options=self.oci.core.models.TcpOptions(
                destination_port_range=self.oci.core.models.PortRange(min=port, max=port)
            ),
        )

    def _create_subnet(
        self,
        compartment_id: str,
        vcn_id: str,
        route_table_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> Any:
        details = self.oci.core.models.CreateSubnetDetails(
            cidr_block="10.42.1.0/24",
            compartment_id=compartment_id,
            display_name=f"{run_id}-subnet",
            dns_label="runner",
            prohibit_public_ip_on_vnic=False,
            route_table_id=route_table_id,
            vcn_id=vcn_id,
            freeform_tags=tags,
        )
        return self.network.create_subnet(details).data

    def _latest_image(self, compartment_id: str, shape: str) -> tuple[str, str]:
        ssh_user = "ubuntu"
        images: list[Any] = []
        selected_label = ""
        for ubuntu_version in ("24.04", "22.04"):
            images = self.compute.list_images(
                compartment_id=compartment_id,
                operating_system="Canonical Ubuntu",
                operating_system_version=ubuntu_version,
                shape=shape,
                sort_by="TIMECREATED",
                sort_order="DESC",
            ).data
            if images:
                selected_label = f"Canonical Ubuntu {ubuntu_version}"
                break
        if not images:
            images = self.compute.list_images(
                compartment_id=compartment_id,
                operating_system="Canonical Ubuntu",
                shape=shape,
                sort_by="TIMECREATED",
                sort_order="DESC",
            ).data
            selected_label = "Canonical Ubuntu"
        if not images:
            images = self.compute.list_images(
                compartment_id=compartment_id,
                operating_system="Oracle Linux",
                shape=shape,
                sort_by="TIMECREATED",
                sort_order="DESC",
            ).data
            ssh_user = "opc"
            selected_label = "Oracle Linux"
        if not images:
            raise FuseKitError(f"No OCI image found for shape {shape}.")
        self._emit_progress(
            "OCI workspace: selected runner image "
            f"{_image_label(images[0], selected_label)} for SSH user {ssh_user}"
        )
        return str(images[0].id), ssh_user

    def _emit_capacity_report(
        self,
        root_compartment_id: str,
        availability_domains: tuple[str, ...],
        plan: OciRunnerPlan,
    ) -> None:
        if not all(
            hasattr(self.oci.core.models, model_name)
            for model_name in (
                "CreateComputeCapacityReportDetails",
                "CreateCapacityReportShapeAvailabilityDetails",
                "CapacityReportInstanceShapeConfig",
            )
        ):
            self._emit_progress("OCI workspace: compute capacity report unavailable in SDK")
            return
        for availability_domain in availability_domains:
            try:
                details = self.oci.core.models.CreateComputeCapacityReportDetails(
                    compartment_id=root_compartment_id,
                    availability_domain=availability_domain,
                    shape_availabilities=[
                        self.oci.core.models.CreateCapacityReportShapeAvailabilityDetails(
                            instance_shape=plan.shape,
                            instance_shape_config=(
                                self.oci.core.models.CapacityReportInstanceShapeConfig(
                                    ocpus=plan.ocpus,
                                    memory_in_gbs=plan.memory_gb,
                                )
                            ),
                        )
                    ],
                )
                report = self.compute.create_compute_capacity_report(details).data
            except Exception as exc:
                self._emit_progress(
                    "OCI workspace: compute capacity report unavailable "
                    f"for {availability_domain}: {_safe_oci_error(exc)}"
                )
                continue
            status = _capacity_report_status(report)
            if status:
                self._emit_progress(
                    f"OCI workspace: capacity report for {plan.shape} "
                    f"in {availability_domain}: {status}"
                )

    def _launch_instance(
        self,
        *,
        compartment_id: str,
        availability_domain: str,
        image_id: str,
        subnet_id: str,
        nsg_id: str,
        plan: OciRunnerPlan,
        run_id: str,
        ssh_public_key: str,
        cloud_init: str,
        tags: dict[str, str],
    ) -> Any:
        shape_config = None
        if plan.shape.endswith(".Flex"):
            shape_config = self.oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=plan.ocpus,
                memory_in_gbs=plan.memory_gb,
            )
        details_kwargs: dict[str, object] = {
            "availability_domain": availability_domain,
            "compartment_id": compartment_id,
            "display_name": run_id,
            "shape": plan.shape,
            "shape_config": shape_config,
            "create_vnic_details": self.oci.core.models.CreateVnicDetails(
                assign_public_ip=False,
                display_name=f"{run_id}-vnic",
                hostname_label="runner",
                subnet_id=subnet_id,
            ),
            "metadata": {
                "ssh_authorized_keys": ssh_public_key,
                "user_data": base64.b64encode(cloud_init.encode("utf-8")).decode("ascii"),
            },
            "source_details": self.oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_id,
                source_type="image",
            ),
            "freeform_tags": tags,
        }
        if hasattr(self.oci.core.models, "InstanceOptions"):
            details_kwargs["instance_options"] = self.oci.core.models.InstanceOptions(
                are_legacy_imds_endpoints_disabled=True,
            )
        if hasattr(self.oci.core.models, "LaunchInstanceAvailabilityConfigDetails"):
            details_kwargs["availability_config"] = (
                self.oci.core.models.LaunchInstanceAvailabilityConfigDetails(
                    recovery_action="RESTORE_INSTANCE",
                )
            )
        details_kwargs["is_pv_encryption_in_transit_enabled"] = True
        details = self.oci.core.models.LaunchInstanceDetails(**details_kwargs)
        try:
            composite = self.oci.core.ComputeClientCompositeOperations(self.compute)
            return composite.launch_instance_and_wait_for_state(
                details,
                wait_for_states=["RUNNING"],
            ).data
        except AttributeError:
            return self.compute.launch_instance(details).data

    def _launch_with_capacity_fallback(
        self,
        *,
        base_plan: OciRunnerPlan,
        compartment_id: str,
        availability_domain: str | None = None,
        availability_domains: tuple[str, ...] | None = None,
        subnet_id: str,
        nsg_id: str,
        run_id: str,
        ssh_public_key: str,
        cloud_init: str,
        tags: dict[str, str],
    ) -> tuple[Any, OciRunnerPlan, str, str]:
        if is_arm_shape(base_plan.shape):
            raise FuseKitError(
                f"OCI runner shape {base_plan.shape} is ARM-based. "
                "FuseKit requires an x86_64 runner."
            )
        domains = availability_domains or ((availability_domain,) if availability_domain else ())
        if not domains:
            raise FuseKitError("OCI account has no availability domains.")
        raw_candidates = [
            base_plan,
            *(
                replace(
                    base_plan,
                    shape=shape,
                    ocpus=DEFAULT_X86_OCPUS,
                    memory_gb=DEFAULT_X86_MEMORY_GB,
                )
                for shape in (DEFAULT_X86_SHAPE, *FALLBACK_X86_SHAPES)
            ),
        ]
        candidates: list[OciRunnerPlan] = []
        seen: set[tuple[str, int, int]] = set()
        for candidate in raw_candidates:
            key = (candidate.shape, candidate.ocpus, candidate.memory_gb)
            if key in seen or is_arm_shape(candidate.shape):
                continue
            seen.add(key)
            candidates.append(candidate)
        last_error: Exception | None = None
        saw_capacity_error = False
        saw_authorization_error = False
        for domain in domains:
            self._emit_progress(f"OCI workspace: checking availability domain {domain}")
            for candidate in candidates:
                try:
                    self._emit_progress(f"OCI workspace: finding image for {candidate.shape}")
                    image_id, ssh_user = self._latest_image(compartment_id, candidate.shape)
                    self._emit_progress(
                        "OCI workspace: launch inputs "
                        f"shape={candidate.shape} ocpus={candidate.ocpus} "
                        f"memory_gb={candidate.memory_gb} ad={domain} "
                        f"compartment={_short_ocid(compartment_id)} "
                        f"subnet={_short_ocid(subnet_id)} "
                        f"image={_short_ocid(image_id)} "
                        "public_ip=post-launch nsg=post-launch"
                    )
                    self._emit_progress(
                        f"OCI workspace: trying shape {candidate.shape} in {domain}"
                    )
                    return (
                        self._launch_instance_with_iam_retries(
                            compartment_id=compartment_id,
                            availability_domain=domain,
                            image_id=image_id,
                            subnet_id=subnet_id,
                            nsg_id=nsg_id,
                            plan=candidate,
                            run_id=run_id,
                            ssh_public_key=ssh_public_key,
                            cloud_init=cloud_init,
                            tags=tags,
                        ),
                        candidate,
                        ssh_user,
                        domain,
                    )
                except Exception as exc:
                    last_error = exc
                    if _is_oci_limit_error(exc):
                        self._emit_progress(
                            f"OCI workspace: account resource limit reached while "
                            f"launching {candidate.shape} in {domain} "
                            f"({_safe_oci_error(exc)})"
                        )
                        raise FuseKitError(_oci_resource_limit_message(exc)) from exc
                    if _is_capacity_error(exc):
                        saw_capacity_error = True
                        self._emit_progress(
                            f"OCI workspace: {candidate.shape} capacity unavailable "
                            f"in {domain}, retrying ({_safe_oci_error(exc)})"
                        )
                        continue
                    if _is_oci_not_authorized_or_not_found(exc):
                        saw_authorization_error = True
                        self._emit_progress(
                            f"OCI workspace: {candidate.shape} launch was not authorized "
                            f"or not visible yet in {domain}, trying next x86 option "
                            f"({_safe_oci_error(exc)})"
                        )
                        continue
                    raise
        if saw_capacity_error and saw_authorization_error:
            raise FuseKitError(
                _oci_mixed_capacity_authorization_message(last_error)
            ) from last_error
        if last_error is not None and _is_oci_not_authorized_or_not_found(last_error):
            raise FuseKitError(_oci_launch_authorization_message(last_error)) from last_error
        raise FuseKitError(
            "OCI capacity was unavailable for all configured x86_64 runner shapes "
            "across all availability domains."
        ) from last_error

    def _launch_instance_with_iam_retries(
        self,
        *,
        compartment_id: str,
        availability_domain: str,
        image_id: str,
        subnet_id: str,
        nsg_id: str,
        plan: OciRunnerPlan,
        run_id: str,
        ssh_public_key: str,
        cloud_init: str,
        tags: dict[str, str],
        attempts: int = 3,
    ) -> Any:
        for attempt in range(1, attempts + 1):
            try:
                return self._launch_instance(
                    compartment_id=compartment_id,
                    availability_domain=availability_domain,
                    image_id=image_id,
                    subnet_id=subnet_id,
                    nsg_id=nsg_id,
                    plan=plan,
                    run_id=run_id,
                    ssh_public_key=ssh_public_key,
                    cloud_init=cloud_init,
                    tags=tags,
                )
            except Exception as exc:
                if not _is_oci_not_authorized_or_not_found(exc) or attempt >= attempts:
                    raise
                self._emit_progress(
                    "OCI workspace: compute launch is waiting for OCI IAM/resource "
                    f"propagation, retrying ({attempt}/{attempts - 1})"
                )
                time.sleep(20 * attempt)

    def _public_ip(
        self,
        compartment_id: str,
        instance_id: str,
        nsg_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> str:
        for _ in range(30):
            attachments = self.compute.list_vnic_attachments(
                compartment_id=compartment_id,
                instance_id=instance_id,
            ).data
            for attachment in attachments:
                self._attach_nsg_to_vnic(str(attachment.vnic_id), nsg_id)
                vnic = self.network.get_vnic(attachment.vnic_id).data
                if getattr(vnic, "public_ip", None):
                    return str(vnic.public_ip)
                assigned_ip = self._assign_public_ip(
                    compartment_id,
                    str(attachment.vnic_id),
                    run_id,
                    tags,
                )
                if assigned_ip:
                    return assigned_ip
            time.sleep(5)
        return ""

    def _attach_nsg_to_vnic(self, vnic_id: str, nsg_id: str) -> None:
        if not hasattr(self.oci.core.models, "UpdateVnicDetails"):
            return
        details = self.oci.core.models.UpdateVnicDetails(nsg_ids=[nsg_id])
        try:
            self.network.update_vnic(vnic_id, details)
        except Exception as exc:
            raise FuseKitError(
                "OCI launched the VM, but FuseKit could not attach the runner network "
                f"security group needed for SSH/control-room/noVNC access: {_safe_oci_error(exc)}"
            ) from exc

    def _assign_public_ip(
        self,
        compartment_id: str,
        vnic_id: str,
        run_id: str,
        tags: dict[str, str],
    ) -> str:
        private_ips = self.network.list_private_ips(vnic_id=vnic_id).data
        if not private_ips:
            return ""
        details = self.oci.core.models.CreatePublicIpDetails(
            compartment_id=compartment_id,
            display_name=f"{run_id}-public-ip",
            lifetime="EPHEMERAL",
            private_ip_id=private_ips[0].id,
            freeform_tags=tags,
        )
        try:
            public_ip = self.network.create_public_ip(details).data
        except Exception as exc:
            raise FuseKitError(
                "OCI launched the VM, but FuseKit could not assign the public IPv4 "
                f"needed for SSH/control-room/noVNC reachability: {_safe_oci_error(exc)}"
            ) from exc
        return str(getattr(public_ip, "ip_address", "") or "")


def load_oci_auth_from_vault_or_config(
    vault: Vault,
    *,
    config_file: Path | None = None,
) -> OciAuth:
    """Load OCI auth from the encrypted vault or an existing OCI config file."""

    suppress_oci_http_debug_logging()
    try:
        config_record = vault.require("runner.oci.config")
        try:
            private_key = vault.require("runner.oci.api_signing_key.private").value
            return _auth_from_api_key_snippet(config_record.value, private_key)
        except FuseKitError:
            token = vault.require("runner.oci.session_token").value
            private_key = vault.require("runner.oci.session_private_key").value
            return _auth_from_session_snippet(config_record.value, token, private_key)
    except FuseKitError:
        return _load_oci_config_file(config_file)


def _load_oci_config_file(config_file: Path | None) -> OciAuth:
    suppress_oci_http_debug_logging()
    try:
        import oci
    except ImportError as exc:
        raise FuseKitError("OCI SDK is not installed. Run `pip install -e .`.") from exc
    path = str(config_file) if config_file else oci.config.DEFAULT_LOCATION
    config = oci.config.from_file(path)
    normalized = {str(key): str(value) for key, value in config.items()}
    if normalized.get("authentication_type"):
        signer = oci.util.get_signer_from_authentication_type(normalized)
        if getattr(signer, "tenancy_id", None):
            normalized.setdefault("tenancy", str(signer.tenancy_id))
        if getattr(signer, "region", None):
            normalized.setdefault("region", str(signer.region))
        return OciAuth(normalized, signer)
    token_file = normalized.get("security_token_file")
    key_file = normalized.get("key_file")
    if token_file and key_file:
        token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
        private_key = oci.signer.load_private_key_from_file(str(Path(key_file).expanduser()))
        signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
        return OciAuth(normalized, signer)
    return OciAuth(normalized)


def _auth_tenancy_id(auth: OciAuth) -> str:
    tenancy = auth.config.get("tenancy")
    if tenancy:
        return tenancy
    signer_tenancy = getattr(auth.signer, "tenancy_id", "")
    if signer_tenancy:
        return str(signer_tenancy)
    raise FuseKitError("OCI auth did not expose a tenancy id.")


def _auth_from_api_key_snippet(config_snippet: str, private_key_pem: str) -> OciAuth:
    suppress_oci_http_debug_logging()
    try:
        import oci
    except ImportError as exc:
        raise FuseKitError("OCI SDK is not installed. Run `pip install -e .`.") from exc
    parser = configparser.ConfigParser()
    parser.read_string(config_snippet)
    section = parser["DEFAULT"]
    config = {
        "tenancy": section["tenancy"],
        "user": section["user"],
        "fingerprint": section.get("fingerprint", ""),
        "region": section.get("region", "us-ashburn-1"),
    }
    signer = oci.signer.Signer(
        tenancy=config["tenancy"],
        user=config["user"],
        fingerprint=config["fingerprint"],
        private_key_content=private_key_pem,
    )
    return OciAuth(config, signer)


def _auth_from_session_snippet(
    config_snippet: str,
    security_token: str,
    private_key_pem: str,
) -> OciAuth:
    suppress_oci_http_debug_logging()
    try:
        import oci
    except ImportError as exc:
        raise FuseKitError("OCI SDK is not installed. Run `pip install -e .`.") from exc
    parser = configparser.ConfigParser()
    parser.read_string(config_snippet)
    section = parser[parser.sections()[0] if parser.sections() else "DEFAULT"]
    config = {
        "tenancy": section["tenancy"],
        "user": section["user"],
        "fingerprint": section.get("fingerprint", ""),
        "region": section.get("region", "us-ashburn-1"),
    }
    private_key = oci.signer.load_private_key_from_string(private_key_pem)
    signer = oci.auth.signers.SecurityTokenSigner(security_token, private_key)
    return OciAuth(config, signer)


def _is_capacity_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "capacity" in text or "out of host" in text


def _is_oci_limit_error(exc: Exception) -> bool:
    status = str(getattr(exc, "status", ""))
    code = str(getattr(exc, "code", ""))
    text = str(exc).lower()
    return (
        code == "LimitExceeded"
        or (status == "400" and "limitexceeded" in text)
        or "resource creation limit has been reached" in text
    )


def _capacity_report_status(report: object) -> str:
    shape_availabilities = getattr(report, "shape_availabilities", None) or []
    statuses: list[str] = []
    for availability in shape_availabilities:
        shape = str(
            getattr(availability, "instance_shape", "")
            or getattr(availability, "shape", "")
        )
        status = str(getattr(availability, "availability_status", "") or "")
        if not status:
            domain_reports = getattr(availability, "domain_level_capacity_reports", None) or []
            nested = [
                str(getattr(item, "availability_status", "") or "")
                for item in domain_reports
                if getattr(item, "availability_status", "")
            ]
            status = ",".join(nested)
        if shape or status:
            statuses.append(":".join(part for part in (shape, status) if part))
    return "; ".join(statuses)


def _image_label(image: object, fallback_label: str) -> str:
    operating_system = str(getattr(image, "operating_system", "") or "")
    version = str(getattr(image, "operating_system_version", "") or "")
    display_name = str(getattr(image, "display_name", "") or "")
    image_id = str(getattr(image, "id", "") or "")
    label_parts = [part for part in (operating_system or fallback_label, version) if part]
    label = " ".join(label_parts).strip() or fallback_label
    suffix = f" ({display_name})" if display_name and display_name not in label else ""
    return f"{label}{suffix} {_short_ocid(image_id)}".strip()


def _short_ocid(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 28:
        return value
    return f"{value[:18]}...{value[-8:]}"


def _is_oci_not_authorized_or_not_found(exc: Exception) -> bool:
    status = str(getattr(exc, "status", ""))
    code = str(getattr(exc, "code", ""))
    return status == "404" and code == "NotAuthorizedOrNotFound"


def _is_oci_region_unavailable(exc: Exception) -> bool:
    status = str(getattr(exc, "status", ""))
    code = str(getattr(exc, "code", ""))
    return status == "404" and code in {"EntityNotFound", "NotAuthorizedOrNotFound"}


def _oci_request_id(exc: Exception | None) -> str:
    if exc is None:
        return ""
    return str(
        getattr(exc, "opc_request_id", "")
        or getattr(exc, "request_id", "")
        or getattr(exc, "opc-request-id", "")
    )


def _oci_region_unavailable_message(exc: Exception, auth: OciAuth) -> str:
    region = auth.config.get("region", "the requested region")
    request_id = _oci_request_id(exc)
    suffix = f" OCI request id: {request_id}." if request_id else ""
    return (
        f"OCI could not list availability domains in {region}. This usually means the "
        "tenancy is not subscribed to that region, IAM has not propagated there, or the "
        "current OCI session is not authorized in that region. Use a subscribed OCI region "
        "for the runner, or subscribe the tenancy to the requested region before launching."
        f"{suffix}"
    )


def _oci_launch_authorization_message(exc: Exception) -> str:
    request_id = _oci_request_id(exc)
    suffix = f" OCI request id: {request_id}." if request_id else ""
    return (
        "OCI rejected the compute instance launch with 404 NotAuthorizedOrNotFound after "
        "retrying x86_64 runner shapes. This usually means the OCI user/session can create "
        "networking resources but cannot launch compute instances in this region/compartment, "
        "or OCI has not made the selected compartment/subnet visible to Compute yet. "
        "Confirm the account has permission to manage instances, vnics, images, and volumes in "
        "the target compartment and that VM.Standard3/E4/E5 Flex shapes are available in "
        f"{'this region'}.{suffix}"
    )


def _oci_resource_limit_message(exc: Exception) -> str:
    request_id = _oci_request_id(exc)
    suffix = f" OCI request id: {request_id}." if request_id else ""
    return (
        "OCI rejected the FuseKit runner launch because this account has reached its "
        "resource creation limit. Delete unused OCI resources, upgrade the tenancy to Pay "
        "As You Go or Oracle Universal Credits, or ask Oracle support to restore resource "
        f"creation capability before launching again.{suffix}"
    )


def _oci_mixed_capacity_authorization_message(exc: Exception | None) -> str:
    request_id = _oci_request_id(exc)
    suffix = f" Last OCI request id: {request_id}." if request_id else ""
    return (
        "OCI could not launch an x86_64 24 GB FuseKit runner after trying all configured "
        "availability domains and x86 shapes. Some attempts reported no capacity, and some "
        "reported 404 NotAuthorizedOrNotFound. This usually means OCI capacity is exhausted "
        "for the allowed shapes in this region, or the current OCI user/session lacks compute "
        "launch permission for one of the fallback shape families. Try another OCI region or "
        "confirm Compute permissions/limits for VM.Standard3, VM.Standard.E4, and "
        f"VM.Standard.E5 Flex.{suffix}"
    )


def _safe_oci_error(exc: Exception) -> str:
    """Return a redacted OCI error summary suitable for receipts."""

    status = getattr(exc, "status", "")
    code = getattr(exc, "code", "")
    message = str(getattr(exc, "message", "") or "")
    request_id = _oci_request_id(exc)
    parts = [str(part) for part in (status, code, message) if part]
    if request_id:
        parts.append(f"request_id={request_id}")
    if parts:
        return " ".join(parts)
    if status or code:
        return " ".join(str(part) for part in (status, code) if part)
    return exc.__class__.__name__


def suppress_oci_http_debug_logging() -> None:
    """Prevent OCI SDK HTTP wire dumps from exposing delegated auth material."""

    for env_name in ("OCI_PYTHON_SDK_DEBUG", "OCI_SDK_DEBUG"):
        os.environ.pop(env_name, None)
    http.client.HTTPConnection.debuglevel = 0
    http.client.HTTPSConnection.debuglevel = 0
    http.client.HTTPConnection.set_debuglevel = _disable_http_debuglevel  # type: ignore[assignment]
    http.client.HTTPSConnection.set_debuglevel = _disable_http_debuglevel  # type: ignore[assignment]
    try:
        import urllib3.connection

        urllib3.connection.HTTPConnection.debuglevel = 0
        urllib3.connection.HTTPSConnection.debuglevel = 0
    except Exception:
        pass
    for logger_name in (
        "oci",
        "oci.base_client",
        "oci._vendor.urllib3",
        "urllib3",
        "urllib3.connectionpool",
    ):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    warnings.filterwarnings(
        "ignore",
        message=r"The 'strict' parameter is no longer needed on Python 3\+.*",
        category=FutureWarning,
    )


def _disable_http_debuglevel(connection: Any, level: int = 0) -> None:
    """Ignore attempts to re-enable stdlib HTTP wire logging."""

    connection.debuglevel = 0


def latest_workspace_from_vault(vault: Vault) -> OciWorkspace:
    """Return the newest OCI workspace stored in the vault."""

    candidates = [
        record
        for record in vault.records.values()
        if record.kind == "runner_workspace" and record.provider == "oci"
    ]
    if not candidates:
        raise FuseKitError("No OCI workspace exists in the vault. Provision the runner first.")
    latest = max(candidates, key=lambda record: record.created_at)
    return OciWorkspace.from_dict(json.loads(latest.value))
