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

from fusekit.crypto.sshkeys import generate_ed25519_keypair
from fusekit.errors import FuseKitError
from fusekit.runner.oci import OciRunnerPlan
from fusekit.runner.remote import render_cloud_init
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
    public_ip: str = ""
    resource_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize non-secret workspace metadata."""

        return {
            "id": self.id,
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "shape": self.shape,
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
            public_ip=str(data.get("public_ip", "")),
            resource_ids={str(k): str(v) for k, v in resource_ids.items()},
        )


class OciProvisioner:
    """Live OCI provisioner using the official OCI Python SDK."""

    def __init__(self, auth: OciAuth, progress: Callable[[str], None] | None = None) -> None:
        suppress_oci_http_debug_logging()
        try:
            import oci
        except ImportError as exc:  # pragma: no cover - exercised by install checks.
            raise FuseKitError("OCI SDK is not installed. Run `pip install -e .`.") from exc
        self.oci = oci
        self.auth = auth
        self.identity = oci.identity.IdentityClient(auth.config, signer=auth.signer)
        self.network = oci.core.VirtualNetworkClient(auth.config, signer=auth.signer)
        self.compute = oci.core.ComputeClient(auth.config, signer=auth.signer)
        self._progress = progress or (lambda message: None)

    def provision(self, plan: OciRunnerPlan, vault: Vault) -> OciWorkspace:
        """Create a live OCI workspace."""

        run_id = f"fusekit-{int(time.time())}"
        ssh_key = generate_ed25519_keypair(run_id)
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
            self._emit_progress(f"OCI workspace {run_id}: creating isolated compartment")
            compartment = self._create_compartment(tenancy_id, run_id, tags)
            compartment_id = str(compartment.id)
            workspace = OciWorkspace(
                id=run_id,
                compartment_id=compartment_id,
                availability_domain="",
                shape=plan.shape,
            )
            workspace.resource_ids["compartment"] = compartment_id
            self._emit_progress("OCI workspace: selecting availability domain")
            availability_domain = self._availability_domain(tenancy_id)
            workspace.availability_domain = availability_domain
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
            instance, selected_plan = self._launch_with_capacity_fallback(
                base_plan=plan,
                compartment_id=compartment_id,
                availability_domain=availability_domain,
                subnet_id=subnet.id,
                nsg_id=nsg.id,
                run_id=run_id,
                ssh_public_key=ssh_key.public_key,
                cloud_init=cloud_init,
                tags=tags,
            )
            workspace.shape = selected_plan.shape
            workspace.resource_ids["instance"] = instance.id
            self._emit_progress(f"OCI workspace: VM is running on shape {selected_plan.shape}")
            self._emit_progress("OCI workspace: waiting for public IP")
            workspace.public_ip = self._public_ip(compartment_id, instance.id)
            if not workspace.public_ip:
                raise FuseKitError("OCI runner did not receive a public IP address.")
            self._emit_progress(f"OCI workspace: ready at {workspace.public_ip}")
            vault.put(
                f"runner.oci.{run_id}.workspace",
                "runner_workspace",
                "oci",
                "OCI clean-room runner workspace",
                json.dumps(workspace.to_dict(), sort_keys=True),
                {"run_id": run_id, "shape": workspace.shape, "public_ip": workspace.public_ip},
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
        compartment = self.identity.create_compartment(details).data
        time.sleep(10)
        return compartment

    def _availability_domain(self, compartment_id: str) -> str:
        domains = self.identity.list_availability_domains(compartment_id).data
        if not domains:
            raise FuseKitError("OCI account has no availability domains.")
        return str(domains[0].name)

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
        ssh_rule = self.oci.core.models.AddSecurityRuleDetails(
            direction="INGRESS",
            protocol="6",
            source="0.0.0.0/0",
            source_type="CIDR_BLOCK",
            tcp_options=self.oci.core.models.TcpOptions(
                destination_port_range=self.oci.core.models.PortRange(min=22, max=22)
            ),
        )
        egress_rule = self.oci.core.models.AddSecurityRuleDetails(
            direction="EGRESS",
            protocol="all",
            destination="0.0.0.0/0",
            destination_type="CIDR_BLOCK",
        )
        security_rules = self.oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
            security_rules=[ssh_rule, egress_rule],
        )
        self.network.add_network_security_group_security_rules(nsg.id, security_rules)
        return nsg

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

    def _latest_image(self, compartment_id: str, shape: str) -> str:
        images = self.compute.list_images(
            compartment_id=compartment_id,
            operating_system="Canonical Ubuntu",
            shape=shape,
            sort_by="TIMECREATED",
            sort_order="DESC",
        ).data
        if not images:
            images = self.compute.list_images(
                compartment_id=compartment_id,
                operating_system="Oracle Linux",
                shape=shape,
                sort_by="TIMECREATED",
                sort_order="DESC",
            ).data
        if not images:
            raise FuseKitError(f"No OCI image found for shape {shape}.")
        return str(images[0].id)

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
        if plan.shape == "VM.Standard.A1.Flex":
            shape_config = self.oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=plan.ocpus,
                memory_in_gbs=plan.memory_gb,
            )
        details = self.oci.core.models.LaunchInstanceDetails(
            availability_domain=availability_domain,
            compartment_id=compartment_id,
            display_name=run_id,
            shape=plan.shape,
            shape_config=shape_config,
            create_vnic_details=self.oci.core.models.CreateVnicDetails(
                assign_public_ip=True,
                display_name=f"{run_id}-vnic",
                nsg_ids=[nsg_id],
                subnet_id=subnet_id,
            ),
            metadata={
                "ssh_authorized_keys": ssh_public_key,
                "user_data": base64.b64encode(cloud_init.encode("utf-8")).decode("ascii"),
            },
            source_details=self.oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_id,
                source_type="image",
            ),
            freeform_tags=tags,
        )
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
        availability_domain: str,
        subnet_id: str,
        nsg_id: str,
        run_id: str,
        ssh_public_key: str,
        cloud_init: str,
        tags: dict[str, str],
    ) -> tuple[Any, OciRunnerPlan]:
        candidates = [
            base_plan,
            replace(base_plan, shape="VM.Standard.A1.Flex", ocpus=1, memory_gb=6),
            replace(base_plan, shape="VM.Standard.E2.1.Micro", ocpus=1, memory_gb=1),
        ]
        last_error: Exception | None = None
        seen: set[tuple[str, int, int]] = set()
        for candidate in candidates:
            key = (candidate.shape, candidate.ocpus, candidate.memory_gb)
            if key in seen:
                continue
            seen.add(key)
            try:
                self._emit_progress(f"OCI workspace: finding image for {candidate.shape}")
                image_id = self._latest_image(compartment_id, candidate.shape)
                self._emit_progress(f"OCI workspace: trying shape {candidate.shape}")
                return (
                    self._launch_instance(
                        compartment_id=compartment_id,
                        availability_domain=availability_domain,
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
                )
            except Exception as exc:
                last_error = exc
                if not _is_capacity_error(exc):
                    raise
                self._emit_progress(
                    f"OCI workspace: {candidate.shape} capacity unavailable, retrying"
                )
        raise FuseKitError(
            "OCI capacity was unavailable for all configured runner shapes."
        ) from last_error

    def _public_ip(self, compartment_id: str, instance_id: str) -> str:
        for _ in range(30):
            attachments = self.compute.list_vnic_attachments(
                compartment_id=compartment_id,
                instance_id=instance_id,
            ).data
            for attachment in attachments:
                vnic = self.network.get_vnic(attachment.vnic_id).data
                if getattr(vnic, "public_ip", None):
                    return str(vnic.public_ip)
            time.sleep(5)
        return ""


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
    return "capacity" in text or "out of host" in text or "limitexceeded" in text


def _safe_oci_error(exc: Exception) -> str:
    """Return a redacted OCI error summary suitable for receipts."""

    status = getattr(exc, "status", "")
    code = getattr(exc, "code", "")
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
