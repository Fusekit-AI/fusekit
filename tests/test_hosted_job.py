from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import replace

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted import (
    advance_hosted_launch_job,
    apply_hosted_worker_proof,
    build_hosted_launch_job,
    build_hosted_worker_contract,
    claim_hosted_launch_job,
    create_hosted_job_token,
    hosted_job_action_receipt,
    hosted_launch_job_from_dict,
    hosted_proof_receipt,
    hosted_worker_claim_receipt,
    hosted_worker_proof_receipt,
    hosted_worker_request,
    render_hosted_control_room,
    render_hosted_proof_receipt,
    verify_hosted_job_token,
)
from fusekit.hosted.job import (
    HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION,
    HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION,
    HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION,
    HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION,
    HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION,
    hosted_byo_oci_bootstrap,
    render_hosted_byo_oci_bootstrap,
    verify_hosted_byo_oci_proof_bundle,
    with_hosted_job_payment_receipt,
)
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.manifest import ServiceRequirement, SetupManifest
from fusekit.runner.cloud_shell import CloudShellLaunchPlan


def _plan():
    manifest = SetupManifest(
        app_name="job-demo",
        required_env=("RESEND_API_KEY",),
        services=(
            ServiceRequirement(
                provider="github",
                kind="repository",
                name="source",
                capabilities=("repo_secrets", "deploy_keys"),
                secrets=("GITHUB_TOKEN",),
            ),
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web",
                capabilities=("project", "env", "deploy"),
                secrets=("VERCEL_TOKEN",),
            ),
        ),
    )
    return build_hosted_launch_plan(manifest, github_source="https://github.com/example/job-demo")


def _byo_proof_bundle_from_bootstrap(bootstrap: dict[str, object]) -> dict[str, object]:
    manifest = bootstrap["proof_manifest"]
    assert isinstance(manifest, dict)
    artifacts = manifest["required_remote_artifacts"]
    assert isinstance(artifacts, list)
    return {
        "schema_version": HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION,
        "job_binding": manifest["job_binding"],
        "user_owned_cost_boundary": manifest["user_owned_cost_boundary"],
        "byo_security_contract": manifest["byo_security_contract"],
        "proof_bundle_root": manifest["proof_bundle_root"],
        "artifacts": [
            {
                "path": artifact["path"],
                "label": artifact["label"],
                "sha256": "sha256:" + ("a" * 64),
                "size_bytes": 1024,
                "redacted": True,
            }
            for artifact in artifacts
            if isinstance(artifact, dict)
        ],
        "completion_evidence": {
            key: True for key in manifest["required_completion_evidence"]
        },
    }


def _paid_checkout_receipt(job) -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-payment.v1",
        "provider": "stripe-checkout",
        "checkout_session_id": "cs_test_paid",
        "status": "complete",
        "payment_status": "paid",
        "mode": "payment",
        "client_reference_id": job.job_id,
        "metadata": {
            "job_id": job.job_id,
            "lane": job.launch_lane,
            "github_source_hash": _public_hash(job.github_source),
            "plan_fingerprint": job.worker_contract.plan_fingerprint,
            "stripe_price_id_hash": job.payment_price_id_hash or "sha256:" + ("b" * 64),
            "price_label_hash": _public_hash(job.payment_price_label),
        },
        "amount_total": 100,
        "currency": "usd",
        "paid": True,
        "price_label": job.payment_price_label,
    }


def _public_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_hosted_launch_job_is_public_safe_and_trust_complete() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-job.v1"
    assert payload["job_id"] == "hosted-test"
    assert payload["status"] == "waiting_for_worker"
    assert "Live URL verification" in payload["proof"]
    assert "Show rollback metadata before risky changes." in payload["rollback"]
    assert "Write detonation receipt before launch is considered complete." in payload["detonation"]
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["launch_lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["worker_contract"]["lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["lane_contract"]["id"] == MANAGED_FUSEKIT_RUN_LANE
    assert payload["payment"]["status"] == "not_required"
    assert payload["worker_contract"]["github_installation_id"] is None
    assert payload["worker_contract"]["plan_integrity"]["algorithm"] == "sha256"
    assert str(payload["worker_contract"]["plan_integrity"]["fingerprint"]).startswith(
        "sha256:"
    )
    assert "approved_actions" in payload["worker_contract"]["plan_integrity"]["covers"]
    assert "contents:read" in " ".join(payload["worker_contract"]["permission_boundary"])
    assert ".fusekit/run_record.json" in payload["worker_contract"]["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in payload["worker_contract"]["required_artifacts"]
    assert any(step["id"] == "provider.gates" for step in payload["steps"])
    assert any(step["id"] == "detonate.worker" for step in payload["steps"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_launch_job_rejects_unknown_lane_instead_of_defaulting_managed() -> None:
    with pytest.raises(FuseKitError, match="Hosted launch lane is invalid"):
        build_hosted_launch_job(
            _plan(),
            launch_lane="managed-fusekit-run-typo",
            job_id="hosted-test",
            now=1_700_000_000,
        )


def test_hosted_payment_receipt_rejects_unexpected_metadata() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    receipt = _paid_checkout_receipt(job)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["provider_token"] = "not-allowed-here"

    with pytest.raises(
        FuseKitError,
        match="Hosted launch payment metadata contains unexpected field",
    ):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_worker_contract_rejects_unknown_lane() -> None:
    with pytest.raises(FuseKitError, match="Hosted launch lane is invalid"):
        build_hosted_worker_contract(
            _plan(),
            launch_lane="bring-your-own-oci-typo",
        )


def test_hosted_proof_receipt_is_redacted_and_not_prematurely_complete() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    receipt = hosted_proof_receipt(job)
    html = render_hosted_proof_receipt(job, job_token="signed-public-job")
    serialized = json.dumps(receipt) + html

    assert receipt["schema_version"] == "fusekit.hosted-proof-receipt.v1"
    assert receipt["completion_ready"] is False
    assert "Completion is not yet proven" in receipt["completion_statement"]
    assert ".fusekit/run_record.json" in receipt["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in receipt["required_artifacts"]
    assert receipt["completion_requires"] == [
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "rollback_metadata",
        "retrieved_remote_artifacts",
        "run_record",
        "detonation_receipt",
        "live_acceptance_report",
        "recording",
    ]
    assert receipt["launch_lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert receipt["lane_contract"]["id"] == MANAGED_FUSEKIT_RUN_LANE
    assert receipt["lane_contract"]["requires_payment"] is True
    assert receipt["plan_integrity"] == job.worker_contract.plan_integrity()
    assert receipt["trust_evidence"]["visible_plan_fingerprint"] == (
        job.worker_contract.plan_fingerprint
    )
    assert "contents:read" in " ".join(receipt["trust_evidence"]["narrow_permissions"])
    assert "github.authorize" in receipt["trust_evidence"]["approved_actions"]
    assert receipt["trust_evidence"]["not_proven_until"] == receipt["completion_requires"]
    cannot_do = receipt["trust_evidence"]["fusekit_cannot_do"]
    assert any("Do not bypass MFA" in item for item in cannot_do)
    assert any("MFA" in gate for gate in receipt["provider_gates"])
    assert any("contents:read" in item for item in receipt["permission_boundary"])
    assert "github.authorize" in receipt["approved_actions"]
    assert any("Request rollback" in item["control"] for item in receipt["reversal_playbook"])
    assert any("Request detonation" in item["control"] for item in receipt["reversal_playbook"])
    assert any(
        "GitHub App installation" in item["control"]
        for item in receipt["reversal_playbook"]
    )
    assert any("Stop launch" in item["control"] for item in receipt["reversal_playbook"])
    assert "Proof receipt." in html
    assert "Completion requires" in html
    assert "retrieved_remote_artifacts" in html
    assert "recording" in html
    assert "Permission boundary" in html
    assert "Trust evidence" in html
    assert "visible_plan_fingerprint" in html
    assert "fusekit_cannot_do" in html
    assert "contents:read" in html
    assert "Approved actions" in html
    assert "vercel.deploy_verify" in html
    assert "Approved plan integrity" in html
    assert job.worker_contract.plan_fingerprint in html
    assert "fresh visible plan" in html
    assert "Provider gates" in html
    assert "These gates stay provider-owned and human-approved" in html
    assert "MFA" in html
    assert "Reversible setup" in html
    assert "Reversal playbook" in html
    assert "Stop launch" in html
    assert "Request rollback" in html
    assert "Request detonation" in html
    assert "GitHub App installation" in html
    assert "Download proof JSON" in html
    assert "format=json" in html
    assert "Back to control room" in html
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_proof_receipt_rejects_private_material_drift() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    unsafe_job = replace(job, proof=("ghs_should_not_render_in_public_proof",))

    with pytest.raises(FuseKitError, match="Hosted proof receipt contains private material"):
        hosted_proof_receipt(unsafe_job)


def test_hosted_byo_proof_receipt_keeps_user_owned_lane_boundary() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    receipt = hosted_proof_receipt(job)
    serialized = json.dumps(receipt)

    assert receipt["launch_lane"] == BYO_OCI_LANE
    assert receipt["lane_contract"]["id"] == BYO_OCI_LANE
    assert receipt["lane_contract"]["requires_payment"] is False
    assert receipt["lane_contract"]["managed_worker_dispatch_allowed"] is False
    assert (
        receipt["lane_contract"]["user_owned_cost_boundary"]["spend_owner"]
        == "user_oci_tenancy"
    )
    assert (
        receipt["lane_contract"]["user_owned_cost_boundary"][
            "fusekit_managed_infrastructure_spend"
        ]
        is False
    )
    assert (
        receipt["lane_contract"]["security_contract"]["runner_architecture"]
        == "amd_x86_64_only"
    )
    assert receipt["lane_contract"]["security_contract"]["runner_profile"] == {
        "provider": "oracle-cloud-infrastructure",
        "runner": "oci-existing",
        "shape": "VM.Standard.E5.Flex",
        "shape_family": "standard-e5",
        "architecture": "amd64/x86_64",
        "arm_allowed": False,
        "visual_runner": "novnc",
    }
    assert (
        receipt["lane_contract"]["security_contract"]["hosted_worker_secret_exported"]
        is False
    )
    assert "live_acceptance_report" in receipt["lane_contract"]["security_contract"][
        "completion_claim_requires"
    ]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_byo_bootstrap_publishes_preflight_and_reversibility_contract() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )

    bootstrap = hosted_byo_oci_bootstrap(job)
    serialized = json.dumps(bootstrap)

    assert bootstrap["handoff_preflight"]["schema_version"] == (
        HOSTED_BYO_OCI_HANDOFF_PREFLIGHT_SCHEMA_VERSION
    )
    assert bootstrap["handoff_preflight"]["must_be_visible_before_cloud_shell"] is True
    assert bootstrap["handoff_preflight"]["cost_acknowledgement"] == {
        "required": True,
        "spend_owner": "user_oci_tenancy",
        "fusekit_fee": "none_for_byo_oci",
        "oracle_billing_gate_owner": "oracle_cloud",
        "statement": (
            "Starting BYO OCI can create Oracle Cloud resources in the user's tenancy; "
            "FuseKit-managed infrastructure spend remains zero."
        ),
    }
    preflight_ids = {check["id"] for check in bootstrap["handoff_preflight"]["checks"]}
    assert preflight_ids == {
        "review_oracle_billing",
        "confirm_amd_shape",
        "keep_human_gates_human",
        "return_redacted_proof",
    }
    assert bootstrap["reversibility"]["schema_version"] == (
        HOSTED_BYO_OCI_REVERSIBILITY_SCHEMA_VERSION
    )
    assert bootstrap["reversibility"]["detonation_required"] is True
    assert bootstrap["reversibility"]["rollback_metadata_required"] is True
    assert bootstrap["reversibility"]["completion_receipt"] == (
        ".fusekit/workspace_detonation.json"
    )
    assert "disposable OCI compute instance" in bootstrap["reversibility"]["delete_targets"]
    assert "encrypted vault" in bootstrap["reversibility"]["survivors"]
    assert "workspace detonation proof" in bootstrap["reversibility"]["statement"]
    assert bootstrap["proof_manifest"]["schema_version"] == (
        HOSTED_BYO_OCI_PROOF_MANIFEST_SCHEMA_VERSION
    )
    assert bootstrap["proof_manifest"]["proof_bundle_root"] == ".fusekit/remote-artifacts"
    assert bootstrap["proof_manifest"]["required_completion_evidence"] == [
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "rollback_metadata",
        "retrieved_remote_artifacts",
        "run_record",
        "detonation_receipt",
        "live_acceptance_report",
        "recording",
    ]
    manifest_artifacts = bootstrap["proof_manifest"]["required_remote_artifacts"]
    assert {
        (artifact["path"], artifact["label"], artifact["secret_boundary"])
        for artifact in manifest_artifacts
    } >= {
        (
            ".fusekit/run_record.json",
            "central Run Record",
            "redacted_public_artifact_only",
        ),
        (
            ".fusekit/rollback_plan.json",
            "rollback metadata",
            "redacted_public_artifact_only",
        ),
        (
            ".fusekit/workspace_detonation.json",
            "workspace detonation receipt",
            "redacted_public_artifact_only",
        ),
        (
            ".fusekit/acceptance_report.json",
            "live acceptance report",
            "redacted_public_artifact_only",
        ),
    }
    assert all(artifact["required"] is True for artifact in manifest_artifacts)
    assert bootstrap["proof_manifest"]["acceptance_gate"] == {
        "mode": "live",
        "remote_artifacts": ".fusekit/remote-artifacts",
        "require_recording": True,
        "command": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
    }
    assert bootstrap["proof_return"]["verifier_contract"] == {
        "input_schema": HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION,
        "output_schema": HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION,
        "requires_job_binding": True,
        "job_binding_fields": [
            "job_id",
            "lane",
            "github_source_hash",
            "plan_fingerprint",
        ],
        "requires_redacted_artifacts": True,
        "requires_completion_evidence": [
            "live_url",
            "provider_verifiers",
            "dns_propagation",
            "rollback_metadata",
            "retrieved_remote_artifacts",
            "run_record",
            "detonation_receipt",
            "live_acceptance_report",
            "recording",
        ],
    }
    assert "worker-local paths are not allowed" in bootstrap["proof_manifest"][
        "secret_boundary"
    ]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "sk_live" not in serialized


def test_hosted_byo_bootstrap_rejects_secret_text_in_public_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )

    def secret_cloud_shell_plan(**_kwargs: object) -> CloudShellLaunchPlan:
        return CloudShellLaunchPlan(
            app_source="https://github.com/example/one",
            fusekit_package="fusekit",
            launch_args=(),
            deeplink_url="https://cloud.oracle.com/?cloudshell=true",
            bootstrap_command="printf '%s' ghs_secret_token_should_not_render",
            fallback_steps=("Paste ghs_secret_token_should_not_render.",),
        )

    monkeypatch.setattr(
        "fusekit.hosted.job.build_cloud_shell_launch_plan",
        secret_cloud_shell_plan,
    )

    with pytest.raises(FuseKitError, match="bootstrap contains private material"):
        hosted_byo_oci_bootstrap(job)


def test_hosted_byo_bootstrap_renders_browser_handoff_page() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )

    html = render_hosted_byo_oci_bootstrap(job, job_token="signed-public-job")
    script_match = re.search(
        r'<script id="fusekit-byo-oci-bootstrap" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert "BYO OCI handoff." in html
    assert "Open Oracle Cloud Shell" in html
    assert "Review Oracle Cloud billing status" in html
    assert "FuseKit fee: none_for_byo_oci" in html
    assert "Confirm the bootstrap uses the AMD/x86_64 runner profile." in html
    assert "workspace detonation proof" in html
    assert "Proof Manifest" in html
    assert ".fusekit/remote-artifacts" in html
    assert "central Run Record" in html
    assert "live acceptance report" in html
    assert "redacted_public_artifact_only" in html
    assert "Download bootstrap JSON" in html
    assert "Back to control room" in html
    assert "fusekit.hosted-byo-oci-bootstrap.v1" in html
    assert "fusekit launch" in html
    assert "--oci-shape VM.Standard.E5.Flex" in html
    assert "cloud.oracle.com" in html
    assert script_match is not None
    script_payload = script_match.group(1)
    assert "&quot;" not in script_payload
    assert "</script" not in script_payload.lower()
    bootstrap = json.loads(script_payload)
    assert bootstrap["schema_version"] == "fusekit.hosted-byo-oci-bootstrap.v1"
    assert bootstrap["lane"] == BYO_OCI_LANE
    assert bootstrap["runner_profile"]["architecture"] == "amd64/x86_64"
    assert "ghs_" not in html
    assert "PRIVATE KEY" not in html
    assert "sk_live" not in html


def test_hosted_byo_bootstrap_exposes_proof_job_binding_contract() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    proof_return = bootstrap["proof_return"]
    assert isinstance(proof_return, dict)
    verifier = proof_return["verifier_contract"]
    assert isinstance(verifier, dict)

    assert verifier["requires_job_binding"] is True
    assert verifier["job_binding_fields"] == [
        "job_id",
        "lane",
        "github_source_hash",
        "plan_fingerprint",
    ]
    assert bootstrap["proof_manifest"]["job_binding"] == {
        "job_id": "hosted-byo",
        "lane": BYO_OCI_LANE,
        "github_source_hash": (
            "sha256:29c7eead948068a33f22cc20a2dc46cd46721f2842706856d10acf37c03b1c30"
        ),
        "plan_fingerprint": job.worker_contract.plan_fingerprint,
    }


def test_hosted_byo_proof_bundle_verifier_accepts_complete_redacted_inventory() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["schema_version"] == HOSTED_BYO_OCI_PROOF_VERIFY_SCHEMA_VERSION
    assert report["input_schema_version"] == HOSTED_BYO_OCI_PROOF_BUNDLE_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blockers"] == []
    assert report["job_binding"] == bootstrap["proof_manifest"]["job_binding"]
    assert report["user_owned_cost_boundary"] == byo_oci_user_owned_cost_boundary()
    assert report["byo_security_contract"] == byo_oci_security_contract()
    assert report["proof_bundle_root"] == ".fusekit/remote-artifacts"
    assert report["artifact_summary"]["missing"] == []
    assert report["artifact_summary"]["unexpected"] == []
    assert report["artifact_summary"]["present_required_count"] == report[
        "artifact_summary"
    ]["required_count"]
    assert all(report["completion_evidence"].values())
    assert "ghs_" not in serialized
    assert "sk_live" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_byo_proof_bundle_verifier_blocks_missing_job_binding() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    bundle.pop("job_binding")

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_job_binding_invalid" in report["blockers"]
    assert "byo_oci_proof_bundle_job_id_mismatch" in report["blockers"]
    assert "byo_oci_proof_bundle_github_source_hash_mismatch" in report["blockers"]
    assert "byo_oci_proof_bundle_plan_fingerprint_mismatch" in report["blockers"]


def test_hosted_byo_proof_bundle_verifier_blocks_replayed_job_binding() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    other_job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo-other",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(other_job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_job_id_mismatch" in report["blockers"]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_byo_proof_bundle_verifier_blocks_source_and_plan_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    binding = bundle["job_binding"]
    assert isinstance(binding, dict)
    binding["github_source_hash"] = "sha256:" + ("b" * 64)
    binding["plan_fingerprint"] = "sha256:" + ("c" * 64)

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_github_source_hash_mismatch" in report["blockers"]
    assert "byo_oci_proof_bundle_plan_fingerprint_mismatch" in report["blockers"]


def test_hosted_byo_proof_bundle_verifier_blocks_malformed_job_binding_hashes() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    binding = bundle["job_binding"]
    assert isinstance(binding, dict)
    binding["github_source_hash"] = "sha256:not-a-real-digest"
    binding["plan_fingerprint"] = "sha256:also-not-a-real-digest"

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_github_source_hash_invalid" in report["blockers"]
    assert "byo_oci_proof_bundle_plan_fingerprint_invalid" in report["blockers"]
    assert "byo_oci_proof_bundle_github_source_hash_mismatch" in report["blockers"]
    assert "byo_oci_proof_bundle_plan_fingerprint_mismatch" in report["blockers"]
    assert report["job_binding"] == {
        "job_id": "hosted-byo",
        "lane": BYO_OCI_LANE,
    }


def test_hosted_byo_proof_bundle_verifier_blocks_cost_and_security_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    cost_boundary = bundle["user_owned_cost_boundary"]
    security_contract = bundle["byo_security_contract"]
    assert isinstance(cost_boundary, dict)
    assert isinstance(security_contract, dict)
    cost_boundary["spend_owner"] = "fusekit_managed_infrastructure"
    security_contract["runner_architecture"] = "arm64"

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_user_owned_cost_boundary_mismatch" in report["blockers"]
    assert "byo_oci_proof_bundle_byo_security_contract_mismatch" in report["blockers"]
    assert report["user_owned_cost_boundary"] == {}
    assert report["byo_security_contract"] == {}


def test_hosted_byo_proof_bundle_verifier_strips_contract_sidecars() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    cost_boundary = bundle["user_owned_cost_boundary"]
    security_contract = bundle["byo_security_contract"]
    assert isinstance(cost_boundary, dict)
    assert isinstance(security_contract, dict)
    cost_boundary["worker_region"] = "us-ashburn-1"
    security_contract["console_session_label"] = "operator-reviewed"

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert (
        "byo_oci_proof_bundle_user_owned_cost_boundary_unexpected_field:worker_region"
        in report["blockers"]
    )
    assert (
        "byo_oci_proof_bundle_byo_security_contract_unexpected_field:console_session_label"
        in report["blockers"]
    )
    assert report["user_owned_cost_boundary"] == byo_oci_user_owned_cost_boundary()
    assert report["byo_security_contract"] == byo_oci_security_contract()
    assert "us-ashburn-1" not in serialized
    assert "operator-reviewed" not in serialized


def test_hosted_byo_proof_bundle_verifier_blocks_missing_cost_and_security_contracts() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    bundle.pop("user_owned_cost_boundary")
    bundle.pop("byo_security_contract")

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_user_owned_cost_boundary_invalid" in report["blockers"]
    assert "byo_oci_proof_bundle_byo_security_contract_invalid" in report["blockers"]
    assert report["user_owned_cost_boundary"] == {}
    assert report["byo_security_contract"] == {}


def test_hosted_byo_proof_bundle_verifier_blocks_missing_and_unsafe_inventory() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifacts.pop()
    artifacts.append(
        {
            "path": "../worker.log",
            "label": "worker log with ghs_not_real_token",
            "sha256": "not-a-hash",
            "size_bytes": -1,
            "redacted": False,
        }
    )
    evidence = bundle["completion_evidence"]
    assert isinstance(evidence, dict)
    evidence["recording"] = False

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert any(str(blocker).startswith("missing_artifact:") for blocker in report["blockers"])
    assert "artifact_path_invalid" in " ".join(str(blocker) for blocker in report["blockers"])
    assert "missing_completion_evidence:recording" in report["blockers"]
    assert "ghs_not_real_token" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_byo_proof_bundle_verifier_blocks_unsafe_artifact_label_and_hash() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifact = artifacts[0]
    assert isinstance(artifact, dict)
    path = str(artifact["path"])
    artifact["label"] = "run record ghs_not_real_token"
    artifact["sha256"] = "sha256:" + ("a" * 63) + "sk_live_not_real"

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert f"artifact_label_unsafe:{path}" in report["blockers"]
    assert f"artifact_sha256_unsafe:{path}" in report["blockers"]
    assert f"artifact_label_mismatch:{path}" in report["blockers"]
    assert f"artifact_sha256_invalid:{path}" in report["blockers"]
    assert "ghs_not_real_token" not in serialized
    assert "sk_live_not_real" not in serialized


def test_hosted_byo_proof_bundle_verifier_redacts_mismatched_label_and_invalid_hash() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifact = artifacts[0]
    assert isinstance(artifact, dict)
    path = str(artifact["path"])
    artifact["label"] = "operator note with raw log summary"
    artifact["sha256"] = "not-a-sha-label"

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)
    artifact_summary = report["artifact_summary"]
    assert isinstance(artifact_summary, dict)
    public_artifacts = artifact_summary["artifacts"]
    assert isinstance(public_artifacts, list)
    public_artifact = next(
        item for item in public_artifacts if isinstance(item, dict) and item["path"] == path
    )

    assert report["ready"] is False
    assert f"artifact_label_mismatch:{path}" in report["blockers"]
    assert f"artifact_sha256_invalid:{path}" in report["blockers"]
    assert public_artifact["label"] == ""
    assert public_artifact["sha256"] == ""
    assert "operator note with raw log summary" not in serialized
    assert "not-a-sha-label" not in serialized


def test_hosted_byo_proof_bundle_verifier_blocks_empty_required_artifacts() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifact = next(
        item
        for item in artifacts
        if isinstance(item, dict) and item["path"] == ".fusekit/run_record.json"
    )
    artifact["size_bytes"] = 0

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "artifact_empty:.fusekit/run_record.json" in report["blockers"]


def test_hosted_byo_proof_bundle_verifier_rejects_boolean_artifact_size() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifact = next(
        item
        for item in artifacts
        if isinstance(item, dict) and item["path"] == ".fusekit/run_record.json"
    )
    artifact["size_bytes"] = True

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is False
    assert "artifact_size_invalid:.fusekit/run_record.json" in report["blockers"]
    assert "artifact_empty:.fusekit/run_record.json" in report["blockers"]


def test_hosted_byo_proof_bundle_verifier_allows_empty_gate_event_stream() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    artifact = next(
        item
        for item in artifacts
        if isinstance(item, dict) and item["path"] == ".fusekit/gate_events.jsonl"
    )
    artifact["size_bytes"] = 0

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)

    assert report["ready"] is True
    assert "artifact_empty:.fusekit/gate_events.jsonl" not in report["blockers"]


def test_hosted_byo_proof_bundle_verifier_blocks_sidecar_fields() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    bundle["raw_worker_log"] = "not-allowed-here"
    binding = bundle["job_binding"]
    assert isinstance(binding, dict)
    binding["worker_ocid"] = "redacted-but-still-not-allowed"
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    first_artifact = artifacts[0]
    assert isinstance(first_artifact, dict)
    first_artifact["local_path"] = "/home/opc/app/.fusekit/run_record.json"
    evidence = bundle["completion_evidence"]
    assert isinstance(evidence, dict)
    evidence["oci_console_session"] = True

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_unexpected_field:raw_worker_log" in report["blockers"]
    assert (
        "byo_oci_proof_bundle_job_binding_unexpected_field:worker_ocid"
        in report["blockers"]
    )
    assert "artifact_row_unexpected_field:0:local_path" in report["blockers"]
    assert "completion_evidence_unexpected_field:oci_console_session" in report["blockers"]
    assert "not-allowed-here" not in serialized
    assert "redacted-but-still-not-allowed" not in serialized
    assert "/home/opc/app/.fusekit/run_record.json" not in serialized


def test_hosted_byo_proof_bundle_redacts_secret_like_sidecar_field_names() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    bootstrap = hosted_byo_oci_bootstrap(job)
    bundle = _byo_proof_bundle_from_bootstrap(bootstrap)
    bundle["sk_live_should_not_be_a_field"] = "not-rendered"
    binding = bundle["job_binding"]
    assert isinstance(binding, dict)
    binding["ghs_should_not_be_a_field"] = "not-rendered"
    artifacts = bundle["artifacts"]
    assert isinstance(artifacts, list)
    first_artifact = artifacts[0]
    assert isinstance(first_artifact, dict)
    first_artifact["sk_live_artifact_field"] = "not-rendered"
    first_artifact["path"] = ".fusekit/sk_live_hidden_path.json"
    evidence = bundle["completion_evidence"]
    assert isinstance(evidence, dict)
    evidence["ghs_should_not_be_evidence"] = True

    report = verify_hosted_byo_oci_proof_bundle(job, bundle)
    serialized = json.dumps(report, sort_keys=True)

    assert report["ready"] is False
    assert "byo_oci_proof_bundle_unexpected_field:redacted" in report["blockers"]
    assert "byo_oci_proof_bundle_job_binding_unexpected_field:redacted" in report[
        "blockers"
    ]
    assert "artifact_row_unexpected_field:0:redacted" in report["blockers"]
    assert "artifact_path_invalid:0" in report["blockers"]
    assert "completion_evidence_unexpected_field:redacted" in report["blockers"]
    assert "sk_live" not in serialized
    assert "ghs_" not in serialized
    assert "not-rendered" not in serialized


def test_hosted_worker_request_binds_live_acceptance_and_no_secret_policy() -> None:
    job = build_hosted_launch_job(
        _plan(),
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    request = hosted_worker_request(started, now=1_700_000_002)
    serialized = json.dumps(request)

    assert request["schema_version"] == "fusekit.hosted-worker-request.v1"
    assert request["job_id"] == "hosted-test"
    assert request["github_source"] == "https://github.com/example/job-demo"
    assert request["claim_policy"]["runner"] == MANAGED_FUSEKIT_RUN_LANE
    assert request["claim_policy"]["github_installation_id"] == 42
    assert request["claim_policy"]["mode"] == "live"
    assert request["claim_policy"]["remote_artifacts_required"] is True
    assert request["claim_policy"]["recording_required"] is True
    assert "worker secrets" in request["secret_boundary"]
    assert "GitHub installation tokens" in request["secret_boundary"]
    assert "Stripe keys" in request["secret_boundary"]
    assert request["plan_integrity"] == started.worker_contract.plan_integrity()
    assert request["worker_contract"]["plan_integrity"] == (
        started.worker_contract.plan_integrity()
    )
    assert request["acceptance_gate"] == {
        "mode": "live",
        "remote_artifacts": ".fusekit/remote-artifacts",
        "require_recording": True,
        "command": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
    }
    assert "retrieved_remote_artifacts" in request["completion_requires"]
    assert "detonation_receipt" in request["completion_requires"]
    assert "recording" in request["completion_requires"]
    assert ".fusekit/run_record.json" in request["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in request["required_artifacts"]
    assert any("Do not bypass MFA" in item for item in request["prohibited"])
    assert any("retrieved artifacts" in item for item in request["prohibited"])
    assert "fraud" in request["prohibited"][0]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_request_rejects_private_material_before_rendering() -> None:
    job = build_hosted_launch_job(
        _plan(),
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    unsafe_contract = replace(
        started.worker_contract,
        approved_actions=("github.authorize", "ghs_should_not_leave_worker_request"),
    )
    unsafe_started = replace(started, worker_contract=unsafe_contract)

    with pytest.raises(FuseKitError, match="Hosted worker request contains private material"):
        hosted_worker_request(unsafe_started, now=1_700_000_002)


def test_hosted_reversal_playbook_links_known_github_installation_settings() -> None:
    job = build_hosted_launch_job(
        _plan(),
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = hosted_proof_receipt(job)
    html = render_hosted_proof_receipt(job, job_token="signed-public-job")
    revoke = next(
        item
        for item in receipt["reversal_playbook"]
        if item["control"] == "Revoke GitHub App installation"
    )
    serialized = json.dumps(receipt) + html

    assert revoke["action_url"] == "https://github.com/settings/installations/42"
    assert 'href="https://github.com/settings/installations/42"' in html
    assert "Open settings" in html
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_worker_claim_updates_job_and_writes_redacted_receipt() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(
        started,
        worker_id="worker-01<script>",
        now=1_700_000_002,
    )
    receipt = hosted_worker_claim_receipt(
        claimed,
        worker_id="worker-01<script>",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in claimed.to_dict()["steps"]}
    serialized = json.dumps(receipt) + json.dumps(claimed.to_dict())

    assert claimed.status == "worker_claimed"
    assert steps["worker.prepare"]["status"] == "done"
    assert "worker-01script" in steps["worker.prepare"]["proof"]
    assert steps["provider.gates"]["status"] == "waiting"
    assert steps["setup.execute"]["status"] == "waiting"
    assert receipt["schema_version"] == "fusekit.hosted-worker-claim.v1"
    assert receipt["job_id"] == "hosted-test"
    assert receipt["worker_id"] == "worker-01script"
    assert receipt["plan_integrity"] == claimed.worker_contract.plan_integrity()
    assert "provider_gate_events" in receipt["next_required_proof"]
    assert "detonation_receipt" in receipt["next_required_proof"]
    assert "recording" in receipt["next_required_proof"]
    assert "<script>" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "ghs_" not in serialized


def test_hosted_worker_id_redacts_secret_shaped_values() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(
        started,
        worker_id="sk_live_should_not_be_a_worker_id",
        now=1_700_000_002,
    )
    claim_receipt = hosted_worker_claim_receipt(
        claimed,
        worker_id="ghs_should_not_be_a_worker_id",
        now=1_700_000_003,
    )
    proof_receipt = hosted_worker_proof_receipt(
        claimed,
        _proof_payload(complete=False, completed_artifacts=[".fusekit/run_record.json"]),
        worker_id="ocid1.worker.should_not_be_a_worker_id",
        now=1_700_000_004,
    )
    steps = {step["id"]: step for step in claimed.to_dict()["steps"]}
    serialized = (
        json.dumps(claimed.to_dict(), sort_keys=True)
        + json.dumps(claim_receipt, sort_keys=True)
        + json.dumps(proof_receipt, sort_keys=True)
    )

    assert "Hosted worker hosted-worker claimed" in steps["worker.prepare"]["proof"]
    assert claim_receipt["worker_id"] == "hosted-worker"
    assert proof_receipt["worker_id"] == "hosted-worker"
    assert "sk_live" not in serialized
    assert "ghs_" not in serialized
    assert "ocid1." not in serialized


def test_hosted_public_receipt_builders_reject_private_material_drift() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)

    unsafe_started = replace(started, job_id="hosted-ghs_should_not_render")
    unsafe_claimed = replace(claimed, job_id="hosted-ghs_should_not_render")

    with pytest.raises(FuseKitError, match="Hosted action receipt contains private material"):
        hosted_job_action_receipt(unsafe_started, action="start", now=1_700_000_003)

    with pytest.raises(
        FuseKitError,
        match="Hosted worker claim receipt contains private material",
    ):
        hosted_worker_claim_receipt(
            unsafe_claimed,
            worker_id="worker-01",
            now=1_700_000_004,
        )

    with pytest.raises(
        FuseKitError,
        match="Hosted worker proof receipt contains private material",
    ):
        hosted_worker_proof_receipt(
            unsafe_claimed,
            _proof_payload(complete=False, completed_artifacts=[".fusekit/run_record.json"]),
            worker_id="worker-01",
            now=1_700_000_005,
        )


def test_hosted_worker_claim_rejects_unstarted_or_terminal_jobs() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)

    with pytest.raises(ValueError):
        claim_hosted_launch_job(job, worker_id="worker-01")

    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    with pytest.raises(ValueError):
        claim_hosted_launch_job(rollback, worker_id="worker-01")
    stopped = advance_hosted_launch_job(job, "stop", now=1_700_000_003)
    with pytest.raises(ValueError):
        claim_hosted_launch_job(stopped, worker_id="worker-01")


def _proof_payload(
    *,
    complete: bool,
    note: str = "",
    completed_artifacts: list[str] | None = None,
    rollback_execution_receipt: bool | None = None,
    post_rollback_verification: bool | None = None,
    workspace_detonation_receipt: bool | None = None,
    scratch_state_destroyed: bool | None = None,
    provider_auth_session_closed: bool | None = None,
    redacted_public_proof_preserved: bool | None = None,
) -> dict[str, object]:
    evidence = {
        "live_url": complete,
        "provider_verifiers": complete,
        "dns_propagation": complete,
        "rollback_metadata": complete,
        "retrieved_remote_artifacts": complete,
        "run_record": complete,
        "detonation_receipt": complete,
        "live_acceptance_report": complete,
        "recording": complete,
    }
    if rollback_execution_receipt is not None:
        evidence["rollback_execution_receipt"] = rollback_execution_receipt
    if post_rollback_verification is not None:
        evidence["post_rollback_verification"] = post_rollback_verification
    if workspace_detonation_receipt is not None:
        evidence["workspace_detonation_receipt"] = workspace_detonation_receipt
    if scratch_state_destroyed is not None:
        evidence["scratch_state_destroyed"] = scratch_state_destroyed
    if provider_auth_session_closed is not None:
        evidence["provider_auth_session_closed"] = provider_auth_session_closed
    if redacted_public_proof_preserved is not None:
        evidence["redacted_public_proof_preserved"] = redacted_public_proof_preserved
    return {
        "schema_version": "fusekit.hosted-worker-proof.v1",
        "evidence": evidence,
        "completed_artifacts": completed_artifacts or [],
        "note": note,
    }


def test_hosted_worker_proof_submission_updates_partial_job_without_completion() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    updated, receipt = apply_hosted_worker_proof(
        claimed,
        _proof_payload(
            complete=False,
            completed_artifacts=[
                ".fusekit/job.json",
                ".fusekit/run_record.json",
            ],
            note="Provider gates are waiting.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}
    serialized = json.dumps(receipt) + json.dumps(updated.to_dict())

    assert updated.status == "proof_submitted"
    assert receipt["schema_version"] == "fusekit.hosted-worker-proof-receipt.v1"
    assert receipt["completion_ready"] is False
    assert receipt["launch_lane"] == MANAGED_FUSEKIT_RUN_LANE
    assert receipt["lane_contract"]["id"] == MANAGED_FUSEKIT_RUN_LANE
    assert ".fusekit/acceptance_report.json" in receipt["missing_artifacts"]
    assert steps["setup.execute"]["status"] == "running"
    assert steps["proof.collect"]["status"] == "waiting"
    assert steps["rollback.ready"]["status"] == "waiting"
    assert steps["detonate.worker"]["status"] == "waiting"
    assert "Provider gates are waiting." in receipt["note"]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_proof_submission_can_mark_complete_only_with_full_evidence() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    updated, receipt = apply_hosted_worker_proof(
        claimed,
        _proof_payload(
            complete=True,
            completed_artifacts=list(claimed.worker_contract.required_artifacts),
            note="Live proof passed.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    proof_receipt = hosted_proof_receipt(updated)
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "complete"
    assert receipt["completion_ready"] is True
    assert receipt["missing_artifacts"] == []
    assert proof_receipt["completion_ready"] is True
    assert steps["provider.gates"]["status"] == "done"
    assert steps["setup.execute"]["status"] == "done"
    assert steps["proof.collect"]["status"] == "done"
    assert steps["rollback.ready"]["status"] == "done"
    assert steps["detonate.worker"]["status"] == "done"


def test_byo_worker_proof_requires_returned_proof_bundle_before_completion() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="byo-worker", now=1_700_000_002)

    updated, receipt = apply_hosted_worker_proof(
        claimed,
        _proof_payload(
            complete=True,
            completed_artifacts=list(claimed.worker_contract.required_artifacts),
            note="BYO live proof flags passed, bundle still pending.",
        ),
        worker_id="byo-worker",
        now=1_700_000_003,
    )
    serialized = json.dumps(receipt)

    assert updated.status == "proof_submitted"
    assert receipt["completion_ready"] is False
    assert receipt["byo_oci_proof_bundle"]["ready"] is False
    assert receipt["byo_oci_proof_bundle"]["blockers"] == [
        "byo_oci_proof_bundle_required_for_completion"
    ]
    assert ".fusekit/run_record.json" in receipt["byo_oci_proof_bundle"][
        "artifact_summary"
    ]["missing"]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_byo_worker_proof_can_complete_with_verified_proof_bundle() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="byo-worker", now=1_700_000_002)
    bootstrap = hosted_byo_oci_bootstrap(claimed)
    proof_payload = _proof_payload(
        complete=True,
        completed_artifacts=list(claimed.worker_contract.required_artifacts),
        note="BYO proof bundle and live acceptance passed.",
    )
    proof_payload["byo_oci_proof_bundle"] = _byo_proof_bundle_from_bootstrap(bootstrap)

    updated, receipt = apply_hosted_worker_proof(
        claimed,
        proof_payload,
        worker_id="byo-worker",
        now=1_700_000_003,
    )

    assert updated.status == "complete"
    assert receipt["completion_ready"] is True
    assert receipt["byo_oci_proof_bundle"]["ready"] is True
    assert receipt["byo_oci_proof_bundle"]["blockers"] == []
    assert receipt["byo_oci_proof_bundle"]["artifact_summary"]["missing"] == []


def test_byo_worker_proof_cannot_complete_with_replayed_proof_bundle() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    other_job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo-other",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="byo-worker", now=1_700_000_002)
    proof_payload = _proof_payload(
        complete=True,
        completed_artifacts=list(claimed.worker_contract.required_artifacts),
        note="BYO proof bundle was replayed from another job.",
    )
    proof_payload["byo_oci_proof_bundle"] = _byo_proof_bundle_from_bootstrap(
        hosted_byo_oci_bootstrap(other_job)
    )

    updated, receipt = apply_hosted_worker_proof(
        claimed,
        proof_payload,
        worker_id="byo-worker",
        now=1_700_000_003,
    )

    assert updated.status == "proof_submitted"
    assert receipt["completion_ready"] is False
    assert receipt["byo_oci_proof_bundle"]["ready"] is False
    assert "byo_oci_proof_bundle_job_id_mismatch" in receipt["byo_oci_proof_bundle"][
        "blockers"
    ]


def test_hosted_worker_proof_requires_rollback_execution_after_rollback_request() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)

    updated, receipt = apply_hosted_worker_proof(
        rollback,
        _proof_payload(
            complete=True,
            completed_artifacts=list(rollback.worker_contract.required_artifacts),
            note="Rollback metadata exists; execution proof is still pending.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "proof_submitted"
    assert receipt["completion_ready"] is False
    assert receipt["maintenance_ready"] is False
    assert receipt["maintenance_required_proof"] == [
        "rollback_execution_receipt",
        "post_rollback_verification",
    ]
    assert receipt["evidence"]["rollback_execution_receipt"] is False
    assert receipt["evidence"]["post_rollback_verification"] is False
    assert steps["rollback.ready"]["status"] == "waiting"
    assert "rollback execution receipt" in steps["rollback.ready"]["proof"]


def test_hosted_worker_proof_marks_rollback_request_complete_with_execution_proof() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)

    updated, receipt = apply_hosted_worker_proof(
        rollback,
        _proof_payload(
            complete=True,
            completed_artifacts=list(rollback.worker_contract.required_artifacts),
            rollback_execution_receipt=True,
            post_rollback_verification=True,
            note="Rollback execution and post-rollback verification passed.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "complete"
    assert receipt["completion_ready"] is True
    assert receipt["maintenance_ready"] is True
    assert receipt["evidence"]["rollback_execution_receipt"] is True
    assert receipt["evidence"]["post_rollback_verification"] is True
    assert steps["rollback.ready"]["status"] == "done"


def test_hosted_worker_proof_requires_detonation_action_proof_after_request() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    detonation = advance_hosted_launch_job(started, "detonate", now=1_700_000_002)

    updated, receipt = apply_hosted_worker_proof(
        detonation,
        _proof_payload(
            complete=True,
            completed_artifacts=list(detonation.worker_contract.required_artifacts),
            note="Detonation receipt exists; action proof is still pending.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "proof_submitted"
    assert receipt["completion_ready"] is False
    assert receipt["maintenance_ready"] is False
    assert receipt["maintenance_required_proof"] == [
        "workspace_detonation_receipt",
        "scratch_state_destroyed",
        "provider_auth_session_closed",
        "redacted_public_proof_preserved",
    ]
    assert receipt["evidence"]["workspace_detonation_receipt"] is False
    assert receipt["evidence"]["scratch_state_destroyed"] is False
    assert receipt["evidence"]["provider_auth_session_closed"] is False
    assert receipt["evidence"]["redacted_public_proof_preserved"] is False
    assert steps["detonate.worker"]["status"] == "waiting"
    assert "scratch cleanup" in steps["detonate.worker"]["proof"]


def test_hosted_worker_proof_marks_detonation_request_complete_with_action_proof() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    detonation = advance_hosted_launch_job(started, "detonate", now=1_700_000_002)

    updated, receipt = apply_hosted_worker_proof(
        detonation,
        _proof_payload(
            complete=True,
            completed_artifacts=list(detonation.worker_contract.required_artifacts),
            workspace_detonation_receipt=True,
            scratch_state_destroyed=True,
            provider_auth_session_closed=True,
            redacted_public_proof_preserved=True,
            note="Detonation action proof passed.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "complete"
    assert receipt["completion_ready"] is True
    assert receipt["maintenance_ready"] is True
    assert receipt["evidence"]["workspace_detonation_receipt"] is True
    assert receipt["evidence"]["scratch_state_destroyed"] is True
    assert receipt["evidence"]["provider_auth_session_closed"] is True
    assert receipt["evidence"]["redacted_public_proof_preserved"] is True
    assert steps["detonate.worker"]["status"] == "done"


def test_hosted_worker_proof_rejects_unknown_artifact_and_secret_text() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)

    with pytest.raises(ValueError):
        hosted_worker_proof_receipt(
            claimed,
            _proof_payload(complete=False, completed_artifacts=[".fusekit/not-real.json"]),
            worker_id="worker-01",
        )

    with pytest.raises(ValueError):
        hosted_worker_proof_receipt(
            claimed,
            _proof_payload(
                complete=False,
                note="Authorization: Bearer raw-provider-token",
            ),
            worker_id="worker-01",
        )


def test_hosted_worker_proof_rejects_top_level_sidecar_fields() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    payload = _proof_payload(
        complete=False,
        completed_artifacts=[".fusekit/run_record.json"],
    )
    payload["raw_worker_log"] = "not-allowed-here"

    with pytest.raises(ValueError, match="worker proof payload contains unsupported keys"):
        hosted_worker_proof_receipt(claimed, payload, worker_id="worker-01")


def test_managed_worker_proof_rejects_byo_proof_bundle_sidecar() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    byo_job = build_hosted_launch_job(
        _plan(),
        launch_lane=BYO_OCI_LANE,
        job_id="hosted-byo",
        now=1_700_000_000,
    )
    payload = _proof_payload(
        complete=False,
        completed_artifacts=[".fusekit/run_record.json"],
    )
    payload["byo_oci_proof_bundle"] = _byo_proof_bundle_from_bootstrap(
        hosted_byo_oci_bootstrap(byo_job)
    )

    with pytest.raises(ValueError, match="worker proof payload contains unsupported keys"):
        hosted_worker_proof_receipt(claimed, payload, worker_id="worker-01")


def test_hosted_control_room_embeds_redacted_job_json() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    action_receipt = hosted_job_action_receipt(started, action="start", now=1_700_000_002)
    html = render_hosted_control_room(
        started,
        action_receipt=action_receipt,
        dispatch_receipt={
            "schema_version": "fusekit.hosted-worker-dispatch.v1",
            "action": "start",
            "dispatched": False,
            "reason": "worker_dispatch_url_not_configured",
        },
    )
    match = re.search(
        r'<script id="fusekit-hosted-job" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert "Hosted launch control room." in html
    assert "Worker contract" in html
    assert "Redacted proof" in html
    assert "Reversible setup" in html
    assert "Request rollback" in html
    assert "Request detonation" in html
    assert "GitHub App installation" in html
    assert "Permission boundary" in html
    assert "backend worker" in html
    assert "Approved actions" in html
    assert "github.authorize" in html
    assert "drift requires a fresh approval" in html
    assert "Provider gates" in html
    assert "human-owned" in html
    assert ".fusekit/run_record.json" in html
    assert ".fusekit/workspace_detonation.json" in html
    assert "Latest protected action: start" in html
    assert "Next proof required" in html
    assert "Worker dispatch: not configured" in html
    assert "Detonation" in html
    assert "Protected controls unavailable" in html
    assert "short-lived" in html
    assert 'disabled aria-disabled="true">Request rollback</button>' in html
    assert "/api/hosted/jobs/hosted-test/actions/rollback?control=" not in html
    assert match is not None
    script_payload = match.group(1)
    assert "&quot;" not in script_payload
    assert "</script" not in script_payload.lower()
    payload = json.loads(script_payload)
    assert payload["schema_version"] == "fusekit.hosted-job.v1"
    assert payload["latest_action_receipt"]["action"] == "start"
    assert payload["worker_dispatch"]["reason"] == "worker_dispatch_url_not_configured"
    assert any("Request rollback" in item["control"] for item in payload["reversal_playbook"])
    assert any(
        "GitHub App installation" in item["control"]
        for item in payload["reversal_playbook"]
    )
    assert any(
        "selected repository" in item
        for item in payload["worker_contract"]["permission_boundary"]
    )
    assert "vercel.deploy_verify" in payload["worker_contract"]["approved_actions"]
    assert any("MFA" in gate for gate in payload["worker_contract"]["gates"])
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert "ghs_" not in json.dumps(payload)


def test_hosted_control_room_renders_real_controls_only_with_control_token() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    html = render_hosted_control_room(
        job,
        control_tokens={
            "start": "signed-start-control-token",
            "stop": "signed-stop-control-token",
            "rollback": "signed-rollback-control-token",
            "detonate": "signed-detonate-control-token",
        },
        job_token="signed-public-job",
    )

    assert "Protected controls unavailable" not in html
    assert (
        '<form method="post" enctype="application/x-www-form-urlencoded" '
        'action="/api/hosted/jobs/hosted-test/actions/start?job=signed-public-job">'
    ) in html
    assert (
        '<form method="post" enctype="application/x-www-form-urlencoded" '
        'action="/api/hosted/jobs/hosted-test/actions/stop?job=signed-public-job">'
    ) in html
    assert 'name="control" value="signed-start-control-token"' in html
    assert 'name="control" value="signed-stop-control-token"' in html
    assert "?control=" not in html
    assert (
        '<form method="post" enctype="application/x-www-form-urlencoded" '
        'action="/api/hosted/jobs/hosted-test/actions/rollback?job=signed-public-job">'
        not in html
    )
    assert (
        '<form method="post" enctype="application/x-www-form-urlencoded" '
        'action="/api/hosted/jobs/hosted-test/actions/detonate?job=signed-public-job">'
        not in html
    )
    assert 'name="control" value="signed-rollback-control-token"' not in html
    assert 'name="control" value="signed-detonate-control-token"' not in html
    assert "job=signed-public-job" in html
    assert 'disabled aria-disabled="true">Start worker</button>' not in html
    assert '<button type="submit">Start worker</button>' in html
    assert '<button type="submit">Stop launch</button>' in html


def test_hosted_launch_job_actions_record_truthful_waiting_states() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)

    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    detonation = advance_hosted_launch_job(rollback, "detonate", now=1_700_000_003)
    steps = {step["id"]: step for step in detonation.to_dict()["steps"]}

    assert started.status == "waiting_for_provider_gates"
    assert rollback.status == "rollback_requested"
    assert detonation.status == "detonation_requested"
    assert steps["provider.gates"]["status"] == "waiting"
    assert steps["rollback.ready"]["status"] == "waiting"
    assert steps["detonate.worker"]["status"] == "waiting"
    assert "waiting" in steps["detonate.worker"]["proof"].lower()
    assert detonation.worker_contract == job.worker_contract
    stopped = advance_hosted_launch_job(job, "stop", now=1_700_000_004)
    stopped_steps = {step["id"]: step for step in stopped.to_dict()["steps"]}
    assert stopped.status == "stopped"
    assert stopped_steps["worker.prepare"]["status"] == "waiting"
    assert "stopped before hosted worker start" in stopped_steps["worker.prepare"]["proof"]
    with pytest.raises(ValueError, match="can only start once"):
        advance_hosted_launch_job(started, "start", now=1_700_000_005)
    with pytest.raises(ValueError, match="only be stopped before worker start"):
        advance_hosted_launch_job(started, "stop", now=1_700_000_006)
    with pytest.raises(ValueError, match="rollback requires"):
        advance_hosted_launch_job(job, "rollback", now=1_700_000_007)
    with pytest.raises(ValueError, match="detonation requires"):
        advance_hosted_launch_job(job, "detonate", now=1_700_000_008)


def test_hosted_job_action_receipts_are_redacted_and_proof_oriented() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    stopped = advance_hosted_launch_job(job, "stop", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    detonation = advance_hosted_launch_job(rollback, "detonate", now=1_700_000_003)

    start_receipt = hosted_job_action_receipt(started, action="start", now=1_700_000_004)
    stop_receipt = hosted_job_action_receipt(stopped, action="stop", now=1_700_000_004)
    rollback_receipt = hosted_job_action_receipt(
        rollback,
        action="rollback",
        now=1_700_000_005,
    )
    detonation_receipt = hosted_job_action_receipt(
        detonation,
        action="detonate",
        now=1_700_000_006,
    )
    serialized = (
        json.dumps(start_receipt)
        + json.dumps(stop_receipt)
        + json.dumps(rollback_receipt)
        + json.dumps(detonation_receipt)
    )

    assert start_receipt["schema_version"] == "fusekit.hosted-job-action-receipt.v1"
    assert start_receipt["plan_integrity"] == started.worker_contract.plan_integrity()
    assert stop_receipt["plan_integrity"] == stopped.worker_contract.plan_integrity()
    assert rollback_receipt["plan_integrity"] == rollback.worker_contract.plan_integrity()
    assert detonation_receipt["plan_integrity"] == (
        detonation.worker_contract.plan_integrity()
    )
    assert start_receipt["next_required_proof"] == [
        "worker_claim",
        "provider_gate_events",
        "live_url",
        "provider_verifiers",
        "dns_propagation",
        "rollback_metadata",
        "retrieved_remote_artifacts",
        "run_record",
        "detonation_receipt",
        "live_acceptance_report",
        "recording",
    ]
    assert stop_receipt["status"] == "stopped"
    assert stop_receipt["next_required_proof"] == [
        "stop_receipt",
        "no_worker_claim_after_stop",
        "no_provider_mutation_after_stop",
        "redacted_public_proof_preserved",
    ]
    assert rollback_receipt["status"] == "rollback_requested"
    assert "rollback_execution_receipt" in rollback_receipt["next_required_proof"]
    assert detonation_receipt["status"] == "detonation_requested"
    assert "scratch_state_destroyed" in detonation_receipt["next_required_proof"]
    assert "MFA" in rollback_receipt["safeguards"][0]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_worker_contract_is_public_and_binds_approved_plan() -> None:
    contract = build_hosted_worker_contract(_plan(), github_installation_id=42)
    payload = contract.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["github_source"] == "https://github.com/example/job-demo"
    assert payload["github_installation_id"] == 42
    assert "Installation tokens are never embedded" in payload["source_token_policy"]
    assert payload["providers"] == ["github", "vercel"]
    assert payload["required_env"] == ["RESEND_API_KEY"]
    assert payload["plan_integrity"] == contract.plan_integrity()
    assert payload["plan_integrity"]["fingerprint"] == contract.plan_fingerprint
    assert payload["plan_integrity"]["covers"] == [
        "app_name",
        "github_source",
        "providers",
        "required_env",
        "approved_actions",
        "required_artifacts",
        "provider_gates",
        "worker_guarantees",
    ]
    assert "non-secret approved-plan metadata" in payload["plan_integrity"][
        "secret_boundary"
    ]
    assert any("contents:read" in item for item in payload["permission_boundary"])
    assert any("backend worker" in item for item in payload["permission_boundary"])
    assert payload["approved_actions"]
    assert ".fusekit/acceptance_report.json" in payload["required_artifacts"]
    assert any("Live acceptance" in guarantee for guarantee in payload["guarantees"])
    assert any("MFA" in gate for gate in payload["gates"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_launch_job_to_dict_rejects_private_material_drift() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    unsafe_proof = replace(job, proof=("worker token ghs_should_not_render",))

    with pytest.raises(FuseKitError, match="Hosted launch job contains private material"):
        unsafe_proof.to_dict()

    unsafe_payment = replace(
        job,
        payment_status="checkout_pending",
        payment_receipt={"secret": "sk_live_should_not_render"},
    )

    with pytest.raises(FuseKitError, match="Hosted launch job contains private material"):
        unsafe_payment.to_dict()


def test_hosted_worker_contract_rejects_boolean_github_installation_id() -> None:
    with pytest.raises(FuseKitError, match="github_installation_id"):
        build_hosted_worker_contract(_plan(), github_installation_id=True)

    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["github_installation_id"] = True

    with pytest.raises(FuseKitError, match="github_installation_id"):
        hosted_launch_job_from_dict(payload)


def test_hosted_worker_contract_decodes_older_public_payload_without_boundary() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract.pop("permission_boundary")

    decoded = hosted_launch_job_from_dict(payload)

    assert decoded.worker_contract.permission_boundary == ()
    assert decoded.worker_contract.plan_fingerprint == job.worker_contract.plan_fingerprint


def test_hosted_job_decode_rejects_top_level_sidecar_fields() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payload["private_note"] = "hidden hosted job sidecar"

    with pytest.raises(
        FuseKitError,
        match="Hosted launch job payload has unexpected fields: private_note",
    ):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_step_sidecar_fields() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    steps = payload["steps"]
    assert isinstance(steps, list)
    first = steps[0]
    assert isinstance(first, dict)
    first["worker_log"] = "sidecar log should not enter public status"

    with pytest.raises(
        FuseKitError,
        match="Hosted launch job step payload has unexpected fields: worker_log",
    ):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_worker_contract_sidecar_fields() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["github_installation_token"] = "ghs_should_not_be_public"

    with pytest.raises(
        FuseKitError,
        match=(
            "Hosted worker contract payload has unexpected fields: "
            "github_installation_token"
        ),
    ):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_lane_contract_drift() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    lane_contract = payload["lane_contract"]
    assert isinstance(lane_contract, dict)
    lane_contract["managed_worker_dispatch_allowed"] = False

    with pytest.raises(FuseKitError, match="Hosted launch lane contract is invalid"):
        hosted_launch_job_from_dict(payload)


def test_hosted_worker_contract_rejects_invalid_plan_integrity() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    plan_integrity = worker_contract["plan_integrity"]
    assert isinstance(plan_integrity, dict)
    plan_integrity["fingerprint"] = "sha256:not-a-real-digest"

    with pytest.raises(FuseKitError, match="plan_integrity fingerprint is invalid"):
        hosted_launch_job_from_dict(payload)


def test_hosted_worker_contract_rejects_plan_integrity_sidecars() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    plan_integrity = worker_contract["plan_integrity"]
    assert isinstance(plan_integrity, dict)
    plan_integrity["raw_plan_json"] = "sidecar plan data should not enter public token"

    with pytest.raises(
        FuseKitError,
        match="Hosted worker contract plan_integrity has unexpected fields: raw_plan_json",
    ):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_unknown_lane() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payload["launch_lane"] = "bring-your-own-oci-typo"

    with pytest.raises(FuseKitError, match="Hosted launch lane is invalid"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_secret_bearing_github_source() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payload["github_source"] = "https://ghs_should_not_be_public@github.com/example/job-demo"

    with pytest.raises(FuseKitError, match="Hosted GitHub source"):
        hosted_launch_job_from_dict(payload)

    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["github_source"] = (
        "https://github.com/example/job-demo?token=sk_live_hidden"
    )

    with pytest.raises(FuseKitError, match="Hosted GitHub source"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_secret_shaped_app_name() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payload["app_name"] = "ghs_should_not_be_public"

    with pytest.raises(FuseKitError, match="Hosted app name"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_secret_shaped_worker_contract_labels() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["providers"] = ["github", "sk_live_provider"]

    with pytest.raises(FuseKitError, match="Hosted provider name"):
        hosted_launch_job_from_dict(payload)

    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["required_env"] = ["RESEND_API_KEY", "sk_live_ENV"]

    with pytest.raises(FuseKitError, match="Hosted env name"):
        hosted_launch_job_from_dict(payload)

    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract["approved_actions"] = ["github.authorize", "sk_live.action"]

    with pytest.raises(FuseKitError, match="Hosted action id"):
        hosted_launch_job_from_dict(payload)


def test_hosted_payment_receipt_requires_full_checkout_shape_before_paid() -> None:
    price_id_hash = _public_hash("price_managed_run")
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        payment_price_id_hash=price_id_hash,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    payload = job.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    assert payment["price_id_hash"] == price_id_hash

    updated = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))

    assert updated.payment_status == "paid"
    assert updated.payment_receipt is not None
    assert updated.payment_receipt["checkout_session_id"] == "cs_test_paid"


def test_hosted_payment_receipt_rejects_paid_receipt_for_wrong_job_binding() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    receipt["client_reference_id"] = "hosted-other"

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_payment_receipt_rejects_paid_receipt_for_plan_or_label_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["plan_fingerprint"] = "sha256:" + ("0" * 64)

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        with_hosted_job_payment_receipt(job, receipt)

    receipt = _paid_checkout_receipt(job)
    receipt["price_label"] = "$2.00 FuseKit managed run"

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_payment_receipt_rejects_paid_receipt_for_price_hash_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        payment_price_id_hash=_public_hash("price_managed_run"),
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["stripe_price_id_hash"] = "sha256:" + ("0" * 64)

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_payment_receipt_rejects_malformed_hash_metadata() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["stripe_price_id_hash"] = "sha256:not-a-real-digest"

    with pytest.raises(FuseKitError, match="payment metadata hash is invalid"):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_payment_receipt_does_not_mark_paid_from_boolean_stub() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )

    updated = with_hosted_job_payment_receipt(job, {"paid": True})

    assert updated.payment_status == "checkout_pending"
    assert updated.payment_receipt is not None
    assert updated.payment_receipt["paid"] is False
    assert updated.payment_receipt["checkout_session_id"] is None


def test_hosted_payment_receipt_does_not_mark_paid_from_boolean_amount() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    receipt["amount_total"] = True

    updated = with_hosted_job_payment_receipt(job, receipt)

    assert updated.payment_status == "checkout_pending"
    assert updated.payment_receipt is not None
    assert updated.payment_receipt["paid"] is False
    assert updated.payment_receipt["amount_total"] is None


def test_hosted_job_decode_normalizes_pending_boolean_paid_stub() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    payload = job.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    payment["status"] = "checkout_pending"
    payment["receipt"] = {"paid": True}

    decoded = hosted_launch_job_from_dict(payload)

    assert decoded.payment_status == "checkout_pending"
    assert decoded.payment_receipt is not None
    assert decoded.payment_receipt["paid"] is False


def test_hosted_payment_receipt_rejects_unexpected_top_level_fields() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    receipt = _paid_checkout_receipt(job)
    receipt["payment_method"] = "pm_should_not_be_persisted"

    with pytest.raises(
        FuseKitError,
        match="Hosted launch payment receipt contains unexpected field",
    ):
        with_hosted_job_payment_receipt(job, receipt)


def test_hosted_job_decode_rejects_paid_status_without_paid_checkout_receipt() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    paid = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))
    payload = paid.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    receipt.pop("amount_total")

    with pytest.raises(FuseKitError, match="paid payment receipt is invalid"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_paid_receipt_binding_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    paid = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))
    payload = paid.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["github_source_hash"] = "sha256:" + ("0" * 64)

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_paid_receipt_price_hash_drift() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        payment_price_id_hash=_public_hash("price_managed_run"),
        job_id="hosted-test",
        now=1_700_000_000,
    )
    paid = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))
    payload = paid.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    assert payment["price_id_hash"] == _public_hash("price_managed_run")
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["stripe_price_id_hash"] = "sha256:" + ("0" * 64)

    with pytest.raises(FuseKitError, match="paid payment receipt does not match"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_malformed_payment_hash_metadata() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    paid = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))
    payload = paid.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    metadata["github_source_hash"] = "sha256:not-a-real-digest"

    with pytest.raises(FuseKitError, match="payment metadata hash is invalid"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_decode_rejects_unexpected_payment_receipt_fields() -> None:
    job = build_hosted_launch_job(
        _plan(),
        launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        payment_required=True,
        payment_price_label="Launch validation: $1.00 FuseKit managed run",
        job_id="hosted-test",
        now=1_700_000_000,
    )
    paid = with_hosted_job_payment_receipt(job, _paid_checkout_receipt(job))
    payload = paid.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    receipt = payment["receipt"]
    assert isinstance(receipt, dict)
    receipt["payment_method"] = "pm_should_not_be_persisted"

    with pytest.raises(
        FuseKitError,
        match="Hosted launch payment receipt contains unexpected field",
    ):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_rejects_ambiguous_payment_price_label() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payment = payload["payment"]
    assert isinstance(payment, dict)
    payment["price_label"] = "Launch validation: .00 FuseKit managed run"

    with pytest.raises(FuseKitError, match="payment price label is invalid"):
        hosted_launch_job_from_dict(payload)

    with pytest.raises(FuseKitError, match="payment receipt price label is invalid"):
        with_hosted_job_payment_receipt(
            job,
            {
                "schema_version": "fusekit.hosted-payment.v1",
                "provider": "stripe-checkout",
                "checkout_session_id": "cs_test_123",
                "status": "complete",
                "payment_status": "paid",
                "mode": "payment",
                "paid": True,
                "price_label": "Launch validation: .00 FuseKit managed run",
            },
        )


def test_hosted_job_token_round_trips_redacted_public_job() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = create_hosted_job_token("job-secret", job, now=1_700_000_001)
    verified = verify_hosted_job_token("job-secret", token, now=1_700_000_002)
    decoded = hosted_launch_job_from_dict(job.to_dict())
    serialized = json.dumps(verified.to_dict())

    assert verified == job
    assert decoded == job
    assert verified.worker_contract.plan_fingerprint == job.worker_contract.plan_fingerprint
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_job_token_rejects_tampering_and_expiry() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = create_hosted_job_token("job-secret", job, now=1_700_000_001)
    payload, signature = token.split(".", 1)

    with pytest.raises(FuseKitError):
        verify_hosted_job_token("job-secret", f"{payload}x.{signature}", now=1_700_000_002)

    with pytest.raises(FuseKitError):
        verify_hosted_job_token(
            "job-secret",
            token,
            now=1_700_100_000,
            ttl_seconds=60,
        )


def test_hosted_job_token_rejects_boolean_timestamp() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = _signed_job_token_payload(
        "job-secret",
        {
            "schema_version": "fusekit.hosted-job-token.v1",
            "issued_at": True,
            "job": job.to_dict(),
        },
    )

    with pytest.raises(FuseKitError, match="timestamp"):
        verify_hosted_job_token("job-secret", token, now=1_700_000_002)


def test_hosted_launch_job_rejects_boolean_created_at() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    payload["created_at"] = True

    with pytest.raises(FuseKitError, match="created_at"):
        hosted_launch_job_from_dict(payload)


def test_hosted_job_token_rejects_signed_sidecar_fields() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = _signed_job_token_payload(
        "job-secret",
        {
            "schema_version": "fusekit.hosted-job-token.v1",
            "issued_at": 1_700_000_001,
            "job": job.to_dict(),
            "private_note": "signed sidecar should not enter public job token",
        },
    )

    with pytest.raises(
        FuseKitError,
        match="Hosted launcher job token payload has unexpected fields: private_note",
    ):
        verify_hosted_job_token("job-secret", token, now=1_700_000_002)


def _signed_job_token_payload(secret: str, payload: dict[str, object]) -> str:
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"
