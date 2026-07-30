from __future__ import annotations

import json
from pathlib import Path

from fusekit.hosted.managed_enablement import (
    HOSTED_MANAGED_ENABLEMENT_MAX_JSON_BYTES,
    HOSTED_MANAGED_ENABLEMENT_SCHEMA_VERSION,
    HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
    build_hosted_managed_enablement_report,
    enable_hosted_managed_runs,
    main,
)
from fusekit.hosted.runtime_secrets import (
    install_hosted_runtime_secret_file,
    verify_hosted_runtime_secret_file,
)

PRICE_ID = "price_1ToydUPZlsTa6iL323anyggA"
PRICE_LABEL = "Launch validation: $1.00 FuseKit managed run"
WEBHOOK_ID = "we_1TyZ5fPZlsTa6iL3Ss7rCfqB"
COMMIT_SHA = "644bbd848e2bddb0ad9782929cdec453d8356f1f"
RSA_PRIVATE_KEY_FIXTURE = (
    "-----BEGIN " "RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAsecretfixture\n"
    "-----END " "RSA PRIVATE KEY-----"
)


def test_managed_enablement_report_accepts_complete_redacted_proof() -> None:
    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=_live_checkout_proof(),
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_MANAGED_ENABLEMENT_SCHEMA_VERSION
    assert report["ready_to_enable"] is True
    assert report["blockers"] == []
    assert report["proof_summary"]["job_store_ready"] is True
    assert report["proof_summary"]["live_checkout_ready"] is True
    assert report["proof_summary"]["live_checkout_bound_to_current_deployment"] is True
    assert report["enablement_contract"]["requires_current_deployment_commit_binding"] is True
    assert "sk_live" not in serialized
    assert "whsec" not in serialized
    assert "card_number" not in serialized.lower()
    assert "payment_method" not in serialized.lower()


def test_managed_enablement_report_requires_live_checkout_and_job_store_proof() -> None:
    readiness = _hosted_readiness_report()
    readiness["job_store"]["writable"] = False
    live_checkout = _live_checkout_proof()
    live_checkout["worker_dispatch_acceptance"] = False

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=readiness,
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "hosted_job_store_not_ready" in report["blockers"]
    assert "live_checkout_worker_dispatch_acceptance_not_true" in report["blockers"]


def test_managed_enablement_report_rejects_stale_live_checkout_commit() -> None:
    live_checkout = _live_checkout_proof()
    live_checkout["expected_commit_sha"] = "0" * 40

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert report["proof_summary"]["live_checkout_bound_to_current_deployment"] is False
    assert "live_checkout_expected_commit_sha_mismatch" in report["blockers"]


def test_managed_enablement_report_rejects_live_checkout_sidecars() -> None:
    live_checkout = _live_checkout_proof()
    live_checkout["operator_note"] = "cached proof from supervised run"

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_proof_unexpected_fields" in report["blockers"]


def test_managed_enablement_report_rejects_live_checkout_proof_input_sidecars() -> None:
    live_checkout = _live_checkout_proof()
    proof_inputs = live_checkout["proof_inputs"]
    assert isinstance(proof_inputs, dict)
    proof_inputs["start_response_path"] = "/var/lib/fusekit/hosted-jobs/start.json"

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_proof_inputs_unexpected_fields" in report["blockers"]


def test_managed_enablement_report_requires_live_checkout_artifact_hashes() -> None:
    live_checkout = _live_checkout_proof()
    live_checkout.pop("proof_artifacts")

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_proof_artifacts_missing" in report["blockers"]


def test_managed_enablement_report_rejects_live_checkout_artifact_hash_drift() -> None:
    live_checkout = _live_checkout_proof()
    proof_artifacts = live_checkout["proof_artifacts"]
    assert isinstance(proof_artifacts, dict)
    proof_artifacts["webhook_receipt_sha256"] = "not-a-sha"
    proof_artifacts["debug_path"] = "/var/lib/fusekit/hosted-jobs/raw.json"

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_proof_artifacts_unexpected_fields" in report["blockers"]
    assert "live_checkout_webhook_receipt_sha256_invalid" in report["blockers"]


def test_managed_enablement_report_rejects_reused_live_checkout_artifact_hash() -> None:
    live_checkout = _live_checkout_proof()
    proof_artifacts = live_checkout["proof_artifacts"]
    assert isinstance(proof_artifacts, dict)
    proof_artifacts["managed_start_response_sha256"] = proof_artifacts[
        "webhook_receipt_sha256"
    ]

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_proof_artifact_sha256_duplicate" in report["blockers"]


def test_managed_enablement_report_binds_artifacts_to_live_checkout_job_id() -> None:
    live_checkout = _live_checkout_proof()
    proof_artifacts = live_checkout["proof_artifacts"]
    assert isinstance(proof_artifacts, dict)
    proof_artifacts["webhook_receipt"] = "hosted-other.stripe-webhook-receipt.json"
    proof_artifacts["managed_start_response"] = "hosted-other.managed-start-response.json"

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=live_checkout,
    )

    assert report["ready_to_enable"] is False
    assert "live_checkout_webhook_receipt_artifact_label_invalid" in report["blockers"]
    assert (
        "live_checkout_managed_start_response_artifact_label_invalid"
        in report["blockers"]
    )


def test_managed_enablement_report_requires_hosted_expected_commit_proof() -> None:
    hosted_verify = _hosted_verify_report()
    checks = hosted_verify["checks"]
    assert isinstance(checks, list)
    hosted_verify["checks"] = [
        check
        for check in checks
        if isinstance(check, dict) and check.get("id") != "hosted.expected_commit"
    ]

    report = build_hosted_managed_enablement_report(
        runtime_secret_verify=_runtime_secret_verify_report(),
        hosted_verify=hosted_verify,
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=_live_checkout_proof(),
    )

    assert report["ready_to_enable"] is False
    assert report["proof_summary"]["live_checkout_bound_to_current_deployment"] is False
    assert "hosted.expected_commit_not_ok" in report["blockers"]


def test_managed_enablement_write_requires_confirmation(tmp_path: Path) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    _write_runtime_file(runtime_file)

    report = enable_hosted_managed_runs(
        runtime_secret_file=str(runtime_file),
        runtime_secret_verify=verify_hosted_runtime_secret_file(path=str(runtime_file)),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=_live_checkout_proof(),
        execute=True,
        confirm_managed_enablement=False,
    )

    assert report["written"] is False
    assert "confirm_managed_enablement_required" in report["blockers"]
    assert "FUSEKIT_MANAGED_RUNS_ENABLED='0'" in runtime_file.read_text(encoding="utf-8")


def test_managed_enablement_can_write_enabled_flag_with_complete_proof(tmp_path: Path) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    _write_runtime_file(runtime_file)

    report = enable_hosted_managed_runs(
        runtime_secret_file=str(runtime_file),
        runtime_secret_verify=verify_hosted_runtime_secret_file(path=str(runtime_file)),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=_live_checkout_proof(),
        execute=True,
        confirm_managed_enablement=True,
    )
    text = runtime_file.read_text(encoding="utf-8")
    serialized = json.dumps(report)

    assert report["written"] is True
    assert report["ready_to_enable"] is True
    assert "FUSEKIT_MANAGED_RUNS_ENABLED='1'" in text
    assert "sk_live" not in serialized
    assert "whsec" not in serialized


def test_managed_enablement_execute_rejects_symlinked_runtime_file_before_parse(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    runtime_link = tmp_path / "hosted-secrets-link.env"
    _write_runtime_file(runtime_file)
    runtime_link.symlink_to(runtime_file)

    def fail_parse(_path: Path) -> tuple[dict[str, str], list[str]]:
        raise AssertionError("runtime file should not be parsed before preflight")

    monkeypatch.setattr(
        "fusekit.hosted.managed_enablement._parse_systemd_env_file",
        fail_parse,
    )

    report = enable_hosted_managed_runs(
        runtime_secret_file=str(runtime_link),
        runtime_secret_verify=verify_hosted_runtime_secret_file(path=str(runtime_file)),
        hosted_verify=_hosted_verify_report(),
        stripe_price_verify=_stripe_price_verify_report(),
        stripe_webhook_verify=_stripe_webhook_verify_report(),
        hosted_readiness=_hosted_readiness_report(),
        live_checkout_proof=_live_checkout_proof(),
        execute=True,
        confirm_managed_enablement=True,
    )

    assert report["written"] is False
    assert report["ready_to_enable"] is False
    assert "runtime_secret_file_preflight_not_ready" in report["blockers"]


def test_managed_enablement_main_reports_incomplete_proof(tmp_path: Path, capsys) -> None:
    paths = _proof_files(tmp_path)
    live_checkout = json.loads(paths["live_checkout"].read_text(encoding="utf-8"))
    live_checkout["ready"] = False
    paths["live_checkout"].write_text(json.dumps(live_checkout), encoding="utf-8")

    exit_code = main(
        [
            "--runtime-secret-verify-report",
            str(paths["runtime"]),
            "--hosted-verify-report",
            str(paths["hosted"]),
            "--stripe-price-verify-report",
            str(paths["price"]),
            "--stripe-webhook-verify-report",
            str(paths["webhook"]),
            "--hosted-readiness-report",
            str(paths["readiness"]),
            "--live-checkout-proof",
            str(paths["live_checkout"]),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["ready_to_enable"] is False
    assert "live_checkout_proof_not_ready" in payload["blockers"]


def test_managed_enablement_main_rejects_symlinked_proof_file(
    tmp_path: Path,
    capsys,
) -> None:
    paths = _proof_files(tmp_path)
    target = paths["runtime"]
    symlink = tmp_path / "runtime-link.json"
    symlink.symlink_to(target)
    paths["runtime"] = symlink

    exit_code = _run_main_with_paths(paths)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["ready_to_enable"] is False
    assert payload["error"] == "managed_enablement_proof_file_symlink"


def test_managed_enablement_main_rejects_oversized_proof_file(
    tmp_path: Path,
    capsys,
) -> None:
    paths = _proof_files(tmp_path)
    paths["runtime"].write_text(
        " " * (HOSTED_MANAGED_ENABLEMENT_MAX_JSON_BYTES + 1),
        encoding="utf-8",
    )

    exit_code = _run_main_with_paths(paths)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["ready_to_enable"] is False
    assert payload["error"] == "managed_enablement_proof_file_too_large"


def _run_main_with_paths(paths: dict[str, Path]) -> int:
    return main(
        [
            "--runtime-secret-verify-report",
            str(paths["runtime"]),
            "--hosted-verify-report",
            str(paths["hosted"]),
            "--stripe-price-verify-report",
            str(paths["price"]),
            "--stripe-webhook-verify-report",
            str(paths["webhook"]),
            "--hosted-readiness-report",
            str(paths["readiness"]),
            "--live-checkout-proof",
            str(paths["live_checkout"]),
        ]
    )


def _write_runtime_file(path: Path) -> None:
    report = install_hosted_runtime_secret_file(
        env={
            "FUSEKIT_HOSTED_ORIGIN": "https://fusekit.snowmanai.org",
            "FUSEKIT_GITHUB_APP_ID": "4197238",
            "FUSEKIT_GITHUB_APP_SLUG": "fusekit-launcher",
            "FUSEKIT_GITHUB_APP_PRIVATE_KEY": RSA_PRIVATE_KEY_FIXTURE,
            "FUSEKIT_HOSTED_STATE_SECRET": "state-secret-value-with-enough-entropy",
            "FUSEKIT_HOSTED_WORKER_SECRET": "worker-secret-value-with-enough-entropy",
            "FUSEKIT_HOSTED_WORKER_DISPATCH_URL": (
                "https://fusekit.snowmanai.org/worker-dispatch/dispatch"
            ),
            "FUSEKIT_STRIPE_SECRET_KEY": "sk_" "live_secretfixture",
            "FUSEKIT_STRIPE_PRICE_ID": PRICE_ID,
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL": PRICE_LABEL,
            "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
            "FUSEKIT_STRIPE_WEBHOOK_SECRET": "whsec_" "secretfixture",
        },
        output_path=str(path),
        execute=True,
    )
    assert report["written"] is True


def _proof_files(tmp_path: Path) -> dict[str, Path]:
    payloads = {
        "runtime": _runtime_secret_verify_report(),
        "hosted": _hosted_verify_report(),
        "price": _stripe_price_verify_report(),
        "webhook": _stripe_webhook_verify_report(),
        "readiness": _hosted_readiness_report(),
        "live_checkout": _live_checkout_proof(),
    }
    paths: dict[str, Path] = {}
    for name, payload in payloads.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths[name] = path
    return paths


def _runtime_secret_verify_report() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-runtime-secret-verify.v1",
        "ready": True,
        "ready_for_managed_payment_staging": True,
        "blockers": [],
        "stripe_runtime_env": {
            "FUSEKIT_MANAGED_RUNS_ENABLED": {
                "configured": True,
                "enabled": False,
                "must_remain_disabled": True,
            },
            "FUSEKIT_STRIPE_SECRET_KEY": {
                "configured": True,
                "account_mode": "live",
                "key_scope": "restricted",
            },
            "FUSEKIT_STRIPE_WEBHOOK_SECRET": {
                "configured": True,
                "valid_shape": True,
                "required_before_enablement": True,
            },
        },
    }


def _hosted_verify_report() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-deployment-verification.v1",
        "ready": True,
        "blocking_checks": [],
        "checks": [
            {"id": "hosted.home", "status": "ok"},
            {"id": "hosted.health", "status": "ok"},
            {"id": "hosted.readiness", "status": "ok"},
            {"id": "hosted.deployment", "status": "ok"},
            {
                "id": "hosted.expected_commit",
                "status": "ok",
                "expected_commit_sha": COMMIT_SHA,
                "actual_commit_sha": COMMIT_SHA,
            },
            {"id": "hosted.github_intake", "status": "ok"},
            {"id": "hosted.stripe_webhook_fail_closed", "status": "ok"},
            {"id": "worker_dispatch.health", "status": "ok"},
            {"id": "worker_dispatch.readiness", "status": "ok"},
        ],
    }


def _stripe_price_verify_report() -> dict[str, object]:
    return {
        "schema_version": "fusekit.stripe-managed-price-verify.v1",
        "ready": True,
        "account_mode": "live",
        "blockers": [],
        "price_id": PRICE_ID,
        "price_label": PRICE_LABEL,
        "checks": {
            "amount_matches": True,
            "currency_matches": True,
            "lookup_key_matches": True,
            "price_active": True,
            "price_id_matches": True,
            "price_is_one_time": True,
            "price_metadata_matches": True,
            "product_active": True,
            "product_expanded": True,
            "product_metadata_matches": True,
            "product_name_scoped": True,
        },
    }


def _stripe_webhook_verify_report() -> dict[str, object]:
    return {
        "schema_version": "fusekit.stripe-managed-webhook-verify.v1",
        "ready": True,
        "account_mode": "live",
        "blockers": [],
        "endpoint_url": "https://fusekit.snowmanai.org/api/hosted/payments/stripe-webhook",
        "webhook_endpoint_id": WEBHOOK_ID,
        "checks": {
            "enabled_events_match": True,
            "endpoint_enabled": True,
            "endpoint_id_matches": True,
            "endpoint_url_matches": True,
            "metadata_matches": True,
        },
    }


def _hosted_readiness_report() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-readiness.v1",
        "ready": True,
        "job_store": {
            "configured": True,
            "writable": True,
            "path_configured": True,
            "stores_public_snapshots_only": True,
        },
        "payment": {
            "enabled": False,
            "managed_runs_enabled": False,
            "account_mode": "live",
            "live_mode_configured": True,
            "price_configured": True,
            "price_label_configured": True,
        },
        "lane_readiness": {
            "lanes": {
                "managed-fusekit-run": {
                    "launchable": False,
                    "blocking_checks": ["managed_runs_not_enabled"],
                },
                "bring-your-own-oci": {"launchable": True, "blocking_checks": []},
            },
        },
    }


def _live_checkout_proof() -> dict[str, object]:
    return {
        "schema_version": HOSTED_MANAGED_LIVE_CHECKOUT_PROOF_SCHEMA_VERSION,
        "input_schema_version": "fusekit.hosted-managed-live-checkout-proof-input.v1",
        "ready": True,
        "blockers": [],
        "lane": "managed-fusekit-run",
        "job_id": "hosted-live-checkout-proof",
        "payment_status": "paid",
        "checkout_session_paid": True,
        "webhook_applied": True,
        "worker_dispatch_acceptance": True,
        "dispatch_requires_paid_checkout_session": True,
        "expected_commit_sha": COMMIT_SHA,
        "proof_inputs": {
            "webhook_receipt_schema": "fusekit.hosted-stripe-webhook.v1",
            "start_action_schema": "fusekit.hosted-job.v1",
            "worker_dispatch_schema": "fusekit.hosted-worker-dispatch.v1",
            "worker_dispatch_receiver_schema": (
                "fusekit.hosted-worker-dispatch-receipt.v1"
            ),
        },
        "proof_artifacts": {
            "webhook_receipt": "hosted-live-checkout-proof.stripe-webhook-receipt.json",
            "webhook_receipt_sha256": "sha256:" + ("1" * 64),
            "managed_start_response": (
                "hosted-live-checkout-proof.managed-start-response.json"
            ),
            "managed_start_response_sha256": "sha256:" + ("2" * 64),
            "live_checkout_proof": "live-checkout-proof.json",
        },
        "secret_boundary": (
            "Live Checkout proof contains no card data, Stripe keys, webhook signing "
            "secrets, worker secrets, provider credentials, or vault material."
        ),
    }
