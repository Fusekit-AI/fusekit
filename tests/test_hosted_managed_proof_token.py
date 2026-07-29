from __future__ import annotations

import json

from fusekit.hosted.managed_proof_token import (
    HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
    build_hosted_managed_proof_token_report,
)
from fusekit.hosted.session import verify_hosted_state_token


def test_managed_proof_helper_emits_purpose_bound_state_token() -> None:
    report = build_hosted_managed_proof_token_report(
        state_secret="hosted-state-secret",
        github_app_slug="fusekit-launcher",
        runtime_secret_verify=_runtime_secret_verify(),
        hosted_readiness=_hosted_readiness(),
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION
    assert report["ready"] is True
    assert report["blockers"] == []
    assert report["query_param"] == "state"
    assert report["state_token_present"] is True
    assert report["install_url_present"] is True
    assert "state_token" in report
    assert str(report["install_url"]).startswith(
        "https://github.com/apps/fusekit-launcher/installations/new?state="
    )
    assert "token" not in report
    assert "managed_proof" not in serialized
    state = verify_hosted_state_token(
        "hosted-state-secret",
        str(report["state_token"]),
    )
    assert state.managed_proof is True
    assert state.return_path == "/"
    assert "Stripe key" in str(report["secret_boundary"])


def test_managed_proof_helper_can_emit_redacted_preflight_without_click_token() -> None:
    report = build_hosted_managed_proof_token_report(
        state_secret="hosted-state-secret",
        github_app_slug="fusekit-launcher",
        runtime_secret_verify=_runtime_secret_verify(),
        hosted_readiness=_hosted_readiness(),
        include_token=False,
    )
    serialized = json.dumps(report)

    assert report["ready"] is True
    assert report["state_token_present"] is True
    assert report["install_url_present"] is True
    assert "state_token" not in report
    assert "install_url" not in report
    assert "hosted-state-secret" not in serialized


def test_managed_proof_helper_refuses_state_when_webhook_is_not_ready() -> None:
    runtime = _runtime_secret_verify()
    stripe = runtime["stripe_runtime_env"]
    assert isinstance(stripe, dict)
    stripe["FUSEKIT_STRIPE_WEBHOOK_SECRET"] = {
        "configured": False,
        "valid_shape": False,
        "required_before_enablement": True,
    }

    report = build_hosted_managed_proof_token_report(
        state_secret="hosted-state-secret",
        github_app_slug="fusekit-launcher",
        runtime_secret_verify=runtime,
        hosted_readiness=_hosted_readiness(),
    )

    assert report["ready"] is False
    assert report["state_token_present"] is False
    assert report["install_url_present"] is False
    assert report["state_token"] == ""
    assert report["install_url"] == ""
    assert report["blockers"] == ["stripe_webhook_secret_required_for_managed_proof"]


def _runtime_secret_verify() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-runtime-secret-verify.v1",
        "ready": True,
        "ready_for_managed_payment_staging": True,
        "blockers": [],
        "stripe_runtime_env": {
            "FUSEKIT_MANAGED_RUNS_ENABLED": {
                "configured": True,
                "must_remain_disabled": True,
                "enabled": False,
            },
            "FUSEKIT_STRIPE_WEBHOOK_SECRET": {
                "configured": True,
                "valid_shape": True,
                "required_before_enablement": True,
            },
        },
    }


def _hosted_readiness() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-readiness.v1",
        "ready": True,
        "blocking_checks": [],
        "payment": {
            "enabled": False,
            "managed_runs_enabled": False,
            "account_mode": "live",
            "live_mode_configured": True,
            "price_configured": True,
            "price_label_configured": True,
        },
        "job_store": {
            "configured": True,
            "writable": True,
            "path_configured": True,
            "stores_public_snapshots_only": True,
        },
        "lane_readiness": {
            "lanes": {
                "managed-fusekit-run": {
                    "launchable": False,
                    "blocking_checks": ["managed_runs_not_enabled"],
                },
                "bring-your-own-oci": {
                    "launchable": True,
                    "blocking_checks": [],
                },
            },
        },
    }
