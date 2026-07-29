from __future__ import annotations

import json
from pathlib import Path

from fusekit.hosted.managed_proof_token import (
    HOSTED_MANAGED_PROOF_TOKEN_MAX_JSON_BYTES,
    HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
    build_hosted_managed_proof_token_report,
    main,
)
from fusekit.hosted.runtime_secrets import install_hosted_runtime_secret_file
from fusekit.hosted.session import verify_hosted_state_token

RSA_PRIVATE_KEY_FIXTURE = (
    "-----BEGIN " "RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAsecretfixture\n"
    "-----END " "RSA PRIVATE KEY-----"
)


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


def test_managed_proof_cli_rejects_symlinked_runtime_file_before_parse(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    runtime_link = tmp_path / "hosted-secrets-link.env"
    _write_runtime_secret_file(runtime_file)
    runtime_link.symlink_to(runtime_file)

    def fail_parse(_path: Path) -> tuple[dict[str, str], list[str]]:
        raise AssertionError("runtime file should not be parsed before preflight")

    monkeypatch.setattr(
        "fusekit.hosted.managed_proof_token._parse_systemd_env_file",
        fail_parse,
    )

    exit_code = main(["--runtime-secret-file", str(runtime_link), "--redacted"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["error"] == "managed_proof_token_runtime_secret_file_preflight_not_ready"


def test_managed_proof_cli_rejects_symlinked_readiness_report(
    tmp_path: Path,
    capsys,
) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    readiness_file = tmp_path / "readiness.json"
    readiness_link = tmp_path / "readiness-link.json"
    _write_runtime_secret_file(runtime_file)
    readiness_file.write_text(json.dumps(_hosted_readiness()), encoding="utf-8")
    readiness_link.symlink_to(readiness_file)

    exit_code = main(
        [
            "--runtime-secret-file",
            str(runtime_file),
            "--hosted-readiness-report",
            str(readiness_link),
            "--redacted",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["error"] == "managed_proof_token_report_symlink"


def test_managed_proof_cli_rejects_oversized_readiness_report(
    tmp_path: Path,
    capsys,
) -> None:
    runtime_file = tmp_path / "hosted-secrets.env"
    readiness_file = tmp_path / "readiness.json"
    _write_runtime_secret_file(runtime_file)
    readiness_file.write_text(
        " " * (HOSTED_MANAGED_PROOF_TOKEN_MAX_JSON_BYTES + 1),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--runtime-secret-file",
            str(runtime_file),
            "--hosted-readiness-report",
            str(readiness_file),
            "--redacted",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["error"] == "managed_proof_token_report_too_large"


def _write_runtime_secret_file(path: Path) -> None:
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
            "FUSEKIT_STRIPE_PRICE_ID": "price_1ToydUPZlsTa6iL323anyggA",
            "FUSEKIT_MANAGED_RUN_PRICE_LABEL": (
                "Launch validation: $1.00 FuseKit managed run"
            ),
            "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
            "FUSEKIT_STRIPE_WEBHOOK_SECRET": "whsec_" "secretfixture",
        },
        output_path=str(path),
        execute=True,
    )
    assert report["written"] is True


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
