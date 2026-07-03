from __future__ import annotations

import json

from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_INSTALL_SCHEMA_VERSION,
    HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION,
    build_hosted_runtime_secret_plan,
    install_hosted_runtime_secret_file,
    main,
)
from fusekit.security import contains_durable_secret_text


def _env(**overrides: str) -> dict[str, str]:
    value = {
        "FUSEKIT_HOSTED_ORIGIN": "https://fusekit.snowmanai.org",
        "FUSEKIT_GITHUB_APP_ID": "4197238",
        "FUSEKIT_GITHUB_APP_SLUG": "fusekit-launcher",
        "FUSEKIT_GITHUB_APP_PRIVATE_KEY": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEAsecretfixture\n"
            "-----END RSA PRIVATE KEY-----"
        ),
        "FUSEKIT_HOSTED_STATE_SECRET": "state-secret-value-with-enough-entropy",
        "FUSEKIT_HOSTED_WORKER_SECRET": "worker-secret-value-with-enough-entropy",
        "FUSEKIT_HOSTED_WORKER_DISPATCH_URL": "https://fusekit.snowmanai.org/dispatch",
        "FUSEKIT_STRIPE_SECRET_KEY": "sk_live_secretfixture",
        "FUSEKIT_STRIPE_PRICE_ID": "price_1ToydUPZlsTa6iL323anyggA",
        "FUSEKIT_MANAGED_RUN_PRICE_LABEL": "Launch validation: $1.00 FuseKit managed run",
        "FUSEKIT_MANAGED_RUNS_ENABLED": "0",
    }
    value.update(overrides)
    return value


def test_runtime_secret_plan_reports_readiness_without_secret_values() -> None:
    plan = build_hosted_runtime_secret_plan(env=_env())

    serialized = json.dumps(plan, sort_keys=True)
    assert plan["schema_version"] == HOSTED_RUNTIME_SECRET_PLAN_SCHEMA_VERSION
    assert plan["mode"] == "plan_only"
    assert plan["mutates_host"] is False
    assert plan["mutates_provider"] is False
    assert plan["ready_to_write_secret_file"] is True
    assert plan["ready_for_managed_payment_staging"] is True
    assert plan["blockers"] == []
    assert plan["secret_file"] == {
        "path": "/etc/fusekit/hosted-secrets.env",
        "owner": "root:root",
        "mode": "0600",
        "directory_owner": "root:root",
        "directory_mode": "0700",
    }
    assert plan["stripe_runtime_env"]["FUSEKIT_STRIPE_SECRET_KEY"] == {
        "configured": True,
        "account_mode": "live",
    }
    assert plan["stripe_runtime_env"]["FUSEKIT_STRIPE_PRICE_ID"]["public_id"] == (
        "price_1ToydUPZlsTa6iL323anyggA"
    )
    assert "sk_live_secretfixture" not in serialized
    assert "secretfixture" not in serialized
    assert "state-secret-value" not in serialized
    assert "worker-secret-value" not in serialized
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert not contains_durable_secret_text(serialized)


def test_runtime_secret_plan_can_treat_state_secrets_as_host_generated() -> None:
    env = _env(FUSEKIT_HOSTED_STATE_SECRET="", FUSEKIT_HOSTED_WORKER_SECRET="")

    plan = build_hosted_runtime_secret_plan(
        env=env,
        allow_generated_state_secrets=True,
    )

    assert plan["ready_to_write_secret_file"] is True
    assert plan["required_runtime_env"]["FUSEKIT_HOSTED_STATE_SECRET"] == {
        "configured": False,
        "generated_at_install": True,
        "source": "generated_on_host_install",
    }
    assert plan["required_runtime_env"]["FUSEKIT_HOSTED_WORKER_SECRET"] == {
        "configured": False,
        "generated_at_install": True,
        "source": "generated_on_host_install",
    }


def test_runtime_secret_plan_blocks_missing_required_values_and_managed_enabled() -> None:
    plan = build_hosted_runtime_secret_plan(
        env=_env(
            FUSEKIT_GITHUB_APP_PRIVATE_KEY="",
            FUSEKIT_HOSTED_WORKER_DISPATCH_URL="http://example.com/dispatch",
            FUSEKIT_MANAGED_RUNS_ENABLED="1",
        )
    )

    assert plan["ready_to_write_secret_file"] is False
    assert plan["ready_for_managed_payment_staging"] is False
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in plan["blockers"]
    assert "hosted_worker_dispatch_url_must_be_https_without_credentials" in plan["blockers"]
    assert "managed_runs_must_stay_disabled_until_checkout_proof" in plan["blockers"]


def test_runtime_secret_plan_cli_reads_env_json(tmp_path, capfd) -> None:
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps(_env()), encoding="utf-8")

    exit_code = main(["--env-json", str(env_path)])
    output = json.loads(capfd.readouterr().out)

    assert exit_code == 0
    assert output["schema_version"] == HOSTED_RUNTIME_SECRET_INSTALL_SCHEMA_VERSION
    assert output["mode"] == "plan_only"
    assert output["executed"] is False
    assert output["written"] is False
    assert output["ready_to_write_secret_file"] is True
    assert output["ready_for_managed_payment_staging"] is True


def test_runtime_secret_installer_writes_owner_only_env_file_without_public_values(
    tmp_path,
) -> None:
    output_path = tmp_path / "hosted-secrets.env"

    report = install_hosted_runtime_secret_file(
        env=_env(FUSEKIT_HOSTED_STATE_SECRET="", FUSEKIT_HOSTED_WORKER_SECRET=""),
        output_path=str(output_path),
        allow_generated_state_secrets=True,
        execute=True,
    )
    serialized = json.dumps(report, sort_keys=True)
    written = output_path.read_text(encoding="utf-8")

    assert report["schema_version"] == HOSTED_RUNTIME_SECRET_INSTALL_SCHEMA_VERSION
    assert report["mode"] == "write"
    assert report["mutates_host"] is True
    assert report["mutates_provider"] is False
    assert report["ready_to_write_secret_file"] is True
    assert report["ready_for_managed_payment_staging"] is True
    assert report["executed"] is True
    assert report["written"] is True
    assert report["generated_secret_names"] == [
        "FUSEKIT_HOSTED_STATE_SECRET",
        "FUSEKIT_HOSTED_WORKER_SECRET",
    ]
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in report["keys_written"]
    assert "FUSEKIT_MANAGED_RUNS_ENABLED" in report["keys_written"]
    assert "FUSEKIT_MANAGED_RUNS_ENABLED='0'" in written
    assert "FUSEKIT_HOSTED_STATE_SECRET='" in written
    assert "FUSEKIT_HOSTED_WORKER_SECRET='" in written
    assert "sk_live_secretfixture" in written
    assert "BEGIN RSA PRIVATE KEY" in written
    assert "sk_live_secretfixture" not in serialized
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert "state-secret-value" not in serialized
    assert not contains_durable_secret_text(serialized)


def test_runtime_secret_installer_does_not_write_when_blocked(tmp_path) -> None:
    output_path = tmp_path / "hosted-secrets.env"

    report = install_hosted_runtime_secret_file(
        env=_env(FUSEKIT_GITHUB_APP_PRIVATE_KEY=""),
        output_path=str(output_path),
        execute=True,
    )

    assert report["ready_to_write_secret_file"] is False
    assert report["written"] is False
    assert "FUSEKIT_GITHUB_APP_PRIVATE_KEY" in report["blockers"]
    assert not output_path.exists()
