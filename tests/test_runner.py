from __future__ import annotations

import json
import subprocess
import tarfile
from pathlib import Path

from fusekit.rollback import execute_native_rollback, plan_rollback, start_over
from fusekit.runner.broker import resolve_runner
from fusekit.runner.cloud_shell import (
    build_cloud_shell_launch_plan,
    render_cloud_shell_launcher,
)
from fusekit.runner.control_room import render_control_room
from fusekit.runner.job import JobState
from fusekit.runner.loop import run_remote_loop
from fusekit.runner.oci import capture_oci_api_key_profile, prepare_oci_api_signing_key
from fusekit.runner.oci_live import (
    OciWorkspace,
    _load_oci_config_file,
    latest_workspace_from_vault,
)
from fusekit.runner.remote import (
    execute_remote_setup,
    render_cloud_init,
    should_include_app_path,
)
from fusekit.runner.server import control_room_payload
from fusekit.security import scan_for_secret_leaks
from fusekit.vault import Vault


def test_runner_auto_uses_local_for_explicit_rehearsal(tmp_path) -> None:
    resolution = resolve_runner("auto", allow_incomplete=True, oci_config_file=tmp_path / "nope")

    assert resolution.selected == "local"
    assert resolution.reason == "explicit local rehearsal"


def test_runner_auto_selects_cloud_shell_when_no_config(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)

    resolution = resolve_runner("auto", oci_config_file=tmp_path / "missing")

    assert resolution.selected == "oci-cloud-shell"


def test_cloud_shell_launcher_contains_deeplink_and_fallback_command() -> None:
    plan = build_cloud_shell_launch_plan(
        app_source="https://github.com/example/app.git",
        fusekit_package="git+https://github.com/example/fusekit.git",
        launch_args=(
            "--github-repo",
            "example/app",
            "--dns-zone",
            "example.com",
            "--infer-ui",
        ),
    )
    html = render_cloud_shell_launcher(plan)

    assert "cloud.oracle.com" in plan.deeplink_url
    assert "fusekit launch" in plan.bootstrap_command
    assert "https://github.com/example/app.git" in plan.bootstrap_command
    assert "git+https://github.com/example/fusekit.git" in plan.bootstrap_command
    assert "--github-repo example/app" in plan.bootstrap_command
    assert "--dns-zone example.com" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert plan.launch_args[-1] == "--infer-ui"
    assert "Copy Bootstrap Command" in html
    assert "Passphrase:" in plan.bootstrap_command


def test_oci_api_key_profile_is_encrypted_vault_material() -> None:
    vault = Vault.empty()
    public_key = prepare_oci_api_signing_key(vault)
    returned_public_key = capture_oci_api_key_profile(
        vault,
        config_snippet=(
            "[DEFAULT]\n"
            "tenancy=ocid1.tenancy.oc1..example\n"
            "user=ocid1.user.oc1..example\n"
            "fingerprint=aa:bb\n"
            "region=us-ashburn-1\n"
        ),
    )

    assert returned_public_key == public_key
    assert "BEGIN PUBLIC KEY" in public_key
    assert vault.require("runner.oci.profile").metadata["auth_mode"] == "api-key-upload"
    private_record = vault.require("runner.oci.api_signing_key.private")
    assert "BEGIN RSA PRIVATE KEY" in private_record.value
    assert "BEGIN RSA PRIVATE KEY" not in str(vault.public_index())


def test_control_room_renders_job_without_secrets(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("oci.authorize", "waiting", "OCI login required")
    job_path = tmp_path / "job.json"
    job.save(job_path)

    html = render_control_room(job)
    payload = control_room_payload(job_path)

    assert "FuseKit Control Room" in html
    assert "OCI login required" in html
    assert "fk-test" in html
    assert payload["id"] == "fk-test"


def test_remote_bootstrap_artifacts_are_self_contained() -> None:
    cloud_init = render_cloud_init(openclaw_install_url="https://openclaw.ai/install-cli.sh")
    git_cloud_init = render_cloud_init(
        fusekit_wheel_url="git+https://github.com/example/fusekit.git",
        openclaw_install_url="https://openclaw.ai/install-cli.sh",
    )

    assert "python3 -m pip install --upgrade fusekit" in cloud_init
    assert (
        "python3 -m pip install --upgrade "
        "git+https://github.com/example/fusekit.git"
    ) in git_cloud_init
    assert "python3 -m playwright install --with-deps chromium" in cloud_init
    assert "openclaw browser status" in cloud_init
    assert "fusekit-runner-verify" in cloud_init
    assert should_include_app_path(Path("src/index.js"))
    assert not should_include_app_path(Path(".env"))
    assert not should_include_app_path(Path(".fusekit/fusekit.vault.json"))


def test_latest_workspace_round_trips_from_vault() -> None:
    vault = Vault.empty()
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        public_ip="203.0.113.10",
        resource_ids={"instance": "ocid1.instance.oc1..example"},
    )
    vault.put(
        "runner.oci.fusekit-test.workspace",
        "runner_workspace",
        "oci",
        "workspace",
        json.dumps(workspace.to_dict()),
    )

    loaded = latest_workspace_from_vault(vault)

    assert loaded.shape == "VM.Standard3.Flex"
    assert loaded.public_ip == "203.0.113.10"


def test_remote_setup_uploads_executes_and_downloads_without_secret_paths(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log('ok')", encoding="utf-8")
    (app / ".env").write_text("SECRET=value", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "runner.oci.fusekit-test.ssh.private",
        "ssh_private_key",
        "oci",
        "runner key",
        "PRIVATE KEY",
    )
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="tenancy",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        public_ip="203.0.113.10",
    )
    calls: list[list[str]] = []

    def runner(
        command: list[str],
        *,
        input_text: str | None = None,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert input_text != "secret-passphrase" or "cat >" in command[-1]
        if stdout_path is not None:
            with tarfile.open(stdout_path, "w:gz"):
                pass
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = execute_remote_setup(
        workspace=workspace,
        vault=vault,
        app_path=app,
        local_output_dir=tmp_path / "out",
        passphrase="secret-passphrase",
        launch_args=("--github-repo", "owner/repo", "--infer-ui"),
        runner=runner,
    )

    assert result["output_dir"] == str(tmp_path / "out")
    assert any(command[0] == "scp" for command in calls)
    assert any(
        command[0] == "scp" and command[-1].endswith("/.fusekit/fusekit.vault.json")
        for command in calls
    )
    assert any("fusekit launch . --runner local --yes" in command[-1] for command in calls)
    assert any("--github-repo owner/repo --infer-ui" in command[-1] for command in calls)
    assert any(
        "trap 'rm -f /var/lib/fusekit-runner/passphrase' EXIT" in command[-1]
        for command in calls
    )


def test_cloud_shell_style_oci_config_uses_delegation_token_signer(
    tmp_path,
    monkeypatch,
) -> None:
    import oci

    class FakeSigner:
        tenancy_id = "ocid1.tenancy.oc1..cloudshell"
        region = "us-ashburn-1"

    def fake_from_file(path: str) -> dict[str, str]:
        assert path == str(tmp_path / "config")
        return {
            "authentication_type": "instance_principal",
            "delegation_token_file": str(tmp_path / "delegation-token"),
            "region": "us-ashburn-1",
        }

    def fake_get_signer_from_authentication_type(config: dict[str, str]) -> FakeSigner:
        assert config["authentication_type"] == "instance_principal"
        return FakeSigner()

    monkeypatch.setattr(oci.config, "from_file", fake_from_file)
    monkeypatch.setattr(
        oci.util,
        "get_signer_from_authentication_type",
        fake_get_signer_from_authentication_type,
    )

    auth = _load_oci_config_file(tmp_path / "config")

    assert auth.config["tenancy"] == "ocid1.tenancy.oc1..cloudshell"
    assert auth.config["region"] == "us-ashburn-1"
    assert isinstance(auth.signer, FakeSigner)


def test_secret_leak_scanner_reports_locations_without_values(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "config.txt").write_text("API_KEY=test-supersecretvalue123456\n", encoding="utf-8")

    findings = scan_for_secret_leaks(app)

    assert findings[0].path == "config.txt"
    assert findings[0].line == 1
    assert "supersecret" not in str([finding.to_dict() for finding in findings])


def test_rollback_and_start_over_are_redacted_and_preserve_vault(tmp_path) -> None:
    app = tmp_path / "app"
    fusekit = app / ".fusekit"
    fusekit.mkdir(parents=True)
    (fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {"action": "github.secret", "status": "ok"},
                    {"action": "vercel.env", "status": "ok"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (fusekit / "job.json").write_text("{}", encoding="utf-8")
    (fusekit / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")

    rollback = plan_rollback(fusekit / "setup_receipt.json")
    result = start_over(app)

    assert any(action.action == "rollback.github.secret" for action in rollback)
    assert "job.json" in " ".join(result["removed"])
    assert (fusekit / "fusekit.vault.json").exists()


def test_remote_loop_marks_job_done(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("passphrase", encoding="utf-8")
    job_path = tmp_path / "job.json"

    def fake_run(
        command: list[str],
        *,
        capture_output: bool,
        check: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    assert run_remote_loop(app_path=app, job_state=job_path, passphrase_file=passphrase) == 0
    job = JobState.load(job_path)
    assert any(step.id == "setup.execute" and step.status == "done" for step in job.steps)


def test_execute_native_rollback_calls_provider_deletes(monkeypatch, tmp_path) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "actions": [
                    {"action": "github.secret", "details": {"repo": "o/r", "secret": "APP_KEY"}},
                    {"action": "github.deploy_key", "details": {"repo": "o/r", "key_id": "42"}},
                ]
            }
        ),
        encoding="utf-8",
    )
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "token",
        "test-github-token-hidden",
    )
    calls: list[tuple[str, str, str]] = []

    class FakeGitHubProvider:
        def __init__(self, token: str) -> None:
            assert token == "test-github-token-hidden"

        def delete_repo_secret(self, repo: str, name: str) -> dict[str, object]:
            calls.append(("secret", repo, name))
            return {}

        def delete_deploy_key(self, repo: str, key_id: str) -> dict[str, object]:
            calls.append(("key", repo, key_id))
            return {}

    monkeypatch.setattr("fusekit.providers.github.GitHubProvider", FakeGitHubProvider)

    actions = execute_native_rollback(receipt, vault)

    assert ("secret", "o/r", "APP_KEY") in calls
    assert ("key", "o/r", "42") in calls
    assert any(action.status == "done" for action in actions)
