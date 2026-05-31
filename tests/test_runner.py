from __future__ import annotations

import json
import shlex
import subprocess
import tarfile
from pathlib import Path

import pytest

from fusekit.errors import FuseKitError
from fusekit.rollback import execute_native_rollback, plan_rollback, start_over
from fusekit.runner.broker import resolve_runner
from fusekit.runner.cloud_shell import (
    build_cloud_shell_launch_plan,
    render_cloud_shell_launcher,
)
from fusekit.runner.control_room import render_control_room
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState
from fusekit.runner.loop import run_remote_loop
from fusekit.runner.oci import capture_oci_api_key_profile, prepare_oci_api_signing_key
from fusekit.runner.oci_live import (
    OciProvisioner,
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


def test_runner_env_override_rejects_unknown_runner(monkeypatch) -> None:
    monkeypatch.setenv("FUSEKIT_RUNNER", "surprise-runner")

    with pytest.raises(FuseKitError, match="Unknown runner"):
        resolve_runner("auto")


def test_job_status_preserves_failure_after_cleanup_step(tmp_path) -> None:
    from fusekit.runner.job import JobState

    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "failed", "remote setup failed")
    job.mark("detonate.workspace", "done", "cleanup attempted")

    assert job.status == "failed"


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
    assert "python_cmd=python3" in plan.bootstrap_command
    assert "retry \"$python_cmd\" -m pip install --user --upgrade" in plan.bootstrap_command
    assert "fusekit --version" in plan.bootstrap_command
    assert "Git is required in OCI Cloud Shell for git+ FuseKit packages" in plan.bootstrap_command
    assert "codeload.github.com" in plan.bootstrap_command
    assert "https://github.com/example/app.git" in plan.bootstrap_command
    assert "git+https://github.com/example/fusekit.git" in plan.bootstrap_command
    assert "--github-repo example/app" in plan.bootstrap_command
    assert "--dns-zone example.com" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert plan.launch_args[-1] == "--infer-ui"
    assert "Copy Bootstrap Command" in html
    assert 'role="status"' in html
    assert "navigator.clipboard.writeText" in html
    assert "Copy was blocked" in html
    assert "command.select()" in html
    assert "Passphrase:" in plan.bootstrap_command


def test_cloud_shell_bootstrap_command_is_valid_shell() -> None:
    plan = build_cloud_shell_launch_plan(
        app_source="https://github.com/example/app.git",
        launch_args=("--infer-ui",),
    )
    command = shlex.split(plan.bootstrap_command)

    result = subprocess.run(
        ["bash", "-n"],
        input=command[2],
        capture_output=True,
        check=False,
        text=True,
    )

    assert command[:2] == ["bash", "-lc"]
    assert result.returncode == 0, result.stderr


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
    assert "What you need to do" in html
    assert "Oracle Cloud is opening the clean room" in html
    assert "Live refresh paused. Reopen or restart the control-room server." in html
    assert "Snapshot view. Serve the control room for live updates." in html
    assert "setRefreshStatus" in html
    assert "fk-test" in html
    assert payload["id"] == "fk-test"


def test_control_room_payload_includes_active_gate_records(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
    )

    payload = control_room_payload(job_path)

    assert payload["status"] == "running"
    assert payload["gates"][0]["provider"] == "vercel"
    assert payload["gates"][0]["status"] == "waiting"
    assert "token" in str(payload["gates"][0]["reason"])


def test_control_room_gate_help_includes_resume_link_and_attempts(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
    )
    service.wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
    )

    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")

    assert "Open provider gate" in html
    assert "gate-attempts" in html
    assert "https://vercel.com/account/tokens" in html
    assert '"attempts":2' in html or '"attempts": 2' in html


def test_control_room_uses_privacy_mascot_for_secret_gates(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark(
        "provider.resend.authorization",
        "waiting",
        "Resend API key token is ready; paste it into FuseKit's hidden prompt.",
    )

    html = render_control_room(job)

    assert "state-privacy" in html
    assert "privacy-mitten" in html
    assert "covering his eyes while secrets stay private" in html
    assert "isPrivacyStep" in html
    assert "hidden prompt" in html


def test_control_room_payload_reports_corrupt_gate_state(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "gates.json").write_text("{not json", encoding="utf-8")

    payload = control_room_payload(job_path)

    assert payload["gates"] == []
    assert "Gate state could not be read" in str(payload["gate_state_error"])


def test_remote_bootstrap_artifacts_are_self_contained() -> None:
    cloud_init = render_cloud_init(openclaw_install_url="https://openclaw.ai/install-cli.sh")
    git_cloud_init = render_cloud_init(
        fusekit_wheel_url="git+https://github.com/example/fusekit.git",
        openclaw_install_url="https://openclaw.ai/install-cli.sh",
    )

    assert "python3-venv" in cloud_init
    assert "/opt/fusekit-python/bin/python -m pip install --upgrade fusekit" in cloud_init
    assert (
        "/opt/fusekit-python/bin/python -m pip install --upgrade "
        "git+https://github.com/example/fusekit.git"
    ) in git_cloud_init
    assert "/opt/fusekit-python/bin/python -m playwright install --with-deps chromium" in cloud_init
    assert "chromium-browser" not in cloud_init
    assert "openclaw browser status --json" in cloud_init
    assert "fusekit-runner-verify" in cloud_init
    assert "export PATH=/opt/fusekit-python/bin:/opt/fusekit-openclaw/bin:$PATH" in cloud_init
    assert "FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw" in cloud_init
    assert "ln -sf /opt/fusekit-python/bin/fusekit /usr/local/bin/fusekit" in cloud_init
    assert "ln -sf /opt/fusekit-openclaw/bin/openclaw /usr/local/bin/openclaw" in cloud_init
    assert "  - |\n    python3 - <<'PY'" in cloud_init
    assert "/opt/fusekit-openclaw/openclaw/bin" not in cloud_init
    assert should_include_app_path(Path("src/index.js"))
    assert not should_include_app_path(Path(".env"))
    assert not should_include_app_path(Path(".env.production"))
    assert not should_include_app_path(Path(".npmrc"))
    assert not should_include_app_path(Path(".vercel/project.json"))
    assert not should_include_app_path(Path("id_ed25519"))
    assert not should_include_app_path(Path("service.credentials.json"))
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


def test_oci_detonation_reports_provider_delete_failures() -> None:
    class FailedDelete(Exception):
        status = 409
        code = "Conflict"

    class FakeCompute:
        def terminate_instance(self, instance_id: str, *, preserve_boot_volume: bool) -> None:
            assert instance_id == "ocid1.instance.oc1..example"
            assert preserve_boot_volume is False

    class FakeNetwork:
        def delete_subnet(self, resource_id: str) -> None:
            raise FailedDelete(resource_id)

        def delete_network_security_group(self, resource_id: str) -> None:
            return None

        def delete_route_table(self, resource_id: str) -> None:
            return None

        def delete_internet_gateway(self, resource_id: str) -> None:
            return None

        def delete_vcn(self, resource_id: str) -> None:
            return None

    class FakeIdentity:
        def delete_compartment(self, resource_id: str) -> None:
            raise FailedDelete(resource_id)

    provisioner = object.__new__(OciProvisioner)
    provisioner.compute = FakeCompute()
    provisioner.network = FakeNetwork()
    provisioner.identity = FakeIdentity()
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        resource_ids={
            "instance": "ocid1.instance.oc1..example",
            "subnet": "ocid1.subnet.oc1..example",
            "network_security_group": "ocid1.nsg.oc1..example",
            "route_table": "ocid1.routetable.oc1..example",
            "internet_gateway": "ocid1.ig.oc1..example",
            "vcn": "ocid1.vcn.oc1..example",
            "compartment": "ocid1.compartment.oc1..example",
        },
    )

    deleted = provisioner.detonate(workspace)

    assert deleted["instance"] == "ocid1.instance.oc1..example"
    assert deleted["failed.subnet"] == "409 Conflict"
    assert deleted["failed.compartment"] == "409 Conflict"


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
            archive = tarfile.open(stdout_path, "w:gz")
            payload = tmp_path / "job.json"
            gates = tmp_path / "gates.json"
            payload.write_text("{}", encoding="utf-8")
            gates.write_text('{"gates":[]}', encoding="utf-8")
            archive.add(payload, arcname=".fusekit/job.json")
            archive.add(gates, arcname=".fusekit/gates.json")
            archive.close()
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
    assert any(
        "FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "FUSEKIT_HOME=/var/lib/fusekit-runner/fusekit-runtime" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert (tmp_path / "out" / ".fusekit" / "gates.json").exists()
    assert any(".fusekit/gates.json" in command[-1] for command in calls if command[0] == "ssh")
    assert any("[ -n \"$existing\" ] || exit 44" in command[-1] for command in calls)


def test_remote_artifact_extraction_rejects_invalid_archive(tmp_path) -> None:
    from fusekit.errors import FuseKitError
    from fusekit.runner.remote import _extract_artifacts

    archive = tmp_path / "bad.tar.gz"
    archive.write_text("not a tarball", encoding="utf-8")

    try:
        _extract_artifacts(archive, tmp_path / "out")
    except FuseKitError as exc:
        assert "archive could not be read" in str(exc)
    else:
        raise AssertionError("invalid remote artifact archive should fail")


def test_cloud_shell_style_oci_config_uses_delegation_token_signer(
    tmp_path,
    monkeypatch,
) -> None:
    import oci

    class FakeSigner:
        tenancy_id = "ocid1.tenancy.oc1..cloudshell"
        region = "us-ashburn-1"

    def local_from_file(path: str) -> dict[str, str]:
        assert path == str(tmp_path / "config")
        return {
            "authentication_type": "instance_principal",
            "delegation_token_file": str(tmp_path / "delegation-token"),
            "region": "us-ashburn-1",
        }

    def local_get_signer_from_authentication_type(config: dict[str, str]) -> FakeSigner:
        assert config["authentication_type"] == "instance_principal"
        return FakeSigner()

    monkeypatch.setattr(oci.config, "from_file", local_from_file)
    monkeypatch.setattr(
        oci.util,
        "get_signer_from_authentication_type",
        local_get_signer_from_authentication_type,
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

    def local_run(
        command: list[str],
        *,
        capture_output: bool,
        check: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", local_run)

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
