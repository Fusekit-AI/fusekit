from __future__ import annotations

import http.client
import json
import os
import shlex
import subprocess
import tarfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from fusekit.errors import FuseKitError
from fusekit.rollback import execute_native_rollback, plan_rollback, start_over
from fusekit.runner.broker import resolve_runner
from fusekit.runner.cloud_shell import (
    build_cloud_shell_launch_plan,
    render_cloud_shell_launcher,
)
from fusekit.runner.control_room import (
    control_room_payload as static_control_room_payload,
)
from fusekit.runner.control_room import render_control_room
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState
from fusekit.runner.loop import run_remote_loop
from fusekit.runner.oci import (
    build_oci_runner_plan,
    capture_oci_api_key_profile,
    prepare_oci_api_signing_key,
)
from fusekit.runner.oci_live import (
    OciProvisioner,
    OciWorkspace,
    _load_oci_config_file,
    latest_workspace_from_vault,
    suppress_oci_http_debug_logging,
)
from fusekit.runner.remote import (
    _extract_artifacts,
    execute_remote_setup,
    render_cloud_init,
    should_include_app_path,
)
from fusekit.runner.run_state import LaunchRunState, update_run_state
from fusekit.runner.server import _handler, _is_loopback, control_room_payload
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


def test_job_state_writes_recovery_checkpoints(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "provider token hidden prompt is open")
    job_path = tmp_path / "job.json"

    job.save(job_path)
    checkpoint_payload = json.loads((tmp_path / "checkpoints.json").read_text("utf-8"))

    assert "checkpoints" in job.to_dict()
    assert checkpoint_payload["job_id"] == "fk-test"
    setup = next(
        item for item in checkpoint_payload["checkpoints"] if item["id"] == "setup.execute"
    )
    assert setup["status"] == "running"
    assert setup["mascot_state"] == "privacy"
    assert "Human gates wait forever" in setup["resume_hint"]


def test_launch_run_state_contract_tracks_detonation_readiness(tmp_path) -> None:
    path = tmp_path / "run_state.json"

    state = update_run_state(
        path,
        app_repo_known=True,
        runner_selected=True,
        oci_ready=True,
        browser_ready=False,
        vault_created=True,
        secrets_captured=True,
        provider_checks_passed_or_pending_safe=False,
        receipt_written=True,
    )

    assert path.stat().st_mode & 0o777 == 0o600
    assert state.oci_ready is True
    assert state.browser_ready is False
    assert state.missing_for_detonation() == ["provider_checks_passed_or_pending_safe"]
    assert state.to_dict()["ready_to_detonate"] is False

    loaded = LaunchRunState.load(path)
    loaded.mark(provider_checks_passed_or_pending_safe=True, detonation_safe=True)

    assert loaded.missing_for_detonation() == []
    assert loaded.to_dict()["ready_to_detonate"] is True


def test_launch_run_state_notes_are_redacted(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    state = LaunchRunState()
    fake_secret = "fake_test_secret_value_abcdefghijklmnopqrstuvwxyz"
    state.add_note(f"captured key={fake_secret}")
    state.save(path)

    payload = json.loads(path.read_text("utf-8"))

    assert fake_secret not in json.dumps(payload)
    assert "[redacted]" in json.dumps(payload)


def test_launch_run_state_recovers_from_corrupt_state(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    path.write_text("{not-json", encoding="utf-8")

    state = update_run_state(path, runner_selected=True)
    payload = json.loads(path.read_text("utf-8"))

    assert state.runner_selected is True
    assert payload["runner_selected"] is True
    assert "rebuilt" in payload["notes"][0]


def test_launch_run_state_parses_false_strings_as_false(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    path.write_text(
        json.dumps(
            {
                "app_repo_known": "false",
                "runner_selected": "true",
                "oci_ready": "0",
                "browser_ready": "1",
            }
        ),
        encoding="utf-8",
    )

    state = LaunchRunState.load(path)

    assert state.app_repo_known is False
    assert state.runner_selected is True
    assert state.oci_ready is False
    assert state.browser_ready is True


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
    assert "sys.version_info >= (3, 10)" in plan.bootstrap_command
    assert "uv python install 3.12" in plan.bootstrap_command
    assert "uv venv --python 3.12" in plan.bootstrap_command
    assert "pip_target_flag=--user" in plan.bootstrap_command
    assert "pip_target_flag=" in plan.bootstrap_command
    assert "export PATH=\"$work/python/bin:$PATH\"" in plan.bootstrap_command
    assert "export FUSEKIT_OPENCLAW_HOME_MODE=default" in plan.bootstrap_command
    assert "retry \"$python_cmd\" -m pip install --user --upgrade" in plan.bootstrap_command
    assert "fusekit --version" in plan.bootstrap_command
    assert "Git is required in OCI Cloud Shell for git+ FuseKit packages" in plan.bootstrap_command
    assert "fusekit source fetch" in plan.bootstrap_command
    assert "--github-auth auto" in plan.bootstrap_command
    assert "--capture-stdin" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert "--vault \"$vaultfile\"" in plan.bootstrap_command
    assert "https://github.com/example/app.git" in plan.bootstrap_command
    assert "git+https://github.com/example/fusekit.git" in plan.bootstrap_command
    assert "--github-repo example/app" in plan.bootstrap_command
    assert "--dns-zone example.com" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert plan.launch_args[-1] == "--infer-ui"
    assert "SnowmanAI / FuseKit" in html
    assert "Privacy mode" in html
    assert "Copy Backup Command" in html
    assert 'role="status"' in html
    assert "navigator.clipboard.writeText" in html
    assert "document.execCommand('copy')" in html
    assert "Press Command+C" in html
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
    assert "Recovery map" in html
    assert "Every step stays alive" in html
    assert "checkpoint-card" in html
    assert "waiting politely with a tiny access badge" in html
    assert "Live refresh paused. Reopen or restart the control-room server." in html
    assert "Snapshot view. Serve the control room for live updates." in html
    assert "setRefreshStatus" in html
    assert "fk-test" in html
    assert payload["id"] == "fk-test"


def test_control_room_brand_and_snowman_markup_match_assets(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")

    html = render_control_room(job)

    assert "mark-hat" in html
    assert "mark-node mark-node-a" in html
    assert "brand-copy" in html
    assert '<span class="snow-hat"></span>' in html
    assert '<span class="steam one"></span>' in html


def test_control_room_renders_launch_run_state_contract(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert "Launch contract" in html
    assert "What FuseKit knows" in html
    assert 'data-run-state-field="app_repo_known"' in html
    assert "renderRunState" in html
    assert payload["run_state"]["app_repo_known"] is True
    assert payload["run_state"]["vault_created"] is True


def test_control_room_renders_verification_trust_cards(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "overall": "pending",
                "checks": [
                    {
                        "provider": "resend",
                        "check": "auth_valid",
                        "status": "passed",
                        "summary": "resend auth valid passed.",
                        "repair": "Nothing needed.",
                    },
                    {
                        "provider": "cloudflare",
                        "check": "dns_verified",
                        "status": "pending",
                        "summary": "cloudflare dns verified is still pending.",
                        "repair": "Keep waiting for DNS propagation.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    job.add_artifact("verification_report", report)

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert "Trust checks" in html
    assert "Proof it really works" in html
    assert "trust-snow state-passed" in html
    assert "trust-snow state-checking" in html
    assert payload["verification"]["overall"] == "pending"


def test_control_room_reports_invalid_verification_report_as_failed(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    report = tmp_path / "verification_report.json"
    report.write_text("[]", encoding="utf-8")
    job.add_artifact("verification_report", report)

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["verification"]["overall"] == "failed"
    assert "not a JSON object" in payload["verification"]["error"]


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
        classification="mfa",
        target="Continue",
        follow_steps=("Click Continue", "Finish the MFA prompt"),
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = control_room_payload(job_path)

    assert payload["status"] == "running"
    assert payload["gates"][0]["provider"] == "vercel"
    assert payload["gates"][0]["status"] == "waiting"
    assert "token" in str(payload["gates"][0]["reason"])
    assert "vercel needs your approval" in html
    assert "Click Continue" in html
    assert "Snowman highlighted" in html
    assert 'data-gate-pass="provider.vercel.authorization"' in html
    assert "<strong data-count-waiting>1</strong> gates" in html


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
        classification="mfa",
        target="ref=7",
        follow_steps=("Use the highlighted MFA field.", "Click I finished this step."),
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
    assert "Use the highlighted MFA field." in html
    assert "I finished this step" in html
    assert "state-gate" in html


def test_control_room_post_marks_human_gate_passed(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
        follow_steps=("Pass the provider MFA challenge.",),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(url, method="POST", headers={"x-fusekit-control-room": "resume"})
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert GateService.load(tmp_path / "gates.json").records[
        "provider.github.mfa.123"
    ].status == "passed"


def test_control_room_post_rejects_cross_site_gate_pass(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        with pytest.raises(HTTPError):
            urlopen(Request(url, method="POST"), timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert GateService.load(tmp_path / "gates.json").records[
        "provider.github.mfa.123"
    ].status == "waiting"


def test_control_room_post_rejects_untrusted_origin(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers={
                "x-fusekit-control-room": "resume",
                "Origin": "https://evil.example",
            },
        )
        with pytest.raises(HTTPError):
            urlopen(request, timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert GateService.load(tmp_path / "gates.json").records[
        "provider.github.mfa.123"
    ].status == "waiting"


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


def test_control_room_server_uses_local_only_and_security_headers(tmp_path) -> None:
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("localhost")
    assert not _is_loopback("0.0.0.0")

    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]


def test_remote_bootstrap_artifacts_are_self_contained() -> None:
    cloud_init = render_cloud_init(openclaw_install_url="https://openclaw.ai/install-cli.sh")
    git_cloud_init = render_cloud_init(
        fusekit_wheel_url="git+https://github.com/example/fusekit.git",
        openclaw_install_url="https://openclaw.ai/install-cli.sh",
    )

    assert "python3-venv" in cloud_init
    assert (
        "fusekit-retry /opt/fusekit-python/bin/python -m pip install --upgrade fusekit"
        in cloud_init
    )
    assert (
        "fusekit-retry /opt/fusekit-python/bin/python -m pip install --upgrade "
        "git+https://github.com/example/fusekit.git"
    ) in git_cloud_init
    assert (
        "fusekit-retry /opt/fusekit-python/bin/python -m playwright install --with-deps chromium"
        in cloud_init
    )
    assert "chromium-browser" not in cloud_init
    assert "openclaw browser status --json" in cloud_init
    assert "fusekit-runner-verify" in cloud_init
    assert "fusekit-retry" in cloud_init
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


def test_remote_artifact_extract_rejects_unsafe_paths(tmp_path) -> None:
    archive = tmp_path / "artifacts.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        payload = tmp_path / "payload.txt"
        payload.write_text("bad", encoding="utf-8")
        tar.add(payload, arcname="../escape.txt")

    with pytest.raises(FuseKitError, match="unsafe paths"):
        _extract_artifacts(archive, tmp_path / "out")


def test_remote_artifact_extract_rejects_empty_archives(tmp_path) -> None:
    archive = tmp_path / "artifacts.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass

    with pytest.raises(FuseKitError, match="did not contain files"):
        _extract_artifacts(archive, tmp_path / "out")


def test_remote_artifact_bundle_requires_survivor_files(tmp_path) -> None:
    from fusekit.runner.remote import _validate_artifact_bundle

    (tmp_path / ".fusekit").mkdir()
    (tmp_path / ".fusekit" / "job.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".fusekit" / "checkpoints.json").write_text("{}", encoding="utf-8")

    with pytest.raises(FuseKitError, match="fusekit.vault.json"):
        _validate_artifact_bundle(tmp_path)


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


def test_oci_provision_cleans_partial_workspace_when_readiness_fails() -> None:
    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class FakeProvisioner(OciProvisioner):
        def __init__(self) -> None:
            self.auth = type("Auth", (), {"config": {"tenancy": "ocid1.tenancy.example"}})()
            self.deleted: OciWorkspace | None = None

        def _create_compartment(
            self,
            tenancy_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.compartment.example")

        def _availability_domain(self, compartment_id: str) -> str:
            return "AD-1"

        def _create_vcn(self, compartment_id: str, run_id: str, tags: dict[str, str]) -> Created:
            return Created("ocid1.vcn.example")

        def _create_internet_gateway(
            self,
            compartment_id: str,
            vcn_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.ig.example")

        def _create_route_table(
            self,
            compartment_id: str,
            vcn_id: str,
            gateway_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.route.example")

        def _create_nsg(
            self,
            compartment_id: str,
            vcn_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.nsg.example")

        def _create_subnet(
            self,
            compartment_id: str,
            vcn_id: str,
            route_table_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.subnet.example")

        def _launch_with_capacity_fallback(self, **kwargs: object) -> tuple[Created, object]:
            return Created("ocid1.instance.example"), kwargs["base_plan"]

        def _public_ip(self, compartment_id: str, instance_id: str) -> str:
            return ""

        def detonate(self, workspace: OciWorkspace) -> dict[str, str]:
            self.deleted = workspace
            return {"instance": workspace.resource_ids.get("instance", "")}

    vault = Vault.empty()
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = FakeProvisioner()

    with pytest.raises(FuseKitError, match="public IP"):
        provisioner.provision(plan, vault)

    assert provisioner.deleted is not None
    assert provisioner.deleted.resource_ids["instance"] == "ocid1.instance.example"
    assert provisioner.deleted.resource_ids["compartment"] == "ocid1.compartment.example"


def test_oci_create_nsg_wraps_security_rules_for_sdk_request() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        CreateNetworkSecurityGroupDetails = Details
        AddSecurityRuleDetails = Details
        TcpOptions = Details
        PortRange = Details
        AddNetworkSecurityGroupSecurityRulesDetails = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeNetwork:
        def __init__(self) -> None:
            self.added: tuple[str, object] | None = None

        def create_network_security_group(self, details: object) -> Response:
            assert cast(Any, details).display_name == "fusekit-test-nsg"
            return Response(Created("ocid1.nsg.example"))

        def add_network_security_group_security_rules(self, nsg_id: str, details: object) -> None:
            self.added = (nsg_id, details)

    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.network = FakeNetwork()

    nsg = provisioner._create_nsg(
        "ocid1.compartment.example",
        "ocid1.vcn.example",
        "fusekit-test",
        {"fusekit": "true"},
    )

    assert nsg.id == "ocid1.nsg.example"
    assert provisioner.network.added is not None
    nsg_id, details = provisioner.network.added
    assert nsg_id == "ocid1.nsg.example"
    assert not isinstance(details, list)
    assert len(details.security_rules) == 2
    assert details.security_rules[0].direction == "INGRESS"
    assert details.security_rules[1].direction == "EGRESS"


def test_oci_debug_logging_is_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    original_http_level = http.client.HTTPConnection.debuglevel
    original_https_level = http.client.HTTPSConnection.debuglevel
    try:
        monkeypatch.setenv("OCI_PYTHON_SDK_DEBUG", "1")
        monkeypatch.setenv("OCI_SDK_DEBUG", "1")
        http.client.HTTPConnection.debuglevel = 1
        http.client.HTTPSConnection.debuglevel = 1
        suppress_oci_http_debug_logging()

        assert http.client.HTTPConnection.debuglevel == 0
        assert http.client.HTTPSConnection.debuglevel == 0
        assert "OCI_PYTHON_SDK_DEBUG" not in os.environ
        assert "OCI_SDK_DEBUG" not in os.environ

        connection = object.__new__(http.client.HTTPConnection)
        http.client.HTTPConnection.set_debuglevel(connection, 1)
        assert connection.debuglevel == 0
    finally:
        http.client.HTTPConnection.debuglevel = original_http_level
        http.client.HTTPSConnection.debuglevel = original_https_level


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
            checkpoints = tmp_path / "checkpoints.json"
            vault_file = tmp_path / "fusekit.vault.json"
            audit = tmp_path / "audit.jsonl"
            receipt = tmp_path / "setup_receipt.json"
            verification = tmp_path / "verification_report.json"
            rollback = tmp_path / "rollback_plan.json"
            payload.write_text("{}", encoding="utf-8")
            gates.write_text('{"gates":[]}', encoding="utf-8")
            checkpoints.write_text('{"checkpoints":[]}', encoding="utf-8")
            vault_file.write_text("encrypted", encoding="utf-8")
            audit.write_text('{"event":"ok"}\n', encoding="utf-8")
            receipt.write_text('{"actions":[]}', encoding="utf-8")
            verification.write_text('{"checks":[]}', encoding="utf-8")
            rollback.write_text(
                '{"rollback":[{"action":"rollback.test","status":"planned"}]}',
                encoding="utf-8",
            )
            archive.add(payload, arcname=".fusekit/job.json")
            archive.add(gates, arcname=".fusekit/gates.json")
            archive.add(checkpoints, arcname=".fusekit/checkpoints.json")
            archive.add(vault_file, arcname=".fusekit/fusekit.vault.json")
            archive.add(audit, arcname=".fusekit/audit.jsonl")
            archive.add(receipt, arcname=".fusekit/setup_receipt.json")
            archive.add(verification, arcname=".fusekit/verification_report.json")
            archive.add(rollback, arcname=".fusekit/rollback_plan.json")
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
    assert result["artifact_status"] == "complete"
    assert any(command[0] == "scp" for command in calls)
    assert any(command[0] == "ssh" and command[-1] == "true" for command in calls)
    assert any(
        "cloud-init status --wait && fusekit-runner-verify" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
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
    assert (tmp_path / "out" / ".fusekit" / "checkpoints.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "fusekit.vault.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "audit.jsonl").exists()
    assert (tmp_path / "out" / ".fusekit" / "setup_receipt.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "verification_report.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "rollback_plan.json").exists()
    assert any(".fusekit/gates.json" in command[-1] for command in calls if command[0] == "ssh")
    assert any(
        ".fusekit/checkpoints.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        ".fusekit/verification_report.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        ".fusekit/rollback_plan.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
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


def test_remote_artifact_bundle_requires_detonation_survivors(tmp_path) -> None:
    from fusekit.errors import FuseKitError
    from fusekit.runner.remote import _validate_artifact_bundle

    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    for name in (
        "fusekit.vault.json",
        "job.json",
        "checkpoints.json",
        "verification_report.json",
        "rollback_plan.json",
    ):
        (fusekit_dir / name).write_text("{}", encoding="utf-8")

    with pytest.raises(FuseKitError, match="audit.jsonl"):
        _validate_artifact_bundle(tmp_path)


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
    secret = "redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456"
    (app / "config.txt").write_text(f"API_KEY={secret}\n", encoding="utf-8")

    findings = scan_for_secret_leaks(app)

    assert findings[0].path == "config.txt"
    assert findings[0].line == 1
    assert secret not in str([finding.to_dict() for finding in findings])


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
    fusekit = app / ".fusekit"
    fusekit.mkdir()
    (fusekit / "verification_report.json").write_text(
        '{"checks":[{"provider":"live_app","check":"live_url_healthy","status":"passed"}]}',
        encoding="utf-8",
    )
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
    assert any(step.id == "verify.live" and step.status == "done" for step in job.steps)


def test_remote_loop_rejects_missing_safe_verification(monkeypatch, tmp_path) -> None:
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

    with pytest.raises(FuseKitError, match="safe verification"):
        run_remote_loop(app_path=app, job_state=job_path, passphrase_file=passphrase)
    job = JobState.load(job_path)
    assert any(step.id == "verify.live" and step.status == "failed" for step in job.steps)


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
