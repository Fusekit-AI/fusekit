from __future__ import annotations

import re
from pathlib import Path


def test_readme_real_provider_path_names_resend_and_vm_capture() -> None:
    text = Path("README.md").read_text(encoding="utf-8")

    assert "The V1 real path is GitHub + Resend + Vercel + Cloudflare DNS." in text
    assert "Bundled GitHub, Resend, Vercel, and Cloudflare behavior" in text
    assert "RESEND_API_KEY" in text
    assert "exact env-named FuseKit control" in text
    assert "`Capture RESEND_API_KEY from VM clipboard`" in text
    assert "`Capture GITHUB_TOKEN from VM clipboard`" in text
    assert "VM browser `Capture from VM clipboard` buttons" not in text
    assert "VM browser `Capture from VM clipboard` flow" not in text
    assert "one-time `RESEND_API_KEY` capture from the VM" in text
    assert "FuseKit then owns Resend domain/audience setup by API before DNS" in text
    assert "browser surface" not in text.lower()
    assert "matching FuseKit `Capture from VM clipboard` button" not in text


def test_acceptance_runbook_uses_launcher_capture_for_public_recording() -> None:
    text = Path("docs/acceptance-runbook.md").read_text(encoding="utf-8")
    match = re.search(r"```zsh\n(fusekit launch .*?)\n```", text, flags=re.DOTALL)

    assert match is not None
    launch_command = match.group(1)
    assert "--control-room" in launch_command
    assert "--infer-ui" in launch_command
    assert "--capture-stdin" not in launch_command
    assert "exact `Capture <ENV> from VM clipboard`" in text
    assert "not the public no-thinking launcher path" in text
    assert "Public Recording Rules" in text
    assert "Open provider gate in VM" in text
    assert "I finished this step" in text
    assert "Do not paste secrets into the host" in text
    assert "Empty Domains or Audiences" in text
    assert "pages are not a user task" in text
    assert "FuseKit creates or reuses the sending domain" in text
    assert "audience by API" in text
    assert "`Permission: Full access`" in text
    assert "`Domain: All domains`" in text
    assert (
        "A Resend row that says `Permission: Full access` and `Domain: All domains`"
        in text
    )
    assert "is still not enough by itself" in text
    assert "Do not click Resend Add domain or Add audience" in text
    assert "`public_launch_ready: true`" in text
    assert "`recording_ready: true`" in text
    assert '"public_launch_ready": true' in text
    assert '"recording_ready": true' in text
    assert "unless a future FuseKit gate" not in text
    assert "unless FuseKit asks" not in text
    assert "Use the control-room VM browser and `Capture from VM clipboard` buttons" not in text


def test_public_launch_readiness_requires_exact_capture_controls() -> None:
    text = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")

    assert "exact controls such as `Capture RESEND_API_KEY from VM clipboard`" in text
    assert "manual, placeholder, or" in text
    assert "targets must name `Capture from VM clipboard`" not in text


def test_friction_log_keeps_resend_recovery_launcher_owned() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "regenerate the Resend runtime gate" not in text
    assert "keep the live launcher/control room open while FuseKit rebuilds" in text
    assert "only `RESEND_API_KEY` uses Capture" in text


def test_friction_log_tracks_generic_capture_fallback_fix() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert (
        "Generic provider, verification, acceptance, and control-room fallback copy"
        in text
    )
    assert "single highlighted launcher gate" in text
    assert "exact env-named Capture button rendered for that gate" in text
    assert "Resend-specific copy names `RESEND_API_KEY` only on real Resend" in text


def test_oci_runner_lane_defines_prepared_environment_contract() -> None:
    text = Path("docs/oci-runner-lane.md").read_text(encoding="utf-8")

    assert "prepared environment contract" in text
    assert "expected x86_64 architecture" in text
    assert "FuseKit runner helpers" in text
    assert "Chromium smoke-test readiness" in text
    assert "installed-binary inventory" in text
    assert "shared Chrome provider profile" in text
    assert "before the first provider account gate" in text


def test_northstar_background_contract_includes_verified_runner_profile() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Prepared runner profile first" in text
    assert "OpenClaw or the approved browser spine" in text
    assert "installed binary inventory" in text
    assert "noVNC" in text
    assert "must be verified" in text
    assert "before provider gates appear" in text


def test_northstar_defines_detonation_pressure_test() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Detonation Pressure Test" in text
    assert "The product object" in text
    assert "Run Record, not the VM" in text
    assert "Plaintext runtime state dies" in text
    assert "Public recording" in text
    assert "readiness must stay false" in text
    assert "Evented resume beats click-and-hope" in text


def test_oci_lane_requires_detonation_survivor_set() -> None:
    text = Path("docs/oci-runner-lane.md").read_text(encoding="utf-8")

    assert "survivor set" in text
    assert "encrypted vault" in text
    assert "Run Record" in text
    assert "redacted artifacts" in text
    assert "resume checkpoints" in text
    assert "no host-machine state required" in text


def test_northstar_pressure_tests_background_agent_objects() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Ona Audit Pressure Test" in text
    assert "Run Record" in text
    assert "Runner Profile Contract" in text
    assert "Provider Playbooks" in text
    assert "Live Verifiers" in text
    assert "Evented Resume" in text
    assert "Disposable Workers, Durable State" in text
    assert "Audit-First UX" in text
    assert "Repeated or stale clicks must be idempotent" in text


def test_northstar_defines_background_agent_contract() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Background Agent Contract" in text
    assert "prepared, disposable cloud workstation" in text
    assert "Prepared runner profile first" in text
    assert "Deterministic scripts first, guided browser second" in text
    assert "One observable control room" in text
    assert "Event-sourced run journal" in text
    assert "Policy boundaries by default" in text
    assert "Human gates are real gates only" in text


def test_public_launch_readiness_requires_background_agent_evidence() -> None:
    text = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")

    assert "disposable background workstation was ready before the first provider gate" in text
    assert "x86_64 architecture" in text
    assert "approved browser spine" in text
    assert "Playwright smoke test" in text
    assert "installed-binary inventory" in text
    assert "shared provider browser profile" in text
    assert "provider opens, Capture clicks" in text
    assert "raw secrets and provider callback tokens redacted" in text


def test_friction_log_tracks_runner_verify_prepared_environment_fix() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "wrong architecture or miss noVNC/visual helper binaries" in text
    assert "`fusekit-runner-verify` now fails before provider setup" in text
    assert "Playwright Chromium can launch" in text
    assert "shared Chrome provider profile path exists" in text


def test_friction_log_tracks_visual_query_value_sanitization() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "checking their values" in text
    assert "autoconnect=1" in text
    assert "resize=scale" in text
    assert "reject the visual session before rendering" in text


def test_friction_log_tracks_runner_readiness_artifact() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "`fusekit-runner-verify` could stop a bad VM" in text
    assert ".fusekit/runner_readiness.json" in text
    assert "artifact retrieval requires it" in text
    assert "live acceptance fails unless the proof shows x86_64" in text
    assert "Playwright Chromium" in text
    assert "shared provider browser profile" in text
    assert "installed-binary inventory" in text


def test_friction_log_tracks_remote_worker_cleanup_proof() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "bare `remote_worker` success string" in text
    assert "fusekit.remote-worker-cleanup.v1" in text
    assert "host_machine_state_required=false" in text
    assert "live acceptance fail closed unless that proof is present" in text
    assert "Remote worker cleanup proof" in text
    assert "host-machine state was not required" in text


def test_friction_log_tracks_detonation_survivor_preflight_guards() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "central Run Record had not yet been written" in text
    assert "local launch writes the current Run Record before cleanup can proceed" in text
    assert "not the raw durable `run_state.json`" in text
    assert "require `.fusekit/run_state.json` before OCI detonation" in text
    assert "raw callback URLs, bearer text, or token-looking strings" in text
    assert (
        "fails closed on credential-looking text while allowing explicitly redacted values" in text
    )
