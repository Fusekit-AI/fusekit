from __future__ import annotations

import re
from pathlib import Path


def test_readme_real_provider_path_names_resend_and_vm_capture() -> None:
    text = Path("README.md").read_text(encoding="utf-8")

    assert "The V1 real path is GitHub + Resend + Vercel + Cloudflare DNS." in text
    assert "Bundled GitHub, Resend, Vercel, and Cloudflare behavior" in text
    assert "RESEND_API_KEY" in text
    assert "Capture from VM clipboard" in text
    assert "one-time `RESEND_API_KEY` capture from the VM" in text
    assert "FuseKit then owns Resend domain/audience setup by API before DNS" in text
    assert "browser surface" not in text.lower()


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
    assert "shared Chrome provider profile" in text
    assert "before the first provider account gate" in text


def test_northstar_next_slices_include_verified_runner_profile() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "verified prepared-environment profile" in text
    assert "OpenClaw/browser spine" in text
    assert "noVNC" in text
    assert "before provider gates are shown" in text
