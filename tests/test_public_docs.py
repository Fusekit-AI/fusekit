from __future__ import annotations

import re
from pathlib import Path


def test_readme_real_provider_path_names_resend_and_vm_capture() -> None:
    text = Path("README.md").read_text(encoding="utf-8")

    assert "The V1 real path is GitHub + Resend + Vercel + Cloudflare DNS." in text
    assert "Bundled GitHub, Resend, Vercel, and Cloudflare behavior" in text
    assert "RESEND_API_KEY" in text
    assert "Capture from VM clipboard" in text


def test_acceptance_runbook_uses_launcher_capture_for_public_recording() -> None:
    text = Path("docs/acceptance-runbook.md").read_text(encoding="utf-8")
    match = re.search(r"```zsh\n(fusekit launch .*?)\n```", text, flags=re.DOTALL)

    assert match is not None
    launch_command = match.group(1)
    assert "--control-room" in launch_command
    assert "--infer-ui" in launch_command
    assert "--capture-stdin" not in launch_command
    assert "Capture from VM clipboard" in text
    assert "not the public no-thinking launcher path" in text
