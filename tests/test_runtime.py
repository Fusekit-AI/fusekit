from __future__ import annotations

import subprocess

import fusekit.runtime.bootstrap as bootstrap


def test_bootstrap_runs_openclaw_installer_when_missing(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    monkeypatch.setenv("FUSEKIT_OPENCLAW_BIN", str(tmp_path / "missing-openclaw"))
    monkeypatch.setattr(
        bootstrap,
        "_download_file",
        lambda url, destination: destination.write_text(""),
    )

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        openclaw_bin = tmp_path / "openclaw" / "bin" / "openclaw"
        openclaw_bin.parent.mkdir(parents=True, exist_ok=True)
        openclaw_bin.write_text("#!/bin/sh\n", encoding="utf-8")
        openclaw_bin.chmod(0o700)
        monkeypatch.setenv("FUSEKIT_OPENCLAW_BIN", str(openclaw_bin))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = bootstrap.bootstrap_runtime(install=True, runner=runner)

    assert "openclaw" in result.installed
    assert "openclaw" in result.configured
    assert calls
    assert "install-openclaw.sh" in calls[0][-1]
    assert calls[-3:] == [
        [
            "env",
            f"OPENCLAW_HOME={bootstrap.openclaw_state_home()}",
            str(tmp_path / "openclaw" / "bin" / "openclaw"),
            "--version",
        ],
        [
            "env",
            f"OPENCLAW_HOME={bootstrap.openclaw_state_home()}",
            str(tmp_path / "openclaw" / "bin" / "openclaw"),
            "doctor",
            "--non-interactive",
        ],
        [
            "env",
            f"OPENCLAW_HOME={bootstrap.openclaw_state_home()}",
            str(tmp_path / "openclaw" / "bin" / "openclaw"),
            "browser",
            "status",
        ],
    ]
