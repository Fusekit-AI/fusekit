from __future__ import annotations

import json
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
            "--json",
        ],
    ]


def test_doctor_verifies_openclaw_doctor_and_browser(monkeypatch, tmp_path) -> None:
    openclaw_bin = tmp_path / "openclaw"
    openclaw_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    openclaw_bin.chmod(0o700)
    monkeypatch.setenv("FUSEKIT_OPENCLAW_BIN", str(openclaw_bin))
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[-3:] == ["browser", "status", "--json"]:
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="browser missing")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    result = bootstrap.doctor(runner=runner)

    assert not result.ok
    assert "browser missing" in result.statuses[-1].detail
    assert calls[-1][-3:] == ["browser", "status", "--json"]


def test_bootstrap_config_disables_browser_evaluate_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FUSEKIT_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    bootstrap._ensure_browser_plugin_config()

    primary = tmp_path / "openclaw-state" / "openclaw.json"
    default = tmp_path / "home" / ".openclaw" / "openclaw.json"
    for path in (primary, default):
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["browser"]["enabled"] is True
        assert raw["browser"]["evaluateEnabled"] is False
        assert "browser" in raw["plugins"]["allow"]
        assert oct(path.stat().st_mode & 0o777) == "0o600"
