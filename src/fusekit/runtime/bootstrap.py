"""Install and verify FuseKit runtime components."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fusekit.errors import FuseKitError

OPENCLAW_INSTALL_URL = "https://openclaw.ai/install-cli.sh"


class CommandRunner(Protocol):
    """Command runner used by bootstrap."""

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a command."""


@dataclass(frozen=True)
class RuntimeStatus:
    """Status for one runtime component."""

    name: str
    ok: bool
    detail: str
    remedy: str = ""

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize status."""

        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "remedy": self.remedy,
        }


@dataclass(frozen=True)
class BootstrapResult:
    """Result of a bootstrap run."""

    statuses: tuple[RuntimeStatus, ...]
    installed: tuple[str, ...]
    configured: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Return true when all runtime checks pass."""

        return all(status.ok for status in self.statuses)

    def to_dict(self) -> dict[str, object]:
        """Serialize result."""

        return {
            "ok": self.ok,
            "installed": list(self.installed),
            "configured": list(self.configured),
            "statuses": [status.to_dict() for status in self.statuses],
        }


def doctor(openclaw_bin: str | None = None) -> BootstrapResult:
    """Check whether FuseKit runtime components are available."""

    statuses = [
        _python_status(),
        _openclaw_status(openclaw_bin),
    ]
    return BootstrapResult(statuses=tuple(statuses), installed=())


def bootstrap_runtime(
    install: bool,
    openclaw_bin: str | None = None,
    runner: CommandRunner | None = None,
) -> BootstrapResult:
    """Ensure runtime components exist, installing missing components when requested."""

    before = doctor(openclaw_bin)
    if before.ok or not install:
        return before
    installed: list[str] = []
    configured: list[str] = []
    if not _openclaw_status(openclaw_bin).ok:
        _install_openclaw(runner or _default_runner)
        installed.append("openclaw")
    _configure_openclaw(runner or _default_runner)
    configured.append("openclaw")
    after = doctor(openclaw_bin)
    if not after.ok:
        details = "; ".join(status.detail for status in after.statuses if not status.ok)
        raise FuseKitError(f"Runtime bootstrap completed but verification failed: {details}")
    return BootstrapResult(
        statuses=after.statuses,
        installed=tuple(installed),
        configured=tuple(configured),
    )


def openclaw_binary() -> str:
    """Return the preferred OpenClaw binary path."""

    env = os.environ.get("FUSEKIT_OPENCLAW_BIN")
    if env:
        return env
    found = shutil.which("openclaw")
    if found:
        return found
    local = fusekit_home() / "openclaw" / "bin" / "openclaw"
    if local.exists():
        return str(local)
    home_local = Path.home() / ".openclaw" / "bin" / "openclaw"
    if home_local.exists():
        return str(home_local)
    return "openclaw"


def _python_status() -> RuntimeStatus:
    return RuntimeStatus(
        name="python",
        ok=True,
        detail=f"{platform.python_implementation()} {platform.python_version()}",
    )


def _openclaw_status(openclaw_bin: str | None = None) -> RuntimeStatus:
    binary = openclaw_bin or openclaw_binary()
    if shutil.which(binary) or Path(binary).exists():
        return RuntimeStatus(name="openclaw", ok=True, detail=binary)
    return RuntimeStatus(
        name="openclaw",
        ok=False,
        detail="not installed",
        remedy=f"run FuseKit bootstrap or install from {OPENCLAW_INSTALL_URL}",
    )


def _install_openclaw(runner: CommandRunner) -> None:
    home = fusekit_home()
    home.mkdir(parents=True, exist_ok=True)
    installer = home / "install-openclaw.sh"
    _download_file(OPENCLAW_INSTALL_URL, installer)
    expected_sha256 = os.environ.get("FUSEKIT_OPENCLAW_INSTALL_SHA256", "")
    if expected_sha256:
        _verify_sha256(installer, expected_sha256)
    installer.chmod(0o700)
    version = os.environ.get("FUSEKIT_OPENCLAW_VERSION", "latest")
    command = [
        "bash",
        "-lc",
        (
            f"OPENCLAW_HOME='{openclaw_state_home()}' "
            f"bash '{installer}' --prefix '{home / 'openclaw'}' --version '{version}' --no-onboard"
        ),
    ]
    completed = runner(command)
    if completed.returncode != 0:
        raise FuseKitError(completed.stderr or "OpenClaw installation failed.")


def _configure_openclaw(runner: CommandRunner) -> None:
    binary = openclaw_binary()
    _ensure_browser_plugin_config()
    checks = [
        _openclaw_command(binary, ["--version"]),
        _openclaw_command(binary, ["doctor", "--non-interactive"]),
        _openclaw_command(binary, ["browser", "status"]),
    ]
    for command in checks:
        completed = runner(command)
        if completed.returncode != 0:
            raise FuseKitError(
                completed.stderr
                or completed.stdout
                or f"OpenClaw setup verification failed: {' '.join(command)}"
            )


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, check=False, text=True, timeout=900)


def fusekit_home() -> Path:
    """Return FuseKit's owned runtime home."""

    return Path(os.environ.get("FUSEKIT_HOME", Path.home() / ".fusekit-runtime"))


def openclaw_state_home() -> Path:
    """Return FuseKit-owned OpenClaw state home."""

    return fusekit_home() / "openclaw-state"


def _openclaw_command(binary: str, args: list[str]) -> list[str]:
    return ["env", f"OPENCLAW_HOME={openclaw_state_home()}", binary, *args]


def _ensure_browser_plugin_config() -> None:
    """Ensure FuseKit-owned OpenClaw state allows the browser plugin."""

    config_dir = openclaw_state_home()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "openclaw.json"
    if config_path.exists():
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            backup = config_path.with_suffix(".json.bak")
            config_path.replace(backup)
            raw = {}
    else:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    plugins = raw.get("plugins")
    if not isinstance(plugins, dict):
        plugins = {}
        raw["plugins"] = plugins
    allowed = plugins.get("allow")
    if allowed is None:
        plugins["allow"] = ["browser"]
    elif isinstance(allowed, list) and "browser" not in allowed:
        allowed.append("browser")
    raw.setdefault("browser", {})
    config_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _download_file(url: str, destination: Path) -> None:
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
    except OSError as exc:
        raise FuseKitError(f"Could not download runtime component installer: {url}") from exc
    destination.write_bytes(data)


def _verify_sha256(path: Path, expected: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest.lower() != expected.lower():
        raise FuseKitError("Downloaded OpenClaw installer did not match expected SHA-256.")
