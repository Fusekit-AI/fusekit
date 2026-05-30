"""OpenClaw browser spine adapter."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fusekit.errors import ProviderError
from fusekit.runtime.bootstrap import openclaw_binary, openclaw_state_home


class CommandRunner(Protocol):
    """Callable command runner used by the OpenClaw adapter."""

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a command and return a completed process."""


@dataclass(frozen=True)
class SpineResult:
    """Result of one spine action."""

    action: str
    command: tuple[str, ...]
    status: str
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, str | list[str]]:
        """Serialize a non-secret action result."""

        return {
            "action": self.action,
            "command": list(self.command),
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass
class OpenClawBrowserSpine:
    """Adapter around `openclaw browser`."""

    profile: str = "openclaw"
    binary: str | None = None
    dry_run: bool = False
    runner: CommandRunner | None = None

    def available(self) -> bool:
        """Return whether the configured OpenClaw binary is available."""

        binary = self._binary()
        return self.dry_run or shutil.which(binary) is not None or Path(binary).exists()

    def start(self) -> SpineResult:
        """Start or attach to the OpenClaw-managed browser profile."""

        return self._run("start", ["start"])

    def open(self, url: str) -> SpineResult:
        """Open a URL through OpenClaw browser control."""

        return self._run("open", ["open", url])

    def navigate(self, url: str) -> SpineResult:
        """Navigate the active OpenClaw browser tab."""

        return self._run("navigate", ["navigate", url])

    def snapshot(self) -> SpineResult:
        """Capture a stable OpenClaw browser snapshot."""

        return self._run("snapshot", ["snapshot"])

    def click(self, ref: str) -> SpineResult:
        """Click a snapshot ref."""

        return self._run("click", ["click", ref])

    def click_text(self, text_or_ref: str) -> SpineResult:
        """Click a snapshot ref or text target supplied by an inferred playbook."""

        return self.click(text_or_ref)

    def type_text(self, ref: str, text: str) -> SpineResult:
        """Type text into a snapshot ref."""

        return self._run("type", ["type", ref, text])

    def fill_label(self, label_or_ref: str, value: str) -> SpineResult:
        """Fill a snapshot ref or label target supplied by an inferred playbook."""

        return self.type_text(label_or_ref, value)

    def press(self, key: str) -> SpineResult:
        """Press a key in the active OpenClaw browser tab."""

        return self._run("press", ["press", key])

    def wait_for_text(self, text: str) -> SpineResult:
        """Capture a snapshot while waiting logic is handled by the inference loop."""

        del text
        return self._run("wait_for_text", ["snapshot"])

    def _run(self, action: str, args: list[str]) -> SpineResult:
        command = [
            "env",
            f"OPENCLAW_HOME={openclaw_state_home()}",
            self._binary(),
            "browser",
            "--browser-profile",
            self.profile,
            *args,
        ]
        if self.dry_run:
            return SpineResult(action=action, command=tuple(command), status="dry-run")
        if self.runner is None and not self.available():
            raise ProviderError(
                "OpenClaw CLI is not available. Install OpenClaw or run with --dry-run-spine."
            )
        run = self.runner or _default_runner
        completed = run(command)
        status = "ok" if completed.returncode == 0 else "failed"
        if completed.returncode != 0:
            raise ProviderError(
                f"OpenClaw browser action failed: {action}: {completed.stderr.strip()}"
            )
        return SpineResult(
            action=action,
            command=tuple(command),
            status=status,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _binary(self) -> str:
        return self.binary or os.environ.get("FUSEKIT_OPENCLAW_BIN", openclaw_binary())


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, check=False, text=True, timeout=60)
