"""OpenClaw browser spine adapter."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fusekit.errors import ProviderError
from fusekit.runtime.bootstrap import _openclaw_env_prefix, openclaw_binary


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
            "command": _safe_command(self.action, self.command),
            "status": self.status,
            "stdout": _safe_output(self.action, self.stdout),
            "stderr": _safe_output(self.action, self.stderr),
        }


@dataclass
class OpenClawBrowserSpine:
    """Adapter around `openclaw browser`."""

    profile: str = "openclaw"
    binary: str | None = None
    dry_run: bool = False
    efficient_snapshots: bool = True
    label_snapshots: bool = False
    runner: CommandRunner | None = None

    def available(self) -> bool:
        """Return whether the configured OpenClaw binary is available."""

        binary = self._binary()
        return self.dry_run or shutil.which(binary) is not None or Path(binary).exists()

    def browser_command_available(self) -> bool:
        """Return whether this OpenClaw build exposes browser automation commands."""

        if self.dry_run:
            return True
        if not self.available():
            return False
        run = self.runner or _default_runner
        try:
            completed = run([*_openclaw_env_prefix(), self._binary(), "browser", "doctor"])
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

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

        args = ["snapshot", "--interactive", "--compact", "--depth", "6"]
        if self.efficient_snapshots:
            args.append("--efficient")
        if self.label_snapshots:
            args.append("--labels")
        args.append("--json")
        return self._run("snapshot", args)

    def screenshot(self, *, full_page: bool = False) -> SpineResult:
        """Capture a screenshot for visual recovery/debugging."""

        args = ["screenshot"]
        if full_page:
            args.append("--full-page")
        return self._run("screenshot", args)

    def console_errors(self) -> SpineResult:
        """Read browser console errors for recovery evidence."""

        return self._run("console_errors", ["errors", "--clear", "--json"])

    def network_requests(self, *, filter_text: str = "api") -> SpineResult:
        """Read matching network requests for recovery evidence."""

        return self._run(
            "network_requests",
            ["requests", "--filter", filter_text, "--clear", "--json"],
        )

    def trace_start(self) -> SpineResult:
        """Start an OpenClaw browser trace."""

        return self._run("trace_start", ["trace", "start"])

    def trace_stop(self) -> SpineResult:
        """Stop an OpenClaw browser trace."""

        return self._run("trace_stop", ["trace", "stop"])

    def click(self, ref: str) -> SpineResult:
        """Click a snapshot ref."""

        return self._run("click", ["click", ref])

    def highlight(self, ref: str) -> SpineResult:
        """Highlight a snapshot ref for human attention."""

        return self._run("highlight", ["highlight", ref])

    def scroll_into_view(self, ref: str) -> SpineResult:
        """Scroll a snapshot ref into view before human attention or automation."""

        return self._run("scroll_into_view", ["scrollintoview", ref])

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
        """Wait for visible text through OpenClaw."""

        return self._run("wait_for_text", ["wait", "--text", text])

    def wait_for_state(
        self,
        *,
        selector: str = "",
        url: str = "",
        load: str = "networkidle",
        timeout_ms: int = 15000,
    ) -> SpineResult:
        """Wait for richer page readiness signals through OpenClaw."""

        args = ["wait"]
        if selector:
            args.append(selector)
        if url:
            args.extend(["--url", url])
        if load:
            args.extend(["--load", load])
        args.extend(["--timeout-ms", str(timeout_ms)])
        return self._run("wait_for_state", args)

    def _run(self, action: str, args: list[str]) -> SpineResult:
        command = [
            *_openclaw_env_prefix(),
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
        if self.runner is None and not self.browser_command_available():
            raise ProviderError(
                "OpenClaw browser commands are not available in this OpenClaw build. "
                "Run with --spine playwright for browser automation."
            )
        run = self.runner or _default_runner
        completed = run(command)
        status = "ok" if completed.returncode == 0 else "failed"
        if completed.returncode != 0:
            detail = _safe_output(action, completed.stderr.strip())
            suffix = f": {detail}" if detail else ""
            raise ProviderError(
                f"OpenClaw browser action failed: {action}{suffix}"
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


_BROWSER_OUTPUT_ACTIONS = {
    "console_errors",
    "network_requests",
    "screenshot",
    "snapshot",
    "trace_stop",
}


def _safe_command(action: str, command: tuple[str, ...]) -> list[str]:
    safe = list(command)
    if action == "type" and safe:
        safe[-1] = "[REDACTED]"
    return safe


def _safe_output(action: str, value: str) -> str:
    if not value:
        return ""
    if action in _BROWSER_OUTPUT_ACTIONS:
        return f"[REDACTED_BROWSER_OUTPUT bytes={len(value.encode('utf-8'))}]"
    return value
