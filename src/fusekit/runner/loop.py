"""Durable remote runner loop."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.runner.job import JobState


def run_remote_loop(
    *,
    app_path: Path,
    job_state: Path,
    passphrase_file: Path,
    interval_seconds: float = 5.0,
    once: bool = True,
) -> int:
    """Run the remote setup loop with checkpoint updates."""

    job = JobState.load(job_state) if job_state.exists() else JobState.create(
        f"remote-{int(time.time())}",
        app_path,
        "remote-vm",
    )
    while True:
        job.mark("setup.execute", "running", "remote FuseKit launch started")
        job.save(job_state)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "fusekit",
                "launch",
                str(app_path),
                "--runner",
                "local",
                "--yes",
                "--passphrase-file",
                str(passphrase_file),
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=7200,
        )
        if completed.returncode == 0:
            job.mark("setup.execute", "done", "remote FuseKit launch completed")
            job.mark("verify.live", "done", "verification delegated to setup receipt")
            job.save(job_state)
            return 0
        job.mark("setup.execute", "failed", "remote FuseKit launch failed")
        job.save(job_state)
        if once:
            raise FuseKitError("Remote FuseKit launch failed.")
        time.sleep(interval_seconds)


def main(argv: list[str] | None = None) -> int:
    """Remote loop CLI entrypoint."""

    parser = argparse.ArgumentParser(prog="fusekit-runner-loop")
    parser.add_argument("app_path", type=Path)
    parser.add_argument("--job-state", type=Path, default=Path(".fusekit/job.json"))
    parser.add_argument("--passphrase-file", type=Path, required=True)
    parser.add_argument("--forever", action="store_true")
    args = parser.parse_args(argv)
    return run_remote_loop(
        app_path=args.app_path,
        job_state=args.job_state,
        passphrase_file=args.passphrase_file,
        once=not args.forever,
    )


if __name__ == "__main__":
    raise SystemExit(main())
