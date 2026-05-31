"""Remote runner bootstrap artifacts."""

from __future__ import annotations

import subprocess
import tarfile
import tempfile
from pathlib import Path
from shlex import quote
from typing import TYPE_CHECKING, Protocol

from fusekit.errors import FuseKitError
from fusekit.vault import Vault

if TYPE_CHECKING:
    from fusekit.runner.oci_live import OciWorkspace

EXCLUDED_APP_PATHS = (
    ".git",
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.preview",
    ".npmrc",
    ".pypirc",
    ".vercel",
    ".fusekit",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
)


class CommandRunner(Protocol):
    """Command runner for SSH/SCP commands."""

    def __call__(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a command."""


def should_include_app_path(path: Path) -> bool:
    """Return true when a repo path may be uploaded to a remote runner."""

    parts = set(path.parts)
    if any(excluded in parts for excluded in EXCLUDED_APP_PATHS):
        return False
    name = path.name
    lower_name = name.lower()
    if lower_name.startswith(".env."):
        return False
    if lower_name in {"id_rsa", "id_ed25519", "id_ecdsa", "credentials.json"}:
        return False
    if lower_name.endswith((".vault", ".vault.json", ".pem", ".key", ".p12", ".pfx")):
        return False
    if any(marker in lower_name for marker in ("secret", "credential", "private_key")) and (
        lower_name.endswith((".json", ".txt", ".env", ".yaml", ".yml"))
    ):
        return False
    return True


def render_cloud_init(*, fusekit_wheel_url: str = "", openclaw_install_url: str) -> str:
    """Render cloud-init for a self-contained FuseKit runner VM."""

    fusekit_package = quote(fusekit_wheel_url or "fusekit")
    install_fusekit = f"python3 -m pip install --upgrade {fusekit_package}"
    install_openclaw = (
        "OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state "
        "bash /opt/fusekit-openclaw/install-openclaw.sh "
        "--prefix /opt/fusekit-openclaw --version latest --no-onboard"
    )
    verify_openclaw = (
        "export PATH=/opt/fusekit-openclaw/bin:$PATH && "
        "OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state fusekit-runner-verify"
    )
    runner_loop = (
        "fusekit-runner-loop /var/lib/fusekit-runner/app "
        "--job-state /var/lib/fusekit-runner/app/.fusekit/job.json "
        "--passphrase-file /var/lib/fusekit-runner/passphrase"
    )
    return f"""#cloud-config
package_update: true
packages:
  - python3
  - python3-pip
  - git
  - openssh-client
  - unzip
  - jq
  - ca-certificates
  - curl
  - chromium-browser
write_files:
  - path: /usr/local/sbin/fusekit-runner-verify
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      python3 --version
      fusekit --version
      openclaw --version
      openclaw doctor --non-interactive
      openclaw browser status
  - path: /usr/local/sbin/fusekit-runner-loop-once
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      {runner_loop}
runcmd:
  - mkdir -p /var/lib/fusekit-runner
  - python3 -m pip install --upgrade pip
  - {install_fusekit}
  - python3 -m playwright install --with-deps chromium
  - mkdir -p /opt/fusekit-openclaw
  - python3 - <<'PY'
import pathlib, urllib.request
url = {openclaw_install_url!r}
target = pathlib.Path('/opt/fusekit-openclaw/install-openclaw.sh')
target.write_bytes(urllib.request.urlopen(url, timeout=60).read())
target.chmod(0o755)
PY
  - {install_openclaw}
  - {verify_openclaw}
"""


def execute_remote_setup(
    *,
    workspace: OciWorkspace,
    vault: Vault,
    app_path: Path,
    local_output_dir: Path,
    passphrase: str,
    launch_args: tuple[str, ...] = (),
    runner: CommandRunner | None = None,
) -> dict[str, str]:
    """Upload an app, run FuseKit remotely, and download encrypted/redacted artifacts."""

    key = _workspace_ssh_private_key(vault, workspace.id)
    run = runner or _default_runner
    with tempfile.TemporaryDirectory(prefix="fusekit-oci-") as temp:
        temp_path = Path(temp)
        key_path = temp_path / "runner.key"
        key_path.write_text(key, encoding="utf-8")
        key_path.chmod(0o600)
        archive = temp_path / "app.tar.gz"
        _create_app_archive(app_path, archive)
        remote = f"opc@{workspace.public_ip}"
        ssh = _ssh_base(key_path)
        scp = _scp_base(key_path)
        _run_checked(run, [*ssh, remote, "mkdir -p /var/lib/fusekit-runner/app"])
        _run_checked(run, [*scp, str(archive), f"{remote}:/var/lib/fusekit-runner/app.tar.gz"])
        _run_checked(
            run,
            [
                *ssh,
                remote,
                "tar -xzf /var/lib/fusekit-runner/app.tar.gz "
                "-C /var/lib/fusekit-runner/app",
            ],
        )
        vault_snapshot = temp_path / "fusekit.vault.json"
        vault.save(vault_snapshot, passphrase)
        _run_checked(run, [*ssh, remote, "mkdir -p /var/lib/fusekit-runner/app/.fusekit"])
        _run_checked(
            run,
            [
                *scp,
                str(vault_snapshot),
                f"{remote}:/var/lib/fusekit-runner/app/.fusekit/fusekit.vault.json",
            ],
        )
        launch = (
            "umask 077; "
            "trap 'rm -f /var/lib/fusekit-runner/passphrase' EXIT; "
            "cat > /var/lib/fusekit-runner/passphrase; "
            "cd /var/lib/fusekit-runner/app; "
            "fusekit launch . --runner local --yes "
            "--passphrase-file /var/lib/fusekit-runner/passphrase "
            f"{_quote_args(launch_args)}"
        )
        _run_checked(run, [*ssh, remote, launch], input_text=passphrase)
        local_output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = local_output_dir / "fusekit-artifacts.tar.gz"
        fetch = (
            "cd /var/lib/fusekit-runner/app && "
            "set -- .fusekit/fusekit.vault.json .fusekit/audit.jsonl "
            ".fusekit/setup_receipt.json .fusekit/setup_receipt.md .fusekit/job.json "
            ".fusekit/gates.json; "
            "existing=''; "
            "for path in \"$@\"; do [ -f \"$path\" ] && existing=\"$existing $path\"; done; "
            "[ -n \"$existing\" ] || exit 44; "
            "tar -czf - $existing"
        )
        _run_checked(run, [*ssh, remote, fetch], stdout_path=artifacts)
        _extract_artifacts(artifacts, local_output_dir)
    return {"artifact_archive": str(artifacts), "output_dir": str(local_output_dir)}


def detonate_remote_worker(
    *,
    workspace: OciWorkspace,
    vault: Vault,
    runner: CommandRunner | None = None,
) -> None:
    """Remove remote plaintext worker state over SSH."""

    key = _workspace_ssh_private_key(vault, workspace.id)
    run = runner or _default_runner
    with tempfile.TemporaryDirectory(prefix="fusekit-oci-key-") as temp:
        key_path = Path(temp) / "runner.key"
        key_path.write_text(key, encoding="utf-8")
        key_path.chmod(0o600)
        remote = f"opc@{workspace.public_ip}"
        command = (
            "rm -rf /var/lib/fusekit-runner/app "
            "/var/lib/fusekit-runner/tmp "
            "/var/lib/fusekit-runner/openclaw-state "
            "/var/lib/fusekit-runner/passphrase "
            "/var/lib/fusekit-runner/app.tar.gz"
        )
        _run_checked(run, [*_ssh_base(key_path), remote, command])


def _quote_args(args: tuple[str, ...]) -> str:
    return " ".join(quote(arg) for arg in args)


def _create_app_archive(app_path: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz") as tar:
        for path in app_path.rglob("*"):
            relative = path.relative_to(app_path)
            if not should_include_app_path(relative):
                continue
            tar.add(path, arcname=str(relative), recursive=False)


def _extract_artifacts(archive: Path, output_dir: Path) -> None:
    try:
        with tarfile.open(archive, "r:gz") as tar:
            safe_members = []
            for member in tar.getmembers():
                target = (output_dir / member.name).resolve()
                try:
                    target.relative_to(output_dir.resolve())
                except ValueError:
                    continue
                safe_members.append(member)
            tar.extractall(output_dir, members=safe_members)
    except tarfile.TarError as exc:
        raise FuseKitError("Remote artifact archive could not be read.") from exc


def _workspace_ssh_private_key(vault: Vault, run_id: str) -> str:
    return vault.require(f"runner.oci.{run_id}.ssh.private").value


def _ssh_base(key_path: Path) -> list[str]:
    return [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
        str(key_path),
    ]


def _scp_base(key_path: Path) -> list[str]:
    return [
        "scp",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
        str(key_path),
    ]


def _run_checked(
    runner: CommandRunner,
    command: list[str],
    *,
    input_text: str | None = None,
    stdout_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = runner(command, input_text=input_text, stdout_path=stdout_path)
    if completed.returncode != 0:
        raise FuseKitError(completed.stderr or "Remote runner command failed.")
    return completed


def _default_runner(
    command: list[str],
    *,
    input_text: str | None = None,
    stdout_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if stdout_path is None:
        return subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            check=False,
            text=True,
            timeout=1800,
        )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        timeout=1800,
    )
    stdout_path.write_bytes(completed.stdout)
    return subprocess.CompletedProcess(
        command,
        completed.returncode,
        stdout="",
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )
