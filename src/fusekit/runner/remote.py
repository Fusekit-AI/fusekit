"""Remote runner bootstrap artifacts."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from shlex import quote
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlencode

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

CONTROL_ROOM_PORT = 8765
NOVNC_PORT = 6080
VISUAL_DISPLAY = ":99"
PROVIDER_BROWSER_PROFILE = "/var/lib/fusekit-runner/visual/chrome-provider-profile"


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
    python_bin = "/opt/fusekit-python/bin/python"
    playwright_browsers_path = "/opt/fusekit-playwright-browsers"
    retry_bin = "/usr/local/sbin/fusekit-retry"
    apt_system_packages = (
        "python3 python3-pip python3-venv git openssh-client unzip jq "
        "ca-certificates curl"
    )
    apt_visual_packages = "xvfb fluxbox x11vnc novnc websockify xterm"
    fusekit_install_flags = "--upgrade"
    if fusekit_wheel_url.startswith("git+"):
        fusekit_install_flags = "--upgrade --force-reinstall --no-cache-dir"
    install_fusekit = f"{python_bin} -m pip install {fusekit_install_flags} {fusekit_package}"
    install_pip_tools = f"{python_bin} -m pip install --upgrade pip setuptools wheel"
    install_playwright = (
        f"env PLAYWRIGHT_BROWSERS_PATH={playwright_browsers_path} "
        f"{python_bin} -m playwright install --with-deps chromium"
    )
    install_openclaw = (
        "env OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state "
        "bash /opt/fusekit-openclaw/install-openclaw.sh "
        "--prefix /opt/fusekit-openclaw --version latest --no-onboard"
    )
    verify_openclaw = (
        "export PATH=/opt/fusekit-openclaw/bin:$PATH && "
        "OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state "
        "/usr/local/sbin/fusekit-runner-verify"
    )
    chown_runner_state = (
        "runner_user=; "
        "if id ubuntu >/dev/null 2>&1; then runner_user=ubuntu; "
        "elif id opc >/dev/null 2>&1; then runner_user=opc; fi; "
        "if [ -n \"$runner_user\" ]; then "
        "chown -R \"$runner_user:$runner_user\" "
        f"/var/lib/fusekit-runner {playwright_browsers_path}; "
        "fi"
    )
    runner_loop = (
        "fusekit-runner-loop /var/lib/fusekit-runner/app "
        "--job-state /var/lib/fusekit-runner/app/.fusekit/job.json "
        "--passphrase-file /var/lib/fusekit-runner/passphrase"
    )
    return f"""#cloud-config
apt:
  conf: |
    Acquire::ForceIPv4 "true";
  primary:
    - arches: [default]
      uri: http://archive.ubuntu.com/ubuntu
  security:
    - arches: [default]
      uri: http://security.ubuntu.com/ubuntu
write_files:
  - path: /usr/local/sbin/fusekit-retry
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      attempts=0
      until "$@"; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
          exit 1
        fi
        sleep $((attempts * 10))
      done
  - path: /usr/local/sbin/fusekit-runner-verify
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      export PATH=/opt/fusekit-python/bin:/opt/fusekit-openclaw/bin:$PATH
      export FUSEKIT_HOME=/var/lib/fusekit-runner/fusekit-runtime
      export FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw
      export OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state
      export PLAYWRIGHT_BROWSERS_PATH={playwright_browsers_path}
      case "$(uname -m)" in
        x86_64|amd64) ;;
        *)
          printf '%s\\n' "FuseKit runner requires x86_64 architecture; got $(uname -m)." >&2
          exit 1
          ;;
      esac
      test -x /usr/local/sbin/fusekit-runner-loop-once
      test -x /usr/local/sbin/fusekit-visual-start
      for command in Xvfb x11vnc fluxbox; do
        command -v "$command" >/dev/null 2>&1
      done
      if ! command -v websockify >/dev/null 2>&1 \
        && [ ! -x /usr/share/novnc/utils/novnc_proxy ]; then
        printf '%s\\n' "FuseKit runner requires websockify or novnc_proxy for noVNC." >&2
        exit 1
      fi
      mkdir -p /var/lib/fusekit-runner/visual/chrome-provider-profile
      python3 --version
      /opt/fusekit-python/bin/python --version
      fusekit --version
      openclaw --version
      openclaw doctor --non-interactive
      /opt/fusekit-python/bin/python - <<'PY'
      from playwright.sync_api import sync_playwright
      with sync_playwright() as playwright:
          browser = playwright.chromium.launch(headless=True)
          page = browser.new_page()
          page.goto('data:text/html,<title>fusekit-ok</title>')
          assert page.title() == 'fusekit-ok'
          browser.close()
      PY
      /opt/fusekit-python/bin/python - <<'PY'
      import json
      import platform
      from pathlib import Path
      readiness = dict(
          schema_version="fusekit.runner-readiness.v1",
          status="ready",
          architecture=platform.machine(),
          checks=dict(
              x86_64_architecture=True,
              runner_helpers=True,
              visual_commands=True,
              novnc=True,
              openclaw=True,
              playwright_chromium=True,
              shared_provider_browser_profile=True,
          ),
          provider_browser_profile="/var/lib/fusekit-runner/visual/chrome-provider-profile",
          playwright_browsers_path="{playwright_browsers_path}",
      )
      target = Path("/var/lib/fusekit-runner/runner-readiness.json")
      target.write_text(json.dumps(readiness, sort_keys=True) + "\\n", encoding="utf-8")
      target.chmod(0o600)
      PY
  - path: /usr/local/sbin/fusekit-runner-loop-once
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      export PATH=/opt/fusekit-python/bin:/opt/fusekit-openclaw/bin:$PATH
      export FUSEKIT_HOME=/var/lib/fusekit-runner/fusekit-runtime
      export FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw
      export OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state
      export PLAYWRIGHT_BROWSERS_PATH={playwright_browsers_path}
      {runner_loop}
  - path: /usr/local/sbin/fusekit-visual-start
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      display="${{FUSEKIT_VISUAL_DISPLAY:-{VISUAL_DISPLAY}}}"
      width="${{FUSEKIT_VISUAL_WIDTH:-1440}}"
      height="${{FUSEKIT_VISUAL_HEIGHT:-900}}"
      state_dir="/var/lib/fusekit-runner/visual"
      password_file="$state_dir/vnc.pass"
      password_text_file="$state_dir/vnc.password"
      mkdir -p "$state_dir"
      chmod 700 "$state_dir"
      if [ -n "${{FUSEKIT_VISUAL_PASSWORD:-}}" ]; then
        printf '%s\\n' "$FUSEKIT_VISUAL_PASSWORD" > "$password_text_file"
      elif [ ! -s "$password_text_file" ]; then
        python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$password_text_file"
      fi
      chmod 600 "$password_text_file"
      if [ ! -s "$password_file" ]; then
        x11vnc -storepasswd "$(cat "$password_text_file")" "$password_file" >/dev/null
        chmod 600 "$password_file"
      fi
      if ! pgrep -f "Xvfb $display" >/dev/null 2>&1; then
        nohup Xvfb "$display" -screen 0 "${{width}}x${{height}}x24" -nolisten tcp \
          > "$state_dir/xvfb.log" 2>&1 &
      fi
      export DISPLAY="$display"
      if command -v fluxbox >/dev/null 2>&1 && ! pgrep -f "fluxbox" >/dev/null 2>&1; then
        nohup fluxbox > "$state_dir/window-manager.log" 2>&1 &
      fi
      if ! pgrep -f "x11vnc.*5900" >/dev/null 2>&1; then
        nohup x11vnc -display "$display" -localhost -forever -shared -rfbport 5900 \
          -rfbauth "$password_file" -noxdamage -repeat -quiet \
          > "$state_dir/x11vnc.log" 2>&1 &
      fi
      novnc_web="/usr/share/novnc"
      if ! pgrep -f "websockify.*{NOVNC_PORT}" >/dev/null 2>&1; then
        if command -v websockify >/dev/null 2>&1; then
          nohup websockify --web "$novnc_web" 0.0.0.0:{NOVNC_PORT} localhost:5900 \
            > "$state_dir/novnc.log" 2>&1 &
        elif [ -x /usr/share/novnc/utils/novnc_proxy ]; then
          nohup /usr/share/novnc/utils/novnc_proxy --listen {NOVNC_PORT} --vnc localhost:5900 \
            > "$state_dir/novnc.log" 2>&1 &
        else
          printf '%s\\n' "websockify/noVNC is not installed" > "$state_dir/error"
          exit 1
        fi
      fi
runcmd:
  - mkdir -p /var/lib/fusekit-runner/visual/chrome-provider-profile
  - mkdir -p {playwright_browsers_path}
  - iptables -I INPUT -p tcp --dport {CONTROL_ROOM_PORT} -j ACCEPT || true
  - iptables -I INPUT -p tcp --dport {NOVNC_PORT} -j ACCEPT || true
  - |
    if command -v apt-get >/dev/null 2>&1; then
      {retry_bin} apt-get -o Acquire::ForceIPv4=true update
      DEBIAN_FRONTEND=noninteractive {retry_bin} apt-get \
        -o Acquire::ForceIPv4=true install -y {apt_system_packages}
    fi
  - python3 -m venv /opt/fusekit-python
  - {retry_bin} {install_pip_tools}
  - {retry_bin} {install_fusekit}
  - {retry_bin} {install_playwright}
  - |
    if command -v apt-get >/dev/null 2>&1; then
      {retry_bin} apt-get -o Acquire::ForceIPv4=true update
      DEBIAN_FRONTEND=noninteractive {retry_bin} apt-get \
        -o Acquire::ForceIPv4=true install -y {apt_visual_packages}
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y xorg-x11-server-Xvfb fluxbox x11vnc novnc python3-websockify || true
    fi
  - ln -sf /opt/fusekit-python/bin/fusekit /usr/local/bin/fusekit
  - ln -sf /opt/fusekit-python/bin/fusekit-runner-loop /usr/local/bin/fusekit-runner-loop
  - mkdir -p /opt/fusekit-openclaw
  - |
    python3 - <<'PY'
    import pathlib, time, urllib.request
    url = {openclaw_install_url!r}
    target = pathlib.Path('/opt/fusekit-openclaw/install-openclaw.sh')
    for attempt in range(1, 6):
        try:
            target.write_bytes(urllib.request.urlopen(url, timeout=60).read())
            break
        except OSError as exc:
            if attempt == 5:
                raise
            time.sleep(attempt * 10)
    target.chmod(0o755)
    PY
  - {retry_bin} {install_openclaw}
  - ln -sf /opt/fusekit-openclaw/bin/openclaw /usr/local/bin/openclaw
  - |
    runner_user=
    if id ubuntu >/dev/null 2>&1; then
      runner_user=ubuntu
    elif id opc >/dev/null 2>&1; then
      runner_user=opc
    fi
    if [ -n "$runner_user" ]; then
      chown -R "$runner_user:$runner_user" /var/lib/fusekit-runner {playwright_browsers_path}
    fi
  - {verify_openclaw}
  - {chown_runner_state}
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
        remote = _workspace_remote(workspace)
        ssh = _ssh_base(key_path)
        scp = _scp_base(key_path)
        _wait_for_remote_ready(run, ssh, remote)
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
                *ssh,
                remote,
                "cp /var/lib/fusekit-runner/runner-readiness.json "
                "/var/lib/fusekit-runner/app/.fusekit/runner_readiness.json",
            ],
        )
        _run_checked(
            run,
            [
                *scp,
                str(vault_snapshot),
                f"{remote}:/var/lib/fusekit-runner/app/.fusekit/fusekit.vault.json",
            ],
        )
        visual = _remote_visual_session(workspace, launch_args)
        if visual is not None:
            _prepare_remote_visual_session(run, ssh, remote, visual)
        display_export = f"export DISPLAY={quote(VISUAL_DISPLAY)}; " if visual is not None else ""
        openclaw_browser_prepare = ""
        if visual is not None:
            openclaw_browser_prepare = (
                "chrome_path=$(find /opt/fusekit-playwright-browsers -type f "
                "\\( -path '*/chrome-linux*/chrome' -o -path '*/chrome-linux64/chrome' \\) "
                "-perm -111 | head -n 1); "
                "if [ -n \"$chrome_path\" ]; then "
                "openclaw config set browser.executablePath \"$chrome_path\" "
                ">/dev/null 2>&1 || true; "
                "openclaw config set browser.headless false --strict-json >/dev/null 2>&1 || true; "
                "openclaw config set browser.noSandbox true --strict-json >/dev/null 2>&1 || true; "
                "openclaw config set gateway.auth.mode none >/dev/null 2>&1 || true; "
                "openclaw config set gateway.port 19002 --strict-json >/dev/null 2>&1 || true; "
                "openclaw config set gateway.remote.url ws://127.0.0.1:19002 "
                ">/dev/null 2>&1 || true; "
                "pgrep -f 'openclaw gateway run.*19002' >/dev/null 2>&1 || "
                "nohup env DISPLAY=$DISPLAY openclaw gateway run --allow-unconfigured "
                "--auth none --bind loopback --port 19002 --compact "
                "> /var/lib/fusekit-runner/openclaw-gateway.log 2>&1 & "
                "sleep 2; "
                "fi; "
            )
        launch = (
            "umask 077; "
            "export PATH=/opt/fusekit-python/bin:/opt/fusekit-openclaw/bin:$PATH; "
            "export FUSEKIT_HOME=/var/lib/fusekit-runner/fusekit-runtime; "
            "export FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw; "
            "export FUSEKIT_OPENCLAW_HOME_MODE=default; "
            "unset OPENCLAW_HOME; "
            "export PLAYWRIGHT_BROWSERS_PATH=/opt/fusekit-playwright-browsers; "
            f"export FUSEKIT_PROVIDER_BROWSER_PROFILE={quote(PROVIDER_BROWSER_PROFILE)}; "
            f"{display_export}"
            f"{openclaw_browser_prepare}"
            "trap 'rm -f /var/lib/fusekit-runner/passphrase' EXIT; "
            "cat > /var/lib/fusekit-runner/passphrase; "
            "cd /var/lib/fusekit-runner/app; "
            "fusekit launch . --runner local --yes "
            "--passphrase-file /var/lib/fusekit-runner/passphrase "
            f"{_quote_args(launch_args)}"
        )
        _run_checked(run, [*ssh, remote, launch], input_text=passphrase, stream_output=True)
        local_output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = local_output_dir / "fusekit-artifacts.tar.gz"
        fetch = (
            "cd /var/lib/fusekit-runner/app && "
            "set -- .fusekit/fusekit.vault.json .fusekit/audit.jsonl "
            ".fusekit/setup_receipt.json .fusekit/setup_receipt.md .fusekit/job.json "
            ".fusekit/checkpoints.json .fusekit/run_record.json "
            ".fusekit/verification_report.json "
            ".fusekit/rollback_plan.json .fusekit/provider_strategies.json "
            ".fusekit/gates.json .fusekit/gate_events.jsonl "
            ".fusekit/runner_readiness.json; "
            "existing=''; "
            "for path in \"$@\"; do [ -f \"$path\" ] && existing=\"$existing $path\"; done; "
            "[ -n \"$existing\" ] || exit 44; "
            "tar -czf - $existing"
        )
        _run_checked(run, [*ssh, remote, fetch], stdout_path=artifacts)
        _extract_artifacts(artifacts, local_output_dir)
        completeness = _validate_artifact_bundle(local_output_dir)
    return {
        "artifact_archive": str(artifacts),
        "output_dir": str(local_output_dir),
        "artifact_status": completeness,
        **({"control_room_url": visual["control_room_url"]} if visual is not None else {}),
        **({"novnc_url": visual["novnc_url"]} if visual is not None else {}),
    }


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
        remote = _workspace_remote(workspace)
        cleanup_script = (
            "pkill -f '[f]usekit control-room --serve' || true; "
            "pkill -f '[o]penclaw gateway run.*19002' || true; "
            "pkill -f '[c]hrome-linux.*/chrome' || true; "
            "pkill -f '[w]ebsockify.*6080' || true; "
            "pkill -f '[x]11vnc.*5900' || true; "
            "pkill -f '[X]vfb :99' || true; "
            "pkill -f '[f]luxbox' || true; "
            "rm -rf /var/lib/fusekit-runner/app "
            "/var/lib/fusekit-runner/tmp "
            "/var/lib/fusekit-runner/openclaw-state "
            "/var/lib/fusekit-runner/passphrase "
            "/var/lib/fusekit-runner/app.tar.gz "
            "/var/lib/fusekit-runner/visual "
            "/var/lib/fusekit-runner/control-room.log "
            "/var/lib/fusekit-runner/openclaw-gateway.log"
        )
        command = (
            "sudo -n sh -c "
            + quote(cleanup_script)
            + " || "
            "sh -c "
            + quote(cleanup_script)
        )
        _run_checked(run, [*_ssh_base(key_path), remote, command])


def _quote_args(args: tuple[str, ...]) -> str:
    return " ".join(quote(arg) for arg in args)


def _remote_visual_session(
    workspace: OciWorkspace,
    launch_args: tuple[str, ...],
) -> dict[str, str] | None:
    mode = _launch_arg_value(launch_args, "--visual-runner")
    if mode in {"", "off"}:
        return None
    if mode == "auto":
        mode = "novnc"
    if mode != "novnc":
        return None
    public_ip = str(getattr(workspace, "public_ip", "") or "")
    if not public_ip:
        return None
    control_token = secrets.token_urlsafe(24)
    visual_password = secrets.token_urlsafe(18)
    novnc_params = urlencode(
        {
            "autoconnect": "1",
            "resize": "scale",
        }
    )
    return {
        "mode": "novnc",
        "display": VISUAL_DISPLAY,
        "control_room_token": control_token,
        "control_room_url": f"http://{public_ip}:{CONTROL_ROOM_PORT}/?token={control_token}",
        "novnc_url": f"http://{public_ip}:{NOVNC_PORT}/vnc.html?{novnc_params}",
        "novnc_password": visual_password,
    }


def _launch_arg_value(args: tuple[str, ...], flag: str) -> str:
    try:
        index = args.index(flag)
    except ValueError:
        return ""
    if index + 1 >= len(args):
        return ""
    return args[index + 1]


def _prepare_remote_visual_session(
    runner: CommandRunner,
    ssh: list[str],
    remote: str,
    visual: dict[str, str],
) -> None:
    visual_payload = {
        "runner": "novnc",
        "status": "starting",
        "interactive": True,
        "display": visual["display"],
        "control_room_url": visual["control_room_url"],
        "novnc_url": visual["novnc_url"],
        "novnc_password": visual["novnc_password"],
        "provider_browser_profile": PROVIDER_BROWSER_PROFILE,
        "notes": [
            "The browser is running on the disposable OCI VM.",
            "Use the noVNC window to complete human gates in the same session FuseKit observes.",
        ],
    }
    visual_ready_payload = {**visual_payload, "status": "ready"}
    initial_visual_job = {
        "id": "remote-visual-session",
        "app_path": "/var/lib/fusekit-runner/app",
        "runner": "oci-remote",
        "status": "running",
        "steps": [
            {
                "id": "remote.bootstrap",
                "label": "Bootstrap FuseKit and visual browser session",
                "status": "running",
                "detail": "FuseKit is starting the live VM browser.",
            }
        ],
        "checkpoints": [],
        "artifacts": {"visual_session": "/var/lib/fusekit-runner/app/.fusekit/visual.json"},
    }
    command = (
        "umask 077; "
        "mkdir -p /var/lib/fusekit-runner/app/.fusekit /var/lib/fusekit-runner; "
        f"printf %s {quote(json.dumps(visual_payload, sort_keys=True))} "
        "> /var/lib/fusekit-runner/app/.fusekit/visual.json; "
        "[ -f /var/lib/fusekit-runner/app/.fusekit/job.json ] || "
        f"printf %s {quote(json.dumps(initial_visual_job, sort_keys=True))} "
        "> /var/lib/fusekit-runner/app/.fusekit/job.json; "
        f"export FUSEKIT_VISUAL_PASSWORD={quote(visual['novnc_password'])}; "
        f"export FUSEKIT_VISUAL_DISPLAY={quote(visual['display'])}; "
        f"export FUSEKIT_PROVIDER_BROWSER_PROFILE={quote(PROVIDER_BROWSER_PROFILE)}; "
        "/usr/local/sbin/fusekit-visual-start; "
        f"for i in $(seq 1 20); do "
        f"if curl -fsS http://127.0.0.1:{NOVNC_PORT}/vnc.html >/dev/null 2>&1; "
        "then break; fi; sleep 1; done; "
        f"curl -fsS http://127.0.0.1:{NOVNC_PORT}/vnc.html >/dev/null || "
        "(cat /var/lib/fusekit-runner/visual/*.log "
        "/var/lib/fusekit-runner/visual/error 2>/dev/null >&2; exit 45); "
        f"printf %s {quote(json.dumps(visual_ready_payload, sort_keys=True))} "
        "> /var/lib/fusekit-runner/app/.fusekit/visual.json; "
        f"export FUSEKIT_CONTROL_ROOM_TOKEN={quote(visual['control_room_token'])}; "
        "export FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1; "
        f"export FUSEKIT_PROVIDER_BROWSER_PROFILE={quote(PROVIDER_BROWSER_PROFILE)}; "
        "nohup fusekit control-room --serve "
        "--job-state /var/lib/fusekit-runner/app/.fusekit/job.json "
        f"--host 0.0.0.0 --port {CONTROL_ROOM_PORT} "
        "> /var/lib/fusekit-runner/control-room.log 2>&1 &"
    )
    _run_checked(runner, [*ssh, remote, command])


def _create_app_archive(app_path: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz") as tar:
        for path in app_path.rglob("*"):
            relative = path.relative_to(app_path)
            if not should_include_app_path(relative):
                continue
            tar.add(path, arcname=str(relative), recursive=False)


def _extract_artifacts(archive: Path, output_dir: Path) -> None:
    try:
        extracted = 0
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                target = (output_dir / member.name).resolve()
                try:
                    target.relative_to(output_dir.resolve())
                except ValueError:
                    raise FuseKitError(
                        "Remote artifact archive contains unsafe paths."
                    ) from None
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    continue
                with source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                    extracted += 1
        if extracted == 0:
            raise FuseKitError("Remote artifact archive did not contain files.")
    except tarfile.TarError as exc:
        raise FuseKitError("Remote artifact archive could not be read.") from exc


def _validate_artifact_bundle(output_dir: Path) -> str:
    required = (
        ".fusekit/fusekit.vault.json",
        ".fusekit/audit.jsonl",
        ".fusekit/setup_receipt.json",
        ".fusekit/job.json",
        ".fusekit/checkpoints.json",
        ".fusekit/run_record.json",
        ".fusekit/verification_report.json",
        ".fusekit/rollback_plan.json",
        ".fusekit/provider_strategies.json",
        ".fusekit/runner_readiness.json",
    )
    missing = [path for path in required if not (output_dir / path).is_file()]
    if missing:
        raise FuseKitError(
            "Remote artifact bundle is incomplete; missing "
            + ", ".join(missing)
            + ". Detonation should not be trusted until artifacts are recovered."
        )
    return "complete"


def _workspace_ssh_private_key(vault: Vault, run_id: str) -> str:
    return vault.require(f"runner.oci.{run_id}.ssh.private").value


def _workspace_remote(workspace: OciWorkspace) -> str:
    ssh_user = getattr(workspace, "ssh_user", "opc") or "opc"
    return f"{ssh_user}@{workspace.public_ip}"


def _ssh_base(key_path: Path) -> list[str]:
    return [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(key_path),
    ]


def _scp_base(key_path: Path) -> list[str]:
    return [
        "scp",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(key_path),
    ]


def _wait_for_remote_ready(
    runner: CommandRunner,
    ssh: list[str],
    remote: str,
    *,
    attempts: int = 60,
    delay_seconds: int = 10,
) -> None:
    last_error = ""
    for attempt in range(1, attempts + 1):
        completed = runner([*ssh, remote, "true"])
        if completed.returncode == 0:
            _run_checked(
                runner,
                [*ssh, remote, _remote_ready_command()],
            )
            return
        last_error = completed.stderr.strip() or completed.stdout.strip()
        if attempt < attempts:
            time.sleep(delay_seconds)
    detail = f" Last SSH error: {last_error[:500]}" if last_error else ""
    raise FuseKitError(f"OCI runner did not become reachable over SSH.{detail}")


def _remote_ready_command(*, timeout_seconds: int = 1200) -> str:
    polls = max(1, timeout_seconds // 10)
    return (
        f"timeout_polls={polls}; "
        "cloud_status=''; "
        "for i in $(seq 1 \"$timeout_polls\"); do "
        "cloud_status=$(cloud-init status --long 2>&1 || true); "
        "if ! printf '%s\\n' \"$cloud_status\" | grep -Eqi 'status:.*running'; "
        "then break; fi; "
        "sleep 10; "
        "done; "
        "cloud_status=$(cloud-init status --long 2>&1 || true); "
        "if printf '%s\\n' \"$cloud_status\" | grep -Eqi 'status:.*running'; then "
        "printf '%s\\n' \"$cloud_status\" >&2; "
        "printf '%s\\n' 'cloud-init did not finish before FuseKit runner readiness timeout.' >&2; "
        "printf '%s\\n' '--- cloud-init-output tail ---' >&2; "
        "sudo tail -120 /var/log/cloud-init-output.log >&2 2>/dev/null || true; "
        "exit 124; fi; "
        "cloud_degraded=0; "
        "if printf '%s\\n' \"$cloud_status\" | "
        "grep -Eqi 'status:.*degraded|extended_status:.*degraded|status:.*error'; "
        "then cloud_degraded=1; fi; "
        "if [ ! -x /usr/local/sbin/fusekit-runner-verify ]; then "
        "printf '%s\\n' \"$cloud_status\" >&2; "
        "printf '%s\\n' '--- cloud-init-output tail ---' >&2; "
        "sudo tail -120 /var/log/cloud-init-output.log >&2 2>/dev/null || true; "
        "printf '%s\\n' 'fusekit-runner-verify missing; "
        "cloud-init bootstrap did not install runner helpers.' >&2; exit 127; fi; "
        "if [ \"$cloud_degraded\" = 1 ]; then "
        "printf '%s\\n' \"$cloud_status\" >&2; "
        "printf '%s\\n' 'cloud-init is degraded, but runner helpers exist; "
        "continuing only if runner verification passes.' >&2; fi; "
        "/usr/local/sbin/fusekit-runner-verify"
    )


def _run_checked(
    runner: CommandRunner,
    command: list[str],
    *,
    input_text: str | None = None,
    stdout_path: Path | None = None,
    stream_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    if stream_output and runner is _default_runner:
        completed = _default_runner(
            command,
            input_text=input_text,
            stdout_path=stdout_path,
            stream_output=True,
        )
    else:
        completed = runner(command, input_text=input_text, stdout_path=stdout_path)
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        message = f"Remote runner command failed with exit {completed.returncode}."
        if detail:
            message = f"{message} {detail[:500]}"
        raise FuseKitError(message)
    return completed


def _default_runner(
    command: list[str],
    *,
    input_text: str | None = None,
    stdout_path: Path | None = None,
    stream_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    if stdout_path is None:
        if stream_output:
            process = subprocess.Popen(  # noqa: S603
                command,
                stdin=subprocess.PIPE,
                text=True,
            )
            try:
                process.communicate(input=input_text, timeout=3600)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                return subprocess.CompletedProcess(
                    command,
                    124,
                    stdout="",
                    stderr="Remote runner command timed out after 3600 seconds.",
                )
            return subprocess.CompletedProcess(command, process.returncode, stdout="", stderr="")
        return subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            check=False,
            text=True,
            timeout=3600,
        )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        timeout=3600,
    )
    stdout_path.write_bytes(completed.stdout)
    return subprocess.CompletedProcess(
        command,
        completed.returncode,
        stdout="",
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )
