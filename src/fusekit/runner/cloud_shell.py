"""OCI Cloud Shell deeplink and local launcher helpers."""

from __future__ import annotations

import html
import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode

OCI_CLOUD_SHELL_URL = "https://cloud.oracle.com/"


@dataclass(frozen=True)
class CloudShellLaunchPlan:
    """Non-secret Cloud Shell launch material."""

    app_source: str
    fusekit_package: str
    launch_args: tuple[str, ...]
    deeplink_url: str
    bootstrap_command: str
    fallback_steps: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the launch plan."""

        return {
            "app_source": self.app_source,
            "fusekit_package": self.fusekit_package,
            "launch_args": list(self.launch_args),
            "deeplink_url": self.deeplink_url,
            "bootstrap_command": self.bootstrap_command,
            "fallback_steps": list(self.fallback_steps),
        }


def build_cloud_shell_launch_plan(
    *,
    app_source: str = "",
    fusekit_package: str = "fusekit",
    runner: str = "oci-existing",
    fusekit_gates: str = "service-only",
    launch_args: tuple[str, ...] = (),
) -> CloudShellLaunchPlan:
    """Build a real-capable OCI Cloud Shell bootstrap plan."""

    command = build_cloud_shell_bootstrap_command(
        app_source=app_source,
        fusekit_package=fusekit_package,
        runner=runner,
        fusekit_gates=fusekit_gates,
        launch_args=launch_args,
    )
    return CloudShellLaunchPlan(
        app_source=app_source,
        fusekit_package=fusekit_package,
        launch_args=launch_args,
        deeplink_url=cloud_shell_deeplink(command),
        bootstrap_command=command,
        fallback_steps=(
            "Open Oracle Cloud Shell.",
            "Paste and run the bootstrap command if Oracle does not auto-run deeplink commands.",
            "Enter the vault passphrase only when Cloud Shell prompts for it.",
            "Let the Cloud Shell bootstrap provision the disposable FuseKit runner.",
        ),
    )


def build_cloud_shell_bootstrap_command(
    *,
    app_source: str = "",
    fusekit_package: str = "fusekit",
    runner: str = "oci-existing",
    fusekit_gates: str = "service-only",
    launch_args: tuple[str, ...] = (),
) -> str:
    """Return a shell command that starts FuseKit from OCI Cloud Shell."""

    package = shlex.quote(fusekit_package)
    source = shlex.quote(app_source)
    runner_arg = shlex.quote(runner)
    gates_arg = shlex.quote(fusekit_gates)
    extra_args = " ".join(shlex.quote(arg) for arg in launch_args)
    launch_suffix = f" {extra_args}" if extra_args else ""
    source_fetch_args = " ".join(shlex.quote(arg) for arg in _source_fetch_args(launch_args))
    source_fetch_suffix = f" {source_fetch_args}" if source_fetch_args else ""
    return (
        "bash -lc "
        + shlex.quote(
            "\n".join(
                [
                    "set -euo pipefail",
                    "export PATH=\"$HOME/.local/bin:$PATH\"",
                    "work=\"$HOME/fusekit-cloud-shell\"",
                    "passfile=\"\"",
                    (
                        "cleanup() { stty echo >/dev/null 2>&1 || true; "
                        "[ -n \"${passfile:-}\" ] && rm -f \"$passfile\"; }"
                    ),
                    "trap cleanup EXIT INT TERM",
                    (
                        "retry() { attempts=0; until \"$@\"; do attempts=$((attempts + 1)); "
                        "if [ \"$attempts\" -ge 3 ]; then return 1; fi; "
                        "printf '%s\\n' \"Retrying after transient setup failure: $*\" >&2; "
                        "sleep $((attempts * 5)); done; }"
                    ),
                    "rm -rf \"$work\"",
                    "mkdir -p \"$work\"",
                    (
                        "if command -v python3 >/dev/null 2>&1; then python_cmd=python3; "
                        "elif command -v python >/dev/null 2>&1; then python_cmd=python; "
                        "else printf '%s\\n' 'Python is required in OCI Cloud Shell.' >&2; "
                        "exit 43; fi"
                    ),
                    "pip_target_flag=--user",
                    f"fusekit_package={package}",
                    (
                        "if [ \"${fusekit_package#git+}\" != \"$fusekit_package\" ] && "
                        "! command -v git >/dev/null 2>&1; then "
                        "printf '%s\\n' 'Git is required in OCI Cloud Shell for git+ "
                        "FuseKit packages.' >&2; exit 43; fi"
                    ),
                    "\"$python_cmd\" -m ensurepip --upgrade >/dev/null 2>&1 || true",
                    "retry \"$python_cmd\" -m pip install --user --upgrade pip setuptools wheel",
                    (
                        "if ! \"$python_cmd\" - <<'PY'\n"
                        "import sys\n"
                        "raise SystemExit(0 if sys.version_info >= (3, 10) else 1)\n"
                        "PY\n"
                        "then\n"
                        "  printf '%s\\n' "
                        "'Python 3.10+ was not the default. Installing an isolated "
                        "Python 3.12 runtime with uv.'\n"
                        "  retry \"$python_cmd\" -m pip install --user --upgrade uv\n"
                        "  export PATH=\"$HOME/.local/bin:$PATH\"\n"
                        "  retry uv python install 3.12\n"
                        "  retry uv venv --python 3.12 \"$work/python\"\n"
                        "  python_cmd=\"$work/python/bin/python\"\n"
                        "  export PATH=\"$work/python/bin:$PATH\"\n"
                        "  pip_target_flag=\n"
                        "fi"
                    ),
                    (
                        "retry \"$python_cmd\" -m pip install "
                        "${pip_target_flag:+$pip_target_flag} --upgrade \"$fusekit_package\""
                    ),
                    "fusekit --version",
                    f"app_source={source}",
                    "printf '%s\\n' 'Enter a vault passphrase for FuseKit.'",
                    "stty -echo",
                    "printf 'Passphrase: '",
                    "IFS= read -r passphrase",
                    "stty echo",
                    "printf '\\n'",
                    "umask 077",
                    "passfile=\"$work/passphrase\"",
                    "printf '%s\\n' \"$passphrase\" > \"$passfile\"",
                    "vaultfile=\"$work/fusekit.vault.json\"",
                    "if [ -n \"$app_source\" ]; then",
                    (
                        "  fusekit source fetch \"$app_source\" --dest \"$work/app\" "
                        "--vault \"$vaultfile\" --passphrase-file \"$passfile\" "
                        "--github-auth auto --handoff --open-browser --capture-stdin "
                        "--spine openclaw --infer-ui "
                        "--gate-retry-seconds 300 --gate-max-attempts 0"
                        f"{source_fetch_suffix}"
                    ),
                    "else",
                    "  mkdir -p \"$work/app\"",
                    "  printf '%s\\n' 'No app_source was supplied. Upload or clone the app into:'",
                    "  printf '%s\\n' \"$work/app\"",
                    "  printf '%s\\n' 'Then rerun the fusekit launch command printed below.'",
                    "fi",
                    (
                        "if [ -f \"$work/app/fusekit.yaml\" ] || "
                        "[ -f \"$work/app/package.json\" ] || "
                        "[ -d \"$work/app/src\" ]; then"
                    ),
                    (
                        "  fusekit launch \"$work/app\" "
                        f"--runner {runner_arg} "
                        f"--fusekit-gates {gates_arg} "
                        "--control-room "
                        "--vault \"$vaultfile\" "
                        f"--passphrase-file \"$passfile\"{launch_suffix}"
                    ),
                    "else",
                    (
                        "  printf '%s\\n' "
                        "'fusekit launch $HOME/fusekit-cloud-shell/app "
                        f"--runner {runner_arg} --fusekit-gates {gates_arg} "
                        "--control-room --vault "
                        "$HOME/fusekit-cloud-shell/fusekit.vault.json --passphrase-file "
                        f"$HOME/fusekit-cloud-shell/passphrase{launch_suffix}'"
                    ),
                    "fi",
                ]
            )
        )
    )


def _source_fetch_args(launch_args: tuple[str, ...]) -> tuple[str, ...]:
    """Forward only safe source-fetch options from the later launch command."""

    forwarded: list[str] = []
    value_flags = {
        "--llm-provider",
        "--llm-model",
        "--llm-base-url",
        "--llm-api-key-env",
        "--llm-auth-mode",
        "--openclaw-profile",
    }
    bool_flags = {"--capture-llm-key", "--llm-openclaw-device-code", "--dry-run-spine"}
    index = 0
    while index < len(launch_args):
        item = launch_args[index]
        if item in value_flags and index + 1 < len(launch_args):
            forwarded.extend([item, launch_args[index + 1]])
            index += 2
            continue
        if item in bool_flags:
            forwarded.append(item)
        index += 1
    return tuple(forwarded)


def cloud_shell_deeplink(command: str) -> str:
    """Build an OCI Console Cloud Shell deeplink with command fallback parameters."""

    query = urlencode(
        {
            "cloudshell": "true",
            "command": command,
        },
        quote_via=quote,
    )
    return f"{OCI_CLOUD_SHELL_URL}?{query}"


def render_cloud_shell_launcher(plan: CloudShellLaunchPlan) -> str:
    """Render a standalone local HTML launcher."""

    payload = json.dumps(plan.to_dict(), sort_keys=True)
    escaped_command = html.escape(plan.bootstrap_command)
    escaped_url = html.escape(plan.deeplink_url, quote=True)
    escaped_source = html.escape(plan.app_source)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit OCI Launcher</title>
  <style>
    :root {{
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      background: #f7f7f4;
      color: #181a1b;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
    }}
    main {{
      width: min(920px, calc(100vw - 32px));
      display: grid;
      gap: 18px;
    }}
    h1 {{
      font-size: 28px;
      line-height: 1.15;
      margin: 0;
    }}
    p {{
      margin: 0;
      line-height: 1.5;
      color: #3c4247;
    }}
    textarea, input {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #b9c0c7;
      border-radius: 6px;
      padding: 12px;
      font: 14px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #ffffff;
      color: #111315;
    }}
    textarea {{
      min-height: 230px;
      resize: vertical;
    }}
    .actions {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }}
    button, a.button {{
      border: 1px solid #20262c;
      border-radius: 6px;
      background: #20262c;
      color: #ffffff;
      padding: 10px 14px;
      text-decoration: none;
      font-weight: 650;
      cursor: pointer;
    }}
    button.secondary {{
      background: #ffffff;
      color: #20262c;
    }}
    .status {{
      min-height: 22px;
      font-size: 14px;
      color: #38536b;
    }}
  </style>
</head>
<body>
  <main>
    <h1>FuseKit OCI Launcher</h1>
    <p>
      Open Oracle Cloud Shell, pass Oracle's own account gates, then let FuseKit
      bootstrap the disposable runner. The passphrase is entered in Cloud Shell
      and is not embedded in this page.
    </p>
    <label>
      App source
      <input id="source" value="{escaped_source}" aria-describedby="source-example">
    </label>
    <div id="source-example">Example: https://github.com/owner/repo.git</div>
    <textarea id="command" spellcheck="false">{escaped_command}</textarea>
    <div class="actions">
      <a class="button" id="open" href="{escaped_url}" target="_blank" rel="noreferrer">
        Open OCI Cloud Shell
      </a>
      <button id="copy" type="button" class="secondary">Copy Bootstrap Command</button>
      <button id="refresh" type="button" class="secondary">Update From Source</button>
    </div>
    <div id="status" class="status" role="status" aria-live="polite"></div>
  </main>
  <script type="application/json" id="payload">{html.escape(payload)}</script>
  <script>
    const source = document.querySelector('#source');
    const command = document.querySelector('#command');
    const openLink = document.querySelector('#open');
    const status = document.querySelector('#status');
    const initial = JSON.parse(document.querySelector('#payload').textContent);

    function shellQuote(value) {{
      return "'" + value.replaceAll("'", "'\\\\''") + "'";
    }}

    function buildCommand(appSource) {{
      const quotedSource = shellQuote(appSource.trim());
      return initial.bootstrap_command.replace(
        /^app_source=.*$/m,
        `app_source=${{quotedSource}}`
      );
    }}

    function refresh() {{
      command.value = buildCommand(source.value);
      const params = new URLSearchParams({{ cloudshell: 'true', command: command.value }});
      openLink.href = 'https://cloud.oracle.com/?' + params.toString();
      status.textContent = 'Launcher updated.';
    }}

    document.querySelector('#refresh').addEventListener('click', refresh);
    document.querySelector('#copy').addEventListener('click', async () => {{
      try {{
        await navigator.clipboard.writeText(command.value);
        status.textContent = 'Bootstrap command copied.';
      }} catch (error) {{
        command.focus();
        command.select();
        status.textContent =
          'Copy was blocked. FuseKit selected the exact command for you.';
      }}
    }});
  </script>
</body>
</html>
"""


def write_cloud_shell_launcher(plan: CloudShellLaunchPlan, path: Path) -> None:
    """Write the standalone Cloud Shell launcher HTML."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cloud_shell_launcher(plan), encoding="utf-8")
