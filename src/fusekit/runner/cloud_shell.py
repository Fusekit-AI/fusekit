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
    return (
        "bash -lc "
        + shlex.quote(
            "\n".join(
                [
                    "set -euo pipefail",
                    "export PATH=\"$HOME/.local/bin:$PATH\"",
                    "work=\"$HOME/fusekit-cloud-shell\"",
                    "rm -rf \"$work\"",
                    "mkdir -p \"$work\"",
                    f"python3 -m pip install --user --upgrade {package}",
                    f"app_source={source}",
                    "if [ -n \"$app_source\" ]; then",
                    "  git clone --depth=1 \"$app_source\" \"$work/app\"",
                    "else",
                    "  mkdir -p \"$work/app\"",
                    "  printf '%s\\n' 'No app_source was supplied. Upload or clone the app into:'",
                    "  printf '%s\\n' \"$work/app\"",
                    "  printf '%s\\n' 'Then rerun the fusekit launch command printed below.'",
                    "fi",
                    "printf '%s\\n' 'Enter a vault passphrase for FuseKit.'",
                    "stty -echo",
                    "printf 'Passphrase: '",
                    "IFS= read -r passphrase",
                    "stty echo",
                    "printf '\\n'",
                    "passfile=\"$work/passphrase\"",
                    "umask 077",
                    "printf '%s\\n' \"$passphrase\" > \"$passfile\"",
                    "trap 'rm -f \"$passfile\"' EXIT",
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
                        f"--passphrase-file \"$passfile\"{launch_suffix}"
                    ),
                    "else",
                    (
                        "  printf '%s\\n' "
                        "'fusekit launch $HOME/fusekit-cloud-shell/app "
                        f"--runner {runner_arg} --fusekit-gates {gates_arg} "
                        "--control-room --passphrase-file "
                        f"$HOME/fusekit-cloud-shell/passphrase{launch_suffix}'"
                    ),
                    "fi",
                ]
            )
        )
    )


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
    <div id="status" class="status"></div>
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
      await navigator.clipboard.writeText(command.value);
      status.textContent = 'Bootstrap command copied.';
    }});
  </script>
</body>
</html>
"""


def write_cloud_shell_launcher(plan: CloudShellLaunchPlan, path: Path) -> None:
    """Write the standalone Cloud Shell launcher HTML."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cloud_shell_launcher(plan), encoding="utf-8")
