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
        deeplink_url=cloud_shell_url(),
        bootstrap_command=command,
        fallback_steps=(
            "Open Oracle Cloud Shell.",
            "Paste and run the bootstrap command in Cloud Shell.",
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
                    "export FUSEKIT_OPENCLAW_HOME_MODE=default",
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
                        "python_cmd=\n"
                        "for candidate in python3.12 python3.11 python3.10 python3 python; do\n"
                        "  if command -v \"$candidate\" >/dev/null 2>&1 && "
                        "\"$candidate\" - 2>/dev/null <<'PY'\n"
                        "import sys\n"
                        "raise SystemExit(0 if sys.version_info >= (3, 10) else 1)\n"
                        "PY\n"
                        "  then\n"
                        "    python_cmd=\"$candidate\"\n"
                        "    break\n"
                        "  fi\n"
                        "done"
                    ),
                    "pip_target_flag=--user",
                    f"fusekit_package={package}",
                    (
                        "if [ \"${fusekit_package#git+}\" != \"$fusekit_package\" ] && "
                        "! command -v git >/dev/null 2>&1; then "
                        "printf '%s\\n' 'Git is required in OCI Cloud Shell for git+ "
                        "FuseKit packages.' >&2; exit 43; fi"
                    ),
                    (
                        "if [ -z \"$python_cmd\" ]; then\n"
                        "  printf '%s\\n' 'Python 3.10+ was not available. "
                        "Installing an isolated Python 3.12 runtime with uv.'\n"
                        "  if ! command -v curl >/dev/null 2>&1; then "
                        "printf '%s\\n' 'curl is required to install Python in OCI "
                        "Cloud Shell.' >&2; exit 43; fi\n"
                        "  rm -f \"$HOME/.local/bin/uv\"\n"
                        "  retry sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'\n"
                        "  export PATH=\"$HOME/.local/bin:$PATH\"\n"
                        "  retry \"$HOME/.local/bin/uv\" python install 3.12\n"
                        "  retry \"$HOME/.local/bin/uv\" venv --python 3.12 \"$work/python\"\n"
                        "  python_cmd=\"$work/python/bin/python\"\n"
                        "  export PATH=\"$work/python/bin:$PATH\"\n"
                        "  pip_target_flag=\n"
                        "fi"
                    ),
                    "\"$python_cmd\" -m ensurepip --upgrade >/dev/null 2>&1 || true",
                    (
                        "retry \"$python_cmd\" -m pip install "
                        "${pip_target_flag:+$pip_target_flag} --upgrade pip setuptools wheel"
                    ),
                    (
                        "fusekit_install_flags=\"--upgrade\"\n"
                        "if [ \"${fusekit_package#git+}\" != \"$fusekit_package\" ]; then\n"
                        "  fusekit_install_flags=\"--upgrade --force-reinstall --no-cache-dir\"\n"
                        "fi\n"
                        "retry \"$python_cmd\" -m pip install "
                        "${pip_target_flag:+$pip_target_flag} "
                        "$fusekit_install_flags \"$fusekit_package\""
                    ),
                    "fusekit --version",
                    "rm -rf \"$HOME/.fusekit-runtime/openclaw\"",
                    f"app_source={source}",
                    "printf '%s\\n' 'Enter a vault passphrase for FuseKit.'",
                    "printf 'Passphrase: '",
                    "if [ -t 0 ]; then",
                    "  stty -echo",
                    "  IFS= read -r passphrase",
                    "  stty echo",
                    "  printf '\\n'",
                    "else",
                    "  IFS= read -r passphrase",
                    "fi",
                    "umask 077",
                    "passfile=\"$work/passphrase\"",
                    "printf '%s\\n' \"$passphrase\" > \"$passfile\"",
                    "vaultfile=\"$work/fusekit.vault.json\"",
                    "if [ -n \"$app_source\" ]; then",
                    (
                        "  fusekit source fetch \"$app_source\" --dest \"$work/app\" "
                        "--vault \"$vaultfile\" --passphrase-file \"$passfile\" "
                        "--github-auth auto --handoff --open-browser --capture-stdin "
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
                        "--control-room --no-bootstrap "
                        "--vault \"$vaultfile\" "
                        f"--passphrase-file \"$passfile\"{launch_suffix}"
                    ),
                    "else",
                    (
                        "  printf '%s\\n' "
                        "'fusekit launch $HOME/fusekit-cloud-shell/app "
                        f"--runner {runner_arg} --fusekit-gates {gates_arg} "
                        "--control-room --no-bootstrap --vault "
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


def cloud_shell_url() -> str:
    """Return the OCI Console Cloud Shell URL without an embedded command."""

    return f"{OCI_CLOUD_SHELL_URL}?cloudshell=true"


def render_cloud_shell_launcher(plan: CloudShellLaunchPlan) -> str:
    """Render a standalone local HTML launcher."""

    payload = json.dumps(plan.to_dict(), sort_keys=True)
    escaped_command = html.escape(plan.bootstrap_command)
    escaped_url = html.escape(plan.deeplink_url, quote=True)
    escaped_source = html.escape(plan.app_source)
    launch_summary = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in _launcher_summary_items(plan)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Snowman FuseKit Launcher</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --snow-navy: #00152a;
      --snow-blue: #0097ff;
      --snow-ice: #eef8ff;
      --snow-ink: #071525;
      --snow-muted: #60738a;
      background: var(--snow-ice);
      color: var(--snow-ink);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 82% 8%, rgba(0, 151, 255, 0.20), transparent 30%),
        linear-gradient(90deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
        linear-gradient(180deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
        var(--snow-ice);
      background-size: 100% 100%, 42px 42px, 42px 42px;
    }}
    main {{
      width: min(1120px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 30px 0;
      display: grid;
      gap: 22px;
    }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 290px;
      gap: 28px;
      align-items: center;
      border-bottom: 2px solid var(--snow-navy);
      padding-bottom: 24px;
    }}
    .brand {{
      display: inline-flex;
      gap: 12px;
      align-items: center;
      font-weight: 900;
      color: var(--snow-navy);
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: 0;
    }}
    .brand-mark {{
      width: 38px;
      height: 38px;
      border-radius: 8px;
      background: var(--snow-navy);
      position: relative;
      box-shadow: inset 0 0 0 1px rgba(0, 151, 255, 0.24);
    }}
    .brand-mark::before {{
      content: "";
      position: absolute;
      width: 18px;
      height: 18px;
      left: 10px;
      top: 15px;
      border: 4px solid var(--snow-blue);
      border-radius: 50%;
    }}
    .brand-mark::after {{
      content: "";
      position: absolute;
      width: 22px;
      height: 6px;
      left: 8px;
      top: 9px;
      border-radius: 999px;
      background: var(--snow-blue);
      box-shadow: 4px -7px 0 -1px var(--snow-blue);
    }}
    h1, h2, p {{
      margin: 0;
    }}
    h1 {{
      max-width: 780px;
      margin-top: 12px;
      font-size: clamp(38px, 6vw, 68px);
      line-height: 0.98;
      letter-spacing: 0;
    }}
    h2 {{
      font-size: 18px;
      line-height: 1.2;
    }}
    p {{
      line-height: 1.5;
      color: #31465c;
    }}
    .lede {{
      max-width: 760px;
      margin-top: 14px;
      font-size: 16px;
    }}
    .panel {{
      border: 1px solid rgba(0, 21, 42, 0.14);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.78);
      box-shadow: 0 24px 80px rgba(0, 21, 42, 0.08);
      padding: 18px;
    }}
    .snowman-stage {{
      min-height: 260px;
      display: grid;
      place-items: center;
      position: relative;
      overflow: hidden;
    }}
    .snowman {{
      position: relative;
      width: 150px;
      height: 204px;
      animation: bob 3s ease-in-out infinite;
    }}
    .hat, .head, .body, .base, .arm, .spark {{
      position: absolute;
    }}
    .hat {{
      width: 56px;
      height: 28px;
      left: 47px;
      top: 4px;
      border-radius: 8px 8px 3px 3px;
      background: var(--snow-navy);
    }}
    .hat::after {{
      content: "";
      position: absolute;
      width: 78px;
      height: 8px;
      left: -11px;
      top: 24px;
      border-radius: 999px;
      background: var(--snow-navy);
    }}
    .head {{
      width: 72px;
      height: 72px;
      left: 39px;
      top: 34px;
      border-radius: 50%;
      background: white;
      border: 2px solid rgba(0, 151, 255, 0.22);
    }}
    .head::before,
    .head::after {{
      content: "";
      position: absolute;
      width: 8px;
      height: 8px;
      top: 27px;
      border-radius: 50%;
      background: var(--snow-navy);
      transition: transform 160ms ease;
    }}
    .head::before {{ left: 22px; }}
    .head::after {{ right: 22px; }}
    .private .head::before,
    .private .head::after {{
      height: 3px;
      transform: translateY(3px);
    }}
    .smile {{
      position: absolute;
      width: 26px;
      height: 12px;
      left: 23px;
      top: 43px;
      border-bottom: 3px solid var(--snow-blue);
      border-radius: 0 0 999px 999px;
    }}
    .body {{
      width: 106px;
      height: 94px;
      left: 22px;
      top: 93px;
      border-radius: 50%;
      background: white;
      border: 2px solid rgba(0, 151, 255, 0.18);
    }}
    .base {{
      width: 138px;
      height: 24px;
      left: 6px;
      top: 174px;
      border-radius: 50%;
      background: rgba(0, 151, 255, 0.16);
    }}
    .arm {{
      width: 54px;
      height: 4px;
      top: 112px;
      background: var(--snow-navy);
      border-radius: 999px;
    }}
    .arm.left {{
      left: 2px;
      transform: rotate(-26deg);
      transform-origin: right center;
      animation: wave 2.8s ease-in-out infinite;
    }}
    .arm.right {{
      right: 0;
      transform: rotate(24deg);
      transform-origin: left center;
    }}
    .spark {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--snow-blue);
      box-shadow: 0 0 18px rgba(0, 151, 255, 0.7);
      animation: sparkle 2.4s ease-in-out infinite;
    }}
    .spark.one {{ left: 26px; top: 48px; }}
    .spark.two {{ right: 24px; top: 72px; animation-delay: 0.6s; }}
    .spark.three {{ left: 68px; bottom: 18px; animation-delay: 1.1s; }}
    .snow-caption {{
      position: absolute;
      left: 18px;
      right: 18px;
      bottom: 18px;
      color: var(--snow-muted);
      font-size: 13px;
      text-align: center;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 18px;
      align-items: start;
    }}
    .summary {{
      display: grid;
      gap: 10px;
      padding-left: 18px;
      margin: 14px 0 0;
      color: #31465c;
    }}
    textarea, input {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid rgba(0, 21, 42, 0.18);
      border-radius: 6px;
      padding: 12px;
      font: 14px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #ffffff;
      color: #111315;
    }}
    textarea {{
      min-height: 170px;
      resize: vertical;
    }}
    .actions {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 14px;
    }}
    button, a.button {{
      border: 1px solid var(--snow-navy);
      border-radius: 6px;
      background: var(--snow-navy);
      color: #ffffff;
      padding: 12px 15px;
      text-decoration: none;
      font-weight: 850;
      cursor: pointer;
    }}
    .button.primary {{
      background: var(--snow-blue);
      border-color: var(--snow-blue);
      color: white;
      box-shadow: 0 12px 28px rgba(0, 151, 255, 0.28);
    }}
    .secondary {{
      background: #ffffff;
      color: var(--snow-navy);
    }}
    .status {{
      min-height: 22px;
      font-size: 14px;
      color: #38536b;
    }}
    details {{
      margin-top: 16px;
    }}
    summary {{
      cursor: pointer;
      color: var(--snow-navy);
      font-weight: 850;
    }}
    @keyframes bob {{
      0%, 100% {{ transform: translateY(0) rotate(-1deg); }}
      50% {{ transform: translateY(-7px) rotate(1deg); }}
    }}
    @keyframes wave {{
      0%, 100% {{ transform: rotate(-30deg); }}
      50% {{ transform: rotate(-10deg); }}
    }}
    @keyframes sparkle {{
      0%, 100% {{ opacity: 0.25; transform: scale(0.75); }}
      50% {{ opacity: 1; transform: scale(1.2); }}
    }}
    @media (max-width: 860px) {{
      .hero, .grid {{
        grid-template-columns: 1fr;
      }}
      h1 {{
        font-size: 42px;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div>
        <div class="brand"><span class="brand-mark"></span><span>SnowmanAI / FuseKit</span></div>
        <h1>Launch this app from a clean cloud room.</h1>
        <p class="lede">
          One click opens OCI Cloud Shell. Snowman waits at provider gates,
          keeps secrets out of this page, and hands the setup to FuseKit inside
          the disposable runner.
        </p>
      </div>
      <div class="panel snowman-stage private" aria-label="Snowman privacy helper">
        <div class="snowman">
          <span class="base"></span>
          <span class="hat"></span>
          <span class="head"><span class="smile"></span></span>
          <span class="body"></span>
          <span class="arm left"></span>
          <span class="arm right"></span>
          <span class="spark one"></span>
          <span class="spark two"></span>
          <span class="spark three"></span>
        </div>
        <p class="snow-caption">Privacy mode: passphrases are entered in Cloud Shell, not here.</p>
      </div>
    </section>
    <section class="grid">
      <div class="panel">
        <h2>Ready To Launch</h2>
        <p>
          Review the app source, copy the bootstrap command, then open OCI.
          Paste the command into Cloud Shell after Oracle opens the terminal.
        </p>
        <label>
          App source
          <input id="source" value="{escaped_source}" aria-describedby="source-example">
        </label>
        <div id="source-example">Example: https://github.com/owner/repo.git</div>
        <div class="actions">
          <button id="copy" type="button" class="button primary">Copy Bootstrap Command</button>
          <a
            class="button secondary"
            id="open"
            href="{escaped_url}"
            target="_blank"
            rel="noreferrer"
          >
            Open OCI Cloud Shell
          </a>
          <button id="refresh" type="button" class="secondary">Update Source</button>
        </div>
        <div id="status" class="status" role="status" aria-live="polite"></div>
        <details>
          <summary>Backup command</summary>
          <textarea id="command" spellcheck="false">{escaped_command}</textarea>
        </details>
      </div>
      <div class="panel">
        <h2>What Snowman Will Carry</h2>
        <ul class="summary">
          {launch_summary}
        </ul>
      </div>
    </section>
  </main>
  <script type="application/json" id="payload">{_safe_script_json(payload)}</script>
  <script>
    const source = document.querySelector('#source');
    const command = document.querySelector('#command');
    const openLink = document.querySelector('#open');
    const status = document.querySelector('#status');
    const initial = JSON.parse(document.querySelector('#payload').textContent);

    function utf8Base64(value) {{
      const bytes = new TextEncoder().encode(value);
      let binary = '';
      bytes.forEach((byte) => {{
        binary += String.fromCharCode(byte);
      }});
      return window.btoa(binary);
    }}

    function sourceAssignment(appSource) {{
      const trimmed = appSource.trim();
      if (!trimmed) {{
        return 'app_source=';
      }}
      return `app_source="$(printf %s ${{utf8Base64(trimmed)}} | base64 -d)"`;
    }}

    function buildCommand(appSource) {{
      return initial.bootstrap_command.replace(
        /^app_source=.*$/m,
        sourceAssignment(appSource)
      );
    }}

    function refresh() {{
      command.value = buildCommand(source.value);
      openLink.href = initial.deeplink_url;
      status.textContent = 'Launcher updated.';
    }}

    function fallbackCopy(text) {{
      const scratch = document.createElement('textarea');
      scratch.value = text;
      scratch.setAttribute('readonly', '');
      scratch.style.position = 'fixed';
      scratch.style.left = '-9999px';
      scratch.style.top = '0';
      document.body.appendChild(scratch);
      scratch.focus();
      scratch.select();
      scratch.setSelectionRange(0, scratch.value.length);
      const copied = document.execCommand('copy');
      scratch.remove();
      if (!copied) {{
        throw new Error('selection copy unavailable');
      }}
    }}

    async function copyText(text) {{
      if (navigator.clipboard && window.isSecureContext) {{
        try {{
          await Promise.race([
            navigator.clipboard.writeText(text),
            new Promise((_, reject) => {{
              window.setTimeout(
                () => reject(new Error('clipboard write timed out')),
                1200
              );
            }}),
          ]);
          return;
        }} catch (error) {{
          fallbackCopy(text);
          return;
        }}
      }}
      fallbackCopy(text);
    }}

    document.querySelector('#refresh').addEventListener('click', refresh);
    document.querySelector('#copy').addEventListener('click', async () => {{
      command.value = buildCommand(source.value);
      try {{
        await copyText(command.value);
        status.textContent = 'Bootstrap command copied.';
      }} catch (error) {{
        command.closest('details').open = true;
        command.focus();
        command.select();
        command.setSelectionRange(0, command.value.length);
        status.textContent =
          'Copy was blocked. Press Command+C; FuseKit selected the exact command.';
      }}
    }});
  </script>
</body>
</html>
"""


def _safe_script_json(payload: str) -> str:
    """Return JSON text safe for embedding in a raw-text script tag."""

    return payload.replace("</", "<\\/")


def _launcher_summary_items(plan: CloudShellLaunchPlan) -> tuple[str, ...]:
    """Build friendly, non-secret launch summary lines for the launcher."""

    args = list(plan.launch_args)

    def value_after(flag: str) -> str:
        try:
            index = args.index(flag)
        except ValueError:
            return ""
        if index + 1 >= len(args):
            return ""
        return args[index + 1]

    items = [
        f"App repo: {plan.app_source or 'provided after launch'}",
        f"FuseKit package: {plan.fusekit_package}",
    ]
    github_repo = value_after("--github-repo")
    vercel_project = value_after("--vercel-project")
    dns_zone = value_after("--dns-zone")
    live_url = value_after("--live-url")
    if github_repo:
        items.append(f"GitHub repo: {github_repo}")
    if vercel_project:
        items.append(f"Vercel project: {vercel_project}")
    if dns_zone:
        items.append(f"DNS zone: {dns_zone}")
    if live_url:
        items.append(f"Live URL check: {live_url}")
    if "--infer-ui" in args:
        items.append("Computer-use guidance: enabled")
    if "--capture-stdin" in args or "--capture-stdin" in plan.bootstrap_command:
        items.append(
            "Secret capture: Capture from VM clipboard buttons save directly to the encrypted vault"
        )
    return tuple(items)


def write_cloud_shell_launcher(plan: CloudShellLaunchPlan, path: Path) -> None:
    """Write the standalone Cloud Shell launcher HTML."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cloud_shell_launcher(plan), encoding="utf-8")
