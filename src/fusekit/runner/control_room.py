"""Static control-room UI rendering."""

from __future__ import annotations

import html
from pathlib import Path

from fusekit.runner.job import JobState


def render_control_room(job: JobState) -> str:
    """Render a standalone HTML control-room page."""

    steps = "\n".join(
        "<tr>"
        f"<td>{html.escape(step.label)}</td>"
        f"<td><span class='status {html.escape(step.status)}'>"
        f"{html.escape(step.status)}</span></td>"
        f"<td>{html.escape(step.detail)}</td>"
        "</tr>"
        for step in job.steps
    )
    artifacts = "\n".join(
        f"<li><code>{html.escape(name)}</code>: {html.escape(path)}</li>"
        for name, path in sorted(job.artifacts.items())
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit Control Room</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; background: #f6f7f9; color: #18202a; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 32px 20px; }}
    header {{ display: flex; justify-content: space-between; gap: 16px; align-items: end; }}
    h1 {{ font-size: 28px; margin: 0 0 6px; }}
    p {{ margin: 0; color: #526070; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 24px; background: #fff; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #e2e6eb; }}
    th {{ font-size: 12px; text-transform: uppercase; color: #607080; }}
    code {{ background: #edf0f3; padding: 2px 5px; border-radius: 4px; }}
    .pill {{ background: #18202a; color: white; border-radius: 999px; padding: 7px 10px; }}
    .status {{ display: inline-block; min-width: 70px; padding: 4px 8px; border-radius: 5px; }}
    .pending {{ background: #edf0f3; }}
    .running {{ background: #d8ebff; }}
    .waiting {{ background: #fff1c7; }}
    .done {{ background: #dff4df; }}
    .failed {{ background: #ffe0df; }}
    section {{ margin-top: 26px; }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>FuseKit Control Room</h1>
        <p>Job <code>{html.escape(job.id)}</code> for <code>{html.escape(job.app_path)}</code></p>
      </div>
      <div class="pill">{html.escape(job.runner)} · {html.escape(job.status)}</div>
    </header>
    <section>
      <table>
        <thead><tr><th>Step</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>{steps}</tbody>
      </table>
    </section>
    <section>
      <h2>Artifacts</h2>
      <ul>{artifacts or "<li>No artifacts yet</li>"}</ul>
    </section>
  </main>
</body>
</html>
"""


def write_control_room(job: JobState, path: Path) -> None:
    """Write the control-room HTML file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_control_room(job), encoding="utf-8")
