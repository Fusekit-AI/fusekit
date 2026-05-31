"""Static control-room UI rendering."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from fusekit.runner.gate_guidance import GateGuidance, infer_gate_provider, provider_gate_guidance
from fusekit.runner.job import JobState, JobStep

STATUS_LABELS = {
    "created": "Created",
    "pending": "Pending",
    "running": "Running",
    "waiting": "Human gate",
    "done": "Done",
    "failed": "Needs repair",
    "skipped": "Skipped",
}

TERMINAL_STEP_STATUSES = {"done", "skipped"}


def render_control_room(job: JobState) -> str:
    """Render a standalone HTML control-room page."""

    payload = _safe_json(job.to_dict())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit Control Room</title>
  <style>{_STYLE}</style>
</head>
<body>
  <main class="shell">
    {_render_header(job)}
    <section class="overview" aria-label="Launch overview">
      {_render_progress(job)}
      {_render_focus(job)}
    </section>
    <section class="workspace">
      {_render_steps(job)}
      {_render_artifacts(job)}
    </section>
  </main>
  <script id="job-data" type="application/json">{payload}</script>
  <script>{_SCRIPT}</script>
</body>
</html>
"""


def write_control_room(job: JobState, path: Path) -> None:
    """Write the control-room HTML file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_control_room(job), encoding="utf-8")


def _render_header(job: JobState) -> str:
    return f"""
    <header class="hero">
      <div>
        {_render_brand_lockup("control room")}
        <h1>{html.escape(_headline(job))}</h1>
        <p>
          Job <code>{html.escape(job.id)}</code> is wiring
          <code>{html.escape(job.app_path)}</code> through the
          <code>{html.escape(job.runner)}</code> lane.
        </p>
      </div>
      <div class="status-stack" aria-label="Job status">
        <span class="pill status {html.escape(job.status)}" data-job-status>
          {html.escape(_status_label(job.status))}
        </span>
        <span class="pill muted" data-updated-at>
          Updated {_format_time(job.updated_at)}
        </span>
      </div>
    </header>
"""


def _render_progress(job: JobState) -> str:
    done, total, percent = _progress(job)
    counts = _status_counts(job.steps)
    return f"""
      <article class="progress-panel">
        <div class="panel-top">
          <span class="section-kicker">Launch progress</span>
          <strong data-progress-label>{done}/{total} steps</strong>
        </div>
        <div class="meter" aria-label="Progress">
          <span data-progress-bar style="width: {percent}%"></span>
        </div>
        <div class="stats">
          <span><strong data-count-running>{counts["running"]}</strong> running</span>
          <span><strong data-count-waiting>{counts["waiting"]}</strong> gates</span>
          <span><strong data-count-done>{counts["done"]}</strong> done</span>
          <span><strong data-count-failed>{counts["failed"]}</strong> repair</span>
        </div>
      </article>
"""


def _render_focus(job: JobState) -> str:
    current = _current_step(job)
    next_step = _next_step(job, current)
    gate_class = " gate" if current and current.status == "waiting" else ""
    mascot_state = _mascot_state(current, job)
    focus_label = html.escape(_focus_kicker(current))
    focus_status = html.escape(current.status if current else job.status)
    current_label = html.escape(current.label if current else "Launch complete")
    next_label = html.escape(next_step.label if next_step else "Artifacts and audit review")
    return f"""
      <article class="focus-panel{gate_class}" data-focus-panel>
        <div class="panel-top">
          <span class="section-kicker" data-focus-kicker>{focus_label}</span>
          <span class="mini-dot {focus_status}" data-focus-dot></span>
        </div>
        {_render_snowman_scene(mascot_state)}
        <h2 data-current-title>{current_label}</h2>
        <p data-current-detail>{html.escape(_step_detail(current))}</p>
        <div data-gate-help>{_render_gate_help(current)}</div>
        <div class="next-line">
          <span>Next</span>
          <strong data-next-title>{next_label}</strong>
        </div>
      </article>
"""


def _render_steps(job: JobState) -> str:
    cards = "\n".join(_render_step(step, index) for index, step in enumerate(job.steps, start=1))
    return f"""
      <section class="timeline" aria-label="Setup steps">
        <div class="section-head">
          <div>
            <span class="section-kicker">Worker timeline</span>
            <h2>What FuseKit is doing</h2>
          </div>
          <span class="live-pill">Live refresh when served</span>
        </div>
        <ol class="steps" data-steps>{cards}</ol>
      </section>
"""


def _render_step(step: JobStep, index: int) -> str:
    status = html.escape(step.status)
    status_label = html.escape(_status_label(step.status))
    return f"""
          <li class="step-card {status}" data-step-id="{html.escape(step.id)}">
            <span class="step-number">{index:02d}</span>
            <div class="step-copy">
              <strong>{html.escape(step.label)}</strong>
              <span>{html.escape(_step_detail(step))}</span>
            </div>
            <span class="badge {status}">{status_label}</span>
          </li>
"""


def _render_artifacts(job: JobState) -> str:
    rows = "\n".join(
        f"""
          <li>
            <div>
              <strong>{html.escape(name)}</strong>
              <code>{html.escape(path)}</code>
            </div>
            <button type="button" data-copy="{html.escape(path)}">Copy path</button>
          </li>
"""
        for name, path in sorted(job.artifacts.items())
    )
    if not rows:
        rows = (
            "<li class='empty'>Encrypted vault, receipts, and audit logs appear "
            "here after retrieval.</li>"
        )
    return f"""
      <aside class="artifact-panel" aria-label="Artifacts">
        <div class="section-head compact">
          <div>
            <span class="section-kicker">Survivors</span>
            <h2>Artifacts</h2>
          </div>
        </div>
        <ul class="artifacts" data-artifacts>{rows}</ul>
        <p class="artifact-note">
          This room should show only encrypted vaults, redacted receipts, audit logs,
          and rollback metadata. Raw secrets do not belong here.
        </p>
</aside>
"""


def _render_brand_lockup(surface: str) -> str:
    return f"""
        <div class="brand-lockup" aria-label="Snowman AI FuseKit {html.escape(surface)}">
          <span class="brand-mark" aria-hidden="true">
            <span class="mark-hat"></span>
            <span class="mark-head"></span>
            <span class="mark-node mark-node-a"></span>
            <span class="mark-node mark-node-b"></span>
            <span class="mark-node mark-node-c"></span>
          </span>
          <span class="brand-copy">
            <strong>Snowman AI</strong>
            <span>FuseKit {html.escape(surface)}</span>
          </span>
        </div>
"""


def _render_snowman_scene(state: str) -> str:
    return f"""
        <div class="snow-scene state-{html.escape(state)}" data-snow-scene>
          <div class="snowman" aria-hidden="true">
            <span class="snow-hat"></span>
            <span class="snow-head">
              <span class="eye left"></span>
              <span class="eye right"></span>
              <span class="nose"></span>
            </span>
            <span class="snow-body">
              <span class="button one"></span>
              <span class="button two"></span>
            </span>
            <span class="arm left"></span>
            <span class="arm right"></span>
            <span class="puddle"></span>
            <span class="steam one"></span>
            <span class="steam two"></span>
          </div>
          <div class="snow-prop" data-snow-caption>{html.escape(_mascot_caption(state))}</div>
        </div>
"""


def _headline(job: JobState) -> str:
    if job.status == "waiting":
        return "Waiting at a human gate"
    if job.status == "failed":
        return "Launch needs attention"
    if job.status == "done":
        return "Launch is complete"
    return "Launch in progress"


def _mascot_state(step: JobStep | None, job: JobState) -> str:
    if step and step.id == "detonate.workspace":
        return "detonate"
    if job.status == "done":
        return "done"
    if step and step.status == "waiting":
        return "gate"
    if step and step.status == "failed":
        return "repair"
    if step and "verify" in step.id:
        return "verify"
    if step and any(part in step.id for part in ["provision", "bootstrap", "upload", "setup"]):
        return "working"
    return "launch"


def _mascot_caption(state: str) -> str:
    captions = {
        "launch": "packing the clean-room suitcase",
        "working": "tightening the little launch bolts",
        "gate": "waiting politely with a tiny access badge",
        "verify": "checking the live app with a frosty magnifier",
        "repair": "opening the repair kit",
        "detonate": "melting away the worker state",
        "done": "saving only the encrypted survivors",
    }
    return captions.get(state, captions["launch"])


def _current_step(job: JobState) -> JobStep | None:
    for status in ("failed", "waiting", "running"):
        for step in job.steps:
            if step.status == status:
                return step
    for step in job.steps:
        if step.status == "pending":
            return step
    return job.steps[-1] if job.steps else None


def _next_step(job: JobState, current: JobStep | None) -> JobStep | None:
    if current is None:
        return None
    seen_current = False
    for step in job.steps:
        if seen_current and step.status not in TERMINAL_STEP_STATUSES:
            return step
        if step.id == current.id:
            seen_current = True
    return None


def _progress(job: JobState) -> tuple[int, int, int]:
    total = max(len(job.steps), 1)
    done = sum(1 for step in job.steps if step.status in TERMINAL_STEP_STATUSES)
    return done, len(job.steps), round((done / total) * 100)


def _status_counts(steps: list[JobStep]) -> dict[str, int]:
    counts = {"running": 0, "waiting": 0, "done": 0, "failed": 0}
    for step in steps:
        if step.status in counts:
            counts[step.status] += 1
        elif step.status == "skipped":
            counts["done"] += 1
    return counts


def _focus_kicker(step: JobStep | None) -> str:
    if step is None:
        return "Current focus"
    if step.status == "waiting":
        return "Human gate"
    if step.status == "failed":
        return "Repair needed"
    if step.status == "running":
        return "Now running"
    return "Up next"


def _step_detail(step: JobStep | None) -> str:
    if step is None:
        return "FuseKit is preserving encrypted and redacted artifacts."
    return step.detail or "Queued and ready for the worker."


def _render_gate_help(step: JobStep | None) -> str:
    if step is None or step.status != "waiting":
        return ""
    guidance = _guidance_for_step(step)
    actions = "".join(f"<li>{html.escape(action)}</li>" for action in guidance.actions)
    return f"""
        <div class="gate-help">
          <span>What you need to do</span>
          <strong>{html.escape(guidance.title)}</strong>
          <p>{html.escape(guidance.body)}</p>
          <ol>{actions}</ol>
          <em>{html.escape(guidance.reassurance)}</em>
        </div>
"""


def _guidance_for_step(step: JobStep) -> GateGuidance:
    provider = infer_gate_provider(f"{step.id} {step.label} {step.detail}")
    return provider_gate_guidance(provider)


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status.replace("_", " ").title())


def _format_time(timestamp: float) -> str:
    age = max(0, int(time.time() - timestamp))
    if age < 60:
        return "just now"
    if age < 3600:
        return f"{age // 60}m ago"
    if age < 86400:
        return f"{age // 3600}h ago"
    return f"{age // 86400}d ago"


def _safe_json(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True)
    return data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


_STYLE = r"""
:root {
  color-scheme: light;
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  --snow-navy: #00152a;
  --snow-deep: #020b18;
  --snow-blue: #0097ff;
  --snow-blue-dark: #0067d9;
  --snow-ice: #eef8ff;
  --snow-panel: rgba(255, 255, 255, 0.82);
  --snow-line: rgba(0, 151, 255, 0.18);
  --snow-ink: #071525;
  --snow-muted: #60738a;
  background: var(--snow-ice);
  color: var(--snow-ink);
}

* {
  box-sizing: border-box;
}

html {
  min-width: 320px;
}

body {
  min-width: 320px;
  margin: 0;
  overflow-x: hidden;
  background:
    radial-gradient(circle at 76% 4%, rgba(0, 151, 255, 0.22), transparent 28%),
    radial-gradient(circle at 10% 22%, rgba(0, 103, 217, 0.12), transparent 26%),
    linear-gradient(90deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
    linear-gradient(180deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
    var(--snow-ice);
  background-size: 100% 100%, 100% 100%, 42px 42px, 42px 42px;
}

.shell {
  width: 100%;
  max-width: 1480px;
  margin: 0 auto;
  padding: 34px;
  overflow: hidden;
}

.hero {
  min-width: 0;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 28px;
  padding-bottom: 28px;
  border-bottom: 2px solid var(--snow-navy);
}

.brand-lockup {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  min-height: 48px;
}

.brand-mark {
  position: relative;
  width: 44px;
  height: 44px;
  border-radius: 8px;
  background: var(--snow-navy);
  box-shadow: inset 0 0 0 1px rgba(0, 151, 255, 0.22);
}

.mark-hat,
.mark-head,
.mark-node {
  position: absolute;
  background: var(--snow-blue);
  box-shadow: 0 0 16px rgba(0, 151, 255, 0.38);
}

.mark-hat {
  width: 20px;
  height: 14px;
  top: 5px;
  left: 12px;
  border-radius: 4px 4px 2px 2px;
}

.mark-hat::after {
  content: "";
  position: absolute;
  width: 28px;
  height: 5px;
  left: -4px;
  top: 12px;
  border-radius: 999px;
  background: inherit;
}

.mark-head {
  width: 18px;
  height: 18px;
  top: 21px;
  left: 14px;
  border-radius: 50%;
  background: transparent;
  border: 4px solid var(--snow-blue);
}

.mark-node {
  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.mark-node::before {
  content: "";
  position: absolute;
  width: 16px;
  height: 3px;
  left: -14px;
  top: 2px;
  border-radius: 999px;
  background: var(--snow-blue);
  transform-origin: right center;
}

.mark-node-a {
  left: 7px;
  top: 26px;
}

.mark-node-a::before {
  transform: rotate(34deg);
}

.mark-node-b {
  left: 9px;
  top: 36px;
}

.mark-node-b::before {
  transform: rotate(-36deg);
}

.mark-node-c {
  right: 6px;
  bottom: 5px;
}

.brand-copy {
  display: grid;
  gap: 1px;
}

.brand-copy strong {
  color: var(--snow-navy);
  font-size: 17px;
}

.brand-copy span {
  color: var(--snow-muted);
  font-size: 12px;
  font-weight: 850;
  text-transform: uppercase;
}

.eyebrow,
.section-kicker {
  color: var(--snow-muted);
  font-size: 12px;
  font-weight: 850;
  letter-spacing: 0;
  text-transform: uppercase;
}

h1,
h2,
p {
  margin: 0;
}

h1 {
  max-width: 760px;
  margin-top: 8px;
  font-size: 58px;
  line-height: 1;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.hero p {
  max-width: 820px;
  margin-top: 14px;
  color: #31465c;
  font-size: 16px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

code {
  border: 1px solid rgba(0, 21, 42, 0.12);
  border-radius: 6px;
  padding: 2px 6px;
  background: rgba(255, 255, 255, 0.72);
  color: var(--snow-ink);
  font: 0.94em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-wrap: anywhere;
}

.status-stack {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  min-width: 260px;
}

.pill,
.badge,
.live-pill,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 32px;
  border: 1px solid rgba(0, 21, 42, 0.14);
  border-radius: 999px;
  padding: 7px 11px;
  background: rgba(255, 255, 255, 0.72);
  color: #15304c;
  font-size: 12px;
  font-weight: 850;
  white-space: nowrap;
}

.pill.status {
  border-color: transparent;
  color: var(--snow-ink);
}

.pill.muted,
.live-pill {
  color: var(--snow-muted);
}

.overview {
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(360px, 1.1fr);
  gap: 18px;
  margin-top: 22px;
}

.progress-panel,
.focus-panel,
.timeline,
.artifact-panel {
  min-width: 0;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  background: var(--snow-panel);
  box-shadow: 0 28px 70px rgba(0, 21, 42, 0.1);
}

.progress-panel,
.focus-panel {
  padding: 18px;
}

.panel-top,
.section-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
}

.panel-top strong {
  font-size: 13px;
}

.meter {
  height: 14px;
  margin: 28px 0 14px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(0, 21, 42, 0.09);
}

.meter span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--snow-blue), #6fd7ff);
  transition: width 220ms ease;
}

.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.stats span {
  min-height: 54px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 10px;
  color: #536b82;
  background: rgba(255, 255, 255, 0.52);
  font-size: 12px;
  font-weight: 800;
}

.stats strong {
  display: block;
  color: var(--snow-navy);
  font-size: 22px;
  line-height: 1;
}

.focus-panel {
  overflow: hidden;
  background:
    radial-gradient(circle at 84% 12%, rgba(0, 151, 255, 0.28), transparent 30%),
    linear-gradient(135deg, var(--snow-navy), var(--snow-deep));
  color: #f7fbff;
}

.focus-panel.gate {
  background:
    radial-gradient(circle at 82% 10%, rgba(0, 151, 255, 0.32), transparent 32%),
    linear-gradient(135deg, #001f3f, #04101e);
}

.focus-panel .section-kicker,
.focus-panel p,
.next-line span {
  color: #bfc7c1;
}

.gate-help {
  display: grid;
  gap: 9px;
  margin: 16px 0 0;
  border: 1px solid rgba(111, 215, 255, 0.22);
  border-radius: 8px;
  padding: 14px;
  background: rgba(255, 255, 255, 0.08);
}

.gate-help span {
  color: #9bdcff;
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.gate-help strong {
  color: #ffffff;
  font-size: 15px;
}

.gate-help p,
.gate-help em,
.gate-help li {
  color: #d7e7f2;
  font-size: 13px;
  line-height: 1.45;
}

.gate-help ol {
  display: grid;
  gap: 7px;
  margin: 0;
  padding-left: 20px;
}

.gate-help em {
  color: #b7e8ff;
  font-style: normal;
  font-weight: 850;
}

.snow-scene {
  position: relative;
  min-height: 136px;
  margin: 18px 0 4px;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 8px;
  background:
    linear-gradient(120deg, rgba(255, 255, 255, 0.08), transparent),
    radial-gradient(circle at 74% 25%, rgba(0, 151, 255, 0.22), transparent 34%);
}

.snow-scene::before {
  content: "";
  position: absolute;
  inset: auto 18px 20px 108px;
  height: 2px;
  border-radius: 999px;
  background: linear-gradient(90deg, transparent, rgba(111, 215, 255, 0.82), transparent);
  animation: data-wave 2.8s ease-in-out infinite;
}

.snowman {
  position: absolute;
  left: 26px;
  bottom: 18px;
  width: 86px;
  height: 94px;
  animation: snow-bob 2.4s ease-in-out infinite;
}

.snow-head,
.snow-body,
.snow-hat,
.arm,
.puddle,
.steam {
  position: absolute;
}

.snow-head {
  width: 39px;
  height: 39px;
  left: 24px;
  top: 14px;
  border-radius: 50%;
  background: #ffffff;
  box-shadow: inset -6px -7px 0 #d9efff;
}

.snow-body {
  width: 60px;
  height: 54px;
  left: 13px;
  bottom: 0;
  border-radius: 48% 48% 42% 42%;
  background: #ffffff;
  box-shadow: inset -8px -9px 0 #d9efff;
}

.snow-hat {
  width: 34px;
  height: 20px;
  left: 26px;
  top: 1px;
  border-radius: 6px 6px 2px 2px;
  background: var(--snow-blue);
  box-shadow: 0 0 18px rgba(0, 151, 255, 0.4);
}

.snow-hat::after {
  content: "";
  position: absolute;
  width: 44px;
  height: 7px;
  left: -5px;
  top: 17px;
  border-radius: 999px;
  background: var(--snow-blue);
}

.eye {
  position: absolute;
  width: 4px;
  height: 4px;
  top: 14px;
  border-radius: 50%;
  background: var(--snow-navy);
}

.eye.left {
  left: 12px;
}

.eye.right {
  right: 12px;
}

.nose {
  position: absolute;
  width: 13px;
  height: 5px;
  left: 19px;
  top: 21px;
  border-radius: 999px;
  background: #ff9f2e;
}

.button {
  position: absolute;
  width: 5px;
  height: 5px;
  left: 27px;
  border-radius: 50%;
  background: var(--snow-blue-dark);
}

.button.one {
  top: 18px;
}

.button.two {
  top: 32px;
}

.arm {
  width: 32px;
  height: 4px;
  top: 49px;
  border-radius: 999px;
  background: #7e5a38;
}

.arm.left {
  left: 1px;
  transform: rotate(-22deg);
}

.arm.right {
  right: 0;
  transform: rotate(24deg);
  transform-origin: left center;
}

.snow-prop {
  position: absolute;
  left: 124px;
  right: 18px;
  bottom: 22px;
  color: #d5ecff;
  font-size: 13px;
  font-weight: 850;
  line-height: 1.35;
  overflow-wrap: anywhere;
  white-space: normal;
}

.snow-prop::before {
  content: "";
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 8px;
  border-radius: 50%;
  background: var(--snow-blue);
  box-shadow: 0 0 14px rgba(0, 151, 255, 0.65);
}

.state-gate .arm.right {
  animation: snow-wave 1.1s ease-in-out infinite;
}

.state-gate .snow-prop::after {
  content: "  · Tap the provider prompt, then I keep going.";
  color: rgba(255, 255, 255, 0.68);
}

.state-working .snow-hat,
.state-launch .snow-hat {
  animation: hat-tap 1.4s ease-in-out infinite;
}

.state-verify .snowman::after {
  content: "";
  position: absolute;
  width: 25px;
  height: 25px;
  right: -14px;
  top: 35px;
  border: 4px solid #bfe8ff;
  border-radius: 50%;
  box-shadow: 0 0 14px rgba(0, 151, 255, 0.35);
}

.state-verify .snowman::before {
  content: "";
  position: absolute;
  width: 20px;
  height: 4px;
  right: -24px;
  top: 62px;
  border-radius: 999px;
  background: #bfe8ff;
  transform: rotate(42deg);
}

.state-repair .arm.left {
  animation: snow-fix 0.9s ease-in-out infinite;
}

.state-detonate .snow-head,
.state-detonate .snow-body {
  animation: snow-melt 2.2s ease-in-out infinite;
}

.state-detonate .puddle {
  width: 76px;
  height: 16px;
  left: 5px;
  bottom: -2px;
  border-radius: 50%;
  background: rgba(157, 222, 255, 0.52);
  animation: puddle-grow 2.2s ease-in-out infinite;
}

.state-detonate .steam {
  width: 3px;
  height: 24px;
  bottom: 52px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.74);
  opacity: 0;
}

.state-detonate .steam.one {
  left: 34px;
  animation: steam-rise 1.8s ease-in-out infinite;
}

.state-detonate .steam.two {
  left: 50px;
  animation: steam-rise 1.8s ease-in-out 0.4s infinite;
}

.state-done .snowman {
  animation: snow-celebrate 0.9s ease-in-out infinite;
}

@keyframes data-wave {
  0%, 100% { transform: translateX(-16px); opacity: 0.42; }
  50% { transform: translateX(18px); opacity: 1; }
}

@keyframes snow-bob {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-5px); }
}

@keyframes snow-wave {
  0%, 100% { transform: rotate(18deg); }
  50% { transform: rotate(-30deg); }
}

@keyframes hat-tap {
  0%, 100% { transform: rotate(0); }
  50% { transform: rotate(-5deg) translateY(-2px); }
}

@keyframes snow-fix {
  0%, 100% { transform: rotate(-22deg); }
  50% { transform: rotate(14deg); }
}

@keyframes snow-melt {
  0%, 100% { transform: scaleY(1); opacity: 1; }
  50% { transform: scaleY(0.7) translateY(16px); opacity: 0.72; }
}

@keyframes puddle-grow {
  0%, 100% { transform: scaleX(0.7); opacity: 0.3; }
  50% { transform: scaleX(1); opacity: 0.75; }
}

@keyframes steam-rise {
  0% { transform: translateY(12px); opacity: 0; }
  40% { opacity: 0.8; }
  100% { transform: translateY(-22px); opacity: 0; }
}

@keyframes snow-celebrate {
  0%, 100% { transform: rotate(-2deg) translateY(0); }
  50% { transform: rotate(3deg) translateY(-5px); }
}

.focus-panel h2 {
  margin-top: 28px;
  font-size: 32px;
  line-height: 1.05;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.focus-panel p {
  max-width: 760px;
  margin-top: 12px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.mini-dot {
  flex: 0 0 auto;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #8d9691;
  box-shadow: 0 0 0 5px rgba(141, 150, 145, 0.14);
}

.next-line {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 28px;
}

.next-line strong {
  color: #ffffff;
  overflow-wrap: anywhere;
}

.workspace {
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
  gap: 18px;
  margin-top: 18px;
}

.timeline,
.artifact-panel {
  min-width: 0;
  padding: 20px;
}

.section-head {
  margin-bottom: 18px;
}

.section-head h2 {
  margin-top: 5px;
  font-size: 24px;
  letter-spacing: 0;
}

.steps,
.artifacts {
  display: grid;
  gap: 10px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.step-card {
  display: grid;
  grid-template-columns: 44px minmax(0, 1fr) auto;
  gap: 14px;
  align-items: center;
  min-height: 74px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.72);
}

.step-card.running,
.step-card.waiting,
.step-card.failed {
  border-color: rgba(17, 22, 21, 0.34);
  background: #ffffff;
}

.step-number {
  color: #6a736f;
  font-size: 13px;
  font-weight: 900;
}

.step-copy {
  min-width: 0;
}

.step-copy strong,
.step-copy span {
  display: block;
}

.step-copy strong {
  color: #141918;
}

.step-copy span {
  margin-top: 4px;
  color: #55605b;
  font-size: 13px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.badge {
  min-width: 86px;
}

.status.running,
.badge.running,
.mini-dot.running {
  background: #cfe7ff;
}

.status.waiting,
.badge.waiting,
.mini-dot.waiting {
  background: #ffe5a3;
}

.status.done,
.badge.done,
.badge.skipped,
.mini-dot.done,
.mini-dot.skipped {
  background: #c9f5bd;
}

.status.failed,
.badge.failed,
.mini-dot.failed {
  background: #ffd2cc;
}

.status.pending,
.badge.pending,
.mini-dot.pending {
  background: #e8ebe8;
}

.artifacts li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  border-bottom: 1px solid rgba(17, 22, 21, 0.12);
  padding: 12px 0;
}

.artifacts strong,
.artifacts code {
  display: block;
}

.artifacts code {
  margin-top: 6px;
}

.artifacts .empty {
  display: block;
  color: #59645f;
  line-height: 1.5;
}

button {
  border-radius: 8px;
  background: #111615;
  color: #f5f3ea;
  cursor: pointer;
}

.artifact-note {
  margin-top: 18px;
  color: #59645f;
  font-size: 13px;
  line-height: 1.5;
}

@media (max-width: 1040px) {
  .overview,
  .workspace {
    grid-template-columns: 1fr;
  }

  .status-stack {
    justify-content: flex-start;
  }
}

@media (max-width: 720px) {
  .shell {
    padding: 22px 16px;
  }

  .hero,
  .panel-top,
  .section-head {
    display: grid;
  }

  .overview,
  .workspace {
    display: block;
    grid-template-columns: minmax(0, 1fr);
  }

  .progress-panel,
  .focus-panel,
  .timeline,
  .artifact-panel {
    width: 100%;
    max-width: 100%;
    margin-bottom: 18px;
  }

  h1 {
    font-size: 31px;
    max-width: 100%;
  }

  code {
    white-space: normal;
    word-break: break-word;
  }

  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .stats span {
    min-width: 0;
  }

  .focus-panel h2 {
    font-size: 20px;
    max-width: 100%;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .focus-panel p,
  .next-line,
  .next-line strong {
    font-size: 14px;
    max-width: 310px;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .snow-scene {
    min-height: 170px;
  }

  .snow-scene::before {
    inset: auto 14px 18px 112px;
  }

  .snowman {
    left: 20px;
    transform: scale(0.9);
    transform-origin: left bottom;
  }

  .snow-prop {
    left: 108px;
    right: 14px;
    bottom: 28px;
    max-width: 218px;
    font-size: 12px;
  }

  .step-card,
  .artifacts li {
    grid-template-columns: 1fr;
  }

  .badge,
  button {
    width: fit-content;
  }
}
"""


_SCRIPT = r"""
const initialJob = JSON.parse(document.getElementById("job-data").textContent);

const labels = {
  created: "Created",
  pending: "Pending",
  running: "Running",
  waiting: "Human gate",
  done: "Done",
  failed: "Needs repair",
  skipped: "Skipped",
};

function label(status) {
  return labels[status] || String(status || "unknown").replaceAll("_", " ");
}

function stepDetail(step) {
  return step?.detail || "Queued and ready for the worker.";
}

function statusCounts(steps) {
  const counts = { running: 0, waiting: 0, done: 0, failed: 0 };
  for (const step of steps || []) {
    if (step.status === "skipped") counts.done += 1;
    else if (counts[step.status] !== undefined) counts[step.status] += 1;
  }
  return counts;
}

function activeGate(job) {
  return (job.gates || []).find((gate) => ["waiting", "resurfaced"].includes(gate.status));
}

function gateStateErrorStep(job) {
  if (!job.gate_state_error) return null;
  return {
    id: "gate.state.error",
    label: "Gate state needs repair",
    status: "failed",
    detail: job.gate_state_error,
  };
}

function gateStep(gate) {
  if (!gate) return null;
  return {
    id: gate.id || "provider.gate",
    label: `${gate.provider || "Provider"} needs your approval`,
    status: "waiting",
    detail: gate.reason || "A provider-created human gate is waiting.",
    updated_at: gate.updated_at,
  };
}

function progress(job) {
  const steps = job.steps || [];
  const total = Math.max(steps.length, 1);
  const done = steps.filter((step) => ["done", "skipped"].includes(step.status)).length;
  return { done, total: steps.length, percent: Math.round((done / total) * 100) };
}

function currentStep(job) {
  const gateError = gateStateErrorStep(job);
  if (gateError) return gateError;
  const gate = gateStep(activeGate(job));
  if (gate) return gate;
  for (const status of ["failed", "waiting", "running"]) {
    const active = (job.steps || []).find((step) => step.status === status);
    if (active) return active;
  }
  return (job.steps || []).find((step) => step.status === "pending") || (job.steps || []).at(-1);
}

function nextStep(job, current) {
  if (!current) return null;
  const steps = job.steps || [];
  const index = steps.findIndex((step) => step.id === current.id);
  return steps.slice(index + 1).find((step) => !["done", "skipped"].includes(step.status));
}

function focusKicker(step) {
  if (!step) return "Current focus";
  if (step.status === "waiting") return "Human gate";
  if (step.status === "failed") return "Repair needed";
  if (step.status === "running") return "Now running";
  return "Up next";
}

function mascotState(step, job) {
  if (step?.id === "detonate.workspace") return "detonate";
  if (job.status === "done") return "done";
  if (step?.status === "waiting") return "gate";
  if (step?.status === "failed") return "repair";
  if (step?.id?.includes("verify")) return "verify";
  if (["provision", "bootstrap", "upload", "setup"].some((part) => step?.id?.includes(part))) {
    return "working";
  }
  return "launch";
}

function mascotCaption(state) {
  return {
    launch: "packing the clean-room suitcase",
    working: "tightening the little launch bolts",
    gate: "waiting politely with a tiny access badge",
    verify: "checking the live app with a frosty magnifier",
    repair: "opening the repair kit",
    detonate: "melting away the worker state",
    done: "saving only the encrypted survivors",
  }[state] || "packing the clean-room suitcase";
}

function inferGateProvider(text) {
  const lower = String(text || "").toLowerCase();
  for (const provider of ["github", "vercel", "cloudflare", "resend", "oci", "openai"]) {
    if (lower.includes(provider)) return provider;
  }
  if (lower.includes("oracle") || lower.includes("cloud shell")) return "oci";
  return "generic";
}

function gateGuidance(provider) {
  return {
    github: {
      title: "GitHub is asking for your approval",
      body:
        "FuseKit opened GitHub so the repo can receive deploy keys and encrypted secrets.",
      actions: [
        "Sign in or create the GitHub account when GitHub asks.",
        "Pass email, passkey, MFA, CAPTCHA, or consent prompts yourself.",
        "When GitHub reveals the approved token, paste it into FuseKit's hidden prompt.",
      ],
      reassurance: "FuseKit waits here, then resumes automatically after the token is captured.",
    },
    vercel: {
      title: "Vercel is checking deploy permission",
      body:
        "FuseKit is connecting the app repo to Vercel and starting deployment.",
      actions: [
        "Sign in or create the Vercel account when prompted.",
        "Approve GitHub connection, team, billing, MFA, CAPTCHA, or consent prompts if shown.",
        "When Vercel reveals the approved token, paste it into FuseKit's hidden prompt.",
      ],
      reassurance: "FuseKit keeps the run alive and continues once Vercel accepts the gate.",
    },
    cloudflare: {
      title: "Cloudflare is checking domain control",
      body:
        "FuseKit is preparing DNS records and waiting for Cloudflare approval.",
      actions: [
        "Sign in or create the Cloudflare account when prompted.",
        "Pass nameserver, domain ownership, MFA, CAPTCHA, billing, or consent prompts yourself.",
        "When Cloudflare reveals the approved DNS token, paste it into FuseKit's hidden prompt.",
      ],
      reassurance: "FuseKit will keep retrying DNS verification instead of giving up early.",
    },
    resend: {
      title: "Resend is checking email sending access",
      body:
        "FuseKit is preparing email delivery credentials and domain verification records.",
      actions: [
        "Sign in or create the Resend account when prompted.",
        "Pass email verification, MFA, CAPTCHA, billing, consent, or domain checks yourself.",
        "When Resend reveals the API key, paste it into FuseKit's hidden prompt.",
      ],
      reassurance: "FuseKit stores the key only in the encrypted vault and then resumes setup.",
    },
    oci: {
      title: "Oracle Cloud is opening the clean room",
      body:
        "FuseKit is starting the disposable OCI workspace that runs setup away from your computer.",
      actions: [
        "Sign in or create the OCI account when Oracle asks.",
        "Pass MFA, CAPTCHA, payment verification, tenancy, or Cloud Shell prompts yourself.",
        "Leave the Cloud Shell tab open; FuseKit will continue from there.",
      ],
      reassurance: "FuseKit treats this as a waiting state, not a failure.",
    },
    openai: {
      title: "OpenAI is authorizing the brain lane",
      body:
        "FuseKit needs an LLM route when no API key is already available.",
      actions: [
        "Sign in to OpenAI when prompted.",
        "Pass MFA, CAPTCHA, consent, or organization prompts yourself.",
        "Return to FuseKit after the provider says authorization is complete.",
      ],
      reassurance: "FuseKit encrypts auth state and detonates plaintext worker state later.",
    },
  }[provider] || {
    title: "A provider needs a human check",
    body:
      "FuseKit has done what it can safely automate. The provider needs account approval.",
    actions: [
      "Look at the browser or provider tab FuseKit opened.",
      "Complete login, MFA, CAPTCHA, consent, payment, or ownership prompts yourself.",
      "When the page says the action is done, return to FuseKit and it will continue.",
    ],
    reassurance: "The worker remains alive and will retry this gate until it passes.",
  };
}

function renderGateHelp(step) {
  if (step?.status !== "waiting") return "";
  const guidance = gateGuidance(inferGateProvider(`${step.id} ${step.label} ${step.detail}`));
  return `
    <div class="gate-help">
      <span>What you need to do</span>
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.body)}</p>
      <ol>${guidance.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ol>
      <em>${escapeHtml(guidance.reassurance)}</em>
    </div>
  `;
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value || "";
  return div.innerHTML;
}

function renderSteps(job) {
  const root = document.querySelector("[data-steps]");
  root.innerHTML = (job.steps || [])
    .map((step, index) => `
      <li class="step-card ${escapeHtml(step.status)}" data-step-id="${escapeHtml(step.id)}">
        <span class="step-number">${String(index + 1).padStart(2, "0")}</span>
        <div class="step-copy">
          <strong>${escapeHtml(step.label)}</strong>
          <span>${escapeHtml(stepDetail(step))}</span>
        </div>
        <span class="badge ${escapeHtml(step.status)}">${escapeHtml(label(step.status))}</span>
      </li>
    `)
    .join("");
}

function renderArtifacts(job) {
  const root = document.querySelector("[data-artifacts]");
  const entries = Object.entries(job.artifacts || {}).sort();
  if (!entries.length) {
    root.innerHTML =
      "<li class='empty'>Encrypted vault, receipts, and audit logs appear " +
      "here after retrieval.</li>";
    return;
  }
  root.innerHTML = entries
    .map(([name, path]) => `
      <li>
        <div>
          <strong>${escapeHtml(name)}</strong>
          <code>${escapeHtml(path)}</code>
        </div>
        <button type="button" data-copy="${escapeHtml(path)}">Copy path</button>
      </li>
    `)
    .join("");
}

function render(job) {
  const prog = progress(job);
  const counts = statusCounts(job.steps);
  if (activeGate(job)) counts.waiting += 1;
  if (job.gate_state_error) counts.failed += 1;
  const current = currentStep(job);
  const next = nextStep(job, current);
  const statusPill = document.querySelector("[data-job-status]");
  statusPill.textContent = label(job.status);
  statusPill.className = `pill status ${job.status}`;
  document.querySelector("[data-updated-at]").textContent = "Updated just now";
  document.querySelector("[data-progress-label]").textContent = `${prog.done}/${prog.total} steps`;
  document.querySelector("[data-progress-bar]").style.width = `${prog.percent}%`;
  document.querySelector("[data-count-running]").textContent = counts.running;
  document.querySelector("[data-count-waiting]").textContent = counts.waiting;
  document.querySelector("[data-count-done]").textContent = counts.done;
  document.querySelector("[data-count-failed]").textContent = counts.failed;

  const focus = document.querySelector("[data-focus-panel]");
  focus.classList.toggle("gate", current?.status === "waiting");
  document.querySelector("[data-focus-kicker]").textContent = focusKicker(current);
  const state = mascotState(current, job);
  const scene = document.querySelector("[data-snow-scene]");
  scene.className = `snow-scene state-${state}`;
  document.querySelector("[data-snow-caption]").textContent = mascotCaption(state);
  const dot = document.querySelector("[data-focus-dot]");
  dot.className = `mini-dot ${current?.status || job.status}`;
  document.querySelector("[data-current-title]").textContent = current?.label || "Launch complete";
  document.querySelector("[data-current-detail]").textContent =
    current ? stepDetail(current) : "FuseKit is preserving encrypted and redacted artifacts.";
  document.querySelector("[data-gate-help]").innerHTML = renderGateHelp(current);
  document.querySelector("[data-next-title]").textContent =
    next?.label || "Artifacts and audit review";
  renderSteps(job);
  renderArtifacts(job);
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  await navigator.clipboard.writeText(button.dataset.copy);
  button.textContent = "Copied";
  setTimeout(() => {
    button.textContent = "Copy path";
  }, 1200);
});

async function refreshJob() {
  try {
    const response = await fetch("/api/job", { cache: "no-store" });
    if (!response.ok) return;
    render(await response.json());
  } catch {
    // Static files opened from disk simply keep their embedded state.
  }
}

render(initialJob);
if (location.protocol.startsWith("http")) {
  setInterval(refreshJob, 2000);
}
"""
