"""Static control-room UI rendering."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

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
ACTIVE_STEP_STATUSES = {"running", "waiting", "failed"}


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
        <div class="eyebrow">FuseKit control room</div>
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
        <h2 data-current-title>{current_label}</h2>
        <p data-current-detail>{html.escape(_step_detail(current))}</p>
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


def _headline(job: JobState) -> str:
    if job.status == "waiting":
        return "Waiting at a human gate"
    if job.status == "failed":
        return "Launch needs attention"
    if job.status == "done":
        return "Launch is complete"
    return "Launch in progress"


def _current_step(job: JobState) -> JobStep | None:
    for step in job.steps:
        if step.status in ACTIVE_STEP_STATUSES:
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
  background: #efeee7;
  color: #111615;
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
    linear-gradient(90deg, rgba(18, 22, 20, 0.05) 1px, transparent 1px),
    linear-gradient(180deg, rgba(18, 22, 20, 0.05) 1px, transparent 1px),
    #efeee7;
  background-size: 42px 42px;
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
  border-bottom: 2px solid #111615;
}

.eyebrow,
.section-kicker {
  color: #5b625f;
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
  color: #38413d;
  font-size: 16px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

code {
  border: 1px solid rgba(17, 22, 21, 0.12);
  border-radius: 6px;
  padding: 2px 6px;
  background: rgba(255, 255, 255, 0.72);
  color: #111615;
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
  border: 1px solid rgba(17, 22, 21, 0.14);
  border-radius: 999px;
  padding: 7px 11px;
  background: rgba(255, 255, 255, 0.72);
  color: #25302d;
  font-size: 12px;
  font-weight: 850;
  white-space: nowrap;
}

.pill.status {
  border-color: transparent;
  color: #111615;
}

.pill.muted,
.live-pill {
  color: #5b625f;
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
  border: 1px solid rgba(17, 22, 21, 0.13);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.66);
  box-shadow: 0 28px 70px rgba(17, 22, 21, 0.08);
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
  background: rgba(17, 22, 21, 0.1);
}

.meter span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: #1b6b57;
  transition: width 220ms ease;
}

.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.stats span {
  min-height: 54px;
  border: 1px solid rgba(17, 22, 21, 0.1);
  border-radius: 10px;
  padding: 10px;
  color: #4d5652;
  background: rgba(255, 255, 255, 0.52);
  font-size: 12px;
  font-weight: 800;
}

.stats strong {
  display: block;
  color: #111615;
  font-size: 22px;
  line-height: 1;
}

.focus-panel {
  background: #111615;
  color: #f5f3ea;
}

.focus-panel.gate {
  background: #261905;
}

.focus-panel .section-kicker,
.focus-panel p,
.next-line span {
  color: #bfc7c1;
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
  border-radius: 12px;
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
    max-width: 340px;
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
    word-break: break-word;
  }

  .focus-panel p,
  .next-line,
  .next-line strong {
    font-size: 14px;
    max-width: 310px;
    word-break: break-word;
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

function progress(job) {
  const steps = job.steps || [];
  const total = Math.max(steps.length, 1);
  const done = steps.filter((step) => ["done", "skipped"].includes(step.status)).length;
  return { done, total: steps.length, percent: Math.round((done / total) * 100) };
}

function currentStep(job) {
  const active = (job.steps || []).find((step) =>
    ["running", "waiting", "failed"].includes(step.status)
  );
  if (active) return active;
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
  const dot = document.querySelector("[data-focus-dot]");
  dot.className = `mini-dot ${current?.status || job.status}`;
  document.querySelector("[data-current-title]").textContent = current?.label || "Launch complete";
  document.querySelector("[data-current-detail]").textContent =
    current ? stepDetail(current) : "FuseKit is preserving encrypted and redacted artifacts.";
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
