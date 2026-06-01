"""Static control-room UI rendering."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from fusekit.runner.gate_guidance import GateGuidance, infer_gate_provider, provider_gate_guidance
from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState, JobStep

STATUS_LABELS = {
    "created": "Created",
    "pending": "Pending",
    "running": "Running",
    "waiting": "Human gate",
    "done": "Done",
    "failed": "Needs repair",
    "skipped": "Skipped",
    "passed": "Passed",
    "repairing": "Repairing",
}

TERMINAL_STEP_STATUSES = {"done", "skipped"}


def render_control_room(job: JobState, *, gate_path: Path | None = None) -> str:
    """Render a standalone HTML control-room page."""

    control_payload = control_room_payload(job, gate_path=gate_path)
    payload = _safe_json(control_payload)
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
    {_render_recovery(job)}
    {_render_trust(control_payload.get("verification", {}))}
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
    html = render_control_room(job, gate_path=path.parent / "gates.json")
    path.write_text(html, encoding="utf-8")


def control_room_payload(job: JobState, *, gate_path: Path | None = None) -> dict[str, Any]:
    """Build the embedded control-room payload with durable gate state."""

    payload = job.to_dict()
    payload["verification"] = _read_verification_report(_verification_report_path(job, gate_path))
    if gate_path is None:
        payload.setdefault("gates", [])
        return payload
    gates, error = _read_gate_records(gate_path)
    payload["gates"] = gates
    if error:
        payload["gate_state_error"] = error
    return payload


def _read_gate_records(gate_path: Path) -> tuple[list[dict[str, str | int | float]], str]:
    if not gate_path.exists():
        return [], ""
    try:
        raw = json.loads(gate_path.read_text(encoding="utf-8"))
        records = [
            GateRecord.from_dict(item).to_dict()
            for item in raw.get("gates", [])
            if isinstance(item, dict)
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return [], f"Gate state could not be read from {gate_path.name}: {type(exc).__name__}"
    return records, ""


def _verification_report_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("verification_report", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "verification_report.json"
    return None


def _read_verification_report(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "overall": "failed",
            "checks": [],
            "error": f"Verification report could not be read from {path.name}",
        }
    return raw if isinstance(raw, dict) else {}


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
        <span class="pill refresh-ok" data-refresh-status>
          Live when served
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


def _render_recovery(job: JobState) -> str:
    cards = "\n".join(_render_checkpoint_card(item) for item in _visible_checkpoints(job))
    return f"""
    <section class="recovery-panel" aria-label="Recovery checkpoints">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Recovery map</span>
          <h2>Every step stays alive</h2>
        </div>
        <span class="live-pill">Plain-language resume hints</span>
      </div>
      <div class="checkpoint-grid" data-checkpoints>{cards}</div>
    </section>
"""


def _render_trust(report: Any) -> str:
    checks = list(report.get("checks", [])) if isinstance(report, dict) else []
    if checks:
        cards = "\n".join(_render_trust_card(check) for check in checks[:8])
    else:
        cards = """
        <article class="trust-card pending">
          <div class="trust-snow state-checking" aria-hidden="true"></div>
          <div>
            <span>Waiting</span>
            <strong>Trust checks appear after verification</strong>
            <p>
              Snowman will inspect provider setup, DNS, app health, and encrypted
              survivor artifacts.
            </p>
            <em>Nothing to do yet. Keep the control room open.</em>
          </div>
        </article>
"""
    overall = str(report.get("overall", "waiting")) if isinstance(report, dict) else "waiting"
    return f"""
    <section class="trust-panel" aria-label="Verification trust checks">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Trust checks</span>
          <h2>Proof it really works</h2>
        </div>
        <span class="live-pill trust-{html.escape(overall)}">
          Snowman verification: {html.escape(overall)}
        </span>
      </div>
      <div class="trust-grid" data-trust-checks>{cards}</div>
    </section>
"""


def _render_trust_card(check: dict[str, Any]) -> str:
    status = str(check.get("status", "pending"))
    snow = _trust_snow_state(status)
    title = f"{check.get('provider', 'provider')} · {check.get('check', 'check')}"
    return f"""
        <article class="trust-card {html.escape(status)}">
          <div class="trust-snow state-{html.escape(snow)}" aria-hidden="true"></div>
          <div>
            <span>{html.escape(_status_label(status))}</span>
            <strong>{html.escape(title.replace('_', ' '))}</strong>
            <p>{html.escape(str(check.get('summary', 'Verification is running.')))}</p>
            <em>{html.escape(str(check.get('repair', 'Keep the control room open.')))}</em>
          </div>
        </article>
"""


def _trust_snow_state(status: str) -> str:
    return {
        "passed": "passed",
        "pending": "checking",
        "repairing": "repairing",
        "failed": "failed",
        "skipped": "checking",
    }.get(status, "checking")


def _visible_checkpoints(job: JobState) -> list[Any]:
    active = [
        checkpoint
        for checkpoint in job.checkpoints
        if checkpoint.status in {"failed", "waiting", "running"}
    ]
    if active:
        return active[:4]
    pending = [checkpoint for checkpoint in job.checkpoints if checkpoint.status == "pending"]
    if pending:
        return pending[:3]
    return job.checkpoints[-3:]


def _render_checkpoint_card(checkpoint: Any) -> str:
    status = html.escape(checkpoint.status)
    mascot_state = html.escape(checkpoint.mascot_state)
    return f"""
        <article class="checkpoint-card {status}" data-checkpoint-id="{html.escape(checkpoint.id)}">
          <div class="checkpoint-snow state-{mascot_state}" aria-hidden="true">
            <span class="mini-snow-head"></span>
            <span class="mini-snow-body"></span>
          </div>
          <div>
            <span>{html.escape(_status_label(checkpoint.status))}</span>
            <strong>{html.escape(checkpoint.label)}</strong>
            <p>{html.escape(checkpoint.detail)}</p>
            <em>{html.escape(checkpoint.next_action)}</em>
            <code>{html.escape(checkpoint.resume_hint)}</code>
          </div>
        </article>
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
              <span class="privacy-mitten left"></span>
              <span class="privacy-mitten right"></span>
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
    if step and _is_privacy_step(step):
        return "privacy"
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
        "privacy": "covering his eyes while secrets stay private",
        "verify": "checking the live app with a frosty magnifier",
        "repair": "opening the repair kit",
        "detonate": "melting away the worker state",
        "done": "saving only the encrypted survivors",
    }
    return captions.get(state, captions["launch"])


_PRIVACY_STEP_SIGNALS = (
    "api key",
    "api-key",
    "captcha",
    "credential",
    "hidden prompt",
    "mfa",
    "passkey",
    "passphrase",
    "password",
    "payment",
    "private key",
    "secret",
    "token",
    "vault",
)


def _is_privacy_step(step: JobStep) -> bool:
    if step.status not in {"waiting", "running"}:
        return False
    text = f"{step.id} {step.label} {step.detail}".lower()
    return any(signal in text for signal in _PRIVACY_STEP_SIGNALS)


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

.pill.refresh-ok {
  border-color: rgba(54, 127, 54, 0.24);
  color: #1f5e28;
}

.pill.refresh-stale {
  border-color: rgba(172, 92, 18, 0.26);
  background: #fff0cf;
  color: #74420f;
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

.gate-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.gate-link,
.gate-attempts {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  border-radius: 999px;
  padding: 6px 10px;
  background: rgba(255, 255, 255, 0.12);
  color: #f7fbff;
  font-size: 12px;
  font-weight: 850;
  text-decoration: none;
}

.gate-link {
  border: 1px solid rgba(111, 215, 255, 0.34);
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
.privacy-mitten,
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

.privacy-mitten {
  z-index: 2;
  width: 15px;
  height: 12px;
  top: 10px;
  border-radius: 999px 999px 7px 7px;
  background: var(--snow-blue);
  box-shadow:
    inset -3px -3px 0 rgba(0, 21, 42, 0.16),
    0 0 12px rgba(111, 215, 255, 0.42);
  opacity: 0;
  transform: translateY(7px) scale(0.75);
  transition:
    opacity 180ms ease,
    transform 180ms ease;
}

.privacy-mitten.left {
  left: 6px;
  transform: rotate(-16deg) translateY(7px) scale(0.75);
}

.privacy-mitten.right {
  right: 6px;
  transform: rotate(16deg) translateY(7px) scale(0.75);
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

.state-privacy .privacy-mitten {
  opacity: 1;
}

.state-privacy .privacy-mitten.left {
  animation: privacy-peek-left 2.4s ease-in-out infinite;
  transform: rotate(-16deg) translateY(0) scale(1);
}

.state-privacy .privacy-mitten.right {
  animation: privacy-peek-right 2.4s ease-in-out infinite;
  transform: rotate(16deg) translateY(0) scale(1);
}

.state-privacy .arm.left {
  transform: rotate(-42deg) translate(18px, -12px);
}

.state-privacy .arm.right {
  transform: rotate(42deg) translate(-18px, -12px);
}

.state-privacy .snow-prop::after {
  content: "  · Hidden prompts and vault encryption keep secrets yours.";
  color: rgba(255, 255, 255, 0.72);
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

@keyframes privacy-peek-left {
  0%, 100% { transform: rotate(-16deg) translateY(0) scale(1); }
  55% { transform: rotate(-11deg) translateY(-1px) scale(1.02); }
}

@keyframes privacy-peek-right {
  0%, 100% { transform: rotate(16deg) translateY(0) scale(1); }
  55% { transform: rotate(11deg) translateY(-1px) scale(1.02); }
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

.recovery-panel {
  min-width: 0;
  margin-top: 18px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 20px;
  background: rgba(255, 255, 255, 0.76);
  box-shadow: 0 22px 52px rgba(0, 21, 42, 0.08);
}

.checkpoint-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.checkpoint-card {
  display: grid;
  grid-template-columns: 48px minmax(0, 1fr);
  gap: 12px;
  min-height: 172px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.72);
}

.checkpoint-card.running,
.checkpoint-card.waiting,
.checkpoint-card.failed {
  background: #ffffff;
}

.checkpoint-card span,
.checkpoint-card em,
.checkpoint-card code,
.checkpoint-card p,
.checkpoint-card strong {
  display: block;
  overflow-wrap: anywhere;
}

.checkpoint-card span {
  color: var(--snow-muted);
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.checkpoint-card strong {
  margin-top: 5px;
  color: var(--snow-navy);
  font-size: 15px;
}

.checkpoint-card p {
  margin-top: 8px;
  color: #42566c;
  font-size: 13px;
  line-height: 1.42;
}

.checkpoint-card em {
  margin-top: 10px;
  color: #133a5c;
  font-size: 12px;
  font-style: normal;
  font-weight: 850;
  line-height: 1.35;
}

.checkpoint-card code {
  margin-top: 10px;
  padding: 7px;
  font-size: 11px;
  line-height: 1.35;
}

.checkpoint-snow {
  position: relative;
  width: 42px;
  height: 54px;
  align-self: start;
}

.mini-snow-head,
.mini-snow-body {
  position: absolute;
  left: 50%;
  border-radius: 50%;
  background: #ffffff;
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 1px rgba(0, 151, 255, 0.16);
  transform: translateX(-50%);
}

.mini-snow-head {
  width: 24px;
  height: 24px;
  top: 2px;
}

.mini-snow-body {
  width: 34px;
  height: 31px;
  bottom: 0;
}

.checkpoint-snow.state-working {
  animation: snow-bob 1.8s ease-in-out infinite;
}

.checkpoint-snow.state-gate .mini-snow-head {
  animation: hat-tap 1.2s ease-in-out infinite;
}

.checkpoint-snow.state-privacy::after {
  content: "";
  position: absolute;
  left: 8px;
  top: 10px;
  width: 26px;
  height: 10px;
  border-radius: 999px;
  background: var(--snow-blue);
}

.checkpoint-snow.state-repair {
  animation: snow-fix 1s ease-in-out infinite;
}

.checkpoint-snow.state-verify::after {
  content: "";
  position: absolute;
  right: -4px;
  top: 20px;
  width: 14px;
  height: 14px;
  border: 3px solid var(--snow-blue);
  border-radius: 50%;
}

.checkpoint-snow.state-detonate {
  animation: snow-melt 2s ease-in-out infinite;
}

.trust-panel {
  min-width: 0;
  margin-top: 18px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 20px;
  background:
    radial-gradient(circle at 92% 8%, rgba(0, 151, 255, 0.18), transparent 24%),
    rgba(255, 255, 255, 0.8);
  box-shadow: 0 22px 52px rgba(0, 21, 42, 0.08);
}

.trust-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.trust-card {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr);
  gap: 12px;
  min-height: 164px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.78);
}

.trust-card.passed {
  border-color: rgba(54, 127, 54, 0.28);
  background: #f0fff0;
}

.trust-card.pending,
.trust-card.repairing {
  border-color: rgba(0, 151, 255, 0.22);
}

.trust-card.failed {
  border-color: rgba(185, 48, 32, 0.24);
  background: #fff3f0;
}

.trust-card span,
.trust-card strong,
.trust-card p,
.trust-card em {
  display: block;
  overflow-wrap: anywhere;
}

.trust-card span {
  color: var(--snow-muted);
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.trust-card strong {
  margin-top: 5px;
  color: var(--snow-navy);
  font-size: 15px;
}

.trust-card p {
  margin-top: 8px;
  color: #42566c;
  font-size: 13px;
  line-height: 1.42;
}

.trust-card em {
  margin-top: 10px;
  color: #133a5c;
  font-size: 12px;
  font-style: normal;
  font-weight: 850;
  line-height: 1.35;
}

.trust-snow {
  position: relative;
  width: 38px;
  height: 50px;
}

.trust-snow::before,
.trust-snow::after {
  content: "";
  position: absolute;
  left: 50%;
  border-radius: 50%;
  background: #ffffff;
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 1px rgba(0, 151, 255, 0.16);
  transform: translateX(-50%);
}

.trust-snow::before {
  width: 23px;
  height: 23px;
  top: 2px;
}

.trust-snow::after {
  width: 33px;
  height: 30px;
  bottom: 0;
}

.trust-snow.state-checking {
  animation: snow-bob 1.6s ease-in-out infinite;
}

.trust-snow.state-passed {
  animation: snow-celebrate 0.9s ease-in-out infinite;
}

.trust-snow.state-passed::before {
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 3px rgba(99, 210, 118, 0.24);
}

.trust-snow.state-repairing {
  animation: snow-fix 0.95s ease-in-out infinite;
}

.trust-snow.state-failed {
  animation: hat-tap 0.9s ease-in-out infinite;
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
  .workspace,
  .checkpoint-grid,
  .trust-grid {
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
  .artifact-panel,
  .recovery-panel,
  .trust-panel {
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
    provider: gate.provider || "",
    resume_url: gate.resume_url || "",
    attempts: gate.attempts || 0,
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
  if (isPrivacyStep(step)) return "privacy";
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
    privacy: "covering his eyes while secrets stay private",
    verify: "checking the live app with a frosty magnifier",
    repair: "opening the repair kit",
    detonate: "melting away the worker state",
    done: "saving only the encrypted survivors",
  }[state] || "packing the clean-room suitcase";
}

const privacyStepSignals = [
  "api key",
  "api-key",
  "captcha",
  "credential",
  "hidden prompt",
  "mfa",
  "passkey",
  "passphrase",
  "password",
  "payment",
  "private key",
  "secret",
  "token",
  "vault",
];

function isPrivacyStep(step) {
  if (!step || !["waiting", "running"].includes(step.status)) return false;
  const text = `${step.id || ""} ${step.label || ""} ${step.detail || ""}`.toLowerCase();
  return privacyStepSignals.some((signal) => text.includes(signal));
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
  const resumeLink = step.resume_url
    ? [
        `<a class="gate-link" href="${escapeAttr(step.resume_url)}"`,
        ` target="_blank" rel="noreferrer">Open provider gate</a>`,
      ].join("")
    : "";
  const attempts = step.attempts
    ? [
        `<span class="gate-attempts">Resurfaced ${escapeHtml(String(step.attempts))}`,
        ` time${step.attempts === 1 ? "" : "s"}</span>`,
      ].join("")
    : "";
  const meta = resumeLink || attempts
    ? `<div class="gate-meta">${resumeLink}${attempts}</div>`
    : "";
  return `
    <div class="gate-help">
      <span>What you need to do</span>
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.body)}</p>
      ${meta}
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

function escapeAttr(value) {
  return escapeHtml(value).replaceAll('"', "&quot;");
}

function classToken(value) {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "");
}

function renderSteps(job) {
  const root = document.querySelector("[data-steps]");
  root.innerHTML = (job.steps || [])
    .map((step, index) => `
      <li class="step-card ${classToken(step.status)}" data-step-id="${escapeAttr(step.id)}">
        <span class="step-number">${String(index + 1).padStart(2, "0")}</span>
        <div class="step-copy">
          <strong>${escapeHtml(step.label)}</strong>
          <span>${escapeHtml(stepDetail(step))}</span>
        </div>
        <span class="badge ${classToken(step.status)}">${escapeHtml(label(step.status))}</span>
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
        <button type="button" data-copy="${escapeAttr(path)}">Copy path</button>
      </li>
    `)
    .join("");
}

function visibleCheckpoints(job) {
  const checkpoints = job.checkpoints || [];
  const active = checkpoints.filter((item) =>
    ["failed", "waiting", "running"].includes(item.status),
  );
  if (active.length) return active.slice(0, 4);
  const pending = checkpoints.filter((item) => item.status === "pending");
  if (pending.length) return pending.slice(0, 3);
  return checkpoints.slice(-3);
}

function renderCheckpoints(job) {
  const root = document.querySelector("[data-checkpoints]");
  if (!root) return;
  const checkpoints = visibleCheckpoints(job);
  if (!checkpoints.length) {
    root.innerHTML =
      "<article class='checkpoint-card pending'><div></div><div>" +
      "<span>Ready</span><strong>Waiting for first checkpoint</strong>" +
      "<p>FuseKit will populate this map as soon as the worker starts.</p>" +
      "<em>Nothing needed yet.</em><code>Keep this control room open.</code>" +
      "</div></article>";
    return;
  }
  root.innerHTML = checkpoints
    .map((checkpoint) => `
      <article class="checkpoint-card ${classToken(checkpoint.status)}"
        data-checkpoint-id="${escapeAttr(checkpoint.id)}">
        <div class="checkpoint-snow state-${classToken(checkpoint.mascot_state)}"
          aria-hidden="true">
          <span class="mini-snow-head"></span>
          <span class="mini-snow-body"></span>
        </div>
        <div>
          <span>${escapeHtml(label(checkpoint.status))}</span>
          <strong>${escapeHtml(checkpoint.label)}</strong>
          <p>${escapeHtml(checkpoint.detail)}</p>
          <em>${escapeHtml(checkpoint.next_action)}</em>
          <code>${escapeHtml(checkpoint.resume_hint)}</code>
        </div>
      </article>
    `)
    .join("");
}

function trustSnowState(status) {
  return {
    passed: "passed",
    pending: "checking",
    repairing: "repairing",
    failed: "failed",
    skipped: "checking",
  }[status] || "checking";
}

function renderTrust(job) {
  const root = document.querySelector("[data-trust-checks]");
  if (!root) return;
  const report = job.verification || {};
  const checks = report.checks || [];
  if (!checks.length) {
    root.innerHTML =
      "<article class='trust-card pending'>" +
      "<div class='trust-snow state-checking' aria-hidden='true'></div><div>" +
      "<span>Waiting</span><strong>Trust checks appear after verification</strong>" +
      "<p>Snowman will inspect provider setup, DNS, app health, " +
      "and encrypted survivor artifacts.</p>" +
      "<em>Nothing to do yet. Keep the control room open.</em>" +
      "</div></article>";
    return;
  }
  root.innerHTML = checks
    .slice(0, 8)
    .map((check) => {
      const status = classToken(check.status || "pending");
      const snow = trustSnowState(status);
      const title = `${check.provider || "provider"} · ${check.check || "check"}`.replaceAll(
        "_",
        " ",
      );
      return `
        <article class="trust-card ${status}">
          <div class="trust-snow state-${classToken(snow)}" aria-hidden="true"></div>
          <div>
            <span>${escapeHtml(label(status))}</span>
            <strong>${escapeHtml(title)}</strong>
            <p>${escapeHtml(check.summary || "Verification is running.")}</p>
            <em>${escapeHtml(check.repair || "Keep the control room open.")}</em>
          </div>
        </article>
      `;
    })
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
  statusPill.className = `pill status ${classToken(job.status)}`;
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
  dot.className = `mini-dot ${classToken(current?.status || job.status)}`;
  document.querySelector("[data-current-title]").textContent = current?.label || "Launch complete";
  document.querySelector("[data-current-detail]").textContent =
    current ? stepDetail(current) : "FuseKit is preserving encrypted and redacted artifacts.";
  document.querySelector("[data-gate-help]").innerHTML = renderGateHelp(current);
  document.querySelector("[data-next-title]").textContent =
    next?.label || "Artifacts and audit review";
  renderCheckpoints(job);
  renderTrust(job);
  renderSteps(job);
  renderArtifacts(job);
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = "Copy path";
    }, 1200);
  } catch {
    button.textContent = "Copy blocked";
    setRefreshStatus("Copy was blocked by the browser. Select the path text manually.", "stale");
  }
});

function setRefreshStatus(text, tone = "ok") {
  const node = document.querySelector("[data-refresh-status]");
  if (!node) return;
  node.textContent = text;
  node.className = `pill ${tone === "stale" ? "refresh-stale" : "refresh-ok"}`;
}

async function refreshJob() {
  try {
    const response = await fetch("/api/job", { cache: "no-store" });
    if (!response.ok) {
      setRefreshStatus(`Live refresh paused (${response.status})`, "stale");
      return;
    }
    render(await response.json());
    setRefreshStatus("Live refresh connected");
  } catch {
    setRefreshStatus(
      location.protocol.startsWith("http")
        ? "Live refresh paused. Reopen or restart the control-room server."
        : "Snapshot view. Serve the control room for live updates.",
      "stale",
    );
  }
}

render(initialJob);
if (location.protocol.startsWith("http")) {
  setInterval(refreshJob, 2000);
}
"""
