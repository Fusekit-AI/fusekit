"""Static control-room UI rendering."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fusekit.runner.control_room.assets import STYLE
from fusekit.runner.control_room.cards import (
    TERMINAL_STEP_STATUSES,
    progress,
    status_counts,
    status_label,
)
from fusekit.runner.control_room.events import SCRIPT
from fusekit.runner.control_room.redaction import redact_gate_target
from fusekit.runner.control_room.snowman import (
    mascot_state,
    render_brand_lockup,
    render_snowman_scene,
)
from fusekit.runner.control_room.state import control_room_payload
from fusekit.runner.gate_guidance import GateGuidance, infer_gate_provider, provider_gate_guidance
from fusekit.runner.job import JobState, JobStep


def render_control_room(
    job: JobState,
    *,
    gate_path: Path | None = None,
    action_token: str = "",
) -> str:
    """Render a standalone HTML control-room page."""

    control_payload = control_room_payload(job, gate_path=gate_path)
    if action_token:
        control_payload["control_room_action_token"] = action_token
    payload = _safe_json(_public_payload(control_payload))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit Control Room</title>
  <style>{STYLE}</style>
</head>
<body>
  <main class="shell">
    {_render_header(job)}
    <section class="overview" aria-label="Launch overview">
      {_render_progress(job, control_payload)}
      {_render_focus(job, control_payload)}
    </section>
    <div data-visual-session>{_render_visual_session(control_payload.get("visual", {}))}</div>
    {_render_recovery(job)}
    {_render_run_state(control_payload.get("run_state", {}))}
    {_render_acceptance_blockers(control_payload.get("acceptance", {}))}
    {_render_provider_strategies(control_payload.get("provider_strategies", {}))}
    {_render_trust(control_payload.get("verification", {}))}
    <section class="workspace">
      {_render_steps(job)}
      {_render_artifacts(job)}
    </section>
  </main>
  <script id="job-data" type="application/json">{payload}</script>
  <script>{SCRIPT}</script>
</body>
</html>
"""


def write_control_room(job: JobState, path: Path) -> None:
    """Write the control-room HTML file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_control_room(job, gate_path=path.parent / "gates.json")
    path.write_text(html, encoding="utf-8")


def _render_header(job: JobState) -> str:
    return f"""
    <header class="hero">
      <div>
        {render_brand_lockup("control room")}
        <h1>{html.escape(_headline(job))}</h1>
        <p>
          Job <code>{html.escape(job.id)}</code> is wiring
          <code>{html.escape(job.app_path)}</code> through the
          <code>{html.escape(job.runner)}</code> lane.
        </p>
      </div>
      <div class="status-stack" aria-label="Job status">
        <span class="pill status {html.escape(job.status)}" data-job-status>
          {html.escape(status_label(job.status))}
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


def _render_progress(job: JobState, payload: dict[str, Any]) -> str:
    done, total, percent = progress(job.steps)
    counts = status_counts(job.steps)
    active_gate = _active_gate(payload)
    if (
        active_gate
        and active_gate.get("status") != "resume_requested"
        and not any(step.status == "waiting" for step in job.steps)
    ):
        counts["waiting"] += 1
    if payload.get("gate_state_error") and not any(step.status == "failed" for step in job.steps):
        counts["failed"] += 1
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


def _render_focus(job: JobState, payload: dict[str, Any]) -> str:
    current = _current_step(job, payload)
    next_step = _next_step(job, current)
    gate_class = " gate" if current and current.status == "waiting" else ""
    current_mascot_state = mascot_state(current, job)
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
        {render_snowman_scene(current_mascot_state)}
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
    step_status_label = html.escape(status_label(step.status))
    return f"""
          <li class="step-card {status}" data-step-id="{html.escape(step.id)}">
            <span class="step-number">{index:02d}</span>
            <div class="step-copy">
              <strong>{html.escape(step.label)}</strong>
              <span>{html.escape(_step_detail(step))}</span>
            </div>
            <span class="badge {status}">{step_status_label}</span>
          </li>
"""


def _public_copy(value: Any) -> str:
    """Translate stale internal/fallback wording into launcher-safe user copy."""

    text = str(value or "")
    replacements = (
        (
            "paste it into FuseKit's hidden prompt",
            "copy it inside the VM browser, then click the matching "
            "Capture from VM clipboard button",
        ),
        (
            "paste into FuseKit's hidden prompt",
            "copy inside the VM browser, then click the matching "
            "Capture from VM clipboard button",
        ),
        ("hidden Cloud Shell prompts", "Capture from VM clipboard buttons"),
        ("hidden prompts/env handoff", "VM clipboard Capture fallback"),
        ("hidden prompts", "VM clipboard Capture fallback"),
        ("hidden prompt", "VM clipboard Capture"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _public_target(value: Any) -> str:
    """Return a display-safe gate target."""

    return redact_gate_target(_public_copy(value))


def _public_payload(value: Any) -> Any:
    """Return a display-safe payload for the static control-room bootstrap JSON."""

    if isinstance(value, dict):
        return {key: _public_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_public_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_public_payload(item) for item in value]
    if isinstance(value, str):
        return _public_copy(value)
    return value


def _render_artifacts(job: JobState) -> str:
    rows = "\n".join(
        f"""
          <li>
            <div>
              <strong>{html.escape(name)}</strong>
              <code>{html.escape(path)}</code>
            </div>
            <button type="button" data-copy="{html.escape(path)}" data-copy-label="path">
              Copy path
            </button>
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


def _render_visual_session(visual: Any) -> str:
    if not isinstance(visual, dict) or not visual.get("novnc_url"):
        return ""
    novnc_url = str(visual.get("novnc_url", ""))
    control_room_url = str(visual.get("control_room_url", ""))
    password = str(visual.get("novnc_password", ""))
    iframe_url = _url_with_query_param(novnc_url, "password", password)
    status = str(visual.get("status", "ready") or "ready")
    password_row = (
        f"""
            <div class="visual-secret-row">
              <input
                value="{html.escape(password)}"
                readonly
                aria-label="noVNC password"
              />
              <button
                type="button"
                data-copy="{html.escape(password)}"
                data-copy-label="password"
              >
                Copy
              </button>
            </div>
        """
        if password
        else "<span>Stored only on the active VM</span>"
    )
    control_link = (
        f'<a href="{html.escape(control_room_url)}" target="_blank" rel="noreferrer">'
        "Open live control room</a>"
        if control_room_url
        else ""
    )
    return f"""
    <section class="visual-panel" aria-label="Live VM browser">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Live VM browser</span>
          <h2>Human gates happen here</h2>
        </div>
        <span class="live-pill" data-visual-status>
          Visual session: {html.escape(status)}
        </span>
      </div>
      <div class="visual-grid">
        <iframe
          class="visual-frame"
          src="{html.escape(iframe_url)}"
          title="FuseKit VM browser"
          tabindex="0"
          referrerpolicy="no-referrer"
          allow="clipboard-read; clipboard-write"
          sandbox="allow-scripts allow-same-origin allow-forms allow-pointer-lock allow-modals"
        ></iframe>
        <aside class="visual-help">
          <strong>Interactive remote browser</strong>
          <p>
            This is the disposable VM display. Use it to click, type, and pass
            provider gates while FuseKit keeps observing the same session.
          </p>
          <div class="visual-secret">
            <span>noVNC password</span>
            {password_row}
          </div>
          <div class="visual-actions">
            <a href="{html.escape(iframe_url)}" target="_blank" rel="noreferrer">
              Open live VM browser
            </a>
            <button
              type="button"
              data-copy="{html.escape(iframe_url)}"
              data-copy-label="live VM browser link"
            >
              Copy live VM browser link
            </button>
            {control_link}
          </div>
        </aside>
      </div>
    </section>
"""


def _render_acceptance_blockers(report: Any) -> str:
    report = report if isinstance(report, dict) else {}
    blockers = _acceptance_blockers(report)
    error = str(report.get("error", "") or "")
    ready = bool(report.get("launch_ready", False))
    mode = str(report.get("mode", "") or "").strip().lower()
    if error:
        cards = f"""
        <article class="trust-card failed">
          <div class="trust-snow state-failed" aria-hidden="true"></div>
          <div>
            <span>Needs repair</span>
            <strong>Acceptance report could not load</strong>
            <p>{html.escape(error)}</p>
            <em>Rerun acceptance so FuseKit can rebuild launch-readiness proof.</em>
          </div>
        </article>
"""
        summary = "acceptance report needs repair"
    elif ready and mode == "live":
        cards = """
        <article class="trust-card passed">
          <div class="trust-snow state-passed" aria-hidden="true"></div>
          <div>
            <span>Passed</span>
            <strong>Acceptance blockers are clear</strong>
            <p>The live run has the required proof to be launch-ready.</p>
            <em>Record the demo from this clean state.</em>
          </div>
        </article>
"""
        summary = "launch-ready proof is clear"
    elif ready:
        cards = """
        <article class="trust-card pending">
          <div class="trust-snow state-checking" aria-hidden="true"></div>
          <div>
            <span>Rehearsal passed</span>
            <strong>Live acceptance is still required</strong>
            <p>Local rehearsal proof is clear, but it is not live provider evidence.</p>
            <em>Run live acceptance after the provider run before recording the demo.</em>
          </div>
        </article>
"""
        summary = "live acceptance still required"
    elif blockers:
        cards = "\n".join(
            _render_acceptance_blocker_card(blocker)
            for blocker in blockers[:8]
            if isinstance(blocker, dict)
        )
        summary = f"{len(blockers)} launch blocker{'s' if len(blockers) != 1 else ''}"
    else:
        cards = """
        <article class="trust-card pending">
          <div class="trust-snow state-checking" aria-hidden="true"></div>
          <div>
            <span>Waiting</span>
            <strong>Launch blockers appear after acceptance</strong>
            <p>
              FuseKit will list any remaining provider, DNS, vault, audit,
              or demo blockers here.
            </p>
            <em>Keep the control room open while setup and verification run.</em>
          </div>
        </article>
"""
        summary = "acceptance proof is waiting"
    return f"""
    <section class="acceptance-panel" aria-label="Launch-readiness blockers">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Launch blockers</span>
          <h2>What must be fixed before recording</h2>
        </div>
        <span class="live-pill" data-acceptance-overall>{html.escape(summary)}</span>
      </div>
      <div class="acceptance-grid" data-acceptance-blockers>{cards}</div>
    </section>
"""


def _acceptance_blockers(report: dict[str, Any]) -> list[dict[str, Any]]:
    blockers = report.get("blockers", [])
    if isinstance(blockers, list):
        normalized = [blocker for blocker in blockers if isinstance(blocker, dict)]
        if normalized:
            return normalized
    missing = report.get("missing", [])
    if not isinstance(missing, list):
        return []
    return [
        _missing_acceptance_blocker(str(item))
        for item in missing
        if str(item).strip()
    ]


def _missing_acceptance_blocker(item: str) -> dict[str, str]:
    category, next_action = _missing_acceptance_guidance(item)
    return {
        "category": category,
        "item": item,
        "next_action": next_action,
    }


def _missing_acceptance_guidance(item: str) -> tuple[str, str]:
    guidance = {
        "encrypted vault": (
            "Vault",
            (
                "Run the launcher with vault capture enabled so FuseKit stores secrets "
                "only in the encrypted vault."
            ),
        ),
        "redacted setup receipt": (
            "Receipt",
            "Rerun setup so the worker writes a redacted setup receipt with no raw secrets.",
        ),
        "safe verification report": (
            "Verification",
            (
                "Let FuseKit finish provider verification and resolve any visible "
                "provider gate it surfaces in the VM browser."
            ),
        ),
        "rollback metadata": (
            "Rollback",
            "Let FuseKit generate rollback actions from the redacted setup receipt.",
        ),
        "audited human gate interventions": (
            "Human gates",
            (
                "Open, capture, or resume each control-room gate through the launcher so "
                "redacted audit events are written."
            ),
        ),
        "resolved human gates": (
            "Human gates",
            (
                "Finish or repair every waiting, resurfaced, or retrying control-room gate "
                "before recording."
            ),
        ),
        "guided human gates": (
            "Human gates",
            "Regenerate gate state so every control-room gate has follow-me steps, "
            "next action, and resume hint.",
        ),
        "provider strategy decisions": (
            "Provider routes",
            (
                "Run provider setup through the strategy recorder so API, vault, or "
                "VM follow-me choices are proven."
            ),
        ),
        "complete provider strategy evidence": (
            "Provider routes",
            "Record selected-route kind, status, deterministic flags, reason, and candidates.",
        ),
        "complete provider strategy coverage": (
            "Provider routes",
            "Record provider strategy evidence for every provider declared by the manifest.",
        ),
        "complete provider verification coverage": (
            "Verification",
            "Record verification checks for every provider declared by the manifest.",
        ),
        "complete rollback coverage": (
            "Rollback",
            "Record rollback metadata for every provider declared by the manifest.",
        ),
        "Resend-before-DNS provider setup order": (
            "Provider order",
            "Run Resend domain setup before Cloudflare/DNS so Resend DNS records are included.",
        ),
        "Resend DNS records in receipt DNS proposal": (
            "Provider order",
            (
                "Let FuseKit create or reuse the Resend sending domain first, then approve "
                "the DNS apply gate so Cloudflare receives the exact Resend records."
            ),
        ),
        "Resend runtime env in Vercel receipt": (
            "Deployment env",
            (
                "Capture RESEND_API_KEY in the launcher, then let FuseKit create or reuse "
                "the Resend domain/audience values by API and push the required RESEND_* "
                "runtime variables into Vercel before verification."
            ),
        ),
        "provider contract-health receipt proof": (
            "Provider routes",
            (
                "Let FuseKit rerun provider setup so each API route proves a read-only "
                "provider health check before changing provider state."
            ),
        ),
        "validated provider capability packs": (
            "Provider packs",
            "Regenerate provider capability packs for this app's providers before setup runs.",
        ),
        "verified live URL": (
            "Deployment",
            "Let FuseKit verify the deployed live URL and write it into the setup receipt.",
        ),
        "clean leak scan": (
            "Security",
            "Remove plaintext setup secrets from app files and rerun the launch leak scan.",
        ),
        "detonated worker state": (
            "Detonation",
            (
                "Run detonation so plaintext worker, browser, visual, provider-auth, "
                "control-room, and gateway scratch state is destroyed after encrypted "
                "proof is preserved."
            ),
        ),
    }
    return guidance.get(
        item,
        ("Launch evidence", _unknown_acceptance_blocker_action(item)),
    )


def _unknown_acceptance_blocker_action(item: str) -> str:
    return (
        f"Keep the control room open while FuseKit regenerates launch evidence for {item}. "
        "Use any visible Open provider gate in VM, Capture from VM clipboard, "
        "I finished this step, Approve setup plan, or Approve DNS apply control that appears. "
        "If no specific launcher control appears, rerun the same live launch/acceptance so "
        "FuseKit can rebuild this proof artifact."
    )


def _render_acceptance_blocker_card(blocker: dict[str, Any]) -> str:
    category = str(blocker.get("category", "Launch blocker") or "Launch blocker")
    item = str(blocker.get("item", "Acceptance item") or "Acceptance item")
    next_action = str(
        blocker.get("next_action", "") or _unknown_acceptance_blocker_action(item)
    )
    detail = str(blocker.get("detail", "") or "").strip()
    detail_block = (
        f"<code>{html.escape(_public_copy(detail))}</code>"
        if detail
        else ""
    )
    return f"""
        <article class="trust-card failed">
          <div class="trust-snow state-failed" aria-hidden="true"></div>
          <div>
            <span>{html.escape(category)}</span>
            <strong>{html.escape(item)}</strong>
            <p>{html.escape(next_action)}</p>
            {detail_block}
            <em>FuseKit will keep this visible until acceptance proof passes.</em>
          </div>
        </article>
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


def _render_provider_strategies(strategies: Any) -> str:
    payload = strategies if isinstance(strategies, dict) else {}
    providers = payload.get("providers", [])
    if not isinstance(providers, list) or not providers:
        cards = """
        <article class="strategy-card pending">
          <span>Waiting</span>
          <strong>Provider routes appear after setup starts</strong>
          <p>FuseKit will show whether it chose API, CLI, browser guidance, or follow-me.</p>
        </article>
"""
    else:
        plan = _render_strategy_plan(providers)
        cards = plan + "\n".join(_render_strategy_card(item) for item in providers)
    return f"""
    <section class="strategy-panel" aria-label="Provider route decisions">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Provider routes</span>
          <h2>How FuseKit is connecting services</h2>
        </div>
        <span class="live-pill">API, CLI, browser, or follow-me</span>
      </div>
      <div class="strategy-grid" data-provider-strategies>{cards}</div>
    </section>
"""


def _render_strategy_plan(providers: list[Any]) -> str:
    items = _strategy_plan_items(providers)
    if not items:
        return ""
    rows = "".join(
        f"<li>{html.escape(_public_copy(item))}</li>"
        for item in items
        if item.strip()
    )
    return f"""
        <article class="strategy-card strategy-plan">
          <span>Route plan</span>
          <strong>What happens in order</strong>
          <ol>{rows}</ol>
        </article>
"""


def _strategy_plan_items(providers: list[Any]) -> list[str]:
    records = list(_iter_strategy_records(providers))
    if not records:
        return []
    items: list[str] = []
    has_resend_domain = any(
        _strategy_provider(record) == "resend"
        and _strategy_recipe(record) == "resend-domain"
        and _strategy_route(record) == "api"
        and _strategy_evidence(record).get("downstream_order") == "before_dns_apply"
        for record in records
    )
    has_dns = any(
        _strategy_provider(record) in {"cloudflare", "dns"}
        or "dns" in _strategy_recipe(record)
        for record in records
    )
    has_vercel_resend_env = any(
        _strategy_provider(record) == "vercel"
        and _strategy_route(record) == "api"
        and "env" in _strategy_recipe(record)
        for record in records
    )
    token_targets = sorted(
        {
            str(record.get("target", "")).strip().upper()
            for record in records
            if _strategy_route(record) in {"browser_guided", "human_follow_me"}
            and str(record.get("target", "")).strip()
        }
    )
    has_human_gate = any(
        _strategy_route(record) in {"browser_guided", "human_follow_me"}
        for record in records
    )
    has_api = any(_strategy_route(record) == "api" for record in records)
    if has_resend_domain:
        items.append(
            "First, FuseKit creates or reuses the Resend sending domain by API; "
            "do not click Add domain in Resend."
        )
    if has_resend_domain and has_dns:
        items.append(
            "Then FuseKit carries the Resend DNS records into the DNS approval gate "
            "with the app records before Cloudflare/DNS apply runs."
        )
    if has_vercel_resend_env:
        items.append(
            "After RESEND_API_KEY capture lets FuseKit create or reuse the Resend "
            "domain/audience values by API, FuseKit writes the required RESEND_* runtime "
            "variables into Vercel before deployment verification."
        )
    if token_targets:
        capture_labels = ", ".join(
            f"Capture {target} from VM clipboard" for target in token_targets
        )
        items.append(
            "If a provider token gate appears, click Open provider gate in VM, copy "
            "the value inside the shared VM browser, then click "
            f"{capture_labels}."
        )
    elif has_human_gate:
        items.append(
            "For provider-owned login, MFA, consent, or billing gates, click Open "
            "provider gate in VM, finish the prompt in the shared VM browser, then "
            "click the visible I finished this step button in the control room only "
            "after the provider confirms."
        )
    if not items and has_api:
        items.append(
            "FuseKit will run deterministic provider API setup after authorization "
            "and read-only health checks pass."
        )
    return items


def _iter_strategy_records(providers: list[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for provider_record in providers:
        if not isinstance(provider_record, dict):
            continue
        provider = str(provider_record.get("provider", "")).strip().lower()
        strategies = provider_record.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        for strategy in strategies:
            if isinstance(strategy, dict):
                records.append({**strategy, "_provider": provider})
    return records


def _strategy_provider(record: dict[str, Any]) -> str:
    return str(record.get("_provider", record.get("provider", ""))).strip().lower()


def _strategy_recipe(record: dict[str, Any]) -> str:
    return str(record.get("recipe", "")).strip().lower()


def _strategy_route(record: dict[str, Any]) -> str:
    decision = record.get("decision", {})
    selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
    fallback = selected.get("kind", "") if isinstance(selected, dict) else ""
    return str(record.get("strategy", fallback)).strip()


def _strategy_evidence(record: dict[str, Any]) -> dict[str, Any]:
    decision = record.get("decision", {})
    selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
    evidence = selected.get("evidence", {}) if isinstance(selected, dict) else {}
    return evidence if isinstance(evidence, dict) else {}


def _render_strategy_card(provider_record: Any) -> str:
    if not isinstance(provider_record, dict):
        return ""
    provider = str(provider_record.get("provider", "provider"))
    strategies = provider_record.get("strategies", [])
    if not isinstance(strategies, list) or not strategies:
        return f"""
        <article class="strategy-card pending">
          <span>{html.escape(provider)}</span>
          <strong>No route decision recorded yet</strong>
          <p>FuseKit is still preparing provider setup.</p>
        </article>
"""
    rows = "\n".join(
        _render_strategy_row(provider, item)
        for item in strategies
        if isinstance(item, dict)
    )
    return f"""
        <article class="strategy-card">
          <span>{html.escape(provider)}</span>
          <strong>{len(strategies)} setup route{'s' if len(strategies) != 1 else ''}</strong>
          <div>{rows}</div>
        </article>
"""


def _render_strategy_row(provider: str, strategy: dict[str, Any]) -> str:
    decision = strategy.get("decision", {})
    selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
    reason = str(selected.get("reason", "")) if isinstance(selected, dict) else ""
    route_summary = _strategy_route_summary(provider, strategy, selected)
    route = str(strategy.get("strategy", "unknown"))
    status = str(strategy.get("status", "pending"))
    recipe = str(strategy.get("recipe", "setup"))
    next_action = str(strategy.get("next_action", "") or "").strip()
    resume_hint = str(strategy.get("resume_hint", "") or "").strip()
    follow_steps = strategy.get("follow_steps", [])
    step_items = (
        "".join(
            f"<li>{html.escape(_public_copy(str(step)))}</li>"
            for step in follow_steps
            if str(step).strip()
        )
        if isinstance(follow_steps, list)
        else ""
    )
    guide = (
        "<small><b>Next:</b> "
        f"{html.escape(_public_copy(next_action))}</small>"
        if next_action
        else ""
    )
    hint = (
        f"<small>{html.escape(_public_copy(resume_hint))}</small>" if resume_hint else ""
    )
    steps = f"<ol>{step_items}</ol>" if step_items else ""
    return f"""
            <div class="strategy-row">
              <b>{html.escape(recipe)}</b>
              <em>{html.escape(route.replace('_', ' '))} · {html.escape(status)}</em>
              <small>{html.escape(route_summary)}</small>
              <small>{html.escape(reason)}</small>
              {guide}
              {hint}
              {steps}
            </div>
"""


def _strategy_route_summary(provider: str, strategy: dict[str, Any], selected: Any) -> str:
    selected = selected if isinstance(selected, dict) else {}
    route = str(strategy.get("strategy", selected.get("kind", "unknown")))
    recipe = str(strategy.get("recipe", ""))
    evidence = selected.get("evidence", {})
    evidence = evidence if isinstance(evidence, dict) else {}
    deterministic = bool(selected.get("deterministic", False))
    implemented = bool(selected.get("implemented", False))
    if route == "api":
        if provider.lower() == "resend" and recipe == "resend-domain":
            if evidence.get("downstream_order") == "before_dns_apply":
                return (
                    "API automation: FuseKit creates or reuses the Resend domain, "
                    "collects DNS records, then waits for DNS approval."
                )
        if provider.lower() == "resend" and recipe == "resend-audience":
            if evidence.get("conditional") == "only_when_app_requires_audience":
                return (
                    "API automation: FuseKit creates or reuses a Resend audience only "
                    "when this app requires one."
                )
        return "API automation: deterministic provider setup runs after authorization."
    if route == "official_cli":
        return "Official CLI route: deterministic when installed and enabled."
    if route == "local_vault":
        return "Vault capture: already-approved values move directly into the encrypted vault."
    if route in {"browser_guided", "human_follow_me"}:
        return (
            "VM follow-me: the user passes provider-owned gates, then FuseKit "
            "continues with verified setup."
        )
    if deterministic or implemented:
        return "Deterministic route selected for this setup step."
    return "FuseKit recorded the safest available route for this setup step."


_RUN_STATE_LABELS = {
    "app_repo_known": "App repo",
    "runner_selected": "Runner",
    "oci_ready": "OCI",
    "browser_ready": "Browser",
    "provider_sessions_known": "Provider gates",
    "vault_created": "Vault",
    "secrets_captured": "Secrets",
    "provider_checks_passed_or_pending_safe": "Provider checks",
    "receipt_written": "Receipt",
    "detonation_safe": "Detonation",
}

_RUN_STATE_DETAILS = {
    "app_repo_known": (
        "Source found. FuseKit knows what to launch.",
        "Waiting for a repo URL or local app source that the clean room can fetch.",
    ),
    "runner_selected": (
        "Execution lane selected.",
        "Choosing local, OCI Cloud Shell, or OCI VM based on available authorization.",
    ),
    "oci_ready": (
        "Clean-room runner is ready or not required.",
        "Waiting for OCI Cloud Shell, OCI VM provisioning, or a local-runner decision.",
    ),
    "browser_ready": (
        "Computer-use browser is ready.",
        "Waiting for the provider browser spine to open and report healthy state.",
    ),
    "provider_sessions_known": (
        "Provider gates are tracked.",
        "Waiting for provider login, MFA, consent, billing, or token gates to surface.",
    ),
    "vault_created": (
        "Encrypted vault exists.",
        "Creating the passphrase-protected vault before any secrets are captured.",
    ),
    "secrets_captured": (
        "Secrets are stored only in the vault.",
        "Waiting for approved tokens, keys, webhook secrets, or generated credentials.",
    ),
    "provider_checks_passed_or_pending_safe": (
        "Provider checks passed or are explicitly safe to wait on.",
        "Waiting for API, DNS, deploy, webhook, email, and live-app checks.",
    ),
    "receipt_written": (
        "Redacted receipt exists.",
        "Writing the audit-friendly receipt without raw secrets.",
    ),
    "detonation_safe": (
        "Preflight passed and detonation can run.",
        "Waiting for vault, audit, receipt, verification, rollback, and leak checks.",
    ),
}


def _render_run_state(state: Any) -> str:
    state = state if isinstance(state, dict) else {}
    cards = "\n".join(
        _render_run_state_card(field, bool(state.get(field, False)))
        for field in _RUN_STATE_LABELS
    )
    ready = bool(state.get("ready_to_detonate", False))
    missing = state.get("missing_for_detonation", [])
    if isinstance(missing, list) and missing:
        summary = f"{len(missing)} detonation preflight items pending"
    elif ready:
        summary = "detonation preflight is ready"
    else:
        summary = "launch contract is still filling in"
    return f"""
    <section class="run-state-panel" aria-label="Launch run-state contract">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Launch contract</span>
          <h2>What FuseKit knows</h2>
        </div>
        <span class="live-pill" data-run-state-overall>{html.escape(summary)}</span>
      </div>
      <div class="run-state-grid" data-run-state-checks>{cards}</div>
    </section>
"""


def _render_run_state_card(field: str, passed: bool) -> str:
    status = "passed" if passed else "pending"
    snow = "passed" if passed else "checking"
    label = _RUN_STATE_LABELS[field]
    ready_detail, pending_detail = _RUN_STATE_DETAILS[field]
    detail = ready_detail if passed else pending_detail
    return f"""
        <article class="trust-card {status}" data-run-state-field="{html.escape(field)}">
          <div class="trust-snow state-{snow}" aria-hidden="true"></div>
          <div>
            <span>{html.escape(status_label(status))}</span>
            <strong>{html.escape(label)}</strong>
            <p>{html.escape(detail)}</p>
            <em>{html.escape(field.replace('_', ' '))}</em>
          </div>
        </article>
"""


def _render_trust_card(check: dict[str, Any]) -> str:
    status = str(check.get("status", "pending"))
    snow = _trust_snow_state(status)
    title = f"{check.get('provider', 'provider')} · {check.get('check', 'check')}"
    summary, repair = _trust_card_copy(check)
    return f"""
        <article class="trust-card {html.escape(status)}">
          <div class="trust-snow state-{html.escape(snow)}" aria-hidden="true"></div>
          <div>
            <span>{html.escape(status_label(status))}</span>
            <strong>{html.escape(title.replace('_', ' '))}</strong>
            <p>{html.escape(summary)}</p>
            <em>{html.escape(repair)}</em>
          </div>
        </article>
"""


def _trust_card_copy(check: dict[str, Any]) -> tuple[str, str]:
    details = check.get("details", {})
    details = details if isinstance(details, dict) else {}
    reason = str(details.get("reason", "") or "")
    if (
        str(check.get("status", "")) == "pending"
        and bool(details.get("pending_safe", False))
        and "dns" in reason.lower()
        and "approval" in reason.lower()
    ):
        return (
            "DNS changes are waiting for approval or propagation.",
            "Approve/apply the exact DNS records in the setup plan; FuseKit will keep verifying.",
        )
    return (
        str(check.get("summary", "Verification is running.")),
        str(check.get("repair", "Keep the control room open.")),
    )


def _trust_snow_state(status: str) -> str:
    return {
        "passed": "passed",
        "pending": "checking",
        "repairing": "repairing",
        "failed": "failed",
        "needs_human_gate": "checking",
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
            <span>{html.escape(status_label(checkpoint.status))}</span>
            <strong>{html.escape(checkpoint.label)}</strong>
            <p>{html.escape(_public_copy(checkpoint.detail))}</p>
            <em>{html.escape(_public_copy(checkpoint.next_action))}</em>
            <code>{html.escape(_public_copy(checkpoint.resume_hint))}</code>
          </div>
        </article>
"""


def _headline(job: JobState) -> str:
    if job.status == "waiting":
        return "Waiting at a human gate"
    if job.status == "failed":
        return "Launch needs attention"
    if job.status == "done":
        return "Launch is complete"
    return "Launch in progress"


def _current_step(job: JobState, payload: dict[str, Any] | None = None) -> Any:
    payload = payload or {}
    if payload.get("gate_state_error"):
        return SimpleNamespace(
            id="gate.state.error",
            label="Gate state needs repair",
            status="failed",
            detail=str(payload["gate_state_error"]),
        )
    active_gate = _active_gate(payload)
    if active_gate:
        return _gate_step(active_gate)
    for status in ("failed", "waiting", "running"):
        for step in job.steps:
            if step.status == status:
                return step
    for step in job.steps:
        if step.status == "pending":
            return step
    return job.steps[-1] if job.steps else None


def _next_step(job: JobState, current: Any) -> JobStep | None:
    if current is None:
        return None
    seen_current = False
    for step in job.steps:
        if seen_current and step.status not in TERMINAL_STEP_STATUSES:
            return step
        if step.id == current.id:
            seen_current = True
    if not any(step.id == current.id for step in job.steps):
        for step in job.steps:
            if step.status not in TERMINAL_STEP_STATUSES:
                return step
    return None


def _focus_kicker(step: Any) -> str:
    if step is None:
        return "Current focus"
    if step.status == "waiting":
        return "Human gate"
    if step.status == "failed":
        return "Repair needed"
    if step.status == "running":
        return "Now running"
    return "Up next"


def _step_detail(step: Any) -> str:
    if step is None:
        return "FuseKit is preserving encrypted and redacted artifacts."
    return _public_copy(step.detail or "Queued and ready for the worker.")


def _render_gate_help(step: Any) -> str:
    if step is None:
        return ""
    status = str(getattr(step, "status", "") or "")
    retrying = _is_retrying_gate_step(step)
    if status != "waiting" and not retrying:
        return ""
    guidance = _guidance_for_step(step)
    if retrying:
        next_action = str(getattr(step, "next_action", "") or "").strip()
        resume_hint = str(getattr(step, "resume_hint", "") or "").strip()
        next_block = (
            "<div class=\"gate-next\">"
            f"<strong>Next</strong><p>{html.escape(_public_copy(next_action))}</p>"
            f"<em>{html.escape(_public_copy(resume_hint))}</em>"
            "</div>"
            if next_action or resume_hint
            else ""
        )
        classification = str(getattr(step, "classification", "") or "").replace("_", " ")
        classification_label = (
            f'<span class="gate-classification">{html.escape(classification)}</span>'
            if classification
            else ""
        )
        return f"""
        <div class="gate-help gate-rechecking">
          <span>FuseKit is rechecking now</span>{classification_label}
          <strong>{html.escape(str(getattr(step, "label", "") or guidance.title))}</strong>
          <p>{html.escape(_step_detail(step))}</p>
          <em>{html.escape(_public_copy(guidance.reassurance))}</em>
          {next_block}
        </div>
"""
    follow_steps = getattr(step, "follow_steps", None)
    actions_source = (
        follow_steps
        if isinstance(follow_steps, list) and follow_steps
        else guidance.actions
    )
    actions = "".join(f"<li>{html.escape(_public_copy(action))}</li>" for action in actions_source)
    resume_url = str(getattr(step, "resume_url", "") or "")
    gate_id = str(getattr(step, "id", "") or "")
    resume_link = (
        f'<button class="gate-link" type="button" data-gate-open="{html.escape(gate_id)}">'
        "Open provider gate in VM</button>"
        if resume_url and gate_id
        else ""
    )
    attempts = int(getattr(step, "attempts", 0) or 0)
    attempts_label = (
        f'<span class="gate-attempts">Resurfaced {attempts} '
        f'time{"" if attempts == 1 else "s"}</span>'
        if attempts
        else ""
    )
    meta = (
        f'<div class="gate-meta">{resume_link}{attempts_label}</div>'
        if resume_link or attempts_label
        else ""
    )
    classification = str(getattr(step, "classification", "") or "").replace("_", " ")
    classification_label = (
        f'<span class="gate-classification">{html.escape(classification)}</span>'
        if classification
        else ""
    )
    target = str(getattr(step, "target", "") or "")
    capture_targets = _capture_targets(target)
    captured_targets = tuple(
        str(item).strip().upper()
        for item in getattr(step, "captured_targets", ())
        if str(item).strip()
    )
    safe_target = _public_target(target)
    target_label = (
        '<p class="gate-target">Snowman highlighted: '
        f"<strong>{html.escape(safe_target)}</strong></p>"
        if target
        else ""
    )
    resume_button = (
        f'<button class="gate-done" type="button" data-gate-pass="{html.escape(gate_id)}">'
        f"{html.escape(_gate_done_label(step))}</button>"
        if gate_id and not capture_targets
        else ""
    )
    capture_buttons = _render_capture_buttons(gate_id, target, captured_targets)
    next_action = str(getattr(step, "next_action", "") or "").strip()
    resume_hint = str(getattr(step, "resume_hint", "") or "").strip()
    next_block = (
        "<div class=\"gate-next\">"
        f"<strong>Next</strong><p>{html.escape(_public_copy(next_action))}</p>"
        f"<em>{html.escape(_public_copy(resume_hint))}</em>"
        "</div>"
        if next_action or resume_hint
        else ""
    )
    success_criteria = getattr(step, "success_criteria", None)
    avoid_steps = getattr(step, "avoid_steps", None)
    criteria_block = _render_gate_criteria(
        guidance,
        success_criteria=success_criteria,
        avoid_steps=avoid_steps,
    )
    return f"""
        <div class="gate-help">
          <span>What you need to do</span>{classification_label}
          <strong>{html.escape(guidance.title)}</strong>
          <p>{html.escape(guidance.body)}</p>
          {target_label}
          {meta}
          <ol>{actions}</ol>
          {criteria_block}
          <em>{html.escape(guidance.reassurance)}</em>
          {next_block}
          {capture_buttons}
          {resume_button}
        </div>
"""


def _render_gate_criteria(
    guidance: GateGuidance,
    *,
    success_criteria: Any = None,
    avoid_steps: Any = None,
) -> str:
    blocks: list[str] = []
    success = _string_list(success_criteria) or list(guidance.success)
    avoid = _string_list(avoid_steps) or list(guidance.avoid)
    if success:
        rows = "".join(
            f"<li>{html.escape(_public_copy(item))}</li>"
            for item in success
            if str(item).strip()
        )
        if rows:
            blocks.append(
                '<div class="gate-criteria success"><strong>Success looks like</strong>'
                f"<ul>{rows}</ul></div>"
            )
    if avoid:
        rows = "".join(
            f"<li>{html.escape(_public_copy(item))}</li>"
            for item in avoid
            if str(item).strip()
        )
        if rows:
            blocks.append(
                '<div class="gate-criteria avoid"><strong>Avoid</strong>'
                f"<ul>{rows}</ul></div>"
            )
    if not blocks:
        return ""
    return f'<div class="gate-criteria-grid">{"".join(blocks)}</div>'


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value if str(item).strip()]


def _is_retrying_gate_step(step: Any) -> bool:
    return (
        str(getattr(step, "status", "") or "") == "running"
        and bool(str(getattr(step, "id", "") or ""))
        and bool(str(getattr(step, "provider", "") or ""))
        and (
            bool(str(getattr(step, "next_action", "") or ""))
            or bool(str(getattr(step, "resume_hint", "") or ""))
        )
    )


def _gate_done_label(step: Any) -> str:
    classification = str(getattr(step, "classification", "") or "").lower()
    provider = str(getattr(step, "provider", "") or "").lower()
    if classification == "dns-approval" or provider == "dns":
        return "Approve DNS apply"
    if classification == "setup-approval" or provider == "fusekit":
        return "Approve setup plan"
    return "I finished this step"


def _render_capture_buttons(
    gate_id: str,
    target: str,
    captured_targets: tuple[str, ...] = (),
) -> str:
    targets = _capture_targets(target)
    if not gate_id or not targets:
        return ""
    captured = set(captured_targets)
    buttons = "".join(_render_capture_button(gate_id, item, item in captured) for item in targets)
    captured_count = len([item for item in targets if item in captured])
    progress = (
        f"<span>{captured_count}/{len(targets)} captured</span>"
        if len(targets) > 1
        else ""
    )
    plural = "value" if len(targets) == 1 else "values"
    return f"""
      <div class="gate-capture-panel">
        <div class="gate-capture-head">
          <strong>Safe secret capture</strong>
          {progress}
        </div>
        <p>
          Copy the provider {plural} inside the VM browser, then click the matching
          Capture from VM clipboard button below.
          FuseKit reads only the VM clipboard and saves it directly into the encrypted vault.
        </p>
        <div class="gate-capture-row">{buttons}</div>
      </div>
    """


def _render_capture_button(gate_id: str, target: str, captured: bool) -> str:
    disabled = " disabled" if captured else ""
    label = f"Captured {target}" if captured else f"Capture {target} from VM clipboard"
    return (
        f'<button class="gate-capture" type="button" '
        f'data-gate-capture="{html.escape(gate_id)}" '
        f'data-gate-capture-target="{html.escape(target)}"{disabled}>'
        f"{html.escape(label)}</button>"
    )


def _capture_targets(target: str) -> tuple[str, ...]:
    return tuple(
        item
        for item in (part.strip().upper() for part in target.split(","))
        if item.isidentifier() and item == item.upper() and len(item) > 2 and "_" in item
    )


def _guidance_for_step(step: Any) -> GateGuidance:
    provider = str(getattr(step, "provider", "") or "").strip().lower()
    if not provider:
        provider = infer_gate_provider(f"{step.id} {step.label} {step.detail}")
    return provider_gate_guidance(provider)


def _active_gate(payload: dict[str, Any]) -> dict[str, Any] | None:
    gates = payload.get("gates", [])
    if not isinstance(gates, list):
        return None
    for gate in gates:
        if isinstance(gate, dict) and str(gate.get("status", "")) in {
            "waiting",
            "resurfaced",
            "resume_requested",
        }:
            return gate
    return None


def _gate_step(gate: dict[str, Any]) -> Any:
    provider = str(gate.get("provider", "") or "Provider")
    retrying = str(gate.get("status", "")) == "resume_requested"
    return SimpleNamespace(
        id=str(gate.get("id", "") or "provider.gate"),
        label=(
            f"{provider} gate is being rechecked"
            if retrying
            else f"{provider} needs your approval"
        ),
        status="running" if retrying else "waiting",
        detail=(
            _gate_retry_detail(gate)
            if retrying
            else str(gate.get("reason", "") or "A provider-created human gate is waiting.")
        ),
        provider=provider,
        resume_url=str(gate.get("resume_url", "") or ""),
        classification=str(gate.get("classification", "") or ""),
        target=str(gate.get("target", "") or ""),
        follow_steps=gate.get("follow_steps", []),
        next_action=str(gate.get("next_action", "") or ""),
        resume_hint=str(gate.get("resume_hint", "") or ""),
        attempts=int(gate.get("attempts", 0) or 0),
        captured_targets=gate.get("captured_targets", []),
    )


def _gate_retry_detail(gate: dict[str, Any]) -> str:
    next_action = str(gate.get("next_action", "") or "").strip()
    if next_action:
        return next_action
    classification = str(gate.get("classification", "") or "").lower()
    provider = str(gate.get("provider", "") or "").lower()
    if classification == "dns-approval" or provider == "dns":
        return "FuseKit is applying the approved DNS records now."
    if classification == "setup-approval" or provider == "fusekit":
        return "FuseKit is continuing with the approved setup plan now."
    return "You marked this step finished. FuseKit is retrying provider verification now."


def _url_with_query_param(url: str, key: str, value: str) -> str:
    if not url or not value:
        return url
    parts = urlsplit(url)
    query = [(item_key, item_value) for item_key, item_value in parse_qsl(parts.query)]
    query = [(item_key, item_value) for item_key, item_value in query if item_key != key]
    query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


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
