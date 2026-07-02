"""Universal hosted launcher contract and trust-first HTML rendering."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any

from fusekit.hosted.lanes import hosted_launch_lanes
from fusekit.manifest import SetupManifest
from fusekit.planner import SetupAction, build_plan

HOSTED_LAUNCHER_SCHEMA_VERSION = "fusekit.hosted-launcher.v1"
TRUST_CONTRACT_SCHEMA_VERSION = "fusekit.hosted-trust-contract.v1"

TRUST_STORY = (
    "open core",
    "narrow permissions",
    "visible plan",
    "redacted proof",
    "reversible setup",
)

NO_TERMINAL_PROMISE = (
    "No terminal, local install, download, or copied command is required in the hosted path."
)

HOSTED_LAUNCH_PATH = (
    "Visit the hosted FuseKit URL.",
    "Install the FuseKit GitHub App on one selected repository.",
    "Review the visible plan and approved action ids before worker start.",
    "Click Start hosted launch and pass only provider-owned human gates.",
    "Receive the live URL, redacted proof receipt, rollback metadata, and detonation receipt.",
)
HOSTED_PLAIN_LANGUAGE_JOURNEY = (
    "Open fusekit.snowmanai.org in a browser.",
    "Click Start hosted launch.",
    "Sign in to GitHub if asked and choose exactly one repository.",
    "Review the setup plan FuseKit shows before provider changes.",
    "Click Start hosted launch in the control room.",
    "Complete only the provider-owned screens FuseKit highlights.",
    "Review the live URL, redacted proof, rollback metadata, and detonation receipt.",
)
HOSTED_PROOF_REQUIREMENTS = (
    "Live URL verification",
    "Provider verifier results",
    "DNS propagation status",
    "Redacted setup receipt",
    "Redacted audit log",
    "Run Record",
    "Detonation receipt",
    "Live acceptance report",
    "Recording proof",
)
HOSTED_COMPLETION_EVIDENCE_KEYS = (
    "live_url",
    "provider_verifiers",
    "dns_propagation",
    "rollback_metadata",
    "retrieved_remote_artifacts",
    "run_record",
    "detonation_receipt",
    "live_acceptance_report",
    "recording",
)
HOSTED_REVERSAL_PATH = (
    "Show rollback metadata before risky changes.",
    "Preserve rollback actions for provider resources FuseKit creates.",
    "Offer stop, revoke access, rollback, and download redacted proof actions.",
)
HOSTED_PROHIBITED_ACTIONS = (
    "Do not bypass MFA, CAPTCHA, passkeys, billing, fraud, consent, or domain gates.",
    "Do not render or return raw provider credentials, installation tokens, or vault secrets.",
    "Do not mutate DNS or paid provider resources without explicit visible approval.",
    (
        "Do not claim completion before live acceptance, retrieved artifacts, "
        "and detonation proof pass."
    ),
)


@dataclass(frozen=True)
class HostedLaunchTrustContract:
    """Public trust contract shown before a hosted launch starts."""

    scope: tuple[str, ...]
    permissions: tuple[str, ...]
    secret_boundary: str
    launch_path: tuple[str, ...]
    plain_language_journey: tuple[str, ...]
    proof: tuple[str, ...]
    proof_evidence_keys: tuple[str, ...]
    rollback: tuple[str, ...]
    prohibited: tuple[str, ...]
    user_gates: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the public trust contract."""

        return {
            "schema_version": TRUST_CONTRACT_SCHEMA_VERSION,
            "story": list(TRUST_STORY),
            "no_terminal_promise": NO_TERMINAL_PROMISE,
            "scope": list(self.scope),
            "permissions": list(self.permissions),
            "secret_boundary": self.secret_boundary,
            "launch_path": list(self.launch_path),
            "plain_language_journey": list(self.plain_language_journey),
            "proof": list(self.proof),
            "proof_evidence_keys": list(self.proof_evidence_keys),
            "rollback": list(self.rollback),
            "prohibited": list(self.prohibited),
            "user_gates": list(self.user_gates),
        }


@dataclass(frozen=True)
class HostedLaunchPlan:
    """Universal hosted-launch preview for a GitHub app repo."""

    app_name: str
    github_source: str
    providers: tuple[str, ...]
    required_env: tuple[str, ...]
    actions: tuple[SetupAction, ...]
    trust: HostedLaunchTrustContract

    def to_dict(self) -> dict[str, object]:
        """Serialize the hosted launch preview."""

        return {
            "schema_version": HOSTED_LAUNCHER_SCHEMA_VERSION,
            "app_name": self.app_name,
            "github_source": self.github_source,
            "intake": "github-app",
            "providers": list(self.providers),
            "required_env": list(self.required_env),
            "actions": [
                {
                    "id": action.id,
                    "kind": action.kind,
                    "provider": action.provider,
                    "summary": action.summary,
                    "risk": action.risk,
                }
                for action in self.actions
            ],
            "trust": self.trust.to_dict(),
        }


def build_hosted_launch_plan(
    manifest: SetupManifest,
    *,
    github_source: str,
) -> HostedLaunchPlan:
    """Build the non-secret hosted launch plan shown before provider gates."""

    plan = build_plan(manifest)
    providers = _provider_names(manifest)
    user_gate_providers = _user_gate_providers(plan.actions)
    trust = HostedLaunchTrustContract(
        scope=(
            f"Scan and launch the selected GitHub repository: {github_source}",
            "Create or update only resources named in the visible launch plan.",
            "Use provider-native APIs, CLIs, or human gates according to the route plan.",
            "Detonate disposable worker, browser, auth, log, and plaintext setup state.",
        ),
        permissions=_permission_summary(providers),
        secret_boundary=(
            "Provider credentials are captured only into the encrypted FuseKit vault. "
            "Raw secrets are never rendered in the hosted page, proof, receipts, logs, "
            "or generated apps except for app-scoped runtime values the provider requires."
        ),
        launch_path=HOSTED_LAUNCH_PATH,
        plain_language_journey=HOSTED_PLAIN_LANGUAGE_JOURNEY,
        proof=HOSTED_PROOF_REQUIREMENTS,
        proof_evidence_keys=HOSTED_COMPLETION_EVIDENCE_KEYS,
        rollback=HOSTED_REVERSAL_PATH,
        prohibited=HOSTED_PROHIBITED_ACTIONS,
        user_gates=tuple(
            f"{provider}: login, MFA, CAPTCHA, billing, consent, or copy-once secret screens"
            for provider in user_gate_providers
        )
        or ("Provider-owned login, MFA, billing, consent, and copy-once secret gates",),
    )
    return HostedLaunchPlan(
        app_name=manifest.app_name,
        github_source=github_source,
        providers=providers,
        required_env=tuple(sorted(manifest.required_env)),
        actions=plan.actions,
        trust=trust,
    )


def render_hosted_launcher(
    plan: HostedLaunchPlan,
    *,
    launch_url: str = "",
    launch_urls: dict[str, str] | None = None,
    lane_readiness: dict[str, object] | None = None,
) -> str:
    """Render a no-terminal hosted launcher page for a universal GitHub app."""

    payload = json.dumps(plan.to_dict(), sort_keys=True)
    providers = _list_markup(plan.providers)
    env_names = _list_markup(plan.required_env or ("No app env vars detected yet",))
    actions = "\n".join(_action_card(action) for action in plan.actions)
    trust = plan.trust
    proof = _list_markup(trust.proof)
    rollback = _list_markup(trust.rollback)
    prohibited = _list_markup(trust.prohibited)
    user_gates = _list_markup(trust.user_gates)
    scope = _list_markup(trust.scope)
    permissions = _list_markup(trust.permissions)
    launch_path = _ordered_list_markup(trust.launch_path)
    plain_language_journey = _ordered_list_markup(trust.plain_language_journey)
    story = " / ".join(TRUST_STORY)
    title = html.escape(f"Launch {plan.app_name} with FuseKit")
    source = html.escape(plan.github_source)
    app_name = html.escape(plan.app_name)
    start_control = _lane_controls(
        launch_url=launch_url,
        launch_urls=launch_urls or {},
        lane_readiness=lane_readiness or {},
    )
    secret_boundary = html.escape(trust.secret_boundary)
    no_terminal = html.escape(NO_TERMINAL_PROMISE)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #52616f;
      --line: #cfd9e2;
      --blue: #0077cc;
      --green: #167a4a;
      --amber: #8a5a00;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
    }}
    main {{
      width: min(1180px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 28px 0 44px;
      display: grid;
      gap: 18px;
    }}
    header {{
      border-bottom: 2px solid var(--ink);
      padding-bottom: 20px;
      display: grid;
      gap: 12px;
    }}
    .eyebrow {{
      font-size: 12px;
      font-weight: 850;
      text-transform: uppercase;
      color: var(--blue);
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{
      font-size: clamp(36px, 5vw, 64px);
      line-height: 1;
      letter-spacing: 0;
      max-width: 860px;
    }}
    .lede {{
      max-width: 790px;
      color: #31465c;
      font-size: 17px;
      line-height: 1.45;
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }}
    .lanes {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      width: 100%;
    }}
    .lane {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      display: grid;
      gap: 8px;
      background: white;
    }}
    .lane p {{
      color: var(--muted);
      line-height: 1.4;
    }}
    button,
    .button {{
      min-height: 44px;
      border-radius: 6px;
      border: 1px solid var(--blue);
      background: var(--blue);
      color: white;
      padding: 0 16px;
      font-weight: 850;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
    }}
    button.secondary,
    .button.secondary {{
      background: white;
      color: var(--blue);
    }}
    .button.disabled {{
      background: #d8e1ea;
      border-color: #aebcca;
      color: #52616f;
      cursor: not-allowed;
    }}
    .grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 18px;
      align-items: start;
    }}
    section, aside {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 14px;
    }}
    .compact-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      min-height: 84px;
    }}
    .metric strong {{
      display: block;
      font-size: 22px;
      line-height: 1.1;
    }}
    .metric span {{
      color: var(--muted);
      font-size: 13px;
    }}
    ul {{
      margin: 0;
      padding-left: 20px;
      color: #2e4256;
    }}
    li + li {{ margin-top: 6px; }}
    .action-list {{
      display: grid;
      gap: 8px;
    }}
    .action-card {{
      border: 1px solid var(--line);
      border-left: 4px solid var(--green);
      border-radius: 6px;
      padding: 10px 12px;
      display: grid;
      gap: 4px;
    }}
    .action-card.user_required,
    .action-card.approval_required {{
      border-left-color: var(--amber);
    }}
    .action-card small {{
      color: var(--muted);
    }}
    .trust-band {{
      border-color: rgba(0, 119, 204, 0.35);
      background: #eef8ff;
    }}
    .source {{
      overflow-wrap: anywhere;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
    }}
    script[type="application/json"] {{ display: none; }}
    @media (max-width: 880px) {{
      .grid, .compact-grid, .lanes {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">SnowmanAI / FuseKit hosted launcher</div>
      <h1>Launch any GitHub app with a supervised setup worker.</h1>
      <p class="lede">
        {app_name} is ready for a visible launch plan. FuseKit uses {html.escape(story)}
        so a nontechnical user can click once, approve provider-owned gates, and receive
        live proof without running commands.
      </p>
      <p class="source">{source}</p>
      <div class="actions">
        {start_control}
        <a class="button secondary" href="#narrow-permissions">Preview permissions</a>
      </div>
      <p class="lede">{no_terminal}</p>
    </header>
    <section class="trust-band" aria-label="Trust contract">
      <h2>Trust contract</h2>
      <p>{secret_boundary}</p>
      <div class="compact-grid">
        <div class="metric">
          <strong>{len(plan.providers)}</strong><span>providers detected</span>
        </div>
        <div class="metric">
          <strong>{len(plan.actions)}</strong><span>planned setup steps</span>
        </div>
        <div class="metric">
          <strong>{len(plan.required_env)}</strong><span>runtime env labels</span>
        </div>
      </div>
    </section>
    <div class="grid">
      <section aria-label="Visible launch plan">
        <h2>Visible plan</h2>
        <div class="action-list">{actions}</div>
      </section>
      <aside aria-label="Trust details">
        <h2 id="narrow-permissions">Narrow permissions</h2>
        {permissions}
        <h2>Launch path</h2>
        {launch_path}
        <h2>Plain-language click path</h2>
        {plain_language_journey}
        <h2>Scope</h2>
        {scope}
        <h2>Provider gates</h2>
        {user_gates}
        <h2>Redacted proof</h2>
        {proof}
        <h2>Reversible setup</h2>
        {rollback}
        <h2>What FuseKit will not do</h2>
        {prohibited}
        <h2>Providers</h2>
        {providers}
        <h2>Runtime env labels</h2>
        {env_names}
      </aside>
    </div>
    <script id="fusekit-hosted-launch-plan" type="application/json">{html.escape(payload)}</script>
  </main>
</body>
</html>
"""


def _lane_controls(
    *,
    launch_url: str,
    launch_urls: dict[str, str],
    lane_readiness: dict[str, object],
) -> str:
    if launch_urls:
        rows = "\n".join(
            _lane_control(
                lane.lane_id,
                launch_urls.get(lane.lane_id, ""),
                lane_readiness=lane_readiness,
            )
            for lane in hosted_launch_lanes()
        )
        return f"""
        <div class="lanes" aria-label="Launch lanes">
          {rows}
        </div>
"""
    if launch_url:
        return (
            f'<a class="button" href="{html.escape(launch_url, quote=True)}">'
            "Start hosted launch</a>"
        )
    return '<span class="button disabled" aria-disabled="true">Start hosted launch</span>'


def _lane_control(
    lane_id: str,
    launch_url: str,
    *,
    lane_readiness: dict[str, object],
) -> str:
    lane = next(lane for lane in hosted_launch_lanes() if lane.lane_id == lane_id)
    label = html.escape(lane.label)
    summary = html.escape(lane.summary)
    ready = _lane_is_launchable(lane_readiness, lane_id)
    next_actions = _lane_next_actions(lane_readiness, lane_id)
    if launch_url and ready:
        button = (
            f'<a class="button" href="{html.escape(launch_url, quote=True)}">'
            f"{label}</a>"
        )
    else:
        button = '<span class="button disabled" aria-disabled="true">Unavailable</span>'
    details = ""
    if next_actions:
        details = f"<p>{html.escape(next_actions[0])}</p>"
    return f"""
          <article class="lane">
            <h3>{label}</h3>
            <p>{summary}</p>
            {details}
            {button}
          </article>
"""


def _lane_is_launchable(lane_readiness: dict[str, object], lane_id: str) -> bool:
    if not lane_readiness:
        return True
    lanes = lane_readiness.get("lanes")
    if not isinstance(lanes, dict):
        return False
    lane = lanes.get(lane_id)
    return isinstance(lane, dict) and lane.get("launchable") is True


def _lane_next_actions(lane_readiness: dict[str, object], lane_id: str) -> list[str]:
    lanes = lane_readiness.get("lanes")
    if not isinstance(lanes, dict):
        return []
    lane = lanes.get(lane_id)
    if not isinstance(lane, dict):
        return []
    actions = lane.get("next_actions")
    if not isinstance(actions, list):
        return []
    return [action for action in actions if isinstance(action, str) and action]


def _provider_names(manifest: SetupManifest) -> tuple[str, ...]:
    names = {service.provider.lower() for service in manifest.services}
    names.update(domain.provider.lower() for domain in manifest.domains)
    if manifest.webhooks:
        names.add("webhooks")
    return tuple(sorted(names))


def _user_gate_providers(actions: tuple[SetupAction, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                action.provider
                for action in actions
                if action.kind in {"user_required", "approval_required"}
                and action.provider != "fusekit"
            }
        )
    )


def _permission_summary(providers: tuple[str, ...]) -> tuple[str, ...]:
    items = [
        "GitHub App installation scoped to one selected repository with contents:read.",
        (
            "GitHub write changes, such as deploy keys or repository secrets, require "
            "a separate visible approval/provider route before mutation."
        ),
    ]
    if "vercel" in providers:
        items.append("Vercel project/env/deploy access for the selected app.")
    if "cloudflare" in providers or "dns" in providers:
        items.append("DNS write access only for proposed records after explicit approval.")
    if "resend" in providers:
        items.append("Resend domain/audience/email setup through provider APIs after key capture.")
    known = {"github", "vercel", "cloudflare", "dns", "resend"}
    if any(provider not in known for provider in providers):
        items.append("Additional providers are routed through validated capability packs.")
    return tuple(items)


def _list_markup(items: tuple[str, ...]) -> str:
    rows = "\n".join(f"<li>{html.escape(item)}</li>" for item in items)
    return f"<ul>{rows}</ul>"


def _ordered_list_markup(items: tuple[str, ...]) -> str:
    rows = "\n".join(f"<li>{html.escape(item)}</li>" for item in items)
    return f"<ol>{rows}</ol>"


def _action_card(action: SetupAction) -> str:
    return (
        f'<article class="action-card {html.escape(action.kind)}">'
        f"<h3>{html.escape(action.summary)}</h3>"
        f"<small>{html.escape(action.provider)} / {html.escape(action.kind)} / "
        f"risk: {html.escape(action.risk)}</small>"
        "</article>"
    )


def public_plan_summary(plan: HostedLaunchPlan) -> dict[str, Any]:
    """Return the small public summary a hosted API can expose."""

    return {
        "schema_version": HOSTED_LAUNCHER_SCHEMA_VERSION,
        "app_name": plan.app_name,
        "github_source": plan.github_source,
        "providers": list(plan.providers),
        "action_count": len(plan.actions),
        "trust_story": list(TRUST_STORY),
        "no_terminal": True,
        "launch_path": list(plan.trust.launch_path),
        "plain_language_journey": list(plan.trust.plain_language_journey),
        "proof": list(plan.trust.proof),
        "rollback": list(plan.trust.rollback),
        "prohibited": list(plan.trust.prohibited),
    }
