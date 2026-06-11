# FuseKit North-Star Provider Strategy

FuseKit's user promise is a universal magic lane: the user should not need to
understand provider APIs, deploy keys, env vars, DNS, billing gates, OAuth
scopes, or token storage. FuseKit should guide the human through provider-owned
gates, capture only approved capabilities into the encrypted vault, then use the
fastest reliable deterministic route to finish setup.

Real-run friction is tracked in
[`docs/magic-path-friction-log.md`](magic-path-friction-log.md). A launcher flow
is not launch-ready until observed user interventions are either automated,
converted into explicit control-room gates, or kept as open acceptance items.

## Principle

FuseKit does not prefer APIs for their own sake. FuseKit prefers the most
reliable proven path for the current account, provider, goal, and runner.

The preferred order is:

1. Provider-native API when authorization and scopes are proven.
2. Official provider CLI when it is installed, authenticated, and more reliable
   for the specific goal.
3. Guided provider browser when the provider requires login, MFA, CAPTCHA,
   consent, billing, token creation, or account setup.
4. Human follow-me when the safest path is to tell the user exactly where to
   click until the provider-owned gate is complete.

The browser remains a first-class strategy. It should be the concierge for
human/provider gates, not the only source of truth for setup success.

## Background Agent Contract

FuseKit's durable implementation model is a governed background agent running
inside a prepared, disposable cloud workstation. The user should be able to
start the lane, pass provider-owned trust gates, and then watch or resume the
same run without managing shells, local browser profiles, provider docs, or
manual cleanup.

The contract is:

- Prepared runner profile first: x86_64, supported browser dependencies,
  OpenClaw or the approved browser spine, Playwright smoke test, noVNC, shared
  provider browser profile, helper binaries, and vault access must be verified
  before provider gates appear.
- Deterministic scripts first, guided browser second: use provider APIs or
  official CLIs when they are proven healthy; use browser automation and
  human follow-me only for provider-owned login, MFA, CAPTCHA, consent,
  billing, or copy-once-token gates.
- One observable control room: status timeline, route plan, current blocker,
  VM browser, exact Capture controls, approvals, audit state, and recovery
  hints must all live in the launcher/control room.
- Event-sourced run journal: every provider open, Capture, approval, retry,
  generated provider value, DNS proposal/apply, verification result, rollback
  action, and detonation step is recorded as redacted evidence for resume and
  acceptance.
- Policy boundaries by default: provider secrets stay in the encrypted vault or
  provider-native secret stores, state-changing browser actions require
  control-room CSRF/action-token proof, provider navigation stays in the VM
  browser, and plaintext worker/browser/auth scratch is detonated after proof is
  preserved.
- Human gates are real gates only: FuseKit must not ask the user to interpret
  provider order of operations, choose scopes from memory, paste host-side
  commands, compare DNS records, or debug runner setup during the public path.

## Strategy Graph

Every provider-pack setup recipe gets a strategy decision:

- `api`: deterministic provider API/SDK route.
- `official_cli`: deterministic provider CLI route.
- `browser_guided`: OpenClaw/Playwright-guided provider surface.
- `human_follow_me`: exact human instructions and highlighted gates.
- `local_vault`: deterministic local vault capture for already-approved values.

Account creation is also explicit pack metadata:

- `api`: only when the pack declares a matching setup recipe and FuseKit has a
  real executor for it.
- `supervised`: provider signup/account selection is a first-class human gate.
- `none`: FuseKit must block and explain why account creation is unavailable.

Each decision records:

- selected route
- considered candidates
- whether the route is deterministic
- whether FuseKit can execute it in the current runner
- evidence such as token availability, CLI availability, and handoff URL
- next action when the selected route requires a human gate

## Runtime Flow

1. Scan the app and synthesize or load provider packs.
2. For each setup goal, evaluate route health:
   - token/capability exists in encrypted vault or environment
   - official CLI exists and is usable
   - provider handoff URL exists
   - browser/visual runner is available
   - human gate policy allows waiting
3. Execute deterministic API/local routes immediately.
4. If deterministic routes are blocked, surface a provider gate with clear
   follow-me instructions.
5. After the human approves or creates the needed capability, capture it into
   the vault.
6. Re-run strategy selection and execute deterministic setup.
7. Verify through provider APIs, DNS checks, and live HTTP checks.
8. Pull only encrypted/redacted artifacts.
9. Detonate plaintext worker, browser, and provider auth state.

## Provider Pack Maintenance

Provider relationships should be maintained centrally, not by end users.
FuseKit core should stay stable while provider packs can update independently.

The durable path is:

- versioned provider packs
- signed provider-pack registry
- pack provenance and tool permissions
- contract tests for each provider strategy
- live health checks before selecting a route
- fallback strategy graph when a provider API, CLI, or UI route changes

Provider pack updates must be signed and auditable. FuseKit should never execute
untrusted live code from arbitrary provider docs or pages.

Current public catalog packs declare account creation as `supervised`. That is
intentional: many providers require email, MFA, CAPTCHA, billing, identity, or
consent gates before issuing app capabilities. FuseKit can guide those gates and
capture approved outputs, but it must not promise fake automatic account
creation unless a provider-supported API route is implemented and tested.

## OCI Acceptance

OCI is required for public-lane acceptance, but not for every local code change.
Local tests prove strategy selection, receipts, redaction, and fallback logic.
OCI acceptance proves:

- x86_64 runner boots with the golden or bootstrapped toolchain
- OpenClaw/Playwright/noVNC visual surface works
- strategy decisions survive remote execution
- provider gates are visible and interactive
- deterministic setup resumes after vault capture
- artifacts exclude visual secrets and plaintext provider state
- detonation removes app, visual, browser, gateway, and auth scratch state

## Current Implementation Slice

The first north-star slice adds `fusekit.providers.strategy` and wires strategy
decisions into provider-pack setup execution. Existing API handlers still perform
the deterministic work. Missing authorization now becomes an explicit
`needs_human_gate` strategy result with next-action guidance rather than a
thin missing-token failure. API-backed provider routes also run a read-only
contract-health check before provider mutations; failed health checks become a
guided token-refresh/capture gate, and live acceptance requires the receipt to
prove health succeeded before setup. The control room renders a provider Route
plan from strategy evidence so users see Resend domain setup, DNS approval,
Vercel env wiring, and token-capture gates in the intended order.
Those provider route decisions are also persisted into durable checkpoint
resume records, so a refreshed or resumed launcher keeps the same no-thinking
next action instead of falling back to generic setup-worker guidance.

Next slices:

1. Promote the OCI runner into a verified prepared-environment profile: x86_64,
   supported Ubuntu image, FuseKit runner helpers, OpenClaw/browser spine,
   Playwright Chromium smoke test, noVNC, and shared Chrome provider profile
   must pass before provider gates are shown.
2. Add official CLI executors for providers where CLI is more reliable.
3. Add signed remote provider-pack registry support.
4. Run a real OCI provider acceptance using GitHub, Vercel, Cloudflare, and a
   disposable domain.
