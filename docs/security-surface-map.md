# FuseKit Security Surface Map

This map tracks externally reachable routes, state-changing actions, and the controls
that prevent browser-origin CSRF, chained CSRF-to-command execution, and command
injection.

## HTTP Routes

FuseKit does not expose a general web app API. The only runtime HTTP server in the
Python package is the live control room in `fusekit.runner.control_room.server`.

| Route | Method | State | Protection |
| --- | --- | --- | --- |
| `/` | `GET` | Read-only control-room HTML. | Local-only bind by default. Remote bind requires `FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1` and a `secrets.token_urlsafe`-style `FUSEKIT_CONTROL_ROOM_TOKEN` with at least 32 URL-safe characters. `Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `form-action 'none'`. |
| `/index.html` | `GET` | Read-only control-room HTML. | Same as `/`. |
| `/api/job` | `GET` | Read-only redacted job payload. | Same as `/`. |
| `/api/gates/<gate_id>/pass` | `POST` | Marks one gate as `resume_requested` in `.fusekit/gates.json`; for setup-plan and DNS-approval gates this is the protected control-room approval signal consumed by the worker. | Requires `x-fusekit-control-room: resume`; rejects untrusted `Origin`; rejects browser-declared cross-site `Sec-Fetch-Site`; every state-changing POST must echo the page's per-control-room `x-fusekit-action-token`; remote access additionally requires token via bearer/query/cookie; no CORS headers are emitted; refuses secret-capture gates until every target is captured into the vault. |
| `/api/gates/<gate_id>/open` | `POST` | Opens the gate's provider URL in the shared VM browser and records debounce metadata. | Same POST protections as `/pass`; URL is read from the durable gate record and validated with `require_safe_url`; launches only executable Chrome/Chromium-family binaries through a fixed argv list, not caller-supplied commands; strips token/key/password/auth/session-style environment variables before spawning the browser; responses expose only the browser executable name, not runner filesystem paths; repeated opens are debounced. |
| `/api/gates/<gate_id>/capture-clipboard` | `POST` | Reads the VM clipboard for one approved capture target, writes it into the encrypted vault, and marks capture progress. | Same POST protections as `/pass`; request body must be bounded `application/json`; target must match the gate's env-style allowlist; clipboard value size/text is bounded; stale captures are rejected after the gate auto-resumes for verification; response includes only target/record metadata, never raw secret text. |

| Unknown routes | `GET`/`POST` | None. | Unknown GET returns `404` with zero-length body, the same no-store/CSP/frame/security headers as known routes, and no CORS allow headers. Unknown POST first passes the same control-room header, origin/fetch-site, action-token, and optional remote-token checks as state-changing POSTs, then returns the same zero-length `404`; attacker-origin or tokenless unknown POSTs fail before route handling. |
| Any route | `OPTIONS` | None. | Returns `405` with security headers and no CORS allow headers, so browser preflights for custom-header POSTs fail closed. |

The live VM browser iframe is not a general-purpose embed surface. Visual session
state is sanitized before the browser payload sees it: the noVNC URL must be
HTTP(S), credential-free, and end in `/vnc.html`; only expected noVNC query keys
are preserved; the live control-room link is kept only when it is HTTP(S),
credential-free, and on the same host as noVNC; unsafe visual passwords are dropped.

The control-room gate POST routes append redacted audit events for provider-gate
open, resume, and clipboard-capture actions. Audit payloads record gate/provider
metadata and counts, not provider URLs or clipboard values. The `/pass` route never
accepts arbitrary commands, resource identifiers, DNS record bodies, or raw approval
payloads from the browser; the worker interprets only the durable gate id/status
that FuseKit already created.

Gate target text is also display-redacted before it reaches the browser payload.
FuseKit preserves useful target shape such as domains, env names, and redacted query
keys, but token-like values, callback codes, API keys, and long opaque strings are
replaced with `[redacted]`.

There is no browser route that accepts a shell command, command arguments,
provider recipe name, vault path, user name, admin account request, raw secret
value, or arbitrary state mutation. Unknown GET/POST paths return `404`.

## State-Changing CLI and Provider Actions

These actions are not browser routes. They require local CLI execution, a remote runner
SSH session provisioned by FuseKit, or an encrypted vault/passphrase boundary.

| Surface | State changed | Guardrail |
| --- | --- | --- |
| `fusekit install` / provider pack synthesis | Writes manifests and provider-pack JSON. | Local filesystem only; generated packs are validated for HTTPS URLs, raw-secret absence, prohibited bypass language, and tool-permission bindings. |
| `fusekit unlock` / `fusekit request` | Opens encrypted vault or creates short-lived vault sessions. | Passphrase or short-lived session token required; session token is not persisted; session file is encrypted and owner-only. |
| `fusekit authorize` | Captures approved provider secrets into the encrypted vault. | Public guided runs use `Capture from VM clipboard` buttons for approved env targets; CLI-only fallback can use a non-echoing prompt or env handoff. Raw secrets are redacted from output, logs, receipts, and control-room payloads. |
| `fusekit apply` / `fusekit launch --runner local` | Runs provider setup recipes, writes receipts, audit logs, verification report, rollback metadata. | Provider strategy must select a deterministic API/CLI/browser/vault-capture lane; missing provider auth becomes a human gate; DNS apply requires explicit `approve_dns`. |
| Provider account creation | Creates or selects an account/project with an external provider. | Capability packs declare `api`, `supervised`, or `none`; API mode requires a matching setup recipe; current public catalog packs are supervised gates because signup usually involves provider-owned email, MFA, CAPTCHA, billing, identity, fraud, or consent checks. |
| GitHub provider recipes | Deploy keys and repo secrets. | Requires provider token in vault/env; values are sent through provider API primitives and redacted from artifacts. |
| Vercel provider recipes | Project, env vars, deployment. | Requires provider token; env replacement creates before deleting old values unless repair requires replacement. |
| Cloudflare provider recipes | DNS proposal/apply/verify. | Proposal is safe by default; apply requires explicit DNS approval scope; rollback metadata is written. |
| `fusekit rollback --execute` | Provider-native delete/revoke/restore actions from receipt metadata. | Requires vault/provider token and receipt-derived action metadata. |
| `fusekit detonate` / remote detonation | Deletes worker/tmp state, browser/visual/OpenClaw scratch state, FuseKit-controlled transient logs, uploaded app archives, passphrase files, and remote OCI resources. | Detonation preflight requires encrypted/redacted survivor artifacts, safe verification report, and rollback metadata before trusting cleanup; live acceptance now rejects leftover plaintext worker, browser, visual, provider-auth, or gateway/control-room scratch. |
| OCI remote launch | Creates disposable VM/networking, uploads app archive/vault, runs remote FuseKit, retrieves artifacts. | x86_64-only shapes; app upload excludes secret paths; SSH uses generated keys; passphrase is stdin/file-scoped; remote artifacts are validated before detonation. |

## Command Injection Boundaries

- Local OpenClaw/browser commands use `subprocess.run([...])` argv lists.
- The live control-room provider-gate launcher accepts only executable
  Chrome/Chromium-family browser binaries and sanitizes the X display value before
  passing it through the `DISPLAY` environment; provider/API/token/passphrase-style
  environment variables are removed from the spawned browser environment.
- OpenClaw installer execution uses argv form, not `bash -lc`, so `FUSEKIT_HOME` and
  `FUSEKIT_OPENCLAW_VERSION` are not shell-interpreted.
- Cloud Shell bootstrap is a generated shell script, but all external launch arguments,
  app source values, package refs, runner modes, and forwarded options are quoted with
  `shlex.quote`.
- Remote SSH commands are fixed templates. User/launch arguments forwarded into remote
  `fusekit launch` are quoted with `shlex.quote` before entering the remote shell.
- Remote visual/control-room tokens are generated with `secrets.token_urlsafe` and quoted
  before entering remote shell snippets.
- Live control-room refresh avoids duplicating the noVNC password into extra frontend
  dataset state; the visual credential is used only for the iframe autoconnect URL and
  explicit copy affordance.
- Visual-session state is normalized before rendering so a corrupted `visual.json`
  cannot turn the control room into a clipboard-enabled arbitrary iframe.
- Source archive extraction validates paths and single-root layout before replacing the
  destination; remote artifact extraction validates target paths and does not use
  `tar.extractall`.

## Browser Attack Model

A malicious website should not be able to use the user's browser to mutate FuseKit state
or trigger commands:

- Simple HTML forms cannot set `x-fusekit-control-room`, so gate POSTs fail.
- JavaScript `fetch` with that custom header triggers CORS preflight; FuseKit returns
  `405` and emits no `Access-Control-Allow-Origin`,
  `Access-Control-Allow-Methods`, or `Access-Control-Allow-Headers` headers.
- Clipboard-capture POSTs additionally require a bounded `application/json` object,
  so form/plaintext bodies are rejected before any vault or gate mutation.
- Setup-plan and DNS approvals use the same protected `/pass` route as other gates:
  the browser can only request resume for a pre-existing FuseKit gate id, while the
  CLI worker owns the setup plan and DNS record content it will apply.
- If a browser sends `Origin`, it must match the control-room host and be loopback for
  local untokened control rooms.
- If a browser sends `Sec-Fetch-Site: cross-site`, FuseKit rejects the state-changing
  POST even when other headers are present.
- Local and remote state-changing POSTs require the explicit
  `x-fusekit-action-token` header from the live control-room page instead of
  accepting cookie-authenticated or loopback POSTs alone.
- Rejected state-changing POST responses keep `Cache-Control: no-store`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSP frame/form
  restrictions, and no CORS allow headers.
- The per-control-room action token is stored owner-only; existing valid token
  files have their permissions repaired before reuse.
- Tokenized remote control rooms still reject attacker-origin gate POSTs before
  mutating gate state.
- Remote control rooms reject weak or non-URL-safe tokens at startup and require
  a `secrets.token_urlsafe`-style token with at least 32 URL-safe characters;
  token cookies are emitted only for token-url-safe values and are `HttpOnly`
  and `SameSite=Strict`.
- Browser GETs that authenticate with `?token=` set the control-room cookie and
  redirect back to the same route without the token query parameter so the token
  does not stay in the address bar for recordings, screenshots, or browser history.
- The browser client does not reuse the remote access token as the
  `x-fusekit-action-token`; state-changing requests use only the owner-only action
  token embedded in the served control-room payload.
- Acceptance ledger snapshots apply both structured secret-key redaction and
  public token-shape/path redaction before writing proof artifacts.
- The control room never exposes a route that executes arbitrary shell commands.

## Current Residual Risk

Live provider setup still depends on supervised provider gates and real provider APIs.
FuseKit can guide and verify those paths, but it must not bypass MFA, CAPTCHA, billing,
identity, fraud, consent, or provider authorization screens.
