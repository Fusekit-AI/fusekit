# FuseKit Security Surface Map

This map tracks externally reachable routes, state-changing actions, and the controls
that prevent browser-origin CSRF, chained CSRF-to-command execution, and command
injection.

## HTTP Routes

FuseKit does not expose a general web app API. The only runtime HTTP server in the
Python package is the live control room in `fusekit.runner.control_room.server`.
The server owns the code-backed route inventory in `CONTROL_ROOM_ROUTE_SURFACE`;
this document must stay in lockstep with that constant so new browser-reachable
routes cannot appear without an explicit state-change and protection classification.

| Route | Method | State | Protection |
| --- | --- | --- | --- |
| `/` | `GET` | Read-only control-room HTML. | Local-only bind by default. Remote bind requires `FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1` and a `secrets.token_urlsafe`-style `FUSEKIT_CONTROL_ROOM_TOKEN` with at least 32 URL-safe characters. `Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `form-action 'none'`, `object-src 'none'`; generated control-room CSS/JS use per-response nonces instead of broad `unsafe-inline`, with inline style/script attributes disabled; `Permissions-Policy` disables camera, microphone, geolocation, payment, USB/HID/serial/Bluetooth, and motion sensors. |
| `/index.html` | `GET` | Read-only control-room HTML. | Same as `/`. |
| `/api/job` | `GET` | Read-only redacted job payload. | Same as `/`. |
| `/api/gates/<gate_id>/pass` | `POST` | Marks an active gate as `resume_requested` in `.fusekit/gates.json`; for setup-plan and DNS-approval gates this is the protected control-room approval signal consumed by the worker. | Requires `x-fusekit-control-room: resume`; rejects untrusted `Origin`; rejects browser-declared cross-site or same-site `Sec-Fetch-Site`; every state-changing POST must echo the page's per-control-room `x-fusekit-action-token`; remote access additionally requires token via bearer/query/cookie; no CORS headers are emitted; refuses secret-capture gates until every target is captured into the vault; stale `passed` or already `resume_requested` gates acknowledge current state without mutating gates, appending audit, or minting wake proof. |
| `/api/gates/<gate_id>/open` | `POST` | Opens an active gate's provider URL in the shared VM browser and records debounce metadata. | Same POST protections as `/pass`; stale `passed` or already `resume_requested` gates acknowledge current state without launching Chrome, mutating gates, or appending open-audit proof; URL is read from the durable gate record and validated with `require_safe_url`, including rejection of local/private network targets by default; launches only executable Chrome/Chromium-family binaries through a fixed argv list, not caller-supplied commands; strips token/key/password/auth/session-style environment variables before spawning the browser; responses expose only the browser executable name, not runner filesystem paths; repeated active opens are debounced. |
| `/api/gates/<gate_id>/capture-clipboard` | `POST` | Reads the VM clipboard for one approved capture target, writes it into the encrypted vault, and marks capture progress. | Same POST protections as `/pass`; request body must be bounded `application/json`; target must match the gate's env-style allowlist; clipboard value size/text is bounded; stale captures are rejected after the gate auto-resumes for verification; duplicate captures for a target already stored in the encrypted vault acknowledge current state without rereading the VM clipboard, rewriting vault records, appending audit, or minting wake proof; response includes only target/record metadata, never raw secret text. |

| Unknown routes | `GET`/`POST` | None. | Unknown GET returns `404` with zero-length body, the same no-store/CSP/frame/security headers as known routes, and no CORS allow headers. Unknown POST first passes the same control-room header, origin/fetch-site, action-token, and optional remote-token checks as state-changing POSTs, then returns the same zero-length `404`; attacker-origin or tokenless unknown POSTs fail before route handling. |
| Any route | `OPTIONS` | None. | Returns `405` with security headers and no CORS allow headers, so browser preflights for custom-header POSTs fail closed. |

The route inventory uses these protection class labels:

- `local-or-remote-token` for read-only routes that are local-only by default and
  require the generated remote token when the control room is remotely bound.
- `control-room-header-origin-fetch-site-action-token` for every state-changing
  gate POST, meaning the request must carry the explicit control-room header,
  same-origin/loopback `Origin`, non-cross-site/non-same-site `Sec-Fetch-Site`, and the
  owner-only per-page action token.
- `security-headers-no-cors-posts-auth-before-404` for unknown routes, meaning
  security headers and no CORS allow headers are emitted, and unknown POSTs must
  satisfy auth/CSRF checks before returning `404`.

The live VM browser iframe is not a general-purpose embed surface. Visual session
state is sanitized before the browser payload sees it: the noVNC URL must be
HTTP(S), credential-free, hosted on a public IP VM, and end in `/vnc.html`; only
expected noVNC query keys and generated values are preserved; the live
control-room link is kept only when it is HTTP(S), credential-free, hosted on
the same public IP as noVNC, and
not a hostname, loopback, or private-network target; tokenized control-room links
keep a `token` query only when it has the same 32+ URL-safe shape required by the
remote server, and public snapshots redact the token value; unsafe visual
passwords are dropped; provider browser profile metadata is preserved only when it
matches the FuseKit-owned shared Chrome provider profile used by the VM gate opener.

The control-room gate POST routes append redacted audit events for provider-gate
open, resume, and clipboard-capture actions. Audit payloads record gate/provider
metadata and counts, not provider URLs or clipboard values. The `/pass` route never
accepts arbitrary commands, resource identifiers, DNS record bodies, or raw approval
payloads from the browser; the worker interprets only the durable gate id/status
that FuseKit already created.

Gate capture and resume actions also append redacted `.fusekit/gate_events.jsonl`
wake events. These events prove that a human approval or VM-clipboard capture
occurred and can wake retry/resume logic after an OCI worker is killed or
recreated. They store gate ids, provider names, statuses, and env-target labels,
but never raw clipboard values, provider tokens, URLs, or command payloads.
Control-room capture and resume audit entries include the corresponding wake
event id, and live acceptance requires that id to exist in `gate_events.jsonl`
before the action counts as proof. This prevents a standalone `I finished this
step` audit line from looking like a durable, resumable run after the VM is
detonated.
The central Run Record carries those same non-secret wake event ids on audit
trail entries derived from gate events, so post-detonation review does not need
plaintext browser state or raw log reconstruction to prove which protected
action woke the worker.
The Run Record retains the full redacted audit trail instead of truncating it,
so repeated retries, provider gates, captures, and approvals remain auditable
after the disposable OCI worker is gone.

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
| `fusekit install` / provider pack synthesis | Writes manifests and provider-pack JSON. | Local filesystem only; generated packs are validated for HTTPS URLs, raw-secret absence, prohibited bypass language, local/host browser-tab side channels, and tool-permission bindings. |
| `fusekit unlock` / `fusekit request` | Opens encrypted vault or creates short-lived vault sessions. | Passphrase or short-lived session token required; session token is not persisted; session file is encrypted and owner-only. |
| `fusekit authorize` | Captures approved provider secrets into the encrypted vault. | Public guided runs use exact env-target buttons such as `Capture RESEND_API_KEY from VM clipboard`; durable gates and provider strategies must not ship placeholder `Capture <TARGET> from VM clipboard` copy when the env target is known. CLI-only fallback can use a non-echoing prompt or env handoff. Raw secrets are redacted from output, logs, receipts, and control-room payloads. |
| `fusekit apply` / `fusekit launch --runner local` | Runs provider setup recipes, writes receipts, audit logs, verification report, rollback metadata. | Provider strategy must select a deterministic API/CLI/browser/vault-capture lane; missing provider auth becomes a human gate; public control-room DNS apply requires a protected `Approve DNS apply` gate, while advanced/CI runs may use explicit upfront `approve_dns` scope. |
| Provider account creation | Creates or selects an account/project with an external provider. | Capability packs declare `api`, `supervised`, or `none`; API mode requires a matching setup recipe; current public catalog packs are supervised gates because signup usually involves provider-owned email, MFA, CAPTCHA, billing, identity, fraud, or consent checks. |
| GitHub provider recipes | Deploy keys and repo secrets. | Requires provider token in vault/env; values are sent through provider API primitives and redacted from artifacts. |
| Vercel provider recipes | Project, env vars, deployment. | Requires provider token; env replacement creates before deleting old values unless repair requires replacement. |
| Cloudflare provider recipes | DNS proposal/apply/verify. | Proposal is safe by default; public apply requires protected per-domain launcher approval and advanced/CI apply requires explicit DNS approval scope; rollback metadata is written. |
| `fusekit rollback --execute` | Provider-native delete/revoke/restore actions from receipt metadata. | Requires vault/provider token and receipt-derived action metadata. |
| `fusekit detonate` / remote detonation | Deletes worker/tmp state, browser/visual/OpenClaw scratch state, FuseKit-controlled transient logs, uploaded app archives, passphrase files, and remote OCI resources. | Detonation preflight requires encrypted/redacted survivor artifacts, safe verification report, and rollback metadata before trusting cleanup; workspace detonation receipts must prove the remote worker, OCI VM, and every standard FuseKit-created network resource class were deleted or name the missing classes; remote-worker proof must include the targeted VM process patterns, disposable paths, and `host_machine_state_required=false`; live acceptance rejects leftover plaintext worker, browser, visual, provider-auth, or gateway/control-room scratch. |
| OCI remote launch | Creates disposable VM/networking, uploads app archive/vault, runs remote FuseKit, retrieves artifacts. | x86_64-only shapes; app upload excludes secret paths; SSH uses generated keys; passphrase is stdin/file-scoped; remote artifacts are validated before detonation. |

## Command Injection Boundaries

- Local OpenClaw/browser commands use `subprocess.run([...])` argv lists.
- The live control-room provider-gate launcher accepts only executable
  Chrome/Chromium-family browser binaries and rejects local/private network gate
  URLs before launch. It sanitizes the X display value before passing it through
  the `DISPLAY` environment; provider/API/token/passphrase-style environment
  variables are removed from the spawned browser environment.
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
  cannot turn the control room into a clipboard-enabled arbitrary iframe or claim a
  disconnected provider browser profile.
- Source archive extraction validates paths, single-root layout, and normal-file
  zip metadata before replacing the destination; symlink, device, FIFO/socket,
  absolute, and backslash entries are rejected. Remote artifact extraction
  validates target paths and does not use `tar.extractall`.

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
- Browser metadata is treated as a browser-origin guard, not as a local automation
  requirement: if a request sends `Origin`, it must match the control-room host and
  be loopback for local untokened control rooms; if it sends
  `Sec-Fetch-Site: cross-site` or `same-site`, FuseKit rejects the state-changing
  POST even when other headers are present. Requests without browser metadata still
  require the control-room header and owner-only action token, preserving deterministic
  runner/local automation without widening the browser CSRF surface.
- Local and remote state-changing POSTs require the explicit
  `x-fusekit-action-token` header from the live control-room page instead of
  accepting cookie-authenticated or loopback POSTs alone.
- Rejected state-changing POST responses keep `Cache-Control: no-store`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSP frame/form
  restrictions, restrictive `Permissions-Policy`, and no CORS allow headers.
- Served live control-room pages use per-response CSP nonces for the generated
  stylesheet, bootstrap JSON, and event script, with inline style/script
  attributes disabled.
- The per-control-room action token is stored owner-only; existing valid token
  files have their permissions repaired before reuse.
- Tokenized remote control rooms still reject attacker-origin gate POSTs before
  mutating gate state.
- Remote control rooms reject weak or non-URL-safe tokens at startup and require
  a `secrets.token_urlsafe`-style token with at least 32 URL-safe characters;
  token cookies are emitted only for token-url-safe values and are `HttpOnly`
  and `SameSite=Strict` with an eight-hour `Max-Age`, so recording/session
  convenience does not create an unbounded browser credential.
- Malformed token cookie headers are treated as absent credentials, returning a
  normal invalid-token response instead of raising out of the request handler.
- Browser GETs that authenticate with `?token=` set the control-room cookie and
  redirect back to the same route without the token query parameter so the token
  does not stay in the address bar for recordings, screenshots, or browser history.
- State-changing POSTs reject `?token=` authentication in the URL. Remote POSTs
  must use the cleaned control-room cookie or bearer token plus the per-page
  action token, keeping remote credentials out of mutable action URLs.
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
