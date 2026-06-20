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
| `/api/gates/<gate_id>/pass` | `POST` | State-changing: marks an active gate as `resume_requested` in `.fusekit/gates.json`; for setup-plan and DNS-approval gates this is the protected control-room approval signal consumed by the worker. | Requires `x-fusekit-control-room: resume`; rejects untrusted `Origin`; rejects browser-declared cross-site or same-site `Sec-Fetch-Site`; every state-changing POST must echo the page's per-control-room `x-fusekit-action-token`; remote access additionally requires token via bearer/query/cookie; no CORS headers are emitted; accepts no request body, so the browser can only ask FuseKit to resume a pre-existing durable gate id; refuses secret-capture gates until every target is captured into the vault; stale `passed` or already `resume_requested` gates acknowledge current state without mutating gates, appending audit, or minting wake proof. |
| `/api/gates/<gate_id>/open` | `POST` | State-changing: opens an active gate's provider URL in the shared VM browser and records debounce metadata. | Same POST protections as `/pass`; accepts no request body and reads the provider URL only from the durable gate record; stale `passed` or already `resume_requested` gates acknowledge current state without launching Chrome, mutating gates, or appending open-audit proof; URL is validated with `require_safe_url`, including rejection of local/private network targets by default; launches only executable Chrome/Chromium-family binaries through a fixed argv list, not caller-supplied commands; strips token/key/password/auth/session-style environment variables before spawning the browser; provider browser profiles must live under FuseKit-owned visual state (`.fusekit`/app visual state for local control rooms or `/var/lib/fusekit-runner/visual` for OCI) so detonation can remove auth/profile state; responses expose only the browser executable name, not runner filesystem paths; repeated active opens are debounced. |
| `/api/gates/<gate_id>/capture-clipboard` | `POST` | State-changing: reads the VM clipboard for one approved capture target, writes it into the encrypted vault, and marks capture progress. | Same POST protections as `/pass`; request body must be bounded `application/json`; target must match the gate's env-style allowlist; clipboard value size/text is bounded; stale captures are rejected after the gate auto-resumes for verification; duplicate captures for a target already stored in the encrypted vault acknowledge current state without rereading the VM clipboard or rewriting vault records, and if every required value is already captured but resume proof is missing they mint only the missing resume wake/audit proof; response includes only target/record metadata, never raw secret text. |

| Unknown routes | `GET`/`POST`/`OPTIONS` | None. | Unknown GET returns `404` with zero-length body, the same no-store/CSP/frame/security headers as known routes, and no CORS allow headers. Unknown POST first passes the same control-room header, origin/fetch-site, action-token, and optional remote-token checks as state-changing POSTs, then returns the same zero-length `404`; attacker-origin or tokenless unknown POSTs fail before route handling. |
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
Live acceptance validates both the raw JSONL rows and the central Run Record
`wake_events` summary against the generated wake-event field set, so extra
sidecar metadata or padded event names cannot become durable human-gate proof.
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
after the disposable OCI worker is gone. Audit-log event names are public-redacted
before becoming central audit entries, so malformed or stale `audit.jsonl` events
cannot preserve callback URLs or token-shaped text in Run Record `action` or
`summary` fields.
The raw audit survivor is also checked directly before live acceptance treats it
as public proof: `audit.jsonl` must parse as JSONL object rows, each row must use
the generated top-level fields (`event`, optional `data`, optional `ts`) with a
trimmed event name, and every row must be free of credential-looking text and
unredacted callback URLs. This keeps the redacted audit log requirement from
being satisfied by a present but poisoned or sidecar-shaped log.

Durable gate display text is also display-redacted before it reaches the browser
payload. FuseKit preserves useful shape such as gate ids, provider names, statuses,
env targets, and the Open/Capture controls, but token-like values, callback codes,
API keys, long opaque strings, and sensitive query values in reasons, resume URLs,
follow steps, criteria, next actions, and hints are replaced with `[redacted]`.
The central Run Record applies a stricter gate-ingest redaction before writing
`provider_gates.records`: provider and callback URLs are replaced with
`[redacted-url]`, token-shaped guidance is scrubbed, and only non-secret proof shape
such as gate ids, provider names, statuses, env targets, wake ids, and timestamps
survives for post-detonation review. Even structural gate and wake-event fields
such as ids, provider names, classifications, targets, and approval summaries pass
through public redaction before they enter the central proof object. Live
acceptance requires approval summaries to be shaped, tied to a durable gate, and
anchored to a matching `resume_requested` wake event when they claim the protected
control-room approval path was used.

Acceptance reports are treated as public proof input, not trusted UI data. The
control-room reader reshapes `.fusekit/acceptance/report.json` before embedding it
in static HTML or returning `/api/job`: launch flags are strict booleans, blockers,
checks, missing proof, errors, and recording-contract text pass through public-text
redaction, artifact paths are public-path normalized, and unexpected fields are
dropped.
The Run Record also public-redacts the embedded acceptance summary before writing
`acceptance.blockers` or `acceptance.error`, so stale report text cannot preserve
callback URLs or token-shaped blockers inside the central proof object.
Embedded acceptance readiness also carries `remote_artifacts_ready`, and
recordability is recomputed from live public launch proof, retrieved survivor
artifacts, and recording-contract proof instead of trusting a sidecar ready flag.
Run Records are also redacted at the control-room reader boundary before they enter
static HTML or `/api/job`; stale or hand-edited statement, error, blocker, path, or
extra-field strings cannot carry token-shaped material into the browser payload.
Frontend public-copy rendering repeats the token-shaped redaction as a last-line
display guard for refreshed cards and action-status text.
Live acceptance applies the same rule to the central Run Record itself: any
credential-looking string or unredacted provider callback URL anywhere in
`run_record.json` fails public launch proof, even when the callback URL does not
carry an obvious token query string.
The central Run Record stores its base `app_path` as a public label, not a host or
VM absolute path, and live acceptance rejects absolute app-path values before
public launch proof can pass.
Embedded launch run-state proof is public-redacted before it is written to
`run_record.json`, so stale or hand-edited `run_state.json` notes cannot preserve
callback URLs, token-shaped text, or unsafe operational details in the central
proof object.
Vault metadata is sanitized before the Run Record writes credential-capture proof:
raw value-style fields such as `value`, passphrase, password, private-key, and
token-value entries are dropped recursively, and remaining metadata is
public-redacted. Live acceptance enforces the same field denylist against
hand-edited or stale Run Records, so the central record can prove which
credential records exist without becoming a second vault.
Vault acceptance treats the encrypted bundle itself as a boundary proof: the
bundle must contain no plaintext or credential-looking markers, must unlock with
the supplied passphrase, and must reject a deliberately wrong passphrase. Corrupt
or modified bundles become redacted `vault.unlock` failures instead of crashing
acceptance.
Verifier reports and provider strategy/playbook artifacts use the same public-payload
redaction at read time. The browser keeps structural provider, check, route, control,
and recipe identifiers, while repair text, summaries, reasons, next actions, proof
strings, callback URLs, path-like fields, and unexpected secret-shaped fields are
redacted before display.
Base job state, run-state notes, standalone model/inference contracts, and artifact
paths are also context-redacted before browser delivery. Structural launch ids and
the per-page action token are preserved so live controls still work, but step details,
checkpoint copy, notes, contract descriptions, and artifact paths cannot expose
token-shaped material or local workspace paths.
Remote artifact inventory treats selected non-secret durable survivors as public
proof inputs too. Before a retrieved OCI bundle can satisfy
`remote_artifacts.loaded`, every required survivor must be a regular retrieved
file, not merely an existing path or directory. Acceptance then parses
`job.json`, `run_state.json`, `checkpoints.json`, and
`worker_replacement_drill.json` and rejects callback URLs or credential-looking
text in those standalone files. This keeps resume state, checkpoint recovery copy,
and replacement proof from relying on browser payload redaction or Run Record
embedding to hide unsafe survivor text. The same inventory gate rejects sidecar
or padded `job.json` and generated
`checkpoints.json` fields before remote resume proof can support launch
readiness. Raw `run_state.json` must also use the generated launch-state contract:
literal boolean readiness flags, numeric timestamps, trimmed notes and
`missing_for_detonation` rows, and no sidecar run-state fields. The Run Record
`state` proof is validated against the same contract before live acceptance or
cleanup preflight trusts it, so a central proof object cannot preserve looser
run-state metadata than the standalone survivor. The Run Record top-level
envelope must also match the writer-owned field set with non-negative created/updated
timestamps before either gate trusts it, preventing sidecar proof fields from
surviving as launch metadata. Cleanup preflight also rejects hollow generated
proof sections, so empty `{}`/`[]` placeholders for vault, provider route,
runner, worker-replacement, verifier, evidence, artifact, rehearsal, or
automation-boundary proof cannot stand in for real central evidence. Raw
`worker_replacement_drill.json` must also use the generated replacement-drill
shape: passed status, exact fields, literal boolean drill flags, trimmed and
duplicate-free restored source ids, no host-machine state, no VM-local plaintext
reuse, and no sidecar drill notes before retrieved artifacts can support public
recording readiness.
Run Record artifact paths are serialized as public labels, and
`fusekit.evidence-inventory.v1` includes only files that resolve inside the
`.fusekit` artifact root. Outside worker or host files can be marked as existing
artifacts without leaking absolute paths, but they cannot become public evidence
for detonation review. Live acceptance also validates `artifacts[]` rows directly:
each row must have a public-safe name, a relative non-traversing public path without
credential query text, and a boolean existence flag, so stale or hand-edited
artifact lists cannot smuggle absolute paths or anonymous proof rows into launch
review.
Run Record counters are also validated as real JSON numbers, not booleans: live
acceptance rejects `true`/`false` values in gate totals, wake-event counts,
evidence counts, human-action/rehearsal counts, automation-boundary counts,
verifier counts, and audit counts before they can satisfy public launch proof.
Embedded Run Record provider-strategy and provider-playbook proof is also
public-redacted before `provider_strategies`, `provider_playbook`, or
`automation_boundary` are written. Provider, recipe, route, status, and selected
candidate shape is preserved for acceptance drift checks, while callback URLs,
token-like repair reasons, and unsafe instruction strings are removed from the
central proof object. Live acceptance also rejects unredacted callback URLs in
the standalone `provider_strategies.json` artifact before route or playbook
signature comparison.
Provider capability-pack acceptance has a matching public-proof layer after
schema validation: per-provider pack snapshots reject credential-looking text or
unredacted callback URLs, and `provider_packs.validated` fails if any required
provider pack fails. Ordinary provider token, project, signup, and documentation
URLs remain allowed; provider callback return URLs do not become launch proof.
Raw durable gate and wake-event survivors are guarded separately from their
browser and Run Record redacted views: live acceptance rejects credential-looking
text or unredacted callback URLs in `gates.json` and in each `gate_events.jsonl`
row before gate resolution, intervention audit proof, or wake-event signature
comparison can pass. Live acceptance also requires raw gate and gate-event rows to
use the generated provider-gate and wake-event field sets, so sidecar control
proof cannot pass launch readiness before cleanup rejects it. Ordinary provider
setup/review URLs remain allowed; provider callback return URLs do not survive as
public launch proof.
Embedded verification reports get the same Run Record treatment: provider, check,
status, and pending-safe shape is preserved for verifier drift checks, while
callback URLs, token-shaped repair details, and unsafe verifier messages are
removed before `verification` or `verifiers` reach the public record. The
standalone `verification_report.json` artifact is checked for unredacted callback
URLs before provider-check signature comparison.
Central Run Record drift checks also require any present standalone comparison
artifact to be a readable regular JSON object before comparing signatures; a
directory, unreadable file, or malformed JSON placeholder named like verifier,
provider-strategy, detonation, readiness, or LLM-contract proof fails the central
record instead of being treated as an absent optional comparison.
Rollback metadata is also treated as public survivor proof: live acceptance rejects
unredacted callback URLs in `rollback_plan.json` before rollback actions or
provider coverage can satisfy launch readiness.
Setup receipt proof is public-redacted before receipt-derived Run Record audit
entries are written, and live acceptance rejects standalone `setup_receipt.json`
survivors containing credential-looking text or unredacted callback URLs. Receipt
action indexes, categories, providers, and high-level statuses remain reviewable
without preserving callback URLs, token-shaped action text, or unsafe provider
details as central audit proof.
Embedded `llm_contract` proof is public-redacted before `llm_contract` or
`model_inference` are written to the Run Record, and live acceptance rejects a
standalone `llm_contract.json` survivor if it contains credential-looking text or
an unredacted callback URL. This keeps the model/inference lane reviewable while
preventing raw LLM keys, callback URLs, or token-shaped recovery copy from
surviving as launch proof. The Run Record contract must also carry shaped auth
lanes with ids, labels, boolean availability/action flags, public-safe
descriptions, and a `default_lane` that matches one of those lanes;
`model_inference.lane_count` must match the embedded contract so launch readiness
cannot be satisfied by a hollow model status.
Embedded workspace detonation receipts are public-redacted before
`detonation.workspace_receipt` is written, and live acceptance rejects standalone
`workspace_detonation.json` survivors containing credential-looking text or
unredacted callback URLs. This keeps OCI no-trace cleanup proof comparable while
preventing callback URLs, token-shaped cleanup reasons, or unsafe resource-summary
text from becoming public launch proof. Live acceptance also requires the
generated receipt, resource-summary, and remote-worker cleanup fields exactly,
with trimmed public text and no sidecar cleanup notes.
Worker-replacement drill proof is recursively public-redacted before the Run
Record embeds it, and the replacement proof contract requires `restored_from` to
match the durable replacement source ids exactly. Extra restored source labels are
not allowed to stand in for the encrypted vault, Run Record, gate events, runner
readiness, or other declared survivor artifacts.
Detonation preflight applies the same public-survivor rule before worker cleanup
is trusted: the encrypted vault must not contain plaintext or credential-looking
markers, and the central Run Record, `audit.jsonl`, setup receipt, verification
report, rollback metadata, standalone `llm_contract.json`, and optional
worker-replacement drill must not contain credential-looking text or unredacted
callback URLs. Required public JSON survivors must also parse as readable JSON
objects with labeled artifact failures, and the audit log must parse as non-empty
JSONL object rows. This keeps no-trace cleanup from destroying the worker while stale
standalone proof still depends on later browser or acceptance redaction.
Runner-readiness proof stays exact in `runner_readiness.json`, but the central Run
Record uses public labels for the shared provider-browser profile, Playwright
browser cache, and installed binary paths. Live acceptance normalizes both shapes
before comparing them and snapshots the same public summary, so the Run Record
and acceptance ledger can prove VM/browser readiness without publishing VM-local
path layouts. Live acceptance also treats `runner_readiness.json` as a standalone
survivor: credential-looking text or unredacted callback URLs block
`runner_readiness.prepared` before the x86/browser capability contract can support
launch readiness. The shared runner-readiness validator also rejects sidecar
fields and padded generated strings across the readiness envelope, profile
contract, browser stack, observed facts, health checks, and installed-binary rows.
Visual-session proof keeps a specialized transport boundary: `novnc_url` and
`control_room_url` must satisfy the safe public-VM URL rules before they can be
embedded, control-room URL tokens are redacted from snapshots, and callback-shaped
visual URLs are rejected. Raw `visual.json` launch proof must also match the
generated noVNC artifact envelope, including exact fields, trimmed public
strings, the expected display, and generated guidance notes; stale sidecar
metadata, paths, provider return details, or drifted notes cannot support
`visual_state.safe`.
Browser-visible JSON action responses use the same context-aware public redaction
before they are written to the socket, so protected POST responses preserve gate
ids, statuses, capture targets, and wake metadata while redacting token-shaped gate
hints, provider error text, callback URLs, and path-like details.

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
| `fusekit detonate` / remote detonation | Deletes worker/tmp state, browser/visual/OpenClaw scratch state, FuseKit-controlled transient logs, uploaded app archives, passphrase files, and remote OCI resources. | Detonation preflight requires encrypted/redacted survivor artifacts, the central Run Record, safe verification report, rollback metadata, matching `model_inference`/`llm_contract` proof, and generated `visual.json` noVNC/control-room proof before trusting cleanup; workspace detonation receipts must prove the remote worker, OCI VM, provider-observed boot volume deletion, ephemeral public IP release, and every standard FuseKit-created network resource class were deleted or name the missing classes; remote-worker proof must include the targeted VM process patterns, disposable paths, and `host_machine_state_required=false`; live acceptance rejects leftover plaintext worker, browser, visual, provider-auth, or gateway/control-room scratch. |
| OCI remote launch | Creates disposable VM/networking, uploads app archive/vault, runs remote FuseKit, retrieves artifacts. | x86_64-only shapes; app upload excludes secret paths; SSH uses generated keys; passphrase is stdin/file-scoped; remote artifacts, including the durable run state and Run Record, are validated before detonation. |

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
  disconnected provider browser profile. Valid noVNC/control-room fields are preserved
  for the live VM iframe, while extra visual metadata is public-redacted and
  path-normalized before browser delivery.
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
- Pass and open POSTs accept no request body; their only mutable input is the
  already-created durable gate id in the route.
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
