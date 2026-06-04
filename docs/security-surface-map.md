# FuseKit Security Surface Map

This map tracks externally reachable routes, state-changing actions, and the controls
that prevent browser-origin CSRF, chained CSRF-to-command execution, and command
injection.

## HTTP Routes

FuseKit does not expose a general web app API. The only runtime HTTP server in the
Python package is the live control room in `fusekit.runner.control_room.server`.

| Route | Method | State | Protection |
| --- | --- | --- | --- |
| `/` | `GET` | Read-only control-room HTML. | Local-only bind by default. Remote bind requires `FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1` and `FUSEKIT_CONTROL_ROOM_TOKEN`. `Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `form-action 'none'`. |
| `/index.html` | `GET` | Read-only control-room HTML. | Same as `/`. |
| `/api/job` | `GET` | Read-only redacted job payload. | Same as `/`. |
| `/api/gates/<gate_id>/pass` | `POST` | Marks one human gate as passed in `.fusekit/gates.json`. | Requires `x-fusekit-control-room: resume`; rejects untrusted `Origin`; rejects browser-declared cross-site `Sec-Fetch-Site`; remote access requires token via bearer/query/cookie; no CORS headers are emitted. |
| Any route | `OPTIONS` | None. | Returns `405` with security headers and no CORS allow headers, so browser preflights for custom-header POSTs fail closed. |

## State-Changing CLI and Provider Actions

These actions are not browser routes. They require local CLI execution, a remote runner
SSH session provisioned by FuseKit, or an encrypted vault/passphrase boundary.

| Surface | State changed | Guardrail |
| --- | --- | --- |
| `fusekit install` / provider pack synthesis | Writes manifests and provider-pack JSON. | Local filesystem only; generated packs are validated for HTTPS URLs, raw-secret absence, prohibited bypass language, and tool-permission bindings. |
| `fusekit unlock` / `fusekit request` | Opens encrypted vault or creates short-lived vault sessions. | Passphrase or short-lived session token required; session token is not persisted; session file is encrypted and owner-only. |
| `fusekit authorize` | Captures approved provider secrets into the encrypted vault. | Uses hidden prompts/env handoff; raw secrets are redacted from output, logs, receipts, and control-room payloads. |
| `fusekit apply` / `fusekit launch --runner local` | Runs provider setup recipes, writes receipts, audit logs, verification report, rollback metadata. | Provider strategy must select a deterministic API/CLI/browser/vault-capture lane; missing provider auth becomes a human gate; DNS apply requires explicit `approve_dns`. |
| GitHub provider recipes | Deploy keys and repo secrets. | Requires provider token in vault/env; values are sent through provider API primitives and redacted from artifacts. |
| Vercel provider recipes | Project, env vars, deployment. | Requires provider token; env replacement creates before deleting old values unless repair requires replacement. |
| Cloudflare provider recipes | DNS proposal/apply/verify. | Proposal is safe by default; apply requires explicit DNS approval scope; rollback metadata is written. |
| `fusekit rollback --execute` | Provider-native delete/revoke/restore actions from receipt metadata. | Requires vault/provider token and receipt-derived action metadata. |
| `fusekit detonate` / remote detonation | Deletes worker/tmp state and remote OCI resources. | Detonation preflight requires encrypted/redacted survivor artifacts, safe verification report, and rollback metadata before trusting cleanup. |
| OCI remote launch | Creates disposable VM/networking, uploads app archive/vault, runs remote FuseKit, retrieves artifacts. | x86_64-only shapes; app upload excludes secret paths; SSH uses generated keys; passphrase is stdin/file-scoped; remote artifacts are validated before detonation. |

## Command Injection Boundaries

- Local OpenClaw/browser commands use `subprocess.run([...])` argv lists.
- OpenClaw installer execution uses argv form, not `bash -lc`, so `FUSEKIT_HOME` and
  `FUSEKIT_OPENCLAW_VERSION` are not shell-interpreted.
- Cloud Shell bootstrap is a generated shell script, but all external launch arguments,
  app source values, package refs, runner modes, and forwarded options are quoted with
  `shlex.quote`.
- Remote SSH commands are fixed templates. User/launch arguments forwarded into remote
  `fusekit launch` are quoted with `shlex.quote` before entering the remote shell.
- Remote visual/control-room tokens are generated with `secrets.token_urlsafe` and quoted
  before entering remote shell snippets.
- Source archive extraction validates paths and single-root layout before replacing the
  destination; remote artifact extraction validates target paths and does not use
  `tar.extractall`.

## Browser Attack Model

A malicious website should not be able to use the user's browser to mutate FuseKit state
or trigger commands:

- Simple HTML forms cannot set `x-fusekit-control-room`, so gate POSTs fail.
- JavaScript `fetch` with that custom header triggers CORS preflight; FuseKit returns
  `405` without CORS allow headers.
- If a browser sends `Origin`, it must match the control-room host and be loopback for
  local untokened control rooms.
- If a browser sends `Sec-Fetch-Site: cross-site`, FuseKit rejects the state-changing
  POST even when other headers are present.
- Remote control rooms require an unguessable token; token cookies are `HttpOnly` and
  `SameSite=Lax`.
- The control room never exposes a route that executes arbitrary shell commands.

## Current Residual Risk

Live provider setup still depends on supervised provider gates and real provider APIs.
FuseKit can guide and verify those paths, but it must not bypass MFA, CAPTCHA, billing,
identity, fraud, consent, or provider authorization screens.
