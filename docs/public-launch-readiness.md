# Public Launch Readiness

FuseKit should launch publicly only when the first acceptance path is narrow,
real, and provable.

## Launch Claim

AI can write the app. FuseKit makes it real.

The public walkthrough should show one generated app moving from code-only to
live connected services:

- app repo scanned
- setup plan generated
- provider authorization gates opened through the computer-use spine
- GitHub, Resend, Vercel, and DNS configured in dependency order
- secrets sealed in the encrypted vault
- live URL verified
- redacted receipts and audit ledger written
- plaintext worker state detonated

## Harness Gate

Before publishing a public walkthrough, run:

```zsh
fusekit acceptance run /path/to/generated-app \
  --mode live \
  --vault /path/to/generated-app/.fusekit/fusekit.vault.json \
  --passphrase-file /path/to/pass.txt
```

The run is launch-ready only when `.fusekit/acceptance/report.json` contains:

```json
{
  "blockers": [],
  "launch_ready": true,
  "mode": "live",
  "public_launch_ready": true,
  "recording_proof_ready": true,
  "recording_ready": true
}
```

`launch_ready: true` in rehearsal mode only means the local product invariants
passed. A public walkthrough is ready to record only when live mode also writes
`public_launch_ready: true`, `recording_proof_ready: true`, and
`recording_ready: true`.

Live mode does not claim provider success without proof. It requires the real encrypted vault,
passphrase unlock proof, redacted setup receipt, redacted audit log, live URL in
the receipt, validated provider packs, complete provider route decisions, clean
leak scan, resolved durable gate state, and detonated worker state. Complete
route decisions include the selected route kind, status, deterministic/implemented
flags, reason, and considered candidates, so the control room can explain whether
FuseKit used API automation, secure vault capture, or VM follow-me. When both
the prepared runner profile and provider gates are present, the run must prove
the disposable background workstation was ready before the first provider gate:
x86_64 architecture, approved browser spine, Playwright smoke test, noVNC,
shared provider browser profile, helper binaries, and vault access. The run
journal must also show the control-room path for provider opens, Capture clicks,
setup/DNS approvals, retries, generated provider values, verification, rollback,
and detonation, with raw secrets and provider callback tokens redacted. When both
provider route decisions and launch checkpoints are present, the checkpoint
recovery map must preserve the same provider-route next actions so refreshed
launcher sessions do not regress to generic setup guidance. When both
provider route decisions and setup receipts claim an API route succeeded, the
receipt must also prove that the provider's read-only contract-health check
succeeded before the provider setup action, so stale, revoked, or mis-scoped
tokens are routed back through guided capture before mutations. When both
Resend and DNS are present, the provider strategy artifact must prove Resend ran
before Cloudflare/DNS so Resend-generated domain records are included in the
approved DNS changes. The setup receipt must independently prove the same flow:
`resend.domain` succeeds first, returns DNS records, and a later `dns.propose`
action contains those exact Resend records. When the app deploys through Vercel
and declares `RESEND_*` runtime variables, the receipt must also prove that
`vercel.env` configured each required Resend runtime key. Any durable human gate
recorded during the run must include follow-me steps, a plain next action, and a
resume hint, plus matching redacted control-room audit proof, even if the gate
later passed. Human-gate guidance must be launcher-actionable: provider gates
must carry an openable provider URL for `Open provider gate in VM`, provider gates
with URLs must send the user through the VM browser path, copy-once env/token
targets must name exact controls such as `Capture RESEND_API_KEY from VM clipboard`,
and public proof must reject hidden-prompt, side-channel, manual, placeholder, or
figure-it-out wording. Non-secret provider
gates plus setup/DNS approval gates must also prove the visible
`I finished this step`, `Approve setup plan`, or `Approve DNS apply` click through
redacted `control_room.gate_resume_requested` audit events. Detonation proof must
cover worker/temp state plus browser profile,
visual-session scratch, OpenClaw/auth state, passphrase files, uploaded app archives,
and FuseKit-controlled control-room/gateway logs; only encrypted or redacted proof
artifacts may survive. The central Run Record must also include
`durable_state` proof showing that the encrypted vault, job state, run state,
checkpoints, gates, and provider route decisions all survived outside the
disposable worker, so the OCI VM can be replaced or detonated without losing the
run. It must also include a non-secret `fusekit.evidence-inventory.v1` inventory
for logs, screenshots, visual state, and receipts by path and type only, so the
demo can prove what happened without embedding screenshots, provider URLs,
clipboard values, or raw secret text. The Run Record must also include a
`fusekit.human-action-trace.v1` summary that maps every recorded provider open,
VM-clipboard Capture, and approval click to a visible control-room gate and its
follow-me instructions, with no unguided actions. It must carry the same
provider-strategy contract as the standalone provider route artifact: schema
version, provider list, strategy rows, selected route status, and fallback
candidates must be present and match the artifact's route decisions so the
ordered route plan survives OCI detonation without drift. Its live verifier
summary must likewise match `verification_report.json` provider checks, including
pending-safe status, so green control-room checks survive OCI detonation without
becoming stale display state.
Public OCI acceptance also
requires a `fusekit.detonation-scope.v1` proof
that names the complete no-trace destroy set, including provider-auth scratch,
browser profiles, passphrase files, uploaded app archives, control-room logs,
gateway logs, and the disposable OCI workspace, while preserving only encrypted
or redacted run artifacts until completion.

## Acceptance Path

Use the most reliable path first:

1. GitHub repo connection and repo secrets/deploy key.
2. Resend API key capture, then Resend domain creation/reuse through the API.
3. Vercel project connection or creation, env vars, deploy, live URL.
4. Cloudflare DNS proposal/apply/verify using app DNS plus Resend-generated records.
5. Optional second segment: Plaid sandbox setup to show broader provider-pack reach.

Plaid should not be the first proof because financial-provider onboarding can
add compliance and review gates that distract from the core launch story.

For a new-site/new-account recording, the control room must make the provider
order obvious enough that the user does not have to infer prerequisites. A
permissioned Resend API key satisfies only the auth gate; FuseKit must then create
or reuse the Resend sending domain by API, create an audience only when the app
requires one, carry the returned Resend DNS records into the Cloudflare approval
plan, and continue without asking the user to manually create Resend domains or
audiences. The provider-routes panel must show this as an ordered Route plan so
the user can follow or watch the lane without deciding whether to click provider
setup controls such as Resend's Add domain button.

## Harness Layer

FuseKit has a native proof layer:

- redacted run ledger
- content-addressed artifact snapshots
- acceptance report with rehearsal/live modes
- provider-pack validation snapshots
- vault public-index proof without raw secrets
- complete provider-route proof for the chosen automation or follow-me path
- redacted durable gate-state proof that every control-room gate was guided and
  no gate remains unresolved
- redacted control-room intervention audit proof for every recorded human gate
- control-room launch-blocker visibility for `blockers[]` recovery actions
- receipt/audit/broad detonation/leak-scan gates

The harness only reports whether the run is public-launch ready. It does not
grant provider access, bypass human gates, or make unverified provider-success claims.
When the report is not launch-ready, `blockers[]` is the plain-language recovery
map for the next demo pass and must be visible in the control room.
