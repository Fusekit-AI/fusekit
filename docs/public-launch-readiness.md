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
  "launch_ready": true,
  "mode": "live"
}
```

Live mode does not claim provider success without proof. It requires the real encrypted vault,
passphrase unlock proof, redacted setup receipt, redacted audit log, live URL in
the receipt, validated provider packs, complete provider route decisions, clean
leak scan, resolved durable gate state, and detonated worker state. Complete
route decisions include the selected route kind, status, deterministic/implemented
flags, reason, and considered candidates, so the control room can explain whether
FuseKit used API automation, secure vault capture, or VM follow-me. When both
Resend and DNS are present, the provider strategy artifact must prove Resend ran
before Cloudflare/DNS so Resend-generated domain records are included in the
approved DNS changes. Any durable human gate recorded during the run must include
a plain next action and resume hint, plus matching redacted control-room audit
proof, even if the gate later passed.

## Acceptance Path

Use the most reliable path first:

1. GitHub repo connection and repo secrets/deploy key.
2. Resend API key capture, then Resend domain creation/reuse through the API.
3. Vercel project connection or creation, env vars, deploy, live URL.
4. Cloudflare DNS proposal/apply/verify using app DNS plus Resend-generated records.
5. Optional second segment: Plaid sandbox setup to show broader provider-pack reach.

Plaid should not be the first proof because financial-provider onboarding can
add compliance and review gates that distract from the core launch story.

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
- receipt/audit/detonation/leak-scan gates

The harness only reports whether the run is public-launch ready. It does not
grant provider access, bypass human gates, or make unverified provider-success claims.
