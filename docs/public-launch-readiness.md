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
- GitHub, Vercel, DNS, and one app service configured
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

Live mode does not fake provider success. It requires the real encrypted vault,
passphrase unlock proof, redacted setup receipt, redacted audit log, live URL in
the receipt, validated provider packs, clean leak scan, and detonated worker
state.

## Acceptance Path

Use the most reliable path first:

1. GitHub repo connection and repo secrets/deploy key.
2. Vercel project connection or creation, env vars, deploy, live URL.
3. Cloudflare DNS proposal/apply/verify using a disposable test domain.
4. Resend domain/API key setup as the provider-pack service target.
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
- receipt/audit/detonation/leak-scan gates

The harness only reports whether the run is public-launch ready. It does not
grant provider access, bypass human gates, or make fake provider-success claims.
