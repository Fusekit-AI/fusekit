# FuseKit Acceptance Demo Runbook

Use the checked-in `examples/moonlite-rsvp` app as a controlled public
acceptance target. The point of the run is not the app itself; the point is to
show FuseKit taking an AI-built app from code-only to live services, encrypted
vault, redacted proof, and detonation.

The app is `Moonlite RSVP`: a party invitation and RSVP page that needs GitHub,
Vercel, custom DNS, Resend, a webhook secret, vault encryption, verification,
and detonation.

## Recording Outline

1. Show the generated app repo.
2. Point out that it has code but no real services.
3. Run `fusekit scan examples/moonlite-rsvp`.
4. Show the plan: GitHub, Vercel, Cloudflare DNS, Resend, webhook secret.
5. Run the real launch against a disposable GitHub repo and domain.
6. Pass only service-created human gates: login, MFA, consent, domain ownership.
7. Show FuseKit continuing after the gates.
8. Open the live custom domain.
9. Submit the RSVP form and show Resend delivered or accepted the email.
10. Show the encrypted vault file is unreadable.
11. Show wrong passphrase fails.
12. Show redacted receipt and audit log.
13. Run `fusekit acceptance run --mode live`.
14. Show `"launch_ready": true`.
15. Show detonation proof.

## Real Launch Command Shape

Replace the repo, project, domain, package source, and passphrase path with the
resources used for the acceptance run.

```zsh
fusekit launch /path/to/moonlite-rsvp \
  --runner auto \
  --app-source https://github.com/owner/moonlite-rsvp.git \
  --fusekit-package git+https://github.com/owner/fusekit.git \
  --github-repo owner/moonlite-rsvp \
  --vercel-project moonlite-rsvp \
  --dns-zone example.rsvp \
  --live-url https://example.rsvp \
  --infer-ui \
  --capture-stdin \
  --verify-attempts 10 \
  --verify-retry-seconds 30 \
  --control-room
```

Then run the proof gate:

```zsh
fusekit acceptance run /path/to/moonlite-rsvp \
  --mode live \
  --vault /path/to/moonlite-rsvp/.fusekit/fusekit.vault.json \
  --passphrase-file /path/to/pass.txt
```

## Launch Bar

Do not publish the public walkthrough until:

- the live acceptance report says `launch_ready: true`
- the custom domain resolves
- Resend API/domain verification passes
- Vercel deployment is live
- GitHub secrets/deploy-key verification passes
- vault opens only with the right passphrase
- receipts and logs are redacted
- leak scan is clean
- detonation proof is visible
