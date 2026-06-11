# FuseKit Acceptance Runbook

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
4. Show the plan: GitHub, Resend, Vercel, Cloudflare DNS, webhook secret.
5. Run the real launch against a disposable GitHub repo and domain.
6. Pass only service-created human gates: login, MFA, consent, domain ownership,
   and copy-once provider secrets.
7. Show FuseKit continuing after the gates.
8. Show Resend running before DNS: FuseKit captures the setup key, creates or
   reuses the sending domain, then hands the returned DNS records to Cloudflare.
9. Open the live custom domain.
10. Submit the RSVP form and show Resend delivered or accepted the email.
11. Show the encrypted vault file is unreadable.
12. Show wrong passphrase fails.
13. Show redacted receipt and audit log.
14. Run `fusekit acceptance run --mode live`.
15. Show `"launch_ready": true`.
16. Show detonation proof.

## Real Launch Command Shape

Replace the app source, package source, and passphrase path with the resources
used for the acceptance run. FuseKit derives the GitHub repo, Vercel project,
DNS zone, and live URL from the repo URL and scanned manifest unless advanced
overrides are supplied.

```zsh
fusekit launch /path/to/moonlite-rsvp \
  --runner auto \
  --app-source https://github.com/owner/moonlite-rsvp.git \
  --fusekit-package git+https://github.com/owner/fusekit.git \
  --infer-ui \
  --verify-attempts 10 \
  --verify-retry-seconds 30 \
  --control-room
```

Use the control-room VM browser and exact `Capture <ENV> from VM clipboard`
buttons for copy-once provider keys during the recording. `--capture-stdin` is only for an
advanced CLI fallback rehearsal, not the public no-thinking launcher path.

## Public Recording Rules

- Keep every provider interaction inside the control-room VM browser.
- Use `Open provider gate in VM` for provider login, MFA, consent, billing,
  domain-ownership, or copy-once secret screens.
- After copying a provider token inside the VM browser, click the exact
  `Capture <ENV> from VM clipboard` button that names that value.
  Do not paste secrets into the host laptop, host browser, terminal, or recording notes.
- For non-secret provider confirmations, use `I finished this step` only after
  the provider screen confirms the requested action.
- For Resend, stay on API Keys during first setup. Empty Domains or Audiences
  pages are not a user task; FuseKit creates or reuses the sending domain and
  audience by API after `RESEND_API_KEY` is captured.
- When creating the Resend setup key, choose `Permission: Full access` and
  `Domain: All domains`; FuseKit narrows the actual app wiring through the
  provider APIs and encrypted vault after capture.
- A Resend row that says `Permission: Full access` and `Domain: All domains`
  is still not enough by itself. If the raw key value is not visible/copyable,
  create a new setup key and capture that raw value into the encrypted vault.
- Do not click Resend Add domain or Add audience during the public path.
  FuseKit owns Resend domain and audience setup by API after key capture.

Then run the proof gate:

```zsh
fusekit acceptance run /path/to/moonlite-rsvp \
  --mode live \
  --remote-artifacts /path/to/moonlite-rsvp/.fusekit/remote-artifacts \
  --passphrase-file /path/to/pass.txt
```

## Launch Bar

Do not publish the public walkthrough until:

- the live acceptance report says `launch_ready: true`
- the custom domain resolves
- Resend API/domain verification passes
- provider strategy order proves Resend ran before Cloudflare/DNS
- Vercel deployment is live
- GitHub secrets/deploy-key verification passes
- no control-room gate remains waiting, resurfaced, retrying, or failed
- vault opens only with the right passphrase
- receipts and logs are redacted
- leak scan is clean
- detonation proof is visible
