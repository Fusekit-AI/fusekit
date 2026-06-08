# Threat Model

FuseKit is a setup worker and encrypted capability vault for AI-built apps. It
handles real secrets while configuring real providers, then preserves encrypted
artifacts and removes plaintext worker state.

## Assets

- provider tokens and OAuth/session material
- account credentials entered or created during setup
- API keys, webhook secrets, SSH private keys, DNS tokens, database credentials,
  and deployment secrets
- vault passphrase while in use
- generated app source and provider configuration
- redacted receipts, audit logs, and acceptance reports

## Security Goals

- Raw secrets do not enter generated app source files.
- Raw secrets do not appear in receipts, audit logs, terminal summaries, or
  acceptance artifacts.
- The vault file is unintelligible without the passphrase.
- Wrong passphrases fail.
- Provider tokens are routed only to allowed provider/setup paths.
- Temporary worker state is removed after setup unless explicitly retained for
  debugging.
- Human/provider gates are waited on, not bypassed.

## Non-Goals

- FuseKit does not bypass CAPTCHA, MFA, passkeys, fraud checks, payment
  verification, or provider consent screens.
- FuseKit does not export browser password managers.
- FuseKit does not make provider guarantees stronger than the provider's own
  APIs and authorization model.
- FuseKit does not protect secrets after a user intentionally copies them into
  another system outside FuseKit's control.

## Trust Boundaries

- Generated apps are untrusted consumers. They may request capabilities, but
  must not receive raw secrets.
- Provider websites and APIs are external systems. FuseKit can guide setup and
  verify outcomes, but service-side gates remain provider-controlled.
- The local or OCI runner is temporary worker infrastructure. It may hold
  plaintext secrets while unlocked, and must be detonated after setup.
- The encrypted vault is the long-lived secret artifact.
- Receipts, audit logs, launcher files, and acceptance reports are public by
  default and must be redacted.

## Control Room Attack Surface

The control room is the only browser-facing surface that can advance a live
setup run. Its state-changing routes are intentionally small:

- `/api/gates/<gate_id>/pass` records a protected human approval or resume
  signal after a provider gate is complete.
- `/api/gates/<gate_id>/open` opens the provider URL inside the VM visual
  browser, using fixed argv execution rather than shell-evaluated strings.
- `/api/gates/<gate_id>/capture-clipboard` captures the VM clipboard for the
  named secret target and writes it to the encrypted vault.

Every state-changing control-room POST must keep all of these protections:

- the `x-fusekit-control-room: resume` header
- the per-page `x-fusekit-action-token` value
- same-origin or loopback `Origin` validation
- `Sec-Fetch-Site` rejection for browser-declared cross-site requests
- no permissive CORS preflight response
- remote access disabled unless an explicit remote token is configured

The control room must never expose a route that accepts arbitrary shell
commands, creates OS or application admin accounts, edits startup files, or
installs persistence. Provider gate launches must validate the provider URL and
run the browser with an argv list only. Clipboard capture must validate the
expected target shape, reject copied page URLs or multi-token blobs, and record
audit fingerprints instead of raw secret text.

## Safety Model

```mermaid
flowchart LR
    User["Human user<br/>passes provider gates"] --> Runner["FuseKit runner<br/>local or OCI clean room"]
    App["Generated app<br/>untrusted consumer"] --> Broker["Capability broker<br/>default deny"]
    Runner --> Vault["Encrypted vault<br/>long-lived secret artifact"]
    Runner --> Providers["Provider APIs and websites<br/>GitHub, Vercel, DNS, email"]
    Providers --> Gates["Provider-owned gates<br/>MFA, CAPTCHA, billing, consent"]
    Gates --> User
    Broker --> SafeResponses["Safe capability responses<br/>metadata, health, handles"]
    Vault --> Broker
    Runner --> Receipts["Redacted receipts, audit logs,<br/>verification reports"]
    Runner --> Detonation["Detonation<br/>remove plaintext worker state"]

    App -. "raw-secret request denied" .-> Broker
    Providers -. "raw tokens captured only after approval" .-> Vault
    Receipts -. "public-safe artifacts" .-> User
```

The central boundary is between the unlocked runner and everything that can
outlive the setup run. Secrets may be present only inside the active runner or
encrypted vault. Generated apps, receipts, audits, prompts, screenshots,
launcher files, and acceptance artifacts receive redacted metadata or safe
capability responses.

## Main Risks

- secret leakage through generated files, logs, receipts, screenshots, command
  arguments, or crash output
- LLM-generated provider packs sending secrets to untrusted endpoints
- overbroad wildcard env-secret routing
- stale browser/session state left after provider setup
- rollback metadata that cannot revoke/delete provider resources
- users force-adding ignored `.fusekit` artifacts to a public repository

## Controls

- passphrase-protected vault using memory-hard KDF and authenticated encryption
- capability broker denial of raw secret export
- redaction utilities for receipts and audits
- secret-route classification and provider-pack validation
- endpoint-purpose validation for secret-bearing HTTP checks
- leak scanner for app trees and artifacts
- `.gitignore` rules for vaults, receipts, audit logs, private keys, and local
  env files
- runner detonation for local/remote worker state
- tests for wrong-passphrase behavior, redaction, secret routing, and leak scans

## Residual Risk

FuseKit is powerful because it can configure real accounts and services. Users
should run live acceptance paths with disposable accounts/domains first, review
receipts, and rotate provider credentials after high-risk tests. Managed
enterprise deployments should add org policy, central audit review, and
provider-specific least-privilege templates.
