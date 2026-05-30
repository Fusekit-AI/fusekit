# FuseKit Project Goal

## Product Promise

AI can write the app. FuseKit makes it real.

FuseKit is an open-source detonated setup worker and encrypted capability vault for AI-built apps. It should be able to take a generated website or app from "code exists" to "real services are configured and working" by creating accounts, passwords, API keys, DNS settings, deployment secrets, webhook secrets, SSH keys, service connections, and provider tokens, then sealing those secrets into a cipher-protected vault file before destroying temporary worker state.

The core invariant is simple: FuseKit may create and hold real setup secrets, but generated apps, prompts, logs, public repos, and post-detonation temp files must never receive raw secrets.

## Real End State

FuseKit should become a real working setup worker that can:

- Inspect a website or app repo and infer required setup.
- Create provider accounts, project resources, service connections, passwords, API keys, deploy keys, SSH keys, DNS tokens, webhook secrets, and environment secrets where provider APIs and terms allow it.
- Guide the user through required human steps such as account login, billing setup, CAPTCHA, MFA, domain registrar ownership, or provider consent, then capture the resulting user-approved credentials directly into the encrypted vault.
- Configure deploy targets, environment variables, DNS records, webhooks, OAuth redirect URLs, repo secrets, SSH keys, database projects, and payment-provider settings.
- Verify that the website actually works after setup.
- Store created passwords, account credentials, API keys, primary keys, DNS settings, private keys, webhook secrets, provider tokens, and service connection details only in an encrypted vault bundle protected by a passphrase and modern authenticated encryption.
- Keep decrypted secrets in memory only inside the FuseKit vault runtime.
- Return safe capability results to apps and agents instead of raw keys or passwords.
- Write redacted audit logs and setup receipts.
- Detonate temporary worker state so prompts, public code, logs, receipts, temp files, and casual filesystem access cannot reveal secrets.

## Cipher Vault Model

FuseKit's main artifact is an encrypted secret file. It should be useless to anyone who finds it without the passphrase.

- Generate or collect service passwords, API keys, provider tokens, DNS credentials, private keys, webhook signing secrets, and service configuration secrets during setup.
- Immediately write those secrets into a passphrase-protected encrypted vault bundle.
- Use a memory-hard KDF such as Argon2id or scrypt and authenticated encryption such as XChaCha20-Poly1305 or AES-256-GCM.
- Store enough encrypted metadata to restore, rotate, audit, and use each credential later.
- Keep decrypted values only in memory inside the FuseKit vault runtime.
- Detonate plaintext temp files, browser scratch state, worker state, raw provider outputs, and unencrypted setup notes.
- Prefer OAuth, device authorization, scoped API tokens, deploy keys, service accounts, and provider-specific secret stores when those are the correct way to connect a service.
- Store account passwords as encrypted vault records when FuseKit creates them or when the user explicitly enters them for FuseKit-managed setup.
- Never scrape or export browser password managers.
- Never bypass CAPTCHA, MFA, passkeys, provider fraud controls, or payment/card verification.
- Never make production DNS, billing, payment, or destructive infrastructure changes without an approval gate.
- Treat passphrases, session tokens, account passwords, API keys, private keys, DNS tokens, webhook secrets, and provider refresh tokens as secrets.

## MVP Scope

The MVP should be real-capable, not a fake product demo. Automated tests may use local test doubles and mock provider adapters so the project can be tested safely, but the product architecture and CLI should be built for real adapters.

The first shippable version should support at least one complete real website setup path, preferably:

- GitHub repo connection and repo secrets.
- Vercel project creation or connection.
- DNS propose/apply flow through a supported DNS provider.
- Environment variable configuration.
- Webhook configuration and verification.
- Encrypted FuseKit vault bundle.
- Redacted setup receipt.
- Detonation of temporary worker state.

## Required V1 Provider Path

The first real build must not stop at mocks or interfaces. It must complete one real setup path using:

- GitHub repository connection and repo secret/deploy-key configuration.
- Vercel project creation or connection, environment variable configuration, deployment, and live URL verification.
- One supported DNS provider with propose, approve, apply, verify, and rollback metadata.
- Webhook signing secret creation or capture.
- SSH/deploy key generation where needed.
- A passphrase-protected FuseKit cipher vault containing the created or captured passwords, account credentials, API keys, DNS settings, private keys, provider tokens, webhook secrets, and service connection settings.
- Detonation that removes plaintext worker state and leaves only encrypted vault artifacts plus redacted logs and receipts.

## Definition Of Done

- `pip install -e .` works from a fresh checkout.
- `pytest` passes.
- FuseKit can scan or accept a setup manifest for a real website.
- FuseKit can produce a setup plan that separates automatic actions, user-required actions, and approval-required actions.
- FuseKit can connect to real providers through safe adapters once the user authorizes each provider.
- FuseKit can create or configure real resources where permitted by provider APIs.
- FuseKit can create or collect passwords, API keys, SSH keys, DNS settings, provider tokens, webhook secrets, and service connection settings, then encrypt them into a passphrase-protected vault bundle.
- Wrong passphrase fails.
- Raw secrets never appear in app responses, logs, receipts, terminal summaries, or detonation survivors.
- Approval-required capabilities pause and require human approval.
- Detonation cleanup removes temporary setup state while preserving encrypted vault artifacts and redacted receipts.
- README explains the real setup flow and the safety boundaries clearly.
- `.gitignore` prevents vault bundles, audit logs, setup receipts, worker state, and temp files from being committed by default.
- A real end-to-end acceptance run has been completed for one website/app repo and documented in the README.

## Non-Goals And Hard Boundaries

- No CAPTCHA bypass.
- No MFA bypass.
- No password-manager export.
- No hidden credential harvesting.
- No production DNS apply without approval.
- No payment/billing changes without approval.
- No unconstrained SSH command execution.
- No storing raw secrets in generated app repos or public project files.
- No pretending test doubles are a real provider integration.
