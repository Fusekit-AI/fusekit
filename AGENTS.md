# AGENTS.md

## Mission

Build FuseKit as a shippable, robust, open-source detonated setup worker and capability vault for AI-built apps.

The highest-priority invariant is:

Generated apps may request capabilities. Only FuseKit may use secrets internally. Raw secrets must never leave the vault runtime.

## Working Rules

- Keep implementation small, test-backed, and easy to evaluate.
- Build real-capable provider interfaces. Use local test doubles for tests, not as the product's end state.
- Do not add real provider credentials, paid cloud actions, GitHub publishing, browser automation, MFA/CAPTCHA flows, or production DNS changes without explicit user approval.
- Never bypass CAPTCHA, MFA, passkeys, billing checks, provider fraud controls, or consent screens.
- Prefer OAuth, device authorization, scoped API tokens, deploy keys, service accounts, and provider-native secret stores over account-password storage.
- Treat secret leakage tests as product features, not cleanup.
- Use deterministic local test doubles for automated tests only. Do not present fake provider output as the finished product.
- Keep public receipts and audit logs useful, but redacted.
- Update `docs/implementation-plan.md` as milestones change.

## Development Commands

```zsh
source .venv/bin/activate
python -m pytest
python -m ruff check .
python -m mypy src
```

## Architecture Direction

- CLI-first Python package.
- Local-first runtime for MVP.
- Typed manifests and JSON schemas.
- Real-capable provider adapter contracts for GitHub, Vercel, Supabase, Stripe, DNS, SSH, and webhooks.
- Passphrase-protected encrypted credential bundles.
- Short-lived sessions.
- Default-deny policy engine with allow, deny, and approval-required decisions.
- Redacted JSONL audit log.
- Non-secret setup receipt.
- Detonation cleanup for temporary worker state.

## Product Voice

FuseKit should feel practical, sharp, and security-native:

- Developer tagline: The secure setup worker for AI-built apps.
- Public tagline: AI can write the app. FuseKit makes it real.
- Enterprise tagline: Capability-based secrets runtime for AI-built software.

## Git And Scope

- This repository is independent and self-contained.
- Do not use GitHub, commit, push, or configure remotes unless the user asks.
- Do not touch files outside this repository unless the user explicitly points to them or approves the change.
