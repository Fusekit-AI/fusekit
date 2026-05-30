# Contributing

FuseKit is early and security-sensitive. Contributions are welcome when they
preserve the core invariant: generated apps can request capabilities, but raw
secrets must stay inside FuseKit's vault runtime.

## Development Setup

```zsh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src
```

## Contribution Guidelines

- Keep changes small and test-backed.
- Use local test doubles for provider behavior in automated tests.
- Do not add real provider credentials, live account artifacts, vaults, `.env`
  files, receipts, audit logs, or browser auth state.
- Do not add code that bypasses CAPTCHA, MFA, passkeys, fraud checks, provider
  consent, billing verification, or password managers.
- Prefer provider-native auth, scoped tokens, deploy keys, service accounts, and
  provider secret stores.
- Add or update tests for redaction, vault behavior, rollback, and detonation
  when changing secret-handling code.

## Provider Packs

Provider packs should include:

- detection evidence
- signup/login/token URLs
- expected service gates
- required environment variables
- setup recipes with explicit tool permissions
- verification recipes with endpoint purpose declarations
- rollback guidance
- prohibited actions

Packs must not contain raw secrets.
