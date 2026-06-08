## Summary

## Safety checklist

- [ ] No raw secrets, vaults, `.env` files, provider tokens, browser auth state,
      receipts, audit logs, or private keys are committed.
- [ ] Provider behavior uses local doubles in tests.
- [ ] Secret handling, redaction, rollback, or detonation changes include tests.
- [ ] No CAPTCHA/MFA/passkey/fraud/payment/consent bypass logic is introduced.

## Verification

```zsh
bash scripts/check.sh
```
