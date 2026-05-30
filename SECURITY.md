# Security Policy

FuseKit handles provider credentials, API keys, SSH keys, webhook secrets, DNS
tokens, and other sensitive setup material. Please report security issues
privately.

## Reporting

Open a private security advisory on GitHub or email the maintainers listed in
the repository profile. Do not open a public issue for suspected secret leaks,
vault bypasses, unsafe provider automation, or detonation failures.

## Security Model

FuseKit's security-critical code is open source so users can inspect the
boundary:

- vault encryption and wrong-passphrase behavior
- capability broker denial of raw secret export
- redacted receipts and audit logs
- provider secret routing safeguards
- plaintext leak scanning
- detonation of worker state

FuseKit does not attempt to bypass CAPTCHA, MFA, passkeys, fraud checks,
payment verification, provider consent, or provider terms. Those remain human
or provider-controlled gates.

## Secret Handling Rules

- Do not commit `.fusekit/`, vault files, audit logs, setup receipts, private
  keys, `.env` files, provider tokens, browser auth state, or acceptance-run
  artifacts containing live account metadata.
- Use local doubles in tests.
- Use disposable accounts and domains for live acceptance runs.
- Treat terminal output, screenshots, receipts, and logs as public unless proven
  otherwise.

## Supported Versions

FuseKit is pre-1.0. Security fixes are applied to the main development line
until a stable release policy is published.
