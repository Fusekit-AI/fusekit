# Roadmap

FuseKit is pre-1.0. The current focus is proving one real, secure, repeatable
launch path before broadening provider coverage.

## 0.1 Trust Core

- scanner, planner, manifest, and CLI
- encrypted vault and capability broker
- redacted audit/receipt artifacts
- detonation cleanup
- provider capability pack schema and validation
- GitHub, Vercel, Cloudflare DNS, Resend, and Plaid starter paths
- local rehearsal acceptance harness

## 0.2 Clean-Room Runner

- OCI Cloud Shell launcher
- disposable OCI VM provisioning
- remote worker bootstrap with OpenClaw/browser dependencies
- remote artifact retrieval and workspace detonation
- public live acceptance run against a disposable app/domain

## 0.3 Provider Intelligence

- broader scanner inference for OAuth, webhooks, domains, routes, and env vars
- provider-pack repair loop from verification failures
- expanded verification recipes for DNS, TLS, webhooks, deploy keys, OAuth
  redirects, and provider health checks
- provider-native rollback/revoke coverage

## 1.0 Stable Public Core

- documented threat model and security policy
- stable vault format
- stable provider pack schema
- reproducible live acceptance run
- packaged release install path
- compatibility policy for providers and vault bundles

## Outside The Public Core

Hosted launchers, managed runners, team dashboards, enterprise policy, provider
pack marketplace features, and customer-specific automation traces are separate
product layers. See `docs/open-core-boundary.md`.
