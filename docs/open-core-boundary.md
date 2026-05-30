# Open-Core Boundary

FuseKit is designed as an open-source trust core with room for hosted and
commercial products around it.

## Open-Source Core

The public repository should include the pieces users need to inspect, run, and
trust the security boundary:

- scanner, manifest, and planner
- encrypted vault format and unlock behavior
- capability broker and raw-secret export denial
- redacted audit logs and receipts
- detonation cleanup
- provider capability pack schema and validators
- provider-neutral setup and verification engines
- starter provider packs and reusable provider primitives
- local and OCI runner client code
- acceptance harness and public proof artifacts
- CLI, docs, examples, and tests

This code should be useful on its own. It should not be a thin SDK for a hosted
service.

## Hosted Or Commercial Layer

The following belong outside the public core until there is a deliberate release
decision:

- hosted one-click launcher service
- managed runner fleet and run orchestration backend
- account, billing, telemetry, and team dashboard
- enterprise approval, policy, audit-search, and org-vault features
- private provider automation traces and repair data
- curated provider-pack marketplace or scoring system
- customer-specific playbooks and support runbooks
- launch strategy, financing notes, partnership notes, and sales material
- live acceptance-run vaults, tokens, account metadata, and provider logs

Reference implementations can be open-sourced after live proof, but the initial public
repository should make the trust core credible while leaving the managed product
boundary intact.

## Public Messaging

Lead with the product promise:

> AI can write the app. FuseKit makes it real.

Avoid publishing internal launch strategy, financing goals, private
customer notes, or provider-specific operational traces. The public repo should
feel like a serious infrastructure project that can be adopted by developers and
evaluated by security-minded teams.
