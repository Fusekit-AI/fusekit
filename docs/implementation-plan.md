# FuseKit Implementation Plan

## Current Status

- [x] Local Python project base exists.
- [x] Dev tooling exists: pytest, Ruff, MyPy.
- [x] Product goal has been reframed around a real-capable detonated setup worker and capability vault.
- [x] MVP architecture modules exist.
- [x] Real-capable provider adapter contracts exist.
- [x] Cipher vault format for created passwords, API keys, SSH keys, DNS settings, provider tokens, and service credentials exists.
- [ ] First real website setup path exists. Local acceptance works; real provider run awaits supervised GitHub/Vercel/DNS authorization.
- [x] Security invariants are enforced by tests.
- [x] CLI defaults to real-provider execution; incomplete local rehearsals require explicit opt-in.
- [x] FuseKit bootstraps its own runtime components instead of assuming Codex/OpenClaw is preinstalled.
- [x] FuseKit captures provider-agnostic LLM configuration, defaulting to OpenAI-compatible `gpt-5.5`.
- [x] Add one-click `install.sh` that creates a local FuseKit environment and app launch entrypoint.
- [x] Runtime bootstrap downloads OpenClaw installer through Python, not a preinstalled `curl`.
- [x] Runtime bootstrap verifies downloaded components with OpenClaw version and doctor checks before launch continues.
- [x] Human gates are resumable wait checkpoints with retry/re-handoff loops instead of terminal failures.
- [x] OpenAI/OpenClaw authorization is the default fallback LLM lane when no API key is supplied.
- [x] OCI clean-room runner lane has a concrete implementation design.
- [x] Runner broker, resumable job state, and local control-room artifact exist.
- [x] Live control-room server, leak scanner, rollback/start-over, and remote runner loop exist.
- [x] Control-room UI is polished with progress, current/next focus, human-gate emphasis, live refresh, and artifact copy actions.
- [x] SnowmanAI branding and state-specific snowman mascot animations are applied to the control room.
- [x] `launch --runner auto` enters OCI authorization inline instead of requiring a separate runner authorization command.
- [x] `launch --runner auto` now defaults to OCI Cloud Shell deeplink when no local OCI profile/config exists.
- [x] FuseKit prompt gates are opt-in through `--fusekit-gates explicit`; default launch uses service-created gates only.
- [x] Provider capability packs can be synthesized, validated, authorized, and planned for detected services without built-in adapters.
- [x] Provider capability packs now carry executable verification recipes for env, HTTP JSON, DNS, and live URL health checks.
- [x] Provider capability packs now carry setup recipes, with GitHub, Vercel, and Cloudflare routed through the capability recipe runtime.
- [x] Acceptance harness exists: redacted ledger, content-addressed artifact snapshots, and rehearsal/live launch-readiness reports.
- [x] Public acceptance target exists: `examples/moonlite-rsvp` is a party RSVP app that activates GitHub, Vercel, Cloudflare DNS, Resend, webhook secret, vault, verification, and detonation proof.
- [x] Public acceptance target has a polished RSVP surface for launch-recording use across desktop and mobile.
- [x] P0 North Star audit fixes: pack secret fan-out is route-limited, explicit app-env secret routes reject provider/runner/LLM auth material, secret-bearing HTTP verification targets are provider-domain constrained, and provider pack synthesis now has an LLM-capable intelligence loop with validation/repair/cache.
- [x] P1 North Star audit fixes: provider-pack setup execution uses a handler registry, unknown required verification/setup recipes fail instead of silently skipping, OCI remote launches replay non-secret launch/app context, and verification polling can return pending.
- [x] P2 North Star audit fixes: service gates have durable persisted state, provider-pack rollback intent can be planned directly, verification retry knobs are exposed in CLI/remote launch, and OpenClaw bootstrap supports version/hash pinning.
- [x] Post-audit bug pass: OCI VM bootstrap now installs OpenClaw on the executable PATH, OpenClaw wait snapshots use the correct command shape, provider verification treats pending live checks as incomplete unless explicitly allowed, and launch-readiness artifacts use product language while preserving compatibility aliases.
- [x] Product-surface hardening pass: public code/docs now use launch-ready capability wording, provider intelligence refuses silent vault downgrade, capability packs no longer duplicate schema fields, and OCI detonation reports provider delete failures instead of swallowing them.
- [x] Live-run readiness bug pass: remote uploads exclude additional secret-bearing config/key files, artifact retrieval fails loudly on missing/invalid archives, failed OCI remote launches still attempt workspace detonation, runner env overrides reject unknown lanes, and job status preserves failed state after cleanup.
- [x] Vercel deployment hardening: project creation can connect the GitHub repository from normal `owner/repo` input, and production deployments can trigger from GitHub org/repo when Vercel's internal repo id is not available.
- [x] Zero-knowledge launch defaults: FuseKit derives GitHub repo slug, Vercel project name, live URL, and DNS zone from the app source, manifest, or git remote so users do not need provider-specific vocabulary.
- [x] Human-gate UX hardening: terminal handoff and control-room waiting states now show plain-language provider gate cards with exact human actions, reassurance that FuseKit keeps waiting, and no raw secret material.
- [x] Live control-room gate hardening: served control-room payload now includes durable `gates.json` records so active provider gates surface even when the broader setup step is still running.
- [x] Gate-state loss hardening: corrupt gate state now surfaces as a repairable control-room error, and remote artifact retrieval preserves `.fusekit/gates.json` alongside receipts, vault, audit, and job state.
- [x] Comfort/noise hardening: control-room refresh and clipboard failures now surface as calm, repairable UI states instead of silent no-ops, and the launcher validates public GitHub HTTPS app sources while using Git-free package/app download fallbacks where possible.
- [x] Computer-use action-plane hardening: OpenClaw now uses interactive compact JSON snapshots and real wait commands, inferred navigation records before/after observations, starts/stops traces when supported, rejects unsafe navigation/key presses, resurfaces provider gates, and writes redacted recovery events instead of failing silently.
- [x] Verification repair loop: failed or pending provider-pack verification can now trigger a bounded inferred UI repair pass, feed redacted verification errors into the computer-use goal, rerun verification afterward, and record repair evidence in audit/receipt artifacts.
- [x] Human-attention guidance: inferred service gates can now highlight the provider-screen target that needs human attention, and the control room surfaces provider resume links plus resurfacing counts for waiting gates.
- [x] Static control-room hardening: saved control-room HTML now embeds durable gate state and corrupt-gate errors just like the live server, so provider waits remain visible even when opened as a file artifact.
- [x] OCI launcher copy hardening: Cloud Shell launcher clipboard failures now select the bootstrap command and explain the manual copy fallback instead of failing silently.
- [x] OCI/runtime bootstrap hardening: `doctor` now verifies OpenClaw version, doctor, and browser status instead of accepting a merely present binary; Cloud Shell bootstrap retries transient installs and can download public GitHub app sources without Git; OCI VMs use a dedicated Python venv, persistent FuseKit/OpenClaw PATH exports, and clearer remote command failures.
- [x] OpenClaw capability hardening: browser snapshots now use efficient JSON payloads by default, optional label overlays are available for human targeting, diagnostics use fresh cleared errors/requests, inferred UI navigation can use rich wait conditions, provider gates scroll targets into view before highlighting, and FuseKit-owned OpenClaw state disables page evaluate by default.
- [x] Privacy reassurance UX: the control-room Snowman now switches into an eyes-covered privacy pose for secret-bearing gates and running steps involving passphrases, tokens, API keys, private keys, payment/MFA checks, hidden prompts, or vault operations.
- [x] Private GitHub source lane: Cloud Shell bootstrap now prompts for the vault passphrase before app retrieval, uses `fusekit source fetch` to download public or private GitHub repos through HTTPS archives, captures approved GitHub App/PAT tokens into the encrypted vault, avoids SSH setup or token-in-URL cloning, and runs a GitHub-specific OpenClaw guidance/highlight goal for private repo approval.
- [x] OCI launcher/installer/VM smoothness pass: source fetching now discovers public GitHub default branches before archive download, launcher/bootstrap source-fetch commands avoid duplicate OpenClaw flags, OCI VM bootstrap retries transient package/browser/OpenClaw installation failures, direct VM runs wait for SSH plus cloud-init plus FuseKit/OpenClaw/browser verification with a longer setup timeout before app upload, and failed partial OCI provisioning attempts detonate created resources.
- [x] Security hardening pass: outbound URL fetches now enforce HTTPS with loopback-only HTTP exceptions, provider HTTP/LLM error bodies no longer echo into public errors, control-room serving is local-only by default with no-store/security headers, dynamic control-room HTML uses attribute/class sanitizers, browser spine result serialization redacts typed text and raw browser output, remote artifact extraction avoids `tar.extractall`, vault writes are atomic owner-only files, the runtime floor is Python 3.10, and local/Cloud Shell bootstrap paths can self-provision an isolated Python 3.12 runtime when the default Python is older.
- [x] Cross-repo bug pass: GitHub source URLs now reject non-root repo pages, failed app archive extraction preserves the previous destination, and remote artifact retrieval fails on empty or unsafe archives instead of silently continuing.
- [x] Alive workflow hardening pass: runner jobs now write durable `checkpoints.json` recovery state with next actions/resume hints, the control room renders Snowman-backed recovery cards for active phases, static control-room artifacts refresh after launch state changes, and remote detonation is guarded by encrypted/redacted artifact completeness checks.
- [x] Trust verification hardening pass: `apply` now writes a redacted `verification_report.json` even when verification needs repair, OCI artifact retrieval requires it before detonation can be trusted, and the control room renders Snowman-backed trust cards for passed, pending, repairing, and failed provider/live-app checks.
- [x] Provider verification/deployment preflight hardening: GitHub, Vercel, Cloudflare/DNS, Resend, Plaid, webhook, and live-app checks now have provider-specific recipe/card semantics, redacted repair guidance, pending-safe DNS/domain/deploy handling, rollback metadata artifacts, and detonation preflight checks before worker destruction.
- [x] Provider UI stump hardening: inferred computer-use now classifies login, MFA, CAPTCHA, consent, missing token, changed navigation, API error, page loading, billing, and unknown UI drift; writes follow-me steps into durable gates; lets the human take over and click resume; falls back to provider-native setup when tokens exist; saves redacted successful provider memory; and keeps verification as the source of truth.
- [x] Provider UI security hardening: snapshots sent to the LLM are redacted, persisted target hints avoid secret-looking text, provider-memory/gate files are private atomic writes, control-room gate resume requires a same-origin custom header, UI repair waits are not treated as success, and provider verification accepts only passed or pending-safe checks before detonation can proceed.
- [x] Guided-gate UX hardening: provider friction copy now leads the user through highlighted provider prompts or autonomous retries instead of asking them to interpret provider screens, figure out navigation, or manually recover setup.
- [x] Magic-lane reliability split: CLI command entrypoints now route through focused command modules, and the control room is split into views, durable state, cards, snowman mascot logic, browser events, CSS assets, and server modules while preserving compatibility imports.
- [x] Canonical launch run-state contract: launches now write `.fusekit/run_state.json` with app repo, runner, OCI, browser, provider session, vault, secret capture, provider-check, receipt, and detonation-safety readiness fields for resume and audit.
- [x] Control-room review hardening: run-state readiness now renders as a launch-contract panel, Snowman/brand markup matches its CSS assets after the modular split, and gate-resume POSTs reject untrusted browser origins.
- [x] Resume/idempotence hardening: OCI/Cloud Shell launches reuse compatible waiting job state, preserve the same job id on resume, attach run-state artifacts to the control room, recover from corrupt run-state files with a redacted rebuild note, parse persisted readiness booleans strictly, reuse existing GitHub deploy-key vault records, create Vercel env vars before deleting old values unless provider repair requires replacement, and continue through provider verification/repair/fallback as the source of truth.
- [x] Whole-lane failure-mode tests: run-state detonation readiness/redaction, corrupt-state recovery, strict false-value parsing, OCI-ready/browser-missing state, provider-gate waits, token-backed API fallback, DNS pending-safe verification, detonation preflight blocking, interrupted Cloud Shell resume, control-room launch-contract rendering, and Vercel env repair are covered by local tests.
- [x] Precision-alignment pass: remote artifact completeness now matches detonation preflight survivors, provider-check run-state readiness and the remote runner loop are driven by the redacted verification report instead of optimistic completion, durable gates render the same guided follow-me UI in static and live control rooms, and launch-contract cards now explain the exact next condition for each phase.
- [x] Truth/user-surface alignment pass: local launches now write the same durable job, checkpoint, run-state, and optional control-room artifacts as OCI launches; `fusekit detonate` uses the split command module correctly; and live acceptance readiness checks the verification report plus rollback metadata directly instead of trusting receipt presence alone.
- [x] Live OCI provisioning hardening: NSG security rules now use the OCI SDK request-details wrapper expected by the live API, and OCI HTTP debug/wire logging is suppressed before provisioning so delegated auth material cannot spill into terminals or run logs.

## Milestone 1: Repo Skeleton And CLI

- [x] Add `LICENSE`.
- [x] Add package modules: `manifest`, `scanner`, `planner`, `policy`, `approvals`, `audit`, and `errors`.
- [x] Add package folders: `crypto`, `vault`, `providers`, `capabilities`, `detonation`, and `schemas`.
- [x] Add CLI command shell for `scan`, `validate`, `plan`, `authorize`, `apply`, `verify`, `receipt`, `unlock`, `request`, and `detonate`.
- [x] Add `install`, `setup`, and `launch` commands for one-click app integration and guided setup.
- [x] Make OpenClaw the default supervised computer-use spine for provider authorization.
- [x] Add `bootstrap` and `doctor` commands for self-contained runtime setup.
- [x] Add `--llm-auth-mode auto|api-key|openclaw` and OpenClaw device-code support.
- [x] Add basic validation tests.

## Milestone 2: App Scanner And Manifest

- [x] Implement repo scanner for common website stacks.
- [x] Detect environment variable usage.
- [x] Detect provider SDK usage.
- [x] Detect Plaid dependencies/env and emit a provider-pack service with a generated pack path.
- [ ] Detect DNS/domain and webhook needs where possible. Webhook env detection exists; DNS is manifest-driven for V1.
- [x] Generate `fusekit.yaml` with required services, capabilities, approvals, and user-required steps.

## Milestone 3: Planning Engine

- [x] Represent setup actions as automatic, user-required, or approval-required.
- [x] Generate plain-English and JSON setup plans.
- [x] Fail closed on unknown high-risk setup actions.
- [x] Add tests for plan generation and risk classification.

## Milestone 4: Cipher Vault Bundle

- [x] Implement memory-hard KDF.
- [x] Implement authenticated encryption.
- [x] Define credential bundle schema.
- [x] Store generated passwords, account credentials, provider tokens, API keys, DNS settings, SSH keys, webhook secrets, and sensitive setup settings as encrypted records.
- [x] Ensure someone who opens the encrypted vault file without the passphrase cannot understand its contents.
- [x] Add wrong-passphrase and no-plaintext tests.

## Milestone 5: Vault Runtime And Sessions

- [x] Unlock bundle into memory only.
- [x] Create short-lived local vault session tokens.
- [x] Implement secret broker.
- [x] Implement capability request and response schemas.
- [x] Deny raw-secret export attempts.
- [x] Ensure tokens are not written to logs or receipts.

## Milestone 6: Policy And Approvals

- [x] Implement default-deny policy.
- [x] Implement allow, deny, and require-approval matching.
- [x] Require approval for production DNS, billing, payment, destructive infra, and arbitrary SSH commands.
- [x] Add approval CLI or local approval UI. V1 uses explicit CLI approval flags.
- [x] Add fail-closed tests.

## Milestone 7: Working Real Provider Adapters

- [x] Define provider authorization contracts.
- [x] Implement GitHub repo secret and deploy key adapter.
- [x] Implement Vercel project and environment variable adapter.
- [x] Implement DNS propose/apply adapter for one provider.
- [x] Implement webhook create/verify utilities.
- [ ] Create accounts automatically where provider APIs allow it.
- [x] Use supervised user handoff when provider APIs require browser login, CAPTCHA, MFA, billing, or identity checks, then capture approved resulting credentials into the encrypted vault.
- [x] Open provider signup/token/project pages for GitHub, Vercel, and Cloudflare during authorization handoff.
- [x] Add OpenClaw browser spine adapter and provider authorization playbooks.
- [x] Add Playwright internal/dev fallback adapter and provider UI playbooks for GitHub, Vercel, Cloudflare, and Resend.
- [x] Add bounded inferred UI navigation loop with LLM-planned actions and service-gate stops.
- [x] Allow the inferred UI navigation loop to run through OpenClaw by default, with Playwright as a fallback adapter.
- [x] Make inferred UI service gates durable waits that retry/resnapshot instead of terminal stops.
- [x] Add action-plane evidence around inferred navigation: observation snapshots, trace hooks, after-action snapshots, safe-key/HTTPS validation, and redacted blocked-action recovery.
- [x] Feed provider verification failures back into the inferred UI loop for targeted repair before final failure.
- [x] Use browser highlight primitives to guide the human at service-created gates without bypassing provider controls.
- [x] Detect Resend email dependency and add Resend provider handoff metadata.
- [x] Add stump classification, follow-me guidance, human takeover/resume, provider-memory hints, and token-backed API fallback to the inferred provider UI loop.
- [x] Add OpenClaw OpenAI auth fallback that records OpenClaw auth-profile state into the encrypted vault when present.
- [x] Add validated provider capability-pack synthesis with a real-capable Plaid setup recipe.
- [x] Add `fusekit provider synthesize`, `provider validate`, and `provider list`.
- [x] Add `fusekit provider verify` and capability-pack verification integrated into `apply`.
- [x] Add Resend and Plaid executable pack verification recipes.
- [x] Move `apply` off provider-specific CLI branches and onto provider-pack setup execution.
- [x] Add secret-routing safeguards so wildcard setup recipes only route app/runtime env secrets, not provider auth tokens or runner/LLM credentials.
- [x] Add setup recipe validation so explicit app env-store recipes cannot route provider auth tokens into GitHub/Vercel secrets.
- [x] Add validation that rejects LLM-generated HTTP verification recipes that send secrets to domains outside provider-owned/documented hosts.
- [x] Add provider intelligence loop that collects app evidence, drafts a pack through a heuristic or OpenAI-compatible LLM source, validates, repairs, and writes the cached pack.

## Milestone 8: Real Website Setup Path

- [x] Pick one initial website stack.
- [x] Scan app and generate setup manifest.
- [x] Provide one-command setup orchestration for scan, plan, authorization, apply, verify, receipt, and detonation.
- [x] Connect GitHub repo, including private source retrieval through supervised GitHub App/PAT authorization without local SSH setup.
- [x] Connect deployment target adapter path. Live proof still depends on supervised provider authorization.
- [x] Configure environment variables through provider-pack setup. Live proof still depends on supervised provider authorization.
- [ ] Propose and optionally apply DNS.
- [ ] Verify deployed website health.
- [x] Store all sensitive setup material in encrypted vault bundle.
- [ ] Document the real acceptance run in README. Reproduction steps are documented; real run log is pending supervised authorization.

## Milestone 9: Audit, Receipt, And Detonation

- [x] Implement redaction utilities.
- [x] Implement JSONL audit log.
- [x] Implement non-secret setup receipt.
- [x] Implement detonation cleanup.
- [x] Preserve encrypted bundle, redacted audit log, and redacted setup receipt.
- [x] Detonate FuseKit-owned OpenClaw state after launches that used OpenClaw auth or provider handoff so OAuth/profile state does not remain as plaintext worker access.
- [x] Add no-secret scanning tests for logs, receipts, terminal summaries, and temp files.

## Milestone 10: Launch Hardening

- [x] Rewrite README around the real setup flow.
- [ ] Add safety model diagram.
- [x] Add local control-room HTML artifact for runner/job visibility.
- [x] Add live control-room server for runner/job visibility.
- [x] Add plaintext secret-leak scanner for repos and artifacts.
- [x] Add rollback planning and start-over cleanup commands.
- [x] Add rollback planning from provider capability-pack rollback metadata.
- [x] Add provider authorization guide.
- [x] Add launch acceptance harness with redacted proof ledger and launch-readiness report.
- [x] Add public acceptance app/runbook for the launch recording path.
- [ ] Add threat model.
- [x] Run full tests.
- [x] Verify package install from fresh checkout.
- [x] Verify `.gitignore` blocks vault bundles, logs, receipts, and worker temp files.

## Milestone 11: OCI Clean-Room Runner

- [x] Design the OCI runner lane in `docs/oci-runner-lane.md`.
- [x] Add runner selection to `launch`: `--runner auto|local|oci-cloud-shell|oci-free|oci-existing`.
- [x] Add `fusekit runner` command group.
- [x] Add OCI auth planner with modes: `auto`, `existing-config`, `browser-session`, and `api-key-upload`.
- [x] Add supervised OCI signup/login/API-key handoff through OpenClaw.
- [x] Inline OCI browser-session authorization into `launch` with retrying service-gate waits.
- [x] Store generated OCI signing keys and runner config only in the encrypted vault.
- [x] Add OCI SDK dependency.
- [x] Implement compartment, VCN, subnet, route, internet gateway, NSG, and VM provisioning.
- [x] Implement shape/availability-domain retry and capacity-gate loop.
- [x] Implement cloud-init bootstrap artifact for FuseKit, OpenClaw, browser dependencies, and verification.
- [x] Install Playwright Chromium in the OCI VM runner bootstrap.
- [x] Implement SSH upload/exec/download protocol without command-line passphrase or secret leakage.
- [x] Upload the encrypted FuseKit vault, but not `.fusekit` scratch state, into the remote OCI worker.
- [x] Implement OCI workspace detonation: instance, boot volume, networking, generated API key, SSH keys, and remote worker state.
- [x] Add durable remote runner loop entrypoint for OCI VM execution.
- [x] Add OCI Cloud Shell deeplink/fallback bootstrap plan and local launcher HTML.
- [x] Forward provider/domain/live URL/inference launch intent through the OCI Cloud Shell bootstrap into the clean-room worker.
- [x] Allow Cloud Shell and OCI VM bootstrap to install a selected FuseKit package/repo instead of silently defaulting to PyPI.
- [x] Support OCI Cloud Shell delegation-token config loading for SDK calls.
- [x] Add local doubles for OCI API tests.
- [ ] Add one documented supervised real OCI acceptance run.

## Milestone 12: Super-Magic Launch UX

- [x] Add `fusekit control-room --serve` live UI endpoint.
- [x] Upgrade `fusekit control-room` into a responsive user-facing launch monitor with full job refresh.
- [x] Add `fusekit leak-scan`.
- [x] Add `fusekit rollback`.
- [x] Add `fusekit start-over`.
- [x] Add `fusekit-runner-loop` remote VM entrypoint.
- [x] Add OCI Cloud Shell bootstrap lane.
- [x] Persist provider/OCI/DNS/LLM human-gate state in `.fusekit/gates.json` so gates can be resurfaced instead of treated as one-shot failures.
- [x] Forward launch context and verification retry settings into remote OCI worker launches.
- [x] Expose verification polling with `--verify-attempts` and `--verify-retry-seconds`.
- [x] Add OpenClaw-backed provider docs/UI research before provider-pack drafting. Full ref-based provider action playbooks still need broader coverage.
- [x] Add acceptance harness for scan/plan/pack/vault/receipt/leak-scan/detonation proof artifacts.
- [ ] Add provider capability catalog for common AI-built app services. Plaid pack synthesis exists; broader catalog remains.
- [x] Add stronger provider-pack provenance, endpoint-purpose validation, and tool-permission binding. Generic provider-pack verification covers env, HTTP JSON, DNS records, and URL health; demo-path provider verification covers GitHub secrets/deploy keys, Vercel project/env/deployment URL, Cloudflare API records plus DNS propagation, Resend domain/API health, app health, and webhook signature secrets.
- [x] Polish the public Moonlite RSVP acceptance surface so the live setup path looks credible in recordings.
- [ ] Complete supervised public real acceptance run. README now documents the exact supervised run protocol and current status.

## North Star Audit Remediation

- [x] P0-1: Prevent wildcard secret routes from copying provider auth tokens into generated app/deploy env stores.
- [x] P0-1b: Prevent explicit app env-store setup recipes from routing provider/runner/LLM auth material.
- [x] P0-2: Reject secret-bearing dynamic HTTP verification recipes unless their destinations match provider documented domains or explicit validated provider hosts.
- [x] P0-3: Introduce a provider intelligence loop that can use an OpenAI-compatible LLM to draft, repair, validate, and cache provider packs.
- [x] P1-1: Replace the setup executor's provider-specific branch chain with a recipe handler registry.
- [x] P1-2: Treat unknown required verification recipes as failed, while preserving optional skips.
- [x] P1-3: Replay launch context when delegating to a remote OCI worker.
- [x] P1-4: Add verification polling/pending semantics and expose retry settings through CLI and remote launch.
- [x] P2-1: Add durable gate records for provider, OCI, DNS, plan, and LLM authorization waits.
- [x] P2-2: Add provider-pack rollback intent planning.
- [x] P2-3: Add optional OpenClaw installer version/hash pinning.
- [x] Fixed gap 1: provider intelligence can browse provider docs/UI through OpenClaw before drafting packs.
- [x] Fixed gap 2: scanner evidence now includes routes, config files, webhook handlers, OAuth callbacks, env syntax variants, and custom domain candidates.
- [x] Fixed gap 3: generated packs now carry non-secret provenance, endpoint purpose declarations, and setup/verify tool-permission bindings.
- [x] Fixed gap 4: rollback can execute provider-native delete/revoke/restore paths for GitHub repo secrets/deploy keys, Vercel env/project resources, and Cloudflare DNS proposal metadata.
- [x] Fixed gap 5: README documents the supervised real-provider acceptance run protocol and marks live execution as pending provider account handoff.
- [x] Fixed gap 6: failed/pending provider verification now feeds redacted errors into a bounded inferred UI repair pass and reruns verification.
- [ ] Remaining: full public acceptance run still requires supervised GitHub/Vercel/Cloudflare authorization and a disposable test domain.
- [ ] Remaining: acceptance harness should ingest provider verification results directly from remote OCI artifacts once the first live run is completed.
