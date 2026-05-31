# FuseKit

FuseKit is the secure setup worker for AI-built apps.

AI can write the app. FuseKit makes it real.

FuseKit scans generated apps, plans service setup, captures approved provider credentials, configures real services, seals sensitive material into a passphrase-protected vault, writes redacted receipts, and detonates plaintext worker state.

## What Works Now

- `fusekit scan`, `validate`, `plan`, `authorize`, `apply`, `verify`, `receipt`, `unlock`, `request`, and `detonate`.
- `fusekit install` adds a one-click setup entrypoint to an app.
- `fusekit launch` runs scan, planning, guided authorization, service wiring, verification, receipts, and detonation as one flow.
- `fusekit bootstrap` installs/checks FuseKit-owned runtime components instead of relying on tools already present.
- `fusekit doctor` verifies local runtime readiness.
- Supervised browser handoff for GitHub, Vercel, Cloudflare, and Resend signup/token pages.
- OpenClaw computer-use spine for provider UI navigation, with Playwright retained as an internal/dev fallback adapter.
- Provider capability packs: FuseKit can synthesize, validate, authorize, and verify guided setup packs from app evidence, with Resend and Plaid recipes included.
- Pack-driven setup: GitHub, Vercel, Cloudflare DNS, Resend, and Plaid now run through provider-pack recipes instead of CLI hardcoding.
- Provider-agnostic LLM configuration with OpenAI as the default (`gpt-5.5`) and custom OpenAI-compatible endpoints supported.
- Real-provider execution by default; incomplete local rehearsals require `--allow-incomplete`.
- Acceptance harness: `fusekit acceptance run` writes a redacted run ledger, artifact snapshots, and launch-readiness report.
- OCI Cloud Shell deeplink launcher for a no-local-prerequisite browser-first lane.
- Encrypted vault bundles using scrypt and AES-256-GCM.
- Wrong-passphrase failure and ciphertext-only vault files.
- Redacted JSONL audit logs and setup receipts.
- Raw secret export denial through the capability broker.
- GitHub repo secrets and deploy key adapter.
- Vercel project, environment variable, git deployment, and live URL verification adapter.
- Cloudflare DNS propose, apply, verify, and rollback metadata adapter.
- Webhook signing secret generation and vault storage.

## Install

```zsh
cd fusekit
./install.sh /path/to/generated-app
```

The installer creates a local virtual environment for FuseKit, installs FuseKit, writes the app's one-click `.fusekit/setup.sh`, and leaves runtime bootstrap to `launch`. Add `--web-launcher --app-source https://github.com/owner/repo.git` to also write `.fusekit/launcher.html`, a local OCI Cloud Shell launcher that needs only a browser.

## Local Acceptance Run

This explicit rehearsal uses no provider tokens and makes no external changes. Real provider execution is the default; this local path must opt in with `--allow-incomplete`. It verifies the scanner, planner, vault encryption, redacted receipt, wrong-passphrase failure, and raw-secret request denial.

```zsh
tmpdir="$(mktemp -d)"
mkdir -p "$tmpdir/app/src"
cat > "$tmpdir/app/package.json" <<'JSON'
{"name":"fusekit-app","dependencies":{"@supabase/supabase-js":"latest"}}
JSON
cat > "$tmpdir/app/src/app.ts" <<'TS'
export const secret = process.env.WEBHOOK_SECRET;
export const url = process.env.SUPABASE_URL;
TS
printf "acceptance-passphrase\n" > "$tmpdir/pass.txt"

fusekit install "$tmpdir/app"
fusekit launch "$tmpdir/app" \
  --passphrase-file "$tmpdir/pass.txt" \
  --allow-incomplete \
  --no-bootstrap \
  --yes
fusekit unlock \
  --vault "$tmpdir/app/.fusekit/fusekit.vault.json" \
  --passphrase-file "$tmpdir/pass.txt"
fusekit acceptance run "$tmpdir/app" \
  --mode rehearsal \
  --vault "$tmpdir/app/.fusekit/fusekit.vault.json" \
  --passphrase-file "$tmpdir/pass.txt"
```

Expected checks:

```zsh
! grep -q WEBHOOK_SECRET "$tmpdir/app/.fusekit/fusekit.vault.json"
! fusekit unlock --vault "$tmpdir/app/.fusekit/fusekit.vault.json" --passphrase-file /dev/null
! fusekit request --vault "$tmpdir/app/.fusekit/fusekit.vault.json" --passphrase-file "$tmpdir/pass.txt" secret.raw
```

Verified locally on 2026-05-25: `pip install -e ".[dev]"`, `pytest`, `ruff`, `mypy`, and the local acceptance run passed.

## Launch Acceptance Harness

The launch-readiness gate is `fusekit acceptance run`. It is intentionally split into two modes:

```zsh
fusekit acceptance run /path/to/generated-app --mode rehearsal
fusekit acceptance run /path/to/generated-app \
  --mode live \
  --vault /path/to/generated-app/.fusekit/fusekit.vault.json \
  --passphrase-file /path/to/pass.txt
```

Rehearsal mode proves the local product invariants without pretending a provider setup happened. It scans or loads the manifest, generates the setup plan, validates/snapshots provider packs, checks detonation state, runs a plaintext leak scan, and writes:

- `.fusekit/acceptance/ledger.jsonl`
- `.fusekit/acceptance/report.json`
- `.fusekit/acceptance/artifacts/*.json`

Live mode will not mark the run ready unless it has an encrypted vault, a passphrase unlock proof, redacted receipt, redacted audit log, verified live URL in the receipt, validated provider packs, clean leak scan, and detonated worker state. The harness creates public proof artifacts without raw secrets.

## Real Provider Acceptance Run

The V1 real path is GitHub + Vercel + Cloudflare DNS. FuseKit uses OpenClaw computer use to navigate provider websites and run supervised account/token/project handoff playbooks. It will not bypass login, MFA, CAPTCHA, billing, payment verification, provider fraud controls, or consent screens. Create the account, complete any human gates, create the scoped token, then let FuseKit capture the approved token into the encrypted vault through a hidden prompt, clipboard-aware flow, or env var.

FuseKit does not require Codex, Codex plugins, or preconfigured local skills. A real `launch` bootstraps FuseKit-owned runtime components by default. Today that means installing/checking OpenClaw through the official local-prefix installer, using a user-supplied LLM API key when one exists, then falling back to OpenClaw's OpenAI authorization step when there is no user-provided inference lane. OpenAI `gpt-5.5` is the default because it is the lowest-friction hosted LLM path, but any OpenAI-compatible provider can still be selected with `--llm-provider`, `--llm-model`, `--llm-base-url`, and `--llm-api-key-env`.

LLM authorization modes:

- `--llm-auth-mode auto` is the default: first capture `OPENAI_API_KEY` or a hidden `--capture-llm-key` value, then fall back to OpenClaw OpenAI auth.
- `--llm-auth-mode api-key` requires the API-key lane and will not open OpenClaw auth.
- `--llm-auth-mode openclaw` requires the OpenClaw OpenAI auth lane.
- `--llm-openclaw-device-code` uses OpenClaw's device-code login path when localhost browser callbacks are not suitable.

The OpenClaw fallback runs `openclaw models auth login --provider openai-codex --set-default`, sets the OpenClaw model route to `openai/gpt-5.5`, verifies the auth/model status, captures known OpenClaw auth-state files into the encrypted FuseKit vault when present, and detonates FuseKit-owned OpenClaw state after any launch that used OpenClaw auth or provider handoff so that plaintext OAuth/profile state is not left behind as worker access.

## Provider Capability Packs

When FuseKit detects a service without a built-in API adapter, it now creates a provider capability pack instead of stopping at a vague unknown-provider warning. The pack is a strict JSON setup recipe containing detection evidence, signup/token/project URLs, expected service gates, required env vars, OpenClaw setup goals, executable verification recipes, rollback notes, and explicit prohibited actions. Packs are validated before use: HTTPS URLs are required, verification cannot be empty, raw-secret-looking material is rejected, and instructions to bypass CAPTCHA, MFA, passkeys, fraud checks, consent, password managers, or human gates are refused.

Verification is pack-driven and broad by design. Supported executable recipe kinds include:

- `env-present`: confirm required secrets exist in the encrypted vault or provider env source.
- `http-json`: call a provider API with secret template refs resolved only in memory.
- `dns-record`: verify `A`, `CNAME`, `TXT`, `MX`, and other DNS records through `dnspython`.
- `url-health`: verify a live app URL returns a healthy HTTP status.

Setup is pack-driven too. Bundled GitHub, Vercel, and Cloudflare behavior is now represented as provider-pack setup recipes and executed by the capability recipe runtime. The low-level Python provider modules remain as reusable primitives for API details such as GitHub secret encryption, Vercel env writes, and Cloudflare DNS mutation; the product flow no longer depends on provider-specific CLI branches for those providers.

Example Plaid path:

```zsh
fusekit provider synthesize plaid --app /path/to/generated-app
fusekit provider validate /path/to/generated-app/.fusekit/provider-packs/plaid.json
fusekit provider verify /path/to/generated-app/.fusekit/provider-packs/plaid.json \
  --vault /path/to/generated-app/.fusekit/fusekit.vault.json
fusekit authorize plaid \
  --app /path/to/generated-app \
  --capability-pack /path/to/generated-app/.fusekit/provider-packs/plaid.json \
  --handoff \
  --infer-ui \
  --capture-stdin
```

During `scan`, `install`, and `launch`, Resend/Plaid dependencies or `RESEND_*`/`PLAID_*` env usage produce provider-pack metadata and prepare `.fusekit/provider-packs/<provider>.json`. The launch plan then includes pack synthesis, OpenClaw-guided authorization, vault capture, and pack verification. Plaid's generated pack verifies credentials with an authenticated `/institutions/get` sandbox smoke check. Resend's generated pack verifies the API key against the Domains API. This is real-provider capable, but live Resend/Plaid account/key setup still requires supervised provider authorization and has not been acceptance-run in this checkout.

Minimum token scopes:

- `GITHUB_TOKEN`: access to the target repo, Actions secrets, and deploy keys.
- `VERCEL_TOKEN`: access to the target team/project and deployments.
- `CLOUDFLARE_API_TOKEN`: edit DNS for the target zone.

Example:

```zsh
export FUSEKIT_PASSPHRASE="use-a-long-unique-passphrase"
export APP_API_KEY="..."

fusekit bootstrap

fusekit scan /path/to/generated-app -o /path/to/generated-app/fusekit.yaml
fusekit plan /path/to/generated-app/fusekit.yaml

fusekit authorize github \
  --vault .fusekit/fusekit.vault.json \
  --handoff \
  --capture-stdin \
  --include-project-page
fusekit authorize vercel \
  --vault .fusekit/fusekit.vault.json \
  --handoff \
  --capture-stdin \
  --include-project-page
fusekit authorize cloudflare \
  --vault .fusekit/fusekit.vault.json \
  --handoff \
  --capture-stdin

fusekit apply /path/to/generated-app/fusekit.yaml \
  --vault .fusekit/fusekit.vault.json \
  --app-source https://github.com/owner/repo.git \
  --approve-dns \
  --secret APP_API_KEY=env:APP_API_KEY
```

One-command version:

```zsh
fusekit install /path/to/generated-app
/path/to/generated-app/.fusekit/setup.sh \
  --app-source https://github.com/owner/repo.git \
  --approve-dns \
  --capture-stdin \
  --secret APP_API_KEY=env:APP_API_KEY
```

That one flow scans the app, writes/updates `fusekit.yaml`, derives the GitHub repo, Vercel project, DNS zone, and live URL where possible, opens the provider account/token/project pages through OpenClaw, pauses for human verification gates, captures approved credentials into the vault, wires services together, verifies the live URL when supplied or inferred, writes redacted audit/receipt artifacts, and detonates worker scratch state. Provider-specific flags such as `--github-repo`, `--vercel-project`, `--dns-zone`, and `--live-url` are advanced overrides for unusual repos, monorepos, or domains.

By default, `launch` uses `--fusekit-gates service-only`: it writes `.fusekit/setup_plan.json` and continues without extra FuseKit approval prompts. Use `--fusekit-gates explicit` when you want the older interactive FuseKit plan/DNS prompt gates for audit rehearsals.

Human gates are resumable checkpoints, not terminal failures. By default FuseKit waits forever at service-created gates such as provider login/MFA/CAPTCHA/billing/consent/token capture. If a wait cycle times out, FuseKit re-runs the browser handoff step to return to the same provider checkpoint and continues waiting. `--gate-retry-seconds` controls the retry interval, and `--gate-max-attempts` is available for CI or tests; the default `0` means no maximum.

Use `--approve-dns` as the upfront DNS execution scope when the setup should apply DNS records. Without that scope, service-only mode proposes DNS and records rollback metadata without pausing mid-run. Billing, payment, destructive infrastructure, and arbitrary SSH execution must be declared as upfront execution scope; FuseKit does not add surprise mid-run approval prompts.

`--capture-stdin` uses a hidden prompt. Tokens are not echoed and are not written to receipts or audit logs. If you prefer environment variables, omit `--capture-stdin` and set `GITHUB_TOKEN`, `VERCEL_TOKEN`, or `CLOUDFLARE_API_TOKEN` before running `authorize`.

Private GitHub app repos do not require SSH keys or local Git setup. In the OCI lane, the bootstrap asks for the vault passphrase first, then runs `fusekit source fetch` to retrieve the app source. Public repos download immediately through GitHub HTTPS archives. Private repos trigger a GitHub service gate: the user signs in, approves a scoped GitHub App installation when `FUSEKIT_GITHUB_APP_INSTALL_URL` is configured, or creates a fine-grained token as the fallback. FuseKit runs OpenClaw inference for this step by default, gives GitHub-specific "follow the highlighted control" guidance, and asks OpenClaw to spotlight provider-screen areas that need human attention. FuseKit captures the approved token through a hidden prompt or `GITHUB_TOKEN`/`GITHUB_APP_INSTALLATION_TOKEN`, encrypts it into the vault as `provider.github.token`, fetches the repo without putting the token in the URL or command line, and then continues the setup launch.

OpenClaw is the default handoff spine. In the magic lane, OpenClaw runs on the OCI VM and owns the browser/computer-use layer; FuseKit only supplies the setup intent, inferred navigation loop, vault, and provider rules. Playwright remains available as `--spine playwright` for local debugging or environments where OpenClaw is unavailable, but it is not the normal user-facing lane. Use `--dry-run-spine` to inspect playbooks without opening a browser. Use `--infer-ui` to let FuseKit observe the provider page through OpenClaw, ask the configured LLM for the next safe UI action, execute allowed clicks/fills/navigation, and wait durably at service gates until the human passes them. The inferred action plane records before/after observations, uses efficient interactive JSON snapshots, supports richer wait conditions, rejects unsafe non-HTTPS navigation, cross-provider navigation, and unsafe key presses, starts/stops browser traces when supported, and writes redacted recovery events when a provider page changes under it. When the LLM can identify the provider-screen control that needs human attention, FuseKit scrolls it into view and asks the browser spine to highlight it instead of leaving the user to hunt. When provider-pack verification fails or remains pending, FuseKit can feed the redacted verification error back into a bounded inferred UI repair pass, then rerun verification before failing the launch. Use `--openclaw-profile chrome` to route through an existing Chrome profile when OpenClaw is configured for its Chrome extension relay.

FuseKit expects the OpenClaw CLI browser surface documented as `openclaw browser --browser-profile <name> open <url>`, `snapshot --interactive --compact --depth 6 --efficient --json`, `snapshot --labels`, `wait --text`, rich `wait` conditions such as `--url` and `--load`, `scrollintoview <ref>`, `highlight <ref>`, cleared `errors`/`requests` diagnostics, and `trace start/stop`.

Bootstrap uses OpenClaw's documented local-prefix installer (`https://openclaw.ai/install-cli.sh`) rather than assuming OpenClaw is already on the machine. After download/install, FuseKit verifies the OpenClaw binary with `openclaw --version`, `openclaw doctor --non-interactive`, and `openclaw browser status --json` before launch continues, so a partial runtime install fails immediately instead of becoming a later setup blocker. FuseKit runs OpenClaw with a FuseKit-owned `OPENCLAW_HOME`, writes a private OpenClaw config if needed, disables page evaluate by default, and self-heals the browser plugin allowlist in that private runtime state. `--no-bootstrap` is available only when you intentionally want to manage the runtime yourself or run an explicit local rehearsal.

FuseKit's bootstrap downloads the OpenClaw installer using Python itself, so it does not require `curl` to already exist. The remaining unavoidable starting point is a working Python 3.10+ interpreter to run FuseKit. Provider-created gates such as CAPTCHA, MFA, billing verification, consent screens, domain ownership verification, and production DNS approval are not bypassed; FuseKit pauses there, guides the human, then resumes.

## OCI Runner Lane

The OCI lane lets `fusekit launch --runner auto` run the setup worker from OCI instead of depending on the user's local machine. When no encrypted OCI profile or local OCI config exists, auto mode selects `oci-cloud-shell`, writes a local launcher, opens Oracle Cloud Shell, and provides a bootstrap command fallback. When an OCI profile/config exists, FuseKit can provision a disposable Oracle Cloud VM directly.

Current runner surface:

```zsh
fusekit launch /path/to/generated-app --runner auto --control-room
fusekit launch /path/to/generated-app --runner oci-cloud-shell --app-source https://github.com/owner/repo.git
fusekit launch /path/to/generated-app --runner oci-cloud-shell --app-source https://github.com/owner/repo.git --fusekit-package git+https://github.com/owner/fusekit.git
fusekit source fetch https://github.com/owner/private-repo.git --dest /tmp/app --capture-stdin
fusekit launch /path/to/generated-app --runner local

fusekit runner doctor
fusekit runner plan oci --json
fusekit launcher /path/to/generated-app --app-source https://github.com/owner/repo.git
fusekit runner authorize oci --vault .fusekit/fusekit.vault.json
fusekit runner receipt --job-state .fusekit/job.json
fusekit control-room --job-state .fusekit/job.json
fusekit control-room --job-state .fusekit/job.json --serve
fusekit leak-scan /path/to/generated-app
fusekit rollback --receipt .fusekit/setup_receipt.json
fusekit start-over /path/to/generated-app
```

`--runner auto` uses local execution for explicit local rehearsals, uses an encrypted/existing OCI profile when one exists, and otherwise selects the OCI Cloud Shell deeplink lane. The Cloud Shell lane needs no local Python, OCI CLI, OpenClaw, Git, SSH, or Node beyond the one-time launcher generator; a hosted or pre-generated launcher can reduce that to a browser only. The deeplink opens Oracle Cloud Shell with a bootstrap command and also shows a copy/paste fallback for Oracle environments that do not auto-run custom deeplink commands. The bootstrap carries the selected app source, provider targets, DNS zone, live URL, LLM settings, and UI-inference flags into the clean-room worker. `--fusekit-package` pins the package or Git URL installed in Cloud Shell and forwarded into any nested disposable VM, which keeps unreleased acceptance builds from drifting to the public PyPI package. `fusekit runner authorize oci` remains available as a manual recovery/advanced command, but it is not required for the default Cloud Shell path.

The live OCI adapter creates a compartment, VCN, public subnet, internet gateway, route table, network security group, SSH key, and VM; uploads the app over SSH without known secret files; uploads only the encrypted FuseKit vault for worker use; runs FuseKit remotely with the passphrase over stdin instead of command arguments; downloads only encrypted/redacted artifacts; removes remote plaintext worker state; and terminates/deletes the OCI workspace during detonation. Default shape selection is free-tier friendly, but explicit paid OCI shapes are allowed when selected by the user.

The super-magic shell includes a live control room, a plaintext secret-leak scanner, rollback planning from redacted receipts, start-over cleanup that preserves encrypted artifacts, and a `fusekit-runner-loop` entrypoint that the OCI VM can run durably after bootstrap.

Real-provider acceptance status: implementation is ready for a supervised run, but the run has not been completed in this checkout because provider tokens, account access, and DNS approval are required.


## Supervised Real Acceptance Run

Status as of this checkout: documented and ready, but not yet executed against live provider accounts in this workspace. The blocker is supervised human authorization for GitHub, Vercel, Cloudflare, and a disposable domain. FuseKit must not bypass those service gates.

Acceptance target:

```zsh
fusekit launch /path/to/generated-app \
  --runner auto \
  --app-source https://github.com/owner/generated-app.git \
  --infer-ui \
  --verify-attempts 10 \
  --verify-retry-seconds 30 \
  --control-room
```

Expected supervised gates:

- OpenAI/OpenClaw authorization when no LLM API key is already in the encrypted vault.
- OCI Cloud Shell or OCI account login if the clean-room runner lane is selected.
- GitHub login/MFA/consent and fine-grained token creation for the target repo.
- Vercel login/MFA/consent and project or Git import confirmation.
- Cloudflare login/MFA/domain ownership checks before DNS records can verify.

Acceptance evidence to preserve after a live run:

- `.fusekit/fusekit.vault.json` opens only with the passphrase; wrong passphrase fails.
- `.fusekit/setup_receipt.json` and `.fusekit/setup_receipt.md` contain no raw secrets.
- `.fusekit/audit.jsonl` contains only redacted provider actions.
- `.fusekit/acceptance/report.json` has `"launch_ready": true` from `fusekit acceptance run --mode live`.
- `.fusekit/acceptance/ledger.jsonl` records scan, plan, pack, vault, receipt, leak-scan, and detonation proof events.
- `fusekit leak-scan /path/to/generated-app` reports no plaintext setup secrets.
- `fusekit provider verify ... --verify-attempts 10` confirms provider/API/live checks or reports pending rather than pretending success.
- `fusekit rollback --execute --receipt .fusekit/setup_receipt.json` can remove GitHub repo secrets/deploy keys, Vercel env/project resources created by FuseKit, and Cloudflare DNS records described by rollback metadata.

## Capability Requests

Generated apps and agents should request capabilities instead of raw secrets.

```zsh
fusekit request --vault .fusekit/fusekit.vault.json health
fusekit request --vault .fusekit/fusekit.vault.json vault.index
```

Raw secret export is denied:

```zsh
fusekit request --vault .fusekit/fusekit.vault.json secret.raw
```

## Detonation

Plaintext worker state is removable after setup:

```zsh
fusekit detonate .fusekit/worker .fusekit/tmp --preserve .fusekit/fusekit.vault.json
```

`fusekit launch` runs detonation automatically at the end unless `--no-detonate` is passed for debugging.

`.gitignore` blocks vault bundles, audit logs, receipts, temp worker state, private keys, and common local env files by default.

## Development

```zsh
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src
```

## Project Structure

- `src/fusekit/`: open-source trust core and CLI.
- `docs/threat-model.md`: security model and boundaries.
- `docs/open-core-boundary.md`: what belongs in the public core versus hosted or commercial layers.
- `docs/oci-runner-lane.md`: clean-room OCI runner design.
- `examples/moonlite-rsvp/`: public acceptance fixture for a real launch path.
- `ROADMAP.md`: public release path.
- `SECURITY.md`: vulnerability reporting and secret-handling rules.

## Safety Boundaries

- No CAPTCHA bypass.
- No MFA or passkey bypass.
- No password-manager export.
- No hidden credential harvesting.
- No production DNS apply without approval.
- No payment, billing, or destructive changes without approval.
- No raw secrets in generated app files, logs, receipts, or terminal summaries.
