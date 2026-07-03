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
- Hosted launcher contract for the planned `fusekit.snowmanai.org` no-terminal path.
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

The installer creates a local virtual environment for FuseKit, installs FuseKit, writes the app's one-click `.fusekit/setup.sh`, and leaves runtime bootstrap to `launch`. If the starting machine only has an older Python available, the installer uses `uv` to provision an isolated Python 3.12 runtime for FuseKit instead of stopping early. Add `--web-launcher --app-source https://github.com/owner/repo.git` to also write `.fusekit/launcher.html`, a local OCI Cloud Shell launcher that needs only a browser.

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

Verified locally on 2026-06-01: `pip install -e ".[dev]"`, `pytest`, `ruff`, `mypy`, and the local acceptance run passed.

## Launch Acceptance Harness

The launch-readiness gate is `fusekit acceptance run`. It is intentionally split into two modes:

```zsh
fusekit acceptance run /path/to/generated-app --mode rehearsal
fusekit acceptance run /path/to/generated-app \
  --mode live \
  --remote-artifacts /path/to/generated-app/.fusekit/remote-artifacts \
  --vault /path/to/generated-app/.fusekit/fusekit.vault.json \
  --passphrase-file /path/to/pass.txt \
  --require-recording
```

Rehearsal mode proves the local product invariants without pretending a provider setup happened. It scans or loads the manifest, generates the setup plan, validates/snapshots provider packs, checks detonation state, runs a plaintext leak scan, and writes:

- `.fusekit/acceptance/ledger.jsonl`
- `.fusekit/acceptance/report.json`
- `.fusekit/acceptance/artifacts/*.json`

In rehearsal mode, `launch_ready: true` means the local harness passed; the
same report keeps `public_launch_ready: false` and `recording_ready: false`.
Only live mode can set those public/demo readiness fields to true.

Live mode will not mark the run ready unless it has an encrypted vault, a passphrase unlock proof, redacted receipt, redacted audit log, verified live URL in the receipt, a redacted verification report whose checks are passed or explicitly pending-safe, actionable rollback metadata, validated provider packs, a central Run Record with matching `model_inference` and `llm_contract` proof, clean leak scan, and detonated worker state. The harness creates public proof artifacts without raw secrets.

After an OCI launch, point live acceptance at the retrieved remote artifact bundle so the harness reads the worker's encrypted/redacted evidence directly:

```zsh
fusekit acceptance run /path/to/generated-app \
  --mode live \
  --remote-artifacts /path/to/generated-app/.fusekit/remote-artifacts \
  --passphrase-file /path/to/pass.txt \
  --require-recording
```

Use `--require-recording` for the public walkthrough gate; it is accepted only
with `--mode live` and `--remote-artifacts`, and exits nonzero unless the live
report proves `recording_ready: true` from the retrieved disposable worker
bundle.

## Hosted Universal Launcher

The product launch target is `fusekit.snowmanai.org`: a hosted FuseKit launcher
where a nontechnical user visits a URL, clicks `Start hosted launch`, selects a
GitHub repository through the FuseKit GitHub App, approves provider-owned gates,
and receives a live URL plus redacted proof. The trust story is open core,
narrow permissions, visible plan, redacted proof, and reversible setup.

The open-source core now includes the hosted launch contract and trust-first
renderer in `fusekit.hosted`. This first slice is non-mutating: it can render a
universal GitHub intake preview, provider summary, narrow-permission contract,
visible setup plan, proof list, and rollback promise without asking the user to
run commands. The homepage and deployment contract now expose the open-core
source repository, MIT license, and reviewable hosted entrypoint (`app.py`)
before the user installs the GitHub App. They also publish deployment
provenance from hosted runtime metadata, including the deployment provider, Git
provider, repository owner/name, branch/ref, commit SHA, and production
environment, so the public launcher can be matched back to the reviewed
open-source commit. Vercel deployments can use Vercel system environment
variables; AWS deployments use explicit non-secret `FUSEKIT_HOSTED_GIT_*`
provenance variables, and AWS Elastic Beanstalk provenance must publish a
clean HTTPS Elastic Beanstalk origin rather than a Cloudflare custom domain or
URL with credentials, query strings, fragments, or paths.
Hosted readiness now keeps the start button disabled until that source
provenance verifies, preventing a public launch from starting from an
unreviewable or miswired deployment. The outside-in hosted verifier checks the
readiness endpoint for that same public provenance proof, not just the embedded
homepage contract.
For AWS planning, `fusekit-hosted-aws-plan` is deliberately plan-only. It emits
a redacted proposed account/region/tag/IAM/env/DNS/rollback plan, reports that
it mutates neither AWS nor Cloudflare, refuses Cloudflare proposals outside the
`fusekit.snowmanai.org` CNAME, validates a one-record Cloudflare DNS dry-run
diff, can block wrong-account or wrong-region plans when an expected account or
region allowlist is supplied, rejects malformed AWS account ids, requires the
planned AWS origin CNAME to match the Elastic Beanstalk provider contract,
rejects hidden or malformed DNS dry-run fields, and blocks when a Resource Groups Tagging
API-style export shows protected MailPilot/SOC 2 resources such as
`Application=MailPilot`, `DataBoundary=mailpilot`, Terraform-managed MailPilot
resources, MailPilot-named resources, or PII-tagged resources. Vercel and AWS
source provenance are provider-bound too, so the public proof cannot claim a
reviewed hosted provider while publishing an arbitrary custom domain as the
provider deployment URL. The public hosted deployment contract also exposes
provider permission copy, DNS dry-run policy, rollback proof requirements, and
outside-in readiness summaries so a nontechnical operator can see what remains
without reading terminal output.
The public GitHub intake contract also
embeds the same trust story, no-terminal launch path, required proof list,
reversal path, and open-core metadata before the install click. It
publishes the capability vault boundary as a user-facing and machine-checkable
promise: generated apps may request capabilities, only FuseKit may use secrets
internally, and raw secrets must never leave the vault runtime. It also makes
the GitHub permission boundary explicit: pre-install intake grants
`contents:read` on one selected repository, while any GitHub write capability
requires a separate visible approval/provider route before mutation. Hosted
GitHub token exchanges now fail closed if GitHub returns all-repository access
or broader permissions than selected-repository `contents:read` plus GitHub
metadata read, and the public deployment/intake contracts expose that exact
token boundary for verifier drift checks. The same selected-repository,
`contents:read`, metadata-read, all-repository rejection, and
`contents:write` rejection boundary is visible on the hosted homepage. It also
includes the GitHub App install URL, app JWT, installation
token exchange, signed callback state, selected-repository listing page, and
server-side source fetch/scan into a visible hosted launch plan. It also has a
public-safe hosted job/control-room shell that tracks proof, rollback, and
detonation expectations without exposing provider tokens. The control room now
publishes a redacted hosted-worker contract with the approved action ids,
provider gates, required public artifacts, Run Record, rollback metadata,
acceptance report, and workspace detonation receipt that must exist before the
hosted path can claim completion. The same pages render a permission-boundary
checklist for the selected-repository GitHub App, `contents:read` source
permission, backend-only token exchange, vault/provider-native credential
storage, and HMAC worker dispatch. They also render the approved action ids from
the visible plan, and tell the user that action drift requires fresh approval.
The hosted home, pre-install GitHub intake/deployment contracts, and visible
plan publish the same prohibited-action boundary as the backend worker request:
no MFA/CAPTCHA/passkey, billing, fraud, consent, or domain-gate bypass; no raw
secret rendering; no DNS or paid-resource mutation without explicit approval;
and no completion claim before live acceptance, retrieved artifacts, and
detonation proof pass.
The hosted home and selected-repository plan now publish the same no-terminal
launch path: visit the hosted URL, install the GitHub App on one repository,
review the plan, click start, pass provider-owned gates, and receive the live
URL with redacted proof, rollback metadata, and detonation receipt. The same
contract now carries a plain-language click path for nontechnical users:
open `fusekit.snowmanai.org`, click start, sign in to GitHub if asked, choose
one repository, review the plan, complete only highlighted provider-owned
screens, and review the final proof.
The homepage also shows the completion proof checklist up front: live URL
verification, provider verifiers, DNS propagation, redacted receipt/audit proof,
Run Record, detonation receipt, and live acceptance report must exist before a
hosted launch can claim completion.
It also shows the reversible setup path before install: rollback metadata before
risky changes, rollback actions for created provider resources, and stop,
revoke-access, rollback, and redacted-proof controls.
The same page embeds public JSON contract blocks for GitHub intake, hosted
readiness, and hosted deployment so operators and verifiers can inspect the
machine-readable trust contract without browser storage, tokens, or raw secrets.
The outside-in verifier now parses those embedded homepage contracts and fails
closed if the visible page carries empty, stale, broader-permission, or
credential-looking JSON.
Unavailable homepage and launch-plan start states render as disabled non-links,
while preview controls jump to the relevant trust section instead of pretending
to run.
The provider-gate checklist is rendered as human-owned checkpoints so MFA,
CAPTCHA, billing, fraud, consent, and domain ownership reviews are visible
instead of hidden in logs. It exposes a redacted job status API and
protected start, pre-worker stop, rollback, and detonation request controls.
Those controls carry a signed redacted job token so a stateless hosted function
can recover the public control-room state without a database or raw provider
token, plus distinct short-lived action-bound control tokens for protected
start, stop, rollback, and detonation clicks. Hosted job routes require that
signed job token even when process memory already has the job, so a known
`hosted-*` id cannot mint fresh controls by itself. Browser forms submit
control tokens in URL-encoded POST fields instead of capability-bearing URLs,
and query or JSON control parameters are rejected.
If those control tokens are missing or expired, the control room shows disabled
start/stop/rollback/detonation controls with a plain-language explanation
instead of hiding the controls or rendering unsafe forms.
Browser form actions return the updated control room instead of raw JSON, while
API clients can still request the redacted job object plus a redacted action
receipt naming the next proof required for worker start, rollback, or detonation. Browser
clicks now show that same latest protected-action receipt in the control room,
including public worker-dispatch status, so a nontechnical user sees what the
button requested and what proof remains without seeing any token. The control
room and proof receipt now also publish a browser-visible reversal playbook:
stop before worker start, revoke or narrow the GitHub App installation, request
rollback with provider inventory proof, and request worker detonation while
preserving redacted public proof. When GitHub provides the non-secret
installation id, the revoke step links to the GitHub installation settings page
without exposing installation tokens. A
browser-facing proof receipt page
shows redacted proof, required artifacts, rollback metadata, and detonation
requirements without claiming completion before live evidence exists. The same
signed proof route can return the redacted receipt as JSON for download or
operator archival without exposing tokens. After the
protected `Start worker` action, `/api/hosted/jobs/<job>/worker-request` exposes
a signed-job-token-compatible, redacted machine handoff for the eventual hosted
worker. That request binds the selected GitHub source, approved plan actions,
provider gates, required remote artifacts, live acceptance mode, recording
requirement, non-secret GitHub App installation id for backend source fetch,
rollback metadata, Run Record, and detonation receipt without turning the user
path into a terminal workflow. GitHub installation tokens remain backend-only
and are never embedded in hosted pages, job tokens, receipts, or public proof. A backend-only
`/api/hosted/jobs/<job>/worker-claims` endpoint lets a configured hosted worker
claim that request with `FUSEKIT_HOSTED_WORKER_SECRET`, updates the public job
state, and returns a redacted claim receipt without rendering the worker secret,
provider tokens, GitHub installation token, or vault material. Backend worker
preparation can now exchange the selected repository's GitHub App installation
token inside FuseKit, fetch the approved source into worker scratch space,
re-scan it, and reject execution if the providers, required env vars, approved
actions, gates, or required artifacts differ from the visible plan the user
approved. Its execution-plan output uses public labels only; it does not include
the token, private key, provider credentials, or host filesystem paths. It also
builds a private backend launch invocation for `fusekit launch` plus the live
`fusekit acceptance run --mode live --remote-artifacts ... --require-recording`
gate, while its public serialization redacts worker-local paths to
`<hosted-worker-source>` labels. After the worker run, backend proof assembly
can derive the `/worker-proof` payload from the real required artifact labels,
retrieved required remote-artifacts survivor bundle, and acceptance report; it
stays partial unless live acceptance is recording-ready and every required
public artifact is a real proof file rather than a directory or empty
placeholder. A
`fusekit-hosted-worker` entrypoint now ties those pieces together for
one queued job: claim with the worker bearer secret, prepare source, run the
private launch/acceptance invocations, and submit redacted proof back to the
hosted API. The same entrypoint now accepts a protected action mode, so a hosted
worker can run the existing `fusekit rollback --execute` or `fusekit detonate`
surfaces for signed rollback/detonation requests against the existing worker
workspace, then submit redacted proof. Rollback maintenance proof is
action-aware: rollback metadata alone cannot satisfy a rollback request; the
hosted proof receipt stays incomplete until the worker reports a rollback
execution receipt and explicit post-rollback verification. Detonation maintenance
proof is action-aware too: the hosted proof receipt stays incomplete after a
detonation request until the worker proves the workspace detonation receipt,
scratch-state destruction, provider-auth session closure, and preserved redacted
public proof. In production, protected control-room
actions must post a
signed dispatch envelope to `FUSEKIT_HOSTED_WORKER_DISPATCH_URL`, letting the
hosted button wake a worker service without asking the user to run a terminal
command or download anything. That dispatch carries the signed public job token
needed by `fusekit-hosted-worker` but omits the worker secret, GitHub
installation token, provider credentials, signature, and vault material from the
browser-facing receipt. The dispatch envelope names the requested action
(`start`, `rollback`, or `detonate`) and the public receipt redacts the signed
job token. The open-core `fusekit-hosted-worker-dispatch` receiver verifies the
HMAC envelope with `FUSEKIT_HOSTED_WORKER_SECRET`, starts
`fusekit-hosted-worker` with the signed job token in environment rather than on
the process command line, and returns only a redacted accepted receipt. It also
records a non-secret per-job/action dispatch marker in the worker workspace or
configured dispatch state directory, so duplicate protected clicks do not spawn
duplicate setup, rollback, or detonation workers. Its
`/readiness` endpoint reports only configuration presence and shape errors for
the worker secret, worker id, optional workspace root, and optional dispatch
state directory, and separates basic `ready` status from production readiness:
production readiness requires durable dispatch idempotency through the workspace
or dispatch state directory, plus public mode/scope/proof text showing the
non-secret reservation is recorded before worker spawn. The
backend-only
`/api/hosted/jobs/<job>/worker-proof` endpoint accepts redacted worker proof
snapshots, rejects credential-looking public notes or unsupported artifact
labels, updates public job steps, and only marks hosted completion when live URL,
provider verifier, DNS, rollback, retrieved remote artifact, Run Record,
detonation, live acceptance, and recording proof are all present. The public
proof receipt renders the same redacted `completion_requires` checklist, so a
launcher can see exactly which evidence keys must still be produced. The public
deployment and GitHub intake contracts also expose those exact evidence keys
beside the readable proof labels, letting `fusekit-hosted-verify` catch proof
vocabulary drift before launch. The verifier also checks the public
plain-language click path so the hosted flow cannot quietly fall back to
terminal, download, or expert-only instructions. The friendly browser checklist
also names recording proof explicitly, and protected action plus worker-claim receipts
reuse that same evidence vocabulary, so a start click cannot understate the
remaining recording or remote-artifact proof. The outside-in hosted verifier
checks every friendly completion-proof label on the homepage, not just the
embedded JSON contracts, and also checks the visible homepage text for all five
trust-story labels: open core, narrow permissions, visible plan, redacted proof,
and reversible setup. It also checks every visible reversible-setup step from the
public contract, including rollback metadata, provider rollback actions, and
stop/revoke/rollback/proof controls. The verifier also compares the full operator setup
checklist for the selected hosted provider plus the Cloudflare CNAME
label/proof text, and rejects visible provider-copy drift such as AWS pages
showing Vercel-only setup steps. A redacted
hosted readiness endpoint reports only configuration presence and shape errors,
and keeps the homepage launch button disabled until the GitHub App id, slug, RSA
private key, origin, state secret, worker secret, and worker dispatch URL are
configured and valid.
The same readiness contract now publishes redacted `blocking_checks` and
deduplicated `next_actions`, and the homepage renders that launch-readiness
summary so an operator can see what to fix without exposing private keys,
worker secrets, or provider credentials.
Direct GitHub intake routes also fail closed with the same redacted readiness
object until those checks pass. The
remaining slices are running the approved setup actions inside the hosted worker,
operating the worker service in production, rollback/detonation execution, and
production DNS/deployment.

The repository includes a minimal WSGI entrypoint at `app.py`, a root
`vercel.json` that routes all hosted paths to that entrypoint for Vercel, a
`Procfile` that starts `gunicorn app:app` for AWS Python WSGI runtimes such as
Elastic Beanstalk, and a minimal `requirements.txt` for the browser launcher
runtime. The hosted deploy also pins Python 3.12 with `.python-version` and
uses a wheel-backed `cryptography==42.0.8` requirement so hosted Python
runtimes do not need native OpenSSL compilation for the public launcher. The
hosted app also serves
`/api/hosted/deployment`, a public deployment contract that lists the canonical
origin, machine-readable trust story, WSGI entrypoint/routing files,
GitHub callback URL, Cloudflare DNS record name, health/readiness URLs, the
operator setup checklist for attaching `fusekit.snowmanai.org` to a supported
hosted origin and Cloudflare, worker dispatch receiver setup/verification steps, a structured
one-click launch contract proving the hosted path needs no terminal or download,
production-required worker dispatch wiring, the machine-readable security header
policy, public source-integrity review files for the hosted launcher, and
required environment variable
names without exposing secret values.
`fusekit-hosted-verify --origin https://fusekit.snowmanai.org`
performs the outside-in deployment check against public DNS propagation, the
hosted homepage, `/healthz`, `/api/hosted/readiness`, and
`/api/hosted/deployment`. When the deployment contract publishes a worker
dispatch URL, the same command automatically verifies the worker receiver
`/healthz` and `/readiness` too, including durable worker-dispatch idempotency
mode, scope, and reservation-before-spawn proof for production.
`--worker-dispatch-url` remains available for checking an
explicit receiver URL before it is published in the hosted contract.
For release proof, pass the expected Git commit too:
`fusekit-hosted-verify --origin https://fusekit.snowmanai.org --expected-commit-sha "$(git rev-parse HEAD)"`.
That fails closed when the public source-provenance contract is healthy but the
OCI host is still serving an older commit.
`fusekit-hosted-oci-access-plan` is the matching plan-only OCI redeploy/access
preflight. It consumes redacted instance, VNIC, plugin, SSH probe, and hosted
verifier evidence, confirms the target is the FuseKit-tagged AMD hosted
launcher, and reports whether SSH or OCI Run Command can safely perform the
release without mutating OCI, Cloudflare, MailPilot/AWS, generated-app
credentials, or provider resources. Include available-plugin evidence when it
is available; the planner distinguishes a missing Run Command plugin from an
image that cannot support Run Command and then recommends only the approved SSH
key repair or a replacement FuseKit-tagged AMD host. Its release proof includes a redacted
`release_action` block with the live commit, expected commit, commit state,
allowed deploy paths, safe next action, and exact post-deploy verifier command,
so stale-host repair has a concrete receipt before any host mutation happens.
The matching OCI release template uses `/opt/fusekit/current` as the rollback
symlink, installs exact commits under `/opt/fusekit/releases/<commit>`, writes
only non-secret provenance to `/etc/fusekit/hosted-provenance.env`, restarts
only the hosted launcher and worker-dispatch services, and emits a redacted
release receipt.
The verifier reports Cloudflare/hosted-origin HTTP failures,
readiness mismatches, public DNS failures, homepage trust drift, hosted
runtime/open-core/DNS drift, deployment trust-story drift, homepage completion
proof checklist drift, homepage reversible-setup drift, one-click launch
contract drift, protected-control transport/browser-origin drift, embedded
homepage contract drift, capability-vault boundary drift,
hosted source-integrity drift,
pre-install GitHub intake trust drift, and operator-setup contract drift
as redacted JSON instead of claiming launch readiness. It also publishes
top-level `blocking_checks` and deduplicated `next_actions` so an operator can
see the remaining public setup work without searching every check row. Every
public HTML/JSON payload it fetches is also
checked with FuseKit's credential-text detector, and any failure is reported
only as a redacted failure code. Successful public HTTP responses must also
publish no-store, default-deny CSP, no-framing, no-referrer, nosniff, HSTS,
disabled-permissions, and same-origin opener headers before the verifier marks
them ready. It
also recognizes Cloudflare Error 1000 (`DNS points to prohibited IP`) and
reports the non-secret next action: attach `fusekit.snowmanai.org` to the
hosted origin and route the Cloudflare `fusekit` CNAME to the exact
provider-provided target.
Hosted responses include no-store caching and browser security headers so the
launcher behaves like a hardened control surface from first deploy. The worker
dispatch receiver returns the same no-store, no-framing, no-referrer,
nosniff, HSTS, and disabled-permissions headers on its JSON readiness and
dispatch receipt endpoints.
Hosted launch jobs, protected action receipts, backend worker requests, worker
claim receipts, and worker proof receipts also publish the same non-secret
approved-plan fingerprint. The fingerprint covers the selected app name,
GitHub source URL, detected providers, required environment variable names,
approved action ids, required artifact labels, provider gate labels, and worker
guarantees, so provider/action/gate/artifact/source drift requires a fresh
visible plan before execution.

Production needs a supported hosted origin connected to this repository
or deployed from this checkout, an HTTPS worker dispatch service running
`fusekit-hosted-worker-dispatch` with durable dispatch state, and
`FUSEKIT_HOSTED_WORKER_DISPATCH_URL` set in the hosted environment to that
service. `fusekit.snowmanai.org` is the canonical public origin; route the
Cloudflare `fusekit` subdomain to the exact hosted-provider target for the
chosen runtime. Set these runtime environment variables in the hosted
environment:
`FUSEKIT_HOSTED_ORIGIN`,
`FUSEKIT_GITHUB_APP_ID`, `FUSEKIT_GITHUB_APP_SLUG`,
`FUSEKIT_GITHUB_APP_PRIVATE_KEY`, `FUSEKIT_HOSTED_STATE_SECRET`, and
`FUSEKIT_HOSTED_WORKER_SECRET`. Vercel deployments must expose system
environment variables including `VERCEL_ENV`, `VERCEL_URL`,
`VERCEL_GIT_PROVIDER`, `VERCEL_GIT_REPO_OWNER`, `VERCEL_GIT_REPO_SLUG`,
`VERCEL_GIT_COMMIT_REF`, and `VERCEL_GIT_COMMIT_SHA`. OCI and AWS deployments
must set `FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER` to `oci-compute` or
`aws-elastic-beanstalk`, plus `FUSEKIT_HOSTED_DEPLOYMENT_ENV=production`,
`FUSEKIT_HOSTED_DEPLOYMENT_URL`, `FUSEKIT_HOSTED_GIT_PROVIDER`,
`FUSEKIT_HOSTED_GIT_REPO_OWNER`, `FUSEKIT_HOSTED_GIT_REPO_SLUG`,
`FUSEKIT_HOSTED_GIT_COMMIT_REF`, and `FUSEKIT_HOSTED_GIT_COMMIT_SHA`. The
hosted verifier rejects the deployment if those public source-provenance fields
are missing or point at a different repository. Paid Managed FuseKit runs stay
disabled until the runtime also sets `FUSEKIT_MANAGED_RUNS_ENABLED=1`, a
live-mode `FUSEKIT_STRIPE_SECRET_KEY`, `FUSEKIT_STRIPE_PRICE_ID`, and the
public `FUSEKIT_MANAGED_RUN_PRICE_LABEL` shown before Checkout. Test-mode
Stripe products and prices may be staged while managed runs stay disabled, but
they do not make the public Managed FuseKit Run lane launchable. Production
one-click worker wakeup also needs
`FUSEKIT_HOSTED_WORKER_DISPATCH_URL` pointed at an HTTPS worker dispatch
service running `fusekit-hosted-worker-dispatch` with
`FUSEKIT_HOSTED_WORKER_SECRET` and worker runtime environment configured. Set
`FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR` or a persistent
`FUSEKIT_HOSTED_WORKER_WORKSPACE` for durable duplicate-click protection. Verify
that service with `/healthz` and `/readiness` before setting
`FUSEKIT_HOSTED_WORKER_DISPATCH_URL`. As of the latest local check,
`https://fusekit.snowmanai.org` resolves through Cloudflare to the OCI-hosted
launcher and the basic outside-in hosted verifier passes. Exact release proof
with `--expected-commit-sha` must also pass before claiming the live URL serves
current `main`. The OCI host posture report must also attach the redacted
release receipt from `/var/lib/fusekit/release-receipts` so the validator can
match the moved `/opt/fusekit/current` symlink, restarted services, rollback
commit, and post-deploy verifier command to the same hosted commit. The paid
Managed lane is still intentionally closed until complete Stripe runtime
configuration, Stripe price verification, and a live paid Checkout proof exist.

For shared Snowman AI Stripe accounts, create hosted managed-run pricing with
the repo-native helper so FuseKit only creates a FuseKit-scoped Product and
Price and never edits existing Snowman AI products:

```zsh
FUSEKIT_STRIPE_SECRET_KEY=sk_live_... \
  fusekit-hosted-stripe-price \
    --amount-cents 100 \
    --currency usd \
    --label 'Launch validation: $1.00 FuseKit managed run' \
    --execute \
    --confirm-shared-account
```

If the source checkout has not been installed as a package yet, use the module
fallback with the same flags:

```zsh
FUSEKIT_STRIPE_SECRET_KEY=sk_live_... \
  python -m fusekit.hosted.stripe_setup \
    --amount-cents 100 \
    --currency usd \
    --label 'Launch validation: $1.00 FuseKit managed run' \
    --execute \
    --confirm-shared-account
```

On execute, the helper first looks up the deterministic FuseKit Price
`lookup_key`. If a matching active FuseKit-scoped Price/Product already exists,
it reuses that Price id and reports `reused_existing=true` without creating
another Stripe object. If the lookup key is occupied by non-FuseKit metadata, it
stops instead of touching another Snowman AI product. The command prints only
redacted public JSON: the Stripe Product id, Stripe Price id, whether a mutation
occurred, the public `FUSEKIT_MANAGED_RUN_PRICE_LABEL`, and next runtime
environment actions. Omit `--execute` for a dry run. Before enabling managed
runs, verify the created or reused Price/Product in the shared Stripe account:

```zsh
FUSEKIT_STRIPE_SECRET_KEY=sk_live_... \
FUSEKIT_STRIPE_PRICE_ID=price_... \
  fusekit-hosted-stripe-price-verify \
    --amount-cents 100 \
    --currency usd \
    --label 'Launch validation: $1.00 FuseKit managed run'
```

The source-checkout fallback is:

```zsh
FUSEKIT_STRIPE_SECRET_KEY=sk_live_... \
FUSEKIT_STRIPE_PRICE_ID=price_... \
  python -m fusekit.hosted.stripe_verify \
    --amount-cents 100 \
    --currency usd \
    --label 'Launch validation: $1.00 FuseKit managed run'
```

The verifier retrieves the Stripe Price with its Product, checks the active
one-time amount, currency, lookup key, FuseKit metadata, product scope, and
public label hash, and emits only redacted JSON. Keep
`FUSEKIT_MANAGED_RUNS_ENABLED=0` until the price verifier, live Checkout proof,
and worker-dispatch acceptance have passed. Keep literal dollar-amount labels
in single quotes, or use a currency-code label such as `USD 1.00`, so the shell
cannot expand `$1` into an ambiguous `.00` public price.

## Real Provider Acceptance Run

The V1 real path is GitHub + Resend + Vercel + Cloudflare DNS. FuseKit uses OpenClaw computer use to navigate provider websites and run supervised account/token/project handoff playbooks in the shared VM browser. It will not bypass login, MFA, CAPTCHA, billing, payment verification, provider fraud controls, or consent screens. Create or sign in to the provider account, pass the real human gate, copy any one-time provider token inside the VM browser, then click the exact env-named FuseKit control such as `Capture RESEND_API_KEY from VM clipboard` so the approved value lands directly in the encrypted vault.

FuseKit does not require Codex, Codex plugins, or preconfigured local skills. A real `launch` bootstraps FuseKit-owned runtime components by default. Today that means installing/checking OpenClaw through the official local-prefix installer, using a user-supplied LLM API key when one exists, then falling back to OpenClaw's OpenAI authorization step when there is no user-provided inference lane. OpenAI `gpt-5.5` is the default because it is the lowest-friction hosted LLM path, but any OpenAI-compatible provider can still be selected with `--llm-provider`, `--llm-model`, `--llm-base-url`, and `--llm-api-key-env`.

LLM authorization modes:

- `--llm-auth-mode auto` is the default: first capture `OPENAI_API_KEY` from env or the non-echoing `--capture-llm-key` CLI fallback, then fall back to OpenClaw OpenAI auth.
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

Setup is pack-driven too. Bundled GitHub, Resend, Vercel, and Cloudflare behavior is now represented as provider-pack setup recipes and executed by the capability recipe runtime. The low-level Python provider modules remain as reusable primitives for API details such as GitHub secret encryption, Resend domain/audience setup, Vercel env writes, and Cloudflare DNS mutation; the product flow no longer depends on provider-specific CLI branches for those providers.

Provider setup also records a strategy decision for each recipe: provider API,
official CLI, guided browser, human follow-me, or local vault capture. The
north-star plan is documented in
[`docs/northstar-provider-strategy.md`](docs/northstar-provider-strategy.md).

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

During `scan`, `install`, and `launch`, maintained provider catalog entries produce provider-pack metadata and prepare `.fusekit/provider-packs/<provider>.json`. The catalog covers common generated-app services including Stripe, Supabase, Clerk, Neon, Upstash, OpenAI, Resend, and Plaid. The launch plan then includes pack synthesis, OpenClaw-guided authorization, vault capture, and pack verification. Plaid's generated pack verifies credentials with an authenticated `/institutions/get` sandbox smoke check. Resend's generated pack verifies the API key against the Domains API. Other catalog packs use conservative vault-capture and env-present checks until provider-native setup/verification recipes are explicitly implemented and tested. These paths are real-provider capable, but live account/key setup still requires supervised provider authorization and has not been acceptance-run in this checkout.

Minimum token scopes:

- `GITHUB_TOKEN`: access to the target repo, Actions secrets, and deploy keys.
- `RESEND_API_KEY`: Full access for the first setup so FuseKit can create or reuse the sending domain and audience when required.
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

DNS apply is always explicit. Public control-room runs surface an `Approve DNS apply`
gate after Resend and the app have produced the exact DNS records, then continue
through the DNS provider API after that protected launcher click is recorded.
`--approve-dns` remains available as an upfront CLI execution scope for advanced
or CI-style runs that should apply DNS without pausing at the launcher gate.
Billing, payment, destructive infrastructure, and arbitrary SSH execution must be
declared as upfront execution scope; FuseKit does not add surprise mid-run
approval prompts.

`--capture-stdin` is an advanced CLI fallback that uses a non-echoing prompt.
Public launcher runs should use the exact env-named VM browser Capture buttons,
for example `Capture RESEND_API_KEY from VM clipboard`. Tokens are not echoed and
are not written to receipts or audit logs. If you prefer environment variables
for local CLI work, omit `--capture-stdin` and set `GITHUB_TOKEN`,
`VERCEL_TOKEN`, or `CLOUDFLARE_API_TOKEN` before running `authorize`.

Private GitHub app repos do not require SSH keys or local Git setup. In the OCI
lane, the bootstrap asks for the vault passphrase first, then runs
`fusekit source fetch` to retrieve the app source. Public repos download
immediately through GitHub HTTPS archives. Fetched archives drop checked-in
local state and credential-looking files such as `.env`, `.fusekit`,
dependency/cache folders, vaults, keys, and build-info output. Private repos
trigger a GitHub service gate: the user signs in, approves a scoped GitHub App
installation when `FUSEKIT_GITHUB_APP_INSTALL_URL` is configured, or creates a
fine-grained token as the fallback. FuseKit runs OpenClaw inference for this
step by default, gives
GitHub-specific "follow the highlighted control" guidance, and asks OpenClaw to
spotlight provider-screen areas that need human attention. Public launcher runs
capture the approved token through the exact env-named VM browser Capture button,
such as `Capture GITHUB_TOKEN from VM clipboard`; local CLI fallbacks can use
`GITHUB_TOKEN` or `GITHUB_APP_INSTALLATION_TOKEN`. FuseKit encrypts the token into
the vault as `provider.github.token`, fetches the repo without putting the token
in the URL or command line, and then continues the setup launch.

OpenClaw is the default handoff spine. In the magic lane, OpenClaw runs on the OCI VM and owns the browser/computer-use layer; FuseKit only supplies the setup intent, inferred navigation loop, vault, and provider rules. Playwright remains available as `--spine playwright` for local debugging or environments where OpenClaw is unavailable, but it is not the normal user-facing lane. Use `--dry-run-spine` to inspect playbooks without opening a browser. Use `--infer-ui` to let FuseKit observe the provider page through OpenClaw, ask the configured LLM for the next safe UI action, execute allowed clicks/fills/navigation, and wait durably at service gates until the human passes them. The inferred action plane records before/after observations, uses efficient interactive JSON snapshots, supports richer wait conditions, rejects unsafe non-HTTPS navigation, cross-provider navigation, and unsafe key presses, starts/stops browser traces when supported, and writes redacted recovery events when a provider page changes under it. When the LLM can identify the provider-screen control that needs human attention, FuseKit scrolls it into view and asks the browser spine to highlight it instead of leaving the user to hunt. When provider-pack verification fails or remains pending, FuseKit can feed the redacted verification error back into a bounded inferred UI repair pass, then rerun verification before failing the launch. Use `--openclaw-profile chrome` to route through an existing Chrome profile when OpenClaw is configured for its Chrome extension relay.

FuseKit expects the OpenClaw live VM browser command set documented as `openclaw browser --browser-profile <name> open <url>`, `snapshot --interactive --compact --depth 6 --efficient --json`, `snapshot --labels`, `wait --text`, rich `wait` conditions such as `--url` and `--load`, `scrollintoview <ref>`, `highlight <ref>`, cleared `errors`/`requests` diagnostics, and `trace start/stop`.

Bootstrap uses OpenClaw's documented local-prefix installer (`https://openclaw.ai/install-cli.sh`) rather than assuming OpenClaw is already on the machine. After download/install, FuseKit verifies the OpenClaw binary with `openclaw --version` and `openclaw doctor --non-interactive`, and verifies browser readiness with a Playwright Chromium smoke test against the shared runner browser cache before launch continues. FuseKit runs OpenClaw with a FuseKit-owned `OPENCLAW_HOME`, writes a private OpenClaw config if needed, disables page evaluate by default, and self-heals the browser plugin allowlist in that private runtime state. If the installed OpenClaw build does not expose browser automation commands, FuseKit falls back to its Playwright browser spine for browser automation. `--no-bootstrap` is available only when you intentionally want to manage the runtime yourself or run an explicit local rehearsal.

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

`--runner auto` uses local execution for explicit local rehearsals, uses an encrypted/existing OCI profile when one exists, and otherwise selects the OCI Cloud Shell deeplink lane. The Cloud Shell lane needs no local Python, OCI CLI, OpenClaw, Git, SSH, or Node beyond the one-time launcher generator; a hosted or pre-generated launcher can reduce that to a browser only. The deeplink opens Oracle Cloud Shell with a bootstrap command and also shows a copy/paste fallback for Oracle environments that do not auto-run custom deeplink commands. The bootstrap carries the selected app source, provider targets, DNS zone, live URL, LLM settings, and UI-inference flags into the clean-room worker. Hosted BYO bootstrap pages publish a preflight and reversibility contract before Cloud Shell handoff: Oracle billing belongs to the user's tenancy, FuseKit charges no managed-run fee, AMD/x86_64 shape proof is required, human gates stay human-owned, redacted artifacts must come back, and workspace detonation proof closes the run. Browser clicks render that handoff as HTML, while `format=json` returns the same redacted machine contract. `--fusekit-package` pins the package or Git URL installed in Cloud Shell and forwarded into any nested disposable VM, which keeps unreleased acceptance builds from drifting to the public PyPI package. `fusekit runner authorize oci` remains available as a manual recovery/advanced command, but it is not required for the default Cloud Shell path.

The live OCI adapter uses the selected root/current compartment and creates only the disposable runner resources inside it: VCN, public subnet, internet gateway, route table, network security group, SSH key, and VM. It uploads the app over SSH without known secret files; uploads only the encrypted FuseKit vault for worker use; runs FuseKit remotely with the passphrase over stdin instead of command arguments; downloads only encrypted/redacted artifacts; removes remote plaintext worker state; and terminates/deletes the OCI workspace resources during detonation while preserving the root compartment by design. Default shape selection is free-tier friendly, but explicit paid OCI shapes are allowed when selected by the user.

The super-magic shell includes a live control room, a plaintext secret-leak scanner, rollback planning from redacted receipts, start-over cleanup that preserves encrypted artifacts, and a `fusekit-runner-loop` entrypoint that the OCI VM can run durably after bootstrap.

Real-provider acceptance status: implementation is ready for a supervised run, but the run has not been completed in this checkout because provider tokens, account access, and DNS approval are required.


## Supervised Real Acceptance Run

Status as of this checkout: documented and ready, but not yet executed against live provider accounts in this workspace. The blocker is supervised human authorization for GitHub, Vercel, Cloudflare, Resend, OpenAI/LLM, OCI, billing/MFA/consent screens, and a disposable domain. FuseKit must not bypass those service gates.

Attempted live proof gate on 2026-06-20:

```zsh
fusekit acceptance run /Users/ileanaphoenix/Developer/fusekit/examples/moonlite-rsvp \
  --mode live \
  --remote-artifacts /Users/ileanaphoenix/Developer/fusekit/examples/moonlite-rsvp/.fusekit/remote-artifacts \
  --require-recording \
  --json
```

Result:

```text
fusekit: Remote artifact path does not exist: /Users/ileanaphoenix/Developer/fusekit/examples/moonlite-rsvp/.fusekit/remote-artifacts
```

This is the expected fail-closed result until the supervised OCI/provider run retrieves the encrypted/redacted survivor bundle.

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
- Resend login/MFA/consent and one-time `RESEND_API_KEY` capture from the VM
  clipboard; FuseKit then owns Resend domain/audience setup by API before DNS.
- Vercel login/MFA/consent and project or Git import confirmation.
- Cloudflare login/MFA/domain ownership checks before DNS records can verify.

Acceptance evidence to preserve after a live run:

- `.fusekit/fusekit.vault.json` opens only with the passphrase; wrong passphrase fails.
- `.fusekit/setup_receipt.json` and `.fusekit/setup_receipt.md` contain no raw secrets.
- `.fusekit/audit.jsonl` contains only redacted provider actions.
- `.fusekit/acceptance/report.json` has `"launch_ready": true`, `"public_launch_ready": true`, `"remote_artifacts_ready": true`, `"recording_proof_ready": true`, and `"recording_ready": true` from `fusekit acceptance run --mode live --remote-artifacts .fusekit/remote-artifacts --require-recording`, plus a redacted `"recording_contract"` checklist whose section checks are all true and whose blockers list is empty.
- `.fusekit/acceptance/ledger.jsonl` records scan, plan, pack, vault, receipt, leak-scan, detonation, and final recording-proof summary events.
- For OCI launches, `fusekit acceptance run --mode live --remote-artifacts .fusekit/remote-artifacts --require-recording` ingests the remote worker's vault, receipt, audit log, verification report, and rollback metadata directly.
- `fusekit leak-scan /path/to/generated-app` reports no plaintext setup secrets.
- `fusekit provider verify ... --verify-attempts 10` confirms provider/API/live checks or reports pending rather than pretending success.
- `fusekit rollback --execute --receipt .fusekit/setup_receipt.json` can remove GitHub repo secrets/deploy keys, Vercel env/project resources created by FuseKit, and Cloudflare DNS records described by rollback metadata.

## Capability Requests

Generated apps and agents should request capabilities instead of raw secrets.

```zsh
fusekit request --vault .fusekit/fusekit.vault.json health
fusekit request --vault .fusekit/fusekit.vault.json vault.index
```

For repeated local checks, create a short-lived vault session instead of typing
the passphrase each time:

```zsh
fusekit unlock --vault .fusekit/fusekit.vault.json --session-ttl 900
fusekit request --vault .fusekit/fusekit.vault.json --session-token "$TOKEN" health
```

The owner-only session file expires within an hour and does not store the
bearer token or plaintext passphrase. It only unlocks the local vault long
enough to serve safe capability responses; raw secret export stays denied.

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
bash scripts/check.sh
```

## Project Structure

- `src/fusekit/`: open-source trust core and CLI.
- `docs/threat-model.md`: security model and boundaries.
- `docs/security-surface-map.md`: accessible routes, state-changing actions, and CSRF/command-injection boundaries.
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
