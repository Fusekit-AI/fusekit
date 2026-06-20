# Public Launch Readiness

FuseKit should launch publicly only when the first acceptance path is narrow,
real, and provable.

## Launch Claim

AI can write the app. FuseKit makes it real.

The public walkthrough should show one generated app moving from code-only to
live connected services:

- app repo scanned
- setup plan generated
- provider authorization gates opened through the computer-use spine
- GitHub, Resend, Vercel, and DNS configured in dependency order
- secrets sealed in the encrypted vault
- live URL verified
- redacted receipts and audit ledger written
- plaintext worker state detonated

## Harness Gate

Before publishing a public walkthrough, run:

```zsh
fusekit acceptance run /path/to/generated-app \
  --mode live \
  --remote-artifacts /path/to/generated-app/.fusekit/remote-artifacts \
  --vault /path/to/generated-app/.fusekit/fusekit.vault.json \
  --passphrase-file /path/to/pass.txt \
  --require-recording
```

For public walkthroughs, `--require-recording` makes the command fail unless
the live report proves `recording_ready: true` from the retrieved disposable
worker artifact bundle. The CLI rejects the public recording gate unless
`--mode live` and `--remote-artifacts` are both present, keeping recordability
tied to post-detonation survivor proof instead of local scratch state.

The run is launch-ready only when `.fusekit/acceptance/report.json` contains:

```json
{
  "blockers": [],
  "launch_ready": true,
  "mode": "live",
  "public_launch_ready": true,
  "remote_artifacts_ready": true,
  "recording_contract": {
    "recording_ready": true,
    "blockers": [],
    "checks": {
      "rehearsal_review": true,
      "worker_replacement": true
    }
  },
  "recording_proof_ready": true,
  "recording_ready": true
}
```

`launch_ready: true` in rehearsal mode only means the local product invariants
passed. A public walkthrough is ready to record only when live mode also writes
`public_launch_ready: true`, `recording_proof_ready: true`, and
`remote_artifacts_ready: true`, and `recording_ready: true`.
The same report must expose a redacted `recording_contract` summary copied from
the central Run Record: every section check is a boolean, `blockers` is empty,
and no raw provider URLs, clipboard values, tokens, logs, screenshots, or
secrets are embedded. The `recording_contract.checks.audit_trail` row may turn
green only when the central audit trail uses exact generated fields, required
source indexes, and wake-event anchors, so loose audit proof cannot briefly make
the control room recordable before live acceptance or cleanup preflight rejects it.
If blockers appear before readiness, live acceptance
requires exact non-empty string blocker values with no padding or duplicates so
the recording-proof recovery list cannot be inflated.
If the central Run Record also embeds an `acceptance` summary, live acceptance
and detonation preflight must validate that its ready flags are literal
booleans, `mode` is `live` or `rehearsal`, `blockers` is a list, and `error` is
a string, including the intermediate `recording_proof_ready` flag and redacted
`missing` proof list. Populated summaries must use the exact generated
top-level fields only, so sidecar acceptance notes cannot support launch proof
or cleanup trust; an empty object remains valid before a report has been
generated, but truthy placeholders cannot support launch proof or cleanup trust.
A populated summary must also keep
`public_launch_ready` tied to `launch_ready`, `recording_ready` tied to
`public_launch_ready`, `remote_artifacts_ready`, `recording_proof_ready`,
exact `live`/`rehearsal` mode, and the Run Record's
`recording_contract.recording_ready`, keep `recording_proof_ready` aligned with
that recording contract, keep missing proof entries trimmed, non-empty, and
unique, keep ready states free of blockers, missing proof, embedded acceptance
errors, or unresolved Run Record errors, require non-empty embedded acceptance
error text to be trimmed, and match the acceptance report formulas exactly:
`public_launch_ready == (mode == "live" and launch_ready)` and
`recording_ready == (public_launch_ready and remote_artifacts_ready and recording_proof_ready)`.
The control room applies the same fail-closed formula when reading refreshed
acceptance reports: top-level `recording_ready`, `recording_proof_ready`, live
public-launch readiness, and `recording_contract.recording_ready` must all agree
before the UI tells a launcher to record the demo.
The public acceptance report artifact uses that same contract-aware formula when
serializing `recording_proof_ready` and `recording_ready`, so a standalone green
Run Record check cannot make the report recordable if the embedded recording
contract is missing or false.
The embedded recording contract must also be shaped, cover the full expected
recording-check set, be all-true, and be blocker-free; a hollow or partial
`{ "recording_ready": true }` object is not public recording proof.
When the control room previews recording-contract cards, it leads with the
public-demo proof story: worker replacement, rehearsal review, model inference,
provider playbook, live verifiers, and detonation.
The effective recording-proof formula also requires
`remote_artifacts.loaded: ok`, so a stale or hand-built report cannot become
recordable without proving the retrieved disposable-worker survivor bundle.
The terminal summary from `fusekit acceptance run` prints the same effective
`recording_proof_ready` value, keeping CLI output aligned with JSON reports, the
control room, and `--require-recording`.
Control-room clipboard capture is allowed enough response time for encrypted
vault writes under load, and disconnected browser clients do not turn successful
server-side writes into noisy tracebacks.

Live mode does not claim provider success without proof. It requires the real encrypted vault,
passphrase unlock proof, redacted setup receipt, redacted audit log, live URL in
the receipt, validated provider packs, complete provider route decisions, clean
leak scan, resolved durable gate state, and detonated worker state. Complete
receipt proof means `raw_secrets_exposed` is literal JSON `0`, not a string,
boolean, or float that can be coerced into zero, and the receipt contains no
callback URLs or credential-looking text. The receipt must also use the generated
public shape only: top-level fields are limited to `app_name`, `vault_path`,
`live_url`, `raw_secrets_exposed`, and `actions`, while each action row uses
`action`, `status`, and optional `details`; `action` and `status` text must be
trimmed, and sidecar receipt notes cannot support launch readiness or cleanup
trust. The receipt envelope, raw-secret counter field, public text fields, action
row fields, and required action text fields must come from one shared
setup-receipt contract used by Run Record audit generation, live acceptance, and
cleanup preflight, so zero-secret receipt proof cannot pass one launch gate with
fields another gate rejects. Complete
vault proof means the vault bundle has no plaintext or credential-looking markers,
unlocks with the supplied passphrase, and rejects an intentionally wrong
passphrase; corrupt or modified bundles are launch blockers, not harness crashes.
The central Run Record's vault summary must also be count-backed public metadata:
`record_count` must match `vault.records`, every record needs trimmed
id/kind/provider/label text, duplicate vault ids are rejected, blank or
credential-looking rows are not written, sidecar fields are rejected, and raw
value/passphrase/private-key/password metadata fields cannot survive in `vault.records`.
The final recording contract
must reject loose vault metadata before `recording_contract.checks.vault` can turn
green: `record_count` is a literal integer, vault and record rows use only the
generated fields, id/kind/provider/label are already trimmed public-safe strings,
and sidecar vault notes are not accepted as proof.
The public vault metadata envelope, record fields, and forbidden raw-secret field
names must come from one shared vault-proof contract used by Run Record recording
checks, live acceptance, and detonation preflight, so credential-capture proof
cannot pass one launch gate with fields another gate would reject.
Detonation preflight also rejects setup-receipt survivors whose
`raw_secrets_exposed` value is missing, nonzero, or not literal JSON `0`, and
rejects vault bundle survivors that contain plaintext or credential-looking
markers before cleanup can destroy the worker state. Cleanup preflight also
validates the same exact Run Record vault metadata shape before trusting worker
destruction: no sidecar vault fields, literal integer counts, trimmed public-safe
record values, and no credential-looking id/kind/provider/label text.
Complete audit proof means `audit.jsonl` is valid JSONL, every row uses only
generated top-level audit fields (`event`, optional `data`, optional `ts`) with a
trimmed event name, and every row is free of callback URLs or credential-looking
text before the redacted audit log can count toward launch readiness. The
standalone audit row fields and generated event/data/timestamp field names must
come from one shared audit-log survivor contract used by live acceptance and
cleanup preflight, so raw audit proof cannot pass one launch gate with fields
another gate rejects. Complete route decisions include the selected route kind, status, deterministic/implemented
flags, reason, and considered candidates, so the control room can explain whether
FuseKit used API automation, secure vault capture, or VM follow-me. When both
model reasoning and provider-page inference are needed, the Run Record must carry
matching `model_inference` and `llm_contract` sections: the public contract must
prove an encrypted API-key lane or encrypted OpenClaw OpenAI authorization,
deny raw secret export, and describe encrypted-vault storage without exposing
the raw model credential. Detonation preflight and live acceptance reject stale or
invented model-readiness claims when the contract and summary disagree on the
provider, model, base URL, API-key env, auth mode, required flags, default lane,
or status, and both gates require shaped auth-lane rows plus a
`model_inference.lane_count` matching `llm_contract.lanes` before launch readiness
or cleanup trust can pass. The non-secret LLM contract module is the canonical
owner of the model-summary, contract, security, and auth-lane key sets consumed
by Run Record generation, live acceptance, and cleanup preflight, so those gates
cannot evolve separate inference-contract shapes. The
`required` and `can_proceed_without_api_key` flags must be literal booleans, and
lane counts must be integer proof, not truthy placeholders. Lane ids,
labels, and descriptions must already be trimmed, and lane ids must be unique so
duplicate auth options cannot inflate proof counts. The selected default lane
and the status-proving encrypted lane must also be available and require no
further user action once the contract claims ready encrypted auth, so public
review cannot confuse an offered auth option with a usable inference path. Model
summary, contract, security, and lane rows must use exact generated fields only,
with trimmed public text and no callback URLs or credential-looking strings, so
sidecar model notes cannot stand in for the explicit inference contract. Recording
readiness also recomputes that paired proof, so a green
`recording_contract.checks.model_inference` cannot come from a summary without
the matching public contract lanes. When both
the prepared runner profile and provider gates are present, the run must prove
the disposable background workstation was ready before the first provider gate:
x86_64 architecture, approved browser spine, Playwright smoke test, noVNC,
shared provider browser profile, helper binaries, vault access, and an
installed-binary inventory for Python, FuseKit runner helpers, OpenClaw,
noVNC/VNC helpers, and Playwright Chromium. The Run
Record's runner profile summary must match `runner_readiness.json`, so stale
or thinner runner claims cannot survive OCI detonation as recording proof.
Generated Run Records canonicalize that runner summary before recording checks
run: only the shared readiness/profile/observed/check/binary fields survive,
VM-local provider-profile, browser-cache, and helper-binary paths become public
labels, and malformed checks or sidecar rows are dropped instead of becoming
public proof.
Detonation preflight must require that same `runner_readiness.json` survivor,
validate the runner contract, and reject drift against the Run Record before
worker destruction is trusted.
Acceptance snapshots of runner readiness must use public profile/cache/binary
labels, and the raw `runner_readiness.json` survivor must fail closed on callback
URLs or credential-looking text before it can support recording readiness. The raw
runner-readiness survivor must also use the generated proof envelope only: top-level
readiness fields, profile-contract fields, browser-stack fields, observed facts,
health-check booleans, and installed-binary rows must have exact fields and
trimmed public strings, with no sidecar runner notes. Those fields, schema/status
values, and expected runner profile must come from the shared runner-readiness
contract used by Run Record generation, live acceptance, and cleanup preflight,
so VM/browser handoff proof cannot pass one launch gate with fields another gate
rejects. Visual
session proof must match FuseKit's generated noVNC artifact shape, including
the expected display and guidance notes, and preserve only the validated
noVNC/control-room transport fields needed for the VM iframe. Any sidecar
`visual.json` metadata, padded generated field, drifted note, or callback-shaped
visual URL must fail closed before visual proof can support recording readiness.
The generated visual-state field set, visual transport fields, runner/status/display
values, and fixed VM-browser guidance notes must come from one shared
visual-state contract used by live acceptance and cleanup preflight, so
VM/browser handoff proof cannot pass one launch gate with fields or guidance
another gate rejects.
The run
journal must also show the control-room path for provider opens, Capture clicks,
setup/DNS approvals, retries, generated provider values, verification, rollback,
and detonation, with raw secrets and provider callback tokens redacted. When both
the manifest and rollback metadata are present, rollback coverage must come from
provider rollback rows whose status is `planned` or `done`; `skipped` rows only
document missing rollback targets and cannot satisfy public launch coverage.
Rollback metadata rows must also use generated public fields only:
`action`, `status`, optional `detail`, and optional `provider` text must already
be trimmed, and sidecar rollback notes cannot support launch readiness or cleanup
trust. The rollback metadata envelope, action row fields, public action text
fields, and accepted proof statuses must come from one shared rollback-proof
contract used by live acceptance and cleanup preflight, so provider rollback
coverage proof cannot pass one launch gate with fields or statuses another gate
rejects.
When both
provider route decisions and launch checkpoints are present, the checkpoint
recovery map must preserve the same provider-route next actions so refreshed
launcher sessions do not regress to generic setup guidance. Provider capability
packs must be structurally valid and public-safe: a callback URL or
credential-looking value in any required pack blocks that provider's pack row and
the aggregate provider-pack readiness gate before setup, route planning, or
verification proof can count. When both
provider route decisions and setup receipts claim an API route succeeded, the
receipt must also prove that the provider's read-only contract-health check
succeeded before the provider setup action, so stale, revoked, or mis-scoped
tokens are routed back through guided capture before mutations. When both
Resend and DNS are present, the provider strategy artifact must prove Resend ran
before Cloudflare/DNS so Resend-generated domain records are included in the
approved DNS changes. The setup receipt must independently prove the same flow:
`resend.domain` succeeds first, returns DNS records, and a later `dns.propose`
action for the same manifest domain contains those exact Resend records. When
the app deploys through Vercel and declares `RESEND_*` runtime variables, the
receipt must also prove that
`vercel.env` configured each required Resend runtime key. Any durable human gate
recorded during the run must include follow-me steps, a plain next action, and a
resume hint, plus matching redacted control-room audit proof, even if the gate
later passed. Human-gate guidance must be launcher-actionable: provider gates
must carry an openable provider URL for `Open provider gate in VM`, provider gates
with URLs must send the user through the VM browser path, copy-once env/token
targets must name exact controls such as `Capture RESEND_API_KEY from VM clipboard`,
and public proof must reject hidden-prompt, side-channel, manual, placeholder, or
figure-it-out wording. Non-secret provider
gates plus setup/DNS approval gates must also prove the visible
`I finished this step`, `Approve setup plan`, or `Approve DNS apply` click through
redacted `control_room.gate_resume_requested` audit events. The Run Record's
wake-event summary must match `gate_events.jsonl`, so Capture and approval audit
entries remain anchored to the raw event stream that woke the worker. The Run
Record and live acceptance must also reject unredacted callback URLs or
credential-looking text in the raw `gates.json` and `gate_events.jsonl`
survivors, not merely in their redacted public summaries. The Run
Record must retain the full redacted audit sequence, not a truncated tail, so
long provider retries and repeated approvals remain reviewable after detonation.
Detonation preflight must require `gates.json` and `gate_events.jsonl` survivors
and compare them against the Run Record's provider-gate and wake-event summaries
before cleanup is trusted. Live acceptance must apply the same raw provider-gate
and wake-event shapes before gate readiness or Run Record signature comparison.
The raw `gates.json` survivor must use generated
provider-gate rows directly: no sidecar fields, trimmed id/provider/status/target
values, list-shaped captured targets and follow steps, and non-negative
attempt/timestamp proof. The raw `gates.json` envelope itself must also come from
the shared gate-proof contract used by `GateService` serialization and cleanup
preflight, so guided-control survivor proof cannot pass cleanup with an artifact
shape the writer did not generate. The raw `gate_events.jsonl` survivor must also use the
generated wake-event row shape directly: no sidecar fields, no padded
event/gate/provider/status/target values, literal target counts, list captured
targets, and non-negative event timestamps.
Those provider-gate and wake-event field sets must come from one shared
gate-proof contract used by Run Record recording checks, live acceptance, and
detonation preflight, so the guided-control handoff cannot pass one launch gate
with a shape another gate would reject.
Live acceptance must also validate the central Run Record's `wake_events`
summary against that same generated shape before comparing it to
`gate_events.jsonl`, so sidecar summary fields, padded event names, malformed
counts, or ignored row metadata cannot support public readiness.
Detonation proof must
cover worker/temp state plus browser profile,
visual-session scratch, OpenClaw/auth state, passphrase files, uploaded app archives,
and FuseKit-controlled control-room/gateway logs; only encrypted or redacted proof
artifacts may survive. The central Run Record must also include
`durable_state` proof showing that the encrypted vault, job state, run state,
checkpoints, gates, gate events, and provider route decisions all survived outside the
disposable worker, so the OCI VM can be replaced or detonated without losing the
run. Each durable-state source id must point at its canonical survivor filename,
so public proof cannot claim `run_state`, `gates`, or other durable sources
through a decoy relative path, and detonation preflight must validate that same
canonical durable-source contract before worker cleanup is trusted. Detonation
preflight must also require the durable-worker statement, no-trace OCI wording,
`oci-visual-browser-x86_64` replacement runner profile, encrypted-vault-and-Run
Record state owner, and volatile-surface coverage before worker cleanup is
trusted. The durable-state schemas, worker-and-OCI detonation scope mode,
no-trace/durable-worker statement terms, and replacement state-owner wording
must come from one shared durable-state contract used by Run Record generation,
live acceptance, automation-boundary proof, and cleanup preflight. Retrieved OCI
artifact inventory must also treat
non-secret durable survivor
files as public proof inputs: `job.json`, `run_state.json`, `checkpoints.json`,
and `worker_replacement_drill.json` must be present and free of callback URLs or
credential-looking text before remote artifacts can support launch readiness.
The raw `run_state.json` survivor must use the generated launch-state contract:
all launch-readiness flags and `ready_to_detonate` are literal booleans,
`updated_at` is numeric, notes and `missing_for_detonation` entries are trimmed
public strings, and no sidecar run-state fields may stand in for durable resume
state.
The central Run Record's embedded `state` must use that same generated
launch-state contract before live acceptance or detonation preflight trusts it,
so hand-edited sidecar fields, stringy readiness flags, padded notes, or unknown
`missing_for_detonation` rows cannot become public launch proof or cleanup trust.
The Run Record envelope itself is also exact: live acceptance and cleanup
preflight use the writer-owned top-level field set and require non-negative
`created_at`/`updated_at` proof, so sidecar launch metadata cannot ride along
beside otherwise valid sections.
Before cleanup trust, proof-bearing Run Record sections such as vault metadata,
provider playbook/routes, runner profile, worker-replacement drill, artifacts,
evidence, verifiers, human actions, rehearsal review, and automation boundary
must be non-empty generated sections, not `{}` or `[]` placeholders.
`job.json` and the generated `checkpoints.json` object must also use exact
runner job, step, checkpoint, artifact, and checkpoint-file fields with trimmed
public text and no sidecar resume notes, so remote resume proof cannot be
hand-edited into a different control-room story. Those job, checkpoint,
run-state, and public survivor label fields must come from the shared
remote-survivor contract used by runner job serialization and live acceptance, so
retrieved OCI proof cannot pass with fields the writer did not generate. The raw
`worker_replacement_drill.json` survivor must also be passed, exact-field,
trimmed, duplicate-free, restored from the durable source ids, and explicit that
no host-machine state or VM-local plaintext was reused; pending drills or sidecar
replacement notes cannot support public recording readiness. The central Run
Record recording checklist uses the same fail-closed bar for raw and embedded
worker-replacement proof, so hidden sidecars, callback URLs, credential-looking
text, or padded restore-source rows cannot be summarized away into a green
recording check. It
is not enough for the central Run Record to be clean: detonation preflight must
also reject callback URLs or credential-looking text in standalone public JSON
survivors such as `audit.jsonl`, the setup receipt, verifier report, rollback
metadata, `llm_contract.json`, and `worker_replacement_drill.json` before worker
cleanup is trusted. Those public JSON survivors must be readable JSON objects,
with artifact-specific parser failures recorded before cleanup can proceed.
The `audit.jsonl` survivor must also contain at least one JSON object row, so a
blank audit file cannot stand in for redacted action evidence.
Detonation preflight must also reject duplicate cleanup proof
rows: repeated control-room mutation routes, remote-worker process targets,
cleanup paths, or worker-replacement `restored_from` source labels cannot make
the disposable-worker cleanup or kill/recreate drill look more complete than it
is. The final recording contract must also reject loose control-room security
proof before the mutation surface can be called recordable: route rows,
state-changing route labels, required protection text, and security statements
must be exact generated fields with no padding or sidecar route notes. Those
route inventory and proof fields must come from one shared control-room security
contract used by the route-surface writer, Run Record recording checks, live
acceptance, and detonation preflight, so no launch gate can drift onto a
separate browser mutation vocabulary. Before cleanup destroys the worker, the
Run Record's `recording_contract`
must already prove every non-detonation recording section; `detonation` is the
explicit lone blocker allowed to remain pending at this preflight stage, and the
recording contract envelope and checklist must contain exact generated fields
only. The blocker list must contain exact non-empty string values with no padding
or duplicates. A shared recording-contract module is the canonical owner of the
schema version, field set, ordered checklist, and proof-section mapping used by the Run Record
writer, control room, live acceptance, and cleanup preflight; cleanup preflight
only omits detonation's own section proof while that final cleanup blocker is
still pending. Any section
marked true in that checklist must have its matching Run Record proof section
present before live acceptance or cleanup preflight can pass, so a hand-shaped
checklist cannot stand in for missing provider playbooks, runner proof,
timeline rows, artifacts, verifiers, evidence, or rehearsal review. The
central Run Record identity must also be shaped before cleanup: id, status,
runner, and a public-label `app_path` must be present, and absolute host or VM
workspace paths cannot stand in for public proof. The embedded launch `state`
must also prove `detonation_safe: true` and carry an explicit boolean
`workspace_detonated` value, so cleanup preflight cannot trust a stale or
truthy run-state placeholder. The Run Record's pre-cleanup `detonation` summary
must mirror that readiness: `preflight_safe` is literal true and
`workspace_detonated` is an explicit boolean, even though final detonation proof
is still the one allowed recording-contract blocker at this stage. The
`errors_empty` check must also match the Run Record's actual `errors` list, so
redacted unresolved failures cannot be hidden behind a green checklist. The
`errors` list itself must be explicit and shaped before cleanup: unresolved rows
need source/id/detail fields and public-safe text, while clean runs carry an
empty list instead of omitting the section. Generated Run Records canonicalize
those unresolved rows before persistence: source, id, and detail are already
redacted and trimmed, blank details use public fallback copy, and duplicate
source/id rows are collapsed so failed runs remain reviewable. Provider
timeline proof must be shaped before cleanup: `steps` and `checkpoints` need
id/label/status fields, unique ids, and public-safe detail, next-action, and
resume-hint text so stale progress rows cannot inflate the launch story. Those
timeline rows must also use exact generated fields only: padded ids, labels,
statuses, details, next actions, resume hints, mascot states, malformed
timestamps, or sidecar timeline notes cannot support cleanup trust or
`recording_contract.checks.timeline`. Generated Run Records preserve
`updated_at` timestamp proof and checkpoint `mascot_state` only after trimming
and redaction, so acceptance and cleanup preflight validate the same shape the
writer emits.
The timeline field sets, required public text fields, optional recovery text
fields, and timestamp field must come from one shared timeline-proof contract
used by Run Record generation, live acceptance, and cleanup preflight, so
recovery proof cannot pass one launch gate with fields another gate rejects.
Provider
playbooks and verifier summaries must be shaped and cover GitHub, Resend,
Vercel, DNS/Cloudflare, and `live_app` before preflight trusts them; placeholder
sections cannot support cleanup. Human-action and rehearsal-review sections must
also be shaped, count-backed, bound to durable provider gates, and matched to
visible control-room instructions before preflight trusts cleanup. Provider-gate
and wake-event summaries must also be count-backed: gate provider/status totals
must match the durable records, central Run Record generation must skip unusable
gate rows and collapse duplicate gate ids before deriving those counts, wake-event
totals must match `gate_events.jsonl` summaries, and every captured gate target
must have matching `clipboard_captured` wake proof before cleanup is trusted. The
final recording contract must reject loose provider-gate proof before
`recording_contract.checks.provider_gates` can turn green: padded gate ids,
providers, statuses, targets, captured targets, or sidecar provider-gate notes
cannot stand in for generated gate rows. Live acceptance applies that same exact
provider-gate bar before public readiness, and cleanup preflight applies that
same exact provider-gate bar before worker destruction: literal integer totals/status counts,
generated-field-only gate rows, trimmed provider/status/target values, trimmed
captured-target/follow-step lists, and
non-negative attempt/timestamp proof. Wake-event summaries must use the generated
event-row shape before recording or cleanup trust: central Run Record generation
must trim/redact event rows, skip token/password/secret marker text, collapse
duplicate event ids/proofs before counting, and emit literal integer totals/counts,
generated-field-only rows, trimmed event/gate/provider/status/target values,
trimmed captured-target lists, integer target counts, and non-negative event
timestamps. Run Record approval summaries must also be
shaped before cleanup: every approval row needs id/provider/status/reason/updated_at,
unique ids, public-safe text, matching durable provider-gate ids/statuses, and a
matching `resume_requested` wake event for approval rows that woke the setup worker.
Approval rows must also use exact generated fields only: padded id/provider/status
or reason text, loose approval rows, and sidecar approval notes cannot support
readiness or cleanup trust. Those row fields, public text fields, timestamp field,
and accepted statuses must come from one shared approval-summary contract used by
Run Record generation, live acceptance, and cleanup preflight, so protected
approval proof cannot pass one launch gate with fields another gate rejects.
Generated Run Records canonicalize approval rows
before persistence by trimming/redacting text fields, filling public provider and
reason fallbacks, collapsing duplicate approval ids, and normalizing malformed
approval timestamps to non-negative values.
The Run Record audit trail must also be
count-backed before cleanup: entries need the `fusekit.audit-trail.v1` schema,
required credential/provider/DNS/approval/detonation categories, matching counts,
wake-event ids for Capture or approval rows, and setup-receipt or audit-log
indexes for provider/action rows. Audit entries must also use exact generated
fields only: padded category/action/status/source/summary/provider/target/resource
text or sidecar audit notes cannot support readiness or cleanup trust. The final
Run Record writer also canonicalizes audit rows at the public proof boundary:
public text is trimmed/redacted, missing generated status/summary text gets a
safe fallback, unsupported categories are dropped, and counts are derived from
that canonical ledger. The shared audit-trail contract is the canonical owner of
the schema version, public envelope, entry-field, and required-category sets consumed by Run
Record recording checks, live acceptance, and cleanup preflight. The final
recording contract also recomputes that exact audit-row proof before
`recording_contract.checks.audit_trail` can pass. The Run Record
automation boundary must also be count-backed before cleanup: entries need the
`fusekit.automation-boundary.v1` schema, ready status, complete VNC allow-list,
matching `fusekit_owned`/`human_gate`/zero-blocked route counts, post-gate API/CLI
and human-gate route lists that match the route inventory, and VNC/API/detonation
boundary wording before detonation preflight trusts the worker can be destroyed.
Generated boundaries derive those counts and post-gate lists from a canonical
ready-route ledger: route text is trimmed/redacted, duplicate `provider:recipe`
rows are collapsed, and unsupported or secret-shaped strategy rows remain in
`provider_strategies` diagnostics instead of entering ready automation proof.
The final recording contract must also reject loose automation-boundary proof:
padded VNC allow-list values, padded route/provider/recipe/owner/status text,
padded post-gate route labels, or sidecar automation notes cannot make
`recording_contract.checks.automation_boundary` turn green.
The automation-boundary envelope, ready/repair statuses, worker-and-OCI
detonation scope label, required statement terms, route fields, count fields,
post-gate lists, VNC allow-list, route owners, and route-kind sets must come
from one shared automation-boundary contract used by Run Record recording
checks, live acceptance, and detonation preflight, so post-gate ownership proof
cannot pass one launch gate with a route vocabulary another gate would reject.
The Run Record
must also include a non-secret
`fusekit.evidence-inventory.v1` inventory
for logs, screenshots, visual state, and receipts by path and type only, so the
demo can prove what happened without embedding screenshots, provider URLs,
clipboard values, or raw secret text. Detonation preflight must reject placeholder
artifact/evidence sections: artifact rows must be unique, public-relative, and
boolean-existence-backed, with `exists: true` artifact paths resolved under the
`.fusekit` survivor bundle, and the evidence inventory must carry matching counts
for logs, visual proof, and receipts before cleanup is trusted. Detonation
preflight must also resolve inventoried log, screenshot, visual, and receipt
paths under the `.fusekit` survivor bundle, so `exists: true` cannot point at an
invented file after OCI cleanup. It must also require `visual.json` itself and
validate the generated noVNC/control-room launch-proof envelope, so a placeholder
or hand-edited visual survivor cannot support worker destruction. Live
acceptance must first prove the required retrieved survivors themselves are
regular files, not directories or path placeholders. Live acceptance must prove
every Run Record artifact row and every inventoried evidence path marked
`exists: true` is a relative file inside the retrieved `.fusekit` artifact bundle
and that inventory counts match the listed records, so stale or invented survivor
paths cannot make a demo look ready. Generated Run Records trim and redact artifact names, skip
secret-looking or credential-query artifact labels and paths, and collapse
duplicate generated artifact names or paths before deriving the evidence
inventory. Generated evidence inventories also canonicalize rows at the final
proof boundary: path and source text is trimmed/redacted, unsafe or secret-shaped
evidence rows are skipped, duplicate paths collapse, and counts come from the
canonical row lists. The shared evidence-inventory contract is the canonical owner
of the schema version, artifact row, evidence envelope, evidence row, and count-key sets consumed by
Run Record recording checks, live acceptance, and cleanup preflight. The final recording contract must reject loose artifact proof
before `recording_contract.checks.artifacts` can turn green: artifact rows must
use exact generated `name`, `path`, and `exists` fields, public-relative paths,
trimmed names, and literal boolean existence flags without sidecar artifact notes
or credential-query text. The final recording contract must also reject loose evidence
inventory proof before `recording_contract.checks.evidence` can turn green:
the inventory schema, counts, statement, row fields, public-relative paths,
trimmed sources, and `exists: true` markers must match generated evidence rows
without sidecar evidence notes. The Run Record must also include a
`fusekit.human-action-trace.v1` summary that maps every recorded provider open,
VM-clipboard Capture, and approval click to a visible control-room gate and its
follow-me instructions, with exact trimmed generated fields and no sidecar
action notes or unguided actions. Generated human-action counts must include the
known visible control buckets (`open_provider_gate`, `capture_vm_clipboard`, and
`confirm_gate_finished`) even when a bucket is zero, and diagnostic/non-visible
wake rows must not become human-action rows. Each action `gate_id` must
exist in the durable provider gate records, and each copy-once Capture target
must match the secret/env target declared by that gate before the final
`recording_contract.checks.human_actions` can turn green, so stale tabs or
wrong-token captures cannot satisfy launch readiness after OCI detonation. Its
`fusekit.rehearsal-review.v1` proof must also carry `reviewed_actions` that
mirror those actions, mark every action matched, and name the non-secret proof
source (`gates.json` and, for wake-driven captures/approvals, `gate_events.jsonl`)
with exact trimmed fields and no sidecar review notes, so a clean rehearsal
remains reviewable after OCI detonation. It
cannot be vacuously empty once provider gates, wake events, or human-gate route
ownership exist: live acceptance, recording readiness, and cleanup preflight must
all require at least one guided human-action row in that case, and generated
Run Records must mark the rehearsal review `needs_review` until that proof
exists, including when the automation-boundary route ledger is the first proof
of human-gate ownership. It
must use one shared rehearsal-proof contract for human-action fields, visible
controls, count buckets, review rows, schema versions, and proof-source mapping,
so Run Record recording checks, live acceptance, and detonation preflight all
judge clean-rehearsal evidence with the same vocabulary. It
must carry the same
provider-strategy contract as the standalone provider route artifact: schema
version, provider list, strategy rows, selected route status, and fallback candidates
with kind/status must be present and match the artifact's route decisions so the
ordered route plan survives OCI detonation without drift. The artifact schema,
provider rows, strategy rows, decision fields, selected-route fields, fallback
candidate fields, and ordered writer field lists must come from one shared
provider-strategy contract used by the CLI artifact writer, Run Record
generation, live acceptance, and detonation preflight. Live acceptance and
cleanup preflight must also
require selected-route `deterministic`, `implemented`, and `reason` evidence plus
follow-me fields for `needs_human_gate` strategies, so the central Run Record
preserves why a route was chosen and what the user sees next. Their route drift
comparison must include selected-route reason/evidence and follow-me fields, not
only route kind/status. Resend API route evidence must explicitly prove FuseKit
owns domain/audience setup, users do not manually create those resources, and
domain setup precedes DNS approval. Generated Run Records canonicalize embedded
provider-strategy route proof before recording checks run: provider, strategy,
decision, selected-route, evidence, and fallback-candidate rows are
trimmed/redacted into the generated shape, sidecar or secret-shaped route data
is dropped, and duplicate fallback candidates collapse by kind/status. The Run
Record's provider playbook must
preserve the same public order: Capture needed provider
tokens, create/reuse Resend resources by API, write Vercel runtime env/deploy
state, then surface DNS approval with the complete app and provider-generated
record set. Cleanup preflight must also reject provider playbook rows whose
actor ownership, visible controls, proof sources, resume events, unsafe
instructions, safety notes, or Resend-before-DNS order do not match live
acceptance, and the steps must use exact trimmed generated fields with no extra
sidecar route-plan notes, even when the standalone survivor carries the same
stale playbook. Safety notes must also remain exact generated text rows: no
padded, duplicated, empty, or object-shaped guidance may stand in for launcher
safety proof. Generated Run Records canonicalize provider-playbook rows before
recording checks run: step text and safety notes are trimmed/redacted, malformed
or secret-shaped rows are dropped, sidecar fields are removed, step counts come
from the canonical rows, and the embedded `provider_strategies.playbook` copy
uses the same public shape. The shared provider-playbook contract is the
canonical owner of the public provider families and exact generated step fields
consumed by Run Record generation, live acceptance, and cleanup preflight, so the
deterministic setup order and public-demo provider coverage cannot drift across
gates.
Its live verifier
summary must likewise match `verification_report.json` provider checks, including
pending-safe status, so green control-room checks survive OCI detonation without
becoming stale display state. The Run Record's embedded `verification` object
must be present, carry shaped verifier check rows with explicit provider, check,
and status fields, and match the same verifier report before live acceptance or cleanup is trusted, so the central proof object
cannot keep stale provider-check rows or ignored malformed check placeholders
after the summary was refreshed. Standalone and embedded verification check rows
must use the shared verification-report contract: the writer owns check-row
fields, required/optional text fields, schema version, status/count vocabulary,
safe statuses, and pending-safe check ids consumed by live acceptance and cleanup
preflight, so verifier proof cannot pass one launch gate with fields or statuses
another gate rejects. Standalone and embedded verification check rows
must also reject padded provider/check/status text, empty generated summary or
repair text, non-object details, and sidecar verifier fields before their
normalized signatures can support public proof. The verifier summary must also include
live-provider-verifier guidance that explains green checks and pending-safe
checks, and each generated summary row must be exact: no padded provider/check
identity, non-boolean pending-safe flags, or sidecar verifier notes may stand in
for live proof. Generated verifier summaries trim/redact public check identity
fields and turn malformed or secret-shaped verifier rows into blocking `unknown`
proof instead of silently hiding them. Skipped verifier rows may document optional checks, but they do not
satisfy public-provider or `live_app` coverage; launch proof requires passed or
explicitly pending-safe verifier rows for each covered provider family. The
shared verifier-summary contract is the canonical owner of the schema version,
public envelope, check-row, and count-key sets consumed by Run Record recording checks, live
acceptance, and cleanup preflight. Live
acceptance and detonation preflight must
reject verifier drift between both central Run Record verifier views and the
standalone verifier report before public readiness or worker cleanup can pass,
and they require any present standalone comparison artifact to be a readable
regular JSON object before central Run Record drift proof can pass. Cleanup
preflight must require shaped central provider-strategy rows with
public provider coverage before it compares `provider_strategies.json` route and
playbook signatures against the central Run Record. The standalone
`provider_strategies.json` survivor must also use the generated artifact shape
before live acceptance or cleanup can pass: no top-level, provider, strategy,
decision, selected-route, candidate, or playbook-step sidecar fields may
normalize into accepted route proof. Worker destruction is trusted only after
both shape and survivor drift checks pass.
Public OCI acceptance also
requires a `fusekit.detonation-scope.v1` proof
that names the complete no-trace destroy set, including provider-auth scratch,
browser profiles, passphrase files, uploaded app archives, control-room logs,
gateway logs, and the disposable OCI workspace. That workspace scope must name
the OCI instance, boot volume, ephemeral public IP, VCN, subnet, internet
gateway, route table, security list, and network security group, while
preserving only encrypted or redacted run artifacts until completion. The worker replacement contract must
reference only named durable-state resume sources, cover the same volatile
surfaces that detonation deletes, and agree with the detonation preserve list so
the public demo cannot rely on hidden local browser profiles, host clipboard
history, or VM scratch state. The Run Record's workspace
detonation receipt must match the standalone `workspace_detonation.json` artifact,
so the public demo cannot claim that the OCI VM, boot volume, worker process, or
network resources were destroyed from stale central state alone. Both the embedded
receipt and the standalone survivor must use the generated workspace-detonation
shape only: top-level receipt fields, resource-summary fields, and
remote-worker cleanup fields must be exact, string rows must already be trimmed,
and sidecar workspace cleanup notes cannot support launch readiness. Generated
Run Records canonicalize the embedded receipt before recording checks run:
cleanup text is trimmed/redacted, resource and survivor lists are deduped,
remote-worker cleanup rows keep only the receipt contract, and unsafe failure
details remain non-empty redacted blockers rather than disappearing. Boot volume
cleanup must be provider-observed deletion proof, not merely the
instance-termination request that asked OCI to delete the volume.
The detonation envelope, workspace receipt fields, resource-summary fields,
remote-worker cleanup fields, and cleanup text/list/boolean groups must come
from one shared detonation-proof contract used by Run Record generation, live
acceptance, and cleanup preflight, so no-trace cleanup proof cannot pass one
launch gate with fields another gate rejects.
The final recording contract must expose `worker_replacement` as its own green
check, separate from general durable-state readiness, so the demo cannot hide an
unproven kill/recreate drill inside a broader status summary. That check requires
redacted
`worker_replacement_drill.json` proof and matching embedded Run Record
`worker_replacement_drill` proof showing the worker was destroyed, a replacement
runner profile was verified, durable source labels were restored, the control
room reopened, and a gate or verifier resumed with
`host_machine_state_required=false` and no VM-local plaintext reuse. Those
restored durable source labels must be unique and must exactly match the worker
replacement source contract. The drill field set must come from the shared
worker-replacement contract used by Run Record generation and live acceptance
for both embedded proof and retrieved remote survivors, so public readiness
cannot depend on a launch gate accepting sidecar replacement fields that another
gate would reject. It must
also agree with the Run Record error list: public demo readiness is false if any
unresolved error remains, even when all other proof sections look shaped
correctly. Error entries themselves must be redacted and shaped as trimmed
source/id/detail records with unique source/id identities; provider callback
URLs, bearer strings, raw tokens, passwords, long secret-like values, and sidecar
error fields are not allowed in the durable Run Record.
The same redaction rule applies to Run Record step and checkpoint timeline text
and provider-gate records, because those recovery surfaces survive OCI detonation
and may be shown in the control room or public review. Timeline rows must use
exact generated fields only before they can support public readiness or
`recording_contract.checks.timeline`: padded ids, labels, statuses, details,
next actions, resume hints, mascot states, malformed timestamps, or sidecar
timeline notes are rejected. Standalone gate and
wake-event survivor files must also fail closed on callback URLs even when those
URLs do not contain obvious token-shaped query values.

## Acceptance Path

Use the most reliable path first:

1. GitHub repo connection and repo secrets/deploy key.
2. Resend API key capture, then Resend domain creation/reuse through the API.
3. Vercel project connection or creation, env vars, deploy, live URL.
4. Cloudflare DNS proposal/apply/verify using app DNS plus Resend-generated records.
5. Optional second segment: Plaid sandbox setup to show broader provider-pack reach.

Plaid should not be the first proof because financial-provider onboarding can
add compliance and review gates that distract from the core launch story.

For a new-site/new-account recording, the control room must make the provider
order obvious enough that the user does not have to infer prerequisites. A
permissioned Resend API key satisfies only the auth gate; FuseKit must then create
or reuse the Resend sending domain by API, create an audience only when the app
requires one, carry the returned Resend DNS records into the Cloudflare approval
plan, and continue without asking the user to manually create Resend domains or
audiences. The provider-routes panel must show this as an ordered Route plan so
the user can follow or watch the lane without deciding whether to click provider
setup controls such as Resend's Add domain button.

## Harness Layer

FuseKit has a native proof layer:

- redacted run ledger
- content-addressed artifact snapshots
- acceptance report with rehearsal/live modes
- provider-pack validation snapshots
- vault public-index proof without raw secrets
- complete provider-route proof for the chosen automation or follow-me path
- redacted durable gate-state proof that every control-room gate was guided and
  no gate remains unresolved
- redacted control-room intervention audit proof for every recorded human gate
- control-room launch-blocker visibility for `blockers[]` recovery actions
- receipt/audit/broad detonation/leak-scan gates

The harness only reports whether the run is public-launch ready. It does not
grant provider access, bypass human gates, or make unverified provider-success claims.
When the report is not launch-ready, `blockers[]` is the plain-language recovery
map for the next demo pass and must be visible in the control room. Embedded
Run Record acceptance blockers must use the same shaped recovery-card fields:
non-empty `item`, `category`, and `next_action` strings plus optional string
`detail` only, with all present fields trimmed and non-empty plus trimmed-unique
`item` values so the recovery map cannot be inflated by duplicate,
whitespace-padded duplicate, empty-detail, or sidecar-field cards.
Those envelope, readiness-boolean, blocker-card, and unresolved-error fields
must come from one shared acceptance-summary contract used by Run Record
generation, live acceptance, and detonation preflight.
Every embedded `missing[]` proof string must also have a matching blocker
`item`, while blockers may additionally represent failed acceptance checks.
