from __future__ import annotations

import re
from pathlib import Path


def test_readme_real_provider_path_names_resend_and_vm_capture() -> None:
    text = Path("README.md").read_text(encoding="utf-8")

    assert "The V1 real path is GitHub + Resend + Vercel + Cloudflare DNS." in text
    assert "Bundled GitHub, Resend, Vercel, and Cloudflare behavior" in text
    assert "RESEND_API_KEY" in text
    assert "exact env-named FuseKit control" in text
    assert "`Capture RESEND_API_KEY from VM clipboard`" in text
    assert "`Capture GITHUB_TOKEN from VM clipboard`" in text
    assert "VM browser `Capture from VM clipboard` buttons" not in text
    assert "VM browser `Capture from VM clipboard` flow" not in text
    assert "one-time `RESEND_API_KEY` capture from the VM" in text
    assert "FuseKit then owns Resend domain/audience setup by API before DNS" in text
    assert "browser surface" not in text.lower()
    assert "matching FuseKit `Capture from VM clipboard` button" not in text


def test_acceptance_runbook_uses_launcher_capture_for_public_recording() -> None:
    text = Path("docs/acceptance-runbook.md").read_text(encoding="utf-8")
    match = re.search(r"```zsh\n(fusekit launch .*?)\n```", text, flags=re.DOTALL)

    assert match is not None
    launch_command = match.group(1)
    assert "--control-room" in launch_command
    assert "--infer-ui" in launch_command
    assert "--capture-stdin" not in launch_command
    assert "exact `Capture <ENV> from VM clipboard`" in text
    assert "not the public no-thinking launcher path" in text
    assert "Public Recording Rules" in text
    assert "Open provider gate in VM" in text
    assert "I finished this step" in text
    assert "Do not paste secrets into the host" in text
    assert "Empty Domains or Audiences" in text
    assert "pages are not a user task" in text
    assert "FuseKit creates or reuses the sending domain" in text
    assert "audience by API" in text
    assert "`Permission: Full access`" in text
    assert "`Domain: All domains`" in text
    assert (
        "A Resend row that says `Permission: Full access` and `Domain: All domains`"
        in text
    )
    assert "is still not enough by itself" in text
    assert "Do not click Resend Add domain or Add audience" in text
    assert "Run Record `model_inference` matches `llm_contract.json`" in text
    assert "encrypted API-key or encrypted OpenClaw lane" in text
    assert (
        "Run `fusekit acceptance run --mode live --remote-artifacts "
        ".fusekit/remote-artifacts --require-recording`" in text
    )
    assert "--require-recording" in text
    assert "`public_launch_ready: true`" in text
    assert "`recording_ready: true`" in text
    assert '"public_launch_ready": true' in text
    assert '"remote_artifacts_ready": true' in text
    assert '"recording_ready": true' in text
    assert "unless a future FuseKit gate" not in text
    assert "unless FuseKit asks" not in text
    assert "Use the control-room VM browser and `Capture from VM clipboard` buttons" not in text


def test_readme_acceptance_evidence_includes_recording_proof() -> None:
    text = Path("README.md").read_text(encoding="utf-8")

    assert '"recording_proof_ready": true' in text
    assert '"recording_ready": true' in text
    assert "--require-recording" in text
    assert "exits nonzero" in text
    assert "accepted only" in text
    assert "with `--mode live` and `--remote-artifacts`" in text
    assert (
        "fusekit acceptance run --mode live --remote-artifacts "
        ".fusekit/remote-artifacts --require-recording"
        in text
    )
    assert "final recording-proof summary events" in text


def test_public_launch_readiness_requires_exact_capture_controls() -> None:
    text = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")

    assert "--require-recording" in text
    assert "makes the command fail unless" in text
    assert "exact controls such as `Capture RESEND_API_KEY from VM clipboard`" in text
    assert "matching `model_inference` and `llm_contract` sections" in text
    assert "`remote_artifacts.loaded: ok`" in text
    assert "deny raw secret export" in text
    assert "encrypted-vault storage" in text
    assert "manual, placeholder, or" in text
    assert "targets must name `Capture from VM clipboard`" not in text


def test_public_docs_require_literal_zero_secret_receipt_count() -> None:
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    friction = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "`raw_secrets_exposed` is literal JSON `0`" in readiness
    assert "not a string" in readiness
    assert "boolean, or float that can be coerced into zero" in readiness
    assert "top-level fields are limited to `app_name`, `vault_path`" in readiness
    assert "sidecar receipt notes cannot support launch readiness" in readiness
    assert "Detonation preflight also rejects setup-receipt survivors" in readiness
    assert "missing, nonzero, or not literal JSON `0`" in readiness
    assert "loose setup-receipt envelopes" in friction
    assert "trimmed public action/status text" in friction
    assert "float such as `0.1` truncate into a false zero-secret proof" in friction
    assert "strings, booleans, floats, or nonzero counts fail" in friction
    assert "did not require the receipt's raw-secret exposure counter" in friction
    assert "block worker destruction" in friction


def test_public_docs_require_proving_rollback_statuses() -> None:
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    normalized_readiness = " ".join(readiness.split())
    friction = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "rollback coverage must come from" in readiness
    assert "status is `planned` or `done`" in readiness
    assert "`skipped` rows only document missing rollback targets" in normalized_readiness
    assert "Rollback metadata rows must also use generated public fields only" in (
        readiness
    )
    assert "sidecar rollback notes cannot support launch readiness" in readiness
    assert "Skipped rollback rows could satisfy provider rollback coverage" in friction
    assert "count only `planned` or `done` rollback rows" in friction
    assert "Rollback metadata could carry padded action/status text" in friction
    assert "reject loose rollback metadata" in friction


def test_friction_log_keeps_resend_recovery_launcher_owned() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "regenerate the Resend runtime gate" not in text
    assert "keep the live launcher/control room open while FuseKit rebuilds" in text
    assert "only `RESEND_API_KEY` uses Capture" in text


def test_friction_log_tracks_generic_capture_fallback_fix() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert (
        "Generic provider, verification, acceptance, and control-room fallback copy"
        in text
    )
    assert "single highlighted launcher gate" in text
    assert "exact env-named Capture button rendered for that gate" in text
    assert "Resend-specific copy names `RESEND_API_KEY` only on real Resend" in text


def test_security_surface_map_names_model_inference_preflight() -> None:
    text = Path("docs/security-surface-map.md").read_text(encoding="utf-8")
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    normalized_readiness = " ".join(readiness.split())

    assert "matching `model_inference`/`llm_contract` proof" in text
    assert "before trusting cleanup" in text
    assert "shaped auth-lane rows" in readiness
    assert "`model_inference.lane_count` matching" in readiness
    assert "Recording readiness also recomputes that paired proof" in normalized_readiness
    assert "`recording_contract.checks.model_inference`" in readiness


def test_friction_log_tracks_model_inference_launch_bar_alignment() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "public launch docs and the security map could still omit" in text
    assert "`llm_contract`/`model_inference` proof" in text
    assert "raw-secret export denied" in text
    assert "same hollow `llm_contract.lanes` proof" in text
    assert "required encrypted-auth lane coverage" in text
    assert "`model_inference.lane_count` matching `llm_contract.lanes`" in text
    assert "recording contract could mark `model_inference` ready" in text
    assert "validates the same paired model/LLM-contract proof" in text


def test_friction_log_tracks_recording_contract_summary_hardening() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "recording-contract check values with truthiness" in text
    assert "literal JSON `true`" in text


def test_oci_runner_lane_defines_prepared_environment_contract() -> None:
    text = Path("docs/oci-runner-lane.md").read_text(encoding="utf-8")

    assert "prepared environment contract" in text
    assert "expected x86_64 architecture" in text
    assert "FuseKit runner helpers" in text
    assert "Chromium smoke-test readiness" in text
    assert "installed-binary inventory" in text
    assert "shared Chrome provider profile" in text
    assert "before the first provider account gate" in text


def test_northstar_background_contract_includes_verified_runner_profile() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Prepared runner profile first" in text
    assert "OpenClaw or the approved browser spine" in text
    assert "installed binary inventory" in text
    assert "noVNC" in text
    assert "must be verified" in text
    assert "before provider gates appear" in text


def test_northstar_defines_detonation_pressure_test() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Detonation Pressure Test" in text
    assert "The product object" in text
    assert "Run Record, not the VM" in text
    assert "Plaintext runtime state dies" in text
    assert "Public recording" in text
    assert "readiness must stay false" in text
    assert "Evented resume beats click-and-hope" in text
    assert "provider-observed boot volume deletion" in text


def test_oci_lane_requires_detonation_survivor_set() -> None:
    text = Path("docs/oci-runner-lane.md").read_text(encoding="utf-8")

    assert "survivor set" in text
    assert "encrypted vault" in text
    assert "Run Record" in text
    assert "redacted artifacts" in text
    assert "resume checkpoints" in text
    assert "no host-machine state required" in text


def test_northstar_pressure_tests_background_agent_objects() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Ona Audit Pressure Test" in text
    assert "Run Record" in text
    assert "Runner Profile Contract" in text
    assert "Provider Playbooks" in text
    assert "Live Verifiers" in text
    assert "Evented Resume" in text
    assert "Disposable Workers, Durable State" in text
    assert "Audit-First UX" in text
    assert "Repeated or stale clicks must be idempotent" in text
    assert "provider-observed boot volume deletion" in text


def test_northstar_defines_background_agent_contract() -> None:
    text = Path("docs/northstar-provider-strategy.md").read_text(encoding="utf-8")

    assert "Background Agent Contract" in text
    assert "prepared, disposable cloud workstation" in text
    assert "Prepared runner profile first" in text
    assert "Deterministic scripts first, guided browser second" in text
    assert "One observable control room" in text
    assert "Event-sourced run journal" in text
    assert "Policy boundaries by default" in text
    assert "Human gates are real gates only" in text


def test_public_launch_readiness_requires_background_agent_evidence() -> None:
    text = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")

    assert "disposable background workstation was ready before the first provider gate" in text
    assert "x86_64 architecture" in text
    assert "approved browser spine" in text
    assert "Playwright smoke test" in text
    assert "installed-binary inventory" in text
    assert "shared provider browser profile" in text
    assert "provider opens, Capture clicks" in text
    assert "raw secrets and provider callback tokens redacted" in text
    assert "generated top-level audit fields" in text
    assert "trimmed event name" in text


def test_friction_log_tracks_runner_verify_prepared_environment_fix() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "wrong architecture or miss noVNC/visual helper binaries" in text
    assert "`fusekit-runner-verify` now fails before provider setup" in text
    assert "Playwright Chromium can launch" in text
    assert "shared Chrome provider profile path exists" in text


def test_friction_log_tracks_visual_query_value_sanitization() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "checking their values" in text
    assert "autoconnect=1" in text
    assert "resize=scale" in text
    assert "reject the visual session before rendering" in text


def test_friction_log_tracks_runner_readiness_artifact() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    security = Path("docs/security-surface-map.md").read_text(encoding="utf-8")
    normalized_readiness = " ".join(readiness.split())
    normalized_security = " ".join(security.split())

    assert "`fusekit-runner-verify` could stop a bad VM" in text
    assert ".fusekit/runner_readiness.json" in text
    assert "artifact retrieval requires it" in text
    assert "live acceptance fails unless the proof shows x86_64" in text
    assert "Playwright Chromium" in text
    assert "shared provider browser profile" in text
    assert "installed-binary inventory" in text
    assert "Runner-readiness survivors could carry padded VM/browser profile text" in text
    assert "loose `runner_readiness.json` proof" in text
    assert "generated proof envelope only" in normalized_readiness
    assert "no sidecar runner notes" in normalized_readiness
    assert "sidecar fields and padded generated strings" in normalized_security


def test_friction_log_tracks_remote_worker_cleanup_proof() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")

    assert "bare `remote_worker` success string" in text
    assert "fusekit.remote-worker-cleanup.v1" in text
    assert "host_machine_state_required=false" in text
    assert "live acceptance fail closed unless that proof is present" in text
    assert "Remote worker cleanup proof" in text
    assert "host-machine state was not required" in text


def test_friction_log_tracks_detonation_survivor_preflight_guards() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    security = Path("docs/security-surface-map.md").read_text(encoding="utf-8")
    normalized_readiness = " ".join(readiness.split())
    normalized_security = " ".join(security.split())

    assert "central Run Record had not yet been written" in text
    assert "local launch writes the current Run Record before cleanup can proceed" in text
    assert "not the raw durable `run_state.json`" in text
    assert "require `.fusekit/run_state.json` before OCI detonation" in text
    assert "raw callback URLs, bearer text, or token-looking strings" in text
    assert (
        "fails closed on credential-looking text while allowing explicitly redacted values" in text
    )
    assert "own durable-secret regex" in text
    assert "one shared `contains_durable_secret_text` helper" in text
    assert "sidecar `checkpoints.json` resume notes" in text
    assert "loose job/checkpoint survivor envelopes" in text
    assert "job, step, checkpoint, artifact, and checkpoint-file rows" in text
    assert "stringy launch-state booleans" in text
    assert "loose `run_state.json` survivors" in text
    assert "hand-edited `worker_replacement_drill.json`" in text
    assert "loose worker-replacement drill survivors" in text
    assert "all launch-readiness flags and `ready_to_detonate`" in normalized_readiness
    assert "no sidecar run-state fields" in normalized_readiness
    assert "pending drills or sidecar replacement notes" in normalized_readiness
    assert "exact runner job, step, checkpoint, artifact" in normalized_readiness
    assert "no sidecar resume notes" in normalized_readiness
    assert "literal boolean readiness flags" in normalized_security
    assert "duplicate-free restored source ids" in normalized_security
    assert "sidecar or padded `job.json` and generated `checkpoints.json`" in (
        normalized_security
    )


def test_public_launch_readiness_tracks_detonation_identity_guards() -> None:
    text = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "Detonation preflight must also reject duplicate cleanup proof rows" in normalized
    assert "repeated control-room mutation routes" in text
    assert "loose control-room security proof" in normalized
    assert "sidecar route notes" in text
    assert "remote-worker process targets" in text
    assert "cleanup paths" in text
    assert "worker-replacement `restored_from` source labels" in text
    assert "restored durable source labels must be unique" in text
    assert "every non-detonation recording section" in text
    assert "`detonation` is the explicit lone blocker allowed" in normalized
    assert "matching Run Record proof section present" in normalized
    assert "before live acceptance or cleanup preflight can pass" in normalized
    assert "timeline rows, artifacts, verifiers, evidence, or rehearsal review" in text
    assert "hand-shaped checklist cannot stand in" in normalized
    assert "embeds an `acceptance` summary" in text
    assert "live acceptance and detonation preflight must validate" in normalized
    assert "ready flags are literal booleans" in normalized
    assert "`blockers` is a list" in text
    assert "truthy placeholders cannot support launch proof or cleanup trust" in normalized
    assert "central Run Record identity must also be shaped before cleanup" in text
    assert "id, status, runner, and a public-label `app_path`" in normalized
    assert "absolute host or VM workspace paths cannot stand in" in normalized
    assert "embedded launch `state`" in text
    assert "`workspace_detonated` value" in text
    assert "Run Record's pre-cleanup `detonation` summary" in text
    assert "`preflight_safe` is literal true" in text
    assert "canonical survivor filename" in text
    assert "decoy relative path" in text
    assert "detonation preflight must validate that same" in normalized
    assert "central Run Record's vault summary must also be count-backed" in text
    assert "`record_count` must match `vault.records`" in text
    assert "duplicate vault ids are rejected" in text
    assert "metadata fields cannot survive in `vault.records`" in text
    assert "`recording_contract.checks.vault`" in text
    assert "sidecar vault notes are not accepted as proof" in text
    assert "same exact Run Record vault metadata shape" in text
    assert "no sidecar vault fields" in text
    assert "no credential-looking id/kind/provider/label text" in text
    assert "durable-worker statement" in text
    assert "`oci-visual-browser-x86_64` replacement runner profile" in text
    assert "encrypted-vault-and-Run Record state owner" in normalized
    assert "volatile-surface coverage" in text
    assert "`errors_empty` check must also match" in text
    assert "actual `errors` list" in text
    assert "`errors` list itself must be explicit and shaped before cleanup" in text
    assert "source/id/detail fields and public-safe text" in text
    assert "empty list instead of omitting the section" in text
    assert "timeline proof must be shaped before cleanup" in text
    assert "`steps` and `checkpoints` need" in text
    assert "unique ids" in text
    assert "public-safe detail, next-action, and" in text
    assert "Provider playbooks and verifier summaries must be shaped" in normalized
    assert "GitHub, Resend, Vercel, DNS/Cloudflare, and `live_app`" in normalized
    assert "Skipped verifier rows may document optional checks" in text
    assert "do not satisfy public-provider or `live_app` coverage" in normalized
    assert "Run Record's embedded `verification` object" in text
    assert "carry shaped verifier check rows" in text
    assert (
        "match the same verifier report before live acceptance or cleanup is trusted"
        in normalized
    )
    assert "ignored malformed check placeholders" in text
    assert "both central Run Record verifier views" in text
    assert "Human-action and rehearsal-review sections must also be shaped" in normalized
    assert "bound to durable provider gates" in text
    assert "Provider-gate and wake-event summaries must also be count-backed" in normalized
    assert "clipboard_captured` wake proof" in normalized
    assert "`recording_contract.checks.provider_gates` can turn green" in normalized
    assert "sidecar provider-gate notes" in text
    assert "same exact provider-gate bar before worker destruction" in text
    assert "literal integer totals/status counts" in text
    assert "non-negative attempt/timestamp proof" in text
    assert "Wake-event summaries must use the generated" in text
    assert "literal integer totals/counts" in text
    assert "non-negative event" in text
    assert "Run Record approval summaries must also be shaped before cleanup" in normalized
    assert "every approval row needs id/provider/status/reason/updated_at" in text
    assert "matching durable provider-gate ids/statuses" in text
    assert "matching `resume_requested` wake event" in text
    assert "loose approval rows" in text
    assert "Approval rows must also use exact generated fields only" in normalized
    assert "Run Record audit trail must also be count-backed" in normalized
    assert "`fusekit.audit-trail.v1` schema" in normalized
    assert "wake-event ids for Capture or approval rows" in normalized
    assert "Audit entries must also use exact generated fields only" in normalized
    assert "sidecar audit notes cannot support readiness or cleanup trust" in normalized
    assert "generated top-level audit fields" in text
    assert "trimmed event name" in text
    assert "`recording_contract.checks.audit_trail` can pass" in normalized
    assert "loose audit proof cannot briefly make the control room recordable" in normalized
    assert "automation boundary must also be count-backed" in normalized
    assert "`fusekit.automation-boundary.v1` schema" in normalized
    assert "complete VNC allow-list" in text
    assert "zero-blocked route counts" in text
    assert "post-gate API/CLI" in text
    assert "loose automation-boundary proof" in text
    assert "`recording_contract.checks.automation_boundary` turn green" in normalized
    assert "Detonation preflight must reject placeholder" in normalized
    assert "artifact rows must be unique, public-relative" in normalized
    assert "`exists: true` artifact paths resolved" in normalized
    assert "evidence inventory must carry matching counts" in normalized
    assert "preflight must also resolve inventoried log" in normalized
    assert "`exists: true` cannot point at an invented file" in normalized
    assert "Live acceptance must prove every Run Record artifact row" in normalized
    assert "relative file inside the retrieved `.fusekit` artifact bundle" in normalized
    assert "`recording_contract.checks.artifacts` can turn green" in normalized
    assert "sidecar artifact notes" in text
    assert "`recording_contract.checks.evidence` can turn green" in normalized
    assert "sidecar evidence notes" in text
    assert "recording_contract.checks.human_actions" in text
    assert "wrong-token captures cannot satisfy launch readiness" in text
    assert "`worker_replacement_drill.json` proof and matching embedded Run Record" in text
    assert "`worker_replacement_drill` proof showing the worker was destroyed" in text


def test_friction_log_tracks_detonation_identity_guards() -> None:
    text = Path("docs/magic-path-friction-log.md").read_text(encoding="utf-8")
    readiness = Path("docs/public-launch-readiness.md").read_text(encoding="utf-8")
    normalized_readiness = " ".join(readiness.split())

    assert "Set-based cleanup checks" in text
    assert "one unambiguous proof row per cleanup boundary" in text
    assert "duplicate control-room mutation routes" in text
    assert "trusted hand-edited route counters" in text
    assert "integer `route_count` and `state_changing_route_count`" in text
    assert "remote-worker process/path cleanup rows" in text
    assert "worker-replacement `restored_from` labels" in text
    assert (
        "`detonation` as the explicit only allowed pre-cleanup "
        "recording-contract blocker"
        in text
    )
    assert "loose recording-contract blocker rows" in text
    assert (
        "exact non-empty string values with no padding or duplicates"
        in normalized_readiness
    )
    assert "not named as malformed recording proof" in text
    assert "before public recording proof can pass" in text
    assert "recording-proof recovery list cannot be inflated" in readiness
    assert "final recording contract could mark `control_room_security` ready" in text
    assert "Recording readiness now rejects loose control-room security proof" in text
    assert "checks section drift" in text
    assert "matching Run Record proof section present" in text
    assert "green `recording_contract` section booleans" in text
    assert "empty timeline or artifact list" in text
    assert "before public readiness can pass" in text
    assert "scalar placeholder" in text
    assert "non-empty objects or lists" in text
    assert "durable replacement intent" in text
    assert "embedded Run Record `worker_replacement_drill` section" in text
    assert "extra sidecar notes" in text
    assert "exact trimmed generated fields and no sidecar" in readiness
    assert "padded visible-control text or extra sidecar review notes" in text
    assert "exact trimmed fields and no sidecar review notes" in readiness
    assert "central Run Record with only an id" in text
    assert "public app identity was missing" in text
    assert "public-label app path" in text
    assert "truthy launch-state proof" in text
    assert "stale embedded `verification` object" in text
    assert "`state.detonation_safe` to be literal true" in text
    assert "`state.workspace_detonated` to be an explicit boolean" in text
    assert "Embedded acceptance blockers could be scalar placeholders" in text
    assert "non-empty `item`, `category`, and `next_action` strings" in text
    assert "Duplicate or whitespace-padded duplicate embedded acceptance blocker cards" in text
    assert "trimmed-unique `item` values" in normalized_readiness
    assert "extra sidecar fields" in text
    assert "`detail` only" in readiness
    assert "shaped recovery-card fields" in readiness
    assert "whitespace-padded embedded acceptance `mode`" in text
    assert "exact `live`/`rehearsal` mode" in readiness
    assert "embedded Run Record verification signatures" in text
    assert "malformed extra check rows" in text
    assert "validates the embedded `verification` object" in text
    assert "hollow Run Record `detonation` object" in text
    assert "`detonation.preflight_safe` to be literal true" in text
    assert "`detonation.workspace_detonated` to be an explicit boolean" in text
    assert "Workspace detonation receipts could carry padded cleanup status" in text
    assert "loose workspace-detonation receipts" in text
    assert "generated workspace-detonation shape only" in normalized_readiness
    assert "sidecar workspace cleanup notes cannot support launch readiness" in readiness
    assert "embedded `acceptance` summary could carry stringy ready flags" in text
    assert "empty `acceptance` object as pre-report state" in text
    assert "require the section to exist" in text
    assert "non-empty embedded acceptance summary" in text
    assert "stale but well-shaped embedded `acceptance` summary" in text
    assert "aligned with `recording_contract.recording_ready`" in text
    assert "without preserving the report mode" in text
    assert "summaries to declare `live`" in text
    assert "dropped `recording_proof_ready`" in text
    assert "required by `recording_ready`" in text
    assert "dropped the report's `missing[]` proof list" in text
    assert "preserves redacted `missing` proof strings" in text
    assert "blank or duplicate entries" in text
    assert "missing proof entries trimmed, non-empty, and" in readiness
    assert "recovery strings could carry surrounding whitespace" in text
    assert "blocker-card text fields to be already trimmed" in text
    assert "empty embedded blocker `detail` fields" in text
    assert "empty-detail" in readiness
    assert "missing evidence without a matching recovery card" in text
    assert "Every embedded `missing[]` proof string must also have a matching blocker" in (
        readiness
    )
    assert "derived readiness formulas" in text
    assert "recompute the same readiness formulas as the report object" in text
    assert "stale embedded `acceptance.error` string" in text
    assert "embedded acceptance errors to be empty" in text
    assert "whitespace-only or padded" in text
    assert "trimmed non-empty text" in text
    assert "loose acceptance-report recovery fields" in text
    assert "canonicalize embedded proof at write time" in text
    assert "unresolved Run Record `errors[]` row could coexist" in text
    assert "while unresolved Run Record errors remain" in text
    assert "duplicate source/id error identities" in text
    assert "trimmed source/id/detail records with unique source/id identities" in (
        normalized_readiness
    )
    assert "`recording_ready` tied to" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "intermediate `recording_proof_ready` flag" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "redacted\n`missing` proof list" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "`mode` is `live` or `rehearsal`" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "`public_launch_ready`, `remote_artifacts_ready`, `recording_proof_ready`" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "keep `recording_proof_ready` aligned" in Path(
        "docs/public-launch-readiness.md"
    ).read_text(encoding="utf-8")
    assert "ready states free of blockers, missing proof, embedded acceptance errors" in (
        normalized_readiness
    )
    assert "or unresolved Run Record errors" in normalized_readiness
    assert '`public_launch_ready == (mode == "live" and launch_ready)`' in readiness
    assert (
        "`recording_ready == (public_launch_ready and remote_artifacts_ready "
        "and recording_proof_ready)`"
        in readiness
    )
    assert "public launch readiness or cleanup trust can pass" in text
    assert "rejects `errors_empty` drift" in text
    assert "actual Run Record `errors` list" in text
    assert "missing or malformed Run Record `errors` section" in text
    assert "explicit `errors` list" in text
    assert "validates unresolved error rows for source/id/detail fields" in text
    assert "timeline proof from non-empty `steps` or `checkpoints` lists" in text
    assert "missing id/label/status" in text
    assert "public-safe detail/next-action/resume-hint text" in text
    assert "loose timeline rows" in text
    assert "Timeline rows must use exact generated fields only" in normalized_readiness
    assert "`recording_contract.checks.timeline`" in readiness
    assert "malformed timestamps" in readiness
    assert "final recording contract could mark `timeline` ready" in text
    assert "Recording readiness now rejects loose timeline proof" in text
    assert "truthy `pending_safe` verifier details" in text
    assert "literal JSON `true` for top-level or nested `pending_safe`" in text
    assert "placeholder provider playbook or verifier summary" in text
    assert "GitHub, Resend, Vercel, DNS/Cloudflare, and `live_app` coverage" in text
    assert "stale gate id or captured a token target" in text
    assert "binds each guided human-action row to `provider_gates.records`" in text
    assert "final recording contract could mark `provider_gates` ready" in text
    assert "Recording readiness now rejects loose provider-gate proof" in text
    assert "Detonation preflight could still trust looser provider-gate proof" in text
    assert "Cleanup preflight now applies the same exact provider-gate bar" in text
    assert "could trust wake-event summaries after normalizing" in text
    assert (
        "Recording readiness and cleanup preflight now require generated-field-only "
        "wake-event rows"
    ) in text
    assert "raw `gate_events.jsonl` survivor could still contain sidecar" in text
    assert "validates every raw `gate_events.jsonl` row" in text
    assert "raw `gates.json` survivor could still contain sidecar" in text
    assert "validates raw `gates.json` provider-gate rows" in text
    assert "Placeholder `human_actions` or `rehearsal_review` sections" in text
    assert "count-backed human-action traces bound to durable provider gates" in text
    assert "non-empty approval list before cleanup" in text
    assert "anonymous, duplicated, unsafe, or drifted from durable gate" in text
    assert "wake-event anchors" in text
    assert "Placeholder `audit_trail` sections" in text
    assert "setup-receipt/audit indexes" in text
    assert "loose audit-trail entries" in text
    assert "sidecar audit notes" in text
    assert "final recording contract could mark `audit_trail` ready" in text
    assert "Recording readiness now recomputes exact audit-row proof" in text
    assert "Placeholder `automation_boundary` sections" in text
    assert "complete VNC allow-list" in text
    assert "post-gate API/CLI versus human-gate route lists" in text
    assert "final recording contract could mark `automation_boundary` ready" in text
    assert "padded VNC allow-list values" in text
    assert "non-empty Run Record `vault` section" in text
    assert "unique vault ids" in text
    assert "recursive raw value/passphrase/private-key/password field exclusion" in text
    assert "final recording contract could mark `vault` ready" in text
    assert "Recording readiness now rejects loose vault metadata" in text
    assert "sidecar vault proof is refused" in text
    assert "Detonation preflight still trusted looser Run Record vault metadata" in text
    assert "Cleanup preflight now applies the same exact vault bar" in text
    assert "Placeholder provider-gate or wake-event summaries" in text
    assert "captured-target wake consistency" in text
    assert "Placeholder artifact or evidence sections" in text
    assert "requires `fusekit.evidence-inventory.v1` logs" in text
    assert "artifact rows marked `exists: true`" in text
    assert "Live acceptance could validate Run Record artifact-row shape" in text
    assert "before public launch readiness can pass" in text
    assert "rejects invented artifact files" in text
    assert "final recording contract could mark `artifacts` ready" in text
    assert "Recording readiness now rejects loose artifact proof" in text
    assert "evidence rows marked `exists: true`" in text
    assert "rejects invented files before worker destruction" in text
    assert "final recording contract could mark `evidence` ready" in text
    assert "Recording readiness now rejects loose evidence inventory proof" in text
    assert "Detonation preflight checked the Run Record verifier summary" in text
    assert "compares normalized verifier signatures" in text
    assert "embedded redacted `verification` object" in text
    assert "both Run Record verifier views" in text
    assert "mechanically green verifier summary" in text
    assert "same live-verifier guidance statement" in text
    assert "Standalone verification reports could mark anonymous rows as passed" in text
    assert "requires every check row to name provider, check, and status" in text
    assert "Skipped verifier rows could satisfy public provider coverage" in text
    assert "count only passed or explicitly pending-safe verifier rows" in text
    assert "Detonation preflight trusted the central provider strategy/playbook proof" in text
    assert "requires `provider_strategies.json`" in text
    assert "compares normalized provider route and playbook signatures" in text
    assert "provider strategy signatures while ignoring malformed central route rows" in text
    assert "selected statuses, or fallback candidates" in text
    assert "validates the central `provider_strategies` schema" in text
    assert "fallback candidates could be present but hollow" in text
    assert "object with non-empty kind and status" in text
    assert "omitted the live route-decision evidence users rely on" in text
    assert "deterministic/implemented booleans, route reasons" in text
    assert "follow_steps, next_action, resume_hint" in text
    assert "Live acceptance could validate central provider-strategy presence" in text
    assert "selected-route deterministic/implemented/reason" in text
    assert "route signatures including reason/evidence/follow-me fields" in text
    assert "Resend API route that looked deterministic" in text
    assert "same Resend selected-route evidence as live acceptance" in text
    assert "loose standalone and embedded verification rows" in text
    assert "reject padded provider/check/status text" in readiness
    assert "provider playbook signatures while ignoring stale route semantics" in text
    assert "wrong actor ownership, generic Capture controls" in text
    assert "generic Capture controls, wrong proof sources" in text
    assert "loose verifier-summary rows" in text
    assert "no padded provider/check" in readiness
    assert "applies the live provider-playbook actor, control" in text
    assert "extra sidecar route-plan notes" in text
    assert "loose provider-playbook safety-note rows" in text
    assert "raw `provider_strategies.json` survivor could carry sidecar" in text
    assert "Live acceptance and cleanup preflight now validate" in text
    assert "standalone provider-strategy artifact shape" in text
    assert "selected-route, candidate, and embedded playbook-step rows" in text
    assert "exact trimmed generated fields" in readiness
    assert "Safety notes must also remain exact generated text rows" in readiness
    assert "shaped central provider-strategy rows" in readiness
    assert "actor ownership, visible controls, proof sources" in readiness
    assert "selected-route `deterministic`, `implemented`, and `reason`" in readiness
    assert (
        "Their route drift comparison must include selected-route reason/evidence"
        in normalized_readiness
    )
    assert "fallback candidates with kind/status" in normalized_readiness
    assert "Resend API route evidence must explicitly prove FuseKit owns" in (
        normalized_readiness
    )
    assert "standalone `provider_strategies.json` survivor must also use" in (
        normalized_readiness
    )
    assert "before live acceptance or cleanup can pass" in normalized_readiness
    assert "no top-level, provider, strategy, decision, selected-route" in (
        normalized_readiness
    )
    assert "live-provider-verifier guidance" in readiness
    assert "explicit provider, check, and status fields" in normalized_readiness
    assert "Detonation preflight trusted the Run Record runner profile" in text
    assert "requires `runner_readiness.json`" in text
    assert "validates the shared runner-readiness contract" in text
    assert "Detonation preflight trusted the Run Record provider-gate" in text
    assert "requires `gates.json` and `gate_events.jsonl`" in text
    assert "compares gate/wake signatures" in text
    assert "raw `gate_events.jsonl` survivor must also use" in readiness
    assert "raw `gates.json` survivor must use generated" in readiness
    assert "list-shaped captured targets and follow steps" in readiness
    assert "no sidecar fields" in readiness
    assert "truthy artifact existence values" in text
    assert "`exists` is literal JSON `true`" in text
    assert "different relative file" in text
    assert "canonical survivor filename" in text
    assert (
        "Detonation preflight could still trust a Run Record with drifted "
        "durable-source paths"
        in text
    )
    assert "thinner worker-replacement contract than live acceptance" in text
    assert "exact replacement runner profile" in text
    assert "plaintext VM scratch exclusion" in text
    assert "Live acceptance, Run Record, and detonation preflight counters" in text
    assert "truncated floats" in text
    assert "Counter parsing now accepts only integers or integer strings" in text
