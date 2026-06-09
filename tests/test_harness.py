from __future__ import annotations

import json
from pathlib import Path

from fusekit.cli import main
from fusekit.harness import run_acceptance
from fusekit.harness.acceptance import (
    AcceptanceCheck,
    AcceptanceReport,
    _acceptance_blockers,
    _check_detonation,
    _check_visual_state,
    _gate_open_audit_event_proves_vm_open,
    _gate_resume_audit_requirements,
    _provider_strategy_checkpoint_failures,
    _provider_strategy_shape_failures,
    _rollback_provider_names,
    _unguided_gates,
)
from fusekit.harness.ledger import HarnessLedger
from fusekit.runner.gate_guidance import provider_gate_guidance
from fusekit.runner.gates import GateService
from fusekit.vault import Vault


def _strategy_decision(
    kind: str = "api",
    status: str = "available",
    *,
    evidence: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "selected": {
            "kind": kind,
            "status": status,
            "deterministic": True,
            "implemented": True,
            "reason": "deterministic provider API is available",
            "evidence": evidence or {},
        },
        "candidates": [
            {
                "kind": kind,
                "status": status,
                "deterministic": True,
                "implemented": True,
                "reason": "deterministic provider API is available",
            }
        ],
    }


def _resend_domain_strategy_decision() -> dict[str, object]:
    return _strategy_decision(
        evidence={
            "api_owns": "domain",
            "user_manual_domain_step": "false",
            "downstream_order": "before_dns_apply",
        }
    )


def _resend_audience_strategy_decision() -> dict[str, object]:
    return _strategy_decision(
        evidence={
            "api_owns": "audience",
            "user_manual_audience_step": "false",
            "conditional": "only_when_app_requires_audience",
        }
    )


def _gate_guidance_fields(provider: str) -> dict[str, list[str]]:
    guidance = provider_gate_guidance(provider)
    return {
        "success_criteria": list(guidance.success),
        "avoid_steps": list(guidance.avoid),
    }


def _write_resend_cloudflare_manifest(app: Path) -> None:
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_resend_vercel_manifest(app: Path) -> None:
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env:
  - RESEND_API_KEY
  - RESEND_FROM_EMAIL
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
  - provider: vercel
    kind: hosting
    name: hosting
    capabilities: []
    secrets: []
    settings: {}
domains: []
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_minimum_live_artifacts(remote_fusekit: Path) -> None:
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")


def _write_minimum_resend_vercel_live_artifacts(remote_fusekit: Path) -> None:
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {"provider": "resend", "status": "passed"},
                    {"provider": "vercel", "status": "passed"},
                    {"provider": "live_app", "status": "passed"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.resend.domain", "status": "planned"},
                    {"action": "rollback.vercel.env", "status": "planned"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-env",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")


def _provider_pack_api_setup_action(provider: str, recipe: str) -> dict[str, object]:
    return {
        "action": "provider_pack.setup",
        "status": "ok",
        "details": {
            "provider": provider,
            "setup": [
                {
                    "kind": recipe,
                    "status": "ok",
                    "strategy_decision": _strategy_decision(),
                }
            ],
        },
    }


def test_rollback_provider_names_accepts_current_and_legacy_dns_actions() -> None:
    providers = _rollback_provider_names(
        [
            {"action": "rollback.cloudflare.dns", "status": "planned"},
            {"action": "rollback.dns.cloudflare", "status": "planned"},
            {"action": "rollback.resend.domain", "status": "planned"},
        ]
    )

    assert providers == {"cloudflare", "resend"}


def test_acceptance_rehearsal_writes_ledger_and_report(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="rehearsal")

    assert report.launch_ready is True
    assert (app / "fusekit.yaml").exists()
    assert (app / ".fusekit" / "acceptance" / "ledger.jsonl").exists()
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["blockers"] == []
    assert any(check["id"] == "manifest.scanned" for check in report_json["checks"])


def test_acceptance_report_serializes_public_paths(tmp_path) -> None:
    app = tmp_path / "app"
    artifact = app / ".fusekit" / "acceptance" / "artifacts" / "gates.json"
    report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=False,
        checks=(AcceptanceCheck("gates.resolved", "failed", "Needs repair.", str(artifact)),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert str(tmp_path) not in text
    assert payload["app_path"] == "app"
    assert payload["ledger_path"] == ".fusekit/acceptance/ledger.jsonl"
    assert payload["report_path"] == ".fusekit/acceptance/report.json"
    assert payload["checks"][0]["artifact"] == ".fusekit/acceptance/artifacts/gates.json"


def test_harness_ledger_records_public_artifact_paths(tmp_path) -> None:
    ledger = HarnessLedger.create(tmp_path / "app" / ".fusekit" / "acceptance")

    artifact = ledger.snapshot_json("provider proof", {"ok": True})
    ledger_text = (tmp_path / "app" / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )

    assert artifact.exists()
    assert str(tmp_path) not in ledger_text
    assert ".fusekit/acceptance/artifacts/provider-proof" in ledger_text


def test_harness_ledger_snapshot_redacts_public_token_shapes(tmp_path) -> None:
    ledger = HarnessLedger.create(tmp_path / "app" / ".fusekit" / "acceptance")

    artifact = ledger.snapshot_json(
        "provider callback",
        {
            "url": "https://provider.example/callback?code=secret-code-1234567890&state=ok",
            "notes": [
                "copied github_pat_abcdefghijklmnopqrstuvwxyz1234567890",
                str(tmp_path / "app" / ".fusekit" / "acceptance" / "report.json"),
            ],
        },
    )
    text = artifact.read_text(encoding="utf-8")

    assert "secret-code-1234567890" not in text
    assert "github_pat_abcdefghijklmnopqrstuvwxyz1234567890" not in text
    assert str(tmp_path) not in text
    assert "code=[redacted]" in text
    assert "[redacted]" in text
    assert ".fusekit/acceptance/report.json" in text


def test_acceptance_detonation_blocks_browser_visual_scratch(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    (fusekit_dir / "browser" / "Default").mkdir(parents=True)
    (fusekit_dir / "browser" / "Default" / "Cookies").write_text(
        "session cookie", encoding="utf-8"
    )
    (fusekit_dir / "visual").mkdir()
    (fusekit_dir / "visual" / "x11vnc.log").write_text("visual log", encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-1].id == "detonation.worker_state"
    assert checks[-1].status == "failed"
    assert "worker/browser/visual state" in checks[-1].detail
    assert "browser" in checks[-1].detail
    assert "visual" in checks[-1].detail
    assert str(tmp_path) not in checks[-1].detail
    assert "detonated worker state" in missing


def test_acceptance_detonation_allows_redacted_survivor_artifacts(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    for name in (
        "visual.json",
        "fusekit.vault.json",
        "audit.jsonl",
        "setup_receipt.json",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
        "gates.json",
    ):
        (fusekit_dir / name).write_text("{}", encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-1].id == "detonation.worker_state"
    assert checks[-1].status == "ok"
    assert "browser, visual, and auth scratch" in checks[-1].detail
    assert missing == []


def test_acceptance_rejects_unsafe_visual_state_survivor(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": (
                    "http://203.0.113.10:6080/vnc.html"
                    "?autoconnect=1&password=leaked#frag"
                ),
                "control_room_url": "http://evil.example:8765/?token=stolen",
                "novnc_password": "bad\npassword",
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "noVNC URL" in checks[-1].detail
    assert "control-room URL" in checks[-1].detail
    assert "noVNC password metadata" in checks[-1].detail
    assert "leaked" not in checks[-1].detail
    assert "stolen" not in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_allows_sanitized_visual_state_survivor(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": "http://203.0.113.10:6080/vnc.html?autoconnect=1&resize=scale",
                "control_room_url": "http://203.0.113.10:8765/?token=viewer-token",
                "novnc_password": "viewer-password",
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "ok"
    assert missing == []
    snapshot = Path(checks[-1].artifact).read_text(encoding="utf-8")
    assert "password=" not in snapshot
    assert "viewer-password" not in snapshot
    assert "[REDACTED sha256:" in snapshot


def test_acceptance_gate_guidance_rejects_hidden_prompt_or_wrong_button() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.custom.authorization",
                "provider": "custom",
                "status": "passed",
                "resume_url": "https://provider.example/token",
                "target": "CUSTOM_API_KEY",
                "follow_steps": [
                    "Open the provider page and paste into FuseKit's hidden prompt."
                ],
                "next_action": "Click I finished this step after copying CUSTOM_API_KEY.",
                "resume_hint": "FuseKit will retry verification.",
            }
        ]
    )

    assert any("hidden prompt" in item for item in failures)
    assert any("Capture from VM clipboard" in item for item in failures)
    assert any("secret targets at I finished this step" in item for item in failures)


def test_acceptance_gate_guidance_rejects_local_browser_side_channel() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Use your local browser tab to copy the token.",
                    "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_gate_guidance_allows_local_browser_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Do not use a local browser tab for this gate.",
                    (
                        "Copy the token inside the VM browser and click "
                        "Capture from VM clipboard."
                    ),
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert failures == []


def test_acceptance_gate_guidance_rejects_bad_success_or_avoid_panels() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Copy the token inside the VM browser.",
                    "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": [
                    "If the VM browser is busy, use a local browser tab to finish setup."
                ],
                "avoid_steps": [
                    "Manually create extra webhook integrations if verification stalls."
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)
    assert any("manual action" in item for item in failures)


def test_acceptance_gate_guidance_rejects_affirmative_manual_setup() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.custom.authorization",
                "provider": "custom",
                "status": "passed",
                "classification": "provider-verification",
                "resume_url": "https://provider.example/setup",
                "target": "",
                "follow_steps": [
                    "Click Open provider gate in VM so the provider opens in the VM browser.",
                    "Manually create the provider integration in the dashboard.",
                    "Click I finished this step after setup is done.",
                ],
                "next_action": "Click I finished this step after manual setup.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["The provider integration is created."],
                "avoid_steps": ["Do not paste secrets into chat."],
            }
        ]
    )

    assert any("manual action" in item for item in failures)


def test_acceptance_gate_guidance_allows_negated_manual_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "passed",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    "No manual Resend domain or DNS step is needed here.",
                    "Do not manually create moonlite.rsvp in Resend for this step.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": (
                    "No manual Resend domain work is needed. Click I finished this step "
                    "so FuseKit retries Resend domain setup through the API."
                ),
                "resume_hint": "FuseKit will rerun Resend API setup before Cloudflare DNS.",
                "success_criteria": ["FuseKit owns the Resend setup retry."],
                "avoid_steps": ["Do not click Add domain."],
            }
        ]
    )

    assert failures == []


def test_acceptance_provider_gates_require_openable_resume_url() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    (
                        "Copy the token inside the VM browser and click "
                        "Capture from VM clipboard."
                    ),
                ],
                "next_action": "No action needed.",
                "resume_hint": "FuseKit verified this gate as passed.",
            }
        ]
    )

    assert any(
        item.startswith("provider.github.authorization missing resume_url")
        for item in failures
    )


def test_acceptance_rejects_resend_generated_values_as_capture_targets() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.runtime-values",
                "provider": "resend",
                "status": "passed",
                "classification": "provider-runtime-values",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY,RESEND_FROM_EMAIL,RESEND_AUDIENCE_ID",
                "follow_steps": [
                    "Copy the API key inside the VM browser and click Capture from VM clipboard."
                ],
                "next_action": "No action needed.",
                "resume_hint": "FuseKit verified this gate as passed.",
            }
        ]
    )

    assert (
        "provider.resend.runtime-values.target asks the user to capture "
        "API-generated Resend values: RESEND_AUDIENCE_ID, RESEND_FROM_EMAIL"
    ) in failures


def test_acceptance_resume_audit_is_required_for_non_secret_gate_clicks() -> None:
    requirements = _gate_resume_audit_requirements(
        [
            {
                "id": "provider.cloudflare.domain-review",
                "provider": "cloudflare",
                "classification": "provider-verification",
                "target": "",
            },
            {
                "id": "dns.moonlite.rsvp.approval",
                "provider": "dns",
                "classification": "dns-approval",
                "target": "",
            },
            {
                "id": "provider.resend.api-key",
                "provider": "resend",
                "classification": "provider-authorization",
                "target": "RESEND_API_KEY",
            },
        ]
    )

    assert requirements == [
        "provider.cloudflare.domain-review",
        "dns.moonlite.rsvp.approval",
    ]


def test_acceptance_provider_gate_open_proof_requires_non_reused_launch() -> None:
    base_event = {
        "event": "control_room.gate_open",
        "data": {
            "gate_id": "provider.cloudflare.authorization",
            "reused": False,
            "has_resume_url": True,
            "has_last_opened_url": True,
        },
    }
    reused_event = {
        **base_event,
        "data": {
            **base_event["data"],
            "reused": True,
        },
    }

    assert _gate_open_audit_event_proves_vm_open(base_event) is True
    assert _gate_open_audit_event_proves_vm_open(reused_event) is False


def test_acceptance_human_strategy_guidance_must_be_launcher_actionable() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "custom",
                "strategies": [
                    {
                        "status": "needs_human_gate",
                        "target": "CUSTOM_API_KEY",
                        "follow_steps": ["Figure out the token page yourself."],
                        "next_action": "Paste into FuseKit after manual setup.",
                        "resume_hint": "Retry later.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("non-launcher wording" in item for item in failures)
    assert any("VM browser path" in item for item in failures)
    assert any("Capture from VM clipboard" in item for item in failures)


def test_acceptance_human_strategy_rejects_local_browser_side_channel() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so GitHub opens in "
                                "the VM browser."
                            ),
                            "Use a local browser tab to create the token.",
                            "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_human_strategy_rejects_bad_success_or_avoid_panels() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so GitHub opens in "
                                "the VM browser."
                            ),
                            "Copy the token inside the VM browser.",
                            "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "success_criteria": [
                            "Use your local browser tab if the VM browser is slow."
                        ],
                        "avoid_steps": ["Manually add provider secrets if capture fails."],
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)
    assert any("manual action" in item for item in failures)


def test_acceptance_checkpoint_guidance_rejects_side_channels() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": "Use your local browser tab to create the token.",
                "resume_hint": "Manually add provider secrets if the route fails.",
            }
        ],
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_checkpoint_guidance_requires_open_gate_control() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"cloudflare": {"cloudflare-consent"}},
        [
            {
                "id": "provider.cloudflare.routes",
                "status": "waiting",
                "detail": "cloudflare-consent uses human_follow_me (needs_human_gate)",
                "next_action": "Use the VM browser to approve the named zone.",
                "resume_hint": "Click I finished this step after Cloudflare confirms.",
            }
        ],
    )

    assert any("Open provider gate in VM" in item for item in failures)


def test_acceptance_checkpoint_guidance_requires_capture_for_copy_once_target() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": (
                    "Click Open provider gate in VM and copy the GITHUB_TOKEN value."
                ),
                "resume_hint": "FuseKit will retry provider setup after the value is copied.",
            }
        ],
    )

    assert any("Capture from VM clipboard" in item for item in failures)


def test_acceptance_checkpoint_guidance_accepts_exact_launcher_controls() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": (
                    "Click Open provider gate in VM, copy GITHUB_TOKEN inside the shared "
                    "VM browser, then click Capture from VM clipboard."
                ),
                "resume_hint": "FuseKit will retry provider setup after capture.",
            }
        ],
    )

    assert failures == []


def test_acceptance_checkpoint_guidance_rejects_manual_resend_setup() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"resend": {"resend-domain"}},
        [
            {
                "id": "provider.resend.routes",
                "status": "waiting",
                "detail": "resend-domain uses browser_guided (needs_human_gate)",
                "next_action": "Click Add domain in Resend, then continue.",
                "resume_hint": "FuseKit will wait for DNS after the domain exists.",
            }
        ],
    )

    assert any("manual Resend domain/audience setup" in item for item in failures)


def test_acceptance_checkpoint_guidance_allows_negated_manual_copy_warning() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"vercel": {"vercel-deploy"}},
        [
            {
                "id": "provider.vercel.routes",
                "status": "done",
                "detail": "vercel-deploy uses api (ok)",
                "next_action": "Nothing to copy manually into Vercel.",
                "resume_hint": "FuseKit recorded the deterministic provider route.",
            }
        ],
    )

    assert failures == []


def test_acceptance_live_requires_real_provider_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="live")

    assert report.launch_ready is False
    assert "encrypted vault" in report.missing
    assert "redacted setup receipt" in report.missing
    assert "safe verification report" in report.missing
    assert "rollback metadata" in report.missing
    assert "provider strategy decisions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["encrypted vault"]["category"] == "Vault"
    assert "vault capture enabled" in blockers["encrypted vault"]["next_action"]
    assert blockers["provider strategy decisions"]["category"] == "Provider routes"
    assert "strategy recorder" in blockers["provider strategy decisions"]["next_action"]


def test_acceptance_report_redacts_check_and_blocker_details(tmp_path) -> None:
    raw_code = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    check = AcceptanceCheck(
        "provider.callback",
        "failed",
        f"Provider callback failed: https://provider.example/callback?code={raw_code}&state=ok",
    )
    blockers = _acceptance_blockers([check], [])
    report = AcceptanceReport(
        mode="live",
        app_path=str(tmp_path),
        launch_ready=False,
        checks=(check,),
        ledger_path=str(tmp_path / "ledger.jsonl"),
        report_path=str(tmp_path / "report.json"),
        blockers=(
            *blockers,
            {
                "item": "provider callback",
                "category": "Provider",
                "next_action": "Rerun the provider gate.",
                "detail": (
                    "Raw callback detail: "
                    f"https://provider.example/callback?code={raw_code}&state=ok"
                ),
            },
        ),
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert raw_code not in text
    assert "code=[redacted]" in text
    assert payload["checks"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][1]["detail"].endswith("?code=[redacted]&state=ok")


def test_acceptance_blockers_use_launcher_actionable_check_guidance() -> None:
    checks = [
        AcceptanceCheck(
            "gates.guided",
            "failed",
            "provider.cloudflare.authorization missing resume_url",
        ),
        AcceptanceCheck(
            "gates.audited",
            "failed",
            "missing control_room.gate_resume_requested: provider.cloudflare.authorization",
        ),
        AcceptanceCheck(
            "receipt.resend_dns_flow",
            "failed",
            "Receipt DNS proposal is missing Resend-generated records: MX send.moonlite.rsvp",
        ),
        AcceptanceCheck(
            "receipt.provider_contract_health",
            "failed",
            "Receipt is missing provider API contract-health proof before setup for: vercel",
        ),
        AcceptanceCheck(
            "detonation.worker_state",
            "failed",
            "Plaintext worker/browser/visual state still exists: .fusekit/browser",
        ),
        AcceptanceCheck(
            "gates.resolved",
            "failed",
            "Waiting provider gate still exists: provider.cloudflare.authorization",
        ),
    ]

    blockers = {blocker["item"]: blocker for blocker in _acceptance_blockers(checks, [])}

    assert "Open provider gate in VM URL" in blockers["gates.guided"]["next_action"]
    assert "I finished this step" in blockers["gates.audited"]["next_action"]
    assert "approve the DNS apply gate" in blockers["receipt.resend_dns_flow"]["next_action"]
    assert "read-only provider health check before mutation" in blockers[
        "receipt.provider_contract_health"
    ]["next_action"]
    assert "plaintext worker, browser, visual, and auth scratch state" in blockers[
        "detonation.worker_state"
    ]["next_action"]
    assert "I finished this step button" in blockers["gates.resolved"]["next_action"]
    assert "resume button" not in blockers["gates.resolved"]["next_action"]


def test_acceptance_blockers_explain_missing_gate_event_controls() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    "missing gate events: provider.custom.review",
                )
            ],
            [],
        )
    }

    next_action = blockers["gates.audited"]["next_action"]
    assert "Open provider gate in VM" in next_action
    assert "Capture from VM clipboard" in next_action
    assert "I finished this step" in next_action


def test_acceptance_blockers_explain_resend_generated_value_recovery() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "gates.guided",
                "failed",
                (
                    "provider.resend.runtime-values.target asks the user to capture "
                    "API-generated Resend values: RESEND_FROM_EMAIL"
                ),
            )
        ],
        [],
    )

    assert blockers[0]["item"] == "gates.guided"
    assert "Capture is used only for RESEND_API_KEY" in blockers[0]["next_action"]
    assert "Resend API setup retry" in blockers[0]["next_action"]


def test_acceptance_blockers_explain_manual_resend_setup_recovery() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "gates.guided",
                "failed",
                (
                    "provider.resend.domain.guidance asks for manual Resend "
                    "domain/audience setup"
                ),
            )
        ],
        [],
    )

    assert blockers[0]["item"] == "gates.guided"
    assert "captures only the setup key" in blockers[0]["next_action"]
    assert "domains and audiences through Resend API" in blockers[0]["next_action"]


def test_resend_api_strategy_requires_domain_ownership_evidence() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-domain",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            }
        ]
    )

    assert "resend.strategies[0].selected.evidence.api_owns must be domain" in failures
    assert (
        "resend.strategies[0].selected.evidence.downstream_order must be before_dns_apply"
        in failures
    )


def test_resend_audience_strategy_requires_conditional_api_evidence() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-audience",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            }
        ]
    )

    assert "resend.strategies[0].selected.evidence.api_owns must be audience" in failures
    assert (
        "resend.strategies[0].selected.evidence.conditional must be "
        "only_when_app_requires_audience"
    ) in failures


def test_acceptance_rejects_manual_resend_domain_or_audience_gate_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-verification",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-domain",
                "reason": "Add and verify the Resend sending domain moonlite.rsvp.",
                "resume_url": "https://resend.com/domains",
                "target": "moonlite.rsvp",
                "follow_steps": [
                    "Open Resend in the VM browser.",
                    "Click Add domain and create a Resend domain for moonlite.rsvp.",
                ],
                "next_action": "Click I finished this step after the domain exists.",
                "resume_hint": "FuseKit will continue after the domain is present.",
                "success_criteria": ["A Resend domain exists for moonlite.rsvp."],
                "avoid_steps": ["Do not create broad API keys."],
            },
            {
                "id": "provider.resend.audience",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-runtime-values",
                "resume_url": "https://resend.com/audiences",
                "target": "",
                "follow_steps": [
                    "Open Resend in the VM browser.",
                    "Click Add audience and create the audience in Resend.",
                ],
                "next_action": "Click I finished this step after the audience exists.",
                "resume_hint": "FuseKit will continue after the audience is present.",
                "success_criteria": ["A Resend audience exists."],
                "avoid_steps": ["Do not create broad API keys."],
            },
        ]
    )

    assert any(
        "provider.resend.domain-verification.guidance asks for manual Resend "
        "domain/audience setup" in failure
        for failure in failures
    )
    assert any(
        "provider.resend.audience.guidance asks for manual Resend domain/audience setup"
        in failure
        for failure in failures
    )


def test_acceptance_rejects_manual_resend_setup_in_success_or_avoid_panels() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Open provider gate in VM and stay on Resend API Keys.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": (
                    "Click I finished this step so FuseKit retries Resend API setup."
                ),
                "resume_hint": "FuseKit will create or reuse the sending domain by API.",
                "success_criteria": ["Create a Resend domain for moonlite.rsvp."],
                "avoid_steps": ["If blocked, click Add domain in Resend."],
            }
        ]
    )

    assert any(
        "provider.resend.domain-setup-retry.guidance asks for manual Resend "
        "domain/audience setup" in failure
        for failure in failures
    )


def test_acceptance_allows_resend_api_owned_domain_retry_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Open provider gate in VM and stay on Resend API Keys.",
                    "Do not click Add domain; FuseKit creates or reuses the domain.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": (
                    "Click I finished this step so FuseKit retries Resend API setup."
                ),
                "resume_hint": (
                    "FuseKit will create or reuse the sending domain through Resend API, "
                    "then hand returned DNS records to Cloudflare."
                ),
                "success_criteria": [
                    "Resend API key has been captured through the launcher."
                ],
                "avoid_steps": ["Do not click Add domain in Resend."],
            }
        ]
    )

    assert failures == []


def test_acceptance_allows_gate_service_default_provider_guidance(tmp_path) -> None:
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.github.authorization",
        provider="github",
        reason="GitHub setup token",
        resume_url="https://github.com/settings/tokens?type=beta",
        classification="provider-authorization",
        target="GITHUB_TOKEN",
    )

    gates = json.loads((tmp_path / "gates.json").read_text(encoding="utf-8"))["gates"]

    assert _unguided_gates(gates) == []
    assert any("Open provider gate in VM" in step for step in gates[0]["follow_steps"])
    assert any("Capture from VM clipboard" in step for step in gates[0]["follow_steps"])


def test_acceptance_live_ingests_retrieved_oci_artifacts(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "GitHub token",
        "ghp_secret_for_harness",
    )
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "has_last_opened_url": True,
                            "has_resume_url": True,
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "status": "passed",
                            "target": "OPENAI_API_KEY",
                            "record_id": "provider.openai.token",
                            "source": "vm-clipboard",
                            "storage": "encrypted-vault",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.callback.review",
                            "provider": "provider",
                            "has_last_opened_url": True,
                            "has_resume_url": True,
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.callback.review",
                            "provider": "provider",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [{"provider": "github", "action": "secret.upsert"}],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "github",
                        "check": "repo_secret_exists",
                        "status": "passed",
                    },
                    {
                        "provider": "vercel",
                        "check": "deployment_ready",
                        "status": "passed",
                    },
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.github.secret", "status": "planned"},
                    {"action": "rollback.vercel.env", "status": "planned"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-deploy",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "vercel",
                                    "recipe_kind": "vercel-deploy",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "checkpoints.json").write_text(
        json.dumps(
            {
                "job_id": "fk-test",
                "status": "running",
                "checkpoints": [
                    {
                        "id": "provider.github.routes",
                        "label": "Provider route: github",
                        "status": "done",
                        "detail": "github-repo-secrets uses api (ok)",
                        "next_action": "Nothing to do manually unless FuseKit surfaces a gate.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    },
                    {
                        "id": "provider.vercel.routes",
                        "label": "Provider route: vercel",
                        "status": "done",
                        "detail": "vercel-deploy uses api (ok)",
                        "next_action": "Nothing to copy manually into Vercel.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI auth complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "attempts": 1,
                        "follow_steps": [
                            "Complete login in the VM browser.",
                            (
                                "Copy the OpenAI key inside the VM browser and click "
                                "Capture from VM clipboard."
                            ),
                        ],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "resume_url": "http://localhost:1455/auth/callback?code=secret-code",
                        "last_opened_url": "https://provider.example/?token=secret-token",
                        **_gate_guidance_fields("openai"),
                    },
                    {
                        "id": "provider.callback.review",
                        "provider": "provider",
                        "reason": "Provider callback reviewed",
                        "status": "passed",
                        "classification": "provider-verification",
                        "target": (
                            "https://provider.example/callback?"
                            "code=abcdefghijklmnopqrstuvwxyz1234567890abcdef&state=ok"
                        ),
                        "attempts": 1,
                        "follow_steps": ["Review the highlighted callback."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                        "resume_url": "https://provider.example/review",
                        **_gate_guidance_fields("provider"),
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    assert report.launch_ready is True
    check_ids = {check.id for check in report.checks}
    assert "remote_artifacts.loaded" in check_ids
    assert "verification_report.safe" in check_ids
    assert "provider_strategies.recorded" in check_ids
    assert "provider_strategies.checkpoints" in check_ids
    assert "gates.resolved" in check_ids
    assert "gates.audited" in check_ids
    assert report.missing == ()
    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    gates_artifact = gates_check.artifact
    gates_text = Path(gates_artifact).read_text(encoding="utf-8")
    assert "secret-code" not in gates_text
    assert "secret-token" not in gates_text
    assert "abcdefghijklmnopqrstuvwxyz1234567890abcdef" not in gates_text
    assert "code=[redacted]" in gates_text
    assert "has_resume_url" in gates_text
    assert "captured_count" in gates_text
    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    audit_text = Path(audit_check.artifact).read_text(encoding="utf-8")
    assert "secret-code" not in audit_text
    assert "secret-token" not in audit_text
    assert "provider.openai.authorization" in audit_text
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["blockers"] == []
    assert any(check["id"] == "remote_artifacts.loaded" for check in report_json["checks"])


def test_live_acceptance_requires_provider_route_recovery_checkpoints(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    checkpoint_check = next(
        check for check in report.checks if check.id == "provider_strategies.checkpoints"
    )
    assert report.launch_ready is False
    assert checkpoint_check.status == "failed"
    assert "Provider route checkpoints not found" in checkpoint_check.detail
    assert "provider route recovery checkpoints" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["provider route recovery checkpoints"]["category"] == "Provider routes"
    assert "checkpoints.json" in blockers["provider route recovery checkpoints"]["next_action"]


def test_acceptance_cli_checks_vault_without_leaking_secret(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    (app / "mail.ts").write_text("process.env.RESEND_API_KEY", encoding="utf-8")
    vault_path = app / ".fusekit" / "fusekit.vault.json"
    vault_path.parent.mkdir(parents=True)
    passphrase = tmp_path / "pass.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    secret = "re_super_secret_value"
    vault = Vault.empty()
    vault.put("provider.resend.token", "provider_token", "resend", "Resend token", secret)
    vault.save(vault_path, "passphrase")

    assert (
        main(
            [
                "acceptance",
                "run",
                str(app),
                "--mode",
                "rehearsal",
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "vault.unlock" in output
    assert "vault.wrong_passphrase" in output
    assert secret not in output
    assert secret not in (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )


def test_live_acceptance_requires_resend_before_dns_when_both_are_present(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps({"actions": [], "raw_secrets_exposed": 0, "live_url": "https://moonlite.rsvp"}),
        encoding="utf-8",
    )
    (remote_fusekit / "audit.jsonl").write_text("{}", encoding="utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    order_check = next(check for check in report.checks if check.id == "provider_strategies.order")
    assert report.launch_ready is False
    assert order_check.status == "failed"
    assert "Resend-before-DNS provider setup order" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend-before-DNS provider setup order"]["category"] == "Provider order"
    assert "Run Resend domain setup before Cloudflare/DNS" in blockers[
        "Resend-before-DNS provider setup order"
    ]["next_action"]


def test_live_acceptance_requires_receipt_resend_dns_flow(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "A",
                                        "name": "moonlite.rsvp",
                                        "value": "76.76.21.21",
                                    }
                                }
                            ],
                        },
                    },
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "DNS proposal before Resend domain setup" in receipt_check.detail
    assert "Resend DNS records in receipt DNS proposal" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend DNS records in receipt DNS proposal"]["category"] == "Provider order"
    assert "Cloudflare/DNS proposed the exact Resend verification records" in blockers[
        "Resend DNS records in receipt DNS proposal"
    ]["next_action"]


def test_live_acceptance_accepts_receipt_resend_records_before_dns(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        },
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "A",
                                        "name": "moonlite.rsvp",
                                        "value": "76.76.21.21",
                                    }
                                },
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                },
                            ],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert receipt_check.status == "ok"
    assert "Resend domain setup emitted DNS records before DNS proposal" in receipt_check.detail


def test_live_acceptance_requires_receipt_resend_runtime_env_in_vercel(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "RESEND_FROM_EMAIL" in receipt_check.detail
    assert "Resend runtime env in Vercel receipt" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend runtime env in Vercel receipt"]["category"] == "Deployment env"
    assert "Vercel env setup records every app-required RESEND_*" in blockers[
        "Resend runtime env in Vercel receipt"
    ]["next_action"]


def test_live_acceptance_accepts_receipt_resend_runtime_env_in_vercel(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert receipt_check.status == "ok"
    assert "Resend runtime env keys were configured in Vercel" in receipt_check.detail


def test_live_acceptance_requires_provider_contract_health_before_api_setup(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    _provider_pack_api_setup_action("vercel", "vercel-env"),
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.provider_contract_health"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "vercel" in receipt_check.detail
    assert "provider contract-health receipt proof" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["provider contract-health receipt proof"]["category"] == "Provider routes"
    assert "read-only contract-health check" in blockers[
        "provider contract-health receipt proof"
    ]["next_action"]


def test_live_acceptance_accepts_provider_contract_health_before_api_setup(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.contract_health",
                        "status": "ok",
                        "details": {"provider": "vercel", "checked": True},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    _provider_pack_api_setup_action("vercel", "vercel-env"),
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.provider_contract_health"
    )
    assert receipt_check.status == "ok"
    assert "provider API contract health before token-backed setup" in receipt_check.detail


def test_live_acceptance_requires_complete_provider_strategy_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {"selected": {"kind": "api"}},
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "selected.status is missing" in strategy_check.detail
    assert "complete provider strategy evidence" in report.missing


def test_live_acceptance_requires_guided_human_provider_strategy(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-deploy-key",
                                "strategy": "browser_guided",
                                "status": "needs_human_gate",
                                "decision": {
                                    "selected": {
                                        "kind": "browser_guided",
                                        "status": "available",
                                        "deterministic": False,
                                        "implemented": False,
                                        "reason": "Provider token is missing.",
                                    },
                                    "candidates": [
                                        {
                                            "kind": "browser_guided",
                                            "status": "available",
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "github.strategies[0].follow_steps is missing" in strategy_check.detail
    assert "github.strategies[0].next_action is missing" in strategy_check.detail
    assert "github.strategies[0].resume_hint is missing" in strategy_check.detail
    assert "complete provider strategy evidence" in report.missing


def test_live_acceptance_requires_strategy_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "provider_strategies.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider strategy coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider strategy coverage"]["category"] == "Provider routes"
    assert "every provider declared by the manifest" in blockers[
        "complete provider strategy coverage"
    ]["next_action"]


def test_live_acceptance_requires_verification_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    }
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "verification_report.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider verification coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider verification coverage"]["category"] == "Verification"
    assert "every provider declared by the manifest" in blockers[
        "complete provider verification coverage"
    ]["next_action"]


def test_live_acceptance_requires_rollback_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    },
                    {
                        "provider": "cloudflare",
                        "check": "dns_record_exists",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "rollback_metadata.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete rollback coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete rollback coverage"]["category"] == "Rollback"
    assert "every provider declared by the manifest" in blockers[
        "complete rollback coverage"
    ]["next_action"]


def test_live_acceptance_requires_guided_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    guided_check = next(check for check in report.checks if check.id == "gates.guided")
    assert report.launch_ready is False
    assert guided_check.status == "failed"
    assert (
        "provider.github.authorization missing next_action, resume_hint, follow_steps, "
        "resume_url, success_criteria, avoid_steps"
        in guided_check.detail
    )
    assert "guided human gates" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert "follow_steps" in blockers["guided human gates"]["next_action"]


def test_live_acceptance_requires_audited_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                        "follow_steps": ["Copy the GitHub token in the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.github.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["audited human gate interventions"]["category"] == "Human gates"
    assert "Open provider gate in VM" in blockers[
        "audited human gate interventions"
    ]["next_action"]
    assert "Capture from VM clipboard" in blockers[
        "audited human gate interventions"
    ]["next_action"]
    assert "I finished this step" in blockers[
        "audited human gate interventions"
    ]["next_action"]


def test_live_acceptance_requires_clipboard_capture_for_secret_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "target": "OPENAI_API_KEY",
                            "record_id": "provider.openai.token",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.openai.token", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "openai",
                        "strategies": [
                            {
                                "recipe": "openai-token",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI token captured",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "follow_steps": ["Copy OPENAI_API_KEY inside the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.clipboard_capture" in audit_check.detail
    assert "provider.openai.authorization:OPENAI_API_KEY" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_all_multi_value_gate_captures(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "target": "RESEND_AUDIENCE_ID",
                            "record_id": "app.resend.resend_audience_id",
                            "source": "vm-clipboard",
                            "storage": "encrypted-vault",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.env", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-runtime-values",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.resend.runtime-values",
                        "provider": "resend",
                        "reason": "Resend runtime values captured",
                        "status": "passed",
                        "classification": "provider-runtime-values",
                        "target": "RESEND_AUDIENCE_ID,RESEND_FROM_EMAIL",
                        "captured_targets": ["RESEND_AUDIENCE_ID"],
                        "follow_steps": ["Copy each Resend value inside the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.resend.runtime-values:RESEND_FROM_EMAIL" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_provider_gate_open_audit(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns-records",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare authorization complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                        "follow_steps": ["Open Cloudflare in the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.gate_open" in audit_check.detail
    assert "provider.cloudflare.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_concrete_finished_click_audit(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.auth", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-authorization",
                                "strategy": "human_follow_me",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare authorization complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "follow_steps": ["Approve the visible Cloudflare authorization."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.gate_resume_requested" in audit_check.detail
    assert "provider.cloudflare.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_rejects_malformed_gate_audit_event(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "custom.review",
                            "provider": "custom",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.custom.review", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps({"schema_version": "fusekit.provider-strategies.v1", "providers": []}),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "custom.review",
                        "provider": "custom",
                        "reason": "Custom review gate complete",
                        "status": "passed",
                        "classification": "review",
                        "follow_steps": ["Review the custom provider result in the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "missing gate events: custom.review" in audit_check.detail
    assert "audited human gate interventions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["audited human gate interventions"]["next_action"]
    assert "Open provider gate in VM" in next_action
    assert "Capture from VM clipboard" in next_action
    assert "I finished this step" in next_action


def test_live_acceptance_requires_resolved_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.vercel.env", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare token creation",
                        "status": "waiting",
                        "classification": "provider-authorization",
                        "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so Cloudflare opens "
                                "in the VM browser."
                            )
                        ],
                        "next_action": "Finish Cloudflare login in the VM browser.",
                        "resume_hint": "FuseKit will retry verification after resume.",
                        **_gate_guidance_fields("cloudflare"),
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    gate_check = next(check for check in report.checks if check.id == "gates.resolved")
    assert report.launch_ready is False
    assert gate_check.status == "failed"
    assert "provider.cloudflare.authorization:waiting" in gate_check.detail
    assert "resolved human gates" in report.missing
