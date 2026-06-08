"""Acceptance harness for FuseKit launch readiness."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fusekit.detonation.preflight import (
    verification_report_failures,
)
from fusekit.errors import FuseKitError, VaultError
from fusekit.harness.ledger import HarnessLedger
from fusekit.manifest import SetupManifest, load_manifest, write_manifest
from fusekit.planner import build_plan
from fusekit.providers.capability_pack import (
    load_provider_pack,
    pack_default_path,
    synthesize_provider_pack,
    validate_provider_pack,
    write_provider_pack,
)
from fusekit.scanner import scan_repo
from fusekit.security import redact_public_path, redact_public_text, scan_for_secret_leaks
from fusekit.vault.bundle import Vault


@dataclass(frozen=True)
class AcceptanceCheck:
    """One launch-readiness assertion."""

    id: str
    status: str
    detail: str
    artifact: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize the check."""

        return {
            "id": self.id,
            "status": self.status,
            "detail": redact_public_text(self.detail),
            "artifact": redact_public_path(self.artifact),
        }


@dataclass(frozen=True)
class AcceptanceReport:
    """Public, redacted acceptance report."""

    mode: str
    app_path: str
    launch_ready: bool
    checks: tuple[AcceptanceCheck, ...]
    ledger_path: str
    report_path: str
    missing: tuple[str, ...] = ()
    blockers: tuple[dict[str, str], ...] = ()
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "mode": self.mode,
            "app_path": redact_public_path(self.app_path),
            "launch_ready": self.launch_ready,
            "checks": [check.to_dict() for check in self.checks],
            "missing": list(self.missing),
            "blockers": [_redacted_blocker(blocker) for blocker in self.blockers],
            "ledger_path": redact_public_path(self.ledger_path),
            "report_path": redact_public_path(self.report_path),
            "created_at": self.created_at,
        }


def run_acceptance(
    app_path: Path,
    *,
    mode: str = "rehearsal",
    manifest_path: Path | None = None,
    vault_path: Path | None = None,
    passphrase: str | None = None,
    receipt_path: Path | None = None,
    audit_log_path: Path | None = None,
    remote_artifacts_path: Path | None = None,
    output_dir: Path | None = None,
) -> AcceptanceReport:
    """Run a redacted harness pass for launch readiness.

    Rehearsal mode proves local invariants. Live mode requires real provider evidence and
    intentionally refuses to mark the run ready until those artifacts exist.
    """

    if mode not in {"rehearsal", "live"}:
        raise FuseKitError("acceptance mode must be rehearsal or live.")
    app_path = app_path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    fusekit_dir = app_path / ".fusekit"
    output_dir = _app_relative(app_path, output_dir) or (fusekit_dir / "acceptance")
    remote_fusekit_dir = _resolve_remote_fusekit_dir(app_path, remote_artifacts_path)
    evidence_fusekit_dir = remote_fusekit_dir or fusekit_dir
    ledger = HarnessLedger.create(output_dir)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger.record("acceptance.started", {"mode": mode, "app_path": redact_public_path(app_path)})
    if remote_fusekit_dir is not None:
        _record_remote_artifacts(remote_fusekit_dir, checks, ledger)

    manifest_path = _app_relative(app_path, manifest_path) or (app_path / "fusekit.yaml")
    manifest = _load_or_scan_manifest(app_path, manifest_path, checks, ledger)
    plan = build_plan(manifest)
    plan_path = ledger.snapshot_json("setup-plan", plan.to_dict())
    checks.append(AcceptanceCheck("plan.generated", "ok", "Setup plan generated.", str(plan_path)))

    pack_paths = _ensure_acceptance_packs(app_path, manifest, checks, ledger)
    if pack_paths:
        checks.append(
            AcceptanceCheck(
                "provider_packs.validated",
                "ok",
                f"Validated {len(pack_paths)} provider capability pack(s).",
            )
        )
    elif mode == "live":
        missing.append("validated provider capability packs")
        checks.append(
            AcceptanceCheck(
                "provider_packs.validated",
                "missing",
                "Live launch needs at least one validated provider capability pack.",
            )
        )

    vault_path = _app_relative(app_path, vault_path) or (
        evidence_fusekit_dir / "fusekit.vault.json"
    )
    _check_vault(vault_path, passphrase, mode, checks, missing, ledger)

    receipt_path = _app_relative(app_path, receipt_path) or (
        evidence_fusekit_dir / "setup_receipt.json"
    )
    _check_receipt(receipt_path, mode, checks, missing, ledger)

    audit_log_path = _app_relative(app_path, audit_log_path) or (
        evidence_fusekit_dir / "audit.jsonl"
    )
    _check_audit_log(audit_log_path, mode, checks, missing)
    _check_verification_report(
        evidence_fusekit_dir / "verification_report.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_provider_strategies(
        evidence_fusekit_dir / "provider_strategies.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_gate_state(
        evidence_fusekit_dir / "gates.json",
        mode,
        checks,
        missing,
        ledger,
    )
    _check_gate_audit_events(
        evidence_fusekit_dir / "gates.json",
        audit_log_path,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_rollback_metadata(
        evidence_fusekit_dir / "rollback_plan.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_detonation(evidence_fusekit_dir, mode, checks, missing)
    _check_leaks(app_path, checks, missing, ledger)

    launch_ready = all(check.status == "ok" for check in checks) and not missing
    if mode == "rehearsal":
        launch_ready = all(check.status in {"ok", "skipped"} for check in checks)
    report_path = output_dir / "report.json"
    report = AcceptanceReport(
        mode=mode,
        app_path=str(app_path),
        launch_ready=launch_ready,
        checks=tuple(checks),
        ledger_path=str(output_dir / "ledger.jsonl"),
        report_path=str(report_path),
        missing=tuple(missing),
        blockers=tuple(_acceptance_blockers(checks, missing)),
    )
    report_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    ledger.record("acceptance.finished", {"launch_ready": launch_ready, "missing": missing})
    return report


def _app_relative(app_path: Path, path: Path | None) -> Path | None:
    if path is None:
        return None
    if path.is_absolute():
        return path
    return app_path / path


def _resolve_remote_fusekit_dir(app_path: Path, path: Path | None) -> Path | None:
    root = _app_relative(app_path, path)
    if root is None:
        return None
    root = root.resolve()
    if not root.exists():
        raise FuseKitError(f"Remote artifact path does not exist: {root}")
    fusekit_dir = root if root.name == ".fusekit" else root / ".fusekit"
    if not fusekit_dir.is_dir():
        raise FuseKitError(
            "Remote artifact path must be a retrieved OCI artifact directory "
            f"containing .fusekit: {root}"
        )
    return fusekit_dir


def _record_remote_artifacts(
    remote_fusekit_dir: Path,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> None:
    expected = (
        "fusekit.vault.json",
        "setup_receipt.json",
        "audit.jsonl",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
        "gates.json",
    )
    inventory = {
        name: {
            "present": (remote_fusekit_dir / name).exists(),
            "bytes": (remote_fusekit_dir / name).stat().st_size
            if (remote_fusekit_dir / name).exists()
            else 0,
        }
        for name in expected
    }
    snapshot = ledger.snapshot_json(
        "remote-artifact-inventory",
        {"fusekit_dir": redact_public_path(remote_fusekit_dir), "files": inventory},
    )
    checks.append(
        AcceptanceCheck(
            "remote_artifacts.loaded",
            "ok",
            "Using retrieved OCI artifacts as live acceptance evidence.",
            str(snapshot),
        )
    )


def _acceptance_blockers(
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in missing:
        if item in seen:
            continue
        seen.add(item)
        category, action = _blocker_guidance(item)
        blockers.append({"item": item, "category": category, "next_action": action})
    for check in checks:
        if check.status == "ok" or check.id in seen:
            continue
        if check.status == "skipped":
            continue
        item = check.id
        if item in seen:
            continue
        seen.add(item)
        category, action = _check_blocker_guidance(check)
        blockers.append(
            {
                "item": item,
                "category": category,
                "next_action": action,
                "detail": redact_public_text(check.detail),
            }
        )
    return blockers


def _redacted_blocker(blocker: dict[str, str]) -> dict[str, str]:
    """Return a public-safe launch blocker."""

    return {
        str(key): redact_public_text(value)
        for key, value in blocker.items()
    }


def _blocker_guidance(item: str) -> tuple[str, str]:
    guidance = {
        "encrypted vault": (
            "Vault",
            "Run the live setup with vault capture enabled and retrieve "
            ".fusekit/fusekit.vault.json.",
        ),
        "redacted setup receipt": (
            "Receipt",
            "Retrieve the worker setup receipt and confirm it contains no raw secrets.",
        ),
        "safe verification report": (
            "Verification",
            "Run provider verification until checks pass or are explicitly pending-safe.",
        ),
        "complete provider verification coverage": (
            "Verification",
            "Record verification checks for every provider declared by the manifest.",
        ),
        "rollback metadata": (
            "Rollback",
            "Generate rollback metadata from the redacted setup receipt before launch.",
        ),
        "complete rollback coverage": (
            "Rollback",
            "Record rollback metadata for every provider declared by the manifest.",
        ),
        "provider strategy decisions": (
            "Provider routes",
            "Run provider setup through the strategy recorder so API, vault, or "
            "VM follow-me choices are proven.",
        ),
        "complete provider strategy evidence": (
            "Provider routes",
            "Record selected-route kind, status, deterministic/implemented flags, "
            "reason, and candidates.",
        ),
        "complete provider strategy coverage": (
            "Provider routes",
            "Record provider strategy evidence for every provider declared by the manifest.",
        ),
        "Resend-before-DNS provider setup order": (
            "Provider order",
            "Run Resend domain setup before Cloudflare/DNS so Resend DNS records are included.",
        ),
        "guided human gates": (
            "Human gates",
            "Regenerate gate state with next_action and resume_hint for every control-room gate.",
        ),
        "audited human gate interventions": (
            "Human gates",
            "Open, capture, or resume each control-room gate through the launcher "
            "so redacted audit events are written.",
        ),
        "resolved human gates": (
            "Human gates",
            "Finish or repair every waiting/resurfaced/retrying control-room gate "
            "before acceptance.",
        ),
        "validated provider capability packs": (
            "Provider packs",
            "Generate and validate provider capability packs for the services in the manifest.",
        ),
        "verified live URL": (
            "Deployment",
            "Verify the deployed live URL and write it into the redacted setup receipt.",
        ),
        "clean leak scan": (
            "Security",
            "Remove plaintext setup secrets from app files and artifacts, then rerun leak scan.",
        ),
        "detonated worker state": (
            "Detonation",
            "Run detonation/preflight so plaintext worker state is destroyed after "
            "encrypted artifacts are preserved.",
        ),
    }
    return guidance.get(
        item,
        ("Launch evidence", f"Repair missing launch evidence: {item}."),
    )


def _check_blocker_guidance(check: AcceptanceCheck) -> tuple[str, str]:
    if check.id.startswith("gates."):
        return (
            "Human gates",
            "Repair the control-room gate artifact, then rerun live acceptance.",
        )
    if check.id.startswith("provider_strategies."):
        return (
            "Provider routes",
            "Rerun provider setup so strategy decisions are recorded and ordered correctly.",
        )
    if check.id.startswith("verification_report."):
        return (
            "Verification",
            "Rerun provider verification and resolve failed or unsafe pending checks.",
        )
    if check.id.startswith("vault."):
        return ("Vault", "Regenerate or unlock the encrypted vault evidence.")
    if check.id.startswith("receipt."):
        return ("Receipt", "Regenerate the redacted setup receipt.")
    return ("Launch evidence", f"Repair failed acceptance check {check.id}.")


def _load_or_scan_manifest(
    app_path: Path,
    manifest_path: Path,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> SetupManifest:
    if manifest_path.exists():
        manifest = load_manifest(manifest_path)
        checks.append(
            AcceptanceCheck("manifest.loaded", "ok", "Existing setup manifest loaded.")
        )
    else:
        manifest = scan_repo(app_path)
        write_manifest(manifest, manifest_path)
        checks.append(
            AcceptanceCheck("manifest.scanned", "ok", "App scanned and setup manifest written.")
        )
    manifest_snapshot = ledger.snapshot_json("manifest", manifest.to_dict())
    checks.append(
        AcceptanceCheck(
            "manifest.snapshotted",
            "ok",
            "Manifest snapshot recorded.",
            str(manifest_snapshot),
        )
    )
    return manifest


def _ensure_acceptance_packs(
    app_path: Path,
    manifest: SetupManifest,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> list[Path]:
    providers = {service.provider.lower() for service in manifest.services}
    if manifest.domains:
        providers.add("cloudflare")
    pack_paths: list[Path] = []
    for provider in sorted(providers):
        pack_path = pack_default_path(app_path, provider)
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        pack = load_provider_pack(pack_path)
        validate_provider_pack(pack)
        pack_snapshot = ledger.snapshot_json(f"provider-pack-{provider}", pack.to_dict())
        checks.append(
            AcceptanceCheck(
                f"provider_pack.{provider}",
                "ok",
                "Provider capability pack validated and snapshotted.",
                str(pack_snapshot),
            )
        )
        pack_paths.append(pack_path)
    return pack_paths


def _check_vault(
    vault_path: Path,
    passphrase: str | None,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not vault_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(AcceptanceCheck("vault.exists", status, f"Vault not found: {vault_path}"))
        if mode == "live":
            missing.append("encrypted vault")
        return
    text = vault_path.read_text(encoding="utf-8")
    if "WEBHOOK_SECRET" in text or "BEGIN PRIVATE KEY" in text:
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "failed",
                "Vault contains plaintext markers.",
            )
        )
        missing.append("ciphertext-only vault")
    else:
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "ok",
                "Vault has no obvious plaintext markers.",
            )
        )
    if passphrase is None:
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "vault.unlock",
                status,
                "Passphrase not supplied for vault unlock proof.",
            )
        )
        if mode == "live":
            missing.append("vault unlock proof")
        return
    vault = Vault.open(vault_path, passphrase)
    index = vault.public_index()
    snapshot = ledger.snapshot_json("vault-public-index", {"records": index})
    checks.append(
        AcceptanceCheck(
            "vault.unlock",
            "ok",
            "Vault unlock proof succeeded.",
            str(snapshot),
        )
    )
    wrong_passphrase = passphrase + "\n-fusekit-wrong-passphrase-proof"
    try:
        Vault.open(vault_path, wrong_passphrase)
    except VaultError:
        checks.append(
            AcceptanceCheck(
                "vault.wrong_passphrase",
                "ok",
                "Wrong-passphrase proof failed as expected.",
            )
        )
    else:
        checks.append(
            AcceptanceCheck(
                "vault.wrong_passphrase",
                "failed",
                "Vault opened with an incorrect passphrase.",
            )
        )
        missing.append("wrong-passphrase rejection")


def _check_receipt(
    receipt_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not receipt_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck("receipt.exists", status, f"Receipt not found: {receipt_path}")
        )
        if mode == "live":
            missing.append("redacted setup receipt")
        return
    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    snapshot = ledger.snapshot_json("setup-receipt", raw)
    if int(raw.get("raw_secrets_exposed", 0)) != 0:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "failed",
                "Receipt reports raw secrets exposed.",
            )
        )
        missing.append("redacted receipt")
    else:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "ok",
                "Receipt reports zero raw secrets.",
                str(snapshot),
            )
        )
    live_url = str(raw.get("live_url", ""))
    if mode == "live" and not live_url:
        checks.append(
            AcceptanceCheck(
                "receipt.live_url",
                "missing",
                "Live launch requires a verified live URL.",
            )
        )
        missing.append("verified live URL")
    elif live_url:
        checks.append(
            AcceptanceCheck(
                "receipt.live_url",
                "ok",
                f"Receipt includes live URL: {live_url}",
            )
        )


def _check_audit_log(
    audit_log_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> None:
    if audit_log_path.exists():
        checks.append(AcceptanceCheck("audit.exists", "ok", "Redacted audit log exists."))
        return
    status = "skipped" if mode == "rehearsal" else "missing"
    checks.append(AcceptanceCheck("audit.exists", status, f"Audit log not found: {audit_log_path}"))
    if mode == "live":
        missing.append("redacted audit log")


def _check_verification_report(
    report_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not report_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                status,
                f"Verification report not found: {report_path}",
            )
        )
        if mode == "live":
            missing.append("safe verification report")
        return
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                "failed",
                "Verification report could not be read.",
            )
        )
        missing.append("safe verification report")
        return
    snapshot = ledger.snapshot_json("verification-report", raw)
    failures = verification_report_failures(raw if isinstance(raw, dict) else {})
    if failures:
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                "failed" if mode == "live" else "skipped",
                "Verification is not passed or pending-safe: " + "; ".join(failures),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe verification report")
        return
    _check_verification_provider_coverage(
        raw if isinstance(raw, dict) else {},
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )
    checks.append(
        AcceptanceCheck(
            "verification_report.safe",
            "ok",
            "Verification report is passed or explicitly pending-safe.",
            str(snapshot),
        )
    )


def _check_verification_provider_coverage(
    report: dict[str, Any],
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require verification evidence for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = _verification_provider_names(report)
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "verification_report.coverage",
                "failed" if mode == "live" else "skipped",
                "Verification report is missing manifest providers: " + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider verification coverage")
        return
    checks.append(
        AcceptanceCheck(
            "verification_report.coverage",
            "ok",
            "Verification report covers every provider declared by the manifest.",
            artifact,
        )
    )


def _verification_provider_names(report: dict[str, Any]) -> set[str]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return set()
    return {
        str(check.get("provider", "")).strip().lower()
        for check in checks
        if isinstance(check, dict) and str(check.get("provider", "")).strip()
    }


def _check_provider_strategies(
    strategies_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not strategies_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                status,
                f"Provider strategy artifact not found: {strategies_path}",
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    try:
        raw = json.loads(strategies_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed",
                "Provider strategy artifact could not be read.",
            )
        )
        missing.append("provider strategy decisions")
        return
    snapshot = ledger.snapshot_json("provider-strategies", raw)
    providers = raw.get("providers", []) if isinstance(raw, dict) else []
    schema_version = str(raw.get("schema_version", "")) if isinstance(raw, dict) else ""
    if schema_version != "fusekit.provider-strategies.v1":
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact has an unsupported schema.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    if not _has_strategy_decisions(providers):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact has no provider route decisions.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.recorded",
            "ok",
            "Provider strategy route decisions were recorded.",
            str(snapshot),
        )
    )
    _check_provider_strategy_decision_shape(providers, mode, checks, missing, str(snapshot))
    _check_provider_strategy_coverage(
        providers,
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )
    _check_provider_strategy_order(providers, mode, checks, missing, str(snapshot))


def _has_strategy_decisions(providers: Any) -> bool:
    if not isinstance(providers, list):
        return False
    for provider in providers:
        if not isinstance(provider, dict) or not str(provider.get("provider", "")):
            continue
        strategies = provider.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        if any(isinstance(strategy, dict) and strategy.get("decision") for strategy in strategies):
            return True
    return False


def _check_provider_strategy_decision_shape(
    providers: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require route decisions to include the fields needed for proof and UX."""

    failures = _provider_strategy_shape_failures(providers)
    if failures:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.complete",
                "failed" if mode == "live" else "skipped",
                "Provider strategy decisions are incomplete: " + "; ".join(failures),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider strategy evidence")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.complete",
            "ok",
            "Provider strategy decisions include selected route evidence.",
            artifact,
        )
    )


def _check_provider_strategy_coverage(
    providers: Any,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require strategy proof for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = {
        str(provider.get("provider", "")).strip().lower()
        for provider in providers
        if isinstance(provider, dict)
    }
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.coverage",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact is missing manifest providers: "
                + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider strategy coverage")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.coverage",
            "ok",
            "Provider strategy artifact covers every provider declared by the manifest.",
            artifact,
        )
    )


def _manifest_provider_names(manifest: SetupManifest) -> set[str]:
    providers: set[str] = set()
    for service in manifest.services:
        provider = service.provider.strip().lower()
        if provider:
            providers.add(provider)
    for domain in manifest.domains:
        provider = domain.provider.strip().lower()
        if provider:
            providers.add(provider)
    return providers


def _provider_strategy_shape_failures(providers: Any) -> list[str]:
    if not isinstance(providers, list):
        return ["providers is not a list"]
    failures: list[str] = []
    for provider_index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            failures.append(f"provider[{provider_index}] is not an object")
            continue
        provider_name = str(provider.get("provider", "")).strip() or f"provider[{provider_index}]"
        strategies = provider.get("strategies", [])
        if not isinstance(strategies, list) or not strategies:
            failures.append(f"{provider_name} has no strategies")
            continue
        for strategy_index, strategy in enumerate(strategies):
            label = f"{provider_name}.strategies[{strategy_index}]"
            if not isinstance(strategy, dict):
                failures.append(f"{label} is not an object")
                continue
            decision = strategy.get("decision")
            if not isinstance(decision, dict):
                failures.append(f"{label} is missing decision")
                continue
            selected = decision.get("selected")
            if not isinstance(selected, dict):
                failures.append(f"{label} is missing selected route")
                continue
            _require_strategy_string(selected, "kind", label, failures)
            _require_strategy_string(selected, "status", label, failures)
            _require_strategy_bool(selected, "deterministic", label, failures)
            _require_strategy_bool(selected, "implemented", label, failures)
            _require_strategy_string(selected, "reason", label, failures)
            candidates = decision.get("candidates", [])
            if not isinstance(candidates, list) or not candidates:
                failures.append(f"{label} is missing considered candidates")
    return failures


def _require_strategy_string(
    selected: dict[str, Any],
    key: str,
    label: str,
    failures: list[str],
) -> None:
    if not str(selected.get(key, "")).strip():
        failures.append(f"{label}.selected.{key} is missing")


def _require_strategy_bool(
    selected: dict[str, Any],
    key: str,
    label: str,
    failures: list[str],
) -> None:
    if not isinstance(selected.get(key), bool):
        failures.append(f"{label}.selected.{key} is missing")


def _check_provider_strategy_order(
    providers: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Assert provider strategy order proves Resend emitted DNS before DNS apply."""

    if not isinstance(providers, list):
        return
    ordered = [
        str(provider.get("provider", "")).lower()
        for provider in providers
        if isinstance(provider, dict) and str(provider.get("provider", "")).strip()
    ]
    if "resend" not in ordered or not any(
        provider in ordered for provider in {"cloudflare", "dns"}
    ):
        return
    resend_index = ordered.index("resend")
    dns_index = min(
        ordered.index(provider)
        for provider in ("cloudflare", "dns")
        if provider in ordered
    )
    if resend_index < dns_index:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.order",
                "ok",
                "Provider setup order proves Resend ran before DNS so Resend domain "
                "records can be applied.",
                artifact,
            )
        )
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.order",
            "failed" if mode == "live" else "skipped",
            "Provider setup order put DNS before Resend; Resend domain DNS records may be missing.",
            artifact,
        )
    )
    if mode == "live":
        missing.append("Resend-before-DNS provider setup order")


def _check_gate_state(
    gates_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require live runs to prove no durable human gates remain unresolved."""

    if not gates_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                status,
                f"Gate state not found: {gates_path}",
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    try:
        raw = json.loads(gates_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed",
                "Gate state could not be read.",
            )
        )
        missing.append("resolved human gates")
        return
    if not isinstance(raw, dict) or not isinstance(raw.get("gates"), list):
        snapshot = ledger.snapshot_json("gates", _redacted_gate_state(raw))
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Gate state has an unsupported schema.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    gates = raw["gates"]
    snapshot = ledger.snapshot_json("gates", _redacted_gate_state(raw))
    unguided = _unguided_gates(gates)
    if unguided:
        detail = ", ".join(unguided)
        checks.append(
            AcceptanceCheck(
                "gates.guided",
                "failed" if mode == "live" else "skipped",
                "Control-room gates are missing durable guidance: " + detail,
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("guided human gates")
        return
    checks.append(
        AcceptanceCheck(
            "gates.guided",
            "ok",
            "Every durable control-room gate includes next-action guidance.",
            str(snapshot),
        )
    )
    unresolved = [
        {
            "id": str(gate.get("id", "")),
            "provider": str(gate.get("provider", "")),
            "status": str(gate.get("status", "")),
        }
        for gate in gates
        if isinstance(gate, dict) and str(gate.get("status", "")) != "passed"
    ]
    if unresolved:
        detail = ", ".join(
            f"{gate['id']}:{gate['status']}" for gate in unresolved if gate["id"]
        )
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Unresolved control-room gates remain: " + (detail or "unknown gate"),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    checks.append(
        AcceptanceCheck(
            "gates.resolved",
            "ok",
            "No unresolved control-room gates remain.",
            str(snapshot),
        )
    )


def _unguided_gates(gates: Any) -> list[str]:
    if not isinstance(gates, list):
        return ["gates"]
    missing: list[str] = []
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or f"gate[{index}]")
        missing_fields = [
            field
            for field in ("next_action", "resume_hint")
            if not str(gate.get(field, "")).strip()
        ]
        if missing_fields:
            missing.append(f"{gate_id} missing {', '.join(missing_fields)}")
    return missing


def _redacted_gate_state(raw: Any) -> dict[str, Any]:
    """Return non-secret gate proof data for public acceptance artifacts."""

    if not isinstance(raw, dict):
        return {"schema": "invalid", "gates": []}
    gates = raw.get("gates", [])
    if not isinstance(gates, list):
        return {"schema": "invalid", "gates": []}
    safe_gates: list[dict[str, Any]] = []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        follow_steps = gate.get("follow_steps", [])
        captured_targets = gate.get("captured_targets", [])
        safe_gates.append(
            {
                "id": str(gate.get("id", "")),
                "provider": str(gate.get("provider", "")),
                "status": str(gate.get("status", "")),
                "classification": str(gate.get("classification", "")),
                "target": str(gate.get("target", "")),
                "attempts": _safe_int(gate.get("attempts")),
                "follow_step_count": len(follow_steps) if isinstance(follow_steps, list) else 0,
                "has_next_action": bool(str(gate.get("next_action", ""))),
                "has_resume_hint": bool(str(gate.get("resume_hint", ""))),
                "captured_count": (
                    len(captured_targets) if isinstance(captured_targets, list) else 0
                ),
                "has_resume_url": bool(str(gate.get("resume_url", ""))),
                "has_last_opened_url": bool(str(gate.get("last_opened_url", ""))),
            }
        )
    return {"schema": "fusekit.gates.redacted.v1", "gates": safe_gates}


def _safe_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _check_gate_audit_events(
    gates_path: Path,
    audit_log_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require control-room human interventions to leave redacted audit proof."""

    if not gates_path.exists() or not audit_log_path.exists():
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "skipped" if mode == "rehearsal" else "missing",
                "Gate/audit artifacts were not both available for intervention audit proof.",
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    try:
        gate_raw = json.loads(gates_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                "Gate state could not be read for audit proof.",
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    gates = gate_raw.get("gates", []) if isinstance(gate_raw, dict) else []
    gate_ids = [
        str(gate.get("id", ""))
        for gate in gates
        if isinstance(gate, dict) and str(gate.get("id", "")).strip()
    ]
    capture_requirements = _gate_capture_audit_requirements(gates)
    open_requirements = _gate_open_audit_requirements(gates)
    snapshot = ledger.snapshot_json(
        "gate-audit-proof",
        {
            "schema": "fusekit.gate-audit-proof.v1",
            "gate_count": len(gate_ids),
            "gates": [{"id": gate_id} for gate_id in gate_ids],
            "capture_requirements": [
                {"gate_id": gate_id, "target": target}
                for gate_id, target in capture_requirements
            ],
            "open_requirements": [{"gate_id": gate_id} for gate_id in open_requirements],
        },
    )
    if not gate_ids:
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "ok",
                "No control-room gates required intervention audit proof.",
                str(snapshot),
            )
        )
        return
    audit_events, audit_error = _control_room_audit_events(audit_log_path)
    if audit_error:
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                audit_error,
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    audited_gate_ids = {
        str(event.get("data", {}).get("gate_id", ""))
        for event in audit_events
        if isinstance(event.get("data"), dict)
    }
    captured_targets = {
        (
            str(event.get("data", {}).get("gate_id", "")),
            str(event.get("data", {}).get("target", "")),
        )
        for event in audit_events
        if str(event.get("event", "")) == "control_room.clipboard_capture"
        and isinstance(event.get("data"), dict)
    }
    opened_gate_ids = {
        str(event.get("data", {}).get("gate_id", ""))
        for event in audit_events
        if str(event.get("event", "")) == "control_room.gate_open"
        and isinstance(event.get("data"), dict)
    }
    missing_gate_ids = [gate_id for gate_id in gate_ids if gate_id not in audited_gate_ids]
    missing_captures = [
        (gate_id, target)
        for gate_id, target in capture_requirements
        if (gate_id, target) not in captured_targets
    ]
    missing_opens = [gate_id for gate_id in open_requirements if gate_id not in opened_gate_ids]
    if missing_gate_ids or missing_captures or missing_opens:
        details: list[str] = []
        if missing_gate_ids:
            details.append(
                "missing gate events: " + ", ".join(missing_gate_ids)
            )
        if missing_opens:
            details.append(
                "missing control_room.gate_open: " + ", ".join(missing_opens)
            )
        if missing_captures:
            details.append(
                "missing control_room.clipboard_capture: "
                + ", ".join(
                    f"{gate_id}:{target}" for gate_id, target in missing_captures
                )
            )
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                "Control-room gates are missing redacted audit events: "
                + "; ".join(details),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    checks.append(
        AcceptanceCheck(
            "gates.audited",
            "ok",
            "Every durable control-room gate has redacted intervention audit proof.",
            str(snapshot),
        )
    )


_ENV_TARGET_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


def _gate_capture_audit_requirements(gates: Any) -> list[tuple[str, str]]:
    """Return gate/target pairs that must prove launcher clipboard capture."""

    if not isinstance(gates, list):
        return []
    requirements: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id:
            continue
        for target in _gate_secret_targets(gate):
            key = (gate_id, target)
            if key not in seen:
                requirements.append(key)
                seen.add(key)
    return requirements


def _gate_open_audit_requirements(gates: Any) -> list[str]:
    """Return gate ids that must prove launch through the control-room VM browser."""

    if not isinstance(gates, list):
        return []
    requirements: list[str] = []
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id or gate_id in seen:
            continue
        if str(gate.get("resume_url", "")).strip():
            requirements.append(gate_id)
            seen.add(gate_id)
    return requirements


def _gate_secret_targets(gate: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    target = str(gate.get("target", "")).strip()
    if target:
        targets.extend(part.strip() for part in target.split(","))
    captured_targets = gate.get("captured_targets", [])
    if isinstance(captured_targets, list):
        targets.extend(str(target).strip() for target in captured_targets)
    return list(dict.fromkeys(part for part in targets if _ENV_TARGET_RE.match(part)))


def _control_room_audit_events(audit_log_path: Path) -> tuple[list[dict[str, Any]], str]:
    allowed_events = {
        "control_room.gate_open",
        "control_room.gate_resume_requested",
        "control_room.clipboard_capture",
    }
    events: list[dict[str, Any]] = []
    try:
        lines = audit_log_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], "Audit log could not be read for gate intervention proof."
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return [], f"Audit log contains malformed JSONL at line {line_number}."
        if not isinstance(event, dict):
            return [], f"Audit log line {line_number} is not a JSON object."
        if str(event.get("event", "")) in allowed_events:
            events.append(event)
    return events, ""


def _check_rollback_metadata(
    rollback_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not rollback_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                status,
                f"Rollback metadata not found: {rollback_path}",
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    try:
        raw = json.loads(rollback_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed",
                "Rollback metadata could not be read.",
            )
        )
        missing.append("rollback metadata")
        return
    snapshot = ledger.snapshot_json("rollback-metadata", raw)
    actions_raw = raw.get("rollback", raw.get("actions", [])) if isinstance(raw, dict) else []
    actions = actions_raw if isinstance(actions_raw, list) else []
    actionable = [
        item
        for item in actions
        if isinstance(item, dict)
        and str(item.get("action", "")).startswith("rollback.")
        and str(item.get("status", "")) not in {"missing", "failed"}
    ]
    if not actionable:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata has no provider rollback actions.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    checks.append(
        AcceptanceCheck(
            "rollback_metadata.actionable",
            "ok",
            f"Rollback metadata contains {len(actionable)} provider action(s).",
            str(snapshot),
        )
    )
    _check_rollback_provider_coverage(
        actionable,
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )


def _check_rollback_provider_coverage(
    actions: list[Any],
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require rollback evidence for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = _rollback_provider_names(actions)
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.coverage",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata is missing manifest providers: " + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete rollback coverage")
        return
    checks.append(
        AcceptanceCheck(
            "rollback_metadata.coverage",
            "ok",
            "Rollback metadata covers every provider declared by the manifest.",
            artifact,
        )
    )


def _rollback_provider_names(actions: list[Any]) -> set[str]:
    providers: set[str] = set()
    for item in actions:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider", "")).strip().lower()
        if provider:
            providers.add(provider)
            continue
        action = str(item.get("action", "")).strip().lower()
        parts = action.split(".")
        if len(parts) >= 2 and parts[0] == "rollback" and parts[1]:
            providers.add(parts[1])
    return providers


def _check_detonation(
    fusekit_dir: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> None:
    survivors = [
        path
        for path in (fusekit_dir / "worker", fusekit_dir / "tmp")
        if path.exists() and any(path.iterdir() if path.is_dir() else [path])
    ]
    if survivors:
        checks.append(
            AcceptanceCheck(
                "detonation.worker_state",
                "failed",
                "Plaintext worker/tmp state still exists: "
                + ", ".join(str(path) for path in survivors),
            )
        )
        missing.append("detonated worker state")
        return
    checks.append(
        AcceptanceCheck(
            "detonation.worker_state",
            "ok",
            "Worker/tmp state is detonated or absent.",
        )
    )
    if mode == "live" and not fusekit_dir.exists():
        missing.append("FuseKit artifact directory")


def _check_leaks(
    app_path: Path,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    findings = scan_for_secret_leaks(app_path)
    snapshot = ledger.snapshot_json(
        "leak-scan",
        {"findings": [finding.to_dict() for finding in findings]},
    )
    if findings:
        checks.append(
            AcceptanceCheck(
                "leak_scan.clean",
                "failed",
                f"Secret-looking plaintext findings: {len(findings)}",
                str(snapshot),
            )
        )
        missing.append("clean leak scan")
    else:
        checks.append(
            AcceptanceCheck(
                "leak_scan.clean",
                "ok",
                "No plaintext secret findings.",
                str(snapshot),
            )
        )
