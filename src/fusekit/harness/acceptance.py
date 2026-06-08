"""Acceptance harness for FuseKit launch readiness."""

from __future__ import annotations

import json
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
from fusekit.security import scan_for_secret_leaks
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
            "detail": self.detail,
            "artifact": self.artifact,
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
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "mode": self.mode,
            "app_path": self.app_path,
            "launch_ready": self.launch_ready,
            "checks": [check.to_dict() for check in self.checks],
            "missing": list(self.missing),
            "ledger_path": self.ledger_path,
            "report_path": self.report_path,
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
    ledger.record("acceptance.started", {"mode": mode, "app_path": str(app_path)})
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
        mode,
        checks,
        missing,
        ledger,
    )
    _check_provider_strategies(
        evidence_fusekit_dir / "provider_strategies.json",
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
    _check_rollback_metadata(
        evidence_fusekit_dir / "rollback_plan.json",
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
        {"fusekit_dir": str(remote_fusekit_dir), "files": inventory},
    )
    checks.append(
        AcceptanceCheck(
            "remote_artifacts.loaded",
            "ok",
            "Using retrieved OCI artifacts as live acceptance evidence.",
            str(snapshot),
        )
    )


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
    checks.append(
        AcceptanceCheck(
            "verification_report.safe",
            "ok",
            "Verification report is passed or explicitly pending-safe.",
            str(snapshot),
        )
    )


def _check_provider_strategies(
    strategies_path: Path,
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
    snapshot = ledger.snapshot_json("gates", raw)
    gates = raw.get("gates", []) if isinstance(raw, dict) else []
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


def _check_rollback_metadata(
    rollback_path: Path,
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
