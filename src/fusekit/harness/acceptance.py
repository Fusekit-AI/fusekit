"""Acceptance harness for FuseKit launch readiness."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    ledger = HarnessLedger.create(output_dir)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger.record("acceptance.started", {"mode": mode, "app_path": str(app_path)})

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

    vault_path = _app_relative(app_path, vault_path) or (fusekit_dir / "fusekit.vault.json")
    _check_vault(vault_path, passphrase, mode, checks, missing, ledger)

    receipt_path = _app_relative(app_path, receipt_path) or (fusekit_dir / "setup_receipt.json")
    _check_receipt(receipt_path, mode, checks, missing, ledger)

    audit_log_path = _app_relative(app_path, audit_log_path) or (fusekit_dir / "audit.jsonl")
    _check_audit_log(audit_log_path, mode, checks, missing)
    _check_detonation(fusekit_dir, mode, checks, missing)
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
