"""Detonation preflight checks for survivor artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fusekit.runner.worker_replacement import worker_replacement_drill_failures
from fusekit.security import contains_durable_secret_text, scan_for_secret_leaks

PENDING_SAFE_CHECKS = {
    "dns_propagated",
    "dns_record_exists",
    "domain_verified",
    "deployment_url_exists",
}


@dataclass(frozen=True)
class DetonationPreflightResult:
    """Redacted detonation preflight outcome."""

    ok: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "failures": list(self.failures)}


def run_detonation_preflight(
    *,
    root: Path,
    vault: Path,
    audit: Path,
    receipt: Path,
    verification_report: Path,
    rollback_metadata: Path,
    run_record: Path,
    worker_replacement_drill: Path | None = None,
) -> DetonationPreflightResult:
    """Verify survivor artifacts before plaintext worker state is destroyed."""

    failures: list[str] = []
    for label, path in (
        ("encrypted vault", vault),
        ("audit log", audit),
        ("redacted receipt", receipt),
        ("verification report", verification_report),
        ("rollback metadata", rollback_metadata),
        ("central run record", run_record),
        *(
            (("worker replacement drill", worker_replacement_drill),)
            if worker_replacement_drill is not None
            else ()
        ),
    ):
        if not path.is_file():
            failures.append(f"missing {label}: {path}")

    if verification_report.is_file():
        failures.extend(_verification_failures(_read_json(verification_report)))
    if rollback_metadata.is_file():
        failures.extend(_rollback_failures(_read_json(rollback_metadata)))
    if run_record.is_file():
        failures.extend(_run_record_failures(_read_json(run_record)))
    if worker_replacement_drill is not None and worker_replacement_drill.is_file():
        failures.extend(
            worker_replacement_drill_failures(_read_json(worker_replacement_drill))
        )

    leaks = scan_for_secret_leaks(root)
    if leaks:
        failures.append(f"secret leak scan found {len(leaks)} finding(s)")

    return DetonationPreflightResult(ok=not failures, failures=tuple(failures))


def verification_report_failures(report: dict[str, Any]) -> list[str]:
    """Return redacted verification failures using detonation-preflight semantics."""

    return _verification_failures(report)


def verification_report_allows_detonation(report: dict[str, Any]) -> bool:
    """Return true when a verification report is passed or explicitly pending-safe."""

    return not verification_report_failures(report)


def verification_report_allows_launch_progress(report: dict[str, Any]) -> bool:
    """Return true when a launch can safely pause without treating human gates as failure."""

    return not _verification_failures(report, allow_human_gate=True)


def _verification_failures(
    report: dict[str, Any],
    *,
    allow_human_gate: bool = False,
) -> list[str]:
    checks = report.get("checks", [])
    if not isinstance(checks, list) or not checks:
        return ["verification report has no checks"]
    failures: list[str] = []
    for item in checks:
        if not isinstance(item, dict):
            failures.append("verification report contains an invalid check")
            continue
        provider = str(item.get("provider", "provider"))
        check = str(item.get("check", "check"))
        status = str(item.get("status", ""))
        details = item.get("details", {})
        pending_safe = _check_pending_safe(details)
        if status in {"passed", "skipped"}:
            continue
        if status == "pending" and (pending_safe or check in PENDING_SAFE_CHECKS):
            continue
        if allow_human_gate and status == "needs_human_gate":
            continue
        failures.append(f"{provider}.{check} is {status or 'unknown'}")
    return failures


def _check_pending_safe(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    if bool(details.get("pending_safe")):
        return True
    nested = details.get("details")
    return isinstance(nested, dict) and bool(nested.get("pending_safe"))


def _rollback_failures(payload: dict[str, Any]) -> list[str]:
    actions = payload.get("rollback", payload.get("actions", []))
    if not isinstance(actions, list) or not actions:
        return ["rollback metadata has no actions"]
    actionable = [
        item
        for item in actions
        if isinstance(item, dict)
        and str(item.get("action", "")).startswith("rollback.")
        and str(item.get("status", "")) not in {"missing", "failed"}
    ]
    return [] if actionable else ["rollback metadata has no provider rollback actions"]


def _run_record_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if not payload:
        return ["central run record could not be read"]
    if str(payload.get("schema_version", "") or "") != "fusekit.run-record.v1":
        failures.append("central run record has unsupported schema")
    for key in (
        "id",
        "durable_state",
        "provider_gates",
        "audit_trail",
        "detonation",
        "recording_contract",
    ):
        value = payload.get(key)
        if key == "id":
            if not str(value or "").strip():
                failures.append("central run record is missing id")
            continue
        if not isinstance(value, dict) or not value:
            failures.append(f"central run record is missing {key}")
    durable = payload.get("durable_state", {})
    if isinstance(durable, dict):
        scope = durable.get("detonation_scope", {})
        if not isinstance(scope, dict):
            failures.append("central run record is missing detonation scope")
        elif scope.get("host_machine_state_required") is not False:
            failures.append("central run record requires host-machine state")
    for path, value in _walk_json_strings(payload, path="central run record"):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
            if len(failures) >= 20:
                failures.append("central run record contains additional credential-looking text")
                break
    return failures


def _walk_json_strings(value: Any, *, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        items: list[tuple[str, str]] = []
        for key, nested in value.items():
            key_label = str(key).replace(".", "_")
            items.extend(_walk_json_strings(nested, path=f"{path}.{key_label}"))
        return items
    if isinstance(value, list):
        items = []
        for index, nested in enumerate(value):
            items.extend(_walk_json_strings(nested, path=f"{path}[{index}]"))
        return items
    return []


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}
