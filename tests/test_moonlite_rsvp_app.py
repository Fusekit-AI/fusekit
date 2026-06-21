from __future__ import annotations

import json
import shutil
from pathlib import Path

from fusekit.harness import run_acceptance
from fusekit.scanner import scan_repo
from fusekit.security import scan_for_secret_leaks


def _copy_moonlite_source(dest: Path) -> None:
    shutil.copytree(
        Path("examples/moonlite-rsvp"),
        dest,
        ignore=shutil.ignore_patterns(
            ".fusekit",
            "dist",
            "node_modules",
            "*.tsbuildinfo",
        ),
    )


def test_moonlite_rsvp_app_activates_magic_path() -> None:
    app = Path("examples/moonlite-rsvp")

    manifest = scan_repo(app)
    providers = {service.provider for service in manifest.services}

    assert manifest.app_name == "moonlite-rsvp"
    assert {"github", "vercel", "resend"} <= providers
    assert "next" not in providers
    domain = next(domain for domain in manifest.domains if domain.domain == "moonlite.rsvp")
    records = {(record.type, record.name, record.value) for record in domain.records}
    assert ("A", "moonlite.rsvp", "76.76.21.21") in records
    assert ("CNAME", "www.moonlite.rsvp", "cname.vercel-dns.com") in records
    assert any(webhook.target_url == "/api/webhooks/resend" for webhook in manifest.webhooks)
    assert "WEBHOOK_SECRET" in manifest.required_env
    assert "RESEND_API_KEY" in manifest.required_env
    assert scan_for_secret_leaks(app) == []


def test_moonlite_rsvp_rehearsal_acceptance_is_clean(tmp_path) -> None:
    app = tmp_path / "moonlite-rsvp"
    _copy_moonlite_source(app)
    assert not (app / ".fusekit").exists()
    assert not (app / "node_modules").exists()
    assert not (app / "dist").exists()

    report = run_acceptance(app, mode="rehearsal")

    assert report.launch_ready is True
    assert report.public_launch_ready is False
    assert report.recording_ready is False
    assert report.missing == ()
    assert [
        (check.id, check.status)
        for check in report.checks
        if check.status not in {"ok", "skipped"}
    ] == []
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["public_launch_ready"] is False
    assert report_json["recording_ready"] is False
    assert report_json["blockers"] == []
    assert report_json["missing"] == []
    checks = {check["id"]: check for check in report_json["checks"]}
    assert checks["provider_pack.github"]["status"] == "ok"
    assert checks["provider_pack.vercel"]["status"] == "ok"
    assert checks["provider_pack.resend"]["status"] == "ok"
    assert checks["provider_pack.cloudflare"]["status"] == "ok"
    assert checks["provider_packs.validated"]["status"] == "ok"
    assert checks["leak_scan.clean"]["status"] == "ok"
    assert report_json["ledger_path"] == ".fusekit/acceptance/ledger.jsonl"
    assert report_json["report_path"] == ".fusekit/acceptance/report.json"
    ledger_text = (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text()
    assert "acceptance.started" in ledger_text
    assert "acceptance.finished" in ledger_text
