from __future__ import annotations

from pathlib import Path

from fusekit.scanner import scan_repo
from fusekit.security import scan_for_secret_leaks


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
