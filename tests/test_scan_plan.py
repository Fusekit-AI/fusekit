from __future__ import annotations

import json

from fusekit.planner import build_plan
from fusekit.scanner import scan_repo


def test_scanner_detects_env_and_core_services(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "rsvp-app", "dependencies": {"@supabase/supabase-js": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text(
        "const url = process.env.SUPABASE_URL; const hook = process.env.WEBHOOK_SECRET;",
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    assert manifest.app_name == "rsvp-app"
    assert "SUPABASE_URL" in manifest.required_env
    assert any(service.provider == "github" for service in manifest.services)
    assert any(service.provider == "vercel" for service in manifest.services)
    assert manifest.webhooks[0].secret_name == "WEBHOOK_SECRET"
    supabase = next(service for service in manifest.services if service.provider == "supabase")
    assert "capability_pack" in supabase.capabilities


def test_scanner_detects_resend_email_service(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "email-app", "dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "mail.ts").write_text(
        "const resend = process.env.RESEND_API_KEY;",
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    assert "RESEND_API_KEY" in manifest.required_env
    assert any(service.provider == "resend" for service in manifest.services)


def test_scanner_does_not_treat_next_public_env_as_provider(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "next-app", "dependencies": {"next": "latest", "resend": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "page.tsx").write_text(
        "process.env.NEXT_PUBLIC_APP_URL; process.env.RESEND_API_KEY;",
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    assert any(service.provider == "resend" for service in manifest.services)
    assert not any(service.provider == "next" for service in manifest.services)


def test_scanner_ignores_lockfile_domains(tmp_path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "lock-app"}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/example": {
                        "resolved": "https://registry.npmjs.org/example/-/example.tgz",
                        "funding": "https://opencollective.com/example",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    assert not any(domain.domain == "registry.npmjs.org" for domain in manifest.domains)
    assert not any(domain.domain == "opencollective.com" for domain in manifest.domains)


def test_scanner_detects_plaid_provider_pack(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "finance-app", "dependencies": {"plaid": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "plaid.ts").write_text(
        "const secret = process.env.PLAID_SECRET; const client = process.env.PLAID_CLIENT_ID;",
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)
    plan = build_plan(manifest)

    plaid = next(service for service in manifest.services if service.provider == "plaid")
    assert plaid.kind == "provider-pack"
    assert "capability_pack" in plaid.capabilities
    assert plaid.settings["setup_lane"] == "openclaw-inferred-ui"
    assert any(action.id == "plaid.capability_pack.synthesize" for action in plan.actions)
    assert any(action.id == "plaid.configure_verify" for action in plan.actions)


def test_scanner_plans_catalog_provider_pack_for_common_ai_app_services(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "catalog-app",
                "dependencies": {
                    "@clerk/nextjs": "latest",
                    "@upstash/redis": "latest",
                    "openai": "latest",
                    "stripe": "latest",
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "integrations.ts").write_text(
        "\n".join(
            [
                "process.env.CLERK_SECRET_KEY;",
                "process.env.OPENAI_API_KEY;",
                "process.env.STRIPE_SECRET_KEY;",
                "process.env.UPSTASH_REDIS_REST_TOKEN;",
            ]
        ),
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)
    plan = build_plan(manifest)
    providers = {service.provider: service for service in manifest.services}

    for provider in ("clerk", "openai", "stripe", "upstash"):
        assert provider in providers
        assert "capability_pack" in providers[provider].capabilities
        assert any(action.id == f"{provider}.authorize" for action in plan.actions)
        assert any(action.id == f"{provider}.configure_verify" for action in plan.actions)


def test_plan_marks_dns_apply_as_approval_required(tmp_path) -> None:
    manifest = scan_repo(tmp_path)
    plan = build_plan(manifest)

    assert any(action.id == "github.configure_repo" for action in plan.actions)
    assert any(action.id == "detonate.worker_state" for action in plan.actions)


def test_scanner_infers_routes_domains_webhooks_and_oauth(tmp_path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "deep-app"}), encoding="utf-8")
    route = tmp_path / "app" / "api" / "stripe" / "webhook"
    route.mkdir(parents=True)
    (route / "route.ts").write_text(
        "const secret = process.env['STRIPE_WEBHOOK_SECRET'];",
        encoding="utf-8",
    )
    callback = tmp_path / "app" / "auth" / "callback"
    callback.mkdir(parents=True)
    (callback / "page.tsx").write_text(
        "const id = process.env.GITHUB_CLIENT_ID; const redirect_uri = 'https://example.com/auth/callback';",
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    assert "/api/stripe/webhook" in manifest.metadata["routes"]
    assert "/api/stripe/webhook" in manifest.metadata["webhook_routes"]
    assert "/auth/callback" in manifest.metadata["oauth_callbacks"]
    assert any(domain.domain == "example.com" for domain in manifest.domains)
    assert any(webhook.secret_name == "STRIPE_WEBHOOK_SECRET" for webhook in manifest.webhooks)


def test_scanner_uses_vercel_apex_dns_records(tmp_path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "apex-app"}), encoding="utf-8")
    (tmp_path / "vercel.json").write_text(
        json.dumps({"domains": ["moonlite.rsvp", "invite.moonlite.rsvp"]}),
        encoding="utf-8",
    )

    manifest = scan_repo(tmp_path)

    apex = next(domain for domain in manifest.domains if domain.domain == "moonlite.rsvp")
    subdomain = next(
        domain for domain in manifest.domains if domain.domain == "invite.moonlite.rsvp"
    )
    apex_records = {(record.type, record.name, record.value) for record in apex.records}
    subdomain_records = {
        (record.type, record.name, record.value) for record in subdomain.records
    }
    assert ("A", "moonlite.rsvp", "76.76.21.21") in apex_records
    assert ("CNAME", "www.moonlite.rsvp", "cname.vercel-dns.com") in apex_records
    assert subdomain_records == {("CNAME", "invite.moonlite.rsvp", "cname.vercel-dns.com")}
