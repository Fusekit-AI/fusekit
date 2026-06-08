from __future__ import annotations

import re

from fusekit.runner.gate_guidance import infer_gate_provider, provider_gate_guidance


def test_provider_gate_guidance_is_plain_language_and_non_secret() -> None:
    guidance = provider_gate_guidance("vercel")

    assert "Vercel" in guidance.title
    assert "sign in" in " ".join(guidance.actions).lower()
    assert "VM browser" in " ".join(guidance.actions)
    assert "Capture in FuseKit" in " ".join(guidance.actions)
    assert "token" not in guidance.reassurance.lower()
    assert "secret" not in guidance.reassurance.lower()


def test_provider_gate_guidance_leads_instead_of_delegating_interpretation() -> None:
    forbidden = ("look at", "figure", "yourself", "manually", "if shown")
    for provider in ("github", "vercel", "cloudflare", "resend", "oci", "openai", "unknown"):
        guidance = provider_gate_guidance(provider)
        text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))
        lowered = text.lower()
        assert all(re.search(rf"\b{re.escape(phrase)}\b", lowered) is None for phrase in forbidden)
        assert any(anchor in lowered for anchor in ("highlighted", "open provider gate"))
        if provider in {"github", "vercel", "cloudflare", "resend"}:
            assert "vm browser" in lowered
            assert "capture" in lowered


def test_cloudflare_guidance_names_scoped_token_path() -> None:
    guidance = provider_gate_guidance("cloudflare")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Create Token" in text
    assert "Custom token" in text
    assert "Zone / Zone / Read" in text
    assert "Zone / DNS / Edit" in text
    assert "Specific zone" in text
    assert "encrypted vault" in text


def test_github_guidance_names_repo_scoped_permissions() -> None:
    guidance = provider_gate_guidance("github")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "fine-grained personal access token" in text
    assert "Only select repositories" in text
    assert "exact target repo" in text
    assert "Secrets read/write" in text
    assert "Administration read/write" in text
    assert "Metadata read-only" in text
    assert "encrypted vault" in text


def test_vercel_guidance_names_token_path() -> None:
    guidance = provider_gate_guidance("vercel")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Account Settings > Tokens" in text
    assert "Login Connections" in text
    assert "GitHub" in text
    assert "short expiration" in text
    assert "personal account or team" in text
    assert "encrypted vault" in text


def test_resend_guidance_names_api_key_path() -> None:
    guidance = provider_gate_guidance("resend")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "API Keys" in text
    assert "FuseKit email setup" in text
    assert "Full access" in text
    assert "before Cloudflare DNS" in text
    assert "creates or reuses the Resend domain" in text
    assert "domain and audience" in text
    assert "encrypted vault" in text


def test_infer_gate_provider_from_step_detail() -> None:
    assert infer_gate_provider("OCI Cloud Shell service gate is open") == "oci"
    assert infer_gate_provider("waiting for Cloudflare domain ownership") == "cloudflare"
    assert infer_gate_provider("plain provider gate") == ""
