from __future__ import annotations

import re

from fusekit.runner.gate_guidance import infer_gate_provider, provider_gate_guidance


def test_provider_gate_guidance_is_plain_language_and_non_secret() -> None:
    guidance = provider_gate_guidance("vercel")

    assert "Vercel" in guidance.title
    assert "Sign in" in " ".join(guidance.actions)
    assert "VM-local capture" in " ".join(guidance.actions)
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


def test_cloudflare_guidance_names_scoped_token_path() -> None:
    guidance = provider_gate_guidance("cloudflare")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Create Token" in text
    assert "Custom token" in text
    assert "Zone Read" in text
    assert "DNS Edit" in text
    assert "specific zone" in text
    assert "encrypted vault" in text


def test_github_guidance_names_repo_scoped_permissions() -> None:
    guidance = provider_gate_guidance("github")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "fine-grained personal access token" in text
    assert "target repo" in text
    assert "Secrets read/write" in text
    assert "Administration read/write" in text
    assert "encrypted vault" in text


def test_vercel_guidance_names_token_path() -> None:
    guidance = provider_gate_guidance("vercel")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Account Settings" in text
    assert "Tokens" in text
    assert "Login Connections" in text
    assert "GitHub" in text
    assert "short expiration" in text
    assert "personal account or team" in text
    assert "encrypted vault" in text


def test_resend_guidance_names_api_key_path() -> None:
    guidance = provider_gate_guidance("resend")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "API Keys" in text
    assert "FuseKit email" in text
    assert "sending/domain access" in text
    assert "encrypted vault" in text


def test_infer_gate_provider_from_step_detail() -> None:
    assert infer_gate_provider("OCI Cloud Shell service gate is open") == "oci"
    assert infer_gate_provider("waiting for Cloudflare domain ownership") == "cloudflare"
    assert infer_gate_provider("plain provider gate") == ""
