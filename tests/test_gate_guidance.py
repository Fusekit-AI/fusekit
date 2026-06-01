from __future__ import annotations

from fusekit.runner.gate_guidance import infer_gate_provider, provider_gate_guidance


def test_provider_gate_guidance_is_plain_language_and_non_secret() -> None:
    guidance = provider_gate_guidance("vercel")

    assert "Vercel" in guidance.title
    assert "Sign in" in " ".join(guidance.actions)
    assert "hidden prompt" in " ".join(guidance.actions)
    assert "token" not in guidance.reassurance.lower()
    assert "secret" not in guidance.reassurance.lower()


def test_provider_gate_guidance_leads_instead_of_delegating_interpretation() -> None:
    forbidden = ("look at", "figure", "yourself", "manually", "if shown")
    for provider in ("github", "vercel", "cloudflare", "resend", "oci", "openai", "unknown"):
        guidance = provider_gate_guidance(provider)
        text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))
        lowered = text.lower()
        assert all(phrase not in lowered for phrase in forbidden)
        assert any(anchor in lowered for anchor in ("highlighted", "open provider gate"))


def test_infer_gate_provider_from_step_detail() -> None:
    assert infer_gate_provider("OCI Cloud Shell service gate is open") == "oci"
    assert infer_gate_provider("waiting for Cloudflare domain ownership") == "cloudflare"
    assert infer_gate_provider("plain provider gate") == ""
