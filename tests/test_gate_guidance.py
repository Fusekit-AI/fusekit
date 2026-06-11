from __future__ import annotations

import re

from fusekit.runner.control_room.events import SCRIPT
from fusekit.runner.gate_guidance import (
    gate_guidance_payload,
    infer_gate_provider,
    provider_gate_guidance,
)


def test_provider_gate_guidance_is_plain_language_and_non_secret() -> None:
    guidance = provider_gate_guidance("vercel")

    assert "Vercel" in guidance.title
    assert "sign in" in " ".join(guidance.actions).lower()
    assert "VM browser" in " ".join(guidance.actions)
    assert "Capture VERCEL_TOKEN from VM clipboard" in " ".join(guidance.actions)
    assert "Capture reads the VM clipboard directly" in " ".join(guidance.actions)
    assert "token" not in guidance.reassurance.lower()
    assert "secret" not in guidance.reassurance.lower()


def test_live_control_room_guidance_uses_python_payload() -> None:
    payload = gate_guidance_payload()
    providers = payload["providers"]

    assert "__GATE_GUIDANCE_JSON__" not in SCRIPT
    assert "gateGuidanceData" in SCRIPT
    assert "Object.keys(gateGuidanceData.providers || {})" in SCRIPT
    assert providers["resend"]["title"] in SCRIPT
    assert providers["cloudflare"]["body"] in SCRIPT
    assert payload["generic"]["title"] in SCRIPT


def test_control_room_click_errors_preserve_backend_guidance() -> None:
    assert "function controlRoomFailureMessage" in SCRIPT
    assert "function controlRoomFailureStatus" in SCRIPT
    assert "function renderGateActionStatusBody" in SCRIPT
    assert "payload?.missing_targets" in SCRIPT
    assert "Missing: ${missingTargets.join" in SCRIPT
    assert "Still needed: ${escapeHtml(missingTargets.join" in SCRIPT
    assert "error.gateStatus = gateStatus" in SCRIPT
    assert "setGateActionStatus(gateId, error?.gateStatus || message, \"stale\")" in SCRIPT
    assert "Copy the value inside the VM browser, then click Capture ${target}" in SCRIPT
    assert "from VM clipboard again." in SCRIPT
    assert "gate update failed" not in SCRIPT
    assert "capture failed" not in SCRIPT
    assert "gate open failed" not in SCRIPT


def test_provider_gate_guidance_leads_instead_of_delegating_interpretation() -> None:
    forbidden = ("look at", "figure", "yourself", "manually", "if shown")
    for provider in ("github", "vercel", "cloudflare", "resend", "oci", "openai", "unknown"):
        guidance = provider_gate_guidance(provider)
        text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))
        lowered = text.lower()
        assert all(re.search(rf"\b{re.escape(phrase)}\b", lowered) is None for phrase in forbidden)
        assert "resume button" not in lowered
        if provider in {"openai", "unknown"}:
            assert "i finished this step" in lowered
        assert "open provider gate in vm" in lowered or "highlighted" in lowered
        if provider in {"github", "vercel", "cloudflare", "resend"}:
            assert "vm browser" in lowered
            assert "capture" in lowered


def test_generic_provider_guidance_distinguishes_capture_from_finished() -> None:
    guidance = provider_gate_guidance("custom-provider")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "copy-once API key or token" in text
    assert "Capture CUSTOM_API_KEY from VM clipboard" in text
    assert "button named for that value" in text
    assert "You do not need to paste it into your computer" in text
    assert "Capture reads the VM clipboard directly" in text
    assert "If no env-named Capture button is shown" in text
    assert "I finished this step" in text
    assert "matching button" not in text
    assert "figure" not in text.lower()
    assert "manually" not in text.lower()


def test_cloudflare_guidance_names_scoped_token_path() -> None:
    guidance = provider_gate_guidance("cloudflare")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Create Token" in text
    assert "Custom token" in text
    assert "User API Tokens" in text
    assert "Do not use API Keys or Global API Key" in text
    assert "Zone / Zone / Read" in text
    assert "Zone / DNS / Edit" in text
    assert "exactly two rows" in text
    assert "Specific zone" in text
    assert "Client IP Address Filtering" in text
    assert "TTL blank" in text
    assert "Continue to summary" in text
    assert "encrypted vault" in text
    assert "Open provider gate in VM" in text
    assert "Capture CLOUDFLARE_API_TOKEN from VM clipboard" in text
    assert "Capture reads the VM clipboard directly" in text


def test_github_guidance_names_repo_scoped_permissions() -> None:
    guidance = provider_gate_guidance("github")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "fine-grained personal access token" in text
    assert "Generate new token" in text
    assert "Resource owner" in text
    assert "user or organization FuseKit named" in text
    assert "organization approval or SSO" in text
    assert "Only select repositories" in text
    assert "exact target repo" in text
    assert "Secrets to Read and write" in text
    assert "Administration to Read and write" in text
    assert "unrelated permissions at No access" in text
    assert "Metadata read-only" in text
    assert "encrypted vault" in text
    assert "Open provider gate in VM" in text
    assert "Capture GITHUB_TOKEN from VM clipboard" in text
    assert "Capture reads the VM clipboard directly" in text


def test_vercel_guidance_names_token_path() -> None:
    guidance = provider_gate_guidance("vercel")
    text = " ".join((guidance.title, guidance.body, *guidance.actions, guidance.reassurance))

    assert "Account Settings > Tokens" in text
    assert "top-left account/team switcher" in text
    assert "Personal Account unless FuseKit named a team" in text
    assert "set its scope to Personal Account or the exact team" in text
    assert "Login Connections" in text
    assert "GitHub" in text
    assert "short expiration" in text
    assert "personal account or team" in text
    assert "encrypted vault" in text
    assert "Open provider gate in VM" in text
    assert "Capture VERCEL_TOKEN from VM clipboard" in text


def test_resend_guidance_names_api_key_path() -> None:
    guidance = provider_gate_guidance("resend")
    text = " ".join(
        (
            guidance.title,
            guidance.body,
            *guidance.actions,
            guidance.reassurance,
            *guidance.success,
            *guidance.avoid,
        )
    )

    assert "API Keys" in text
    assert "FuseKit email setup" in text
    assert "Full access" in text
    assert "Permission: Full access" in text
    assert "Domain: All domains" in text
    assert "existing key card" in text
    assert "Permission: Full access and Domain: All domains is not enough" in text
    assert "raw key value" in text
    assert "does not reveal old key secrets again" in text
    assert "before Cloudflare DNS" in text
    assert "creates or reuses the Resend domain" in text
    assert "domain and audience" in text
    assert "No domains yet" in text
    assert "do not click Add domain" in text
    assert "unless FuseKit asks" not in text
    assert "encrypted vault" in text
    assert "Open provider gate in VM" in text
    assert "Capture RESEND_API_KEY from VM clipboard" in text


def test_infer_gate_provider_from_step_detail() -> None:
    assert infer_gate_provider("OCI Cloud Shell service gate is open") == "oci"
    assert infer_gate_provider("waiting for Cloudflare domain ownership") == "cloudflare"
    assert infer_gate_provider("plain provider gate") == ""
