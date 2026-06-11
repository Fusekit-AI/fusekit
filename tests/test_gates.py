from __future__ import annotations

from fusekit.runner.gates import GateService


def test_gate_service_resurfaces_and_persists(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)

    first = service.wait("github-auth", provider="github", reason="MFA", resume_url="https://x")
    second = service.wait("github-auth", provider="github", reason="MFA", resume_url="https://x")

    assert first.status == "waiting"
    assert second.status == "resurfaced"
    assert second.attempts == 2

    loaded = GateService.load(path)
    assert loaded.records["github-auth"].attempts == 2
    assert "Finish the github" in loaded.records["github-auth"].to_dict()["next_action"]
    assert "retry verification" in loaded.records["github-auth"].to_dict()["resume_hint"]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    loaded.pass_gate("github-auth")
    assert GateService.load(path).records["github-auth"].status == "passed"
    assert GateService.load(path).records["github-auth"].to_dict()["next_action"] == (
        "No action needed."
    )


def test_gate_service_does_not_resurface_passed_gate(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)
    service.wait("cloudflare-auth", provider="cloudflare", reason="login", resume_url="https://x")
    service.pass_gate("cloudflare-auth")

    resurfaced = service.wait(
        "cloudflare-auth",
        provider="cloudflare",
        reason="login",
        resume_url="https://x",
    )

    assert resurfaced.status == "passed"
    assert resurfaced.attempts == 1
    assert GateService.load(path).records["cloudflare-auth"].status == "passed"


def test_gate_service_default_capture_copy_names_vm_clipboard_button(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)

    gate = service.wait(
        "resend-auth",
        provider="resend",
        reason="token",
        resume_url="https://x",
        target="RESEND_API_KEY",
    )

    assert gate.to_dict()["next_action"] == (
        "Copy the provider value in the VM browser, then click "
        "Capture RESEND_API_KEY from VM clipboard."
    )
    assert any(
        "Capture RESEND_API_KEY from VM clipboard" in item
        for item in gate.to_dict()["follow_steps"]
    )


def test_gate_service_persists_provider_success_and_avoid_guidance(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)

    service.wait(
        "provider.resend.authorization",
        provider="resend",
        reason="Resend setup key",
        resume_url="https://resend.com/api-keys",
        target="RESEND_API_KEY",
    )

    gate = GateService.load(path).records["provider.resend.authorization"].to_dict()
    assert "success_criteria" in gate
    assert "avoid_steps" in gate
    assert any("All domains" in item for item in gate["follow_steps"])
    assert any("raw Resend API key value" in item for item in gate["success_criteria"])
    assert any(
        "No Resend domains or audiences need to exist" in item
        for item in gate["success_criteria"]
    )
    assert any("Do not click Add domain" in item for item in gate["avoid_steps"])


def test_gate_service_resume_request_can_resurface_after_failed_recheck(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)
    service.wait("resend-auth", provider="resend", reason="token", resume_url="https://x")
    service.mark_captured("resend-auth", "RESEND_API_KEY")
    service.request_resume("resend-auth")

    retrying = GateService.load(path).records["resend-auth"]
    assert retrying.status == "resume_requested"
    assert retrying.captured_targets == ("RESEND_API_KEY",)
    assert retrying.next_action == "FuseKit is retrying provider verification now."
    assert "next guided blocker" in retrying.resume_hint

    resurfaced = GateService.load(path).wait(
        "resend-auth",
        provider="resend",
        reason="token still missing",
        resume_url="https://x",
    )

    assert resurfaced.status == "resurfaced"
    assert resurfaced.attempts == 2
    assert resurfaced.reason == "token still missing"
    assert resurfaced.captured_targets == ()


def test_gate_service_partial_capture_names_vm_clipboard_button(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)
    service.wait(
        "provider.custom.runtime-values",
        provider="custom",
        reason="Runtime values",
        target="CUSTOM_API_KEY,CUSTOM_WEBHOOK_SECRET",
    )
    service.mark_captured("provider.custom.runtime-values", "CUSTOM_API_KEY")

    gate = GateService.load(path).records["provider.custom.runtime-values"]

    assert gate.captured_targets == ("CUSTOM_API_KEY",)
    assert gate.next_action == (
        "Copy the next provider value in the VM browser, then click "
        "Capture CUSTOM_WEBHOOK_SECRET from VM clipboard."
    )
    assert "resume automatically" in gate.resume_hint


def test_gate_service_resume_request_uses_approval_specific_copy(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)
    service.wait(
        "dns.example.com.approval",
        provider="dns",
        reason="DNS approval",
        classification="dns-approval",
    )
    service.wait(
        "fusekit.plan-approval",
        provider="fusekit",
        reason="Plan approval",
        classification="setup-approval",
    )

    service.request_resume("dns.example.com.approval")
    service.request_resume("fusekit.plan-approval")

    loaded = GateService.load(path)
    dns = loaded.records["dns.example.com.approval"]
    plan = loaded.records["fusekit.plan-approval"]
    assert dns.next_action == "FuseKit is applying the approved DNS records now."
    assert "propagation status" in dns.resume_hint
    assert plan.next_action == "FuseKit is continuing with the approved setup plan now."
    assert "provider setup" in plan.resume_hint


def test_gate_service_resume_request_uses_provider_specific_copy(tmp_path) -> None:
    path = tmp_path / "gates.json"
    service = GateService.load(path)
    cases = {
        "provider.cloudflare.authorization": (
            "cloudflare",
            "provider-authorization",
            "rechecking Cloudflare authorization",
        ),
        "provider.resend.domain-setup-retry": (
            "resend",
            "provider-setup-retry",
            "rerunning the provider setup route",
        ),
        "provider.resend.domain-verification": (
            "resend",
            "provider-domain",
            "rechecking the provider domain state",
        ),
        "provider.resend.runtime-values": (
            "resend",
            "provider-runtime-values",
            "rechecking the captured provider values",
        ),
    }
    for gate_id, (provider, classification, _expected) in cases.items():
        service.wait(
            gate_id,
            provider=provider,
            reason="provider gate",
            classification=classification,
        )
        service.request_resume(gate_id)

    loaded = GateService.load(path)
    for gate_id, (_provider, _classification, expected) in cases.items():
        record = loaded.records[gate_id]
        assert expected in record.next_action
        assert "resurface this same gate with updated follow-me instructions" in record.resume_hint
