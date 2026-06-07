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
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    loaded.pass_gate("github-auth")
    assert GateService.load(path).records["github-auth"].status == "passed"


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
