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
    loaded.pass_gate("github-auth")
    assert GateService.load(path).records["github-auth"].status == "passed"
