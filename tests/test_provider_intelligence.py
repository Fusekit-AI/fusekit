from __future__ import annotations

import json

from fusekit.providers.intelligence import OpenClawProviderResearch, ProviderIntelligenceLoop


def test_provider_intelligence_loop_compiles_valid_pack(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"plaid": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "app.ts").write_text("process.env.PLAID_SECRET", encoding="utf-8")
    output = tmp_path / "plaid.json"

    result = ProviderIntelligenceLoop().run(
        provider="plaid",
        app_path=tmp_path,
        output_path=output,
    )

    assert result.pack.provider == "plaid"
    assert result.findings
    assert output.exists()
    assert result.to_dict()["provider"] == "plaid"


class _FakeSpine:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def open(self, url: str) -> object:
        self.urls.append(url)
        return object()

    def snapshot(self) -> object:
        class Snapshot:
            stdout = "API key token webhook environment variables redirect URI"

        return Snapshot()


def test_provider_intelligence_browses_docs_before_drafting(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "mail.ts").write_text("process.env.RESEND_API_KEY", encoding="utf-8")
    spine = _FakeSpine()

    result = ProviderIntelligenceLoop(
        research_sources=(OpenClawProviderResearch(spine),),
    ).run(provider="resend", app_path=tmp_path)

    assert spine.urls
    assert any(finding.source.startswith("https://") for finding in result.findings)
    assert result.pack.provider == "resend"
