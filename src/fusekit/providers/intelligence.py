"""LLM-oriented provider intelligence loop that compiles validated packs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from fusekit.errors import ProviderError
from fusekit.llm import LlmConfig
from fusekit.providers.capability_pack import (
    ProviderCapabilityPack,
    ProviderEvidence,
    collect_provider_evidence,
    synthesize_provider_pack,
    validate_provider_pack,
    write_provider_pack,
)
from fusekit.vault import Vault

PROVIDER_DOC_HINTS = {
    "github": (
        "https://docs.github.com/actions/security-guides/using-secrets-in-github-actions",
        "https://docs.github.com/rest/deploy-keys",
    ),
    "vercel": (
        "https://vercel.com/docs/projects/environment-variables",
        "https://vercel.com/docs/rest-api",
    ),
    "cloudflare": (
        "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
    ),
    "plaid": ("https://plaid.com/docs/api/", "https://plaid.com/docs/auth/"),
    "resend": ("https://resend.com/docs/api-reference/introduction",),
}


@dataclass(frozen=True)
class ResearchFinding:
    """Non-secret evidence used to draft a provider pack."""

    source: str
    summary: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, str]:
        """Serialize the finding."""

        return {"source": self.source, "summary": self.summary, "confidence": self.confidence}


@dataclass(frozen=True)
class IntelligenceLoopResult:
    """Result of a provider intelligence loop run."""

    pack: ProviderCapabilityPack
    findings: tuple[ResearchFinding, ...]
    repairs: tuple[str, ...] = ()
    used_llm: bool = False
    cached_path: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize without secrets."""

        return {
            "provider": self.pack.provider,
            "used_llm": self.used_llm,
            "cached_path": self.cached_path,
            "findings": [finding.to_dict() for finding in self.findings],
            "repairs": list(self.repairs),
        }


class PackDraftSource(Protocol):
    """Source that can draft provider packs from evidence and findings."""

    def draft_pack(
        self,
        *,
        provider: str,
        app_path: Path,
        evidence: ProviderEvidence,
        findings: tuple[ResearchFinding, ...],
        validation_error: str = "",
    ) -> ProviderCapabilityPack:
        """Draft a provider capability pack."""


class ProviderResearchSource(Protocol):
    """Source that can gather non-secret provider setup evidence before drafting."""

    def research(
        self,
        *,
        provider: str,
        evidence: ProviderEvidence,
    ) -> tuple[ResearchFinding, ...]:
        """Gather provider research findings."""


class ResearchSpine(Protocol):
    """OpenClaw-like browser surface for provider research."""

    def open(self, url: str) -> object:
        """Open a provider documentation URL."""

    def snapshot(self) -> object:
        """Capture current page state."""


@dataclass(frozen=True)
class OpenClawProviderResearch:
    """Browse provider docs/UI through an OpenClaw-compatible spine."""

    spine: ResearchSpine
    max_pages: int = 3

    def research(
        self,
        *,
        provider: str,
        evidence: ProviderEvidence,
    ) -> tuple[ResearchFinding, ...]:
        """Open docs/search pages and capture non-secret snapshots for pack drafting."""

        findings: list[ResearchFinding] = []
        for url in _research_urls(provider, evidence)[: self.max_pages]:
            try:
                self.spine.open(url)
                snapshot = self.spine.snapshot()
            except Exception as exc:
                findings.append(
                    ResearchFinding(
                        source=url,
                        summary=f"OpenClaw research could not capture this page: {exc}",
                        confidence="low",
                    )
                )
                continue
            text = str(getattr(snapshot, "stdout", ""))[:2000]
            findings.append(
                ResearchFinding(
                    source=url,
                    summary=_summarize_snapshot(provider, text),
                    confidence="medium" if text else "low",
                )
            )
        return tuple(findings)


@dataclass
class HeuristicPackDraftSource:
    """Fallback source that uses deterministic synthesis."""

    def draft_pack(
        self,
        *,
        provider: str,
        app_path: Path,
        evidence: ProviderEvidence,
        findings: tuple[ResearchFinding, ...],
        validation_error: str = "",
    ) -> ProviderCapabilityPack:
        """Draft a provider capability pack."""

        del findings, validation_error
        return synthesize_provider_pack(provider, app_path, evidence=evidence)


@dataclass(frozen=True)
class OpenAiPackDraftSource:
    """OpenAI-compatible pack drafter."""

    config: LlmConfig
    vault: Vault

    def draft_pack(
        self,
        *,
        provider: str,
        app_path: Path,
        evidence: ProviderEvidence,
        findings: tuple[ResearchFinding, ...],
        validation_error: str = "",
    ) -> ProviderCapabilityPack:
        """Ask the configured LLM for a provider pack JSON object."""

        del app_path
        token = self.vault.require(self.config.record_id).value
        payload = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are FuseKit's provider pack compiler. Return only one JSON "
                        "object matching schema_version fusekit.provider-pack.v1. Do not "
                        "include raw secrets. Do not include bypass instructions for CAPTCHA, "
                        "MFA, passkeys, payment, fraud checks, consent, or password managers. "
                        "Prefer setup/verification recipes that use FuseKit capability handlers."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "provider": provider,
                            "evidence": evidence.__dict__,
                            "findings": [finding.to_dict() for finding in findings],
                            "validation_error": validation_error,
                            "required_sections": [
                                "detection",
                                "handoff",
                                "required_secrets",
                                "setup",
                                "verification",
                                "rollback",
                            ],
                        },
                        sort_keys=True,
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        request = Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=90) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Provider intelligence LLM failed HTTP {exc.code}: {detail}"
            ) from exc
        except (URLError, json.JSONDecodeError, KeyError) as exc:
            raise ProviderError(f"Provider intelligence LLM failed: {exc}") from exc
        content = str(data["choices"][0]["message"]["content"])
        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ProviderError("Provider intelligence LLM returned non-JSON content.") from exc
        if not isinstance(raw, dict):
            raise ProviderError("Provider intelligence LLM returned a non-object pack.")
        return ProviderCapabilityPack.from_dict(raw)


@dataclass
class ProviderIntelligenceLoop:
    """Research, draft, validate, repair, and cache a provider capability pack."""

    draft_source: PackDraftSource = field(default_factory=HeuristicPackDraftSource)
    research_sources: tuple[ProviderResearchSource, ...] = ()
    max_repairs: int = 2

    def run(
        self,
        *,
        provider: str,
        app_path: Path,
        output_path: Path | None = None,
    ) -> IntelligenceLoopResult:
        """Compile a validated pack."""

        evidence = collect_provider_evidence(app_path)
        findings = _collect_research(provider, evidence, self.research_sources)
        repairs: list[str] = []
        validation_error = ""
        for attempt in range(self.max_repairs + 1):
            pack = self.draft_source.draft_pack(
                provider=provider,
                app_path=app_path,
                evidence=evidence,
                findings=findings,
                validation_error=validation_error,
            )
            try:
                validate_provider_pack(pack)
            except ProviderError as exc:
                validation_error = str(exc)
                repairs.append(validation_error)
                if attempt >= self.max_repairs:
                    raise
                continue
            cached_path = ""
            if output_path is not None:
                write_provider_pack(pack, output_path)
                cached_path = str(output_path)
            return IntelligenceLoopResult(
                pack=pack,
                findings=findings,
                repairs=tuple(repairs),
                used_llm=not isinstance(self.draft_source, HeuristicPackDraftSource),
                cached_path=cached_path,
            )
        raise ProviderError("Provider intelligence loop did not produce a valid pack.")


def _research_from_evidence(
    provider: str,
    evidence: ProviderEvidence,
) -> tuple[ResearchFinding, ...]:
    findings = [
        ResearchFinding(
            source="app-scan",
            summary=(
                f"Detected provider {provider} from dependencies={list(evidence.dependencies)} "
                f"env={list(evidence.env_names)} imports={list(evidence.imports)}"
            ),
            confidence="high" if evidence.dependencies or evidence.env_names else "low",
        )
    ]
    return tuple(findings)



def _collect_research(
    provider: str,
    evidence: ProviderEvidence,
    sources: tuple[ProviderResearchSource, ...],
) -> tuple[ResearchFinding, ...]:
    findings = list(_research_from_evidence(provider, evidence))
    for source in sources:
        findings.extend(source.research(provider=provider, evidence=evidence))
    return tuple(findings)


def _research_urls(provider: str, evidence: ProviderEvidence) -> tuple[str, ...]:
    urls: list[str] = list(PROVIDER_DOC_HINTS.get(provider, ()))
    for env_name in evidence.env_names:
        if env_name.lower().startswith(provider.replace("-", "_")):
            urls.append(
                "https://www.google.com/search?q="
                + quote_plus(f"{provider} developer docs {env_name} API key webhook setup")
            )
    if not urls:
        urls.extend(
            [
                f"https://docs.{provider}.com/",
                f"https://{provider}.com/docs",
                "https://www.google.com/search?q="
                + quote_plus(f"{provider} developer API keys webhooks environment variables"),
            ]
        )
    deduped: list[str] = []
    for url in urls:
        if url not in deduped:
            deduped.append(url)
    return tuple(deduped)


def _summarize_snapshot(provider: str, text: str) -> str:
    if not text:
        return f"No readable OpenClaw snapshot was available for {provider}."
    keywords = (
        "api key",
        "token",
        "webhook",
        "environment",
        "oauth",
        "redirect",
        "domain",
        "dns",
        "secret",
    )
    lines = []
    for line in text.splitlines():
        stripped = " ".join(line.split())
        if stripped and any(keyword in stripped.lower() for keyword in keywords):
            lines.append(stripped)
        if len(lines) >= 8:
            break
    if not lines:
        return text[:600]
    return " | ".join(lines)[:1200]
