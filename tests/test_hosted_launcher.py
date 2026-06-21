from __future__ import annotations

import json
import re

from fusekit.hosted import build_hosted_launch_plan, render_hosted_launcher
from fusekit.hosted.launcher import public_plan_summary
from fusekit.manifest import (
    DomainRequirement,
    ServiceRequirement,
    SetupManifest,
    WebhookRequirement,
)


def _manifest() -> SetupManifest:
    return SetupManifest(
        app_name="universal-demo",
        app_path=".",
        required_env=("OPENAI_API_KEY", "RESEND_API_KEY", "WEBHOOK_SECRET"),
        services=(
            ServiceRequirement(
                provider="github",
                kind="repository",
                name="source",
                capabilities=("repo_secrets", "deploy_keys", "capability_pack"),
                secrets=("GITHUB_TOKEN",),
            ),
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web",
                capabilities=("project", "env", "deploy", "capability_pack"),
                secrets=("VERCEL_TOKEN",),
            ),
            ServiceRequirement(
                provider="resend",
                kind="email",
                name="email",
                capabilities=("domain", "audience", "capability_pack"),
                secrets=("RESEND_API_KEY",),
            ),
        ),
        domains=(DomainRequirement(domain="launch.example.com", provider="cloudflare"),),
        webhooks=(
            WebhookRequirement(
                name="provider-webhook",
                target_url="/api/webhooks/provider",
            ),
        ),
    )


def test_hosted_launch_plan_is_universal_github_intake() -> None:
    plan = build_hosted_launch_plan(
        _manifest(),
        github_source="https://github.com/example/any-app",
    )
    raw = plan.to_dict()

    assert raw["schema_version"] == "fusekit.hosted-launcher.v1"
    assert raw["intake"] == "github-app"
    assert raw["github_source"] == "https://github.com/example/any-app"
    assert "github" in raw["providers"]
    assert "vercel" in raw["providers"]
    assert "resend" in raw["providers"]
    assert "cloudflare" in raw["providers"]
    assert "webhooks" in raw["providers"]
    assert raw["trust"]["story"] == [
        "open core",
        "narrow permissions",
        "visible plan",
        "redacted proof",
        "reversible setup",
    ]
    assert raw["trust"]["no_terminal_promise"].startswith("No terminal")
    assert raw["trust"]["launch_path"] == [
        "Visit the hosted FuseKit URL.",
        "Install the FuseKit GitHub App on one selected repository.",
        "Review the visible plan and approved action ids before worker start.",
        "Click Start hosted launch and pass only provider-owned human gates.",
        "Receive the live URL, redacted proof receipt, rollback metadata, and detonation receipt.",
    ]
    assert any(
        "one selected repository with contents:read" in item
        for item in raw["trust"]["permissions"]
    )
    assert any(
        "separate visible approval" in item for item in raw["trust"]["permissions"]
    )
    assert "Raw secrets are never rendered" in raw["trust"]["secret_boundary"]


def test_hosted_launcher_html_has_no_terminal_or_download_happy_path() -> None:
    plan = build_hosted_launch_plan(
        _manifest(),
        github_source="https://github.com/example/any-app",
    )
    html = render_hosted_launcher(plan)
    visible_text = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL)

    assert "Launch any GitHub app" in html
    assert "Start hosted launch" in html
    assert "Download redacted plan" not in html
    assert "Trust contract" in html
    assert "Launch path" in html
    assert 'href="#narrow-permissions"' in html
    assert 'id="narrow-permissions"' in html
    assert "Visit the hosted FuseKit URL." in html
    assert "Review the visible plan and approved action ids before worker start." in html
    assert "Receive the live URL, redacted proof receipt" in html
    assert "Narrow permissions" in html
    assert "one selected repository with contents:read" in html
    assert "separate visible approval" in html
    assert "Visible plan" in html
    assert "Redacted proof" in html
    assert "Reversible setup" in html
    assert "No terminal, local install, download, or copied command" in html
    assert "source .venv" not in visible_text
    assert "fusekit launch" not in visible_text
    assert "pip install" not in visible_text
    assert "copy/paste" not in visible_text.lower()
    assert "Preview permissions</button>" not in html
    assert '<button type="button">Start hosted launch</button>' not in html
    assert '<span class="button disabled" aria-disabled="true">Start hosted launch</span>' in html


def test_hosted_launcher_can_link_to_control_room_without_commands() -> None:
    plan = build_hosted_launch_plan(
        _manifest(),
        github_source="https://github.com/example/any-app",
    )
    html = render_hosted_launcher(
        plan,
        launch_url="/github/control-room?installation_id=42&repo=example%2Fany-app",
    )
    visible_text = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL)
    disabled_start = (
        '<span class="button disabled" aria-disabled="true">Start hosted launch</span>'
    )

    assert 'href="/github/control-room?installation_id=42&amp;repo=example%2Fany-app"' in html
    assert disabled_start not in html
    assert "Start hosted launch" in html
    assert "source .venv" not in visible_text
    assert "fusekit launch" not in visible_text


def test_hosted_launcher_embeds_redacted_public_plan_json() -> None:
    plan = build_hosted_launch_plan(
        _manifest(),
        github_source="https://github.com/example/any-app",
    )
    html = render_hosted_launcher(plan)
    match = re.search(
        r'<script id="fusekit-hosted-launch-plan" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert match is not None
    payload = json.loads(match.group(1).replace("&quot;", '"'))
    assert payload["schema_version"] == "fusekit.hosted-launcher.v1"
    assert payload["trust"]["schema_version"] == "fusekit.hosted-trust-contract.v1"
    assert payload["trust"]["proof"] == [
        "Live URL verification",
        "Provider verifier results",
        "DNS propagation status",
        "Redacted setup receipt",
        "Redacted audit log",
        "Run Record",
        "Detonation receipt",
        "Live acceptance report",
    ]
    serialized = json.dumps(payload)
    assert re.search(r"\bgh[pousr]_[A-Za-z0-9_]{12,}", serialized) is None
    assert re.search(r"\bgithub_pat_[A-Za-z0-9_]{12,}", serialized) is None
    assert re.search(r"\bsk-[A-Za-z0-9_-]{12,}", serialized) is None
    assert re.search(r"\bsk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}", serialized) is None
    assert re.search(r"\bre_[A-Za-z0-9_-]{12,}", serialized) is None


def test_public_plan_summary_is_small_and_trust_first() -> None:
    plan = build_hosted_launch_plan(
        _manifest(),
        github_source="https://github.com/example/any-app",
    )
    summary = public_plan_summary(plan)

    assert summary == {
        "schema_version": "fusekit.hosted-launcher.v1",
        "app_name": "universal-demo",
        "github_source": "https://github.com/example/any-app",
        "providers": ["cloudflare", "github", "resend", "vercel", "webhooks"],
        "action_count": len(plan.actions),
        "trust_story": [
            "open core",
            "narrow permissions",
            "visible plan",
            "redacted proof",
            "reversible setup",
        ],
        "no_terminal": True,
        "launch_path": list(plan.trust.launch_path),
        "proof": list(plan.trust.proof),
        "rollback": list(plan.trust.rollback),
    }
