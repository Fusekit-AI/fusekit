"""Supervised provider signup and authorization handoff flows."""

from __future__ import annotations

from dataclasses import dataclass

from fusekit.errors import ProviderError


@dataclass(frozen=True)
class ProviderHandoff:
    """Human-supervised provider onboarding instructions."""

    provider: str
    signup_url: str
    token_url: str
    project_url: str
    token_env: str
    token_record_id: str
    token_label: str
    required_scopes: tuple[str, ...]
    account_steps: tuple[str, ...]
    secret_steps: tuple[str, ...]

    def urls(self, include_project: bool = False) -> tuple[str, ...]:
        """Return the URLs FuseKit should open for the user."""

        urls = (self.signup_url, self.token_url)
        if include_project:
            return urls + (self.project_url,)
        return urls


HANDOFFS: dict[str, ProviderHandoff] = {
    "github": ProviderHandoff(
        provider="github",
        signup_url="https://github.com/signup",
        token_url="https://github.com/settings/tokens?type=beta",
        project_url="https://github.com/new",
        token_env="GITHUB_TOKEN",
        token_record_id="provider.github.token",
        token_label="GitHub API token",
        required_scopes=(
            "target repo only",
            "repository Secrets read/write",
            "repository Administration read/write",
        ),
        account_steps=(
            "Open GitHub in the VM browser and create or sign in to the account.",
            "Complete the highlighted email, passkey, MFA, CAPTCHA, or consent challenge.",
            "Create or choose the exact repository that will receive secrets and deploy keys.",
        ),
        secret_steps=(
            "Create a fine-grained token named FuseKit setup for only the target repository.",
            "Grant repository Secrets read/write and Administration read/write.",
            (
                "Copy the token once inside the VM browser; FuseKit captures it into the "
                "encrypted vault."
            ),
        ),
    ),
    "vercel": ProviderHandoff(
        provider="vercel",
        signup_url="https://vercel.com/signup",
        token_url="https://vercel.com/account/tokens",
        project_url="https://vercel.com/new",
        token_env="VERCEL_TOKEN",
        token_record_id="provider.vercel.token",
        token_label="Vercel API token",
        required_scopes=("project access", "environment variables", "deployments"),
        account_steps=(
            "Open Vercel in the VM browser and create or sign in to the account.",
            "Complete the highlighted email, SSO, MFA, CAPTCHA, billing, or consent step.",
            "Connect only the named GitHub account/repo under Login Connections when Vercel asks.",
        ),
        secret_steps=(
            "Create an Account Settings > Tokens token named FuseKit deployment.",
            "Use a short expiration and choose the personal account or team FuseKit named.",
            (
                "Copy the token once inside the VM browser; FuseKit captures it into the "
                "encrypted vault."
            ),
        ),
    ),
    "cloudflare": ProviderHandoff(
        provider="cloudflare",
        signup_url="https://dash.cloudflare.com/sign-up",
        token_url="https://dash.cloudflare.com/profile/api-tokens",
        project_url="https://dash.cloudflare.com/",
        token_env="CLOUDFLARE_API_TOKEN",
        token_record_id="provider.cloudflare.token",
        token_label="Cloudflare API token",
        required_scopes=("Zone / Zone / Read", "Zone / DNS / Edit for the target zone"),
        account_steps=(
            "Open Cloudflare in the VM browser and create or sign in to the account.",
            "Add or choose the exact zone that owns the target domain.",
            (
                "Complete the highlighted nameserver, domain ownership, MFA, CAPTCHA, billing, "
                "or consent step."
            ),
        ),
        secret_steps=(
            "Create a Custom token named FuseKit DNS for this domain.",
            "Grant Zone / Zone / Read and Zone / DNS / Edit.",
            "Set Zone Resources to Include / Specific zone and choose the zone FuseKit named.",
            (
                "Copy the token once inside the VM browser; FuseKit captures it into the "
                "encrypted vault."
            ),
        ),
    ),
    "resend": ProviderHandoff(
        provider="resend",
        signup_url="https://resend.com/signup",
        token_url="https://resend.com/api-keys",
        project_url="https://resend.com/domains",
        token_env="RESEND_API_KEY",
        token_record_id="provider.resend.token",
        token_label="Resend API key",
        required_scopes=("Full access for first setup", "domain and audience setup"),
        account_steps=(
            "Open Resend in the VM browser and create or sign in to the account.",
            "Complete the highlighted email, MFA, CAPTCHA, billing, or consent step.",
            "Let FuseKit create or reuse the sending domain and audience after key capture.",
        ),
        secret_steps=(
            "Create an API key named FuseKit email setup with Full access for this first setup.",
            (
                "Copy the API key once inside the VM browser; FuseKit captures it into the "
                "encrypted vault."
            ),
            "FuseKit reads Resend DNS verification records and adds them to the DNS plan.",
        ),
    ),
}


def handoff_for(provider: str) -> ProviderHandoff:
    """Return handoff metadata for a provider."""

    try:
        return HANDOFFS[provider]
    except KeyError as exc:
        raise ProviderError(f"No supervised handoff flow exists for provider: {provider}") from exc
