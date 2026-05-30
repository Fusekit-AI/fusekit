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
        required_scopes=("target repo access", "Actions secrets", "deploy keys"),
        account_steps=(
            "Create or sign in to a GitHub account.",
            "Complete any email verification, passkey, MFA, CAPTCHA, or consent challenge.",
            "Create or choose the repository that will receive secrets and deploy keys.",
        ),
        secret_steps=(
            "Create a fine-grained token for the target repository.",
            "Grant only the repository permissions needed for Actions secrets and deploy keys.",
            "Copy the token once; FuseKit will capture it into the encrypted vault.",
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
            "Create or sign in to a Vercel account.",
            "Complete any email verification, SSO, MFA, CAPTCHA, billing, or consent step.",
            "Connect the Git provider or choose an existing project if Vercel requires it.",
        ),
        secret_steps=(
            "Create an account token with access to the target team or project.",
            "Copy the token once; FuseKit will capture it into the encrypted vault.",
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
        required_scopes=("zone read", "DNS edit for the target zone"),
        account_steps=(
            "Create or sign in to a Cloudflare account.",
            "Add or choose the zone that owns the target domain.",
            (
                "Complete nameserver, domain ownership, MFA, CAPTCHA, billing, "
                "or consent steps yourself."
            ),
        ),
        secret_steps=(
            "Create a scoped API token limited to DNS edit on the target zone.",
            "Copy the token once; FuseKit will capture it into the encrypted vault.",
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
        required_scopes=("email send", "domain verification"),
        account_steps=(
            "Create or sign in to a Resend account.",
            "Complete any email verification, MFA, CAPTCHA, billing, or consent step.",
            "Add or choose the sending domain if the app uses a custom sender.",
        ),
        secret_steps=(
            "Create a scoped API key for sending email.",
            "Copy the API key once; FuseKit will capture it into the encrypted vault.",
            "Copy DNS verification records so FuseKit can add them to the DNS plan.",
        ),
    ),
}


def handoff_for(provider: str) -> ProviderHandoff:
    """Return handoff metadata for a provider."""

    try:
        return HANDOFFS[provider]
    except KeyError as exc:
        raise ProviderError(f"No supervised handoff flow exists for provider: {provider}") from exc
