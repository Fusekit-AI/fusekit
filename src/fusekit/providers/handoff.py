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

        urls = [self.signup_url, self.token_url]
        if include_project and self.project_url:
            urls.append(self.project_url)
        return tuple(dict.fromkeys(url for url in urls if url))


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
            "repository Secrets: Read and write",
            "repository Administration: Read and write",
        ),
        account_steps=(
            "Open GitHub in the VM browser and create or sign in to the account.",
            "Complete the highlighted email, passkey, MFA, CAPTCHA, or consent challenge.",
            "Create or choose the exact repository that will receive secrets and deploy keys.",
        ),
        secret_steps=(
            (
                "Create a fine-grained token named FuseKit setup and set Resource owner "
                "to the GitHub user or organization FuseKit named."
            ),
            (
                "Set Repository access to Only select repositories and choose only the "
                "target repository FuseKit named."
            ),
            (
                "Grant repository permissions Secrets: Read and write and Administration: "
                "Read and write; leave unrelated permissions at No access."
            ),
            (
                "If GitHub shows an organization approval or SSO step, approve only the "
                "named owner and repo."
            ),
            (
                "Copy the token once inside the VM browser; FuseKit captures it into the "
                "encrypted vault. No paste into your computer is needed because Capture "
                "reads the VM clipboard directly."
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
            (
                "Use the top-left account/team switcher to choose Personal Account unless "
                "FuseKit named a team, then open Account Settings > Tokens."
            ),
            (
                "Create a token named FuseKit deployment and set its scope to Personal "
                "Account or the exact team FuseKit named."
            ),
            "Use a short expiration.",
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
            (
                "Open My Profile > API Tokens > User API Tokens. Do not use API Keys or "
                "Global API Key. Choose Create Token, choose Custom token, and name it "
                "FuseKit DNS for this domain."
            ),
            (
                "In Permissions, add exactly two rows: Zone / Zone / Read and "
                "Zone / DNS / Edit."
            ),
            (
                "In Zone Resources, choose Include / Specific zone and select only the "
                "exact zone FuseKit named."
            ),
            (
                "Leave Client IP Address Filtering and TTL blank unless your organization "
                "requires them, then choose Continue to summary and Create Token."
            ),
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
        project_url="",
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
                "If an existing key already has Full access but the raw value is not available, "
                "create a new setup key because Resend does not reveal old key secrets again."
            ),
            (
                "Copy the API key once inside the VM browser; FuseKit captures it into the "
                "encrypted vault. No paste into your computer is needed because Capture "
                "reads the VM clipboard directly."
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
