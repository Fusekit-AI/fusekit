"""Human-friendly guidance for provider-created gates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GateGuidance:
    """Non-secret instructions shown while FuseKit waits for a human gate."""

    title: str
    body: str
    actions: tuple[str, ...]
    reassurance: str


_PROVIDER_GUIDANCE: dict[str, GateGuidance] = {
    "github": GateGuidance(
        title="GitHub needs a repo-scoped setup token",
        body=(
            "FuseKit needs GitHub permission for the target repo so it can create deploy keys "
            "and encrypted Actions secrets without broad account access."
        ),
        actions=(
            "Sign in or create the GitHub account when GitHub asks.",
            (
                "Create a fine-grained personal access token limited to the target repo named "
                "by FuseKit."
            ),
            (
                "Grant repository Secrets read/write and Administration read/write, then finish "
                "highlighted passkey, MFA, CAPTCHA, or consent prompts."
            ),
            (
                "When GitHub reveals the token once, use the VM-local capture path; FuseKit "
                "stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will use GitHub's API and continue once the scoped token is captured.",
    ),
    "vercel": GateGuidance(
        title="Vercel needs a deployment token",
        body=(
            "FuseKit needs a Vercel token scoped to the personal account or team that will own "
            "the project, environment variables, and deployment."
        ),
        actions=(
            "Sign in or create the Vercel account when prompted.",
            (
                "If Vercel says GitHub is not connected, open Login Connections and connect "
                "GitHub before creating or linking the project."
            ),
            (
                "Open Account Settings, choose Tokens, create a token named FuseKit deployment "
                "for this app, and use a short expiration."
            ),
            (
                "Choose the personal account or team FuseKit named, then finish highlighted "
                "GitHub, billing, MFA, CAPTCHA, or consent prompts."
            ),
            (
                "When Vercel reveals the token once, use the VM-local capture path; FuseKit "
                "stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will continue through Vercel's API after capture succeeds.",
    ),
    "cloudflare": GateGuidance(
        title="Cloudflare needs a scoped DNS token",
        body=(
            "FuseKit needs one Cloudflare token scoped to this domain so it can create and verify "
            "only the DNS records named in the setup plan."
        ),
        actions=(
            "Sign in or create the Cloudflare account when prompted.",
            (
                "Open API Tokens, choose Create Token, choose Custom token, and name it "
                "FuseKit DNS for this domain."
            ),
            (
                "Grant Zone Read and DNS Edit for the specific zone FuseKit named, then continue "
                "through highlighted Cloudflare MFA, CAPTCHA, consent, or token reveal gates."
            ),
            (
                "When Cloudflare reveals the token once, use the VM-local capture prompt; FuseKit "
                "stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will use the token through Cloudflare's API and keep retrying DNS verification.",
    ),
    "resend": GateGuidance(
        title="Resend needs an email API key",
        body=(
            "FuseKit needs a Resend API key so it can configure email sending and verify the "
            "domain records named in the setup plan."
        ),
        actions=(
            "Sign in or create the Resend account when prompted.",
            (
                "Open API Keys, create a key named FuseKit email for this app, and choose the "
                "sending/domain access Resend requires."
            ),
            (
                "Finish highlighted email, MFA, CAPTCHA, billing, consent, or domain checks."
            ),
            (
                "When Resend reveals the API key once, use the VM-local capture path; FuseKit "
                "stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will use Resend's API and continue once the email key is captured.",
    ),
    "oci": GateGuidance(
        title="Oracle Cloud is opening the clean room",
        body=(
            "FuseKit is starting the disposable OCI workspace that runs the setup away from your "
            "computer. Oracle may ask you to sign in, create the account, or approve Cloud Shell."
        ),
        actions=(
            "Sign in or create the OCI account when Oracle asks.",
            "Complete the highlighted MFA, CAPTCHA, payment, tenancy, or Cloud Shell prompt.",
            "Leave the Cloud Shell tab open; FuseKit will continue from there.",
        ),
        reassurance="FuseKit treats this as a waiting state, not a failure.",
    ),
    "openai": GateGuidance(
        title="OpenAI is authorizing the brain lane",
        body=(
            "FuseKit needs an LLM route for provider-page reasoning. If no API key is already "
            "available, OpenClaw opens the OpenAI authorization step."
        ),
        actions=(
            "Sign in to OpenAI when prompted.",
            "Complete the highlighted MFA, CAPTCHA, consent, or organization prompt.",
            "Click the resume button after the provider says authorization is complete.",
        ),
        reassurance=(
            "FuseKit encrypts captured auth state and detonates plaintext worker state later."
        ),
    ),
}

_GENERIC = GateGuidance(
    title="A provider needs a human check",
    body=(
        "FuseKit has done everything it can safely automate. The provider is now asking for "
        "something only the account owner is allowed to approve."
    ),
    actions=(
        "Use the Open provider gate button to bring the exact provider page forward.",
        "Complete only highlighted login, MFA, CAPTCHA, consent, payment, or ownership prompts.",
        "Click the resume button here; FuseKit will verify the provider state before continuing.",
    ),
    reassurance="The worker remains alive and will retry this gate until it passes.",
)


def provider_gate_guidance(provider: str) -> GateGuidance:
    """Return human-friendly guidance for a provider gate."""

    key = provider.strip().lower()
    return _PROVIDER_GUIDANCE.get(key, _GENERIC)


def infer_gate_provider(text: str) -> str:
    """Infer provider from a non-secret step detail or gate id."""

    lower = text.lower()
    for provider in _PROVIDER_GUIDANCE:
        if provider in lower:
            return provider
    if "oracle" in lower or "cloud shell" in lower:
        return "oci"
    return ""
