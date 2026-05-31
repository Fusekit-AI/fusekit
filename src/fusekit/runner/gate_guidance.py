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
        title="GitHub is asking for your approval",
        body=(
            "FuseKit opened GitHub so the source repo can receive deploy keys and encrypted "
            "repo secrets. You only need to sign in and approve the provider screens GitHub shows."
        ),
        actions=(
            "Sign in or create the GitHub account when GitHub asks.",
            "Pass email, passkey, MFA, CAPTCHA, or consent prompts yourself.",
            "When GitHub reveals the approved token, paste it into FuseKit's hidden prompt.",
        ),
        reassurance="FuseKit waits here, then resumes automatically after the token is captured.",
    ),
    "vercel": GateGuidance(
        title="Vercel is checking deploy permission",
        body=(
            "FuseKit is connecting the app repo to Vercel, setting encrypted env vars, and "
            "starting the deployment. Vercel may need you to confirm account or Git access."
        ),
        actions=(
            "Sign in or create the Vercel account when prompted.",
            "Approve GitHub connection, team, billing, MFA, CAPTCHA, or consent prompts if shown.",
            "When Vercel reveals the approved token, paste it into FuseKit's hidden prompt.",
        ),
        reassurance="FuseKit keeps the run alive and continues once Vercel accepts the gate.",
    ),
    "cloudflare": GateGuidance(
        title="Cloudflare is checking domain control",
        body=(
            "FuseKit is preparing DNS records for the custom domain. Cloudflare may ask you to "
            "prove the domain belongs to this account before records can verify."
        ),
        actions=(
            "Sign in or create the Cloudflare account when prompted.",
            (
                "Pass nameserver, domain ownership, MFA, CAPTCHA, billing, or consent prompts "
                "yourself."
            ),
            (
                "When Cloudflare reveals the approved DNS token, paste it into FuseKit's hidden "
                "prompt."
            ),
        ),
        reassurance="FuseKit will keep retrying DNS verification instead of giving up early.",
    ),
    "resend": GateGuidance(
        title="Resend is checking email sending access",
        body=(
            "FuseKit is preparing email delivery credentials and domain verification records. "
            "Resend may ask for email, account, billing, or domain verification."
        ),
        actions=(
            "Sign in or create the Resend account when prompted.",
            "Pass email verification, MFA, CAPTCHA, billing, consent, or domain checks yourself.",
            "When Resend reveals the API key, paste it into FuseKit's hidden prompt.",
        ),
        reassurance="FuseKit stores the key only in the encrypted vault and then resumes setup.",
    ),
    "oci": GateGuidance(
        title="Oracle Cloud is opening the clean room",
        body=(
            "FuseKit is starting the disposable OCI workspace that runs the setup away from your "
            "computer. Oracle may ask you to sign in, create the account, or approve Cloud Shell."
        ),
        actions=(
            "Sign in or create the OCI account when Oracle asks.",
            "Pass MFA, CAPTCHA, payment verification, tenancy, or Cloud Shell prompts yourself.",
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
            "Pass MFA, CAPTCHA, consent, or organization prompts yourself.",
            "Return to FuseKit after the provider says authorization is complete.",
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
        "Look at the browser or provider tab FuseKit opened.",
        "Complete login, MFA, CAPTCHA, consent, payment, or ownership prompts yourself.",
        "When the page says the action is done, return to FuseKit and it will continue.",
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
