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

    def to_dict(self) -> dict[str, object]:
        """Serialize guidance for the live control-room browser script."""

        return {
            "title": self.title,
            "body": self.body,
            "actions": list(self.actions),
            "reassurance": self.reassurance,
        }


_PROVIDER_GUIDANCE: dict[str, GateGuidance] = {
    "github": GateGuidance(
        title="GitHub needs a repo-scoped setup token",
        body=(
            "FuseKit needs GitHub permission for the target repo so it can create deploy keys "
            "and encrypted Actions secrets without broad account access. You only approve login, "
            "MFA, CAPTCHA, consent, or token reveal gates; FuseKit does the wiring after capture."
        ),
        actions=(
            "Use the Open provider gate button so GitHub opens in the VM browser, then sign in "
            "or create the account when GitHub asks.",
            (
                "Open Settings > Developer settings > Personal access tokens > Fine-grained "
                "tokens and create a fine-grained personal access token named FuseKit setup."
            ),
            (
                "Set Repository access to Only select repositories and choose the exact target "
                "repo named by FuseKit."
            ),
            (
                "Grant repository permissions Secrets read/write and Administration read/write; "
                "leave Metadata read-only, which GitHub includes automatically."
            ),
            (
                "When GitHub reveals the token once, copy it inside the VM browser and click "
                "Capture in FuseKit; FuseKit stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will use GitHub's API and continue once the scoped token is captured.",
    ),
    "vercel": GateGuidance(
        title="Vercel needs a deployment token",
        body=(
            "FuseKit needs a Vercel token scoped to the personal account or team that will own "
            "the project, environment variables, and deployment. You only approve login, billing, "
            "MFA, CAPTCHA, consent, GitHub connection, or token reveal gates."
        ),
        actions=(
            "Use the Open provider gate button so Vercel opens in the VM browser, then sign in "
            "or create the account when prompted.",
            (
                "Open Account Settings > Tokens and create a token named FuseKit deployment "
                "for the personal account or team FuseKit named."
            ),
            (
                "Use a short expiration. FuseKit will create or connect the project, push "
                "environment variables, and deploy after capture."
            ),
            (
                "If Vercel asks for GitHub Login Connections, connect only the GitHub account "
                "and repo FuseKit named, then return to the token page."
            ),
            (
                "When Vercel reveals the token once, copy it inside the VM browser and click "
                "Capture in FuseKit; FuseKit stores it only in the encrypted vault."
            ),
        ),
        reassurance="FuseKit will continue through Vercel's API after capture succeeds.",
    ),
    "cloudflare": GateGuidance(
        title="Cloudflare needs a scoped DNS token",
        body=(
            "FuseKit needs one Cloudflare token scoped to this domain so it can create and verify "
            "only the DNS records named in the setup plan. You approve account, domain, MFA, "
            "CAPTCHA, consent, nameserver, billing, or token reveal gates; FuseKit applies DNS."
        ),
        actions=(
            "Use the Open provider gate button so Cloudflare opens in the VM browser, then sign "
            "in or create the account when prompted.",
            (
                "Open My Profile > API Tokens, choose Create Token, choose Custom token, and "
                "name it FuseKit DNS for this domain."
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
                "When Cloudflare reveals the token once, copy it inside the VM browser and click "
                "Capture in FuseKit; FuseKit stores it only in the encrypted vault."
            ),
        ),
        reassurance=(
            "FuseKit will use the token through Cloudflare's API and keep retrying "
            "DNS verification."
        ),
    ),
    "resend": GateGuidance(
        title="Resend needs an email API key",
        body=(
            "FuseKit needs the first Resend setup key before any Resend domain exists. That is "
            "why this gate comes before Cloudflare DNS: FuseKit creates or reuses the Resend "
            "domain, reads the DNS records Resend returns, then asks Cloudflare to apply them."
        ),
        actions=(
            "Use the Open provider gate button so Resend opens in the VM browser, then sign in "
            "or create the account when prompted.",
            (
                "Open API Keys, create a key named FuseKit email setup, and choose Full access "
                "for this first setup key."
            ),
            (
                "Do not create Resend domains or audiences by hand unless FuseKit asks. After "
                "capture, FuseKit uses Resend's API to create or reuse the sending domain and "
                "audience required by the app."
            ),
            (
                "When Resend reveals the API key once, copy it inside the VM browser and click "
                "Capture in FuseKit; FuseKit stores it only in the encrypted vault."
            ),
            (
                "After the demo or setup, rotate or revoke the setup key from Resend if you want "
                "a narrower long-term key."
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


def gate_guidance_payload() -> dict[str, object]:
    """Return provider guidance with one Python source of truth for all renderers."""

    return {
        "providers": {
            provider: guidance.to_dict()
            for provider, guidance in _PROVIDER_GUIDANCE.items()
        },
        "generic": _GENERIC.to_dict(),
    }


def infer_gate_provider(text: str) -> str:
    """Infer provider from a non-secret step detail or gate id."""

    lower = text.lower()
    for provider in _PROVIDER_GUIDANCE:
        if provider in lower:
            return provider
    if "oracle" in lower or "cloud shell" in lower:
        return "oci"
    return ""
