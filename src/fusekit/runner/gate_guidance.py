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
    success: tuple[str, ...] = ()
    avoid: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize guidance for the live control-room browser script."""

        return {
            "title": self.title,
            "body": self.body,
            "actions": list(self.actions),
            "reassurance": self.reassurance,
            "success": list(self.success),
            "avoid": list(self.avoid),
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
            "Click Open provider gate in VM so GitHub opens in the VM browser, then sign in "
            "or create the account when GitHub asks.",
            (
                "Open Settings > Developer settings > Personal access tokens > Fine-grained "
                "tokens, click Generate new token, and create a fine-grained personal access "
                "token named FuseKit setup."
            ),
            (
                "Set Resource owner to the GitHub user or organization FuseKit named. If "
                "GitHub shows an organization approval or SSO step, approve only that named "
                "owner and repo."
            ),
            (
                "Set Repository access to Only select repositories and choose the exact target "
                "repo named by FuseKit."
            ),
            (
                "Under Repository permissions, set Secrets to Read and write and Administration "
                "to Read and write. Leave unrelated permissions at No access; Metadata read-only "
                "is included automatically."
            ),
            (
                "When GitHub reveals the token once, copy it inside the VM browser and click "
                "the matching Capture from VM clipboard button; FuseKit stores it only in the "
                "encrypted vault. You do not need to paste it into your computer; Capture "
                "reads the VM clipboard directly."
            ),
        ),
        reassurance="FuseKit will use GitHub's API and continue once the scoped token is captured.",
        success=(
            "A new fine-grained token is copied from GitHub's one-time reveal screen.",
            "The token is limited to the named owner and repository.",
            "Only Secrets and Administration are read/write; unrelated permissions stay off.",
        ),
        avoid=(
            "Do not choose All repositories unless FuseKit explicitly named that scope.",
            "Do not paste the token into the terminal or local browser.",
            "Do not approve unrelated organizations, repos, or SSO prompts.",
        ),
    ),
    "vercel": GateGuidance(
        title="Vercel needs a deployment token",
        body=(
            "FuseKit needs a Vercel token scoped to the personal account or team that will own "
            "the project, environment variables, and deployment. You only approve login, billing, "
            "MFA, CAPTCHA, consent, GitHub connection, or token reveal gates."
        ),
        actions=(
            "Click Open provider gate in VM so Vercel opens in the VM browser, then sign in "
            "or create the account when prompted.",
            (
                "Use the top-left account/team switcher to choose Personal Account unless "
                "FuseKit named a team, then open Account Settings > Tokens."
            ),
            (
                "Create a token named FuseKit deployment and set its scope to Personal "
                "Account or the exact team FuseKit named."
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
                "the matching Capture from VM clipboard button; FuseKit stores it only in the "
                "encrypted vault. You do not need to paste it into your computer; Capture "
                "reads the VM clipboard directly."
            ),
        ),
        reassurance="FuseKit will continue through Vercel's API after capture succeeds.",
        success=(
            "A new Vercel token is copied from the one-time reveal screen.",
            "The token is scoped to Personal Account or the exact team FuseKit named.",
            "Any GitHub connection approval names only the target account and repo.",
        ),
        avoid=(
            "Do not create the token under the wrong team or account.",
            "Do not connect extra GitHub repos or organizations.",
            "Do not paste the token anywhere except the VM clipboard Capture flow.",
        ),
    ),
    "cloudflare": GateGuidance(
        title="Cloudflare needs a scoped DNS token",
        body=(
            "FuseKit needs one Cloudflare token scoped to this domain so it can create and verify "
            "only the DNS records named in the setup plan. You approve account, domain, MFA, "
            "CAPTCHA, consent, nameserver, billing, or token reveal gates; FuseKit applies DNS."
        ),
        actions=(
            "Click Open provider gate in VM so Cloudflare opens in the VM browser, then sign "
            "in or create the account when prompted.",
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
                "When Cloudflare reveals the token once, copy it inside the VM browser and click "
                "the matching Capture from VM clipboard button; FuseKit stores it only in the "
                "encrypted vault. You do not need to paste it into your computer; Capture "
                "reads the VM clipboard directly."
            ),
        ),
        reassurance=(
            "FuseKit will use the token through Cloudflare's API and keep retrying "
            "DNS verification."
        ),
        success=(
            "A Custom User API Token is copied from Cloudflare's one-time reveal screen.",
            "Permissions are Zone / Zone / Read and Zone / DNS / Edit.",
            "Zone Resources is limited to the exact zone FuseKit named.",
        ),
        avoid=(
            "Do not use Global API Key or the older API Keys page.",
            "Do not include all zones unless FuseKit explicitly named that scope.",
            "Do not add IP filtering or TTL rules unless your organization requires them.",
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
            "Click Open provider gate in VM so Resend opens in the VM browser, then sign in "
            "or create the account when prompted.",
            (
                "Open API Keys, create a key named FuseKit email setup, and choose Full access "
                "for this first setup key."
            ),
            (
                "If the key card says Full access and All domains, the permissions are fine; "
                "the missing piece is only the raw key value copied into FuseKit."
            ),
            (
                "An existing key card that says Full access is not enough unless you already "
                "have the raw key value. Resend does not reveal old key secrets again; create "
                "a new setup key if you cannot copy the existing value."
            ),
            (
                "Do not create Resend domains or audiences by hand. After capture, FuseKit "
                "uses Resend's API to create or reuse the sending domain and audience "
                "required by the app."
            ),
            (
                "If Resend shows No domains yet, stay on API Keys; do not click Add domain. "
                "FuseKit creates the domain after the key is captured."
            ),
            (
                "When Resend reveals the API key once, copy it inside the VM browser and click "
                "the matching Capture from VM clipboard button; FuseKit stores it only in the "
                "encrypted vault. You do not need to paste it into your computer; Capture "
                "reads the VM clipboard directly."
            ),
            (
                "After the demo or setup, rotate or revoke the setup key from Resend if you want "
                "a narrower long-term key."
            ),
        ),
        reassurance="FuseKit will use Resend's API and continue once the email key is captured.",
        success=(
            "A raw Resend API key value is copied from a new one-time reveal screen.",
            "The first setup key has Full access so FuseKit can create the sending domain.",
            "No Resend domains or audiences need to exist before this key is captured.",
            "FuseKit owns domain creation, DNS record collection, and optional audience setup.",
        ),
        avoid=(
            "Do not rely on an existing key card unless you can copy the raw key value.",
            "Do not click Add domain when Resend says No domains yet.",
            "Do not create audiences by hand; FuseKit creates them through Resend's API "
            "only when the app requires one.",
        ),
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
        success=(
            "Cloud Shell is open and ready to run the launcher command.",
            "OCI account, tenancy, payment, MFA, or Cloud Shell prompts are complete.",
        ),
        avoid=(
            "Do not close Cloud Shell while the launcher is provisioning.",
            "Do not create extra compartments or VMs by hand; FuseKit provisions the "
            "workspace it needs.",
        ),
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
            "Click I finished this step after the provider says authorization is complete.",
        ),
        reassurance=(
            "FuseKit encrypts captured auth state and detonates plaintext worker state later."
        ),
        success=(
            "OpenAI authorization shows a success callback in the VM browser.",
            "FuseKit resumes without asking for a raw OpenAI key in the control room.",
        ),
        avoid=(
            "Do not restart the auth flow in a different browser profile.",
            "Do not paste provider callback URLs into chat or terminal logs.",
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
        "Click Open provider gate in VM to bring the exact provider page forward.",
        "Complete only highlighted login, MFA, CAPTCHA, consent, payment, or ownership prompts.",
        (
            "If the provider reveals a copy-once API key or token and FuseKit shows a "
            "Capture from VM clipboard button, copy the value inside the VM browser and "
            "click the matching button. You do not need to paste it into your computer; "
            "Capture reads the VM clipboard directly."
        ),
        (
            "If no Capture from VM clipboard button is shown, click I finished this step "
            "after the provider confirms the gate is complete."
        ),
    ),
    reassurance="The worker remains alive and will retry this gate until it passes.",
    success=(
        "The provider page confirms the account-owner action is complete.",
        "If a one-time token is revealed, FuseKit has captured it from the VM clipboard.",
    ),
    avoid=(
        "Do not use a local browser for this gate.",
        "Do not move secrets outside the VM browser and Capture flow unless "
        "FuseKit explicitly labels the run as CLI-only.",
    ),
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
