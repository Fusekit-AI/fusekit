"""Provider capability packs synthesized from app evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fusekit.errors import ProviderError
from fusekit.providers.handoff import ProviderHandoff
from fusekit.providers.secret_routing import classify_secret_name

PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
RAW_SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{12,}|"
    r"(?:key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}"
    r")",
    re.IGNORECASE,
)
BANNED_PHRASES = (
    "bypass captcha",
    "solve captcha automatically",
    "bypass mfa",
    "disable mfa",
    "bypass passkey",
    "skip fraud",
    "bypass fraud",
    "export password manager",
    "scrape password manager",
    "harvest credentials",
    "steal credentials",
    "skip consent",
    "accept consent without user",
)
SERVICE_GATE_WORDS = (
    "captcha",
    "mfa",
    "passkey",
    "payment",
    "billing",
    "fraud",
    "consent",
    "identity",
    "verification",
)
LAUNCHER_CAPTURE_PHRASES = (
    "vm browser",
    "capture reads the vm clipboard directly",
)
LAUNCHER_OPEN_GATE_PHRASE = "open provider gate in vm"
NO_HOST_PASTE_PHRASES = (
    "no paste into your computer",
    "do not paste it into your computer",
    "do not paste into your computer",
)
BUILT_IN_PROVIDERS = {"github", "vercel", "cloudflare", "dns"}
FRAMEWORK_ENV_PREFIXES = {
    "astro",
    "next",
    "nuxt",
    "public",
    "react",
    "remix",
    "svelte",
    "vite",
}
APP_ENV_SETUP_KINDS = {"github-repo-secrets", "vercel-env"}
HTTP_JSON_PURPOSES = {
    "verify-auth",
    "verify-resource",
    "verify-domain",
    "verify-webhook",
    "verify-health",
}
ACCOUNT_CREATION_MODES = {"api", "supervised", "none"}


@dataclass(frozen=True)
class ProviderDetection:
    """How FuseKit recognizes a provider in an app."""

    dependencies: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()
    env_prefixes: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    docs_urls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, list[str]]:
        """Serialize detection hints."""

        return {
            "dependencies": list(self.dependencies),
            "env_names": list(self.env_names),
            "env_prefixes": list(self.env_prefixes),
            "imports": list(self.imports),
            "docs_urls": list(self.docs_urls),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProviderDetection:
        """Deserialize detection hints."""

        return cls(
            dependencies=_tuple(raw.get("dependencies", ()), "detection.dependencies"),
            env_names=_tuple(raw.get("env_names", ()), "detection.env_names"),
            env_prefixes=_tuple(raw.get("env_prefixes", ()), "detection.env_prefixes"),
            imports=_tuple(raw.get("imports", ()), "detection.imports"),
            docs_urls=_tuple(raw.get("docs_urls", ()), "detection.docs_urls"),
        )


@dataclass(frozen=True)
class PackHandoff:
    """Provider URLs and human gates needed for supervised setup."""

    signup_url: str
    token_url: str
    project_url: str = ""
    login_url: str = ""
    token_env: str = ""
    token_record_id: str = ""
    token_label: str = ""
    required_scopes: tuple[str, ...] = ()
    account_steps: tuple[str, ...] = ()
    secret_steps: tuple[str, ...] = ()
    service_gates: tuple[str, ...] = ()
    account_creation: str = "supervised"
    account_creation_recipe: str = ""
    account_creation_reason: str = "Provider account signup is a supervised service gate."

    def to_dict(self) -> dict[str, object]:
        """Serialize handoff metadata."""

        return {
            "signup_url": self.signup_url,
            "login_url": self.login_url,
            "token_url": self.token_url,
            "project_url": self.project_url,
            "token_env": self.token_env,
            "token_record_id": self.token_record_id,
            "token_label": self.token_label,
            "required_scopes": list(self.required_scopes),
            "account_steps": list(self.account_steps),
            "secret_steps": list(self.secret_steps),
            "service_gates": list(self.service_gates),
            "account_creation": self.account_creation,
            "account_creation_recipe": self.account_creation_recipe,
            "account_creation_reason": self.account_creation_reason,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PackHandoff:
        """Deserialize handoff metadata."""

        return cls(
            signup_url=_string(raw, "signup_url"),
            login_url=str(raw.get("login_url", "")),
            token_url=_string(raw, "token_url"),
            project_url=str(raw.get("project_url", "")),
            token_env=str(raw.get("token_env", "")),
            token_record_id=str(raw.get("token_record_id", "")),
            token_label=str(raw.get("token_label", "")),
            required_scopes=_tuple(raw.get("required_scopes", ()), "handoff.required_scopes"),
            account_steps=_tuple(raw.get("account_steps", ()), "handoff.account_steps"),
            secret_steps=_tuple(raw.get("secret_steps", ()), "handoff.secret_steps"),
            service_gates=_tuple(raw.get("service_gates", ()), "handoff.service_gates"),
            account_creation=str(raw.get("account_creation", "supervised")),
            account_creation_recipe=str(raw.get("account_creation_recipe", "")),
            account_creation_reason=str(
                raw.get(
                    "account_creation_reason",
                    "Provider account signup is a supervised service gate.",
                )
            ),
        )


@dataclass(frozen=True)
class VerificationRecipe:
    """A non-secret check FuseKit can run after setup."""

    kind: str
    target: str
    expected: str = ""
    secret_refs: tuple[str, ...] = ()
    inputs: dict[str, str] = field(default_factory=dict)
    optional: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize the recipe."""

        return {
            "kind": self.kind,
            "target": self.target,
            "expected": self.expected,
            "secret_refs": list(self.secret_refs),
            "inputs": dict(self.inputs),
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> VerificationRecipe:
        """Deserialize the recipe."""

        return cls(
            kind=_string(raw, "kind"),
            target=_string(raw, "target"),
            expected=str(raw.get("expected", "")),
            secret_refs=_tuple(raw.get("secret_refs", ()), "verification.secret_refs"),
            inputs=_string_mapping(raw.get("inputs", {}), "verification.inputs"),
            optional=bool(raw.get("optional", False)),
        )


@dataclass(frozen=True)
class SetupRecipe:
    """A provider setup operation executed by the capability recipe runtime."""

    kind: str
    target: str
    secret_refs: tuple[str, ...] = ()
    inputs: dict[str, str] = field(default_factory=dict)
    when: str = ""
    optional: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize the setup recipe."""

        return {
            "kind": self.kind,
            "target": self.target,
            "secret_refs": list(self.secret_refs),
            "inputs": dict(self.inputs),
            "when": self.when,
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SetupRecipe:
        """Deserialize the setup recipe."""

        return cls(
            kind=_string(raw, "kind"),
            target=_string(raw, "target"),
            secret_refs=_tuple(raw.get("secret_refs", ()), "setup.secret_refs"),
            inputs=_string_mapping(raw.get("inputs", {}), "setup.inputs"),
            when=str(raw.get("when", "")),
            optional=bool(raw.get("optional", False)),
        )


@dataclass(frozen=True)
class ProviderCapabilityPack:
    """Validated provider setup pack for computer-use and API setup."""

    schema_version: str
    provider: str
    display_name: str
    category: str
    confidence: str
    evidence: tuple[str, ...]
    detection: ProviderDetection
    handoff: PackHandoff
    required_secrets: tuple[str, ...]
    env_vars: tuple[str, ...]
    setup: tuple[SetupRecipe, ...]
    setup_goals: tuple[str, ...]
    verification: tuple[VerificationRecipe, ...]
    rollback: tuple[str, ...]
    provenance: tuple[str, ...] = ()
    tool_permissions: tuple[str, ...] = ()
    prohibited_actions: tuple[str, ...] = (
        "Do not bypass CAPTCHA, MFA, passkeys, provider fraud controls, or consent screens.",
        "Do not export browser password managers or harvest credentials.",
        "Do not expose raw secrets in app files, logs, receipts, prompts, or terminal output.",
    )

    def __post_init__(self) -> None:
        """Derive non-secret provenance and recipe permission bindings when omitted."""

        if not self.provenance:
            provenance = tuple(f"app-evidence:{line}" for line in self.evidence)
            object.__setattr__(self, "provenance", provenance or ("app-evidence:unavailable",))
        if not self.tool_permissions:
            permissions = [
                *(f"setup:{recipe.kind}" for recipe in self.setup),
                *(f"verify:{recipe.kind}" for recipe in self.verification),
            ]
            object.__setattr__(self, "tool_permissions", tuple(sorted(set(permissions))))

    def to_dict(self) -> dict[str, object]:
        """Serialize the pack."""

        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "display_name": self.display_name,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "detection": self.detection.to_dict(),
            "handoff": self.handoff.to_dict(),
            "required_secrets": list(self.required_secrets),
            "env_vars": list(self.env_vars),
            "setup": [recipe.to_dict() for recipe in self.setup],
            "setup_goals": list(self.setup_goals),
            "verification": [recipe.to_dict() for recipe in self.verification],
            "rollback": list(self.rollback),
            "provenance": list(self.provenance),
            "tool_permissions": list(self.tool_permissions),
            "prohibited_actions": list(self.prohibited_actions),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProviderCapabilityPack:
        """Deserialize a provider pack."""

        detection = raw.get("detection", {})
        handoff = raw.get("handoff", {})
        verification = raw.get("verification", ())
        setup = raw.get("setup", ())
        if not isinstance(detection, dict):
            raise ProviderError("provider pack detection must be a mapping.")
        if not isinstance(handoff, dict):
            raise ProviderError("provider pack handoff must be a mapping.")
        if not isinstance(verification, list):
            raise ProviderError("provider pack verification must be a list.")
        if not isinstance(setup, list):
            raise ProviderError("provider pack setup must be a list.")
        return cls(
            schema_version=str(raw.get("schema_version", "fusekit.provider-pack.v1")),
            provider=_string(raw, "provider"),
            display_name=_string(raw, "display_name"),
            category=str(raw.get("category", "service")),
            confidence=str(raw.get("confidence", "medium")),
            evidence=_tuple(raw.get("evidence", ()), "evidence"),
            detection=ProviderDetection.from_dict(detection),
            handoff=PackHandoff.from_dict(handoff),
            required_secrets=_tuple(raw.get("required_secrets", ()), "required_secrets"),
            env_vars=_tuple(raw.get("env_vars", ()), "env_vars"),
            setup=tuple(SetupRecipe.from_dict(item) for item in setup),
            setup_goals=_tuple(raw.get("setup_goals", ()), "setup_goals"),
            verification=tuple(VerificationRecipe.from_dict(item) for item in verification),
            rollback=_tuple(raw.get("rollback", ()), "rollback"),
            provenance=_tuple(raw.get("provenance", ()), "provenance"),
            tool_permissions=_tuple(raw.get("tool_permissions", ()), "tool_permissions"),
            prohibited_actions=_tuple(raw.get("prohibited_actions", ()), "prohibited_actions"),
        )


@dataclass(frozen=True)
class ProviderEvidence:
    """App evidence available to the capability-pack synthesizer."""

    dependencies: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderCatalogEntry:
    """Maintained provider metadata for common generated-app integrations."""

    provider: str
    display_name: str
    category: str
    dependencies: tuple[str, ...]
    env_names: tuple[str, ...]
    env_prefixes: tuple[str, ...]
    imports: tuple[str, ...]
    docs_urls: tuple[str, ...]
    signup_url: str
    token_url: str
    project_url: str
    token_env: str
    token_label: str
    required_scopes: tuple[str, ...]
    account_steps: tuple[str, ...]
    secret_steps: tuple[str, ...]
    service_gates: tuple[str, ...]
    required_secrets: tuple[str, ...]
    setup_goals: tuple[str, ...]
    rollback: tuple[str, ...]
    confidence: str = "medium"
    login_url: str = ""


COMMON_PROVIDER_CATALOG: dict[str, ProviderCatalogEntry] = {
    "stripe": ProviderCatalogEntry(
        provider="stripe",
        display_name="Stripe",
        category="payments",
        dependencies=("stripe", "@stripe/stripe-js", "@stripe/react-stripe-js"),
        env_names=(
            "STRIPE_SECRET_KEY",
            "STRIPE_WEBHOOK_SECRET",
            "STRIPE_PUBLISHABLE_KEY",
            "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
        ),
        env_prefixes=("STRIPE_", "NEXT_PUBLIC_STRIPE_"),
        imports=("stripe", "@stripe/stripe-js", "@stripe/react-stripe-js"),
        docs_urls=("https://docs.stripe.com/",),
        signup_url="https://dashboard.stripe.com/register",
        login_url="https://dashboard.stripe.com/login",
        token_url="https://dashboard.stripe.com/apikeys",
        project_url="https://dashboard.stripe.com/webhooks",
        token_env="STRIPE_SECRET_KEY",
        token_label="Stripe secret key",
        required_scopes=("restricted API key or secret key for the target account",),
        account_steps=(
            (
                "Click Open provider gate in VM so Stripe opens in the VM browser, "
                "then create or sign in to the account."
            ),
            "Complete the highlighted email, MFA, CAPTCHA, business, identity, or payment gate.",
            "Choose test mode or live mode based on the app launch target.",
        ),
        secret_steps=(
            "Open Developers > API keys and capture the approved secret key.",
            "Create the webhook endpoint when the app has a Stripe webhook route.",
            "Capture STRIPE_WEBHOOK_SECRET after Stripe reveals the endpoint signing secret.",
        ),
        service_gates=(
            "email verification",
            "MFA",
            "CAPTCHA",
            "business verification",
            "identity verification",
            "payment verification",
            "consent",
        ),
        required_secrets=("STRIPE_SECRET_KEY",),
        setup_goals=(
            "Create or connect the Stripe account in the requested mode.",
            "Capture only approved Stripe keys and webhook secrets into the encrypted vault.",
            "Configure webhook endpoints inferred from app routes.",
        ),
        rollback=(
            "Delete FuseKit-created Stripe webhook endpoints.",
            "Rotate or revoke Stripe API keys captured for this app.",
            "Remove Stripe env vars from deployment secret stores.",
        ),
    ),
    "supabase": ProviderCatalogEntry(
        provider="supabase",
        display_name="Supabase",
        category="database",
        dependencies=("@supabase/supabase-js", "supabase"),
        env_names=(
            "SUPABASE_URL",
            "SUPABASE_SERVICE_ROLE_KEY",
            "SUPABASE_ANON_KEY",
            "NEXT_PUBLIC_SUPABASE_URL",
            "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        ),
        env_prefixes=("SUPABASE_", "NEXT_PUBLIC_SUPABASE_"),
        imports=("@supabase/supabase-js", "supabase"),
        docs_urls=("https://supabase.com/docs",),
        signup_url="https://supabase.com/dashboard/sign-up",
        login_url="https://supabase.com/dashboard/sign-in",
        token_url="https://supabase.com/dashboard/account/tokens",
        project_url="https://supabase.com/dashboard/projects",
        token_env="SUPABASE_SERVICE_ROLE_KEY",
        token_label="Supabase service role key",
        required_scopes=("project API settings", "database configuration required by the app"),
        account_steps=(
            (
                "Click Open provider gate in VM so Supabase opens in the VM browser, "
                "then create or sign in."
            ),
            "Complete the highlighted email, SSO, MFA, CAPTCHA, billing, or consent gate.",
            "Create or choose the project and region that match the app.",
        ),
        secret_steps=(
            "Open Project Settings > API for the selected project.",
            "Capture SUPABASE_URL and the approved anon or service role key into the vault.",
            "Apply schema, auth redirect, or storage settings only when the app requires them.",
        ),
        service_gates=("email verification", "SSO", "MFA", "CAPTCHA", "billing", "consent"),
        required_secrets=("SUPABASE_SERVICE_ROLE_KEY",),
        setup_goals=(
            "Create or connect the Supabase project.",
            "Capture project URL and keys into the encrypted vault.",
            "Guide schema, auth, and storage setup only where app evidence requires it.",
        ),
        rollback=(
            "Rotate Supabase service role keys captured for this app.",
            "Remove Supabase env vars from deployment secret stores.",
            "Delete FuseKit-created Supabase project resources only after explicit approval.",
        ),
    ),
    "clerk": ProviderCatalogEntry(
        provider="clerk",
        display_name="Clerk",
        category="auth",
        dependencies=("@clerk/nextjs", "@clerk/clerk-react", "@clerk/remix"),
        env_names=(
            "CLERK_SECRET_KEY",
            "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
            "CLERK_WEBHOOK_SECRET",
        ),
        env_prefixes=("CLERK_", "NEXT_PUBLIC_CLERK_"),
        imports=("@clerk/nextjs", "@clerk/clerk-react", "@clerk/remix"),
        docs_urls=("https://clerk.com/docs",),
        signup_url="https://dashboard.clerk.com/sign-up",
        login_url="https://dashboard.clerk.com/sign-in",
        token_url="https://dashboard.clerk.com/last-active?path=api-keys",
        project_url="https://dashboard.clerk.com/apps",
        token_env="CLERK_SECRET_KEY",
        token_label="Clerk secret key",
        required_scopes=("application API keys", "webhook settings when detected"),
        account_steps=(
            (
                "Click Open provider gate in VM so Clerk opens in the VM browser, "
                "then create or sign in."
            ),
            "Complete the highlighted email, MFA, CAPTCHA, billing, or consent gate.",
            "Create or choose the Clerk application for the app.",
        ),
        secret_steps=(
            "Open API Keys for the selected Clerk application.",
            "Capture CLERK_SECRET_KEY and the public publishable key into the vault/env store.",
            "Create a webhook endpoint and capture CLERK_WEBHOOK_SECRET when required.",
        ),
        service_gates=("email verification", "MFA", "CAPTCHA", "billing", "consent"),
        required_secrets=("CLERK_SECRET_KEY",),
        setup_goals=(
            "Create or connect the Clerk application.",
            "Capture Clerk API keys into the encrypted vault.",
            "Configure auth redirect URLs and webhooks inferred from app routes.",
        ),
        rollback=(
            "Delete FuseKit-created Clerk webhook endpoints.",
            "Rotate Clerk secret keys captured for this app.",
            "Remove Clerk env vars from deployment secret stores.",
        ),
    ),
    "neon": ProviderCatalogEntry(
        provider="neon",
        display_name="Neon",
        category="database",
        dependencies=("@neondatabase/serverless", "neonctl"),
        env_names=("NEON_API_KEY", "DATABASE_URL", "POSTGRES_URL"),
        env_prefixes=("NEON_",),
        imports=("@neondatabase/serverless", "neon"),
        docs_urls=("https://neon.tech/docs",),
        signup_url="https://console.neon.tech/signup",
        login_url="https://console.neon.tech/app/projects",
        token_url="https://console.neon.tech/app/settings/api-keys",
        project_url="https://console.neon.tech/app/projects",
        token_env="NEON_API_KEY",
        token_label="Neon API key",
        required_scopes=("project creation or selected project access",),
        account_steps=(
            (
                "Click Open provider gate in VM so Neon opens in the VM browser, "
                "then create or sign in."
            ),
            "Complete the highlighted email, SSO, MFA, CAPTCHA, billing, or consent gate.",
            "Create or choose the Postgres project and branch for the app.",
        ),
        secret_steps=(
            "Create a Neon API key when project automation is needed.",
            "Capture DATABASE_URL or POSTGRES_URL for the selected branch into the vault.",
        ),
        service_gates=("email verification", "SSO", "MFA", "CAPTCHA", "billing", "consent"),
        required_secrets=("NEON_API_KEY",),
        setup_goals=(
            "Create or connect the Neon Postgres project.",
            "Capture the selected branch connection string into the encrypted vault.",
            "Run migrations only through an explicit app-provided command or approval.",
        ),
        rollback=(
            "Rotate Neon API keys captured for this app.",
            "Remove Neon database URLs from deployment secret stores.",
            "Delete FuseKit-created Neon branches or projects only after explicit approval.",
        ),
    ),
    "upstash": ProviderCatalogEntry(
        provider="upstash",
        display_name="Upstash",
        category="cache",
        dependencies=("@upstash/redis", "@upstash/vector", "@upstash/qstash"),
        env_names=(
            "UPSTASH_REDIS_REST_URL",
            "UPSTASH_REDIS_REST_TOKEN",
            "UPSTASH_VECTOR_REST_URL",
            "UPSTASH_VECTOR_REST_TOKEN",
            "QSTASH_TOKEN",
        ),
        env_prefixes=("UPSTASH_", "QSTASH_"),
        imports=("@upstash/redis", "@upstash/vector", "@upstash/qstash"),
        docs_urls=("https://upstash.com/docs",),
        signup_url="https://console.upstash.com/sign-up",
        login_url="https://console.upstash.com/login",
        token_url="https://console.upstash.com/",
        project_url="https://console.upstash.com/",
        token_env="UPSTASH_REDIS_REST_TOKEN",
        token_label="Upstash REST token",
        required_scopes=("resource credentials for Redis, Vector, or QStash used by the app",),
        account_steps=(
            (
                "Click Open provider gate in VM so Upstash opens in the VM browser, "
                "then create or sign in."
            ),
            "Complete the highlighted email, MFA, CAPTCHA, billing, or consent gate.",
            "Create or choose the Redis, Vector, or QStash resource required by the app.",
        ),
        secret_steps=(
            "Open the selected resource details.",
            "Capture the REST URL and token into the encrypted vault.",
        ),
        service_gates=("email verification", "MFA", "CAPTCHA", "billing", "consent"),
        required_secrets=("UPSTASH_REDIS_REST_TOKEN",),
        setup_goals=(
            "Create or connect the Upstash resource inferred from dependencies.",
            "Capture REST URLs and tokens into the encrypted vault.",
        ),
        rollback=(
            "Rotate Upstash tokens captured for this app.",
            "Remove Upstash env vars from deployment secret stores.",
            "Delete FuseKit-created Upstash resources only after explicit approval.",
        ),
    ),
    "openai": ProviderCatalogEntry(
        provider="openai",
        display_name="OpenAI",
        category="ai",
        dependencies=("openai", "@ai-sdk/openai"),
        env_names=("OPENAI_API_KEY",),
        env_prefixes=("OPENAI_",),
        imports=("openai", "@ai-sdk/openai"),
        docs_urls=("https://platform.openai.com/docs",),
        signup_url="https://platform.openai.com/signup",
        login_url="https://platform.openai.com/login",
        token_url="https://platform.openai.com/api-keys",
        project_url="https://platform.openai.com/settings/organization/projects",
        token_env="OPENAI_API_KEY",
        token_label="OpenAI API key",
        required_scopes=("project API key for the selected app project",),
        account_steps=(
            (
                "Click Open provider gate in VM so OpenAI opens in the VM browser, "
                "then create or sign in."
            ),
            "Complete the highlighted email, MFA, CAPTCHA, billing, payment, or consent gate.",
            "Choose the project that should own the app key.",
        ),
        secret_steps=(
            "Create a project API key for the app.",
            "Capture OPENAI_API_KEY into the encrypted vault.",
        ),
        service_gates=("email verification", "MFA", "CAPTCHA", "billing/payment", "consent"),
        required_secrets=("OPENAI_API_KEY",),
        setup_goals=(
            "Create or choose the OpenAI project for the app.",
            "Capture the project API key into the encrypted vault.",
            "Record model/provider settings without hardcoding raw secrets.",
        ),
        rollback=(
            "Revoke the OpenAI API key captured for this app.",
            "Remove OpenAI env vars from deployment secret stores.",
        ),
    ),
}


def load_provider_pack(path: Path) -> ProviderCapabilityPack:
    """Load and validate a provider pack from JSON."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"Cannot read provider capability pack: {path}") from exc
    if not isinstance(raw, dict):
        raise ProviderError("Provider capability pack must be a JSON object.")
    pack = ProviderCapabilityPack.from_dict(raw)
    validate_provider_pack(pack)
    return pack


def write_provider_pack(pack: ProviderCapabilityPack, path: Path) -> None:
    """Write a provider pack as stable JSON."""

    validate_provider_pack(pack)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pack.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_provider_pack(pack: ProviderCapabilityPack) -> None:
    """Reject unsafe or underspecified provider packs."""

    if pack.schema_version != "fusekit.provider-pack.v1":
        raise ProviderError("Unsupported provider capability pack schema_version.")
    if not PROVIDER_ID_RE.match(pack.provider):
        raise ProviderError("Provider id must be lowercase kebab-case.")
    if pack.confidence not in {"low", "medium", "high"}:
        raise ProviderError("Provider pack confidence must be low, medium, or high.")
    if not pack.required_secrets:
        raise ProviderError("Provider pack must name at least one required secret.")
    if not pack.verification:
        raise ProviderError("Provider pack must include at least one verification recipe.")
    if not pack.provenance:
        raise ProviderError("Provider pack must include non-secret provenance.")
    if not pack.tool_permissions:
        raise ProviderError(
            "Provider pack must bind setup/verification recipes to tool permissions."
        )
    _validate_tool_permissions(pack)
    _validate_url(pack.handoff.signup_url, "handoff.signup_url")
    _validate_url(pack.handoff.token_url, "handoff.token_url")
    for field_name, url in (
        ("handoff.login_url", pack.handoff.login_url),
        ("handoff.project_url", pack.handoff.project_url),
    ):
        if url:
            _validate_url(url, field_name)
    env_names = set(pack.required_secrets) | set(pack.env_vars) | set(pack.detection.env_names)
    for env_name in env_names:
        if not ENV_NAME_RE.match(env_name):
            raise ProviderError(f"Invalid env/secret name in provider pack: {env_name}")
    if pack.handoff.token_env and not ENV_NAME_RE.match(pack.handoff.token_env):
        raise ProviderError(f"Invalid handoff token env: {pack.handoff.token_env}")
    if pack.handoff.token_record_id and not pack.handoff.token_record_id.startswith(
        f"provider.{pack.provider}."
    ):
        raise ProviderError("handoff.token_record_id must be provider-scoped.")
    _validate_account_creation(pack)
    for setup_recipe in pack.setup:
        _validate_setup_secret_routes(pack, setup_recipe)
    for verification_recipe in pack.verification:
        _validate_verification_recipe_destination(pack, verification_recipe)
    scan_payload = pack.to_dict()
    scan_payload["prohibited_actions"] = []
    text = json.dumps(scan_payload, sort_keys=True)
    lowered = text.lower()
    for phrase in BANNED_PHRASES:
        if phrase in lowered:
            raise ProviderError(f"Provider pack contains prohibited instruction: {phrase}")
    if RAW_SECRET_RE.search(text):
        raise ProviderError("Provider pack appears to contain raw secret material.")
    gates = " ".join(pack.handoff.service_gates).lower()
    for word in SERVICE_GATE_WORDS:
        if word in lowered and word not in gates and word not in " ".join(
            pack.prohibited_actions
        ).lower():
            raise ProviderError(f"Provider pack references {word} without a service gate.")
    _validate_launcher_capture_handoff(pack)


def handoff_from_provider_pack(pack: ProviderCapabilityPack) -> ProviderHandoff:
    """Convert a validated provider pack into handoff metadata."""

    validate_provider_pack(pack)
    return ProviderHandoff(
        provider=pack.provider,
        signup_url=pack.handoff.signup_url,
        token_url=pack.handoff.token_url,
        project_url=pack.handoff.project_url or pack.handoff.token_url,
        token_env=pack.handoff.token_env or next(iter(pack.required_secrets)),
        token_record_id=pack.handoff.token_record_id or f"provider.{pack.provider}.token",
        token_label=pack.handoff.token_label or f"{pack.display_name} API token",
        required_scopes=pack.handoff.required_scopes,
        account_steps=pack.handoff.account_steps,
        secret_steps=pack.handoff.secret_steps,
    )


def _validate_launcher_capture_handoff(pack: ProviderCapabilityPack) -> None:
    """Require provider packs to use the public launcher secret-capture path."""

    if not pack.handoff.account_steps:
        raise ProviderError("Provider pack must include launcher account-opening steps.")
    account_text = " ".join(pack.handoff.account_steps).lower()
    if LAUNCHER_OPEN_GATE_PHRASE not in account_text:
        raise ProviderError(
            "Provider pack account_steps must name Open provider gate in VM."
        )
    if "local browser" in account_text or "host browser" in account_text:
        raise ProviderError(
            "Provider pack account_steps must keep provider gates inside the VM browser."
        )
    if not pack.handoff.secret_steps:
        raise ProviderError("Provider pack must include launcher secret capture steps.")
    secret_text = " ".join(pack.handoff.secret_steps).lower()
    for phrase in LAUNCHER_CAPTURE_PHRASES:
        if phrase not in secret_text:
            raise ProviderError(
                "Provider pack secret_steps must use Capture from VM clipboard "
                "and explain that capture reads the VM clipboard directly."
            )
    if not any(phrase in secret_text for phrase in NO_HOST_PASTE_PHRASES):
        raise ProviderError(
            "Provider pack secret_steps must tell users no paste into their computer is needed."
        )
    if "local browser" in secret_text or "host browser" in secret_text:
        raise ProviderError(
            "Provider pack secret_steps must keep secret capture inside the VM browser."
        )
    capture_targets = _launcher_capture_targets(pack)
    if capture_targets:
        missing = [
            target
            for target in capture_targets
            if f"capture {target.lower()} from vm clipboard" not in secret_text
        ]
        if missing:
            if len(missing) == 1:
                raise ProviderError(
                    "Provider pack secret_steps must name the exact visible "
                    f"Capture {missing[0]} from VM clipboard button."
                )
            missing_controls = ", ".join(
                f"Capture {target} from VM clipboard" for target in missing
            )
            raise ProviderError(
                "Provider pack secret_steps must name every exact visible Capture "
                f"button: {missing_controls}."
            )
    elif "capture from vm clipboard" not in secret_text:
        raise ProviderError(
            "Provider pack secret_steps must use Capture from VM clipboard."
        )


def _launcher_capture_targets(pack: ProviderCapabilityPack) -> tuple[str, ...]:
    """Return env targets that need exact launcher Capture button labels."""

    targets: list[str] = []
    if pack.handoff.token_env:
        targets.append(pack.handoff.token_env)
    for secret in pack.required_secrets:
        if _requires_launcher_capture_label(secret, pack.provider):
            targets.append(secret)
    return tuple(dict.fromkeys(targets))


def _requires_launcher_capture_label(secret: str, provider: str) -> bool:
    if not ENV_NAME_RE.match(secret):
        return False
    upper = secret.upper()
    if upper in {"CLIENT_ID", "PLAID_CLIENT_ID"} or upper.endswith(("_CLIENT_ID", "_ENV")):
        return False
    route = classify_secret_name(upper, {provider}).route
    if route != "app_env":
        return True
    return any(
        marker in upper
        for marker in ("SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "API_KEY")
    )


def synthesize_provider_pack(
    provider: str,
    app_path: Path,
    *,
    evidence: ProviderEvidence | None = None,
) -> ProviderCapabilityPack:
    """Synthesize a deterministic capability pack from app evidence."""

    normalized = provider.lower().strip()
    if not PROVIDER_ID_RE.match(normalized):
        raise ProviderError("Provider id must be lowercase kebab-case.")
    evidence = evidence or collect_provider_evidence(app_path)
    if normalized == "github":
        return _github_pack(evidence)
    if normalized == "vercel":
        return _vercel_pack(evidence)
    if normalized in {"cloudflare", "dns"}:
        return _cloudflare_pack(evidence)
    if normalized == "plaid":
        return _plaid_pack(evidence)
    if normalized == "resend":
        return _resend_pack(evidence)
    if normalized in COMMON_PROVIDER_CATALOG:
        return _catalog_pack(COMMON_PROVIDER_CATALOG[normalized], evidence)
    return _inferred_pack(normalized, evidence)


def collect_provider_evidence(app_path: Path) -> ProviderEvidence:
    """Collect package/env/import evidence without persisting secrets."""

    package = app_path / "package.json"
    dependencies: set[str] = set()
    if package.exists():
        try:
            raw = json.loads(package.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key in ("dependencies", "devDependencies"):
                    deps = raw.get(key, {})
                    if isinstance(deps, dict):
                        dependencies.update(str(name) for name in deps)
        except (OSError, json.JSONDecodeError):
            dependencies.clear()
    env_names: set[str] = set()
    imports: set[str] = set()
    skip_dirs = {".git", ".fusekit", "node_modules", ".venv", "dist", "build"}
    env_pattern = r"(?:process\.env\.|import\.meta\.env\.|os\.environ\[)([A-Z][A-Z0-9_]+)"
    for path in app_path.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if not path.is_file() or path.suffix not in {".js", ".jsx", ".ts", ".tsx", ".py", ".env"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        env_names.update(re.findall(env_pattern, text))
        imports.update(re.findall(r"(?:from|import)\s+['\"]?(@?[A-Za-z0-9_\-/]+)", text))
    return ProviderEvidence(
        dependencies=tuple(sorted(dependencies)),
        env_names=tuple(sorted(env_names)),
        imports=tuple(sorted(imports)),
    )


def infer_provider_candidates(evidence: ProviderEvidence) -> tuple[str, ...]:
    """Infer service providers that should use capability packs."""

    deps = set(evidence.dependencies)
    envs = set(evidence.env_names)
    imports = set(evidence.imports)
    candidates: set[str] = set()
    if {"plaid", "plaid-node"} & deps or any(name.startswith("PLAID_") for name in envs):
        candidates.add("plaid")
    if "resend" in deps or any(name.startswith("RESEND_") for name in envs):
        candidates.add("resend")
    for provider, entry in COMMON_PROVIDER_CATALOG.items():
        if (
            deps.intersection(entry.dependencies)
            or imports.intersection(entry.imports)
            or envs.intersection(entry.env_names)
            or any(name.startswith(prefix) for name in envs for prefix in entry.env_prefixes)
        ):
            candidates.add(provider)
    for env_name in envs:
        prefix = env_name.split("_", 1)[0].lower()
        if prefix in FRAMEWORK_ENV_PREFIXES:
            continue
        if prefix in {"github", "vercel", "cloudflare", "webhook"}:
            continue
        if any(prefix in dep.lower() for dep in deps):
            candidates.add(prefix)
    return tuple(sorted(candidates - BUILT_IN_PROVIDERS))


def pack_default_path(app_path: Path, provider: str) -> Path:
    """Return the default on-disk path for a synthesized provider pack."""

    return app_path / ".fusekit" / "provider-packs" / f"{provider}.json"


def catalog_provider_ids() -> tuple[str, ...]:
    """Return provider ids with maintained common-app catalog metadata."""

    return tuple(sorted(COMMON_PROVIDER_CATALOG))


def _plaid_pack(evidence: ProviderEvidence) -> ProviderCapabilityPack:
    env_names = tuple(
        name
        for name in ("PLAID_CLIENT_ID", "PLAID_SECRET", "PLAID_ENV", "PLAID_PRODUCTS")
        if name in evidence.env_names or name != "PLAID_PRODUCTS"
    )
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="plaid",
        display_name="Plaid",
        category="financial-data",
        confidence="high",
        evidence=_evidence_lines("plaid", evidence),
        detection=ProviderDetection(
            dependencies=tuple(dep for dep in evidence.dependencies if "plaid" in dep.lower()),
            env_names=env_names,
            env_prefixes=("PLAID_",),
            imports=tuple(item for item in evidence.imports if "plaid" in item.lower()),
            docs_urls=("https://plaid.com/docs/",),
        ),
        handoff=PackHandoff(
            signup_url="https://dashboard.plaid.com/signup",
            login_url="https://dashboard.plaid.com/signin",
            token_url="https://dashboard.plaid.com/developers/keys",
            project_url="https://dashboard.plaid.com/team/api",
            token_env="PLAID_SECRET",
            token_record_id="provider.plaid.token",
            token_label="Plaid secret key",
            required_scopes=("sandbox/development API keys", "allowed products used by the app"),
            account_steps=(
                (
                    "Click Open provider gate in VM so Plaid opens in the VM browser, "
                    "then create or sign in to the developer account."
                ),
                (
                    "Complete the highlighted Plaid email, MFA, CAPTCHA, business, billing, "
                    "consent, or identity gate."
                ),
                "Choose Sandbox or Development mode based on the app environment.",
            ),
            secret_steps=(
                "Open Developers > Keys and reveal the approved Sandbox or Development secret.",
                (
                    "Copy PLAID_CLIENT_ID, PLAID_SECRET, and PLAID_ENV inside the VM browser, "
                    "then click Capture PLAID_SECRET from VM clipboard and any other "
                    "visible env-named Capture buttons FuseKit shows. "
                    "No paste into your computer is needed because Capture reads the "
                    "VM clipboard directly."
                ),
                "Configure allowed products and redirect/webhook settings required by the app.",
            ),
            service_gates=(
                "email verification",
                "MFA",
                "CAPTCHA",
                "business verification",
                "billing/payment verification",
                "identity verification",
                "consent",
            ),
        ),
        required_secrets=("PLAID_CLIENT_ID", "PLAID_SECRET"),
        env_vars=env_names,
        setup=(
            SetupRecipe(
                kind="vault-capture-env",
                target="PLAID_CLIENT_ID,PLAID_SECRET,PLAID_ENV",
                secret_refs=("PLAID_CLIENT_ID", "PLAID_SECRET"),
            ),
        ),
        setup_goals=(
            "Create or connect the Plaid developer app.",
            "Collect only user-approved Plaid API credentials into the encrypted vault.",
            (
                "Configure products, webhook URL, redirect URI, and environment settings "
                "inferred from the app."
            ),
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target="PLAID_CLIENT_ID,PLAID_SECRET,PLAID_ENV",
                expected=(
                    "all required Plaid env vars are stored in the encrypted "
                    "vault/provider env store"
                ),
                secret_refs=("PLAID_CLIENT_ID", "PLAID_SECRET"),
            ),
            VerificationRecipe(
                kind="http-json",
                target="https://sandbox.plaid.com/institutions/get",
                expected="HTTP 200 with a Plaid request_id",
                secret_refs=("PLAID_CLIENT_ID", "PLAID_SECRET"),
                inputs={
                    "method": "POST",
                    "expected_status": "200",
                    "purpose": "verify-auth",
                    "body_json": (
                        '{"client_id":"${secret:PLAID_CLIENT_ID}",'
                        '"secret":"${secret:PLAID_SECRET}",'
                        '"count":1,"offset":0,"country_codes":["US"]}'
                    ),
                    "response_path": "request_id",
                },
            ),
        ),
        rollback=(
            "Rotate or revoke the Plaid secret in Dashboard > Developers > Keys.",
            "Remove Plaid env vars from provider-native deployment secret stores.",
            "Remove configured webhook or redirect URLs if the app is torn down.",
        ),
    )


def _github_pack(evidence: ProviderEvidence) -> ProviderCapabilityPack:
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="github",
        display_name="GitHub",
        category="source-control",
        confidence="high",
        evidence=_evidence_lines("github", evidence),
        detection=ProviderDetection(env_names=("GITHUB_TOKEN",), env_prefixes=("GITHUB_",)),
        handoff=PackHandoff(
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
                (
                    "Click Open provider gate in VM so GitHub opens in the VM browser, "
                    "then create or sign in to the account."
                ),
                "Complete the highlighted email, passkey, MFA, CAPTCHA, or consent gate.",
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
                    "Copy the token once inside the VM browser, then click "
                    "Capture GITHUB_TOKEN from VM clipboard to store it in the encrypted vault. "
                    "No paste into your computer is needed because Capture reads the VM "
                    "clipboard directly."
                ),
            ),
            service_gates=("email verification", "passkey", "MFA", "CAPTCHA", "consent"),
        ),
        required_secrets=("GITHUB_TOKEN",),
        env_vars=("GITHUB_TOKEN",),
        setup=(
            SetupRecipe(kind="github-deploy-key", target="${input:github_repo}"),
            SetupRecipe(
                kind="github-repo-secrets",
                target="${input:github_repo}",
                secret_refs=("*",),
            ),
        ),
        setup_goals=(
            "Connect the target GitHub repo.",
            "Create a FuseKit deploy key and store the private key only in the vault.",
            "Push app secrets to GitHub Actions secrets without exposing raw values.",
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target="GITHUB_TOKEN",
                expected="GitHub authorization exists in the encrypted vault or env source",
                secret_refs=("GITHUB_TOKEN",),
            ),
            VerificationRecipe(
                kind="github-deploy-key",
                target="${input:github_repo}",
                expected="FuseKit deploy key exists on the target repo",
                inputs={"title": "FuseKit deploy key"},
            ),
            VerificationRecipe(
                kind="github-repo-secret",
                target="${input:github_repo}",
                expected="app runtime secrets exist in GitHub Actions secrets",
                inputs={"names": "${input:app_env_names}"},
            ),
        ),
        rollback=(
            "Remove the FuseKit deploy key from the repository.",
            "Delete or rotate GitHub Actions secrets created by FuseKit.",
            "Revoke the GitHub token.",
        ),
    )


def _vercel_pack(evidence: ProviderEvidence) -> ProviderCapabilityPack:
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="vercel",
        display_name="Vercel",
        category="deployment",
        confidence="high",
        evidence=_evidence_lines("vercel", evidence),
        detection=ProviderDetection(env_names=("VERCEL_TOKEN",), env_prefixes=("VERCEL_",)),
        handoff=PackHandoff(
            signup_url="https://vercel.com/signup",
            token_url="https://vercel.com/account/tokens",
            project_url="https://vercel.com/new",
            token_env="VERCEL_TOKEN",
            token_record_id="provider.vercel.token",
            token_label="Vercel API token",
            required_scopes=("project access", "environment variables", "deployments"),
            account_steps=(
                (
                    "Click Open provider gate in VM so Vercel opens in the VM browser, "
                    "then create or sign in to the account."
                ),
                "Complete the highlighted SSO, MFA, CAPTCHA, billing, payment, or consent gate.",
                (
                    "Connect only the named GitHub account/repo under Login Connections when "
                    "Vercel asks."
                ),
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
                    "Copy the token once inside the VM browser, then click "
                    "Capture VERCEL_TOKEN from VM clipboard to store it in the encrypted vault. "
                    "No paste into your computer is needed because Capture reads the VM "
                    "clipboard directly."
                ),
            ),
            service_gates=("SSO", "MFA", "CAPTCHA", "billing/payment verification", "consent"),
        ),
        required_secrets=("VERCEL_TOKEN",),
        env_vars=("VERCEL_TOKEN",),
        setup=(
            SetupRecipe(kind="vercel-project", target="${input:vercel_project}"),
            SetupRecipe(
                kind="vercel-env",
                target="${input:vercel_project}",
                secret_refs=("*",),
            ),
            SetupRecipe(
                kind="vercel-git-deployment",
                target="${input:vercel_project}",
                when="vercel_project",
            ),
        ),
        setup_goals=(
            "Create or connect the Vercel project.",
            "Push required env vars into Vercel's encrypted env store.",
            "Trigger and verify deployment when a connected Git source is supplied.",
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target="VERCEL_TOKEN",
                expected="Vercel authorization exists in the encrypted vault or env source",
                secret_refs=("VERCEL_TOKEN",),
            ),
            VerificationRecipe(
                kind="vercel-project",
                target="${input:vercel_project}",
                expected="Vercel project exists",
            ),
            VerificationRecipe(
                kind="vercel-env",
                target="${input:vercel_project}",
                expected="app runtime env vars exist in Vercel",
                inputs={"names": "${input:app_env_names}"},
            ),
            VerificationRecipe(
                kind="vercel-deployment-url",
                target="${input:vercel_project}",
                expected="Vercel has a ready deployment URL",
            ),
            VerificationRecipe(kind="url-health", target="$live_url", expected="2xx/3xx"),
        ),
        rollback=(
            "Remove FuseKit-created Vercel env vars.",
            "Delete the Vercel project if FuseKit created it and rollback is requested.",
            "Revoke the Vercel token.",
        ),
    )


def _cloudflare_pack(evidence: ProviderEvidence) -> ProviderCapabilityPack:
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="cloudflare",
        display_name="Cloudflare",
        category="dns",
        confidence="high",
        evidence=_evidence_lines("cloudflare", evidence),
        detection=ProviderDetection(
            env_names=("CLOUDFLARE_API_TOKEN",),
            env_prefixes=("CLOUDFLARE_",),
        ),
        handoff=PackHandoff(
            signup_url="https://dash.cloudflare.com/sign-up",
            token_url="https://dash.cloudflare.com/profile/api-tokens",
            project_url="https://dash.cloudflare.com/",
            token_env="CLOUDFLARE_API_TOKEN",
            token_record_id="provider.cloudflare.token",
            token_label="Cloudflare API token",
            required_scopes=("Zone / Zone / Read", "Zone / DNS / Edit for the target zone"),
            account_steps=(
                (
                    "Click Open provider gate in VM so Cloudflare opens in the VM browser, "
                    "then create or sign in to the account."
                ),
                "Add or choose the exact DNS zone that owns the target domain.",
                (
                    "Complete the highlighted nameserver, domain ownership, MFA, CAPTCHA, "
                    "billing, or consent gate."
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
                    "Copy the token once inside the VM browser, then click "
                    "Capture CLOUDFLARE_API_TOKEN from VM clipboard to store it in the "
                    "encrypted vault. "
                    "No paste into your computer is needed because Capture reads the VM "
                    "clipboard directly."
                ),
            ),
            service_gates=(
                "domain ownership verification",
                "MFA",
                "CAPTCHA",
                "billing/payment verification",
                "consent",
            ),
        ),
        required_secrets=("CLOUDFLARE_API_TOKEN",),
        env_vars=("CLOUDFLARE_API_TOKEN",),
        setup=(SetupRecipe(kind="cloudflare-dns", target="${manifest:domains}"),),
        setup_goals=(
            "Resolve target DNS zones.",
            "Propose DNS changes with rollback metadata.",
            "Apply records only when DNS execution scope is granted.",
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target="CLOUDFLARE_API_TOKEN",
                expected="Cloudflare authorization exists in the encrypted vault or env source",
                secret_refs=("CLOUDFLARE_API_TOKEN",),
            ),
            VerificationRecipe(
                kind="cloudflare-dns-api",
                target="${input:dns_zone}",
                expected="DNS records exist in Cloudflare",
                inputs={"records_json": "${input:dns_records_json}"},
            ),
            VerificationRecipe(
                kind="dns-records",
                target="${input:dns_zone}",
                expected="DNS records have propagated publicly",
                inputs={"records_json": "${input:dns_records_json}"},
            ),
        ),
        rollback=(
            "Use receipt rollback metadata to restore or delete DNS records.",
            "Revoke the Cloudflare API token.",
        ),
    )


def _resend_pack(evidence: ProviderEvidence) -> ProviderCapabilityPack:
    env_names = tuple(
        dict.fromkeys(name for name in evidence.env_names if name.startswith("RESEND_"))
    ) or ("RESEND_API_KEY",)
    if "RESEND_API_KEY" not in env_names:
        env_names = ("RESEND_API_KEY", *env_names)
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="resend",
        display_name="Resend",
        category="email",
        confidence="high",
        evidence=_evidence_lines("resend", evidence),
        detection=ProviderDetection(
            dependencies=tuple(dep for dep in evidence.dependencies if "resend" in dep.lower()),
            env_names=env_names,
            env_prefixes=("RESEND_",),
            imports=tuple(item for item in evidence.imports if "resend" in item.lower()),
            docs_urls=("https://www.resend.com/docs/api-reference/introduction",),
        ),
        handoff=PackHandoff(
            signup_url="https://resend.com/signup",
            login_url="https://resend.com/login",
            token_url="https://resend.com/api-keys",
            project_url="",
            token_env="RESEND_API_KEY",
            token_record_id="provider.resend.token",
            token_label="Resend API key",
            required_scopes=("Full access for first setup", "domain and audience setup"),
            account_steps=(
                (
                    "Click Open provider gate in VM so Resend opens in the VM browser, "
                    "then create or sign in to the account."
                ),
                (
                    "Complete the highlighted email verification, MFA, CAPTCHA, billing, "
                    "or consent gate. Do not use Resend domain setup screens here."
                ),
                "Let FuseKit create or reuse the sending domain and audience after key capture.",
                (
                    "It is okay if Resend shows no domains or audiences yet; FuseKit "
                    "creates or reuses them by API after RESEND_API_KEY is captured."
                ),
            ),
            secret_steps=(
                (
                    "Create an API key named FuseKit email setup with Full access for this "
                    "first setup."
                ),
                (
                    "An existing Full access key row is not enough by itself; FuseKit "
                    "needs the raw key value captured into the encrypted vault."
                ),
                (
                    "If an existing key already has Full access but the raw value is not "
                    "available, create a new setup key because Resend does not reveal old "
                    "key secrets again."
                ),
                (
                    "Copy RESEND_API_KEY once inside the VM browser, then click "
                    "Capture RESEND_API_KEY from VM clipboard to store it in the encrypted vault. "
                    "No paste into your computer is needed because Capture reads the VM "
                    "clipboard directly."
                ),
                "FuseKit creates or reuses the sending domain through Resend's API.",
                "FuseKit uses returned domain verification records as DNS proposals.",
            ),
            service_gates=(
                "email verification",
                "MFA",
                "CAPTCHA",
                "billing/payment verification",
                "consent",
            ),
        ),
        required_secrets=("RESEND_API_KEY",),
        env_vars=env_names,
        setup=(
            SetupRecipe(
                kind="vault-capture-env",
                target="RESEND_API_KEY",
                secret_refs=("RESEND_API_KEY",),
            ),
            SetupRecipe(
                kind="resend-domain",
                target="${input:resend_domain}",
            ),
            SetupRecipe(
                kind="resend-audience",
                target="${input:resend_audience_name}",
                optional=True,
            ),
        ),
        setup_goals=(
            "Create or connect the Resend account.",
            "Create or capture a Full access setup Resend API key into the encrypted vault.",
            "Create or reuse the sending domain through Resend's API.",
            "Feed Resend verification records into DNS proposals before DNS is applied.",
            "Create or reuse a Resend audience only when the app requires one.",
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target="RESEND_API_KEY",
                expected="Resend API key is stored in the encrypted vault/provider env store",
                secret_refs=("RESEND_API_KEY",),
            ),
            VerificationRecipe(
                kind="http-json",
                target="https://api.resend.com/domains",
                expected="HTTP 200 from Resend Domains API",
                secret_refs=("RESEND_API_KEY",),
                inputs={
                    "method": "GET",
                    "expected_status": "200",
                    "purpose": "verify-resource",
                    "auth_secret": "RESEND_API_KEY",
                    "auth_scheme": "Bearer",
                    "response_path": "data",
                },
            ),
            VerificationRecipe(
                kind="resend-domain",
                target="${input:resend_domain}",
                expected="Resend sending domain is verified",
            ),
        ),
        rollback=(
            "Revoke or rotate the Resend API key.",
            "Remove Resend env vars from provider-native deployment secret stores.",
            "Delete the Resend sending domain if the app is torn down.",
        ),
    )


def _catalog_pack(
    entry: ProviderCatalogEntry,
    evidence: ProviderEvidence,
) -> ProviderCapabilityPack:
    detected_env = tuple(name for name in entry.env_names if name in evidence.env_names)
    env_vars = tuple(dict.fromkeys((*entry.required_secrets, *detected_env)))
    required = entry.required_secrets
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider=entry.provider,
        display_name=entry.display_name,
        category=entry.category,
        confidence=entry.confidence,
        evidence=_catalog_evidence_lines(entry, evidence),
        detection=ProviderDetection(
            dependencies=tuple(
                dep for dep in evidence.dependencies if dep in entry.dependencies
            ),
            env_names=env_vars,
            env_prefixes=entry.env_prefixes,
            imports=tuple(item for item in evidence.imports if item in entry.imports),
            docs_urls=entry.docs_urls,
        ),
        handoff=PackHandoff(
            signup_url=entry.signup_url,
            login_url=entry.login_url,
            token_url=entry.token_url,
            project_url=entry.project_url,
            token_env=entry.token_env,
            token_record_id=f"provider.{entry.provider}.token",
            token_label=entry.token_label,
            required_scopes=entry.required_scopes,
            account_steps=entry.account_steps,
            secret_steps=_launcher_secret_steps(entry.secret_steps, entry.token_env),
            service_gates=entry.service_gates,
        ),
        required_secrets=required,
        env_vars=env_vars,
        setup=(
            SetupRecipe(
                kind="vault-capture-env",
                target=",".join(env_vars),
                secret_refs=required,
            ),
        ),
        setup_goals=entry.setup_goals,
        verification=(
            VerificationRecipe(
                kind="env-present",
                target=",".join(env_vars),
                expected=(
                    f"{entry.display_name} required env values are stored in the "
                    "encrypted vault/provider env store"
                ),
                secret_refs=required,
            ),
        ),
        rollback=entry.rollback,
    )


def _inferred_pack(provider: str, evidence: ProviderEvidence) -> ProviderCapabilityPack:
    prefix = provider.replace("-", "_").upper()
    env_names = tuple(name for name in evidence.env_names if name.startswith(f"{prefix}_"))
    required = env_names or (f"{prefix}_API_KEY",)
    base_url = f"https://{provider}.com"
    return ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider=provider,
        display_name=provider.replace("-", " ").title(),
        category="service",
        confidence="medium" if env_names else "low",
        evidence=_evidence_lines(provider, evidence),
        detection=ProviderDetection(
            dependencies=tuple(dep for dep in evidence.dependencies if provider in dep.lower()),
            env_names=env_names,
            env_prefixes=(f"{prefix}_",),
            imports=tuple(item for item in evidence.imports if provider in item.lower()),
            docs_urls=(base_url,),
        ),
        handoff=PackHandoff(
            signup_url=base_url,
            token_url=base_url,
            project_url=base_url,
            token_env=required[0],
            token_record_id=f"provider.{provider}.token",
            token_label=f"{provider} API token",
            required_scopes=("least-privilege access required by the detected app integration",),
            account_steps=(
                (
                    f"Click Open provider gate in VM so {provider} opens in the VM browser, "
                    "then create or sign in."
                ),
                (
                    "Complete the highlighted provider login, MFA, CAPTCHA, billing, fraud, "
                    "consent, or verification gate."
                ),
            ),
            secret_steps=(
                "Navigate to the provider developer/API key settings.",
                (
                    "Create or reveal the approved token/API key and capture it into "
                    "the encrypted vault."
                ),
            )
            + _launcher_capture_step(required[0]),
            service_gates=(
                "login/MFA/CAPTCHA/billing/payment/fraud/consent/verification",
            ),
        ),
        required_secrets=required,
        env_vars=env_names or required,
        setup=(
            SetupRecipe(
                kind="vault-capture-env",
                target=",".join(required),
                secret_refs=required,
            ),
        ),
        setup_goals=(
            f"Use OpenClaw to navigate {provider} setup pages.",
            "Stop at provider-imposed human gates and resume after the user passes them.",
            "Capture only approved secrets into the encrypted vault.",
        ),
        verification=(
            VerificationRecipe(
                kind="env-present",
                target=",".join(required),
                expected="required provider credentials are stored in vault/provider env store",
                secret_refs=required,
            ),
        ),
        rollback=(
            "Rotate or revoke provider API credentials.",
            "Remove provider env vars from deployment secret stores.",
        ),
    )


def _launcher_secret_steps(steps: tuple[str, ...], target: str) -> tuple[str, ...]:
    exact_capture = f"Capture {target} from VM clipboard" if target else ""
    if exact_capture and any(exact_capture in step for step in steps):
        return steps
    return (*steps, *_launcher_capture_step(target))


def _launcher_capture_step(target: str) -> tuple[str, ...]:
    label = target or "the approved provider value"
    capture_label = (
        f"Capture {target} from VM clipboard"
        if target
        else (
            "the visible env-named Capture button, for example "
            "Capture RESEND_API_KEY from VM clipboard"
        )
    )
    return (
        (
            f"When the provider reveals {label}, copy it inside the VM browser and click "
            f"{capture_label}. No paste into your computer "
            "is needed because Capture reads the VM clipboard directly."
        ),
    )


def _evidence_lines(provider: str, evidence: ProviderEvidence) -> tuple[str, ...]:
    lines: list[str] = []
    for dep in evidence.dependencies:
        if provider in dep.lower():
            lines.append(f"dependency:{dep}")
    prefix = provider.replace("-", "_").upper()
    for env_name in evidence.env_names:
        if env_name.startswith(f"{prefix}_"):
            lines.append(f"env:{env_name}")
    for import_name in evidence.imports:
        if provider in import_name.lower():
            lines.append(f"import:{import_name}")
    return tuple(lines or (f"provider:{provider}",))


def _catalog_evidence_lines(
    entry: ProviderCatalogEntry,
    evidence: ProviderEvidence,
) -> tuple[str, ...]:
    lines: list[str] = []
    for dep in evidence.dependencies:
        if dep in entry.dependencies:
            lines.append(f"dependency:{dep}")
    for env_name in evidence.env_names:
        if env_name in entry.env_names or any(
            env_name.startswith(prefix) for prefix in entry.env_prefixes
        ):
            lines.append(f"env:{env_name}")
    for import_name in evidence.imports:
        if import_name in entry.imports:
            lines.append(f"import:{import_name}")
    return tuple(lines or (f"catalog:{entry.provider}",))


def _validate_url(url: str, label: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ProviderError(f"{label} must be an https URL.")


def _validate_verification_recipe_destination(
    pack: ProviderCapabilityPack,
    recipe: VerificationRecipe,
) -> None:
    if recipe.kind != "http-json":
        return
    parsed = urlparse(recipe.target)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ProviderError("http-json verification targets must be https URLs.")
    if not recipe.secret_refs and "${secret:" not in json.dumps(recipe.inputs):
        return
    host = parsed.netloc.lower()
    allowed_hosts = set()
    for url in (
        pack.handoff.signup_url,
        pack.handoff.login_url,
        pack.handoff.token_url,
        pack.handoff.project_url,
        *pack.detection.docs_urls,
    ):
        if url:
            parsed_allowed = urlparse(url)
            if parsed_allowed.netloc:
                allowed_hosts.add(parsed_allowed.netloc.lower())
    configured = recipe.inputs.get("allowed_hosts", "")
    allowed_hosts.update(host.strip().lower() for host in configured.split(",") if host.strip())
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        raise ProviderError(
            "http-json recipes that use secrets must target the provider's documented domains."
        )
    purpose = recipe.inputs.get("purpose", "")
    if purpose not in HTTP_JSON_PURPOSES:
        raise ProviderError(
            "http-json recipes must declare a valid endpoint purpose before using secrets."
        )


def _validate_tool_permissions(pack: ProviderCapabilityPack) -> None:
    permissions = set(pack.tool_permissions)
    for permission in permissions:
        if not re.match(r"^(setup|verify):[a-z0-9-]+$", permission):
            raise ProviderError(f"Invalid provider pack tool permission: {permission}")
    for setup_recipe in pack.setup:
        permission = f"setup:{setup_recipe.kind}"
        if permission not in permissions:
            raise ProviderError(f"Setup recipe is not bound to tool permission: {permission}")
    for verification_recipe in pack.verification:
        permission = f"verify:{verification_recipe.kind}"
        if permission not in permissions:
            raise ProviderError(
                f"Verification recipe is not bound to tool permission: {permission}"
            )


def _validate_account_creation(pack: ProviderCapabilityPack) -> None:
    mode = pack.handoff.account_creation
    recipe_kind = pack.handoff.account_creation_recipe
    if mode not in ACCOUNT_CREATION_MODES:
        raise ProviderError(
            "handoff.account_creation must be api, supervised, or none."
        )
    if not pack.handoff.account_creation_reason.strip():
        raise ProviderError("handoff.account_creation_reason must explain the account route.")
    if mode == "api":
        if not recipe_kind:
            raise ProviderError(
                "API account creation requires handoff.account_creation_recipe."
            )
        if not any(recipe.kind == recipe_kind for recipe in pack.setup):
            raise ProviderError(
                "API account creation recipe must match a setup recipe in the pack."
            )
        return
    if recipe_kind:
        raise ProviderError(
            "Only API account creation may declare handoff.account_creation_recipe."
        )


def _validate_setup_secret_routes(pack: ProviderCapabilityPack, recipe: SetupRecipe) -> None:
    if recipe.kind not in APP_ENV_SETUP_KINDS:
        return
    for ref in recipe.secret_refs:
        if ref == "*":
            continue
        route = classify_secret_name(ref, {pack.provider}).route
        if route not in {"app_env", "webhook_secret"}:
            raise ProviderError(
                f"{recipe.kind} cannot route {route} secret {ref} into app env stores."
            )


def _string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ProviderError(f"{key} must be a non-empty string.")
    return value


def _tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
        return value
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProviderError(f"{label} must be a list of strings.")
    return tuple(value)


def _string_mapping(value: Any, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProviderError(f"{label} must be a mapping.")
    return {str(key): str(item) for key, item in value.items()}
