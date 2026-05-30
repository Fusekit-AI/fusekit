"""Secret routing rules for pack-driven setup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SecretRoute = Literal[
    "provider_auth",
    "app_env",
    "webhook_secret",
    "deploy_key",
    "runner_secret",
    "llm_auth",
]

PROVIDER_AUTH_NAMES = {
    "GITHUB_TOKEN",
    "VERCEL_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "OCI_CONFIG",
    "OPENAI_API_KEY",
}
PROVIDER_AUTH_SUFFIXES = ("_TOKEN", "_API_TOKEN", "_ACCESS_TOKEN", "_REFRESH_TOKEN")
PROVIDER_AUTH_PREFIXES = ("OCI_",)
APP_SECRET_SUFFIXES = ("_SECRET", "_API_KEY", "_KEY", "_URL", "_DSN")


@dataclass(frozen=True)
class RoutedSecret:
    """A secret name and its routing class."""

    name: str
    route: SecretRoute
    reason: str

    def to_dict(self) -> dict[str, str]:
        """Serialize without the secret value."""

        return {"name": self.name, "route": self.route, "reason": self.reason}


def classify_secret_name(name: str, provider_names: set[str] | None = None) -> RoutedSecret:
    """Classify where a secret is allowed to flow."""

    provider_names = provider_names or set()
    upper = name.upper()
    if upper.endswith("PRIVATE_KEY") or upper.endswith("_SSH_KEY"):
        return RoutedSecret(upper, "deploy_key", "private/deploy key")
    if upper.startswith("RUNNER_") or upper.startswith("FUSEKIT_RUNNER_"):
        return RoutedSecret(upper, "runner_secret", "runner-only secret")
    if upper in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}:
        return RoutedSecret(upper, "llm_auth", "LLM authorization")
    if upper in PROVIDER_AUTH_NAMES:
        return RoutedSecret(upper, "provider_auth", "known provider authorization token")
    prefix = upper.split("_", 1)[0].lower()
    if prefix in provider_names and upper.endswith(PROVIDER_AUTH_SUFFIXES):
        return RoutedSecret(upper, "provider_auth", "provider-prefixed authorization token")
    if upper.startswith(PROVIDER_AUTH_PREFIXES):
        return RoutedSecret(upper, "provider_auth", "provider runtime credential")
    if "WEBHOOK" in upper and "SECRET" in upper:
        return RoutedSecret(upper, "webhook_secret", "webhook signing secret")
    if upper.endswith(APP_SECRET_SUFFIXES):
        return RoutedSecret(upper, "app_env", "application runtime secret")
    return RoutedSecret(upper, "app_env", "application runtime setting")


def select_app_env_secrets(
    secrets: dict[str, str],
    *,
    provider_names: set[str],
) -> dict[str, str]:
    """Return only secrets that may be copied into app/deploy env stores."""

    allowed: dict[str, str] = {}
    for name, value in secrets.items():
        route = classify_secret_name(name, provider_names)
        if route.route in {"app_env", "webhook_secret"}:
            allowed[name] = value
    return allowed
