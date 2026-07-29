"""Operator token helper for hosted managed Checkout proof runs."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.hosted.github_app import GitHubAppConfig, github_app_install_url
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_FILE,
    _parse_systemd_env_file,
)
from fusekit.hosted.session import (
    HOSTED_STATE_TTL_SECONDS,
    create_hosted_state_token,
)

HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION = (
    "fusekit.hosted-managed-proof-token-report.v1"
)
HOSTED_MANAGED_PROOF_TOKEN_SECRET_BOUNDARY = (
    "The managed proof state is the normal short-lived GitHub OAuth state token "
    "with an operator-only proof purpose. It is not a Stripe key, webhook secret, "
    "GitHub private key, worker secret, OCI credential, provider credential, or "
    "vault secret. Do not store it in docs, logs, or durable receipts."
)


def build_hosted_managed_proof_token_report(
    *,
    state_secret: str,
    github_app_slug: str = "",
) -> dict[str, object]:
    """Return an operator-use token report without exposing raw runtime secrets."""

    state_token = create_hosted_state_token(
        state_secret,
        return_path="/",
        managed_proof=True,
    )
    install_url = ""
    if github_app_slug:
        install_url = github_app_install_url(
            GitHubAppConfig(
                app_id="0",
                app_slug=github_app_slug,
                private_key_pem="",
            ),
            state=state_token,
        )
    return {
        "schema_version": HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
        "query_param": "state",
        "state_token": state_token,
        "install_url": install_url,
        "expires_in_seconds": HOSTED_STATE_TTL_SECONDS,
        "operator_use": (
            "Visit install_url when present, or use state=<state_token> in the "
            "GitHub App install URL for the supervised managed Checkout proof run."
        ),
        "public_managed_runs_enabled": False,
        "mutates_host": False,
        "mutates_provider": False,
        "secret_boundary": HOSTED_MANAGED_PROOF_TOKEN_SECRET_BOUNDARY,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a short-lived hosted managed Checkout proof token."
    )
    parser.add_argument("--runtime-secret-file", default=HOSTED_RUNTIME_SECRET_FILE)
    parser.add_argument("--state-secret-env", default="FUSEKIT_HOSTED_STATE_SECRET")
    args = parser.parse_args(argv)
    try:
        state_secret = os.environ.get(args.state_secret_env, "")
        github_app_slug = os.environ.get("FUSEKIT_GITHUB_APP_SLUG", "")
        if not state_secret:
            material, failures = _parse_systemd_env_file(Path(args.runtime_secret_file))
            if failures:
                raise FuseKitError("managed_proof_token_runtime_secret_file_invalid")
            state_secret = material.get("FUSEKIT_HOSTED_STATE_SECRET", "")
            github_app_slug = github_app_slug or material.get("FUSEKIT_GITHUB_APP_SLUG", "")
        report = build_hosted_managed_proof_token_report(
            state_secret=state_secret,
            github_app_slug=github_app_slug,
        )
    except (FuseKitError, OSError) as exc:
        report = {
            "schema_version": HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
            "error": str(exc),
            "mutates_host": False,
            "mutates_provider": False,
            "secret_boundary": "Managed proof token errors never emit secret values.",
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if "token" in report else 2


if __name__ == "__main__":
    raise SystemExit(main())
