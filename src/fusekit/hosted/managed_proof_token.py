"""Operator token helper for hosted managed Checkout proof runs."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from fusekit.errors import FuseKitError
from fusekit.hosted.runtime_secrets import (
    HOSTED_RUNTIME_SECRET_FILE,
    _parse_systemd_env_file,
)
from fusekit.hosted.session import (
    HOSTED_MANAGED_PROOF_QUERY_PARAM,
    HOSTED_MANAGED_PROOF_TOKEN_TTL_SECONDS,
    create_hosted_managed_proof_token,
)

HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION = (
    "fusekit.hosted-managed-proof-token-report.v1"
)
HOSTED_MANAGED_PROOF_TOKEN_SECRET_BOUNDARY = (
    "The managed proof token is a short-lived operator click capability for one "
    "supervised Checkout proof collection path. It is not a Stripe key, webhook "
    "secret, GitHub private key, worker secret, OCI credential, provider credential, "
    "or vault secret. Do not store it in docs, logs, or durable receipts."
)


def build_hosted_managed_proof_token_report(
    *,
    state_secret: str,
) -> dict[str, object]:
    """Return an operator-use token report without exposing raw runtime secrets."""

    token = create_hosted_managed_proof_token(state_secret)
    return {
        "schema_version": HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
        "query_param": HOSTED_MANAGED_PROOF_QUERY_PARAM,
        "token": token,
        "expires_in_seconds": HOSTED_MANAGED_PROOF_TOKEN_TTL_SECONDS,
        "operator_use": (
            "Append this token as managed_proof=<token> to a managed-lane "
            "GitHub control-room URL only for the supervised live Checkout proof run."
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
        if not state_secret:
            material, failures = _parse_systemd_env_file(Path(args.runtime_secret_file))
            if failures:
                raise FuseKitError("managed_proof_token_runtime_secret_file_invalid")
            state_secret = material.get("FUSEKIT_HOSTED_STATE_SECRET", "")
        report = build_hosted_managed_proof_token_report(state_secret=state_secret)
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
