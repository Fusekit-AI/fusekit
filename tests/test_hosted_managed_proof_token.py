from __future__ import annotations

import json

from fusekit.hosted.managed_proof_token import (
    HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION,
    build_hosted_managed_proof_token_report,
)
from fusekit.hosted.session import verify_hosted_state_token


def test_managed_proof_helper_emits_purpose_bound_state_token() -> None:
    report = build_hosted_managed_proof_token_report(
        state_secret="hosted-state-secret",
        github_app_slug="fusekit-launcher",
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_MANAGED_PROOF_TOKEN_REPORT_SCHEMA_VERSION
    assert report["query_param"] == "state"
    assert "state_token" in report
    assert str(report["install_url"]).startswith(
        "https://github.com/apps/fusekit-launcher/installations/new?state="
    )
    assert "token" not in report
    assert "managed_proof" not in serialized
    state = verify_hosted_state_token(
        "hosted-state-secret",
        str(report["state_token"]),
    )
    assert state.managed_proof is True
    assert state.return_path == "/"
    assert "Stripe key" in str(report["secret_boundary"])
