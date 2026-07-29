from __future__ import annotations

import pytest

from fusekit.security import (
    contains_durable_secret_text,
    contains_private_marker_text,
    redact_public_text,
)


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: Bearer raw-provider-token",
        "Callback failed at https://provider.example/callback?code=secret-code",
        "api_key = rk_aaaaaaaaaaaaaaaaaaaa",
        "token: github_pat_aaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_contains_durable_secret_text_rejects_raw_credentials(value: str) -> None:
    assert contains_durable_secret_text(value)


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: Bearer [redacted]",
        '{"header": "Authorization: Bearer [redacted]"}',
        "Callback failed at https://provider.example/callback?code=[redacted]",
        '{"resume_url": "https://provider.example/callback?token=[redacted]&code=[redacted]"}',
        "api_key = [redacted]",
        '{"next_action": "capture api_key=[redacted]"}',
        "This proof records only provider names and non-secret wake ids.",
    ],
)
def test_contains_durable_secret_text_allows_redacted_public_text(value: str) -> None:
    assert not contains_durable_secret_text(value)


def test_redacted_public_text_satisfies_durable_secret_detector() -> None:
    raw = "Callback failed at https://provider.example/callback?code=secret-code"

    assert not contains_durable_secret_text(redact_public_text(raw))


@pytest.mark.parametrize(
    "value",
    [
        "checkout metadata: rk_live_should_not_render",
        "instance id: ocid1_instance_oc1_not_public",
        "temporary access key: ASIA_should_not_render",
        "env name: aws_secret_access_key",
        "token prefix: github_pat_should_not_render",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_contains_private_marker_text_rejects_public_marker_shapes(value: str) -> None:
    assert contains_private_marker_text(value)


@pytest.mark.parametrize(
    "value",
    [
        "redacted public proof only",
        "price label: Launch validation $1.00",
        "oci instance <redacted:abcd>",
    ],
)
def test_contains_private_marker_text_allows_public_redacted_shapes(value: str) -> None:
    assert not contains_private_marker_text(value)
