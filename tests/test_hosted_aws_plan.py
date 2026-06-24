from __future__ import annotations

import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.aws_plan import (
    build_hosted_aws_plan,
    protected_aws_resource_findings,
    validate_cloudflare_fusekit_dns_change,
)


def test_hosted_aws_plan_blocks_mailpilot_tagged_account() -> None:
    resources = [
        {
            "ResourceARN": (
                "arn:aws:rds:us-east-1:222795301373:db:mailpilot-production"
            ),
            "Tags": [
                {"Key": "Application", "Value": "MailPilot"},
                {"Key": "DataBoundary", "Value": "mailpilot"},
                {"Key": "ManagedBy", "Value": "Terraform"},
            ],
        }
    ]

    plan = build_hosted_aws_plan(
        account_id="222795301373",
        resource_tag_mappings=resources,
        origin_cname="fusekit-prod.us-east-1.elasticbeanstalk.com",
    )

    assert plan["ready_to_apply"] is False
    assert plan["blockers"] == ["protected_aws_account_resources_detected"]
    safety = plan["account"]["safety_preflight"]
    assert safety["no_mailpilot_resources_touched"] is False
    assert safety["protected_findings"][0]["resource_arn"] == (
        "arn:aws:rds:us-east-1:<aws-account>:db:mailpilot-production"
    )
    assert "222795301373" not in json.dumps(plan)


def test_hosted_aws_plan_clean_account_is_plan_only_and_reversible() -> None:
    plan = build_hosted_aws_plan(
        account_id="222795301373",
        resource_tag_mappings=[],
        origin_cname="fusekit-prod.us-east-1.elasticbeanstalk.com",
    )

    assert plan["ready_to_apply"] is True
    assert plan["mutates_aws"] is False
    assert plan["mutates_cloudflare_dns"] is False
    assert plan["account"]["id"] == "<aws-account:1373>"
    assert plan["proof"]["no_mailpilot_resources_touched"] is True
    assert plan["proof"]["no_dns_apex_or_www_change"] is True
    assert plan["rollback_metadata"]["mailpilot_resources"] == []
    assert "FUSEKIT_HOSTED_DEPLOYMENT_URL" in plan["runtime_env_names"]
    assert plan["cloudflare_dns"] == {
        "zone": "snowmanai.org",
        "record_name": "fusekit",
        "record_type": "CNAME",
        "record_value": "fusekit-prod.us-east-1.elasticbeanstalk.com",
    }


@pytest.mark.parametrize(
    ("record_name", "failure"),
    [
        ("@", "cloudflare_dns_apex_or_www_not_allowed"),
        ("www", "cloudflare_dns_only_fusekit_subdomain_allowed"),
        ("mailpilot", "cloudflare_dns_only_fusekit_subdomain_allowed"),
    ],
)
def test_cloudflare_dns_guard_allows_only_fusekit_subdomain(
    record_name: str,
    failure: str,
) -> None:
    with pytest.raises(FuseKitError, match=failure):
        validate_cloudflare_fusekit_dns_change(
            zone="snowmanai.org",
            record_name=record_name,
            record_type="CNAME",
            record_value="fusekit-prod.us-east-1.elasticbeanstalk.com",
        )


def test_cloudflare_dns_guard_rejects_non_cname_and_secret_like_targets() -> None:
    with pytest.raises(FuseKitError, match="cloudflare_dns_record_type_must_be_cname"):
        validate_cloudflare_fusekit_dns_change(
            zone="snowmanai.org",
            record_name="fusekit",
            record_type="A",
            record_value="192.0.2.10",
        )

    with pytest.raises(FuseKitError, match="cloudflare_dns_target_must_be_public_non_secret"):
        validate_cloudflare_fusekit_dns_change(
            zone="snowmanai.org",
            record_name="fusekit",
            record_type="CNAME",
            record_value="token: github_pat_1234567890abcdefghijklmnop",
        )


def test_protected_aws_resource_findings_detect_mailpilot_name_without_secret_values() -> None:
    findings = protected_aws_resource_findings(
        [
            {
                "ResourceARN": (
                    "arn:aws:secretsmanager:us-east-1:222795301373:secret:mailpilot/db"
                ),
                "Tags": [{"Key": "ManagedBy", "Value": "Terraform"}],
            }
        ]
    )

    assert findings == [
        {
            "resource_arn": (
                "arn:aws:secretsmanager:us-east-1:<aws-account>:secret:mailpilot/db"
            ),
            "tag_keys": ["ManagedBy"],
            "reasons": [
                "protected_iac_boundary:terraform_mailpilot",
                "protected_name:mailpilot",
            ],
        }
    ]
