"""Plan-only AWS hosted launcher safety checks."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence

from fusekit.errors import FuseKitError
from fusekit.hosted.server import (
    HOSTED_AWS_SOURCE_PROVENANCE_ENV,
    REQUIRED_HOSTED_ENV,
)
from fusekit.security import contains_durable_secret_text

HOSTED_AWS_PLAN_SCHEMA_VERSION = "fusekit.hosted-aws-plan.v1"
HOSTED_AWS_DEFAULT_REGION = "us-east-1"
HOSTED_AWS_DEFAULT_ZONE = "snowmanai.org"
HOSTED_AWS_DEFAULT_RECORD_NAME = "fusekit"
HOSTED_AWS_DEFAULT_RECORD_TYPE = "CNAME"

MAILPILOT_PROTECTED_TAGS: tuple[tuple[str, str], ...] = (
    ("Application", "MailPilot"),
    ("DataBoundary", "mailpilot"),
)
MAILPILOT_PROTECTED_TOKEN = "mailpilot"
MAILPILOT_PROTECTED_MARKERS = (
    "application=mailpilot",
    "databoundary=mailpilot",
    "mailpilot",
    "pii",
)


def redacted_aws_account_id(account_id: str) -> str:
    """Return a public-safe AWS account identifier."""

    digits = "".join(ch for ch in account_id if ch.isdigit())
    if len(digits) < 4:
        return "<aws-account>"
    return f"<aws-account:{digits[-4:]}>"


def redact_aws_arn(value: object) -> str:
    """Redact AWS account ids from ARNs or ARN-like strings."""

    text = str(value or "")
    return re.sub(r":\d{12}:", ":<aws-account>:", text)


def protected_aws_resource_findings(
    resource_tag_mappings: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Detect protected MailPilot/SOC2 resources from tag mapping exports."""

    findings: list[dict[str, object]] = []
    for mapping in resource_tag_mappings:
        arn = str(mapping.get("ResourceARN") or mapping.get("resource_arn") or "")
        tags = _normalize_tags(mapping.get("Tags") or mapping.get("tags"))
        reasons = _protected_resource_reasons(arn=arn, tags=tags)
        if reasons:
            findings.append(
                {
                    "resource_arn": redact_aws_arn(arn),
                    "tag_keys": sorted(tags),
                    "reasons": reasons,
                }
            )
    return findings


def assert_safe_aws_account_for_hosted_launcher(
    resource_tag_mappings: Sequence[Mapping[str, object]],
) -> None:
    """Fail closed when the target account contains protected MailPilot resources."""

    findings = protected_aws_resource_findings(resource_tag_mappings)
    if findings:
        raise FuseKitError("protected_aws_account_resources_detected")


def validate_cloudflare_fusekit_dns_change(
    *,
    zone: str,
    record_name: str,
    record_type: str,
    record_value: str,
) -> dict[str, str]:
    """Validate the only DNS change FuseKit may propose for hosted launch."""

    normalized_zone = zone.strip().rstrip(".").lower()
    normalized_name = record_name.strip().rstrip(".").lower()
    normalized_type = record_type.strip().upper()
    normalized_value = record_value.strip().rstrip(".")
    if normalized_zone != HOSTED_AWS_DEFAULT_ZONE:
        raise FuseKitError("cloudflare_zone_must_be_snowmanai_org")
    if normalized_name in {"", "@", HOSTED_AWS_DEFAULT_ZONE, f"www.{HOSTED_AWS_DEFAULT_ZONE}"}:
        raise FuseKitError("cloudflare_dns_apex_or_www_not_allowed")
    if normalized_name != HOSTED_AWS_DEFAULT_RECORD_NAME:
        raise FuseKitError("cloudflare_dns_only_fusekit_subdomain_allowed")
    if normalized_type != HOSTED_AWS_DEFAULT_RECORD_TYPE:
        raise FuseKitError("cloudflare_dns_record_type_must_be_cname")
    if not normalized_value or contains_durable_secret_text(normalized_value):
        raise FuseKitError("cloudflare_dns_target_must_be_public_non_secret")
    if not _valid_dns_hostname(normalized_value):
        raise FuseKitError("cloudflare_dns_target_must_be_hostname")
    if MAILPILOT_PROTECTED_TOKEN in normalized_value.lower():
        raise FuseKitError("cloudflare_dns_target_must_not_reference_mailpilot")
    return {
        "zone": normalized_zone,
        "record_name": normalized_name,
        "record_type": normalized_type,
        "record_value": normalized_value,
    }


def build_hosted_aws_plan(
    *,
    account_id: str,
    region: str = HOSTED_AWS_DEFAULT_REGION,
    resource_tag_mappings: Sequence[Mapping[str, object]] = (),
    origin_cname: str = "fusekit-prod.us-east-1.elasticbeanstalk.com",
    zone: str = HOSTED_AWS_DEFAULT_ZONE,
    record_name: str = HOSTED_AWS_DEFAULT_RECORD_NAME,
) -> dict[str, object]:
    """Build a redacted, non-mutating AWS deployment plan."""

    findings = protected_aws_resource_findings(resource_tag_mappings)
    blockers = ["protected_aws_account_resources_detected"] if findings else []
    dns = validate_cloudflare_fusekit_dns_change(
        zone=zone,
        record_name=record_name,
        record_type=HOSTED_AWS_DEFAULT_RECORD_TYPE,
        record_value=origin_cname,
    )
    plan = {
        "schema_version": HOSTED_AWS_PLAN_SCHEMA_VERSION,
        "mode": "plan_only",
        "mutates_aws": False,
        "mutates_cloudflare_dns": False,
        "ready_to_apply": not blockers,
        "blockers": blockers,
        "account": {
            "id": redacted_aws_account_id(account_id),
            "region": region,
            "safety_preflight": {
                "checked_resource_tag_mappings": len(resource_tag_mappings),
                "protected_findings": findings,
                "no_mailpilot_resources_touched": not findings,
            },
        },
        "provider": "aws-elastic-beanstalk",
        "proposed_tags": {
            "Application": "FuseKit",
            "Environment": "production",
            "DataBoundary": "fusekit-public-launcher",
            "ManagedBy": "FuseKit",
            "PiiData": "false",
        },
        "iam_boundary": {
            "principle": "least_privilege_for_hosted_launcher_only",
            "must_not_reference": ["MailPilot", "mailpilot", "customer-pii", "client-pii"],
            "requires_explicit_apply_approval": True,
        },
        "runtime_env_names": sorted(set(REQUIRED_HOSTED_ENV + HOSTED_AWS_SOURCE_PROVENANCE_ENV)),
        "cloudflare_dns": dns,
        "rollback_metadata": {
            "scope": "fusekit_hosted_launcher_only",
            "dns_records": [dns],
            "aws_resources": [
                "Elastic Beanstalk application/environment tagged Application=FuseKit",
                "launcher runtime environment variables listed in runtime_env_names",
            ],
            "mailpilot_resources": [],
        },
        "proof": {
            "no_mailpilot_resources_touched": not findings,
            "no_dns_apex_or_www_change": True,
            "no_secret_values_in_plan": not contains_durable_secret_text(
                json.dumps(findings, sort_keys=True)
            ),
        },
    }
    serialized = json.dumps(plan, sort_keys=True)
    if contains_durable_secret_text(serialized):
        raise FuseKitError("hosted_aws_plan_contains_secret_text")
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a redacted, non-mutating AWS hosted launcher plan."
    )
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", default=HOSTED_AWS_DEFAULT_REGION)
    parser.add_argument("--resource-tagging-json")
    parser.add_argument("--origin-cname", default="fusekit-prod.us-east-1.elasticbeanstalk.com")
    parser.add_argument("--zone", default=HOSTED_AWS_DEFAULT_ZONE)
    parser.add_argument("--record-name", default=HOSTED_AWS_DEFAULT_RECORD_NAME)
    args = parser.parse_args(argv)

    resource_tag_mappings = _load_resource_tag_mappings(args.resource_tagging_json)
    plan = build_hosted_aws_plan(
        account_id=args.account_id,
        region=args.region,
        resource_tag_mappings=resource_tag_mappings,
        origin_cname=args.origin_cname,
        zone=args.zone,
        record_name=args.record_name,
    )
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 2 if plan["blockers"] else 0


def _normalize_tags(value: object) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(tag_value) for key, tag_value in value.items()}
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return {}
    tags: dict[str, str] = {}
    for item in value:
        if not isinstance(item, Mapping):
            continue
        key = item.get("Key") or item.get("key")
        tag_value = item.get("Value") or item.get("value") or ""
        if key:
            tags[str(key)] = str(tag_value)
    return tags


def _protected_resource_reasons(*, arn: str, tags: Mapping[str, str]) -> list[str]:
    reasons: list[str] = []
    lowered_tags = {key.lower(): value.lower() for key, value in tags.items()}
    flattened = ",".join(f"{key}={value}" for key, value in lowered_tags.items())
    lowered_arn = arn.lower()
    for key, value in MAILPILOT_PROTECTED_TAGS:
        if lowered_tags.get(key.lower()) == value.lower():
            reasons.append(f"protected_tag:{key}")
    if MAILPILOT_PROTECTED_TOKEN in lowered_arn:
        reasons.append("protected_name:mailpilot")
    if lowered_tags.get("managedby") == "terraform" and any(
        marker in f"{flattened},{lowered_arn}" for marker in MAILPILOT_PROTECTED_MARKERS
    ):
        reasons.append("protected_iac_boundary:terraform_mailpilot")
    return sorted(set(reasons))


def _valid_dns_hostname(value: str) -> bool:
    if any(marker in value for marker in ("://", "/", "?", "#", "@")):
        return False
    if not re.fullmatch(
        r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}",
        value,
    ):
        return False
    return True


def _load_resource_tag_mappings(path: str | None) -> Sequence[Mapping[str, object]]:
    if not path:
        return ()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, Mapping):
        mappings = payload.get("ResourceTagMappingList") or payload.get("resources") or []
    else:
        mappings = payload
    if not isinstance(mappings, Sequence) or isinstance(mappings, (str, bytes)):
        raise FuseKitError("resource_tagging_json_must_be_mapping_list")
    return [item for item in mappings if isinstance(item, Mapping)]
