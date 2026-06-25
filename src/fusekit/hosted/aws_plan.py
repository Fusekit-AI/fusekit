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
HOSTED_AWS_ALLOWED_REGIONS = ("us-east-1",)
HOSTED_AWS_DEFAULT_ZONE = "snowmanai.org"
HOSTED_AWS_DEFAULT_RECORD_NAME = "fusekit"
HOSTED_AWS_DEFAULT_RECORD_TYPE = "CNAME"
HOSTED_CLOUDFLARE_DRY_RUN_SCHEMA_VERSION = "fusekit.cloudflare-dns-dry-run.v1"

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
    "customer-pii",
    "client-pii",
)
DNS_DRY_RUN_ALLOWED_KEYS = {
    "action",
    "zone",
    "record_name",
    "record_type",
    "record_value",
    "proxied",
    "ttl",
}


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


def validate_cloudflare_fusekit_dns_dry_run(
    changes: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Validate a non-mutating Cloudflare DNS dry-run diff."""

    if not changes:
        raise FuseKitError("cloudflare_dns_dry_run_changes_missing")
    validated: list[dict[str, str]] = []
    for change in changes:
        unexpected_keys = set(str(key) for key in change) - DNS_DRY_RUN_ALLOWED_KEYS
        if unexpected_keys:
            raise FuseKitError("cloudflare_dns_dry_run_unexpected_fields")
        proxied = change.get("proxied")
        if proxied is not None and not isinstance(proxied, bool):
            raise FuseKitError("cloudflare_dns_dry_run_proxied_must_be_boolean")
        ttl = change.get("ttl")
        if ttl is not None and not (ttl == "auto" or isinstance(ttl, int)):
            raise FuseKitError("cloudflare_dns_dry_run_ttl_invalid")
        action = str(change.get("action") or "").strip().lower()
        if action not in {"create", "update", "upsert", "noop"}:
            raise FuseKitError("cloudflare_dns_dry_run_action_not_allowed")
        record = validate_cloudflare_fusekit_dns_change(
            zone=str(change.get("zone") or ""),
            record_name=str(change.get("record_name") or ""),
            record_type=str(change.get("record_type") or ""),
            record_value=str(change.get("record_value") or ""),
        )
        record["action"] = action
        validated.append(record)
    if len(validated) != 1:
        raise FuseKitError("cloudflare_dns_dry_run_single_record_required")
    return {
        "schema_version": HOSTED_CLOUDFLARE_DRY_RUN_SCHEMA_VERSION,
        "mode": "dry_run",
        "mutates_cloudflare": False,
        "changes": validated,
        "policy": {
            "allowed_fqdn": "fusekit.snowmanai.org",
            "forbidden_records": ["snowmanai.org", "www.snowmanai.org", "*.snowmanai.org"],
            "requires_visible_approval": True,
        },
    }


def build_hosted_aws_plan(
    *,
    account_id: str,
    expected_account_id: str = "",
    region: str = HOSTED_AWS_DEFAULT_REGION,
    allowed_regions: Sequence[str] = HOSTED_AWS_ALLOWED_REGIONS,
    resource_tag_mappings: Sequence[Mapping[str, object]] = (),
    origin_cname: str = "fusekit-prod.us-east-1.elasticbeanstalk.com",
    zone: str = HOSTED_AWS_DEFAULT_ZONE,
    record_name: str = HOSTED_AWS_DEFAULT_RECORD_NAME,
) -> dict[str, object]:
    """Build a redacted, non-mutating AWS deployment plan."""

    findings = protected_aws_resource_findings(resource_tag_mappings)
    blockers = []
    if not _valid_aws_account_id(account_id):
        blockers.append("aws_account_id_invalid")
    if expected_account_id and not _valid_aws_account_id(expected_account_id):
        blockers.append("aws_expected_account_id_invalid")
    if expected_account_id and _account_digits(account_id) != _account_digits(expected_account_id):
        blockers.append("aws_account_id_mismatch")
    if not allowed_regions or not all(
        _valid_aws_region(region_name) for region_name in allowed_regions
    ):
        blockers.append("aws_allowed_regions_invalid")
    if region not in allowed_regions:
        blockers.append("aws_region_not_allowed")
    if not _valid_elastic_beanstalk_cname(origin_cname):
        blockers.append("aws_origin_cname_not_elastic_beanstalk")
    if findings:
        blockers.append("protected_aws_account_resources_detected")
    dns = validate_cloudflare_fusekit_dns_change(
        zone=zone,
        record_name=record_name,
        record_type=HOSTED_AWS_DEFAULT_RECORD_TYPE,
        record_value=origin_cname,
    )
    dns_dry_run = validate_cloudflare_fusekit_dns_dry_run(
        [
            {
                "action": "upsert",
                "zone": dns["zone"],
                "record_name": dns["record_name"],
                "record_type": dns["record_type"],
                "record_value": dns["record_value"],
            }
        ]
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
            "expected_id": (
                redacted_aws_account_id(expected_account_id) if expected_account_id else ""
            ),
            "region": region,
            "allowed_regions": list(allowed_regions),
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
            "account_id_must_match_expected": bool(expected_account_id),
            "allowed_regions": list(allowed_regions),
        },
        "runtime_env_names": sorted(set(REQUIRED_HOSTED_ENV + HOSTED_AWS_SOURCE_PROVENANCE_ENV)),
        "cloudflare_dns": dns,
        "cloudflare_dns_dry_run": dns_dry_run,
        "rollback_metadata": {
            "scope": "fusekit_hosted_launcher_only",
            "dns_records": [dns],
            "aws_resources": [
                "Elastic Beanstalk application/environment tagged Application=FuseKit",
                "launcher runtime environment variables listed in runtime_env_names",
            ],
            "reversible_operations": [
                "delete or restore only the fusekit.snowmanai.org Cloudflare CNAME",
                "terminate only Elastic Beanstalk resources tagged Application=FuseKit",
                "remove only hosted launcher runtime variables listed in runtime_env_names",
            ],
            "completion_requires": [
                "rollback_plan",
                "provider_resource_inventory",
                "rollback_execution_receipt",
                "post_rollback_verification",
            ],
            "mailpilot_resources": [],
        },
        "proof": {
            "no_mailpilot_resources_touched": not findings,
            "aws_account_id_valid": _valid_aws_account_id(account_id),
            "aws_account_id_matches_expected": (
                not expected_account_id
                or _account_digits(account_id) == _account_digits(expected_account_id)
            ),
            "aws_region_allowed": region in allowed_regions,
            "aws_origin_cname_matches_provider": _valid_elastic_beanstalk_cname(origin_cname),
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
    parser.add_argument("--expected-account-id", default="")
    parser.add_argument("--region", default=HOSTED_AWS_DEFAULT_REGION)
    parser.add_argument("--resource-tagging-json")
    parser.add_argument("--origin-cname", default="fusekit-prod.us-east-1.elasticbeanstalk.com")
    parser.add_argument("--zone", default=HOSTED_AWS_DEFAULT_ZONE)
    parser.add_argument("--record-name", default=HOSTED_AWS_DEFAULT_RECORD_NAME)
    args = parser.parse_args(argv)

    resource_tag_mappings = _load_resource_tag_mappings(args.resource_tagging_json)
    plan = build_hosted_aws_plan(
        account_id=args.account_id,
        expected_account_id=args.expected_account_id,
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


def _account_digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _valid_aws_account_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d{12}", _account_digits(value)))


def _valid_aws_region(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z]{2}-[a-z]+-\d", value))


def _valid_elastic_beanstalk_cname(value: str) -> bool:
    hostname = value.strip().rstrip(".").lower()
    return _valid_dns_hostname(hostname) and hostname.endswith(".elasticbeanstalk.com")


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
    if _contains_pii_tag(lowered_tags):
        reasons.append("protected_tag:pii")
    if lowered_tags.get("managedby") == "terraform" and any(
        marker in f"{flattened},{lowered_arn}" for marker in MAILPILOT_PROTECTED_MARKERS
    ):
        reasons.append("protected_iac_boundary:terraform_mailpilot")
    return sorted(set(reasons))


def _contains_pii_tag(lowered_tags: Mapping[str, str]) -> bool:
    false_values = {"", "0", "false", "no", "none", "public", "non-pii", "non_pii"}
    for key, value in lowered_tags.items():
        normalized = value.strip().lower()
        if normalized in false_values:
            continue
        if "pii" in key or "customer-pii" in normalized or "client-pii" in normalized:
            return True
        if key in {"dataclassification", "data_classification", "contains"} and (
            "pii" in normalized or normalized in {"customer", "client", "sensitive"}
        ):
            return True
    return False


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
