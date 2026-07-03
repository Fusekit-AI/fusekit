"""Minimal hosted FuseKit launcher web entrypoint."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import tempfile
import urllib.parse
from collections.abc import Callable, Iterable, MutableMapping
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import Any, cast
from wsgiref.simple_server import make_server

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fusekit.errors import FuseKitError
from fusekit.hosted.billing import (
    HOSTED_PAYMENT_SCHEMA_VERSION,
    STRIPE_CHECKOUT_METADATA_KEYS,
    STRIPE_CHECKOUT_PROVIDER,
    HostedPaymentConfig,
    create_stripe_checkout_session,
    payment_required_receipt,
    retrieve_stripe_checkout_session,
)
from fusekit.hosted.evidence import HOSTED_COMPLETION_EVIDENCE_KEYS
from fusekit.hosted.github_app import (
    GitHubAppConfig,
    UrlOpener,
    exchange_installation_token,
    hosted_github_intake_contract,
    hosted_github_public_token_boundary,
    list_installation_repositories,
    require_hosted_installation_token_boundary,
)
from fusekit.hosted.job import (
    HostedLaunchJob,
    advance_hosted_launch_job,
    apply_hosted_worker_proof,
    build_hosted_launch_job,
    claim_hosted_launch_job,
    create_hosted_job_token,
    hosted_byo_oci_bootstrap,
    hosted_job_action_receipt,
    hosted_proof_receipt,
    hosted_worker_claim_receipt,
    hosted_worker_request,
    render_hosted_byo_oci_bootstrap,
    render_hosted_control_room,
    render_hosted_proof_receipt,
    verify_hosted_job_token,
    with_hosted_job_payment_receipt,
)
from fusekit.hosted.lanes import (
    BYO_OCI_LANE,
    MANAGED_FUSEKIT_RUN_LANE,
    byo_oci_security_contract,
    byo_oci_user_owned_cost_boundary,
    hosted_launch_lane_contract,
    valid_hosted_launch_lane,
)
from fusekit.hosted.launcher import (
    HOSTED_LAUNCH_PATH,
    HOSTED_PLAIN_LANGUAGE_JOURNEY,
    HOSTED_PROHIBITED_ACTIONS,
    HOSTED_PROOF_REQUIREMENTS,
    HOSTED_REVERSAL_PATH,
    NO_TERMINAL_PROMISE,
    TRUST_STORY,
    HostedLaunchPlan,
    build_hosted_launch_plan,
    render_hosted_launcher,
)
from fusekit.hosted.session import create_hosted_state_token, verify_hosted_state_token
from fusekit.scanner import scan_repo
from fusekit.source import (
    UrlOpener as SourceUrlOpener,
)
from fusekit.source import (
    fetch_github_source_archive,
    normalize_github_repo_slug,
)

StartResponse = Callable[[str, list[tuple[str, str]]], object]

HOSTED_CANONICAL_ORIGIN = "https://fusekit.snowmanai.org"
HOSTED_MAX_POST_BODY_BYTES = 65_536
HOSTED_SOURCE_REPOSITORY = "https://github.com/Fusekit-AI/fusekit"
HOSTED_SOURCE_REPOSITORY_OWNER = "Fusekit-AI"
HOSTED_SOURCE_REPOSITORY_NAME = "fusekit"
HOSTED_SOURCE_PROVENANCE_ENV = (
    "VERCEL_ENV",
    "VERCEL_URL",
    "VERCEL_GIT_PROVIDER",
    "VERCEL_GIT_REPO_OWNER",
    "VERCEL_GIT_REPO_SLUG",
    "VERCEL_GIT_COMMIT_REF",
    "VERCEL_GIT_COMMIT_SHA",
)
HOSTED_AWS_SOURCE_PROVENANCE_ENV = (
    "FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER",
    "FUSEKIT_HOSTED_DEPLOYMENT_ENV",
    "FUSEKIT_HOSTED_DEPLOYMENT_URL",
    "FUSEKIT_HOSTED_GIT_PROVIDER",
    "FUSEKIT_HOSTED_GIT_REPO_OWNER",
    "FUSEKIT_HOSTED_GIT_REPO_SLUG",
    "FUSEKIT_HOSTED_GIT_COMMIT_REF",
    "FUSEKIT_HOSTED_GIT_COMMIT_SHA",
)
HOSTED_OCI_SOURCE_PROVENANCE_ENV = HOSTED_AWS_SOURCE_PROVENANCE_ENV
HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV = ("FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER",)
HOSTED_GENERIC_OPERATOR_SETUP_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "select_hosted_deployment_provider",
        "label": (
            "Select the hosted deployment provider explicitly: oci-compute, "
            "aws-elastic-beanstalk, or vercel."
        ),
        "proof": (
            "Hosted readiness reports a supported deployment provider before publishing "
            "provider-specific DNS, runtime, and source-provenance instructions."
        ),
    },
)
HOSTED_VERCEL_OPERATOR_SETUP_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "connect_vercel_project",
        "label": (
            "Connect the Vercel project to the open-source FuseKit repository "
            "and expose Vercel system environment variables."
        ),
        "proof": (
            "Vercel deployment provenance reports the expected GitHub repo, branch, "
            "commit SHA, and production environment."
        ),
    },
    {
        "id": "deploy_worker_dispatch_receiver",
        "label": (
            "Deploy an HTTPS worker dispatch service running "
            "fusekit-hosted-worker-dispatch with durable dispatch state."
        ),
        "proof": "Its /healthz and /readiness endpoints pass with production readiness.",
    },
    {
        "id": "configure_worker_dispatch_url",
        "label": (
            "Set FUSEKIT_HOSTED_WORKER_DISPATCH_URL in the hosted Vercel project "
            "to that HTTPS dispatch endpoint."
        ),
        "proof": "Hosted readiness reports the dispatch URL is configured before launch.",
    },
    {
        "id": "attach_custom_domain",
        "label": "Add fusekit.snowmanai.org as the Vercel custom domain.",
        "proof": "Vercel reports the domain as assigned to this project.",
    },
    {
        "id": "route_cloudflare_cname",
        "label": (
            "In Cloudflare DNS, set the fusekit record to the exact "
            "Vercel-provided CNAME target."
        ),
        "proof": "The subdomain serves FuseKit instead of a Cloudflare error page.",
    },
    {
        "id": "verify_public_contracts",
        "label": (
            "Verify https://fusekit.snowmanai.org/healthz, /api/hosted/readiness, "
            "/api/hosted/deployment, and the worker dispatch receiver from outside "
            "the deployment."
        ),
        "proof": (
            "fusekit-hosted-verify reports DNS, health, readiness, deployment, "
            "and --worker-dispatch-url checks ok."
        ),
    },
)
HOSTED_AWS_OPERATOR_SETUP_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "deploy_aws_python_wsgi_origin",
        "label": (
            "Deploy the hosted FuseKit Python WSGI app to an AWS origin such as "
            "Elastic Beanstalk using Procfile."
        ),
        "proof": (
            "AWS hosted provenance reports the expected GitHub repo, branch, commit SHA, "
            "production environment, and public AWS origin URL."
        ),
    },
    {
        "id": "deploy_worker_dispatch_receiver",
        "label": (
            "Deploy an HTTPS worker dispatch service running "
            "fusekit-hosted-worker-dispatch with durable dispatch state."
        ),
        "proof": "Its /healthz and /readiness endpoints pass with production readiness.",
    },
    {
        "id": "configure_worker_dispatch_url",
        "label": (
            "Set FUSEKIT_HOSTED_WORKER_DISPATCH_URL in the hosted AWS environment "
            "to that HTTPS dispatch endpoint."
        ),
        "proof": "Hosted readiness reports the dispatch URL is configured before launch.",
    },
    {
        "id": "attach_aws_https_origin",
        "label": "Attach fusekit.snowmanai.org to the AWS HTTPS origin.",
        "proof": "AWS and Cloudflare report a valid TLS-backed origin for this subdomain.",
    },
    {
        "id": "route_cloudflare_cname",
        "label": (
            "In Cloudflare DNS, set the fusekit record to the exact AWS-provided "
            "CNAME target."
        ),
        "proof": "The subdomain serves FuseKit instead of a Cloudflare error page.",
    },
    {
        "id": "verify_public_contracts",
        "label": (
            "Verify https://fusekit.snowmanai.org/healthz, /api/hosted/readiness, "
            "/api/hosted/deployment, and the worker dispatch receiver from outside "
            "the deployment."
        ),
        "proof": (
            "fusekit-hosted-verify reports DNS, health, readiness, deployment, "
            "and --worker-dispatch-url checks ok."
        ),
    },
)
HOSTED_OCI_OPERATOR_SETUP_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "deploy_oci_python_wsgi_origin",
        "label": (
            "Deploy the hosted FuseKit Python WSGI app to a tagged OCI Compute origin "
            "using systemd and gunicorn."
        ),
        "proof": (
            "OCI hosted provenance reports the expected GitHub repo, branch, commit SHA, "
            "production environment, and public HTTPS launcher URL."
        ),
    },
    {
        "id": "deploy_worker_dispatch_receiver",
        "label": (
            "Deploy an HTTPS worker dispatch service running "
            "fusekit-hosted-worker-dispatch with durable dispatch state."
        ),
        "proof": "Its /healthz and /readiness endpoints pass with production readiness.",
    },
    {
        "id": "configure_worker_dispatch_url",
        "label": (
            "Set FUSEKIT_HOSTED_WORKER_DISPATCH_URL in the hosted OCI environment "
            "to that HTTPS dispatch endpoint."
        ),
        "proof": "Hosted readiness reports the dispatch URL is configured before launch.",
    },
    {
        "id": "attach_oci_https_origin",
        "label": "Attach fusekit.snowmanai.org to the OCI HTTPS origin through Cloudflare.",
        "proof": "OCI and Cloudflare report a valid TLS-backed origin for this subdomain.",
    },
    {
        "id": "route_cloudflare_a_record",
        "label": (
            "In Cloudflare DNS, set the fusekit record to the exact OCI reserved public "
            "IP address."
        ),
        "proof": "The subdomain serves FuseKit instead of a Cloudflare error page.",
    },
    {
        "id": "verify_public_contracts",
        "label": (
            "Verify https://fusekit.snowmanai.org/healthz, /api/hosted/readiness, "
            "/api/hosted/deployment, and the worker dispatch receiver from outside "
            "the deployment."
        ),
        "proof": (
            "fusekit-hosted-verify reports DNS, health, readiness, deployment, "
            "and --worker-dispatch-url checks ok."
        ),
    },
)
HOSTED_OPERATOR_SETUP_STEPS = HOSTED_VERCEL_OPERATOR_SETUP_STEPS
HOSTED_PUBLIC_TRUST_CONTRACT: dict[str, str] = {
    "open_core": "Source repository, MIT license, and app.py entrypoint are public before install.",
    "narrow_permissions": (
        "GitHub App intake starts with contents:read on one selected repository; "
        "provider mutations require visible approval."
    ),
    "visible_plan": "Providers, approved action ids, human gates, and artifacts are shown first.",
    "redacted_proof": (
        "Public receipts use URLs, statuses, artifact labels, and redacted notes only."
    ),
    "reversible_setup": "Stop, revoke, rollback, and detonation controls preserve public proof.",
}
HOSTED_FORBIDDEN_PUBLIC_MATERIAL = (
    "provider credentials",
    "GitHub installation tokens",
    "GitHub App private keys",
    "worker secrets",
    "HMAC signatures",
    "vault material",
    "copy-once secret values",
)
HOSTED_ALLOWED_PUBLIC_MATERIAL = (
    "provider names",
    "approved action ids",
    "artifact labels",
    "redacted statuses",
    "public URLs",
    "rollback action summaries",
    "detonation receipt status",
)
HOSTED_CAPABILITY_VAULT_BOUNDARY: dict[str, object] = {
    "raw_secret_policy": (
        "Only FuseKit may use secrets internally. Raw secrets must never leave the "
        "vault runtime."
    ),
    "generated_app_policy": (
        "Generated apps may request capabilities; they must not receive provider "
        "credentials, GitHub installation tokens, worker secrets, or vault material."
    ),
    "public_surface_policy": (
        "Hosted pages, job tokens, receipts, logs, proof, and deployment contracts "
        "use redacted labels, statuses, URLs, and artifact names only."
    ),
    "forbidden_public_material": list(HOSTED_FORBIDDEN_PUBLIC_MATERIAL),
    "allowed_public_material": list(HOSTED_ALLOWED_PUBLIC_MATERIAL),
}
HOSTED_SECURITY_HEADERS_CONTRACT: dict[str, object] = {
    "applies_to": [
        "hosted launcher HTML",
        "hosted JSON APIs",
        "hosted worker dispatch JSON APIs",
    ],
    "required_headers": [
        "Cache-Control",
        "Content-Security-Policy",
        "Cross-Origin-Opener-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
    ],
    "requirements": {
        "cache": "no-store",
        "content_security_policy": "default-src 'none' and frame-ancestors 'none'",
        "cross_origin_opener_policy": "same-origin",
        "permissions_policy": "camera, microphone, geolocation, payment, and usb disabled",
        "referrer_policy": "no-referrer",
        "strict_transport_security": "max-age=31536000 with includeSubDomains",
        "content_type_options": "nosniff",
        "frame_options": "DENY",
    },
    "secret_boundary": (
        "Security header contracts list header names and public policy requirements only. "
        "They do not include tokens, cookies, signatures, provider credentials, or vault material."
    ),
}
HOSTED_SOURCE_INTEGRITY_CONTRACT: dict[str, object] = {
    "source_repository": HOSTED_SOURCE_REPOSITORY,
    "license": "MIT",
    "deployment_model": (
        "A supported hosted runtime serves the launcher from public repository files."
    ),
    "reviewable_files": [
        "app.py",
        "vercel.json",
        "Procfile",
        ".python-version",
        "requirements.txt",
        "src/fusekit/hosted/aws_plan.py",
        "src/fusekit/hosted/server.py",
        "src/fusekit/hosted/launcher.py",
        "src/fusekit/hosted/verify.py",
    ],
    "public_contract_endpoints": [
        "/api/hosted/readiness",
        "/api/hosted/deployment",
        "/api/github/intake",
    ],
    "private_generated_artifact_required": False,
    "secret_boundary": (
        "Source integrity proof lists public repository paths, public endpoint paths, "
        "and license metadata only. It does not include build tokens, deploy hooks, "
        "provider credentials, vault material, or generated private artifacts."
    ),
}
HOSTED_PROVIDER_PERMISSION_COPY: dict[str, object] = {
    "github": {
        "visible_label": "GitHub",
        "initial_scope": "one selected repository",
        "requested_permissions": ["contents:read", "metadata:read"],
        "forbidden_permissions": ["contents:write", "secrets:write", "all repositories"],
        "human_gate": (
            "GitHub sign-in, MFA, passkey, SSO, consent, and repo selection stay human-owned."
        ),
    },
    "aws": {
        "visible_label": "AWS hosted origin",
        "initial_scope": "FuseKit hosted launcher account/environment only",
        "requested_permissions": [
            "deploy tagged FuseKit hosted origin",
            "read public deployment provenance",
        ],
        "forbidden_permissions": [
            "MailPilot resources",
            "client PII stores",
            "unscoped AdministratorAccess for generated apps",
        ],
        "human_gate": (
            "AWS account, billing, MFA, organization, and service quota gates stay human-owned."
        ),
    },
    "cloudflare": {
        "visible_label": "Cloudflare DNS",
        "initial_scope": "snowmanai.org fusekit CNAME only",
        "requested_permissions": ["create/update fusekit CNAME after visible approval"],
        "forbidden_permissions": [
            "apex record",
            "www record",
            "wildcard record",
            "MailPilot records",
        ],
        "human_gate": "Cloudflare login, MFA, domain ownership, and DNS approval stay human-owned.",
    },
    "resend": {
        "visible_label": "Resend",
        "initial_scope": "app email domain/audience requested by visible plan",
        "requested_permissions": [
            "domain verification status",
            "audience/sender setup after approval",
        ],
        "forbidden_permissions": ["copy-once API key rendering", "unapproved email domains"],
        "human_gate": (
            "Resend signup, domain verification, billing, and copy-once token gates "
            "stay human-owned."
        ),
    },
    "openai_llm": {
        "visible_label": "OpenAI/LLM",
        "initial_scope": "LLM configuration requested by visible plan",
        "requested_permissions": ["provider/model configuration labels only"],
        "forbidden_permissions": ["raw API key rendering", "training-data or billing changes"],
        "human_gate": (
            "LLM provider login, billing, MFA, consent, and copy-once token gates stay human-owned."
        ),
    },
    "secret_boundary": (
        "Provider permission copy is public explanatory text only. It contains no provider "
        "tokens, AWS credentials, Cloudflare API tokens, Resend keys, OpenAI keys, "
        "GitHub installation tokens, or vault material."
    ),
}
HOSTED_READINESS_SCHEMA_VERSION = "fusekit.hosted-readiness.v1"
HOSTED_DEPLOYMENT_SCHEMA_VERSION = "fusekit.hosted-deployment.v1"
HOSTED_LANE_READINESS_SCHEMA_VERSION = "fusekit.hosted-lane-readiness.v1"
HOSTED_WORKER_DISPATCH_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch.v1"
HOSTED_WORKER_DISPATCH_BINDING_FIELDS = (
    "job_id",
    "action",
    "lane",
    "payment_status",
    "plan_fingerprint",
    "price_label_hash",
)
HOSTED_CONTROL_TOKEN_TTL_SECONDS = 300
REQUIRED_HOSTED_ENV = (
    "FUSEKIT_HOSTED_ORIGIN",
    "FUSEKIT_GITHUB_APP_ID",
    "FUSEKIT_GITHUB_APP_SLUG",
    "FUSEKIT_GITHUB_APP_PRIVATE_KEY",
    "FUSEKIT_HOSTED_STATE_SECRET",
    "FUSEKIT_HOSTED_WORKER_SECRET",
    "FUSEKIT_HOSTED_WORKER_DISPATCH_URL",
)
OPTIONAL_HOSTED_ENV: tuple[str, ...] = ()
HOSTED_READINESS_NEXT_ACTIONS: dict[str, str] = {
    "FUSEKIT_HOSTED_ORIGIN": "Set FUSEKIT_HOSTED_ORIGIN to https://fusekit.snowmanai.org.",
    "FUSEKIT_GITHUB_APP_ID": "Set the GitHub App id for the FuseKit hosted launcher.",
    "FUSEKIT_GITHUB_APP_SLUG": "Set the GitHub App slug for the FuseKit hosted launcher.",
    "FUSEKIT_GITHUB_APP_PRIVATE_KEY": (
        "Set the GitHub App RSA private key in the hosted runtime secret store."
    ),
    "FUSEKIT_HOSTED_STATE_SECRET": (
        "Set a long random hosted state secret for GitHub redirects and control tokens."
    ),
    "FUSEKIT_HOSTED_WORKER_SECRET": (
        "Set a long random worker secret shared only with the hosted worker dispatch receiver."
    ),
    "FUSEKIT_HOSTED_WORKER_DISPATCH_URL": (
        "Deploy the hosted worker dispatch receiver and set its HTTPS dispatch URL."
    ),
    "hosted_origin_must_be_https_origin": (
        "Use an HTTPS origin with no path, query, credentials, or fragment."
    ),
    "hosted_worker_dispatch_url_must_be_https": (
        "Use an HTTPS worker dispatch URL with no credentials in the URL."
    ),
    "github_app_id_must_be_positive_integer": "Use a positive numeric GitHub App id.",
    "github_app_slug_is_invalid": "Use the GitHub App slug exactly as GitHub provides it.",
    "github_app_private_key_must_be_rsa_pem": (
        "Store a valid RSA PEM private key for the GitHub App."
    ),
    "hosted_state_secret_too_short": "Use at least 16 characters for the hosted state secret.",
    "hosted_worker_secret_too_short": "Use at least 16 characters for the worker secret.",
    "stripe_secret_key_required_for_managed_runs": (
        "Store a live FUSEKIT_STRIPE_SECRET_KEY only in the hosted runtime secret file "
        "before enabling managed paid runs."
    ),
    "stripe_live_secret_key_required_for_managed_runs": (
        "Use a live-mode Stripe secret key; test-mode keys can stage Checkout but cannot "
        "enable public managed paid runs."
    ),
    "stripe_price_id_required_for_managed_runs": (
        "Run fusekit-hosted-stripe-price --execute --confirm-shared-account to create a "
        "FuseKit-scoped Stripe Price, then set FUSEKIT_STRIPE_PRICE_ID."
    ),
    "managed_run_price_label_required": (
        "Use the fusekit-hosted-stripe-price output to set FUSEKIT_MANAGED_RUN_PRICE_LABEL "
        "to the public price shown before Checkout."
    ),
    "hosted_deployment_provider_required": (
        "Set FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER to oci-compute, aws-elastic-beanstalk, "
        "or vercel before relying on provider-specific setup instructions."
    ),
    "hosted_deployment_provider_unsupported": (
        "Use a supported hosted deployment provider: oci-compute, aws-elastic-beanstalk, "
        "or vercel."
    ),
    "managed_runs_not_enabled": (
        "Set FUSEKIT_MANAGED_RUNS_ENABLED=1 only after live Stripe Checkout proof and "
        "worker-dispatch acceptance pass."
    ),
    "source_provenance_not_verified": (
        "Publish hosted source provenance for Fusekit-AI/fusekit from the deployment "
        "runtime so the public source provenance verifies."
    ),
}


@dataclass(frozen=True)
class HostedSettings:
    """Public hosted launcher settings."""

    public_origin: str = HOSTED_CANONICAL_ORIGIN
    github_app_id: str = ""
    github_app_slug: str = "fusekit-launcher"
    github_private_key_pem: str = ""
    state_secret: str = ""
    worker_secret: str = ""
    worker_dispatch_url: str = ""
    deployment_provider: str = ""
    vercel_env: str = ""
    vercel_url: str = ""
    vercel_git_provider: str = ""
    vercel_git_repo_owner: str = ""
    vercel_git_repo_slug: str = ""
    vercel_git_commit_ref: str = ""
    vercel_git_commit_sha: str = ""
    aws_deployment_env: str = ""
    aws_deployment_url: str = ""
    aws_git_provider: str = ""
    aws_git_repo_owner: str = ""
    aws_git_repo_slug: str = ""
    aws_git_commit_ref: str = ""
    aws_git_commit_sha: str = ""
    github_opener: UrlOpener | None = None
    worker_dispatch_opener: UrlOpener | None = None
    stripe_opener: UrlOpener | None = None
    managed_runs_enabled: bool = False
    stripe_secret_key: str = ""
    stripe_price_id: str = ""
    managed_run_price_label: str = ""
    stripe_test_mode_allowed: bool = False
    hosted_jobs: MutableMapping[str, HostedLaunchJob] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> HostedSettings:
        """Load hosted settings from environment variables."""

        return cls(
            public_origin=os.environ.get("FUSEKIT_HOSTED_ORIGIN", HOSTED_CANONICAL_ORIGIN),
            github_app_id=os.environ.get("FUSEKIT_GITHUB_APP_ID", ""),
            github_app_slug=os.environ.get("FUSEKIT_GITHUB_APP_SLUG", "fusekit-launcher"),
            github_private_key_pem=os.environ.get("FUSEKIT_GITHUB_APP_PRIVATE_KEY", ""),
            state_secret=os.environ.get("FUSEKIT_HOSTED_STATE_SECRET", ""),
            worker_secret=os.environ.get("FUSEKIT_HOSTED_WORKER_SECRET", ""),
            worker_dispatch_url=os.environ.get("FUSEKIT_HOSTED_WORKER_DISPATCH_URL", ""),
            deployment_provider=os.environ.get("FUSEKIT_HOSTED_DEPLOYMENT_PROVIDER", ""),
            vercel_env=os.environ.get("VERCEL_ENV", ""),
            vercel_url=os.environ.get("VERCEL_URL", ""),
            vercel_git_provider=os.environ.get("VERCEL_GIT_PROVIDER", ""),
            vercel_git_repo_owner=os.environ.get("VERCEL_GIT_REPO_OWNER", ""),
            vercel_git_repo_slug=os.environ.get("VERCEL_GIT_REPO_SLUG", ""),
            vercel_git_commit_ref=os.environ.get("VERCEL_GIT_COMMIT_REF", ""),
            vercel_git_commit_sha=os.environ.get("VERCEL_GIT_COMMIT_SHA", ""),
            aws_deployment_env=os.environ.get("FUSEKIT_HOSTED_DEPLOYMENT_ENV", ""),
            aws_deployment_url=os.environ.get("FUSEKIT_HOSTED_DEPLOYMENT_URL", ""),
            aws_git_provider=os.environ.get("FUSEKIT_HOSTED_GIT_PROVIDER", ""),
            aws_git_repo_owner=os.environ.get("FUSEKIT_HOSTED_GIT_REPO_OWNER", ""),
            aws_git_repo_slug=os.environ.get("FUSEKIT_HOSTED_GIT_REPO_SLUG", ""),
            aws_git_commit_ref=os.environ.get("FUSEKIT_HOSTED_GIT_COMMIT_REF", ""),
            aws_git_commit_sha=os.environ.get("FUSEKIT_HOSTED_GIT_COMMIT_SHA", ""),
            managed_runs_enabled=_env_flag("FUSEKIT_MANAGED_RUNS_ENABLED"),
            stripe_secret_key=os.environ.get("FUSEKIT_STRIPE_SECRET_KEY", ""),
            stripe_price_id=os.environ.get("FUSEKIT_STRIPE_PRICE_ID", ""),
            managed_run_price_label=os.environ.get("FUSEKIT_MANAGED_RUN_PRICE_LABEL", ""),
            stripe_test_mode_allowed=_env_flag("FUSEKIT_STRIPE_TEST_MODE_ALLOWED"),
        )

    def github_config(self) -> GitHubAppConfig:
        """Return the GitHub App config for hosted intake."""

        return GitHubAppConfig(
            app_id=self.github_app_id,
            app_slug=self.github_app_slug,
            private_key_pem=self.github_private_key_pem,
        )

    def payment_config(self) -> HostedPaymentConfig:
        """Return backend-only managed-run payment configuration."""

        return HostedPaymentConfig(
            enabled=self.managed_runs_enabled,
            stripe_secret_key=self.stripe_secret_key,
            stripe_price_id=self.stripe_price_id,
            price_label=self.managed_run_price_label,
            public_origin=_public_origin_label(self.public_origin),
            test_mode_allowed=self.stripe_test_mode_allowed,
            opener=self.stripe_opener,
        )

    def readiness(self) -> dict[str, object]:
        """Return public, redacted hosted readiness metadata."""

        configured = {
            "FUSEKIT_HOSTED_ORIGIN": bool(self.public_origin),
            "FUSEKIT_GITHUB_APP_ID": bool(self.github_app_id),
            "FUSEKIT_GITHUB_APP_SLUG": bool(self.github_app_slug),
            "FUSEKIT_GITHUB_APP_PRIVATE_KEY": bool(self.github_private_key_pem),
            "FUSEKIT_HOSTED_STATE_SECRET": bool(self.state_secret),
            "FUSEKIT_HOSTED_WORKER_SECRET": bool(self.worker_secret),
            "FUSEKIT_HOSTED_WORKER_DISPATCH_URL": bool(self.worker_dispatch_url),
        }
        source_provenance = self.source_provenance()
        missing = tuple(key for key in REQUIRED_HOSTED_ENV if not configured[key])
        invalid = _hosted_config_errors(self) if not missing else ()
        blocking_checks = _hosted_readiness_blocking_checks(missing, invalid)
        required_source_env = self.required_source_provenance_env()
        return {
            "schema_version": HOSTED_READINESS_SCHEMA_VERSION,
            "ready": not missing and not invalid,
            "public_origin": _public_origin_label(self.public_origin),
            "github_app_slug": _github_app_slug_label(self.github_app_slug),
            "configured": configured,
            "payment": self.payment_config().public_dict(),
            "lane_readiness": self.lane_readiness(),
            "missing": list(missing),
            "invalid": list(invalid),
            "blocking_checks": blocking_checks,
            "next_actions": _hosted_readiness_next_actions(missing, invalid),
            "optional_runtime_env": list(OPTIONAL_HOSTED_ENV),
            "required_source_provenance_env": list(required_source_env),
            "source_provenance": source_provenance,
            "secret_boundary": (
                "Readiness reports only configuration presence. Raw GitHub App private keys, "
                "state secrets, installation tokens, and provider credentials are never rendered."
            ),
        }

    def deployment_contract(self) -> dict[str, object]:
        """Return public hosted deployment metadata for operator verification."""

        public_origin = _public_origin_label(self.public_origin)
        dispatch_url = _public_url_label(self.worker_dispatch_url)
        dispatch_receiver_base = _worker_dispatch_receiver_base_url(self.worker_dispatch_url)
        deployment_provider = self.hosted_deployment_provider()
        return {
            "schema_version": HOSTED_DEPLOYMENT_SCHEMA_VERSION,
            "canonical_origin": HOSTED_CANONICAL_ORIGIN,
            "public_origin": public_origin,
            "domain": "fusekit.snowmanai.org",
            "trust_story": list(TRUST_STORY),
            "trust_contract": dict(HOSTED_PUBLIC_TRUST_CONTRACT),
            "launch_lanes": hosted_launch_lane_contract(),
            "payment": self.payment_config().public_dict(),
            "lane_readiness": self.lane_readiness(),
            "capability_vault_boundary": dict(HOSTED_CAPABILITY_VAULT_BOUNDARY),
            "provider_permissions": dict(HOSTED_PROVIDER_PERMISSION_COPY),
            "security_headers": dict(HOSTED_SECURITY_HEADERS_CONTRACT),
            "source_integrity": dict(HOSTED_SOURCE_INTEGRITY_CONTRACT),
            "source_provenance": self.source_provenance(),
            "one_click_launch": {
                "public_url": HOSTED_CANONICAL_ORIGIN,
                "start_control": "Start hosted launch",
                "lanes": hosted_launch_lane_contract(),
                "no_terminal_promise": NO_TERMINAL_PROMISE,
                "intake": "github-app",
                "repository_scope": "one selected GitHub repository",
                "github_repository_permission": "contents:read",
                "launch_path": list(HOSTED_LAUNCH_PATH),
                "plain_language_journey": list(HOSTED_PLAIN_LANGUAGE_JOURNEY),
                "prohibited": list(HOSTED_PROHIBITED_ACTIONS),
                "human_gates": [
                    "GitHub sign-in, MFA, passkey, SSO, consent, or repository selection",
                    (
                        "Provider-owned billing, CAPTCHA, domain ownership, or "
                        "copy-once secret screens"
                    ),
                    "DNS changes only after FuseKit shows the exact proposed records",
                ],
                "completion_requires": list(HOSTED_PROOF_REQUIREMENTS),
                "completion_evidence_keys": list(HOSTED_COMPLETION_EVIDENCE_KEYS),
                "reversal": list(HOSTED_REVERSAL_PATH),
                "terminal_required": False,
                "download_required": False,
            },
            "protected_controls": {
                "actions": ["start", "stop", "rollback", "detonate"],
                "http_method": "POST",
                "control_token_transport": "hidden_form_field",
                "content_type": "application/x-www-form-urlencoded",
                "query_control_behavior": "rejected_as_missing_control",
                "browser_origin_policy": "reject_cross_origin_when_origin_or_referer_present",
                "job_token_transport": "signed_public_query_parameter",
                "binding": "job_id_and_action",
                "token_lifetime": "short-lived",
                "public_url_policy": "action URLs must not include control tokens",
                "missing_token_behavior": "render disabled protected controls",
                "secret_boundary": (
                    "Protected action receipts and public job tokens are redacted. Control "
                    "tokens are action-bound click capabilities, not provider credentials, "
                    "and must not appear in action URLs, deployment contracts, receipts, or "
                    "logs."
                ),
            },
            "runtime": self.runtime_contract(),
            "open_core": {
                "source_repository": HOSTED_SOURCE_REPOSITORY,
                "license": "MIT",
                "reviewable_entrypoint": "app.py",
                "public_contracts": [
                    f"{public_origin}/api/hosted/readiness",
                    f"{public_origin}/api/hosted/deployment",
                ],
            },
            "cloudflare_dns": {
                "zone": "snowmanai.org",
                "record_name": "fusekit",
                "record_type": _cloudflare_record_type_for_provider(deployment_provider),
                "record_value": _cloudflare_record_value_label(deployment_provider),
                "verification": "The subdomain must serve this app, not a Cloudflare error page.",
                "dry_run_policy": {
                    "allowed_actions": ["create", "update", "upsert", "noop"],
                    "allowed_fqdn": "fusekit.snowmanai.org",
                    "forbidden_records": ["snowmanai.org", "www.snowmanai.org", "*.snowmanai.org"],
                    "requires_visible_approval": True,
                },
            },
            "rollback_requirements": {
                "metadata_required_before_completion": True,
                "execution_receipt_required_for_rollback_request": True,
                "post_rollback_verification_required": True,
                "provider_inventory_required": True,
                "secret_boundary": (
                    "Rollback requirements list provider surfaces and proof labels only. "
                    "They do not include provider credentials, API tokens, or vault material."
                ),
            },
            "operator_setup": {
                "target_subdomain": "fusekit.snowmanai.org",
                "steps": [dict(step) for step in self.operator_setup_steps()],
                "secret_boundary": (
                    "Operator setup names provider surfaces and expected public proof only. "
                    "It does not include AWS credentials, Vercel tokens, Cloudflare API tokens, "
                    "GitHub private keys, HMAC secrets, or vault material."
                ),
            },
            "github_app": {
                "callback_url": f"{public_origin}/github/callback",
                "intake_url": f"{public_origin}/api/github/intake",
                "repository_permission": "contents:read",
                "token_boundary": hosted_github_public_token_boundary(),
            },
            "checks": {
                "health": f"{public_origin}/healthz",
                "readiness": f"{public_origin}/api/hosted/readiness",
                "deployment": f"{public_origin}/api/hosted/deployment",
            },
            "required_runtime_env": list(REQUIRED_HOSTED_ENV),
            "optional_runtime_env": list(OPTIONAL_HOSTED_ENV),
            "required_source_provenance_env": list(self.required_source_provenance_env()),
            "worker_dispatch": {
                "env_var": "FUSEKIT_HOSTED_WORKER_DISPATCH_URL",
                "receiver_command": "fusekit-hosted-worker-dispatch",
                "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
                "authentication": "HMAC-SHA256 with FUSEKIT_HOSTED_WORKER_SECRET",
                "production_required": True,
                "no_terminal_wakeup_required": True,
                "dispatch_binding": {
                    "required": True,
                    "required_fields": list(HOSTED_WORKER_DISPATCH_BINDING_FIELDS),
                    "required_for_actions": ["start", "rollback", "detonate"],
                    "lane": MANAGED_FUSEKIT_RUN_LANE,
                    "payment_status": "paid",
                    "hash_fields": ["plan_fingerprint", "price_label_hash"],
                    "secret_boundary": (
                        "Dispatch binding contains only public job/action/lane/payment "
                        "labels and SHA-256 public hashes; job tokens and worker secrets "
                        "are excluded."
                    ),
                },
                "checks": {
                    "dispatch": dispatch_url,
                    "health": f"{dispatch_receiver_base}/healthz",
                    "readiness": f"{dispatch_receiver_base}/readiness",
                },
                "required_runtime_env": [
                    "FUSEKIT_HOSTED_WORKER_SECRET",
                    "FUSEKIT_HOSTED_WORKER_ID",
                ],
                "optional_runtime_env": [
                    "FUSEKIT_HOSTED_WORKER_WORKSPACE",
                    "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR",
                ],
                "secret_boundary": (
                    "Dispatch sends a signed public job token and never sends the worker secret, "
                    "GitHub installation token, provider credentials, or vault material."
                ),
            },
            "secret_boundary": (
                "This contract is public. It contains URLs, record names, and env var names only; "
                "it never includes private keys, state secrets, installation tokens, or provider "
                "credentials."
            ),
        }

    def lane_readiness(self) -> dict[str, object]:
        """Return public, redacted per-lane launch readiness."""

        managed_blockers = _managed_lane_blockers(self)
        byo_blockers = _byo_oci_lane_blockers(self)
        lanes = {
            MANAGED_FUSEKIT_RUN_LANE: {
                "launchable": not managed_blockers,
                "requires_payment": True,
                "managed_worker_dispatch_allowed": not managed_blockers,
                "blocking_checks": managed_blockers,
                "next_actions": _hosted_readiness_next_actions((), tuple(managed_blockers)),
            },
            BYO_OCI_LANE: {
                "launchable": not byo_blockers,
                "requires_payment": False,
                "managed_worker_dispatch_allowed": False,
                "requires_user_cloud_account": True,
                "user_owned_cost_boundary": byo_oci_user_owned_cost_boundary(),
                "security_contract": byo_oci_security_contract(),
                "blocking_checks": byo_blockers,
                "next_actions": _hosted_readiness_next_actions((), tuple(byo_blockers)),
            },
        }
        launchable_lanes = [
            lane_id
            for lane_id in (MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE)
            if lanes[lane_id]["launchable"] is True
        ]
        return {
            "schema_version": HOSTED_LANE_READINESS_SCHEMA_VERSION,
            "default_lane": MANAGED_FUSEKIT_RUN_LANE,
            "recommended_lane": launchable_lanes[0] if launchable_lanes else "",
            "launchable_lanes": launchable_lanes,
            "lanes": lanes,
            "cost_policy": (
                "Managed FuseKit runs are not launchable until server-side Stripe Checkout "
                "is fully configured and each job has a paid receipt. BYO OCI remains the "
                "no-FuseKit-managed-infrastructure lane."
            ),
            "secret_boundary": (
                "Lane readiness exposes only booleans, public lane ids, failure codes, and "
                "next-action labels. It never renders Stripe keys, GitHub tokens, worker "
                "secrets, OCI credentials, or vault material."
            ),
        }

    def hosted_deployment_provider(self) -> str:
        """Return the selected public hosted deployment provider."""

        provider = self.deployment_provider.strip().lower()
        if provider in {"aws", "aws-elastic-beanstalk", "elastic-beanstalk"}:
            return "aws-elastic-beanstalk"
        if provider in {"oci", "oci-compute", "oracle-cloud", "oracle-cloud-infrastructure"}:
            return "oci-compute"
        if provider == "vercel" or self._has_vercel_source_provenance():
            return "vercel"
        return "unknown"

    def deployment_provider_config_error(self) -> str:
        """Return the public config error for unsupported or missing provider selection."""

        if self.hosted_deployment_provider() != "unknown":
            return ""
        if self.deployment_provider.strip():
            return "hosted_deployment_provider_unsupported"
        return "hosted_deployment_provider_required"

    def _has_vercel_source_provenance(self) -> bool:
        return any(
            bool(value)
            for value in (
                self.vercel_env,
                self.vercel_url,
                self.vercel_git_provider,
                self.vercel_git_repo_owner,
                self.vercel_git_repo_slug,
                self.vercel_git_commit_ref,
                self.vercel_git_commit_sha,
            )
        )

    def required_source_provenance_env(self) -> tuple[str, ...]:
        """Return provider-specific non-secret provenance environment names."""

        if self.hosted_deployment_provider() == "aws-elastic-beanstalk":
            return HOSTED_AWS_SOURCE_PROVENANCE_ENV
        if self.hosted_deployment_provider() == "oci-compute":
            return HOSTED_OCI_SOURCE_PROVENANCE_ENV
        if self.hosted_deployment_provider() == "vercel":
            return HOSTED_SOURCE_PROVENANCE_ENV
        return HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV

    def runtime_contract(self) -> dict[str, object]:
        """Return provider-specific hosted runtime metadata."""

        if self.hosted_deployment_provider() == "aws-elastic-beanstalk":
            return {
                "provider": "aws-elastic-beanstalk",
                "entrypoint": "app.py",
                "process_config": "Procfile",
                "requirements": "requirements.txt",
                "python_version": ".python-version",
                "application_export": "app",
                "mode": "python-wsgi",
            }
        if self.hosted_deployment_provider() == "oci-compute":
            return {
                "provider": "oci-compute",
                "entrypoint": "app.py",
                "process_config": "systemd:fusekit-hosted.service",
                "requirements": "requirements.txt",
                "python_version": ".python-version",
                "application_export": "app",
                "mode": "python-wsgi-on-oci-compute",
            }
        if self.hosted_deployment_provider() != "vercel":
            return {
                "provider": "unknown",
                "entrypoint": "app.py",
                "requirements": "requirements.txt",
                "python_version": ".python-version",
                "application_export": "app",
                "mode": "python-wsgi",
            }
        return {
            "provider": "vercel",
            "entrypoint": "app.py",
            "routing_config": "vercel.json",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        }

    def operator_setup_steps(self) -> tuple[dict[str, str], ...]:
        """Return provider-specific public operator setup steps."""

        if self.hosted_deployment_provider() == "aws-elastic-beanstalk":
            return HOSTED_AWS_OPERATOR_SETUP_STEPS
        if self.hosted_deployment_provider() == "oci-compute":
            return HOSTED_OCI_OPERATOR_SETUP_STEPS
        if self.hosted_deployment_provider() == "vercel":
            return HOSTED_VERCEL_OPERATOR_SETUP_STEPS
        return HOSTED_GENERIC_OPERATOR_SETUP_STEPS

    def source_provenance(self) -> dict[str, object]:
        """Return public Git/deployment provenance for the hosted deployment."""

        if self.hosted_deployment_provider() == "aws-elastic-beanstalk":
            return self._aws_source_provenance()
        if self.hosted_deployment_provider() == "oci-compute":
            return self._oci_source_provenance()
        if self.hosted_deployment_provider() != "vercel":
            return self._unknown_source_provenance()

        return self._vercel_source_provenance()

    def _unknown_source_provenance(self) -> dict[str, object]:
        """Return neutral unverified provenance when no provider is selected."""

        return {
            "provider": "unknown",
            "source": "deployment_provider_not_selected",
            "expected": {
                "deployment_provider": "oci-compute | aws-elastic-beanstalk | vercel",
                "source_repository": HOSTED_SOURCE_REPOSITORY,
            },
            "actual": {
                "deployment_provider_configured": bool(self.deployment_provider.strip()),
                "selected_provider": "unknown",
            },
            "verified": False,
            "required_env": list(HOSTED_UNKNOWN_SOURCE_PROVENANCE_ENV),
            "secret_boundary": (
                "Source provenance publishes only the provider-selection state. It does "
                "not publish deployment credentials, GitHub installation tokens, provider "
                "credentials, or vault material."
            ),
        }

    def _vercel_source_provenance(self) -> dict[str, object]:
        """Return public Git/Vercel provenance for the hosted deployment."""

        actual = {
            "deployment_environment": self.vercel_env,
            "deployment_url": self.vercel_url,
            "git_provider": self.vercel_git_provider,
            "repo_owner": self.vercel_git_repo_owner,
            "repo_slug": self.vercel_git_repo_slug,
            "commit_ref": self.vercel_git_commit_ref,
            "commit_sha": self.vercel_git_commit_sha,
        }
        verified = (
            actual["deployment_environment"] == "production"
            and valid_hosted_vercel_deployment_url(actual["deployment_url"])
            and actual["git_provider"] == "github"
            and actual["repo_owner"] == HOSTED_SOURCE_REPOSITORY_OWNER
            and actual["repo_slug"] == HOSTED_SOURCE_REPOSITORY_NAME
            and bool(actual["commit_ref"])
            and _looks_like_git_commit_sha(actual["commit_sha"])
        )
        return {
            "provider": "vercel",
            "source": "vercel_system_environment_variables",
            "expected": {
                "deployment_environment": "production",
                "git_provider": "github",
                "repo_owner": HOSTED_SOURCE_REPOSITORY_OWNER,
                "repo_slug": HOSTED_SOURCE_REPOSITORY_NAME,
                "source_repository": HOSTED_SOURCE_REPOSITORY,
            },
            "actual": actual,
            "verified": verified,
            "required_env": list(HOSTED_SOURCE_PROVENANCE_ENV),
            "secret_boundary": (
                "Source provenance publishes only Vercel/Git metadata: environment, "
                "deployment URL, provider, repository owner/name, branch/ref, and commit "
                "SHA. It does not publish Vercel tokens, project IDs, OIDC tokens, deploy "
                "hooks, GitHub installation tokens, provider credentials, or vault material."
            ),
        }

    def _aws_source_provenance(self) -> dict[str, object]:
        """Return public Git/AWS provenance for the hosted deployment."""

        actual = {
            "deployment_environment": self.aws_deployment_env,
            "deployment_url": self.aws_deployment_url,
            "git_provider": self.aws_git_provider,
            "repo_owner": self.aws_git_repo_owner,
            "repo_slug": self.aws_git_repo_slug,
            "commit_ref": self.aws_git_commit_ref,
            "commit_sha": self.aws_git_commit_sha,
        }
        verified = (
            actual["deployment_environment"] == "production"
            and valid_hosted_aws_deployment_url(actual["deployment_url"])
            and actual["git_provider"] == "github"
            and actual["repo_owner"] == HOSTED_SOURCE_REPOSITORY_OWNER
            and actual["repo_slug"] == HOSTED_SOURCE_REPOSITORY_NAME
            and bool(actual["commit_ref"])
            and _looks_like_git_commit_sha(actual["commit_sha"])
        )
        return {
            "provider": "aws-elastic-beanstalk",
            "source": "fusekit_hosted_environment_variables",
            "expected": {
                "deployment_environment": "production",
                "git_provider": "github",
                "repo_owner": HOSTED_SOURCE_REPOSITORY_OWNER,
                "repo_slug": HOSTED_SOURCE_REPOSITORY_NAME,
                "source_repository": HOSTED_SOURCE_REPOSITORY,
            },
            "actual": actual,
            "verified": verified,
            "required_env": list(HOSTED_AWS_SOURCE_PROVENANCE_ENV),
            "secret_boundary": (
                "Source provenance publishes only AWS/Git metadata: environment, "
                "deployment URL, provider, repository owner/name, branch/ref, and commit "
                "SHA. It does not publish AWS credentials, CloudFormation outputs, access "
                "keys, deploy hooks, GitHub installation tokens, provider credentials, or "
                "vault material."
            ),
        }

    def _oci_source_provenance(self) -> dict[str, object]:
        """Return public Git/OCI provenance for the hosted deployment."""

        actual = {
            "deployment_environment": self.aws_deployment_env,
            "deployment_url": self.aws_deployment_url,
            "git_provider": self.aws_git_provider,
            "repo_owner": self.aws_git_repo_owner,
            "repo_slug": self.aws_git_repo_slug,
            "commit_ref": self.aws_git_commit_ref,
            "commit_sha": self.aws_git_commit_sha,
        }
        verified = (
            actual["deployment_environment"] == "production"
            and valid_hosted_oci_deployment_url(actual["deployment_url"])
            and actual["git_provider"] == "github"
            and actual["repo_owner"] == HOSTED_SOURCE_REPOSITORY_OWNER
            and actual["repo_slug"] == HOSTED_SOURCE_REPOSITORY_NAME
            and bool(actual["commit_ref"])
            and _looks_like_git_commit_sha(actual["commit_sha"])
        )
        return {
            "provider": "oci-compute",
            "source": "fusekit_hosted_environment_variables",
            "expected": {
                "deployment_environment": "production",
                "git_provider": "github",
                "repo_owner": HOSTED_SOURCE_REPOSITORY_OWNER,
                "repo_slug": HOSTED_SOURCE_REPOSITORY_NAME,
                "source_repository": HOSTED_SOURCE_REPOSITORY,
            },
            "actual": actual,
            "verified": verified,
            "required_env": list(HOSTED_OCI_SOURCE_PROVENANCE_ENV),
            "secret_boundary": (
                "Source provenance publishes only OCI/Git metadata: environment, "
                "deployment URL, provider, repository owner/name, branch/ref, and commit "
                "SHA. It does not publish OCI credentials, access keys, deploy hooks, "
                "GitHub installation tokens, provider credentials, or vault material."
            ),
        }


def application(
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    """WSGI application for the hosted launcher."""

    return hosted_application(HostedSettings.from_env())(environ, start_response)


def hosted_application(
    settings: HostedSettings,
) -> Callable[[dict[str, object], StartResponse], Iterable[bytes]]:
    """Build a configured WSGI app."""

    def app(environ: dict[str, object], start_response: StartResponse) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/") or "/")
        if path.startswith("/api/hosted/jobs/"):
            return _hosted_job_api_response(settings, environ, start_response, method=method)
        if method != "GET":
            return _response(
                start_response,
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
            )
        if path == "/healthz":
            return _response(start_response, HTTPStatus.OK, {"ok": True})
        if path == "/api/hosted/readiness":
            return _response(start_response, HTTPStatus.OK, settings.readiness())
        if path == "/api/hosted/deployment":
            return _response(start_response, HTTPStatus.OK, settings.deployment_contract())
        if path == "/":
            return _html_response(start_response, render_hosted_home(settings))
        if _requires_hosted_readiness(path) and not settings.readiness()["ready"]:
            return _hosted_not_ready_response(settings, start_response)
        if path == "/api/github/intake":
            return _response(
                start_response,
                HTTPStatus.OK,
                _github_intake_contract(settings.github_config()),
            )
        if path == "/github/callback":
            return _github_callback_response(settings, environ, start_response)
        if path == "/github/repositories":
            return _github_repositories_response(settings, environ, start_response)
        if path == "/github/plan":
            return _github_plan_response(settings, environ, start_response)
        if path == "/github/control-room":
            return _github_control_room_response(settings, environ, start_response)
        return _response(start_response, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    return app


def render_hosted_home(settings: HostedSettings) -> str:
    """Render the public no-terminal hosted launcher home page."""

    state = ""
    readiness = settings.readiness()
    setup_ready = readiness["ready"] is True
    if setup_ready:
        state = create_hosted_state_token(settings.state_secret, return_path="/")
    contract = _github_intake_contract(settings.github_config(), state=state)
    install_url = html.escape(str(contract["install_url"]), quote=True)
    public_origin = html.escape(str(readiness["public_origin"]))
    payload = html.escape(json.dumps(contract, sort_keys=True))
    readiness_payload = html.escape(json.dumps(readiness, sort_keys=True))
    deployment_contract = settings.deployment_contract()
    deployment_payload = html.escape(json.dumps(deployment_contract, sort_keys=True))
    runtime = cast(dict[str, object], deployment_contract["runtime"])
    provider_label = _deployment_provider_label(str(runtime.get("provider") or ""))
    provider_runtime_mode = html.escape(str(runtime.get("mode") or "hosted runtime"))
    provider_dns_target = html.escape(
        str(
            cast(dict[str, object], deployment_contract["cloudflare_dns"]).get(
                "record_value",
                "Use the exact provider-provided CNAME target.",
            )
        )
    )
    operator_setup = "\n".join(
        (
            "<li>"
            f"{html.escape(step['label'])} "
            f"<span class=\"origin\">Proof: {html.escape(step['proof'])}</span>"
            "</li>"
        )
        for step in settings.operator_setup_steps()
    )
    forbidden_material = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_FORBIDDEN_PUBLIC_MATERIAL
    )
    allowed_material = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_ALLOWED_PUBLIC_MATERIAL
    )
    prohibited_actions = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_PROHIBITED_ACTIONS
    )
    reviewable_files = "\n".join(
        f"<li>{html.escape(item)}</li>"
        for item in cast(list[str], HOSTED_SOURCE_INTEGRITY_CONTRACT["reviewable_files"])
    )
    source_repository = html.escape(HOSTED_SOURCE_REPOSITORY, quote=True)
    status = (
        "Hosted GitHub intake is ready."
        if setup_ready
        else "Hosted GitHub intake is waiting for operator configuration."
    )
    issues = _list_config_issues(readiness)
    readiness_summary = _readiness_summary_section(readiness)
    source_provenance_section = _source_provenance_section(
        cast(dict[str, object], deployment_contract["source_provenance"])
    )
    start_control = (
        f'<a class="button" href="{install_url}">Start hosted launch</a>'
        if setup_ready
        else '<span class="button disabled" aria-disabled="true">Start hosted launch</span>'
    )
    launch_path = "\n".join(f"<li>{html.escape(item)}</li>" for item in HOSTED_LAUNCH_PATH)
    plain_language_journey = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_PLAIN_LANGUAGE_JOURNEY
    )
    completion_requirements = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_PROOF_REQUIREMENTS
    )
    reversal_steps = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in HOSTED_REVERSAL_PATH
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit hosted launcher</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #536476;
      --line: #cfd9e2;
      --blue: #0077cc;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    main {{
      width: min(1040px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 34px 0 48px;
      display: grid;
      gap: 20px;
    }}
    header {{
      border-bottom: 2px solid var(--ink);
      padding-bottom: 22px;
      display: grid;
      gap: 14px;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{
      max-width: 820px;
      font-size: clamp(38px, 6vw, 72px);
      line-height: 0.98;
      letter-spacing: 0;
    }}
    p {{ color: #31465c; line-height: 1.5; max-width: 780px; }}
    .eyebrow {{
      color: var(--blue);
      font-size: 12px;
      font-weight: 850;
      text-transform: uppercase;
    }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 46px;
      width: fit-content;
      border-radius: 6px;
      background: var(--blue);
      color: white;
      padding: 0 18px;
      font-weight: 850;
      text-decoration: none;
    }}
    .button.disabled {{
      background: #d8e1ea;
      border-color: #aebcca;
      color: #52616f;
      cursor: not-allowed;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 12px;
    }}
    ul {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    ol {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    li + li {{ margin-top: 6px; }}
    .origin {{
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }}
    script[type="application/json"] {{ display: none; }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">SnowmanAI / FuseKit</div>
      <h1>Launch any GitHub app without touching a terminal.</h1>
      <p>
        FuseKit is an open-core setup worker with narrow permissions, a visible
        plan, redacted proof, and reversible setup. Start by installing the
        FuseKit GitHub App on one selected repository.
      </p>
      {start_control}
      <p class="origin">{public_origin}</p>
      <p>{html.escape(status)}</p>
      {issues}
    </header>
    {readiness_summary}
    <section aria-label="Trust contract">
      <h2>Before FuseKit runs</h2>
      <ul>
        <li>You choose exactly which GitHub repository FuseKit may read.</li>
        <li>
          GitHub access is selected repository only, requests
          <span class="origin">contents:read</span>, accepts GitHub
          <span class="origin">metadata:read</span>, and rejects all-repository
          or <span class="origin">contents:write</span> installation tokens.
        </li>
        <li>FuseKit shows the detected providers and setup plan before changes.</li>
        <li>Provider credentials stay server-side or inside the encrypted vault.</li>
        <li>Receipts, logs, proof, and generated apps do not expose raw secrets.</li>
        <li>You can stop, revoke access, roll back, and review the detonation receipt.</li>
      </ul>
    </section>
    <section aria-label="Capability vault boundary">
      <h2>Capability vault boundary</h2>
      <p>
        Only FuseKit may use secrets internally. Raw secrets must never leave
        the vault runtime. Generated apps may request capabilities, not raw
        provider credentials.
      </p>
      <h3>Never public</h3>
      <ul>{forbidden_material}</ul>
      <h3>Safe public proof</h3>
      <ul>{allowed_material}</ul>
    </section>
    <section aria-label="Launch path">
      <h2>What happens after the click</h2>
      <ol>{launch_path}</ol>
    </section>
    <section aria-label="Prohibited actions">
      <h2>What FuseKit will not do</h2>
      <ul>{prohibited_actions}</ul>
    </section>
    <section aria-label="Plain-language click path">
      <h2>For someone who just wants to click</h2>
      <ol>{plain_language_journey}</ol>
    </section>
    <section aria-label="Completion proof">
      <h2>Completion requires</h2>
      <p>
        FuseKit does not call a hosted launch complete until the worker submits
        redacted proof for every required live artifact.
      </p>
      <ul>{completion_requirements}</ul>
    </section>
    <section aria-label="Reversible setup">
      <h2>Reversible setup</h2>
      <p>
        FuseKit keeps recovery controls visible: stop before worker start,
        revoke GitHub access, request rollback, and require detonation proof.
      </p>
      <ul>{reversal_steps}</ul>
    </section>
    <section aria-label="Open core">
      <h2>Open core</h2>
      <ul>
        <li>
          Source code is reviewable at
          <a href="{source_repository}">{source_repository}</a>.
        </li>
        <li>The hosted entrypoint is <span class="origin">app.py</span>.</li>
        <li>The public package license is MIT.</li>
        <li>No private generated artifact is required for the hosted click flow.</li>
      </ul>
      <h3>Reviewable hosted files</h3>
      <ul>{reviewable_files}</ul>
    </section>
    {source_provenance_section}
    <section aria-label="Provider gates">
      <h2>What you may need to approve</h2>
      <ul>
        <li>GitHub sign-in, MFA, passkey, SSO, consent, or repository selection.</li>
        <li>Provider-owned billing, CAPTCHA, domain ownership, or copy-once secret screens.</li>
        <li>DNS changes only after FuseKit shows the exact proposed records.</li>
      </ul>
    </section>
    <section aria-label="Hosted deployment contract">
      <h2>Hosted deployment contract</h2>
      <ul>
        <li>This page is intended to run at <span class="origin">{public_origin}</span>.</li>
        <li>
          {html.escape(provider_label)} must serve the Python WSGI entrypoint
          exported from <span class="origin">app.py</span> using
          <span class="origin">{provider_runtime_mode}</span>.
        </li>
        <li>
          Cloudflare should route the <span class="origin">fusekit</span>
          subdomain to the deployment target:
          <span class="origin">{provider_dns_target}</span>
        </li>
        <li>
          The public readiness and deployment endpoints expose configuration
          names only, never secret values.
        </li>
      </ul>
      <ol>{operator_setup}</ol>
    </section>
    <script id="fusekit-github-intake" type="application/json">{payload}</script>
    <script id="fusekit-hosted-readiness" type="application/json">{readiness_payload}</script>
    <script id="fusekit-hosted-deployment" type="application/json">{deployment_payload}</script>
  </main>
</body>
</html>
"""


def _looks_like_git_commit_sha(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 40:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _source_provenance_section(provenance: dict[str, object]) -> str:
    actual = provenance.get("actual")
    actual = actual if isinstance(actual, dict) else {}
    provider = str(provenance.get("provider") or "")
    metadata_label = _deployment_metadata_label(provider)
    status = (
        "verified"
        if provenance.get("verified") is True
        else f"waiting for {metadata_label}"
    )
    repo = (
        f"{actual.get('repo_owner', '')}/{actual.get('repo_slug', '')}".strip("/")
        or "not reported"
    )
    commit_ref = str(actual.get("commit_ref") or "not reported")
    commit_sha = str(actual.get("commit_sha") or "not reported")
    environment = str(actual.get("deployment_environment") or "not reported")
    return f"""
    <section aria-label="Deployment provenance">
      <h2>Deployment provenance</h2>
      <p>
        FuseKit publishes the {html.escape(metadata_label)} for this deployment so the
        hosted page can be matched back to the public source repository.
      </p>
      <ul>
        <li>Status: <span class="origin">{html.escape(status)}</span></li>
        <li>Repository: <span class="origin">{html.escape(repo)}</span></li>
        <li>Branch/ref: <span class="origin">{html.escape(commit_ref)}</span></li>
        <li>Commit SHA: <span class="origin">{html.escape(commit_sha)}</span></li>
        <li>Environment: <span class="origin">{html.escape(environment)}</span></li>
      </ul>
    </section>
"""


def _github_intake_contract(config: GitHubAppConfig, *, state: str = "") -> dict[str, object]:
    return hosted_github_intake_contract(
        config,
        state=state,
        source_repository=HOSTED_SOURCE_REPOSITORY,
        license_name="MIT",
        reviewable_entrypoint="app.py",
    )


def _github_callback_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    state_token = _first_query_value(query, "state")
    installation_id = _first_query_value(query, "installation_id")
    setup_action = _first_query_value(query, "setup_action") or "install"
    if not state_token:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "missing_state"},
        )
    if not installation_id or not installation_id.isdecimal() or int(installation_id) <= 0:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_installation"},
        )
    try:
        state = verify_hosted_state_token(settings.state_secret, state_token)
    except FuseKitError:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_state"},
        )
    body = _render_github_callback_page(
        public_origin=settings.public_origin,
        installation_id=int(installation_id),
        setup_action=setup_action,
        return_path=state.return_path,
        state_token=state_token,
    )
    return _html_response(start_response, body)


def _github_repositories_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    state_token = _first_query_value(query, "state")
    installation_id = _first_query_value(query, "installation_id")
    if not state_token:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_state"})
    if not installation_id or not installation_id.isdecimal() or int(installation_id) <= 0:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_installation"},
        )
    try:
        verify_hosted_state_token(settings.state_secret, state_token)
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_state"})
    try:
        token = exchange_installation_token(
            settings.github_config(),
            installation_id=int(installation_id),
            permissions={"contents": "read"},
            opener=settings.github_opener,
        )
        require_hosted_installation_token_boundary(token)
        repositories = list_installation_repositories(
            settings.github_config(),
            token=token.token,
            opener=settings.github_opener,
        )
    except FuseKitError:
        return _response(
            start_response,
            HTTPStatus.BAD_GATEWAY,
            {"error": "github_repository_intake_failed"},
        )
    body = _render_github_repositories_page(
        public_origin=settings.public_origin,
        installation_id=int(installation_id),
        state_token=state_token,
        repositories=repositories,
    )
    return _html_response(start_response, body)


def _github_plan_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    state_token = _first_query_value(query, "state")
    installation_id = _first_query_value(query, "installation_id")
    repo = _first_query_value(query, "repo")
    if not state_token:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_state"})
    if not installation_id or not installation_id.isdecimal() or int(installation_id) <= 0:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_installation"},
        )
    if not _safe_repo_slug(repo):
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_repository"})
    try:
        verify_hosted_state_token(settings.state_secret, state_token)
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_state"})
    try:
        token = exchange_installation_token(
            settings.github_config(),
            installation_id=int(installation_id),
            permissions={"contents": "read"},
            opener=settings.github_opener,
        )
        require_hosted_installation_token_boundary(token)
        repositories = list_installation_repositories(
            settings.github_config(),
            token=token.token,
            opener=settings.github_opener,
        )
        if repo not in _repository_names(repositories):
            return _response(
                start_response,
                HTTPStatus.FORBIDDEN,
                {"error": "repository_not_selected"},
            )
        plan = _build_plan_from_selected_repo(
            settings,
            repo=repo,
            token=token.token,
        )
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_GATEWAY, {"error": "github_plan_failed"})
    body = render_hosted_launcher(
        plan,
        launch_url=_hosted_control_room_url(
            installation_id=int(installation_id),
            repo=repo,
            state_token=state_token,
            launch_lane=MANAGED_FUSEKIT_RUN_LANE,
        ),
        launch_urls={
            lane: _hosted_control_room_url(
                installation_id=int(installation_id),
                repo=repo,
                state_token=state_token,
                launch_lane=lane,
            )
            for lane in (MANAGED_FUSEKIT_RUN_LANE, BYO_OCI_LANE)
        },
        lane_readiness=settings.lane_readiness(),
    )
    return _html_response(start_response, body)


def _github_control_room_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    state_token = _first_query_value(query, "state")
    installation_id = _first_query_value(query, "installation_id")
    repo = _first_query_value(query, "repo")
    launch_lane = (_first_query_value(query, "lane") or MANAGED_FUSEKIT_RUN_LANE).strip().lower()
    if not state_token:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_state"})
    if not installation_id or not installation_id.isdecimal() or int(installation_id) <= 0:
        return _response(
            start_response,
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_installation"},
        )
    if not _safe_repo_slug(repo):
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_repository"})
    if not valid_hosted_launch_lane(launch_lane):
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_launch_lane"})
    try:
        verify_hosted_state_token(settings.state_secret, state_token)
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_state"})
    lane_readiness = _hosted_lane_readiness(settings, launch_lane)
    if lane_readiness.get("launchable") is not True:
        readiness = settings.lane_readiness()
        return _response(
            start_response,
            HTTPStatus.CONFLICT,
            {
                "error": "lane_not_launchable",
                "lane": launch_lane,
                "recommended_lane": readiness.get("recommended_lane", ""),
                "launchable_lanes": readiness.get("launchable_lanes", []),
                "blocking_checks": lane_readiness.get("blocking_checks", []),
                "next_actions": lane_readiness.get("next_actions", []),
                "secret_boundary": (
                    "Lane launch blocking responses expose only public lane ids, blocker "
                    "codes, and next-action labels. They never include GitHub tokens, Stripe "
                    "keys, worker secrets, OCI credentials, or vault material."
                ),
            },
        )
    try:
        token = exchange_installation_token(
            settings.github_config(),
            installation_id=int(installation_id),
            permissions={"contents": "read"},
            opener=settings.github_opener,
        )
        require_hosted_installation_token_boundary(token)
        repositories = list_installation_repositories(
            settings.github_config(),
            token=token.token,
            opener=settings.github_opener,
        )
        if repo not in _repository_names(repositories):
            return _response(
                start_response,
                HTTPStatus.FORBIDDEN,
                {"error": "repository_not_selected"},
            )
        plan = _build_plan_from_selected_repo(
            settings,
            repo=repo,
            token=token.token,
        )
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_GATEWAY, {"error": "github_job_failed"})
    job = build_hosted_launch_job(
        plan,
        github_installation_id=int(installation_id),
        launch_lane=launch_lane,
        payment_required=launch_lane == MANAGED_FUSEKIT_RUN_LANE,
        payment_price_label=settings.managed_run_price_label,
    )
    settings.hosted_jobs[job.job_id] = job
    job_token = create_hosted_job_token(settings.state_secret, job)
    body = render_hosted_control_room(
        job,
        control_tokens=_hosted_control_tokens(settings, job),
        job_token=job_token,
    )
    return _html_response(start_response, body)


def _hosted_job_api_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    *,
    method: str,
) -> Iterable[bytes]:
    path = str(environ.get("PATH_INFO", "") or "")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 4 or parts[:3] != ["api", "hosted", "jobs"]:
        return _response(start_response, HTTPStatus.NOT_FOUND, {"error": "not_found"})
    job_id = parts[3]
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    try:
        token_job = _job_from_query_token(settings, query, job_id=job_id)
    except FuseKitError:
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_job"})
    if token_job is None:
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_job"})
    job = settings.hosted_jobs.get(job_id) or token_job
    if len(parts) == 4 and method == "GET" and _wants_html(environ):
        return _hosted_job_html_response(settings, start_response, job)
    if len(parts) == 4 and method == "GET":
        return _hosted_job_response(settings, start_response, job)
    if len(parts) == 5 and parts[4] == "proof" and method == "GET":
        return _hosted_proof_receipt_response(settings, environ, start_response, job, query=query)
    if len(parts) == 5 and parts[4] == "worker-request" and method == "GET":
        return _hosted_worker_request_response(start_response, job)
    if len(parts) == 5 and parts[4] == "worker-claims" and method == "POST":
        return _hosted_worker_claim_response(settings, environ, start_response, job)
    if len(parts) == 5 and parts[4] == "worker-proof" and method == "POST":
        return _hosted_worker_proof_response(settings, environ, start_response, job)
    if len(parts) == 5 and parts[4] == "byo-oci-bootstrap" and method == "GET":
        return _hosted_byo_oci_bootstrap_response(settings, environ, start_response, job, query)
    if len(parts) == 6 and parts[4] == "payments" and parts[5] == "checkout" and method == "POST":
        return _hosted_payment_checkout_response(settings, environ, start_response, job=job)
    if (
        len(parts) == 6
        and parts[4] == "payments"
        and parts[5] == "stripe-return"
        and method == "GET"
    ):
        return _hosted_payment_return_response(settings, environ, start_response, job=job)
    if (
        len(parts) == 6
        and parts[4] == "payments"
        and parts[5] == "stripe-cancel"
        and method == "GET"
    ):
        return _hosted_payment_cancel_response(settings, start_response, job)
    if len(parts) == 6 and parts[4] == "actions" and method == "POST":
        return _hosted_job_action_response(
            settings,
            environ,
            start_response,
            job=job,
            action=parts[5],
        )
    return _response(
        start_response,
        HTTPStatus.METHOD_NOT_ALLOWED if method != "GET" else HTTPStatus.NOT_FOUND,
        {"error": "method_not_allowed" if method != "GET" else "not_found"},
    )


def _hosted_job_action_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    *,
    job: HostedLaunchJob,
    action: str,
) -> Iterable[bytes]:
    if not _hosted_action_origin_allowed(settings, environ):
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_control"})
    try:
        form = _form_request_body(environ)
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_control"})
    control_token = _first_query_value(form, "control")
    if not control_token:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_control"})
    try:
        _verify_hosted_control_token(settings, control_token, job=job, action=action)
    except FuseKitError:
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_control"})
    if action == "start" and _managed_payment_required(job):
        return _response(
            start_response,
            HTTPStatus.PAYMENT_REQUIRED,
            {
                "error": "payment_required",
                "payment": payment_required_receipt(
                    lane=job.launch_lane,
                    price_label=settings.managed_run_price_label,
                ),
                "checkout_path": (
                    f"/api/hosted/jobs/{urllib.parse.quote(job.job_id, safe='')}"
                    "/payments/checkout"
                ),
            },
        )
    try:
        updated = advance_hosted_launch_job(job, action)
    except ValueError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_action"})
    action_receipt = hosted_job_action_receipt(updated, action=action)
    job_token = create_hosted_job_token(settings.state_secret, updated)
    dispatch_receipt: dict[str, object] | None = None
    if action in {"start", "rollback", "detonate"} and job.launch_lane != BYO_OCI_LANE:
        try:
            dispatch_receipt = _dispatch_hosted_worker(
                settings,
                updated,
                action=action,
                job_token=job_token,
            )
        except FuseKitError:
            return _response(
                start_response,
                HTTPStatus.BAD_GATEWAY,
                {"error": "worker_dispatch_failed"},
            )
    if action == "start" and job.launch_lane == BYO_OCI_LANE:
        dispatch_receipt = {
            "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            "action": action,
            "dispatched": False,
            "reason": "byo_oci_user_owned_worker_lane",
            "secret_boundary": (
                "BYO OCI does not dispatch FuseKit-managed worker infrastructure. The "
                "user-owned OCI bootstrap exposes only redacted public job metadata."
            ),
        }
    settings.hosted_jobs[job.job_id] = updated
    if _wants_html(environ):
        return _html_response(
            start_response,
            render_hosted_control_room(
                updated,
                control_tokens=_hosted_control_tokens(settings, updated),
                job_token=job_token,
                action_receipt=action_receipt,
                dispatch_receipt=dispatch_receipt,
            ),
        )
    payload = updated.to_dict()
    payload["job_token"] = job_token
    payload["action_receipt"] = action_receipt
    if dispatch_receipt is not None:
        payload["worker_dispatch"] = dispatch_receipt
    return _response(start_response, HTTPStatus.OK, payload)


def _hosted_payment_checkout_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    *,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    if job.launch_lane != MANAGED_FUSEKIT_RUN_LANE:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "payment_not_required"})
    if not _hosted_action_origin_allowed(settings, environ):
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_control"})
    try:
        form = _form_request_body(environ)
    except FuseKitError:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_control"})
    control_token = _first_query_value(form, "control")
    if not control_token:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "missing_control"})
    try:
        _verify_hosted_control_token(settings, control_token, job=job, action="checkout")
    except FuseKitError:
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_control"})
    job_token = create_hosted_job_token(settings.state_secret, job)
    try:
        receipt = create_stripe_checkout_session(
            settings.payment_config(),
            job_id=job.job_id,
            job_token=job_token,
            lane=job.launch_lane,
            github_source=job.github_source,
            plan_fingerprint=job.worker_contract.plan_fingerprint,
        )
    except FuseKitError:
        return _response(
            start_response,
            HTTPStatus.SERVICE_UNAVAILABLE,
            {"error": "payment_not_ready"},
        )
    updated = with_hosted_job_payment_receipt(job, receipt)
    settings.hosted_jobs[job.job_id] = updated
    updated_token = create_hosted_job_token(settings.state_secret, updated)
    payload = updated.to_dict()
    payload["job_token"] = updated_token
    payload["payment"] = updated.to_dict()["payment"]
    if _wants_html(environ) and isinstance(receipt.get("checkout_url"), str):
        return _redirect_response(start_response, str(receipt["checkout_url"]))
    return _response(start_response, HTTPStatus.OK, payload)


def _hosted_payment_return_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    *,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    query = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)
    session_id = _first_query_value(query, "session_id")
    try:
        receipt = retrieve_stripe_checkout_session(
            settings.payment_config(),
            session_id=session_id,
        )
    except FuseKitError:
        return _response(
            start_response,
            HTTPStatus.BAD_GATEWAY,
            {"error": "payment_verification_failed"},
        )
    if not _payment_receipt_matches_job(settings, receipt, job):
        return _response(
            start_response,
            HTTPStatus.FORBIDDEN,
            {"error": "payment_binding_mismatch"},
        )
    if receipt.get("paid") is not True:
        return _response(start_response, HTTPStatus.PAYMENT_REQUIRED, {"error": "payment_not_paid"})
    updated = with_hosted_job_payment_receipt(job, receipt)
    settings.hosted_jobs[job.job_id] = updated
    job_token = create_hosted_job_token(settings.state_secret, updated)
    return _html_response(
        start_response,
        render_hosted_control_room(
            updated,
            control_tokens=_hosted_control_tokens(settings, updated),
            job_token=job_token,
            action_receipt={
                "schema_version": "fusekit.hosted-payment-return.v1",
                "action": "payment",
                "receipt_statement": (
                    "Stripe Checkout authorization verified; managed worker start is now enabled."
                ),
                "next_required_proof": ["worker_claim", "detonation_receipt", "recording"],
            },
        ),
    )


def _hosted_payment_cancel_response(
    settings: HostedSettings,
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    job_token = create_hosted_job_token(settings.state_secret, job)
    return _html_response(
        start_response,
        render_hosted_control_room(
            job,
            control_tokens=_hosted_control_tokens(settings, job),
            job_token=job_token,
            action_receipt={
                "schema_version": "fusekit.hosted-payment-cancel.v1",
                "action": "payment_cancelled",
                "receipt_statement": (
                    "Payment authorization was cancelled; managed worker dispatch remains blocked."
                ),
                "next_required_proof": ["stripe_checkout_authorization"],
            },
        ),
    )


def _hosted_byo_oci_bootstrap_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    job: HostedLaunchJob,
    query: dict[str, list[str]],
) -> Iterable[bytes]:
    if job.launch_lane != BYO_OCI_LANE:
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "byo_oci_not_selected"})
    if job.status == "waiting_for_worker":
        return _response(start_response, HTTPStatus.CONFLICT, {"error": "worker_not_started"})
    if _wants_html(environ) and _first_query_value(query, "format").strip().lower() != "json":
        return _html_response(
            start_response,
            render_hosted_byo_oci_bootstrap(
                job,
                job_token=create_hosted_job_token(settings.state_secret, job),
            ),
        )
    return _response(start_response, HTTPStatus.OK, hosted_byo_oci_bootstrap(job))


def _hosted_job_html_response(
    settings: HostedSettings,
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    job_token = create_hosted_job_token(settings.state_secret, job)
    return _html_response(
        start_response,
        render_hosted_control_room(
            job,
            control_tokens=_hosted_control_tokens(settings, job),
            job_token=job_token,
        ),
    )


def _hosted_proof_receipt_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    job: HostedLaunchJob,
    *,
    query: dict[str, list[str]],
) -> Iterable[bytes]:
    if _first_query_value(query, "format") == "json" or not _wants_html(environ):
        return _response(
            start_response,
            HTTPStatus.OK,
            hosted_proof_receipt(job),
            extra_headers=[
                (
                    "Content-Disposition",
                    f'attachment; filename="{job.job_id}-proof-receipt.json"',
                )
            ],
        )
    job_token = create_hosted_job_token(settings.state_secret, job)
    return _html_response(
        start_response,
        render_hosted_proof_receipt(job, job_token=job_token),
    )


def _hosted_worker_request_response(
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    if job.status in {"waiting_for_worker", "stopped"}:
        return _response(start_response, HTTPStatus.CONFLICT, {"error": "worker_not_started"})
    return _response(start_response, HTTPStatus.OK, hosted_worker_request(job))


def _hosted_worker_claim_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    if not settings.worker_secret or len(settings.worker_secret) < 16:
        return _response(
            start_response,
            HTTPStatus.SERVICE_UNAVAILABLE,
            {"error": "hosted_worker_not_ready", "readiness": settings.readiness()},
        )
    if not _worker_authorized(settings, environ):
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_worker_auth"})
    worker_id = _worker_id(environ)
    try:
        updated = claim_hosted_launch_job(job, worker_id=worker_id)
    except ValueError:
        return _response(start_response, HTTPStatus.CONFLICT, {"error": "worker_claim_rejected"})
    settings.hosted_jobs[job.job_id] = updated
    payload: dict[str, object] = {
        "job": updated.to_dict(),
        "job_token": create_hosted_job_token(settings.state_secret, updated),
        "worker_request": hosted_worker_request(updated),
        "claim_receipt": hosted_worker_claim_receipt(updated, worker_id=worker_id),
    }
    return _response(start_response, HTTPStatus.OK, payload)


def _hosted_worker_proof_response(
    settings: HostedSettings,
    environ: dict[str, object],
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    if not settings.worker_secret or len(settings.worker_secret) < 16:
        return _response(
            start_response,
            HTTPStatus.SERVICE_UNAVAILABLE,
            {"error": "hosted_worker_not_ready", "readiness": settings.readiness()},
        )
    if not _worker_authorized(settings, environ):
        return _response(start_response, HTTPStatus.FORBIDDEN, {"error": "invalid_worker_auth"})
    try:
        proof_payload = _json_request_body(environ)
        updated, receipt = apply_hosted_worker_proof(
            job,
            proof_payload,
            worker_id=_worker_id(environ),
        )
    except (FuseKitError, ValueError, json.JSONDecodeError):
        return _response(start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid_worker_proof"})
    settings.hosted_jobs[job.job_id] = updated
    payload: dict[str, object] = {
        "job": updated.to_dict(),
        "job_token": create_hosted_job_token(settings.state_secret, updated),
        "proof_receipt": receipt,
    }
    return _response(start_response, HTTPStatus.OK, payload)


def _hosted_job_response(
    settings: HostedSettings,
    start_response: StartResponse,
    job: HostedLaunchJob,
) -> Iterable[bytes]:
    payload = job.to_dict()
    payload["job_token"] = create_hosted_job_token(settings.state_secret, job)
    return _response(start_response, HTTPStatus.OK, payload)


def _wants_html(environ: dict[str, object]) -> bool:
    accept = str(environ.get("HTTP_ACCEPT", ""))
    return "text/html" in accept.lower()


def _job_from_query_token(
    settings: HostedSettings,
    query: dict[str, list[str]],
    *,
    job_id: str,
) -> HostedLaunchJob | None:
    job_token = _first_query_value(query, "job")
    if not job_token:
        return None
    job = verify_hosted_job_token(settings.state_secret, job_token)
    if job.job_id != job_id:
        raise FuseKitError("Hosted job token does not match route.")
    return job


def _verify_hosted_control_token(
    settings: HostedSettings,
    token: str,
    *,
    job: HostedLaunchJob,
    action: str,
) -> None:
    control = verify_hosted_state_token(
        settings.state_secret,
        token,
        ttl_seconds=HOSTED_CONTROL_TOKEN_TTL_SECONDS,
    )
    if control.return_path != _hosted_control_return_path(job.job_id, action):
        raise FuseKitError("Hosted control token does not match route.")


def _hosted_control_tokens(settings: HostedSettings, job: HostedLaunchJob) -> dict[str, str]:
    return {
        action: create_hosted_state_token(
            settings.state_secret,
            return_path=_hosted_control_return_path(job.job_id, action),
        )
        for action in ("checkout", "start", "stop", "rollback", "detonate")
    }


def _hosted_control_return_path(job_id: str, action: str) -> str:
    if action == "checkout":
        return f"/api/hosted/jobs/{job_id}/payments/checkout"
    return f"/api/hosted/jobs/{job_id}/actions/{action}"


def _build_plan_from_selected_repo(
    settings: HostedSettings,
    *,
    repo: str,
    token: str,
) -> HostedLaunchPlan:
    source = f"https://github.com/{repo}"
    with tempfile.TemporaryDirectory(prefix="fusekit-hosted-source-") as temp_dir:
        source_result = fetch_github_source_archive(
            source,
            Path(temp_dir) / "app",
            token=token,
            opener=cast(SourceUrlOpener | None, settings.github_opener),
        )
        manifest = scan_repo(source_result.dest)
        return build_hosted_launch_plan(manifest, github_source=source)


def _hosted_control_room_url(
    *,
    installation_id: int,
    repo: str,
    state_token: str,
    launch_lane: str,
) -> str:
    return "/github/control-room?" + urllib.parse.urlencode(
        {
            "installation_id": str(installation_id),
            "repo": repo,
            "state": state_token,
            "lane": launch_lane,
        }
    )


def _render_github_callback_page(
    *,
    public_origin: str,
    installation_id: int,
    setup_action: str,
    return_path: str,
    state_token: str,
) -> str:
    safe_origin = html.escape(public_origin)
    safe_action = html.escape(setup_action)
    safe_return_path = html.escape(return_path, quote=True)
    repositories_url = html.escape(
        "/github/repositories?"
        + urllib.parse.urlencode(
            {
                "installation_id": str(installation_id),
                "state": state_token,
            }
        ),
        quote=True,
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit GitHub connected</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #536476;
      --line: #cfd9e2;
      --blue: #0077cc;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    main {{
      width: min(760px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 34px 0 48px;
      display: grid;
      gap: 18px;
    }}
    h1, p {{ margin: 0; }}
    h1 {{ font-size: clamp(34px, 5vw, 56px); line-height: 1; letter-spacing: 0; }}
    p {{ color: #31465c; line-height: 1.5; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 10px;
    }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      width: fit-content;
      border-radius: 6px;
      background: var(--blue);
      color: white;
      padding: 0 16px;
      font-weight: 850;
      text-decoration: none;
    }}
    .origin {{
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }}
  </style>
</head>
<body>
  <main>
    <h1>GitHub App connected.</h1>
    <p>
      FuseKit received GitHub installation {installation_id} after the
      provider-owned {safe_action} gate. No installation token is embedded in
      this page.
    </p>
    <div class="panel">
      <p>Next: scan the selected repository and show the visible launch plan.</p>
      <p class="origin">{safe_origin}{safe_return_path}</p>
      <a class="button" href="{repositories_url}">Continue</a>
    </div>
  </main>
</body>
</html>
"""


def _requires_hosted_readiness(path: str) -> bool:
    return path == "/api/github/intake" or path.startswith("/github/")


def _hosted_not_ready_response(
    settings: HostedSettings,
    start_response: StartResponse,
) -> Iterable[bytes]:
    return _response(
        start_response,
        HTTPStatus.SERVICE_UNAVAILABLE,
        {
            "error": "hosted_not_ready",
            "readiness": settings.readiness(),
        },
    )


def _list_config_issues(readiness: dict[str, object]) -> str:
    missing = readiness.get("missing")
    invalid = readiness.get("invalid")
    rows: list[str] = []
    if isinstance(missing, list):
        rows.extend(f"missing:{item}" for item in missing)
    if isinstance(invalid, list):
        rows.extend(f"invalid:{item}" for item in invalid)
    if not rows:
        return ""
    items = "\n".join(f"<li>{html.escape(str(item))}</li>" for item in rows)
    return f"""
      <section aria-label="Missing hosted configuration">
        <h2>Operator setup pending</h2>
        <p>FuseKit will not start hosted intake until these configuration checks pass.</p>
        <ul>{items}</ul>
      </section>
"""


def _readiness_summary_section(readiness: dict[str, object]) -> str:
    ready = readiness.get("ready") is True
    blocking_checks = _string_list(readiness.get("blocking_checks"))
    next_actions = _string_list(readiness.get("next_actions"))
    if ready:
        body = "<li>All hosted readiness checks passed.</li>"
    else:
        body = "\n".join(f"<li>{html.escape(item)}</li>" for item in next_actions)
        if not body:
            body = "\n".join(f"<li>{html.escape(item)}</li>" for item in blocking_checks)
    status = "ready" if ready else "blocked"
    return f"""
    <section aria-label="Launch readiness">
      <h2>Launch readiness</h2>
      <p>
        Hosted launch is {status}. FuseKit exposes only public readiness codes
        and next actions here; secret values stay out of the page and JSON.
      </p>
      <ul>{body}</ul>
    </section>
"""


def _hosted_readiness_blocking_checks(
    missing: tuple[str, ...],
    invalid: tuple[str, ...],
) -> list[str]:
    return [f"missing:{item}" for item in missing] + [f"invalid:{item}" for item in invalid]


def _hosted_readiness_next_actions(
    missing: tuple[str, ...],
    invalid: tuple[str, ...],
) -> list[str]:
    actions: list[str] = []
    for item in (*missing, *invalid):
        action = HOSTED_READINESS_NEXT_ACTIONS.get(item, f"Resolve hosted readiness check {item}.")
        if action not in actions:
            actions.append(action)
    return actions


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _deployment_provider_label(provider: str) -> str:
    labels = {
        "aws-elastic-beanstalk": "AWS Elastic Beanstalk",
        "oci-compute": "OCI Compute",
        "vercel": "Vercel",
    }
    return labels.get(provider, "the configured hosted runtime")


def _deployment_metadata_label(provider: str) -> str:
    labels = {
        "aws-elastic-beanstalk": "AWS/Git metadata",
        "oci-compute": "OCI/Git metadata",
        "vercel": "Vercel/Git metadata",
    }
    return labels.get(provider, "hosted runtime/Git metadata")


def _cloudflare_record_type_for_provider(provider: str) -> str:
    if provider == "oci-compute":
        return "A"
    return "CNAME"


def _cloudflare_record_value_label(provider: str) -> str:
    if provider == "aws-elastic-beanstalk":
        return "Use the exact AWS-provided CNAME target for this environment."
    if provider == "oci-compute":
        return "Use the exact OCI reserved public IP address for this environment."
    if provider != "vercel":
        return "Use the exact target for the selected hosted deployment provider."
    return "Use the exact Vercel-provided CNAME target for this project."


def _hosted_config_errors(settings: HostedSettings) -> tuple[str, ...]:
    errors: list[str] = []
    if not _valid_public_origin(settings.public_origin):
        errors.append("hosted_origin_must_be_https_origin")
    if settings.worker_dispatch_url and not _valid_https_url(settings.worker_dispatch_url):
        errors.append("hosted_worker_dispatch_url_must_be_https")
    deployment_provider_error = settings.deployment_provider_config_error()
    if deployment_provider_error:
        errors.append(deployment_provider_error)
    if not settings.github_app_id.isdecimal() or int(settings.github_app_id) <= 0:
        errors.append("github_app_id_must_be_positive_integer")
    if not _valid_github_app_slug(settings.github_app_slug):
        errors.append("github_app_slug_is_invalid")
    if not _valid_rsa_private_key(settings.github_private_key_pem):
        errors.append("github_app_private_key_must_be_rsa_pem")
    if len(settings.state_secret) < 16:
        errors.append("hosted_state_secret_too_short")
    if len(settings.worker_secret) < 16:
        errors.append("hosted_worker_secret_too_short")
    if settings.managed_runs_enabled and not settings.stripe_secret_key.startswith("sk_"):
        errors.append("stripe_secret_key_required_for_managed_runs")
    if (
        settings.managed_runs_enabled
        and settings.stripe_secret_key.startswith("sk_")
        and not settings.payment_config().public_dict().get("live_mode_configured")
        and not (
            settings.stripe_test_mode_allowed
            and settings.payment_config().public_dict().get("account_mode") == "test"
        )
    ):
        errors.append("stripe_live_secret_key_required_for_managed_runs")
    if settings.managed_runs_enabled and not settings.stripe_price_id.startswith("price_"):
        errors.append("stripe_price_id_required_for_managed_runs")
    if settings.managed_runs_enabled and not settings.payment_config().public_dict().get(
        "price_label_configured"
    ):
        errors.append("managed_run_price_label_required")
    if settings.source_provenance().get("verified") is not True:
        errors.append("source_provenance_not_verified")
    return tuple(errors)


def _managed_lane_blockers(settings: HostedSettings) -> list[str]:
    blockers: list[str] = []
    if not settings.managed_runs_enabled:
        blockers.append("managed_runs_not_enabled")
    if not settings.stripe_secret_key.startswith("sk_"):
        blockers.append("stripe_secret_key_required_for_managed_runs")
    elif (
        settings.payment_config().public_dict().get("live_mode_configured") is not True
        and not (
            settings.stripe_test_mode_allowed
            and settings.payment_config().public_dict().get("account_mode") == "test"
        )
    ):
        blockers.append("stripe_live_secret_key_required_for_managed_runs")
    if not settings.stripe_price_id.startswith("price_"):
        blockers.append("stripe_price_id_required_for_managed_runs")
    if not settings.payment_config().public_dict().get("price_label_configured"):
        blockers.append("managed_run_price_label_required")
    if not settings.worker_secret:
        blockers.append("FUSEKIT_HOSTED_WORKER_SECRET")
    elif len(settings.worker_secret) < 16:
        blockers.append("hosted_worker_secret_too_short")
    if not settings.worker_dispatch_url:
        blockers.append("FUSEKIT_HOSTED_WORKER_DISPATCH_URL")
    elif not _valid_https_url(settings.worker_dispatch_url):
        blockers.append("hosted_worker_dispatch_url_must_be_https")
    blockers.extend(_shared_lane_blockers(settings))
    return _unique_public_failures(blockers)


def _hosted_lane_readiness(settings: HostedSettings, lane_id: str) -> dict[str, object]:
    lanes = settings.lane_readiness().get("lanes")
    if not isinstance(lanes, dict):
        return {"launchable": False, "blocking_checks": ["lane_readiness_unavailable"]}
    lane = lanes.get(lane_id)
    if not isinstance(lane, dict):
        return {"launchable": False, "blocking_checks": ["lane_readiness_unavailable"]}
    return dict(lane)


def _byo_oci_lane_blockers(settings: HostedSettings) -> list[str]:
    return _unique_public_failures(_shared_lane_blockers(settings))


def _shared_lane_blockers(settings: HostedSettings) -> list[str]:
    blockers: list[str] = []
    configured = {
        "FUSEKIT_HOSTED_ORIGIN": bool(settings.public_origin),
        "FUSEKIT_GITHUB_APP_ID": bool(settings.github_app_id),
        "FUSEKIT_GITHUB_APP_SLUG": bool(settings.github_app_slug),
        "FUSEKIT_GITHUB_APP_PRIVATE_KEY": bool(settings.github_private_key_pem),
        "FUSEKIT_HOSTED_STATE_SECRET": bool(settings.state_secret),
    }
    blockers.extend(key for key, value in configured.items() if not value)
    if not _valid_public_origin(settings.public_origin):
        blockers.append("hosted_origin_must_be_https_origin")
    if not settings.github_app_id.isdecimal() or int(settings.github_app_id) <= 0:
        blockers.append("github_app_id_must_be_positive_integer")
    if not _valid_github_app_slug(settings.github_app_slug):
        blockers.append("github_app_slug_is_invalid")
    if not _valid_rsa_private_key(settings.github_private_key_pem):
        blockers.append("github_app_private_key_must_be_rsa_pem")
    if len(settings.state_secret) < 16:
        blockers.append("hosted_state_secret_too_short")
    if settings.source_provenance().get("verified") is not True:
        blockers.append("source_provenance_not_verified")
    return blockers


def _unique_public_failures(failures: Iterable[str]) -> list[str]:
    result: list[str] = []
    for failure in failures:
        if failure and failure not in result:
            result.append(failure)
    return result


def _worker_authorized(settings: HostedSettings, environ: dict[str, object]) -> bool:
    authorization = str(environ.get("HTTP_AUTHORIZATION", ""))
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return False
    supplied = authorization[len(prefix) :]
    return hmac.compare_digest(supplied, settings.worker_secret)


def _worker_id(environ: dict[str, object]) -> str:
    value = str(environ.get("HTTP_X_FUSEKIT_WORKER_ID", "")).strip()
    return value or "hosted-worker"


def _managed_payment_required(job: HostedLaunchJob) -> bool:
    return job.launch_lane == MANAGED_FUSEKIT_RUN_LANE and job.payment_status != "paid"


def _payment_receipt_matches_job(
    settings: HostedSettings,
    receipt: dict[str, object],
    job: HostedLaunchJob,
) -> bool:
    if not _payment_receipt_is_paid_checkout(receipt):
        return False
    if receipt.get("client_reference_id") != job.job_id:
        return False
    metadata = receipt.get("metadata")
    if not isinstance(metadata, dict):
        return False
    expected = {
        "job_id": job.job_id,
        "lane": job.launch_lane,
        "github_source_hash": _payment_github_source_hash(job.github_source),
        "plan_fingerprint": job.worker_contract.plan_fingerprint,
        "stripe_price_id_hash": _payment_public_hash(settings.stripe_price_id),
        "price_label_hash": _payment_public_hash(settings.managed_run_price_label),
    }
    for key, expected_value in expected.items():
        if metadata.get(key) != expected_value:
            return False
    return True


def _payment_receipt_is_paid_checkout(receipt: dict[str, object]) -> bool:
    session_id = receipt.get("checkout_session_id")
    amount_total = receipt.get("amount_total")
    currency = receipt.get("currency")
    metadata = receipt.get("metadata")
    return (
        receipt.get("schema_version") == HOSTED_PAYMENT_SCHEMA_VERSION
        and receipt.get("provider") == STRIPE_CHECKOUT_PROVIDER
        and receipt.get("mode") == "payment"
        and receipt.get("status") == "complete"
        and receipt.get("payment_status") == "paid"
        and receipt.get("paid") is True
        and isinstance(session_id, str)
        and session_id.startswith("cs_")
        and isinstance(amount_total, int)
        and amount_total > 0
        and isinstance(currency, str)
        and currency.isalpha()
        and len(currency) == 3
        and isinstance(metadata, dict)
        and all(
            isinstance(metadata.get(key), str) and metadata.get(key)
            for key in STRIPE_CHECKOUT_METADATA_KEYS
        )
    )


def _payment_github_source_hash(github_source: str) -> str:
    return _payment_public_hash(github_source)


def _payment_public_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _dispatch_hosted_worker(
    settings: HostedSettings,
    job: HostedLaunchJob,
    *,
    action: str,
    job_token: str,
) -> dict[str, object]:
    """Send a signed non-secret dispatch envelope to the hosted worker service."""

    if not settings.worker_dispatch_url:
        return {
            "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            "action": action,
            "dispatch_binding": _worker_dispatch_binding(settings, job, action=action),
            "dispatched": False,
            "reason": "worker_dispatch_url_not_configured",
        }
    if not _valid_https_url(settings.worker_dispatch_url):
        raise FuseKitError("Hosted worker dispatch URL must be https.")
    payload: dict[str, object] = {
        "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        "action": action,
        "origin": _public_origin_label(settings.public_origin),
        "job_id": job.job_id,
        "job_token": job_token,
        "dispatch_binding": _worker_dispatch_binding(settings, job, action=action),
        "worker_command": [
            "fusekit-hosted-worker",
            "--origin",
            _public_origin_label(settings.public_origin),
            "--job-id",
            job.job_id,
            "--job-token",
            "<signed-public-job-token>",
            "--action",
            action,
        ],
        "worker_request_url": (
            f"{_public_origin_label(settings.public_origin)}/api/hosted/jobs/"
            f"{urllib.parse.quote(job.job_id, safe='')}/worker-request"
        ),
        "secret_boundary": (
            "Dispatch contains a signed public job token only. The worker secret, "
            "GitHub installation token, provider credentials, and vault material stay "
            "inside backend runtime."
        ),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        settings.worker_dispatch_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "FuseKit",
            "X-FuseKit-Dispatch-Signature": _dispatch_signature(settings.worker_secret, body),
            "X-FuseKit-Dispatch-Schema": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        },
    )
    opener = settings.worker_dispatch_opener or urllib.request.urlopen
    with opener(request, timeout=30.0) as response:
        status = int(getattr(response, "status", 200))
    if status >= 400:
        raise FuseKitError(f"Hosted worker dispatch returned HTTP {status}.")
    return {
        "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        "action": action,
        "dispatched": True,
        "dispatch_url": _public_url_label(settings.worker_dispatch_url),
        "dispatch_binding": _worker_dispatch_binding(settings, job, action=action),
        "secret_boundary": (
            "Dispatch receipt omits the job token, worker secret, signature, provider "
            "tokens, and vault material."
        ),
    }


def _worker_dispatch_binding(
    settings: HostedSettings,
    job: HostedLaunchJob,
    *,
    action: str,
) -> dict[str, str]:
    return {
        "job_id": job.job_id,
        "action": action,
        "lane": job.launch_lane,
        "plan_fingerprint": job.worker_contract.plan_fingerprint,
        "payment_status": job.payment_status,
        "price_label_hash": _payment_public_hash(
            job.payment_price_label or settings.managed_run_price_label
        ),
    }


def _dispatch_signature(secret: str, body: bytes) -> str:
    if len(secret) < 16:
        raise FuseKitError("Hosted worker secret is required for dispatch.")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _json_request_body(environ: dict[str, object]) -> dict[str, object]:
    raw = _request_body(environ, allow_empty=True)
    decoded = json.loads(raw.decode("utf-8") if raw else "{}")
    if not isinstance(decoded, dict):
        raise FuseKitError("JSON request body must be an object.")
    return decoded


def _form_request_body(environ: dict[str, object]) -> dict[str, list[str]]:
    content_type = str(environ.get("CONTENT_TYPE", "") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise FuseKitError("Protected controls require form encoding.")
    raw = _request_body(environ, allow_empty=True)
    if not raw:
        return {}
    return urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)


def _request_body(environ: dict[str, object], *, allow_empty: bool) -> bytes:
    try:
        length = int(str(environ.get("CONTENT_LENGTH", "0") or "0"))
    except ValueError as exc:
        raise FuseKitError("Invalid content length.") from exc
    if length < 0:
        raise FuseKitError("Invalid content length.")
    if length == 0 and not allow_empty:
        raise FuseKitError("Missing request body.")
    if length > HOSTED_MAX_POST_BODY_BYTES:
        raise FuseKitError("Request body is too large.")
    body = environ.get("wsgi.input")
    if not hasattr(body, "read"):
        raise FuseKitError("Missing request body.")
    raw = cast(Any, body).read(length)
    if not isinstance(raw, bytes):
        raise FuseKitError("Invalid request body.")
    if len(raw) != length:
        raise FuseKitError("Incomplete request body.")
    return raw


def _hosted_action_origin_allowed(settings: HostedSettings, environ: dict[str, object]) -> bool:
    allowed = {
        _origin_label(HOSTED_CANONICAL_ORIGIN),
        _origin_label(_public_origin_label(settings.public_origin)),
    }
    origin = str(environ.get("HTTP_ORIGIN", "") or "").strip()
    if origin:
        return _origin_label(origin) in allowed
    referer = str(environ.get("HTTP_REFERER", "") or "").strip()
    if referer:
        return _origin_label(referer) in allowed
    return True


def _origin_label(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _public_origin_label(value: str) -> str:
    return value if _valid_public_origin(value) else HOSTED_CANONICAL_ORIGIN


def _github_app_slug_label(value: str) -> str:
    return value if _valid_github_app_slug(value) else "fusekit-launcher"


def _valid_public_origin(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.path.rstrip("/")
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
    )


def valid_hosted_aws_deployment_url(value: object) -> bool:
    if not isinstance(value, str) or not _valid_public_origin(value):
        return False
    parsed = urllib.parse.urlparse(value)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    return hostname.endswith(".elasticbeanstalk.com")


def valid_hosted_oci_deployment_url(value: object) -> bool:
    if not isinstance(value, str) or not _valid_public_origin(value):
        return False
    parsed = urllib.parse.urlparse(value)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    return hostname in {"fusekit.snowmanai.org", "www.fusekit.snowmanai.org"}


def valid_hosted_vercel_deployment_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme:
        if not _valid_public_origin(value):
            return False
        hostname = parsed.hostname or ""
    else:
        if any(marker in value for marker in ("/", "?", "#", "@")):
            return False
        hostname = value
    hostname = hostname.lower().rstrip(".")
    return bool(hostname) and hostname.endswith(".vercel.app")


def _valid_https_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


def _public_url_label(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if not _valid_https_url(value):
        return "https://worker.invalid"
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _worker_dispatch_receiver_base_url(value: str) -> str:
    public_url = _public_url_label(value)
    parsed = urllib.parse.urlparse(public_url)
    path = parsed.path.rstrip("/")
    if path == "/dispatch" or path.endswith("/dispatch"):
        path = path[: -len("/dispatch")]
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _valid_github_app_slug(value: str) -> bool:
    return bool(value) and urllib.parse.quote(value.strip("/"), safe="") == value


def _valid_rsa_private_key(value: str) -> bool:
    try:
        private_key = serialization.load_pem_private_key(
            value.encode("utf-8"),
            password=None,
        )
    except (TypeError, ValueError):
        return False
    return isinstance(private_key, rsa.RSAPrivateKey)


def _render_github_repositories_page(
    *,
    public_origin: str,
    installation_id: int,
    state_token: str,
    repositories: tuple[dict[str, object], ...],
) -> str:
    safe_origin = html.escape(public_origin)
    repo_rows = "\n".join(
        _repository_row(repo, installation_id=installation_id, state_token=state_token)
        for repo in repositories
    )
    if not repo_rows:
        repo_rows = "<li>No selected repositories were returned by GitHub.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FuseKit repository selection</title>
  <style>
    :root {{
      color-scheme: light;
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      --ink: #101820;
      --muted: #536476;
      --line: #cfd9e2;
      --blue: #0077cc;
      --bg: #f6fbff;
      --panel: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    main {{
      width: min(840px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 34px 0 48px;
      display: grid;
      gap: 18px;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(34px, 5vw, 56px); line-height: 1; letter-spacing: 0; }}
    p {{ color: #31465c; line-height: 1.5; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      display: grid;
      gap: 12px;
    }}
    ul {{ margin: 0; padding-left: 20px; color: #2e4256; }}
    li + li {{ margin-top: 8px; }}
    .origin {{
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Choose the repository to scan.</h1>
    <p>
      FuseKit exchanged the GitHub installation through the server-side app key
      and kept the installation token out of this page.
    </p>
    <section aria-label="Selected repositories">
      <h2>GitHub installation {installation_id}</h2>
      <ul>
        {repo_rows}
      </ul>
    </section>
    <section aria-label="Next visible plan">
      <h2>Next</h2>
      <p>
        FuseKit will scan the selected source, detect providers, and show a
        visible launch plan before any provider mutation or DNS change.
      </p>
      <p class="origin">{safe_origin}</p>
    </section>
  </main>
</body>
</html>
"""


def _repository_row(
    repository: dict[str, object],
    *,
    installation_id: int,
    state_token: str,
) -> str:
    full_name = repository.get("full_name")
    if not isinstance(full_name, str) or not full_name:
        full_name = "unknown repository"
    visibility = "private" if repository.get("private") is True else "public"
    if not _safe_repo_slug(full_name):
        return f"<li>{html.escape(full_name)} <span>({visibility})</span></li>"
    plan_url = html.escape(
        "/github/plan?"
        + urllib.parse.urlencode(
            {
                "installation_id": str(installation_id),
                "repo": full_name,
                "state": state_token,
            }
        ),
        quote=True,
    )
    return (
        f'<li><a href="{plan_url}">{html.escape(full_name)}</a> '
        f"<span>({visibility})</span></li>"
    )


def _repository_names(repositories: tuple[dict[str, object], ...]) -> set[str]:
    names: set[str] = set()
    for repository in repositories:
        full_name = repository.get("full_name")
        if isinstance(full_name, str) and _safe_repo_slug(full_name):
            names.add(full_name)
    return names


def _safe_repo_slug(value: str) -> bool:
    try:
        return normalize_github_repo_slug(value) == value
    except FuseKitError:
        return False


def _first_query_value(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key, [])
    return values[0] if values else ""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _response(
    start_response: StartResponse,
    status: HTTPStatus,
    body: dict[str, object],
    *,
    extra_headers: list[tuple[str, str]] | None = None,
) -> Iterable[bytes]:
    payload = json.dumps(body, sort_keys=True).encode("utf-8")
    headers = _headers("application/json; charset=utf-8", len(payload))
    if extra_headers:
        headers.extend(extra_headers)
    start_response(
        f"{status.value} {status.phrase}",
        headers,
    )
    return [payload]


def _html_response(start_response: StartResponse, body: str) -> Iterable[bytes]:
    payload = body.encode("utf-8")
    start_response(
        "200 OK",
        _headers("text/html; charset=utf-8", len(payload)),
    )
    return [payload]


def _redirect_response(start_response: StartResponse, location: str) -> Iterable[bytes]:
    if not location.startswith("https://checkout.stripe.com/"):
        raise FuseKitError("Hosted redirect target is not allowed.")
    headers = _headers("text/plain; charset=utf-8", 0)
    headers.append(("Location", location))
    start_response("303 See Other", headers)
    return [b""]


def _headers(content_type: str, content_length: int) -> list[tuple[str, str]]:
    return [
        ("Content-Type", content_type),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", _content_security_policy()),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Content-Length", str(content_length)),
    ]


def _content_security_policy() -> str:
    return "; ".join(
        (
            "default-src 'none'",
            "base-uri 'none'",
            "connect-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "script-src 'none'",
            "style-src 'unsafe-inline'",
        )
    )


def main() -> int:
    """Run a local hosted-launcher server for deployment smoke checks."""

    host = os.environ.get("FUSEKIT_HOSTED_BIND", "127.0.0.1")
    port = int(os.environ.get("FUSEKIT_HOSTED_PORT", "8080"))
    app = hosted_application(HostedSettings.from_env())
    with make_server(host, port, app) as server:
        print(f"FuseKit hosted launcher listening on http://{host}:{port}")
        server.serve_forever()
    return 0
