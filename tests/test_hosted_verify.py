from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.verify import (
    HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
    verify_hosted_deployment,
)

PUBLIC_DNS_ADDRESSES = ["2606:4700::6810:84e5", "76.76.21.21"]


class FakeResponse:
    def __init__(self, payload: dict[str, object] | str, *, status: int = 200) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload).encode("utf-8")


class SequenceOpener:
    def __init__(
        self,
        payloads: list[dict[str, object] | str | urllib.error.HTTPError],
    ) -> None:
        self.payloads = payloads
        self.requests: list[urllib.request.Request] = []

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        self.requests.append(request)
        assert timeout == 20.0
        payload = self.payloads.pop(0)
        if isinstance(payload, urllib.error.HTTPError):
            raise payload
        return FakeResponse(payload)


def test_verify_hosted_deployment_passes_launcher_and_dispatch_checks() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            _github_intake_contract(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-worker-dispatch-readiness.v1",
                "ready": True,
            },
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        worker_dispatch_url="https://worker.snowmanai.org/dispatch",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    serialized = json.dumps(report)

    assert report["schema_version"] == HOSTED_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
    assert report["ready"] is True
    assert [check["id"] for check in report["checks"]] == [
        "hosted.dns",
        "hosted.home",
        "hosted.health",
        "hosted.readiness",
        "hosted.deployment",
        "hosted.github_intake",
        "worker_dispatch.health",
        "worker_dispatch.readiness",
    ]
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["hosted.dns"]["hostname"] == "fusekit.snowmanai.org"
    assert checks["hosted.dns"]["addresses"] == PUBLIC_DNS_ADDRESSES
    assert report["worker_dispatch_url"] == "https://worker.snowmanai.org/dispatch"
    assert opener.requests[0].full_url == "https://fusekit.snowmanai.org/"
    assert opener.requests[1].full_url == "https://fusekit.snowmanai.org/healthz"
    assert opener.requests[4].full_url == "https://fusekit.snowmanai.org/api/github/intake"
    assert opener.requests[5].full_url == "https://worker.snowmanai.org/healthz"
    assert opener.requests[6].full_url == "https://worker.snowmanai.org/readiness"
    assert "WORKER_SECRET" not in serialized
    assert "signed-public-job-token" not in serialized


def test_verify_hosted_deployment_reports_cloudflare_error_without_claiming_ready() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/",
                403,
                "Forbidden",
                {},
                io.BytesIO(
                    b"""
                    <title>DNS points to prohibited IP | Cloudflare</title>
                    <h1>Error 1000</h1>
                    <span>Ray ID: test-ray-id</span>
                    """
                ),
            ),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.dns"]["status"] == "ok"
    assert checks["hosted.home"]["status"] == "failed"
    assert checks["hosted.home"]["http_status"] == 403
    assert checks["hosted.home"]["failures"] == ["http_error"]
    assert checks["hosted.home"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Vercel-provided target" in checks["hosted.home"]["next_action"]
    assert checks["hosted.readiness"]["failures"] == ["ready_field_not_true"]
    assert "test-ray-id" not in json.dumps(report)


def test_verify_hosted_deployment_rejects_non_origin_or_secret_url() -> None:
    with pytest.raises(FuseKitError, match="hosted_origin_must_be_https_origin"):
        verify_hosted_deployment(origin="https://user:pass@fusekit.snowmanai.org")

    with pytest.raises(FuseKitError, match="worker_dispatch_url_must_be_https"):
        verify_hosted_deployment(
            origin="https://fusekit.snowmanai.org",
            worker_dispatch_url="https://token@worker.snowmanai.org/dispatch",
            dns_resolver=_public_dns_resolver,
        )


def test_verify_hosted_deployment_diagnoses_compact_cloudflare_1000_body() -> None:
    opener = SequenceOpener(
        [
            urllib.error.HTTPError(
                "https://fusekit.snowmanai.org/",
                403,
                "Forbidden",
                {},
                io.BytesIO(b"error code: 1000\n"),
            ),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": False},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert checks["hosted.home"]["diagnosis"] == (
        "cloudflare_error_1000_dns_points_to_prohibited_ip"
    )
    assert "Cloudflare fusekit CNAME" in checks["hosted.home"]["next_action"]


def test_verify_hosted_deployment_requires_runtime_and_dns_contract() -> None:
    contract = _deployment_contract()
    runtime = contract["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "runtime.txt"
    cloudflare_dns = contract["cloudflare_dns"]
    assert isinstance(cloudflare_dns, dict)
    cloudflare_dns["record_type"] = "A"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "runtime_python_version_mismatch" in checks["hosted.deployment"]["failures"]
    assert "cloudflare_record_type_mismatch" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_requires_operator_setup_contract() -> None:
    contract = _deployment_contract()
    operator_setup = contract["operator_setup"]
    assert isinstance(operator_setup, dict)
    operator_setup["target_subdomain"] = "www.snowmanai.org"
    steps = operator_setup["steps"]
    assert isinstance(steps, list)
    steps.pop()
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.deployment"]["status"] == "failed"
    assert "operator_setup_target_subdomain_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "operator_setup_steps_mismatch" in checks["hosted.deployment"]["failures"]


def test_verify_hosted_deployment_requires_public_trust_contract() -> None:
    contract = _deployment_contract()
    contract["trust_story"] = ["open core", "redacted proof"]
    trust_contract = contract["trust_contract"]
    assert isinstance(trust_contract, dict)
    trust_contract.pop("reversible_setup")
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "trust_story_mismatch" in checks["hosted.deployment"]["failures"]
    assert "trust_contract_keys_mismatch" in checks["hosted.deployment"]["failures"]
    assert "trust_contract_reversible_setup_missing" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_capability_vault_boundary() -> None:
    contract = _deployment_contract()
    boundary = contract["capability_vault_boundary"]
    assert isinstance(boundary, dict)
    boundary["raw_secret_policy"] = "Secrets may be copied into generated apps."
    boundary["forbidden_public_material"] = ["debug logs"]
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "capability_vault_boundary_raw_secret_policy_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]
    assert "capability_vault_boundary_forbidden_public_material_mismatch" in checks[
        "hosted.deployment"
    ]["failures"]


def test_verify_hosted_deployment_requires_one_click_contract() -> None:
    contract = _deployment_contract()
    one_click = contract["one_click_launch"]
    assert isinstance(one_click, dict)
    one_click["no_terminal_promise"] = "Download the CLI and paste this command."
    one_click["terminal_required"] = True
    one_click["download_required"] = True
    one_click["launch_path"] = ["Run a terminal command."]
    one_click["completion_requires"] = ["Live URL verification"]
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            contract,
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert "one_click_launch_no_terminal_promise_mismatch" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_terminal_required_not_false" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_download_required_not_false" in checks["hosted.deployment"][
        "failures"
    ]
    assert "one_click_launch_path_mismatch" in checks["hosted.deployment"]["failures"]
    assert "one_click_launch_completion_requires_mismatch" in checks["hosted.deployment"][
        "failures"
    ]


def test_verify_hosted_deployment_requires_github_intake_contract() -> None:
    intake = _github_intake_contract()
    intake["route"] = "oauth-app"
    intake["launch_path"] = ["Download a CLI."]
    open_core = intake["open_core"]
    assert isinstance(open_core, dict)
    open_core["reviewable_entrypoint"] = "server.py"
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            intake,
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.github_intake"]["status"] == "failed"
    assert "github_intake_route_mismatch" in checks["hosted.github_intake"]["failures"]
    assert "github_intake_launch_path_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]
    assert "github_intake_open_core_entrypoint_mismatch" in checks["hosted.github_intake"][
        "failures"
    ]


def test_verify_hosted_deployment_rejects_credential_text_in_public_json() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {
                "schema_version": "fusekit.hosted-readiness.v1",
                "ready": True,
                "debug": "Authorization: Bearer raw-provider-token",
            },
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    serialized = json.dumps(report)

    assert report["ready"] is False
    assert checks["hosted.readiness"]["failures"] == [
        "public_json_contains_credential_text"
    ]
    assert "raw-provider-token" not in serialized
    assert "Authorization" not in serialized


def test_verify_hosted_deployment_requires_trustworthy_homepage() -> None:
    opener = SequenceOpener(
        [
            (
                "<html><body>Download the CLI. token: "
                "github_pat_1234567890abcdefghijklmnop</body></html>"
            ),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=_public_dns_resolver,
    )
    checks = {check["id"]: check for check in report["checks"]}
    serialized = json.dumps(report)

    assert report["ready"] is False
    assert checks["hosted.home"]["status"] == "failed"
    assert "public_text_contains_credential_text" in checks["hosted.home"]["failures"]
    assert "hosted_home_headline_missing" in checks["hosted.home"]["failures"]
    assert "hosted_home_open_core_missing" in checks["hosted.home"]["failures"]
    assert "github_pat_" not in serialized


def test_verify_hosted_deployment_reports_dns_resolution_failure() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=lambda _hostname: [],
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.dns"]["status"] == "failed"
    assert checks["hosted.dns"]["failures"] == ["dns_no_addresses"]
    assert "Cloudflare fusekit CNAME" in checks["hosted.dns"]["next_action"]


def test_verify_hosted_deployment_rejects_private_dns_addresses() -> None:
    opener = SequenceOpener(
        [
            _home_html(),
            {"ok": True},
            {"schema_version": "fusekit.hosted-readiness.v1", "ready": True},
            _deployment_contract(),
            _github_intake_contract(),
        ]
    )

    report = verify_hosted_deployment(
        origin="https://fusekit.snowmanai.org",
        opener=opener,
        dns_resolver=lambda _hostname: ["127.0.0.1"],
    )
    checks = {check["id"]: check for check in report["checks"]}

    assert report["ready"] is False
    assert checks["hosted.dns"]["failures"] == ["dns_non_public_address"]
    assert checks["hosted.dns"]["addresses"] == ["127.0.0.1"]


def _public_dns_resolver(hostname: str) -> list[str]:
    assert hostname == "fusekit.snowmanai.org"
    return PUBLIC_DNS_ADDRESSES


def _home_html() -> str:
    return """
    <html>
      <body>
        <h1>Launch any GitHub app without touching a terminal.</h1>
        <a>Start hosted launch</a>
        <section>Open core https://github.com/xpxpxp-coder/fusekit</section>
        <section>Capability vault boundary</section>
        <section>Raw secrets must never leave the vault runtime.</section>
        <section>What happens after the click</section>
        <section>What you may need to approve</section>
        <section>Hosted deployment contract</section>
      </body>
    </html>
    """


def _deployment_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.hosted-deployment.v1",
        "trust_story": [
            "open core",
            "narrow permissions",
            "visible plan",
            "redacted proof",
            "reversible setup",
        ],
        "trust_contract": {
            "open_core": "Source repository, MIT license, and app.py entrypoint are public.",
            "narrow_permissions": "GitHub App intake starts with contents:read.",
            "visible_plan": "Providers, approved action ids, gates, and artifacts are shown.",
            "redacted_proof": "Public receipts use redacted notes only.",
            "reversible_setup": "Stop, revoke, rollback, and detonation controls exist.",
        },
        "capability_vault_boundary": {
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
            "forbidden_public_material": [
                "provider credentials",
                "GitHub installation tokens",
                "GitHub App private keys",
                "worker secrets",
                "HMAC signatures",
                "vault material",
                "copy-once secret values",
            ],
            "allowed_public_material": [
                "provider names",
                "approved action ids",
                "artifact labels",
                "redacted statuses",
                "public URLs",
                "rollback action summaries",
                "detonation receipt status",
            ],
        },
        "one_click_launch": {
            "public_url": "https://fusekit.snowmanai.org",
            "start_control": "Start hosted launch",
            "no_terminal_promise": (
                "No terminal, local install, download, or copied command is required "
                "in the hosted path."
            ),
            "intake": "github-app",
            "repository_scope": "one selected GitHub repository",
            "github_repository_permission": "contents:read",
            "launch_path": [
                "Visit the hosted FuseKit URL.",
                "Install the FuseKit GitHub App on one selected repository.",
                "Review the visible plan and approved action ids before worker start.",
                "Click Start hosted launch and pass only provider-owned human gates.",
                (
                    "Receive the live URL, redacted proof receipt, rollback metadata, "
                    "and detonation receipt."
                ),
            ],
            "human_gates": [
                "GitHub sign-in, MFA, passkey, SSO, consent, or repository selection",
                (
                    "Provider-owned billing, CAPTCHA, domain ownership, or copy-once "
                    "secret screens"
                ),
                "DNS changes only after FuseKit shows the exact proposed records",
            ],
            "completion_requires": [
                "Live URL verification",
                "Provider verifier results",
                "DNS propagation status",
                "Redacted setup receipt",
                "Redacted audit log",
                "Run Record",
                "Detonation receipt",
                "Live acceptance report",
            ],
            "reversal": [
                "Show rollback metadata before risky changes.",
                "Preserve rollback actions for provider resources FuseKit creates.",
                "Offer stop, revoke access, rollback, and download redacted proof actions.",
            ],
            "terminal_required": False,
            "download_required": False,
        },
        "runtime": {
            "provider": "vercel",
            "entrypoint": "app.py",
            "routing_config": "vercel.json",
            "requirements": "requirements.txt",
            "python_version": ".python-version",
            "application_export": "app",
            "mode": "python-wsgi",
        },
        "cloudflare_dns": {
            "zone": "snowmanai.org",
            "record_name": "fusekit",
            "record_type": "CNAME",
        },
        "open_core": {
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
        "operator_setup": {
            "target_subdomain": "fusekit.snowmanai.org",
            "steps": [
                {"id": "connect_vercel_project"},
                {"id": "attach_custom_domain"},
                {"id": "route_cloudflare_cname"},
                {"id": "verify_public_contracts"},
            ],
        },
    }


def _github_intake_contract() -> dict[str, object]:
    return {
        "provider": "github",
        "route": "github-app",
        "install_url": "https://github.com/apps/fusekit-launcher/installations/new",
        "trust_story": [
            "open core",
            "narrow permissions",
            "visible plan",
            "redacted proof",
            "reversible setup",
        ],
        "no_terminal_promise": (
            "No terminal, local install, download, or copied command is required "
            "in the hosted path."
        ),
        "launch_path": [
            "Visit the hosted FuseKit URL.",
            "Install the FuseKit GitHub App on one selected repository.",
            "Review the visible plan and approved action ids before worker start.",
            "Click Start hosted launch and pass only provider-owned human gates.",
            (
                "Receive the live URL, redacted proof receipt, rollback metadata, "
                "and detonation receipt."
            ),
        ],
        "proof": [
            "Live URL verification",
            "Provider verifier results",
            "DNS propagation status",
            "Redacted setup receipt",
            "Redacted audit log",
            "Run Record",
            "Detonation receipt",
            "Live acceptance report",
        ],
        "reversal": [
            "Show rollback metadata before risky changes.",
            "Preserve rollback actions for provider resources FuseKit creates.",
            "Offer stop, revoke access, rollback, and download redacted proof actions.",
        ],
        "open_core": {
            "source_repository": "https://github.com/xpxpxp-coder/fusekit",
            "license": "MIT",
            "reviewable_entrypoint": "app.py",
        },
    }
