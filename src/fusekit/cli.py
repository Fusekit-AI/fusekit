"""Command line entry point for FuseKit."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
import webbrowser
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fusekit import __version__
from fusekit.audit import AuditLog, Receipt
from fusekit.capabilities.runtime import CapabilityBroker
from fusekit.commands import apply as apply_command
from fusekit.commands import authorize as authorize_command
from fusekit.commands import detonate as detonate_command
from fusekit.commands import launch as launch_command
from fusekit.commands import plan as plan_command
from fusekit.commands import scan as scan_command
from fusekit.commands import verify as verify_command
from fusekit.detonation.cleanup import detonate as detonate_paths
from fusekit.detonation.preflight import (
    run_detonation_preflight,
    verification_report_allows_detonation,
    verification_report_allows_launch_progress,
)
from fusekit.errors import ApprovalRequired, FuseKitError, ProviderError
from fusekit.harness import run_acceptance
from fusekit.llm import LlmConfig, authorize_openclaw_llm, capture_llm_config
from fusekit.manifest import (
    DnsRecord,
    ServiceRequirement,
    SetupManifest,
    load_manifest,
    write_manifest,
)
from fusekit.planner import build_plan
from fusekit.providers.automation import (
    ProviderSetupContext,
    ensure_webhook_secrets,
    run_provider_pack_setup,
)
from fusekit.providers.capability_pack import (
    ProviderCapabilityPack,
    handoff_from_provider_pack,
    load_provider_pack,
    pack_default_path,
    synthesize_provider_pack,
    validate_provider_pack,
    write_provider_pack,
)
from fusekit.providers.handoff import ProviderHandoff, handoff_for
from fusekit.providers.intelligence import (
    IntelligenceLoopResult,
    OpenAiPackDraftSource,
    OpenClawProviderResearch,
    ProviderIntelligenceLoop,
    ProviderResearchSource,
)
from fusekit.providers.vercel import verify_live_url
from fusekit.providers.verification import VerificationResult, verify_provider_pack
from fusekit.rollback import execute_native_rollback, plan_pack_rollback, plan_rollback, start_over
from fusekit.runner import JobState, JobStep, RunnerResolution, resolve_runner
from fusekit.runner.cloud_shell import build_cloud_shell_launch_plan, write_cloud_shell_launcher
from fusekit.runner.control_room import write_control_room
from fusekit.runner.gate_guidance import provider_gate_guidance
from fusekit.runner.gates import GateRecord, GateService
from fusekit.runner.job import JobCheckpoint
from fusekit.runner.oci import (
    OCI_API_KEYS_URL,
    OCI_CONSOLE_URL,
    OCI_SIGNUP_URL,
    OciRunnerPlan,
    authorize_oci_browser_session,
    build_oci_runner_plan,
    capture_oci_api_key_profile,
    capture_oci_session_profile,
    has_vault_oci_profile,
    oci_runtime_status,
    prepare_oci_api_signing_key,
)
from fusekit.runner.oci_live import (
    OciAuth,
    OciProvisioner,
    OciWorkspace,
    latest_workspace_from_vault,
    load_oci_auth_from_vault_or_config,
)
from fusekit.runner.remote import detonate_remote_worker, execute_remote_setup
from fusekit.runner.run_record import write_run_record
from fusekit.runner.run_state import LaunchRunState, update_run_state
from fusekit.runner.server import serve_control_room
from fusekit.runtime import bootstrap_runtime, doctor
from fusekit.runtime.bootstrap import openclaw_state_home
from fusekit.scanner import scan_repo
from fusekit.security import scan_for_secret_leaks
from fusekit.security.url import require_safe_url
from fusekit.source import (
    fetch_github_source_archive,
    is_github_https_source,
    token_from_env,
)
from fusekit.spine import (
    BrowserPlaybookEvent,
    InferredUiAction,
    OpenAiUiNavigator,
    OpenClawBrowserSpine,
    PlaywrightBrowserSpine,
    StaticUiNavigator,
    execute_provider_ui_playbook,
    provider_authorization_playbook,
    provider_handoff_playbook,
    provider_ui_playbook,
    run_inferred_navigation,
)
from fusekit.spine.infer import UiNavigator
from fusekit.vault.bundle import Vault, open_or_create
from fusekit.vault.session import (
    create_vault_session,
    open_vault_with_session,
)
from fusekit.verification_report import VerificationReport


def main(argv: list[str] | None = None) -> int:
    """Run the FuseKit command line interface."""

    parser = _parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    try:
        return int(args.handler(args))
    except FuseKitError as exc:
        print(f"fusekit: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fusekit", description="FuseKit setup worker")
    parser.add_argument("--version", action="version", version=f"FuseKit {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan an app repo and write a setup manifest")
    scan.add_argument("path", type=Path)
    scan.add_argument("-o", "--output", type=Path, default=Path("fusekit.yaml"))
    scan.set_defaults(handler=scan_command.run)

    validate = sub.add_parser("validate", help="validate a setup manifest")
    validate.add_argument("manifest", type=Path)
    validate.set_defaults(handler=_cmd_validate)

    install = sub.add_parser("install", help="install FuseKit setup entrypoint into an app")
    install.add_argument("path", type=Path)
    install.add_argument("-o", "--manifest", type=Path, default=None)
    install.add_argument("--web-launcher", action="store_true")
    install.add_argument("--app-source", default="")
    install.add_argument("--fusekit-package", default="fusekit")
    install.set_defaults(handler=_cmd_install)

    bootstrap = sub.add_parser("bootstrap", help="install FuseKit runtime components")
    bootstrap.add_argument("--check-only", action="store_true")
    bootstrap.add_argument("--openclaw-bin", default="")
    _vault_args(bootstrap)
    _llm_args(bootstrap)
    bootstrap.set_defaults(handler=_cmd_bootstrap)

    doctor_cmd = sub.add_parser("doctor", help="check FuseKit runtime readiness")
    doctor_cmd.add_argument("--openclaw-bin", default="")
    doctor_cmd.set_defaults(handler=_cmd_doctor)

    plan = sub.add_parser("plan", help="print a setup plan")
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--json", action="store_true", dest="as_json")
    plan.set_defaults(handler=plan_command.run)

    authorize = sub.add_parser(
        "authorize",
        help="capture an approved provider token into the vault",
    )
    authorize.add_argument("provider")
    _vault_args(authorize)
    authorize.add_argument("--app", type=Path, default=Path("."))
    authorize.add_argument("--capability-pack", type=Path, default=None)
    authorize.add_argument("--token-env", default="")
    authorize.add_argument(
        "--handoff",
        action="store_true",
        help="open provider signup/token pages for supervised account setup",
    )
    authorize.add_argument(
        "--open-browser",
        action="store_true",
        help="open handoff URLs in the default browser",
    )
    authorize.add_argument(
        "--spine",
        choices=("system", "openclaw", "playwright"),
        default="openclaw",
        help="computer-use spine; OpenClaw is the default, Playwright is an internal fallback",
    )
    authorize.add_argument("--headless-browser", action="store_true")
    authorize.add_argument("--infer-ui", action="store_true")
    authorize.add_argument("--openclaw-profile", default="openclaw")
    authorize.add_argument(
        "--dry-run-spine",
        action="store_true",
        help="show OpenClaw browser actions without running them",
    )
    authorize.add_argument(
        "--capture-stdin",
        action="store_true",
        help=(
            "allow supervised terminal fallback capture when launcher/VM clipboard "
            "Capture is unavailable"
        ),
    )
    authorize.add_argument(
        "--include-project-page",
        action="store_true",
        help="include the provider project creation/import page in the handoff",
    )
    _gate_args(authorize)
    authorize.set_defaults(handler=authorize_command.run)

    provider = sub.add_parser("provider", help="manage provider capability packs")
    provider_sub = provider.add_subparsers(dest="provider_command")
    provider_synthesize = provider_sub.add_parser(
        "synthesize",
        help="synthesize a provider capability pack from app evidence",
    )
    provider_synthesize.add_argument("provider")
    provider_synthesize.add_argument("--app", type=Path, default=Path("."))
    provider_synthesize.add_argument("-o", "--output", type=Path, default=None)
    provider_synthesize.add_argument("--json", action="store_true", dest="as_json")
    provider_synthesize.add_argument(
        "--intelligence",
        choices=("auto", "heuristic", "llm"),
        default="auto",
        help="compile pack with LLM intelligence when available, otherwise heuristic fallback",
    )
    provider_synthesize.add_argument(
        "--research-spine",
        choices=("openclaw", "none"),
        default="openclaw",
        help="browse provider docs/UI through OpenClaw before drafting the pack",
    )
    provider_synthesize.add_argument("--openclaw-profile", default="openclaw")
    provider_synthesize.add_argument("--dry-run-spine", action="store_true")
    _vault_args(provider_synthesize)
    _llm_args(provider_synthesize)
    provider_synthesize.set_defaults(handler=_cmd_provider_synthesize)
    provider_validate = provider_sub.add_parser("validate", help="validate a provider pack")
    provider_validate.add_argument("pack", type=Path)
    provider_validate.set_defaults(handler=_cmd_provider_validate)
    provider_verify = provider_sub.add_parser(
        "verify",
        help="run executable verification recipes from a provider pack",
    )
    provider_verify.add_argument("pack", type=Path)
    _vault_args(provider_verify)
    provider_verify.add_argument("--live-url", default="")
    _verify_retry_args(provider_verify)
    provider_verify.add_argument("--json", action="store_true", dest="as_json")
    provider_verify.set_defaults(handler=_cmd_provider_verify)
    provider_list = provider_sub.add_parser("list", help="list providers inferred for an app")
    provider_list.add_argument("--app", type=Path, default=Path("."))
    provider_list.add_argument("--json", action="store_true", dest="as_json")
    provider_list.set_defaults(handler=_cmd_provider_list)

    source = sub.add_parser("source", help="fetch public or private app source")
    source_sub = source.add_subparsers(dest="source_command")
    source_fetch = source_sub.add_parser(
        "fetch",
        help="download an app repo into the clean-room workspace",
    )
    source_fetch.add_argument("source")
    source_fetch.add_argument("--dest", type=Path, required=True)
    source_fetch.add_argument(
        "--github-auth",
        choices=("auto", "public", "token", "app"),
        default="auto",
        help="private GitHub source lane; auto tries public, then app/PAT authorization",
    )
    source_fetch.add_argument("--github-token-env", default="GITHUB_TOKEN")
    source_fetch.add_argument(
        "--github-app-install-url",
        default="",
        help="FuseKit GitHub App install URL; defaults to FUSEKIT_GITHUB_APP_INSTALL_URL",
    )
    source_fetch.add_argument("--handoff", action="store_true")
    source_fetch.add_argument("--capture-stdin", action="store_true")
    _vault_args(source_fetch)
    _computer_use_args(source_fetch)
    _gate_args(source_fetch)
    _llm_args(source_fetch)
    source_fetch.set_defaults(handler=_cmd_source_fetch)

    acceptance = sub.add_parser("acceptance", help="run launch-readiness acceptance harness")
    acceptance_sub = acceptance.add_subparsers(dest="acceptance_command")
    acceptance_run = acceptance_sub.add_parser(
        "run",
        help="write a redacted acceptance ledger and launch-readiness report",
    )
    acceptance_run.add_argument("path", type=Path)
    acceptance_run.add_argument("--mode", choices=("rehearsal", "live"), default="rehearsal")
    acceptance_run.add_argument("--manifest", type=Path, default=None)
    _vault_args(acceptance_run)
    acceptance_run.add_argument("--receipt", type=Path, default=None)
    acceptance_run.add_argument("--audit-log", type=Path, default=None)
    acceptance_run.add_argument(
        "--remote-artifacts",
        type=Path,
        default=None,
        help="retrieved OCI artifact directory to use as live acceptance evidence",
    )
    acceptance_run.add_argument("--output-dir", type=Path, default=None)
    acceptance_run.add_argument("--json", action="store_true", dest="as_json")
    acceptance_run.set_defaults(handler=_cmd_acceptance_run)

    apply = sub.add_parser("apply", help="configure real providers from a manifest")
    apply.add_argument("manifest", type=Path)
    _vault_args(apply)
    apply.add_argument("--github-repo", default="")
    apply.add_argument("--vercel-project", default="")
    apply.add_argument("--vercel-framework", default="")
    apply.add_argument("--vercel-git-repo-id", default="")
    apply.add_argument("--vercel-git-ref", default="main")
    apply.add_argument("--live-url", default="")
    apply.add_argument("--dns-zone", default="")
    apply.add_argument("--approve-dns", action="store_true")
    apply.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="permit explicit local rehearsals that skip missing real-provider targets",
    )
    apply.add_argument("--secret", action="append", default=[], help="NAME=env:ENV_VAR")
    _verify_retry_args(apply)
    _computer_use_args(apply)
    apply.add_argument("--audit-log", type=Path, default=Path(".fusekit/audit.jsonl"))
    apply.add_argument("--receipt-json", type=Path, default=Path(".fusekit/setup_receipt.json"))
    apply.add_argument("--receipt-md", type=Path, default=Path(".fusekit/setup_receipt.md"))
    apply.add_argument("--rollback-json", type=Path, default=Path(".fusekit/rollback_plan.json"))
    apply.add_argument(
        "--verification-report",
        type=Path,
        default=Path(".fusekit/verification_report.json"),
    )
    apply.set_defaults(handler=apply_command.run)

    setup = sub.add_parser("setup", help="one-command guided real setup for an app")
    _launch_args(setup)
    setup.set_defaults(handler=launch_command.run)

    launch = sub.add_parser("launch", help="launch a vibe-coded app with FuseKit")
    _launch_args(launch)
    launch.set_defaults(handler=launch_command.run)

    verify = sub.add_parser("verify", help="verify a live app URL")
    verify.add_argument("url")
    verify.set_defaults(handler=verify_command.run)

    receipt = sub.add_parser("receipt", help="write a redacted receipt from a manifest and vault")
    receipt.add_argument("manifest", type=Path)
    _vault_args(receipt)
    receipt.add_argument("-o", "--output", type=Path, default=Path(".fusekit/setup_receipt.json"))
    receipt.set_defaults(handler=_cmd_receipt)

    detonate = sub.add_parser("detonate", help="remove plaintext worker state")
    detonate.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path(".fusekit/worker"), Path(".fusekit/tmp")],
    )
    detonate.add_argument("--preserve", action="append", type=Path, default=[])
    detonate.set_defaults(handler=detonate_command.run)

    unlock = sub.add_parser("unlock", help="unlock a vault and print non-secret metadata")
    _vault_args(unlock)
    unlock.add_argument(
        "--session-ttl",
        type=int,
        default=0,
        help="create a short-lived local vault session token for this many seconds",
    )
    unlock.add_argument("--session-file", type=Path, default=None)
    unlock.set_defaults(handler=_cmd_unlock)

    request = sub.add_parser("request", help="make a safe capability request")
    _vault_args(request)
    request.add_argument("--session-token", default="")
    request.add_argument("--session-token-file", type=Path, default=None)
    request.add_argument("--session-file", type=Path, default=None)
    request.add_argument("capability")
    request.set_defaults(handler=_cmd_request)

    control = sub.add_parser("control-room", help="render a local FuseKit control-room UI")
    control.add_argument("--job-state", type=Path, default=Path(".fusekit/job.json"))
    control.add_argument("--output", type=Path, default=Path(".fusekit/control-room.html"))
    control.add_argument("--serve", action="store_true")
    control.add_argument("--host", default="127.0.0.1")
    control.add_argument("--port", type=int, default=8765)
    control.set_defaults(handler=_cmd_control_room)

    launcher = sub.add_parser("launcher", help="write a local OCI Cloud Shell web launcher")
    launcher.add_argument("path", type=Path)
    launcher.add_argument("-o", "--output", type=Path, default=None)
    launcher.add_argument("--app-source", default="")
    launcher.add_argument("--fusekit-package", default="fusekit")
    launcher.add_argument("--github-repo", default="")
    launcher.add_argument("--vercel-project", default="")
    launcher.add_argument("--live-url", default="")
    launcher.add_argument("--dns-zone", default="")
    launcher.add_argument(
        "--oci-region",
        default="auto",
        help="OCI region for the disposable runner VM, e.g. us-ashburn-1",
    )
    launcher.add_argument(
        "--oci-compartment-mode",
        choices=("root",),
        default="root",
        help="where to create runner resources; FuseKit uses the selected root compartment",
    )
    launcher.add_argument(
        "--approve-dns",
        action="store_true",
        help="forward explicit DNS apply approval into the live Cloud Shell launch",
    )
    launcher.add_argument("--verify-attempts", type=int, default=10)
    launcher.add_argument("--verify-retry-seconds", type=float, default=30.0)
    launcher.add_argument("--gate-retry-seconds", type=float, default=300.0)
    launcher.add_argument("--gate-max-attempts", type=int, default=0)
    launcher.add_argument(
        "--infer-ui",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="let FuseKit guide provider UI setup by default",
    )
    launcher.add_argument(
        "--capture-stdin",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "enable secure provider secret capture; launcher runs use VM clipboard "
            "env-named Capture buttons, with terminal prompts only as fallback"
        ),
    )
    launcher.add_argument(
        "--spine",
        choices=("system", "openclaw", "playwright"),
        default="openclaw",
    )
    launcher.add_argument("--openclaw-profile", default="openclaw")
    _visual_session_args(launcher)
    _llm_args(launcher)
    launcher.add_argument("--open-browser", action="store_true")
    launcher.set_defaults(handler=_cmd_launcher)

    leak_scan = sub.add_parser("leak-scan", help="scan a tree for secret-looking plaintext")
    leak_scan.add_argument("path", type=Path)
    leak_scan.add_argument("--json", action="store_true", dest="as_json")
    leak_scan.set_defaults(handler=_cmd_leak_scan)

    rollback = sub.add_parser("rollback", help="plan or execute rollback")
    rollback.add_argument("--receipt", type=Path, default=Path(".fusekit/setup_receipt.json"))
    rollback.add_argument("--pack", type=Path, default=None)
    rollback.add_argument("--execute", action="store_true")
    _vault_args(rollback)
    rollback.set_defaults(handler=_cmd_rollback)

    start = sub.add_parser("start-over", help="remove restartable FuseKit state")
    start.add_argument("path", type=Path, default=Path("."), nargs="?")
    start.set_defaults(handler=_cmd_start_over)

    runner = sub.add_parser("runner", help="manage execution runner lanes")
    runner_sub = runner.add_subparsers(dest="runner_command")
    runner_doctor = runner_sub.add_parser("doctor", help="check runner readiness")
    runner_doctor.add_argument("--oci-config-file", type=Path, default=None)
    runner_doctor.set_defaults(handler=_cmd_runner_doctor)
    runner_authorize = runner_sub.add_parser("authorize", help="authorize a runner lane")
    runner_authorize.add_argument("runner", choices=("oci",))
    _vault_args(runner_authorize)
    _runner_oci_args(runner_authorize)
    runner_authorize.add_argument("--capture-config-stdin", action="store_true")
    runner_authorize.add_argument("--open-browser", action="store_true")
    runner_authorize.add_argument(
        "--spine",
        choices=("system", "openclaw", "playwright"),
        default="openclaw",
    )
    runner_authorize.add_argument("--openclaw-profile", default="openclaw")
    runner_authorize.add_argument("--headless-browser", action="store_true")
    runner_authorize.add_argument("--dry-run-spine", action="store_true")
    runner_authorize.set_defaults(handler=_cmd_runner_authorize)
    runner_plan = runner_sub.add_parser("plan", help="print a runner provisioning plan")
    runner_plan.add_argument("runner", choices=("oci", "oci-cloud-shell"))
    _runner_oci_args(runner_plan)
    runner_plan.add_argument("--json", action="store_true", dest="as_json")
    runner_plan.set_defaults(handler=_cmd_runner_plan)
    runner_provision = runner_sub.add_parser("provision", help="provision a runner workspace")
    runner_provision.add_argument("runner", choices=("oci",))
    _vault_args(runner_provision)
    _runner_oci_args(runner_provision)
    runner_provision.set_defaults(handler=_cmd_runner_provision)
    runner_exec = runner_sub.add_parser("exec", help="execute setup on a runner workspace")
    runner_exec.add_argument("runner", choices=("oci",))
    runner_exec.add_argument("path", type=Path)
    _vault_args(runner_exec)
    _runner_oci_args(runner_exec)
    _visual_session_args(runner_exec)
    runner_exec.set_defaults(handler=_cmd_runner_exec)
    runner_receipt = runner_sub.add_parser("receipt", help="show runner job status")
    runner_receipt.add_argument("--job-state", type=Path, default=Path(".fusekit/job.json"))
    runner_receipt.set_defaults(handler=_cmd_runner_receipt)
    runner_detonate = runner_sub.add_parser("detonate", help="detonate a runner workspace")
    runner_detonate.add_argument("--runner", choices=("oci",), default="oci")
    runner_detonate.add_argument("--scope", choices=("run", "workspace"), default="workspace")
    runner_detonate.add_argument("--job-state", type=Path, default=Path(".fusekit/job.json"))
    _vault_args(runner_detonate)
    runner_detonate.set_defaults(handler=_cmd_runner_detonate)
    return parser


def _vault_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vault", type=Path, default=Path(".fusekit/fusekit.vault.json"))
    parser.add_argument("--passphrase-file", type=Path, default=None)


def _provider_apply_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--github-repo", default="")
    parser.add_argument("--vercel-project", default="")
    parser.add_argument("--vercel-framework", default="")
    parser.add_argument("--vercel-git-repo-id", default="")
    parser.add_argument("--vercel-git-ref", default="main")
    parser.add_argument("--live-url", default="")
    parser.add_argument("--dns-zone", default="")
    parser.add_argument("--approve-dns", action="store_true")
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="permit explicit local rehearsals that skip missing real-provider targets",
    )
    parser.add_argument("--secret", action="append", default=[], help="NAME=env:ENV_VAR")
    _verify_retry_args(parser)
    parser.add_argument("--audit-log", type=Path, default=Path(".fusekit/audit.jsonl"))
    parser.add_argument("--receipt-json", type=Path, default=Path(".fusekit/setup_receipt.json"))
    parser.add_argument("--receipt-md", type=Path, default=Path(".fusekit/setup_receipt.md"))
    parser.add_argument("--rollback-json", type=Path, default=Path(".fusekit/rollback_plan.json"))
    parser.add_argument(
        "--verification-report",
        type=Path,
        default=Path(".fusekit/verification_report.json"),
    )
    _fusekit_gate_arg(parser)
    _gate_args(parser)


def _computer_use_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--spine",
        choices=("system", "openclaw", "playwright"),
        default="openclaw",
    )
    parser.add_argument("--openclaw-profile", default="openclaw")
    parser.add_argument("--headless-browser", action="store_true")
    parser.add_argument("--infer-ui", action="store_true")
    parser.add_argument("--dry-run-spine", action="store_true")
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--repair-ui-steps", type=int, default=12)


def _visual_session_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--visual-runner",
        choices=("auto", "off", "novnc"),
        default="auto",
        help="remote browser viewing surface; auto enables noVNC for OCI control-room launches",
    )


def _verify_retry_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verify-attempts", type=int, default=1)
    parser.add_argument("--verify-retry-seconds", type=float, default=0.0)


def _launch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", type=Path)
    parser.add_argument("--manifest", type=Path, default=None)
    _vault_args(parser)
    _provider_apply_args(parser)
    parser.add_argument(
        "--runner",
        choices=("auto", "local", "oci-cloud-shell", "oci-free", "oci-existing"),
        default="auto",
    )
    parser.add_argument("--app-source", default="")
    parser.add_argument("--fusekit-package", default="fusekit")
    parser.add_argument("--job-state", type=Path, default=Path(".fusekit/job.json"))
    parser.add_argument("--control-room", action="store_true")
    parser.add_argument("--no-open-launcher", action="store_true")
    _visual_session_args(parser)
    _runner_oci_args(parser)
    parser.add_argument("--capture-stdin", action="store_true")
    _computer_use_args(parser)
    parser.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="do not install/check FuseKit runtime components before launch",
    )
    parser.add_argument("--yes", action="store_true", help="approve the displayed setup plan")
    parser.add_argument("--plan-json", type=Path, default=Path(".fusekit/setup_plan.json"))
    _llm_args(parser)
    parser.add_argument(
        "--no-detonate",
        action="store_true",
        help="leave worker scratch state for debugging",
    )


def _llm_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--llm-provider", default="openai")
    parser.add_argument("--llm-model", default="gpt-5.5")
    parser.add_argument("--llm-base-url", default="https://api.openai.com/v1")
    parser.add_argument("--llm-api-key-env", default="OPENAI_API_KEY")
    parser.add_argument(
        "--llm-auth-mode",
        choices=("auto", "api-key", "openclaw"),
        default="auto",
        help="LLM authorization lane; auto falls back to OpenClaw OpenAI auth",
    )
    parser.add_argument(
        "--llm-openclaw-device-code",
        action="store_true",
        help="use OpenClaw's device-code flow for OpenAI auth instead of browser callback",
    )
    parser.add_argument(
        "--capture-llm-key",
        action="store_true",
        help="allow supervised terminal fallback capture for an LLM API key when it is not in env",
    )


def _runner_oci_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--oci-account-mode",
        choices=("auto", "signup", "existing"),
        default="auto",
    )
    parser.add_argument(
        "--oci-auth-mode",
        choices=("auto", "existing-config", "browser-session", "api-key-upload"),
        default="auto",
    )
    parser.add_argument("--oci-region", default="auto")
    parser.add_argument("--oci-shape", default="auto")
    parser.add_argument(
        "--oci-compartment-mode",
        choices=("root",),
        default="root",
        help="where to create runner resources; FuseKit uses the selected root compartment",
    )
    parser.add_argument("--oci-config-file", type=Path, default=None)
    parser.add_argument("--oci-profile", default="FUSEKIT")


def _gate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--gate-retry-seconds",
        type=float,
        default=300.0,
        help="seconds to wait before retrying a human-gate step",
    )
    parser.add_argument(
        "--gate-max-attempts",
        type=int,
        default=0,
        help="maximum human-gate attempts; 0 means wait forever",
    )


def _fusekit_gate_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fusekit-gates",
        choices=("service-only", "explicit"),
        default="service-only",
        help="service-only avoids FuseKit prompt gates; explicit restores plan/DNS prompts",
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    manifest = scan_repo(args.path)
    write_manifest(manifest, args.output)
    pack_paths = _ensure_provider_packs(args.path.resolve(), manifest)
    print(f"Wrote setup manifest: {args.output}")
    for pack_path in pack_paths:
        print(f"Wrote provider capability pack: {pack_path}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    print(f"Valid manifest for {manifest.app_name}")
    return 0


def _cmd_provider_synthesize(args: argparse.Namespace) -> int:
    app_path = args.app.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    pack = synthesize_provider_pack(args.provider, app_path)
    output = args.output or pack_default_path(app_path, pack.provider)
    if args.intelligence == "heuristic":
        write_provider_pack(pack, output)
        result = None
    else:
        result = _run_provider_intelligence(args, app_path, output)
        pack = result.pack
    if args.as_json:
        print(json.dumps(pack.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Wrote provider capability pack: {output}")
    return 0


def _run_provider_intelligence(
    args: argparse.Namespace,
    app_path: Path,
    output: Path,
) -> IntelligenceLoopResult:
    if args.intelligence == "llm":
        vault = Vault.open(args.vault, _passphrase(args))
        source = OpenAiPackDraftSource(_llm_config_from_args(args), vault)
        return ProviderIntelligenceLoop(
            source,
            research_sources=_provider_research_sources(args),
        ).run(
            provider=args.provider,
            app_path=app_path,
            output_path=output,
        )
    if args.vault.exists():
        try:
            vault = Vault.open(args.vault, _passphrase(args))
        except FuseKitError as exc:
            raise FuseKitError(
                "Provider intelligence could not unlock the configured vault; "
                "refusing to downgrade to heuristic synthesis."
            ) from exc
        source = OpenAiPackDraftSource(_llm_config_from_args(args), vault)
        return ProviderIntelligenceLoop(
            source,
            research_sources=_provider_research_sources(args),
        ).run(
            provider=args.provider,
            app_path=app_path,
            output_path=output,
        )
    return ProviderIntelligenceLoop(
        research_sources=_provider_research_sources(args),
    ).run(
        provider=args.provider,
        app_path=app_path,
        output_path=output,
    )


def _provider_research_sources(args: argparse.Namespace) -> tuple[ProviderResearchSource, ...]:
    if getattr(args, "research_spine", "openclaw") == "none":
        return ()
    if not _openclaw_browser_available(args):
        return ()
    return (
        OpenClawProviderResearch(
            OpenClawBrowserSpine(
                profile=getattr(args, "openclaw_profile", "openclaw"),
                dry_run=bool(getattr(args, "dry_run_spine", False)),
            )
        ),
    )


def _use_playwright_browser_spine(args: argparse.Namespace) -> bool:
    """Return true when browser automation should run through Playwright."""

    spine = getattr(args, "spine", "system")
    if spine == "playwright":
        return True
    if spine != "openclaw":
        return False
    if _openclaw_browser_available(args):
        return False
    print("OpenClaw browser commands are unavailable; using Playwright browser spine.")
    return True


def _playwright_headless(args: argparse.Namespace) -> bool:
    """Return whether Playwright should launch headless for this run."""

    if bool(getattr(args, "headless_browser", False)):
        return True
    if getattr(args, "spine", "system") != "openclaw":
        return False
    if _openclaw_browser_available(args):
        return False
    return not bool(os.environ.get("DISPLAY"))


def _openclaw_browser_available(args: argparse.Namespace) -> bool:
    """Return true when OpenClaw exposes browser automation commands."""

    spine = OpenClawBrowserSpine(
        profile=getattr(args, "openclaw_profile", "openclaw"),
        dry_run=bool(getattr(args, "dry_run_spine", False)),
    )
    return spine.browser_command_available()


def _cmd_provider_validate(args: argparse.Namespace) -> int:
    pack = load_provider_pack(args.pack)
    print(f"Valid provider capability pack for {pack.provider}")
    return 0


def _cmd_provider_verify(args: argparse.Namespace) -> int:
    pack = load_provider_pack(args.pack)
    vault = Vault.open(args.vault, _passphrase(args))
    results = verify_provider_pack(
        pack,
        vault,
        live_url=args.live_url,
        attempts=int(getattr(args, "verify_attempts", 1)),
        retry_seconds=float(getattr(args, "verify_retry_seconds", 0.0)),
    )
    payload = {"provider": pack.provider, "results": [result.to_dict() for result in results]}
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            print(f"{result.status:8} {result.kind:12} {result.target}")
    return 0 if all(result.status in {"ok", "skipped"} for result in results) else 1


def _cmd_provider_list(args: argparse.Namespace) -> int:
    manifest = scan_repo(args.app)
    providers = []
    for service in manifest.services:
        pack_path = _provider_pack_path(args.app, service.provider.lower(), service)
        pack = load_provider_pack(pack_path) if pack_path.exists() else synthesize_provider_pack(
            service.provider.lower(),
            args.app,
        )
        providers.append(
            {
                "provider": service.provider,
                "kind": service.kind,
                "capabilities": list(service.capabilities),
                "capability_pack": service.settings.get("capability_pack", ""),
                "account_creation": pack.handoff.account_creation,
                "account_creation_reason": pack.handoff.account_creation_reason,
            }
        )
    if args.as_json:
        print(json.dumps({"providers": providers}, indent=2, sort_keys=True))
    else:
        for provider in providers:
            pack_note = (
                f" pack={provider['capability_pack']}" if provider["capability_pack"] else ""
            )
            account = f" account={provider['account_creation']}"
            print(f"{provider['provider']:16} {provider['kind']}{account}{pack_note}")
    return 0


def _cmd_source_fetch(args: argparse.Namespace) -> int:
    if not is_github_https_source(args.source):
        raise FuseKitError("Private source fetch currently supports GitHub HTTPS repo URLs.")

    if args.github_auth in {"auto", "public"}:
        try:
            result = fetch_github_source_archive(args.source, args.dest)
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return 0
        except FuseKitError:
            if args.github_auth == "public":
                raise

    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    if getattr(args, "infer_ui", False):
        _capture_llm(args, vault, require=True)
        vault.save(args.vault, passphrase)
    token, token_source = _github_source_token(args, vault)
    token_label = "GitHub API token"
    token_record_id = "provider.github.token"
    source_goal = _github_source_auth_goal(args.source, args.github_auth)
    if not token:
        handoff = _github_source_handoff(args)
        if args.handoff or args.open_browser or args.spine in {"openclaw", "playwright"}:
            _run_handoff(args, "github", handoff, include_project=False, goal=source_goal)
        token, token_source = _await_provider_token(
            args,
            "github",
            handoff,
            include_project=False,
            goal=source_goal,
            handoff_presented=bool(
                args.handoff or args.open_browser or args.spine in {"openclaw", "playwright"}
            ),
        )
        token_label = handoff.token_label
        token_record_id = handoff.token_record_id

    result = fetch_github_source_archive(args.source, args.dest, token=token)
    if not token_source.startswith("vault:"):
        vault.put(
            token_record_id,
            "provider_token",
            "github",
            token_label,
            token,
            {"source": token_source, "purpose": "source-and-provider-setup"},
        )
        vault.save(args.vault, passphrase)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


def _github_source_token(args: argparse.Namespace, vault: Vault) -> tuple[str, str]:
    env_token, env_source = token_from_env(
        args.github_token_env,
        "GITHUB_APP_INSTALLATION_TOKEN",
        "GH_TOKEN",
    )
    if env_token:
        return env_token, env_source
    for record_id in (
        "provider.github.token",
        "provider.github.installation_token",
        "provider.github.source_token",
    ):
        try:
            record = vault.require(record_id)
            return record.value, f"vault:{record_id}"
        except FuseKitError:
            continue
    return "", ""


def _github_source_handoff(args: argparse.Namespace) -> ProviderHandoff:
    install_url = args.github_app_install_url or os.environ.get(
        "FUSEKIT_GITHUB_APP_INSTALL_URL",
        "",
    )
    if args.github_auth == "app" and not install_url:
        raise FuseKitError(
            "GitHub App source auth requires --github-app-install-url or "
            "FUSEKIT_GITHUB_APP_INSTALL_URL."
        )
    if install_url:
        return ProviderHandoff(
            provider="github",
            signup_url="https://github.com/login",
            token_url=install_url,
            project_url=install_url,
            token_env="GITHUB_APP_INSTALLATION_TOKEN",
            token_record_id="provider.github.token",
            token_label="GitHub App installation token",
            required_scopes=(
                "Contents read for the selected repository",
                "Actions secrets and deploy keys when setup will configure GitHub",
            ),
            account_steps=(
                (
                    "Click Open provider gate in VM so GitHub opens in the VM browser, "
                    "then sign in."
                ),
                "Install or authorize the FuseKit GitHub App for only the selected repository.",
                (
                    "Complete the highlighted GitHub passkey, MFA, CAPTCHA, organization, "
                    "or consent gate."
                ),
            ),
            secret_steps=(
                (
                    "When GitHub reveals the app-issued installation token or approved access "
                    "token, copy it inside the VM browser."
                ),
                (
                    "Click Capture GITHUB_APP_INSTALLATION_TOKEN from VM clipboard; "
                    "FuseKit stores the token only in the encrypted vault. No paste into "
                    "your computer is needed because Capture reads the VM clipboard directly."
                ),
            ),
        )
    return handoff_for("github")


def _github_source_auth_goal(source: str, auth_mode: str) -> str:
    return (
        "Guide a non-technical user through GitHub approval for FuseKit to read the "
        f"private app repository {source}. Prefer the FuseKit GitHub App installation "
        "flow when the page is available; otherwise guide fine-grained personal access "
        "token creation. Highlight each provider-screen element the human must touch. "
        "The user should only sign in, choose the exact repository, approve GitHub "
        "permissions, pass passkey/MFA/CAPTCHA/org-consent gates, and copy the final "
        "approved token if GitHub reveals one. Do not enter passwords, passkeys, MFA, "
        "CAPTCHA, payment details, or raw tokens into page fields. Use the gate action "
        "with a target when GitHub needs human attention so FuseKit can spotlight it. "
        "Stop once the app/token approval page is complete or the token reveal/copy step "
        f"is waiting. Requested source auth mode: {auth_mode}."
    )


def _cmd_acceptance_run(args: argparse.Namespace) -> int:
    report = run_acceptance(
        args.path,
        mode=args.mode,
        manifest_path=args.manifest,
        vault_path=args.vault,
        passphrase=_optional_passphrase(args),
        receipt_path=args.receipt,
        audit_log_path=args.audit_log,
        remote_artifacts_path=args.remote_artifacts,
        output_dir=args.output_dir,
    )
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Acceptance mode: {report.mode}")
        print(f"Launch ready: {str(report.launch_ready).lower()}")
        print(f"Public launch ready: {str(report.public_launch_ready).lower()}")
        print(f"Report: {report.report_path}")
        print(f"Ledger: {report.ledger_path}")
        for check in report.checks:
            print(f"{check.status:8} {check.id:28} {check.detail}")
        if report.missing:
            print("Missing:")
            for item in report.missing:
                print(f"- {item}")
    return 0 if report.launch_ready else 1


def _cmd_install(args: argparse.Namespace) -> int:
    app_path = args.path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    manifest = scan_repo(app_path)
    manifest_path = (args.manifest or (app_path / "fusekit.yaml")).resolve()
    write_manifest(manifest, manifest_path)
    pack_paths = _ensure_provider_packs(app_path, manifest)
    fusekit_dir = app_path / ".fusekit"
    fusekit_dir.mkdir(parents=True, exist_ok=True)
    setup_script = fusekit_dir / "setup.sh"
    setup_script.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "cd \"$(dirname \"$0\")/..\"\n"
        "exec fusekit launch . --manifest fusekit.yaml \"$@\"\n",
        encoding="utf-8",
    )
    setup_script.chmod(0o700)
    if args.web_launcher:
        launcher_path = fusekit_dir / "launcher.html"
        plan = build_cloud_shell_launch_plan(
            app_source=args.app_source,
            fusekit_package=args.fusekit_package,
        )
        write_cloud_shell_launcher(plan, launcher_path)
    _append_gitignore(app_path / ".gitignore")
    print(f"Wrote manifest: {manifest_path}")
    for pack_path in pack_paths:
        print(f"Wrote provider capability pack: {pack_path}")
    print(f"Wrote one-click setup entrypoint: {setup_script}")
    if args.web_launcher:
        print(f"Wrote local OCI Cloud Shell launcher: {launcher_path}")
    return 0


def _cmd_launcher(args: argparse.Namespace) -> int:
    app_path = args.path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    _apply_magic_defaults(args, scan_repo(app_path), app_path)
    fusekit_dir = app_path / ".fusekit"
    output = args.output or (fusekit_dir / "launcher.html")
    plan = build_cloud_shell_launch_plan(
        app_source=args.app_source,
        fusekit_package=args.fusekit_package,
        launch_args=_cloud_shell_launcher_launch_args(args),
    )
    write_cloud_shell_launcher(plan, output)
    print(json.dumps({"cloud_shell": plan.to_dict(), "launcher": str(output)}, indent=2))
    if args.open_browser:
        webbrowser.open(output.resolve().as_uri())
    return 0


def _cloud_shell_launcher_launch_args(args: argparse.Namespace) -> tuple[str, ...]:
    """Return launch args appropriate for the no-code Cloud Shell launcher."""

    forwarded: list[str] = []
    pairs = (
        ("--github-repo", "github_repo"),
        ("--vercel-project", "vercel_project"),
        ("--live-url", "live_url"),
        ("--dns-zone", "dns_zone"),
        ("--verify-attempts", "verify_attempts"),
        ("--verify-retry-seconds", "verify_retry_seconds"),
        ("--gate-retry-seconds", "gate_retry_seconds"),
        ("--gate-max-attempts", "gate_max_attempts"),
        ("--oci-region", "oci_region"),
        ("--oci-compartment-mode", "oci_compartment_mode"),
        ("--llm-provider", "llm_provider"),
        ("--llm-model", "llm_model"),
        ("--llm-base-url", "llm_base_url"),
        ("--llm-api-key-env", "llm_api_key_env"),
        ("--llm-auth-mode", "llm_auth_mode"),
        ("--spine", "spine"),
        ("--openclaw-profile", "openclaw_profile"),
        ("--fusekit-package", "fusekit_package"),
    )
    for flag, attr in pairs:
        value = getattr(args, attr, "")
        if attr.startswith("oci_") and value == "auto":
            continue
        if value not in {"", None}:
            forwarded.extend([flag, str(value)])
    for flag in (
        "approve_dns",
        "capture_stdin",
        "infer_ui",
        "capture_llm_key",
        "llm_openclaw_device_code",
    ):
        if bool(getattr(args, flag, False)):
            forwarded.append("--" + flag.replace("_", "-"))
    visual_runner = _resolved_cloud_shell_visual_runner(args)
    if visual_runner:
        forwarded.extend(["--visual-runner", visual_runner])
    return tuple(forwarded)


def _cmd_doctor(args: argparse.Namespace) -> int:
    result = doctor(args.openclaw_bin or None)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 1


def _cmd_bootstrap(args: argparse.Namespace) -> int:
    result = bootstrap_runtime(
        install=not args.check_only,
        openclaw_bin=args.openclaw_bin or None,
    )
    if args.check_only:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.ok else 1
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    _capture_llm(args, vault, require=not args.check_only)
    vault.save(args.vault, passphrase)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 1


def _cmd_plan(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    plan = build_plan(manifest)
    if args.as_json:
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        return 0
    for action in plan.actions:
        print(f"{action.kind:17} {action.id:28} {action.summary}")
    return 0


def _cmd_authorize(args: argparse.Namespace) -> int:
    handoff = _handoff_for_provider_args(args, args.provider)
    _authorize_provider(
        args,
        args.provider,
        include_project=args.include_project_page,
        handoff=handoff,
    )
    return 0


def _authorize_provider(
    args: argparse.Namespace,
    provider: str,
    include_project: bool = False,
    handoff: ProviderHandoff | None = None,
) -> None:
    handoff = handoff or handoff_for(provider)
    gate_id = f"provider.{provider}.authorization"
    should_present_handoff = bool(args.handoff and not _gate_record_exists(args, gate_id))
    if should_present_handoff:
        _run_handoff(args, provider, handoff, include_project)

    token, source = _await_provider_token(
        args,
        provider,
        handoff,
        include_project,
        handoff_presented=should_present_handoff,
    )
    if len(token) < 8:
        raise FuseKitError("Provider token is too short to capture.")
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    vault.put(
        handoff.token_record_id,
        "provider_token",
        provider,
        handoff.token_label,
        token,
        {"source": source},
    )
    vault.save(args.vault, passphrase)
    print(f"Captured {provider} authorization into encrypted vault: {args.vault}")


def _cmd_apply(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    _apply_loaded_manifest(args, manifest)
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    app_path = args.path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    _reject_non_live_launch_modes(args)
    _rebase_setup_artifacts(args, app_path)
    runner_resolution = _resolve_launch_runner(args)
    if runner_resolution.selected == "oci-cloud-shell":
        return _cmd_cloud_shell_runner_launch(args, app_path, runner_resolution.selected)
    if runner_resolution.selected != "local":
        return _cmd_cloud_runner_launch(args, app_path, runner_resolution.selected)
    job = _load_or_create_launch_job(args, app_path, "local")
    _mark_run_state(args, app_repo_known=True, runner_selected=True, oci_ready=True)
    for step_id, detail in (
        ("oci.authorize", "local runner selected; OCI authorization is not required"),
        ("oci.provision", "local runner selected; disposable OCI VM is not required"),
        ("remote.bootstrap", "local runner selected; remote bootstrap is not required"),
        ("app.upload", "local runner selected; app stays on this machine"),
    ):
        job.mark(step_id, "skipped", detail)
    job.mark("setup.execute", "running", "scanning app and preparing setup plan")
    _save_launch_job(args, job)
    args._cached_passphrase = _passphrase(args)
    vault = open_or_create(args.vault, args._cached_passphrase)
    try:
        if not args.no_bootstrap:
            result = bootstrap_runtime(install=True)
            print(json.dumps({"bootstrap": result.to_dict()}, indent=2, sort_keys=True))
            if not result.ok:
                raise FuseKitError("FuseKit runtime bootstrap did not complete.")
        _capture_llm(args, vault, require=not args.allow_incomplete)
        vault.save(args.vault, args._cached_passphrase)
        _mark_run_state(args, vault_created=True)
        manifest_path = (args.manifest or (app_path / "fusekit.yaml")).resolve()
        manifest = scan_repo(app_path)
        _apply_magic_defaults(args, manifest, app_path)
        write_manifest(manifest, manifest_path)
        job.add_artifact("manifest", manifest_path)
        pack_paths = _ensure_provider_packs(app_path, manifest)
        print(f"Scanned app and wrote manifest: {manifest_path}")
        for pack_path in pack_paths:
            print(f"Prepared provider capability pack: {pack_path}")
        plan = build_plan(manifest)
        args.plan_json.parent.mkdir(parents=True, exist_ok=True)
        args.plan_json.write_text(
            json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        job.add_artifact("setup_plan", args.plan_json)
        print("Setup plan:")
        for action in plan.actions:
            print(f"{action.kind:17} {action.id:28} {action.summary}")
        print(f"Setup plan artifact: {args.plan_json}")
        if args.fusekit_gates == "explicit" and not args.yes:
            job.mark("setup.execute", "waiting", "setup plan is waiting for explicit approval")
            _save_launch_job(args, job)
            _await_plan_approval(args)
        if not args.allow_incomplete:
            job.mark("setup.execute", "waiting", "provider authorization gates are being checked")
            _save_launch_job(args, job)
            _authorize_required_providers(args, manifest)
        _mark_run_state(args, browser_ready=True, provider_sessions_known=True)
        job.mark("setup.execute", "running", "configuring providers and writing artifacts")
        _save_launch_job(args, job)
        args.manifest = manifest_path
        _apply_loaded_manifest(args, manifest)
        _attach_local_survivor_artifacts(args, job)
        verification_status, verification_detail = _local_verification_job_result(
            args.verification_report
        )
        job.mark("verify.live", verification_status, verification_detail)
        job.mark("setup.execute", "done", "local setup worker completed")
        job.mark("artifacts.retrieve", "done", "encrypted/redacted artifacts were written locally")
        verification_detonation_safe = _verification_report_path_allows_detonation(
            args.verification_report
        )
        if not args.no_detonate and verification_detonation_safe:
            _run_local_detonation_preflight(args, app_path)
            detonation_targets = [app_path / ".fusekit" / "worker", app_path / ".fusekit" / "tmp"]
            if bool(getattr(args, "_detonate_openclaw_state", False)):
                detonation_targets.append(openclaw_state_home())
            removed = detonate_paths(
                detonation_targets,
                preserve=[
                    args.vault,
                    args.audit_log,
                    args.receipt_json,
                    args.receipt_md,
                    args.verification_report,
                    args.rollback_json,
                ],
            )
            job.mark("detonate.workspace", "done", "local worker scratch state detonated")
            print(json.dumps({"detonated": removed}, indent=2, sort_keys=True))
        elif not args.no_detonate:
            job.mark(
                "detonate.workspace",
                "skipped",
                "worker scratch state retained while provider verification waits",
            )
        else:
            job.mark(
                "detonate.workspace",
                "skipped",
                "worker scratch state retained by --no-detonate",
            )
        _save_launch_job(args, job, vault_index=vault.public_index())
        return 0
    except FuseKitError:
        job.mark("setup.execute", "failed", "local setup worker did not complete")
        _save_launch_job(args, job, vault_index=vault.public_index())
        raise


def _reject_non_live_launch_modes(args: argparse.Namespace) -> None:
    if bool(getattr(args, "dry_run_spine", False)) and not bool(
        getattr(args, "allow_incomplete", False)
    ):
        raise FuseKitError(
            "--dry-run-spine is only allowed with --allow-incomplete. "
            "A live launch must use a real browser spine."
        )


def _apply_loaded_manifest(args: argparse.Namespace, manifest: SetupManifest) -> None:
    _apply_magic_defaults(args, manifest, Path(manifest.app_path))
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    audit = AuditLog(args.audit_log)
    receipt = Receipt(app_name=manifest.app_name, vault_path=str(args.vault))
    verification_report = VerificationReport(
        app_name=manifest.app_name,
        live_url=str(getattr(args, "live_url", "")),
    )
    secrets = _runtime_env_secrets(args, manifest, vault)

    try:
        _capture_provider_tokens(vault, manifest)
        _capture_manifest_provider_env(vault, manifest)
        if hasattr(args, "job_state"):
            _mark_run_state(args, vault_created=True, secrets_captured=True)
        context = ProviderSetupContext(
            manifest=manifest,
            vault=vault,
            audit=audit,
            receipt=receipt,
            secrets=secrets,
            provider_names=_required_providers(manifest),
            inputs=_provider_setup_inputs(args),
            approve_dns=bool(args.approve_dns),
            allow_incomplete=bool(args.allow_incomplete),
            fusekit_gates=str(getattr(args, "fusekit_gates", "service-only")),
        )
        ensure_webhook_secrets(manifest, context)
        _run_manifest_provider_pack_setup(args, manifest, context)
        _attach_generated_dns_records(args, context)

        if args.live_url:
            _verify_apply_live_url(args, audit, receipt, verification_report, manifest=manifest)

        _verify_provider_packs(args, manifest, vault, audit, receipt, verification_report)
        provider_checks_ready = verification_report_allows_launch_progress(
            verification_report.to_dict()
        )
        if hasattr(args, "job_state"):
            _mark_run_state(
                args,
                provider_checks_passed_or_pending_safe=provider_checks_ready,
            )
        if not provider_checks_ready and not args.allow_incomplete:
            raise FuseKitError(
                "Verification did not reach a passed or pending-safe state."
            )
    except FuseKitError:
        _write_apply_artifacts(args, passphrase, vault, audit, receipt, verification_report)
        raise

    _write_apply_artifacts(args, passphrase, vault, audit, receipt, verification_report)
    if hasattr(args, "job_state"):
        _mark_run_state(args, receipt_written=True)
    print(f"Apply finished. Redacted receipt: {args.receipt_json}")
    print(f"Verification report: {args.verification_report}")
    print(f"Encrypted vault: {args.vault}")


def _verify_apply_live_url(
    args: argparse.Namespace,
    audit: AuditLog,
    receipt: Receipt,
    verification_report: VerificationReport,
    manifest: SetupManifest | None = None,
) -> None:
    url = str(args.live_url)
    try:
        result = verify_live_url(url)
    except ProviderError as exc:
        pending_safe = (
            bool(getattr(args, "allow_incomplete", False))
            or _has_pending_provider_gate(args)
            or _live_url_waiting_on_dns_approval(args, manifest)
        )
        if not pending_safe:
            raise
        result = {
            "url": url,
            "ok": False,
            "status": "pending",
            "pending_safe": True,
            "error": str(exc),
        }
    receipt.live_url = url
    verification_report.add_live_url(result)
    audit.record("verify.live_url", result)
    receipt.add_action(
        "verify.live_url",
        "ok" if result["ok"] else "pending" if result.get("pending_safe") else "failed",
        result,
    )


def _live_url_waiting_on_dns_approval(
    args: argparse.Namespace,
    manifest: SetupManifest | None,
) -> bool:
    if manifest is None or bool(getattr(args, "approve_dns", False)):
        return False
    hostname = urlparse(str(getattr(args, "live_url", ""))).hostname or ""
    if not hostname:
        return False
    return hostname in {domain.domain for domain in manifest.domains}


def _has_pending_provider_gate(args: argparse.Namespace) -> bool:
    return _pending_provider_gate(args) is not None


def _pending_provider_gate(
    args: argparse.Namespace,
    provider: str = "",
) -> GateRecord | None:
    try:
        records = GateService.load(_gate_state_path(args)).records.values()
    except (OSError, ValueError):
        return None
    provider = provider.lower()
    for record in records:
        if not record.provider or record.provider in {"dns", "oci"}:
            continue
        if provider and record.provider.lower() != provider:
            continue
        if record.status in {"waiting", "resurfaced"}:
            return record
    return None


def _attach_local_survivor_artifacts(args: argparse.Namespace, job: JobState) -> None:
    for name, path in (
        ("vault", args.vault),
        ("audit_log", args.audit_log),
        ("receipt_json", args.receipt_json),
        ("receipt_md", args.receipt_md),
        ("verification_report", args.verification_report),
        ("rollback_plan", args.rollback_json),
        ("provider_strategies", _provider_strategy_artifact_path(Path(args.vault))),
    ):
        if Path(path).exists():
            job.add_artifact(name, Path(path))


def _local_verification_job_result(path: Path) -> tuple[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "skipped", "local rehearsal did not produce a verification report"
    if not isinstance(raw, dict):
        return "failed", "verification report is malformed"
    checks = raw.get("checks", [])
    if verification_report_allows_detonation(raw):
        return "done", "verification is passed or pending-safe"
    if verification_report_allows_launch_progress(raw):
        return "pending", "verification is waiting on provider human gates"
    if isinstance(checks, list) and checks:
        return "failed", "verification report contains failed or blocked checks"
    return "skipped", "local rehearsal did not require live verification"


def _write_apply_artifacts(
    args: argparse.Namespace,
    passphrase: str,
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
    verification_report: VerificationReport,
) -> None:
    vault.save(args.vault, passphrase)
    verification_report.write(args.verification_report)
    audit.record("verification.report", verification_report.to_dict())
    receipt.write_json(args.receipt_json)
    receipt.write_markdown(args.receipt_md)
    rollback_actions = [action.to_dict() for action in plan_rollback(args.receipt_json)]
    args.rollback_json.parent.mkdir(parents=True, exist_ok=True)
    args.rollback_json.write_text(
        json.dumps({"rollback": rollback_actions}, indent=2, sort_keys=True) + "\n",
        "utf-8",
    )


def _run_local_detonation_preflight(args: argparse.Namespace, app_path: Path) -> None:
    if bool(getattr(args, "allow_incomplete", False)):
        return
    result = run_detonation_preflight(
        root=app_path,
        vault=args.vault,
        audit=args.audit_log,
        receipt=args.receipt_json,
        verification_report=args.verification_report,
        rollback_metadata=args.rollback_json,
    )
    if not result.ok:
        raise FuseKitError(
            "Detonation preflight failed: " + "; ".join(result.failures)
        )
    if hasattr(args, "job_state"):
        _mark_run_state(args, detonation_safe=True)


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify_live_url(args.url)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _cmd_receipt(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    vault = Vault.open(args.vault, _passphrase(args))
    receipt = Receipt(app_name=manifest.app_name, vault_path=str(args.vault))
    receipt.add_action("vault.index", "ok", {"records": vault.public_index()})
    receipt.write_json(args.output)
    print(f"Wrote redacted receipt: {args.output}")
    return 0


def _cmd_detonate(args: argparse.Namespace) -> int:
    removed = detonate_paths(args.paths, preserve=args.preserve)
    print(json.dumps({"removed": removed}, indent=2, sort_keys=True))
    return 0


def _cmd_unlock(args: argparse.Namespace) -> int:
    passphrase = _passphrase(args)
    vault = Vault.open(args.vault, passphrase)
    payload: dict[str, object] = {"records": vault.public_index()}
    if int(getattr(args, "session_ttl", 0) or 0) > 0:
        payload["session"] = create_vault_session(
            vault_path=args.vault,
            passphrase=passphrase,
            session_path=getattr(args, "session_file", None),
            ttl_seconds=int(args.session_ttl),
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_request(args: argparse.Namespace) -> int:
    session_token = _session_token_from_args(args)
    if session_token:
        vault = open_vault_with_session(
            vault_path=args.vault,
            session_token=session_token,
            session_path=getattr(args, "session_file", None),
        )
    else:
        vault = Vault.open(args.vault, _passphrase(args))
    response = CapabilityBroker(vault).request(args.capability)
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0


def _session_token_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "session_token", ""):
        return str(args.session_token)
    token_file = getattr(args, "session_token_file", None)
    if isinstance(token_file, Path):
        try:
            return token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise FuseKitError(f"Cannot read vault session token file: {token_file}") from exc
    return ""


def _cmd_control_room(args: argparse.Namespace) -> int:
    if args.serve:
        print(f"Serving FuseKit control room at http://{args.host}:{args.port}")
        serve_control_room(args.job_state, host=args.host, port=args.port)
        return 0
    job = JobState.load(args.job_state)
    write_control_room(job, args.output)
    print(f"Wrote FuseKit control room: {args.output}")
    return 0


def _cmd_leak_scan(args: argparse.Namespace) -> int:
    findings = scan_for_secret_leaks(args.path)
    payload = {"findings": [finding.to_dict() for finding in findings]}
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(f"{finding.path}:{finding.line}: {finding.kind}")
    return 1 if findings else 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    if args.execute:
        vault = Vault.open(args.vault, _passphrase(args))
        actions = execute_native_rollback(args.receipt, vault)
    else:
        actions = plan_pack_rollback(args.pack) if args.pack else plan_rollback(args.receipt)
    print(json.dumps({"rollback": [action.to_dict() for action in actions]}, indent=2))
    return 0


def _cmd_start_over(args: argparse.Namespace) -> int:
    result = start_over(args.path.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_runner_doctor(args: argparse.Namespace) -> int:
    status = {
        "oci": oci_runtime_status(args.oci_config_file),
        "local": {"available": True},
    }
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


def _cmd_runner_authorize(args: argparse.Namespace) -> int:
    if args.runner != "oci":
        raise FuseKitError(f"Unsupported runner authorization: {args.runner}")
    _run_oci_handoff(args)
    if args.oci_auth_mode in {"auto", "browser-session"} and not args.capture_config_stdin:
        config_file = _oci_config_file(args)
        region = _oci_region(args)
        authorize_oci_browser_session(
            config_file=config_file,
            profile=_oci_profile(args),
            region=region,
        )
        passphrase = _passphrase(args)
        vault = open_or_create(args.vault, passphrase)
        capture_oci_session_profile(vault, config_file=config_file, profile=_oci_profile(args))
        vault.save(args.vault, passphrase)
        print(f"Captured OCI browser-session profile into encrypted vault: {args.vault}")
        return 0
    if not args.capture_config_stdin and not args.oci_config_file:
        passphrase = _passphrase(args)
        vault = open_or_create(args.vault, passphrase)
        public_key = prepare_oci_api_signing_key(vault)
        vault.save(args.vault, passphrase)
        print("OCI handoff URLs:")
        for url in (OCI_SIGNUP_URL, OCI_CONSOLE_URL, OCI_API_KEYS_URL):
            print(f"- {url}")
        print("Upload or paste this public OCI API signing key:")
        print(public_key)
        raise ApprovalRequired(
            "OCI authorization requires an approved OCI config snippet. "
            "Rerun with --oci-config-file or --capture-config-stdin after uploading "
            "FuseKit's public API key in OCI."
        )
    config_snippet = _read_oci_config_snippet(args)
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    public_key = capture_oci_api_key_profile(vault, config_snippet=config_snippet)
    vault.save(args.vault, passphrase)
    print("Upload or paste this public OCI API signing key if it is not already approved:")
    print(public_key)
    print(f"Captured OCI runner profile into encrypted vault: {args.vault}")
    return 0


def _cmd_runner_plan(args: argparse.Namespace) -> int:
    plan = build_oci_runner_plan(
        runner=args.runner,
        auth_mode=args.oci_auth_mode,
        account_mode=args.oci_account_mode,
        compartment_mode=args.oci_compartment_mode,
        region=args.oci_region,
        shape=args.oci_shape,
    )
    if args.as_json:
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        return 0
    print(f"Runner: {plan.runner}")
    print(f"Shape: {plan.shape} ({plan.ocpus} OCPU, {plan.memory_gb} GB)")
    print("Resources:")
    for resource in plan.resources:
        print(f"- {resource}")
    print("Human gates:")
    for gate in plan.gates:
        print(f"- {gate}")
    return 0


def _cmd_runner_provision(args: argparse.Namespace) -> int:
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    has_oci_config = bool(oci_runtime_status(args.oci_config_file)["oci_config"])
    if not has_vault_oci_profile(vault) and not has_oci_config:
        raise ApprovalRequired(
            "OCI provisioning requires an existing OCI config or encrypted OCI runner profile. "
            "Run `fusekit runner authorize oci` first."
        )
    plan = build_oci_runner_plan(
        runner=args.runner,
        auth_mode=args.oci_auth_mode,
        account_mode=args.oci_account_mode,
        compartment_mode=args.oci_compartment_mode,
        region=args.oci_region,
        shape=args.oci_shape,
    )
    workspace = _provision_oci_workspace(args, vault, plan)
    vault.save(args.vault, passphrase)
    print(
        json.dumps(
            {
                "oci_runner_plan": plan.to_dict(),
                "workspace": workspace.to_dict(),
                "status": "provisioned",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _cmd_runner_exec(args: argparse.Namespace) -> int:
    app_path = args.path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    workspace = latest_workspace_from_vault(vault)
    job = JobState.create(f"fk-{uuid.uuid4().hex[:12]}", app_path, f"runner:{args.runner}")
    job.mark("runner.resolve", "done", f"{args.runner} selected")
    job.mark("oci.authorize", "done", "OCI profile available")
    job.mark("oci.provision", "done", f"workspace {workspace.id} at {workspace.public_ip}")
    job.mark("remote.bootstrap", "running", "uploading app and running remote setup")
    job.save(app_path / ".fusekit" / "job.json")
    artifacts = execute_remote_setup(
        workspace=workspace,
        vault=vault,
        app_path=app_path,
        local_output_dir=app_path / ".fusekit" / "remote-artifacts",
        passphrase=passphrase,
        launch_args=_remote_launch_args(args),
    )
    job.mark("remote.bootstrap", "done", "remote setup completed")
    job.mark("artifacts.retrieve", "done", artifacts["output_dir"])
    job.save(app_path / ".fusekit" / "job.json")
    print(json.dumps({"workspace": workspace.to_dict(), "artifacts": artifacts}, indent=2))
    return 0


def _cmd_runner_receipt(args: argparse.Namespace) -> int:
    job = JobState.load(args.job_state)
    print(json.dumps(job.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_runner_detonate(args: argparse.Namespace) -> int:
    job = JobState.load(args.job_state) if args.job_state.exists() else None
    remote_deleted: dict[str, str] = {}
    if args.runner == "oci" and args.vault.exists():
        passphrase = _passphrase(args)
        vault = open_or_create(args.vault, passphrase)
        try:
            workspace = latest_workspace_from_vault(vault)
            detonate_remote_worker(workspace=workspace, vault=vault)
            auth = load_oci_auth_from_vault_or_config(vault, config_file=None)
            remote_deleted = OciProvisioner(auth).detonate(workspace)
        except FuseKitError as exc:
            remote_deleted = {"failed.workspace": str(exc)}
    removed = detonate_paths(
        [Path(".fusekit/worker"), Path(".fusekit/tmp")],
        preserve=[Path(".fusekit/fusekit.vault.json"), args.job_state],
    )
    if job is not None:
        if _workspace_detonation_complete(remote_deleted):
            job.mark("detonate.workspace", "done", f"{args.scope} detonation requested")
        else:
            job.mark("detonate.workspace", "failed", f"{args.scope} detonation incomplete")
        _write_workspace_detonation_receipt(
            args,
            job,
            remote_deleted,
            reason=f"manual {args.scope} detonation",
        )
        write_run_record(job, path=args.job_state.with_name("run_record.json"))
        job.save(args.job_state)
    print(
        json.dumps(
            {
                "runner": args.runner,
                "scope": args.scope,
                "removed": removed,
                "remote_deleted": remote_deleted,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if _workspace_detonation_complete(remote_deleted) else 1


def _resolve_launch_runner(args: argparse.Namespace) -> RunnerResolution:
    vault_has_profile = False
    if args.vault.exists():
        try:
            vault_has_profile = has_vault_oci_profile(Vault.open(args.vault, _passphrase(args)))
        except FuseKitError:
            vault_has_profile = False
    resolution = resolve_runner(
        args.runner,
        allow_incomplete=bool(args.allow_incomplete),
        oci_config_file=args.oci_config_file,
        vault_has_oci_profile=vault_has_profile,
    )
    print(json.dumps({"runner": resolution.to_dict()}, indent=2, sort_keys=True))
    return resolution


def _ensure_oci_authorized_for_launch(
    args: argparse.Namespace,
    vault: Vault,
    passphrase: str,
    job: JobState,
) -> None:
    """Inline the OCI service authorization gate into one-command launch."""

    if has_vault_oci_profile(vault):
        job.mark("oci.authorize", "done", "encrypted OCI profile found")
        _save_launch_job(args, job)
        return
    status = oci_runtime_status(args.oci_config_file)
    if status["oci_config"] and args.oci_auth_mode in {"auto", "existing-config"}:
        job.mark("oci.authorize", "done", "existing OCI config detected")
        _save_launch_job(args, job)
        return
    if args.oci_auth_mode == "api-key-upload":
        _await_oci_api_key_upload(args, vault, passphrase, job)
        return
    _await_oci_browser_session(args, vault, passphrase, job)


def _await_oci_browser_session(
    args: argparse.Namespace,
    vault: Vault,
    passphrase: str,
    job: JobState,
) -> None:
    config_file = _oci_config_file(args)
    profile = _oci_profile(args)
    region = _oci_region(args)
    attempt = 0
    while True:
        attempt += 1
        gate_id = "oci.browser-session"
        _record_gate_waiting(
            args,
            gate_id,
            provider="oci",
            reason="OCI signup/login/MFA/account verification",
            resume_url=OCI_CONSOLE_URL,
        )
        job.mark(
            "oci.authorize",
            "waiting",
            "OCI signup/login/MFA/account verification gate is open",
        )
        _save_launch_job(args, job)
        _run_oci_handoff(args)
        try:
            authorize_oci_browser_session(
                config_file=config_file,
                profile=profile,
                region=region,
            )
            capture_oci_session_profile(vault, config_file=config_file, profile=profile)
            vault.save(args.vault, passphrase)
            job.mark("oci.authorize", "done", "OCI browser-session profile captured")
            _save_launch_job(args, job)
            _record_gate_passed(
                args,
                gate_id,
                provider="oci",
                reason="OCI signup/login/MFA/account verification",
                resume_url=OCI_CONSOLE_URL,
            )
            print(f"Captured OCI browser-session profile into encrypted vault: {args.vault}")
            return
        except FuseKitError as exc:
            _ensure_gate_attempt_allowed(args, attempt, "OCI browser-session authorization")
            print(
                "Waiting for OCI service authorization. Complete Oracle signup/login/MFA/"
                "account verification, then FuseKit will reopen the handoff and retry. "
                f"Last result: {exc}"
            )
            _sleep_for_gate(args, gate_id=gate_id)


def _await_oci_api_key_upload(
    args: argparse.Namespace,
    vault: Vault,
    passphrase: str,
    job: JobState,
) -> None:
    public_key = prepare_oci_api_signing_key(vault)
    vault.save(args.vault, passphrase)
    attempt = 0
    while True:
        attempt += 1
        gate_id = "oci.api-key-upload"
        _record_gate_waiting(
            args,
            gate_id,
            provider="oci",
            reason="OCI API public-key upload/config-snippet",
            resume_url=OCI_API_KEYS_URL,
        )
        job.mark(
            "oci.authorize",
            "waiting",
            "OCI API public-key upload/config-snippet gate is open",
        )
        _save_launch_job(args, job)
        _run_oci_handoff(args)
        print("Upload or paste this public OCI API signing key:")
        print(public_key)
        if args.capture_config_stdin or args.oci_config_file:
            config_snippet = _read_oci_config_snippet(args)
            capture_oci_api_key_profile(vault, config_snippet=config_snippet)
            vault.save(args.vault, passphrase)
            job.mark("oci.authorize", "done", "OCI API key profile captured")
            _save_launch_job(args, job)
            _record_gate_passed(
                args,
                gate_id,
                provider="oci",
                reason="OCI API public-key upload/config-snippet",
                resume_url=OCI_API_KEYS_URL,
            )
            return
        _ensure_gate_attempt_allowed(args, attempt, "OCI API key authorization")
        print(
            "Waiting for OCI API key authorization. Complete Oracle's API key gate, "
            "then provide a config snippet when prompted or rerun with an OCI config file."
        )
        _sleep_for_gate(args, gate_id=gate_id)


def _run_oci_handoff(args: argparse.Namespace) -> None:
    if getattr(args, "open_browser", False):
        for url in (OCI_SIGNUP_URL, OCI_CONSOLE_URL, OCI_API_KEYS_URL):
            webbrowser.open(url)
    if _use_playwright_browser_spine(args):
        playwright_spine = PlaywrightBrowserSpine(
            headless=_playwright_headless(args),
            dry_run=getattr(args, "dry_run_spine", False),
        )
        print("Playwright spine events:")
        try:
            playwright_spine.start()
            for url in (OCI_SIGNUP_URL, OCI_CONSOLE_URL, OCI_API_KEYS_URL):
                event = playwright_spine.open(url)
                print(json.dumps(event.to_dict(), sort_keys=True))
                print(json.dumps(playwright_spine.snapshot().to_dict(), sort_keys=True))
        finally:
            playwright_spine.close()
    elif getattr(args, "spine", "system") == "openclaw":
        if not getattr(args, "dry_run_spine", False):
            args._detonate_openclaw_state = True
        openclaw_spine = OpenClawBrowserSpine(
            profile=getattr(args, "openclaw_profile", "openclaw"),
            dry_run=getattr(args, "dry_run_spine", False),
        )
        print("OpenClaw spine events:")
        for url in (OCI_SIGNUP_URL, OCI_CONSOLE_URL, OCI_API_KEYS_URL):
            event = openclaw_spine.open(url)
            print(json.dumps(event.to_dict(), sort_keys=True))


def _oci_config_file(args: argparse.Namespace) -> Path:
    default = Path.home() / ".oci/config"
    return args.oci_config_file or Path(os.environ.get("OCI_CONFIG_FILE", default))


def _oci_region(args: argparse.Namespace) -> str:
    return args.oci_region if args.oci_region != "auto" else "us-ashburn-1"


def _oci_profile(args: argparse.Namespace) -> str:
    return getattr(args, "oci_profile", "FUSEKIT")


def _detonate_openclaw_state_if_requested(args: argparse.Namespace) -> None:
    if getattr(args, "no_detonate", False):
        return
    if not bool(getattr(args, "_detonate_openclaw_state", False)):
        return
    removed = detonate_paths([openclaw_state_home()], preserve=[])
    print(json.dumps({"detonated_openclaw_state": removed}, indent=2, sort_keys=True))


def _save_launch_job(
    args: argparse.Namespace,
    job: JobState,
    *,
    vault_index: list[dict[str, Any]] | None = None,
) -> None:
    """Persist job, checkpoints, and the static control room when requested."""

    args.job_state.parent.mkdir(parents=True, exist_ok=True)
    run_state_path = _run_state_path(args)
    if run_state_path.exists() and job.artifacts.get("run_state") != str(run_state_path):
        job.add_artifact("run_state", run_state_path)
    checkpoints_path = args.job_state.with_name("checkpoints.json")
    if job.artifacts.get("checkpoints") != str(checkpoints_path):
        job.add_artifact("checkpoints", checkpoints_path)
    run_record_path = args.job_state.with_name("run_record.json")
    if job.artifacts.get("run_record") != str(run_record_path):
        job.add_artifact("run_record", run_record_path)
    write_run_record(job, path=run_record_path, vault_index=vault_index)
    if getattr(args, "control_room", False):
        control_path = args.job_state.parent / "control-room.html"
        if job.artifacts.get("control_room") != str(control_path):
            job.add_artifact("control_room", control_path)
        job.save(args.job_state)
        write_control_room(job, control_path)
        return
    job.save(args.job_state)


def _run_state_path(args: argparse.Namespace) -> Path:
    return Path(args.job_state).parent / "run_state.json"


def _mark_run_state(args: argparse.Namespace, **updates: bool) -> LaunchRunState:
    return update_run_state(_run_state_path(args), **updates)


def _load_or_create_launch_job(
    args: argparse.Namespace,
    app_path: Path,
    runner_name: str,
) -> JobState:
    if args.job_state.exists():
        try:
            job = JobState.load(args.job_state)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            job = JobState.create(f"fk-{uuid.uuid4().hex[:12]}", app_path, runner_name)
        else:
            if job.app_path == str(app_path) and job.runner == runner_name and job.status != "done":
                job.mark("runner.resolve", "done", f"{runner_name} selected; resumed from state")
                return job
    job = JobState.create(f"fk-{uuid.uuid4().hex[:12]}", app_path, runner_name)
    job.mark("runner.resolve", "done", f"{runner_name} selected")
    return job


def _cmd_cloud_runner_launch(args: argparse.Namespace, app_path: Path, runner_name: str) -> int:
    _apply_magic_defaults(args, scan_repo(app_path), app_path)
    job = _load_or_create_launch_job(args, app_path, runner_name)
    _mark_run_state(
        args,
        app_repo_known=bool(args.app_source or _infer_app_source(app_path)),
        runner_selected=True,
    )
    if not args.no_bootstrap:
        result = bootstrap_runtime(install=True)
        print(json.dumps({"bootstrap": result.to_dict()}, indent=2, sort_keys=True))
        if not result.ok:
            raise FuseKitError("FuseKit runtime bootstrap did not complete.")
    plan = build_oci_runner_plan(
        runner=runner_name,
        auth_mode=args.oci_auth_mode,
        account_mode=args.oci_account_mode,
        compartment_mode=args.oci_compartment_mode,
        region=args.oci_region,
        shape=args.oci_shape,
        fusekit_package=args.fusekit_package,
    )
    args.job_state.parent.mkdir(parents=True, exist_ok=True)
    plan_path = args.job_state.parent / "runner_plan.json"
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    job.add_artifact("runner_plan", plan_path)
    _save_launch_job(args, job)
    passphrase = _passphrase(args)
    vault = open_or_create(args.vault, passphrase)
    _mark_run_state(args, vault_created=True)
    _ensure_oci_authorized_for_launch(args, vault, passphrase, job)
    workspace = _provision_oci_workspace(args, vault, plan)
    _mark_run_state(args, oci_ready=True)
    vault.save(args.vault, passphrase)
    workspace_path = args.job_state.parent / "oci_workspace.json"
    workspace_path.write_text(
        json.dumps(workspace.to_dict(), indent=2, sort_keys=True) + "\n",
        "utf-8",
    )
    job.mark("oci.provision", "done", f"workspace {workspace.id} at {workspace.public_ip}")
    job.add_artifact("oci_workspace", workspace_path)
    job.mark("remote.bootstrap", "running", "uploading app and running remote setup")
    job.mark("app.upload", "running", "uploading app without excluded secret paths")
    job.mark("setup.execute", "running", "remote FuseKit launch starting")
    _save_launch_job(args, job)
    remote_deleted: dict[str, str] = {}
    try:
        artifacts = execute_remote_setup(
            workspace=workspace,
            vault=vault,
            app_path=app_path,
            local_output_dir=app_path / ".fusekit" / "remote-artifacts",
            passphrase=passphrase,
            launch_args=_remote_launch_args(args),
        )
    except FuseKitError:
        job.mark("remote.bootstrap", "failed", "remote setup did not complete")
        job.mark("setup.execute", "failed", "remote FuseKit launch failed")
        if not args.no_detonate:
            remote_deleted = _detonate_oci_workspace(args, workspace, vault)
            _record_workspace_detonation(
                args,
                job,
                remote_deleted,
                reason="remote setup failure",
                success_detail="workspace detonated after failed remote setup",
                failure_detail="workspace detonation incomplete after failed remote setup",
            )
        else:
            job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
        _save_launch_job(args, job, vault_index=vault.public_index())
        raise
    job.mark("remote.bootstrap", "done", "remote setup completed")
    _mark_run_state(args, browser_ready=True, provider_sessions_known=True)
    job.mark("app.upload", "done", "app uploaded without excluded secret paths")
    job.mark("setup.execute", "done", "remote FuseKit launch completed")
    job.mark("artifacts.retrieve", "done", artifacts["output_dir"])
    verification_report = (
        Path(artifacts["output_dir"]) / ".fusekit" / "verification_report.json"
    )
    provider_checks_safe = False
    provider_checks_ready = False
    if verification_report.exists():
        job.add_artifact("verification_report", verification_report)
        provider_checks_safe = _verification_report_path_allows_detonation(verification_report)
        provider_checks_ready = _verification_report_path_allows_launch_progress(
            verification_report
        )
    rollback_plan = Path(artifacts["output_dir"]) / ".fusekit" / "rollback_plan.json"
    if rollback_plan.exists():
        job.add_artifact("rollback_plan", rollback_plan)
    provider_strategies = (
        Path(artifacts["output_dir"]) / ".fusekit" / "provider_strategies.json"
    )
    if provider_strategies.exists():
        job.add_artifact("provider_strategies", provider_strategies)
    receipt_path = Path(artifacts["output_dir"]) / ".fusekit" / "setup_receipt.json"
    _mark_run_state(
        args,
        secrets_captured=True,
        provider_checks_passed_or_pending_safe=provider_checks_ready,
        receipt_written=receipt_path.exists(),
    )
    if not provider_checks_ready:
        job.mark(
            "verify.live",
            "failed",
            "remote verification did not reach a passed or pending-safe state",
        )
        if not args.no_detonate:
            remote_deleted = _detonate_oci_workspace(args, workspace, vault)
            _record_workspace_detonation(
                args,
                job,
                remote_deleted,
                reason="failed remote verification",
                success_detail="workspace detonated after failed verification",
                failure_detail="workspace detonation incomplete after failed verification",
            )
        else:
            job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
        _save_launch_job(args, job, vault_index=vault.public_index())
        raise FuseKitError(
            "Remote verification did not reach a passed or pending-safe state."
        )
    if provider_checks_safe:
        job.mark("verify.live", "done", "remote verification is passed or pending-safe")
    else:
        job.mark("verify.live", "pending", "remote verification is waiting on provider gates")
    if args.no_detonate:
        job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
    elif not provider_checks_safe:
        job.mark(
            "detonate.workspace",
            "skipped",
            "workspace retained while provider verification waits",
        )
    else:
        _run_remote_detonation_preflight(args, Path(artifacts["output_dir"]))
        _mark_run_state(args, detonation_safe=True)
        remote_deleted = _detonate_oci_workspace(args, workspace, vault)
        detonation_complete = _record_workspace_detonation(
            args,
            job,
            remote_deleted,
            reason="successful launch",
            success_detail="remote worker and OCI workspace detonated",
            failure_detail="OCI workspace detonation incomplete after successful launch",
        )
        if not detonation_complete:
            _save_launch_job(args, job, vault_index=vault.public_index())
            raise FuseKitError(
                "OCI workspace detonation was incomplete; see workspace_detonation.json."
            )
    _save_launch_job(args, job, vault_index=vault.public_index())
    _detonate_openclaw_state_if_requested(args)
    print(
        json.dumps(
            {
                "workspace": workspace.to_dict(),
                "artifacts": artifacts,
                "remote_deleted": remote_deleted,
                "job_state": str(args.job_state),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _verification_report_path_allows_detonation(path: Path) -> bool:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(raw, dict) and verification_report_allows_detonation(raw)


def _verification_report_path_allows_launch_progress(path: Path) -> bool:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(raw, dict) and verification_report_allows_launch_progress(raw)


def _detonate_oci_workspace(
    args: argparse.Namespace,
    workspace: OciWorkspace,
    vault: Vault,
) -> dict[str, str]:
    remote_deleted: dict[str, str] = {}
    try:
        detonate_remote_worker(workspace=workspace, vault=vault)
    except FuseKitError as exc:
        remote_deleted["failed.remote_worker"] = str(exc)
    try:
        remote_deleted.update(
            OciProvisioner(
                load_oci_auth_from_vault_or_config(vault, config_file=args.oci_config_file)
            ).detonate(workspace)
        )
    except FuseKitError as exc:
        remote_deleted["failed.workspace"] = str(exc)
    return remote_deleted


def _record_workspace_detonation(
    args: argparse.Namespace,
    job: JobState,
    remote_deleted: dict[str, str],
    *,
    reason: str,
    success_detail: str,
    failure_detail: str,
) -> bool:
    complete = _workspace_detonation_complete(remote_deleted)
    _write_workspace_detonation_receipt(args, job, remote_deleted, reason=reason)
    if complete:
        _mark_run_state(args, workspace_detonated=True)
        job.mark("detonate.workspace", "done", success_detail)
    else:
        job.mark("detonate.workspace", "failed", failure_detail)
    return complete


def _workspace_detonation_complete(remote_deleted: dict[str, str]) -> bool:
    return not any(key.startswith("failed.") for key in remote_deleted)


def _write_workspace_detonation_receipt(
    args: argparse.Namespace,
    job: JobState,
    remote_deleted: dict[str, str],
    *,
    reason: str,
) -> Path:
    path = Path(args.job_state).parent / "workspace_detonation.json"
    failures = {
        key: _redact_cli_error(str(value))
        for key, value in sorted(remote_deleted.items())
        if key.startswith("failed.")
    }
    payload: dict[str, Any] = {
        "status": "incomplete" if failures else "complete",
        "reason": reason,
        "deleted": sorted(key for key in remote_deleted if not key.startswith("failed.")),
        "failures": failures,
        "updated_at": time.time(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", "utf-8")
    job.add_artifact("workspace_detonation", path)
    return path


def _run_remote_detonation_preflight(args: argparse.Namespace, output_dir: Path) -> None:
    fusekit_dir = output_dir / ".fusekit"
    result = run_detonation_preflight(
        root=output_dir,
        vault=fusekit_dir / "fusekit.vault.json",
        audit=fusekit_dir / "audit.jsonl",
        receipt=fusekit_dir / "setup_receipt.json",
        verification_report=fusekit_dir / "verification_report.json",
        rollback_metadata=fusekit_dir / "rollback_plan.json",
    )
    if not result.ok:
        args.job_state.parent.mkdir(parents=True, exist_ok=True)
        preflight_path = args.job_state.parent / "detonation_preflight.json"
        preflight_path.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            "utf-8",
        )
        raise FuseKitError(
            "Detonation preflight failed: " + "; ".join(result.failures)
        )


def _cmd_cloud_shell_runner_launch(
    args: argparse.Namespace,
    app_path: Path,
    runner_name: str,
) -> int:
    _apply_magic_defaults(args, scan_repo(app_path), app_path)
    job = _load_or_create_launch_job(args, app_path, runner_name)
    args.job_state.parent.mkdir(parents=True, exist_ok=True)
    app_source = args.app_source or _infer_app_source(app_path)
    args.app_source = app_source
    _mark_run_state(args, app_repo_known=bool(app_source), runner_selected=True, oci_ready=False)
    plan = build_cloud_shell_launch_plan(
        app_source=app_source,
        fusekit_package=args.fusekit_package,
        fusekit_gates=args.fusekit_gates,
        launch_args=_drop_forwarded_option(_remote_launch_args(args), "--fusekit-gates", True),
    )
    launcher_path = args.job_state.parent / "launcher.html"
    plan_path = args.job_state.parent / "cloud_shell_plan.json"
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    write_cloud_shell_launcher(plan, launcher_path)
    job.mark("oci.authorize", "waiting", "OCI Cloud Shell service gate is open")
    _mark_run_state(args, provider_sessions_known=True)
    job.add_artifact("cloud_shell_plan", plan_path)
    job.add_artifact("launcher", launcher_path)
    _save_launch_job(args, job)
    if args.open_browser or not getattr(args, "no_open_launcher", False):
        webbrowser.open(plan.deeplink_url)
    print(
        json.dumps(
            {
                "cloud_shell": plan.to_dict(),
                "job_state": str(args.job_state),
                "launcher": str(launcher_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _infer_app_source(app_path: Path) -> str:
    git_config = app_path / ".git" / "config"
    if not git_config.exists():
        return ""
    try:
        for line in git_config.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("url = "):
                return stripped.removeprefix("url = ").strip()
    except OSError:
        return ""
    return ""


def _remote_launch_args(args: argparse.Namespace) -> tuple[str, ...]:
    forwarded: list[str] = []
    pairs = (
        ("--github-repo", "github_repo"),
        ("--vercel-project", "vercel_project"),
        ("--vercel-framework", "vercel_framework"),
        ("--vercel-git-repo-id", "vercel_git_repo_id"),
        ("--vercel-git-ref", "vercel_git_ref"),
        ("--live-url", "live_url"),
        ("--dns-zone", "dns_zone"),
        ("--llm-provider", "llm_provider"),
        ("--llm-model", "llm_model"),
        ("--llm-base-url", "llm_base_url"),
        ("--llm-api-key-env", "llm_api_key_env"),
        ("--llm-auth-mode", "llm_auth_mode"),
        ("--spine", "spine"),
        ("--openclaw-profile", "openclaw_profile"),
        ("--fusekit-gates", "fusekit_gates"),
        ("--gate-retry-seconds", "gate_retry_seconds"),
        ("--gate-max-attempts", "gate_max_attempts"),
        ("--verify-attempts", "verify_attempts"),
        ("--verify-retry-seconds", "verify_retry_seconds"),
        ("--fusekit-package", "fusekit_package"),
        ("--oci-region", "oci_region"),
        ("--oci-shape", "oci_shape"),
        ("--oci-compartment-mode", "oci_compartment_mode"),
    )
    for flag, attr in pairs:
        value = getattr(args, attr, "")
        if attr.startswith("oci_") and value == "auto":
            continue
        if value not in {"", None}:
            forwarded.extend([flag, str(value)])
    for item in getattr(args, "secret", []):
        forwarded.extend(["--secret", str(item)])
    visual_runner = _resolved_remote_visual_runner(args)
    if visual_runner:
        forwarded.extend(["--visual-runner", visual_runner])
    for flag in (
        "approve_dns",
        "allow_incomplete",
        "capture_stdin",
        "infer_ui",
        "headless_browser",
        "dry_run_spine",
        "open_browser",
        "no_bootstrap",
        "no_detonate",
    ):
        if bool(getattr(args, flag, False)):
            forwarded.append("--" + flag.replace("_", "-"))
    return tuple(forwarded)


def _resolved_cloud_shell_visual_runner(args: argparse.Namespace) -> str:
    visual_runner = str(getattr(args, "visual_runner", "auto") or "auto")
    if visual_runner == "auto":
        return "novnc"
    return visual_runner


def _resolved_remote_visual_runner(args: argparse.Namespace) -> str:
    visual_runner = str(getattr(args, "visual_runner", "auto") or "auto")
    if visual_runner != "auto":
        return visual_runner
    runner = str(getattr(args, "runner", "") or "")
    if runner in {"oci-free", "oci-existing"} and bool(getattr(args, "control_room", False)):
        return "novnc"
    return ""


def _drop_forwarded_option(
    args: tuple[str, ...],
    flag: str,
    takes_value: bool,
) -> tuple[str, ...]:
    filtered: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == flag:
            skip_next = takes_value
            continue
        filtered.append(arg)
    return tuple(filtered)


def _read_oci_config_snippet(args: argparse.Namespace) -> str:
    config_file: Path | None = args.oci_config_file
    if config_file:
        return config_file.read_text(encoding="utf-8").strip()
    if args.capture_config_stdin:
        data = sys.stdin.read().strip()
        if data:
            return data
    raise FuseKitError("No OCI config snippet was provided.")


def _provision_oci_workspace(
    args: argparse.Namespace,
    vault: Vault,
    plan: OciRunnerPlan,
) -> OciWorkspace:
    identity_auth = load_oci_auth_from_vault_or_config(vault, config_file=args.oci_config_file)
    auth = _oci_auth_for_plan_region(identity_auth, plan)
    print(
        "FuseKit is provisioning the OCI clean-room VM. "
        "This can take a few minutes; progress will stay visible.",
        file=sys.stderr,
        flush=True,
    )
    return OciProvisioner(
        auth,
        progress=_print_oci_progress,
        identity_auth=identity_auth,
    ).provision(plan, vault)


def _oci_auth_for_plan_region(auth: OciAuth, plan: OciRunnerPlan) -> OciAuth:
    if not plan.region or plan.region == "auto":
        return auth
    config = dict(auth.config)
    config["region"] = plan.region
    return OciAuth(config, auth.signer)


def _print_oci_progress(message: str) -> None:
    print(f"[fusekit:oci] {message}", file=sys.stderr, flush=True)


def _collect_secrets(items: list[str]) -> dict[str, str]:
    secrets: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise FuseKitError("--secret must be NAME=env:ENV_VAR")
        name, source = item.split("=", 1)
        if not source.startswith("env:"):
            raise FuseKitError("--secret values must be env references, not raw plaintext.")
        env_name = source.removeprefix("env:")
        value = os.environ.get(env_name)
        if not value:
            raise FuseKitError(f"{env_name} is not set for secret {name}.")
        secrets[name] = value
    return secrets


def _collect_manifest_env_secrets(manifest: SetupManifest) -> dict[str, str]:
    """Collect detected env secrets from the current environment without printing values."""

    secrets: dict[str, str] = {}
    names = set(_app_env_names_for_verification(manifest, _required_providers(manifest)))
    for name in sorted(names):
        value = os.environ.get(name)
        if value:
            secrets[name] = value
    return secrets


def _runtime_env_secrets(
    args: argparse.Namespace,
    manifest: SetupManifest,
    vault: Vault,
) -> dict[str, str]:
    """Collect runtime env values from derivable inputs, vault, env, and explicit refs."""

    secrets = _derived_runtime_env_secrets(args, manifest)
    secrets.update(_collect_vault_runtime_env_secrets(manifest, vault))
    secrets.update(_collect_manifest_env_secrets(manifest))
    secrets.update(_collect_secrets(getattr(args, "secret", [])))
    return secrets


def _derived_runtime_env_secrets(
    args: argparse.Namespace,
    manifest: SetupManifest,
) -> dict[str, str]:
    names = set(_app_env_names_for_verification(manifest, _required_providers(manifest)))
    live_url = str(getattr(args, "live_url", "")).strip()
    if live_url and "NEXT_PUBLIC_APP_URL" in names:
        return {"NEXT_PUBLIC_APP_URL": live_url}
    return {}


def _collect_vault_runtime_env_secrets(
    manifest: SetupManifest,
    vault: Vault,
) -> dict[str, str]:
    names = set(_app_env_names_for_verification(manifest, _required_providers(manifest)))
    secrets: dict[str, str] = {}
    for name in sorted(names):
        record = _vault_record_for_env_name(vault, name)
        if record is not None:
            secrets[name] = record.value
    return secrets


def _vault_record_for_env_name(vault: Vault, name: str) -> Any:
    wanted = name.upper()
    wanted_suffix = "." + wanted.lower()
    for record in vault.records.values():
        metadata_env = record.metadata.get("env", "").upper()
        if metadata_env == wanted or record.label.upper() == wanted:
            return record
        if record.id.lower().endswith(wanted_suffix):
            return record
    return None


def _required_providers(manifest: SetupManifest) -> set[str]:
    providers = {service.provider.lower() for service in manifest.services}
    if manifest.domains:
        providers.update(domain.provider.lower() for domain in manifest.domains)
    return providers


def _authorize_required_providers(args: argparse.Namespace, manifest: SetupManifest) -> None:
    seen: set[str] = set()
    services_by_provider = {service.provider.lower(): service for service in manifest.services}
    for provider in sorted(_required_providers(manifest)):
        if provider in seen:
            continue
        seen.add(provider)
        service = services_by_provider.get(provider)
        handoff = _handoff_for_service(args, provider, service, Path(manifest.app_path))
        if handoff is None:
            continue
        if _has_provider_token(args.vault, args, handoff):
            continue
        auth_args = argparse.Namespace(**vars(args))
        auth_args.handoff = True
        auth_args.provider = provider
        auth_args.token_env = ""
        auth_args.include_project_page = provider in {"github", "vercel"}
        _authorize_provider(
            auth_args,
            provider,
            include_project=auth_args.include_project_page,
            handoff=handoff,
        )


def _run_handoff(
    args: argparse.Namespace,
    provider: str,
    handoff: ProviderHandoff,
    include_project: bool,
    goal: str = "",
) -> None:
    _print_handoff(handoff, include_project=include_project)
    if _open_handoff_in_shared_visual_browser(args, handoff, include_project):
        print("Opened provider gate in the shared VM browser session.")
        return
    if _use_playwright_browser_spine(args):
        playwright_spine = PlaywrightBrowserSpine(
            headless=_playwright_headless(args),
            dry_run=args.dry_run_spine,
        )
        try:
            if getattr(args, "infer_ui", False):
                vault = open_or_create(args.vault, _passphrase(args))
                events = run_inferred_navigation(
                    provider=provider,
                    goal=goal or _provider_ui_goal(provider, include_project),
                    start_url=handoff.signup_url,
                    spine=playwright_spine,
                    navigator=_ui_navigator_from_vault(args, vault),
                    gate_retry_seconds=float(getattr(args, "gate_retry_seconds", 300.0)),
                    max_gate_attempts=int(getattr(args, "gate_max_attempts", 0)),
                    gate_recorder=_gate_recorder(args),
                    gate_passed=_gate_passed_checker(args),
                    provider_memory_path=_provider_memory_path(args, provider),
                )
            else:
                try:
                    events = execute_provider_ui_playbook(
                        provider_ui_playbook(provider, include_project=include_project),
                        playwright_spine,
                    )
                except FuseKitError:
                    events = provider_handoff_playbook(
                        handoff,
                        playwright_spine,
                        include_project=include_project,
                    )
        finally:
            playwright_spine.close()
        print("Playwright UI events:")
        for event in events:
            print(json.dumps(event.to_dict(), sort_keys=True))
    elif args.spine == "openclaw":
        if not args.dry_run_spine:
            args._detonate_openclaw_state = True
        openclaw_spine = OpenClawBrowserSpine(
            profile=args.openclaw_profile,
            dry_run=args.dry_run_spine,
        )
        if getattr(args, "infer_ui", False):
            vault = open_or_create(args.vault, _passphrase(args))
            events = run_inferred_navigation(
                provider=provider,
                goal=goal or _provider_ui_goal(provider, include_project),
                start_url=handoff.signup_url,
                spine=openclaw_spine,
                navigator=_ui_navigator_from_vault(args, vault),
                gate_retry_seconds=float(getattr(args, "gate_retry_seconds", 300.0)),
                max_gate_attempts=int(getattr(args, "gate_max_attempts", 0)),
                gate_recorder=_gate_recorder(args),
                gate_passed=_gate_passed_checker(args),
                provider_memory_path=_provider_memory_path(args, provider),
            )
        else:
            try:
                events = provider_authorization_playbook(
                    provider,
                    openclaw_spine,
                    include_project=include_project,
                )
            except FuseKitError:
                events = provider_handoff_playbook(
                    handoff,
                    openclaw_spine,
                    include_project=include_project,
                )
        print("OpenClaw spine events:")
        for event in events:
            print(json.dumps(event.to_dict(), sort_keys=True))
    elif args.open_browser:
        for url in handoff.urls(include_project=include_project):
            webbrowser.open(url)


def _open_handoff_in_shared_visual_browser(
    args: argparse.Namespace,
    handoff: ProviderHandoff,
    include_project: bool,
) -> bool:
    if getattr(args, "dry_run_spine", False):
        return False
    if os.environ.get("FUSEKIT_FORCE_PLAYWRIGHT_PROVIDER_SPINE"):
        return False
    display = os.environ.get("FUSEKIT_VISUAL_DISPLAY", "").strip()
    if not display:
        return False
    browser = _visual_chrome_binary()
    if browser is None:
        return False
    profile_dir = _shared_visual_provider_profile(args)
    if profile_dir is None:
        return False
    profile_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "DISPLAY": display}
    opened = False
    for url in handoff.urls(include_project=include_project):
        safe_url = require_safe_url(url, label=f"{handoff.provider} provider gate URL")
        command = [
            str(browser),
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--start-maximized",
            f"--user-data-dir={profile_dir}",
            safe_url,
        ]
        try:
            subprocess.Popen(
                command,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            return opened
        opened = True
    return opened


def _shared_visual_provider_profile(args: argparse.Namespace) -> Path | None:
    configured = os.environ.get("FUSEKIT_PROVIDER_BROWSER_PROFILE", "").strip()
    if configured:
        return Path(configured)
    job_state = getattr(args, "job_state", None)
    if isinstance(job_state, Path):
        return job_state.parent.parent / "visual" / "chrome-provider-profile"
    return None


def _gate_state_path(args: argparse.Namespace) -> Path:
    for attr in ("path", "app"):
        value = getattr(args, attr, None)
        if isinstance(value, Path):
            return value.resolve() / ".fusekit" / "gates.json"
    job_state = getattr(args, "job_state", None)
    if isinstance(job_state, Path):
        return job_state.parent / "gates.json"
    vault = getattr(args, "vault", None)
    if isinstance(vault, Path):
        return vault.parent / "gates.json"
    return Path(".fusekit/gates.json")


def _record_gate_waiting(
    args: argparse.Namespace,
    gate_id: str,
    *,
    provider: str,
    reason: str,
    resume_url: str = "",
    classification: str = "",
    target: str = "",
    follow_steps: tuple[str, ...] = (),
    next_action: str = "",
    resume_hint: str = "",
) -> None:
    GateService.load(_gate_state_path(args)).wait(
        gate_id,
        provider=provider,
        reason=reason,
        resume_url=resume_url,
        classification=classification,
        target=target,
        follow_steps=follow_steps,
        next_action=next_action,
        resume_hint=resume_hint,
    )


def _record_gate_passed(
    args: argparse.Namespace,
    gate_id: str,
    *,
    provider: str,
    reason: str,
    resume_url: str = "",
) -> None:
    service = GateService.load(_gate_state_path(args))
    if gate_id not in service.records:
        service.wait(gate_id, provider=provider, reason=reason, resume_url=resume_url)
    service.pass_gate(gate_id)


def _gate_record_exists(args: argparse.Namespace, gate_id: str) -> bool:
    if not isinstance(getattr(args, "job_state", None), Path):
        return False
    return gate_id in GateService.load(_gate_state_path(args)).records


def _gate_recorder(args: argparse.Namespace) -> Callable[
    [str, str, str, str, str, tuple[str, ...], str],
    str,
]:
    def record(
        gate_id: str,
        provider: str,
        reason: str,
        resume_url: str,
        target: str,
        follow_steps: tuple[str, ...],
        classification: str,
    ) -> str:
        _record_gate_waiting(
            args,
            gate_id,
            provider=provider,
            reason=reason,
            resume_url=resume_url,
            classification=classification,
            target=target,
            follow_steps=follow_steps,
        )
        return gate_id

    return record


def _gate_passed_checker(args: argparse.Namespace) -> Callable[[str], bool]:
    def is_passed(gate_id: str) -> bool:
        service = GateService.load(_gate_state_path(args))
        record = service.records.get(gate_id)
        return bool(record and record.status in {"passed", "resume_requested"})

    return is_passed


def _provider_memory_path(args: argparse.Namespace, provider: str) -> Path:
    base = _gate_state_path(args).parent / "provider-memory"
    safe_provider = re.sub(r"[^a-z0-9_-]+", "-", provider.lower()).strip("-") or "provider"
    return base / f"{safe_provider}.json"


def _provider_ui_goal(provider: str, include_project: bool) -> str:
    goal = (
        f"Create or sign in to {provider}, reach the token/API key setup page, "
        "configure only non-sensitive project/domain settings, and stop at provider "
        "login/MFA/CAPTCHA/payment/consent or secret reveal gates."
    )
    if include_project:
        goal += " Include project/resource creation when it is offered."
    return goal


def _await_provider_token(
    args: argparse.Namespace,
    provider: str,
    handoff: ProviderHandoff,
    include_project: bool,
    goal: str = "",
    handoff_presented: bool = False,
) -> tuple[str, str]:
    token_env = args.token_env or handoff.token_env
    gate_id = f"provider.{provider}.authorization"
    resume_url = handoff.token_url or handoff.signup_url
    attempt = 0
    while True:
        attempt += 1
        should_present_handoff = (
            attempt == 1 and not handoff_presented and not _gate_record_exists(args, gate_id)
        )
        vault_token = _provider_token_from_vault(args, handoff)
        if vault_token:
            _record_gate_passed(
                args,
                gate_id,
                provider=provider,
                reason=f"{provider} login/MFA/CAPTCHA/billing/consent/token creation",
                resume_url=resume_url,
            )
            return vault_token, f"vault:{handoff.token_record_id}"
        token = os.environ.get(token_env)
        source = f"env:{token_env}"
        if not token and args.capture_stdin and sys.stdin.isatty():
            try:
                token = getpass.getpass(f"Paste approved {provider} token: ").strip()
                source = "supervised-hidden-prompt"
            except (EOFError, OSError):
                token = ""
        if token:
            _record_gate_passed(
                args,
                gate_id,
                provider=provider,
                reason=f"{provider} login/MFA/CAPTCHA/billing/consent/token creation",
                resume_url=resume_url,
            )
            return token, source
        _record_gate_waiting(
            args,
            gate_id,
            provider=provider,
            reason=f"{provider} login/MFA/CAPTCHA/billing/consent/token creation",
            resume_url=resume_url,
            classification="provider-authorization",
            target=token_env,
            follow_steps=_provider_authorization_follow_steps(handoff, token_env),
        )
        prelaunch_control_room = _write_source_fetch_control_room(
            args,
            provider=provider,
            gate_id=gate_id,
            target=token_env,
        )
        guidance = provider_gate_guidance(provider)
        print(
            f"Waiting: {guidance.title}. {guidance.reassurance} "
            f"When the provider reveals the approved key, provide {token_env}. "
            "FuseKit will keep checking for captured credentials."
        )
        if prelaunch_control_room is not None:
            prelaunch_job_state = prelaunch_control_room.parent / "source-fetch-job.json"
            serve_command = (
                "fusekit control-room --serve --job-state "
                f"{shlex_quote(str(prelaunch_job_state))}"
            )
            print(
                "Guided source-fetch control room: "
                f"{prelaunch_control_room}. Open this file for exact steps, or run "
                f"{serve_command} for live VM-browser open and Capture controls."
            )
        _ensure_gate_attempt_allowed(args, attempt, f"{provider} authorization")
        if should_present_handoff:
            _run_handoff(args, provider, handoff, include_project, goal=goal)
        _sleep_for_gate(args, gate_id=gate_id)


def _write_source_fetch_control_room(
    args: argparse.Namespace,
    *,
    provider: str,
    gate_id: str,
    target: str = "",
) -> Path | None:
    """Write a guided control room when source fetch pauses before launch exists."""

    if not hasattr(args, "source") or not hasattr(args, "dest"):
        return None
    gate_path = _gate_state_path(args)
    root = gate_path.parent
    job_path = root / "source-fetch-job.json"
    source = str(getattr(args, "source", "") or "the app source")
    dest = Path(args.dest)
    provider_label = {"github": "GitHub"}.get(provider.lower(), provider.title())
    capture_label = (
        f"Capture {target.strip().upper()} from VM clipboard"
        if target.strip()
        else "the exact env-named Capture button"
    )
    detail = (
        f"{provider_label} authorization is required before FuseKit can fetch {source}. "
        "Use the control-room gate below so this prelaunch step stays guided."
    )
    artifacts = {"gates": str(gate_path)}
    vault_path = getattr(args, "vault", None)
    if vault_path:
        artifacts["vault"] = str(vault_path)
    passphrase_file = getattr(args, "passphrase_file", None)
    if passphrase_file:
        artifacts["passphrase_file"] = str(passphrase_file)

    job = JobState(
        id=f"fk-source-{uuid.uuid4().hex[:12]}",
        app_path=str(dest),
        runner="source-fetch",
        status="waiting",
        steps=[
            JobStep(
                "source.fetch",
                "Fetch app source",
                "waiting",
                detail,
            ),
            JobStep(
                "launch.start",
                "Start guided launch",
                "pending",
                (
                    "FuseKit will continue to the full launch control room after the "
                    "source is fetched."
                ),
            ),
        ],
        checkpoints=[
            JobCheckpoint(
                "source.fetch",
                "Fetch app source",
                "waiting",
                detail,
                next_action=(
                    "Click Open provider gate in VM, copy the approved source token "
                    f"inside the VM browser, then click {capture_label}."
                ),
                resume_hint=(
                    "FuseKit will retry the source fetch after the "
                    f"{gate_id} gate is captured or resumed."
                ),
                mascot_state="gate",
            ),
            JobCheckpoint(
                "launch.start",
                "Start guided launch",
                "pending",
                "The full setup worker has not started yet.",
                next_action="Finish source authorization first.",
                resume_hint="The normal launch control room appears after source fetch succeeds.",
            ),
        ],
        artifacts=artifacts,
    )
    control_room_path = root / "control-room.html"
    job.add_artifact("control_room", control_room_path)
    job.save(job_path)
    write_control_room(job, control_room_path)
    return control_room_path


def _provider_authorization_follow_steps(
    handoff: ProviderHandoff,
    token_env: str,
) -> tuple[str, ...]:
    """Return exact control-room steps for first provider authorization."""

    capture_step = (
        f"When the provider reveals {token_env}, copy it inside the VM browser and "
        f"click the Capture {token_env} from VM clipboard button in FuseKit. Do not "
        "paste it into your computer; Capture reads the VM clipboard directly."
    )
    resume_step = "FuseKit resumes automatically after the token is captured into the vault."
    steps = [step for step in (*handoff.account_steps, *handoff.secret_steps) if step.strip()]
    if token_env and capture_step not in steps:
        steps.append(capture_step)
    steps.append(resume_step)
    return tuple(steps)


def _provider_token_from_vault(args: argparse.Namespace, handoff: ProviderHandoff) -> str:
    if not args.vault.exists():
        return ""
    try:
        vault = Vault.open(args.vault, _passphrase(args))
        return vault.require(handoff.token_record_id).value
    except FuseKitError:
        return ""


def _await_plan_approval(args: argparse.Namespace) -> None:
    gate_id = "fusekit.plan-approval"
    attempt = 0
    while True:
        attempt += 1
        if _gate_resume_requested(args, gate_id):
            _record_gate_passed(
                args,
                gate_id,
                provider="fusekit",
                reason="explicit FuseKit setup-plan approval",
            )
            return
        try:
            answer = input("Approve this setup plan and continue? [y/N] ").strip().lower()
        except (EOFError, OSError):
            answer = ""
        if answer in {"y", "yes"}:
            _record_gate_passed(
                args,
                gate_id,
                provider="fusekit",
                reason="explicit FuseKit setup-plan approval",
            )
            return
        _record_gate_waiting(
            args,
            gate_id,
            provider="fusekit",
            reason="explicit FuseKit setup-plan approval",
            classification="setup-approval",
            follow_steps=(
                "Review the setup plan shown by FuseKit.",
                "Confirm it names only the app, repo, domain, and provider resources you expect.",
                "Click Approve setup plan to continue.",
            ),
            next_action="Approve the setup plan in the control room to continue.",
            resume_hint="FuseKit will continue immediately after this approval is recorded.",
        )
        _ensure_gate_attempt_allowed(args, attempt, "setup plan approval")
        print("Waiting for setup plan approval. FuseKit will keep this launch alive.")
        _sleep_for_gate(args, gate_id=gate_id)


def _await_dns_approval(
    args: argparse.Namespace,
    domain: str,
    *,
    manifest: SetupManifest | None = None,
    context: ProviderSetupContext | None = None,
) -> None:
    gate_id = f"dns.{domain}.approval"
    attempt = 0
    while True:
        attempt += 1
        if _gate_resume_requested(args, gate_id):
            args.approve_dns = True
            _record_gate_passed(
                args,
                gate_id,
                provider="dns",
                reason=f"explicit DNS apply approval for {domain}",
            )
            return
        if not bool(getattr(args, "control_room", False)):
            try:
                answer = input(f"Approve DNS apply for {domain}? [y/N] ").strip().lower()
            except (EOFError, OSError):
                answer = ""
            if answer in {"y", "yes"}:
                args.approve_dns = True
                _record_gate_passed(
                    args,
                    gate_id,
                    provider="dns",
                    reason=f"explicit DNS apply approval for {domain}",
                )
                return
        _record_gate_waiting(
            args,
            gate_id,
            provider="dns",
            reason=f"explicit DNS apply approval for {domain}",
            classification="dns-approval",
            follow_steps=_dns_approval_follow_steps(domain, manifest=manifest, context=context),
            next_action=_dns_approval_next_action(domain, manifest=manifest, context=context),
            resume_hint=(
                "FuseKit will apply the approved app and provider-generated DNS records "
                "through the DNS provider API and keep verifying propagation."
            ),
        )
        _ensure_gate_attempt_allowed(args, attempt, f"DNS approval for {domain}")
        print(f"Waiting for DNS approval for {domain}. FuseKit will retry this gate.")
        _sleep_for_gate(args, gate_id=gate_id)


def _dns_approval_follow_steps(
    domain: str,
    *,
    manifest: SetupManifest | None = None,
    context: ProviderSetupContext | None = None,
) -> tuple[str, ...]:
    steps = [
        f"Review the DNS plan for {domain} in the control room.",
        "Approve only records that match the app, Resend, Vercel, and domain named by FuseKit.",
        "Click Approve DNS apply; FuseKit will apply the records and verify propagation.",
    ]
    steps.extend(_dns_approval_record_steps(domain, manifest=manifest, context=context))
    return tuple(steps)


def _dns_approval_next_action(
    domain: str,
    *,
    manifest: SetupManifest | None = None,
    context: ProviderSetupContext | None = None,
) -> str:
    count = len(_dns_approval_records(domain, manifest=manifest, context=context))
    if count:
        return f"Approve applying {count} DNS record(s) for {domain}."
    return f"Approve applying the DNS records for {domain}."


def _dns_approval_record_steps(
    domain: str,
    *,
    manifest: SetupManifest | None,
    context: ProviderSetupContext | None,
) -> tuple[str, ...]:
    app_records = _dns_approval_records(
        domain,
        manifest=manifest,
        context=context,
        generated=False,
    )
    generated_records = _dns_approval_records(
        domain,
        manifest=manifest,
        context=context,
        app=False,
    )
    steps: list[str] = []
    if app_records:
        steps.append(
            "App DNS records: "
            + "; ".join(_dns_record_summary(record) for record in app_records)
            + "."
        )
    if generated_records:
        steps.append(
            "Provider-generated DNS records from Resend/API setup: "
            + "; ".join(_dns_record_summary(record) for record in generated_records)
            + "."
        )
    return tuple(steps)


def _dns_approval_records(
    domain: str,
    *,
    manifest: SetupManifest | None,
    context: ProviderSetupContext | None,
    app: bool = True,
    generated: bool = True,
) -> tuple[DnsRecord, ...]:
    records: list[DnsRecord] = []
    if app and manifest is not None:
        for requirement in manifest.domains:
            if requirement.domain == domain:
                records.extend(requirement.records)
    if generated and context is not None:
        records.extend(context.generated_dns_records.get(domain, ()))
    return tuple(records)


def _dns_record_summary(record: DnsRecord) -> str:
    priority = f" priority {record.priority}" if record.priority is not None else ""
    return f"{record.type} {record.name} -> {record.value}{priority}"


def _ensure_gate_attempt_allowed(args: argparse.Namespace, attempt: int, label: str) -> None:
    max_attempts = int(getattr(args, "gate_max_attempts", 0))
    if max_attempts and attempt >= max_attempts:
        raise ApprovalRequired(f"{label} was not passed after {attempt} attempt(s).")


def _sleep_for_gate(args: argparse.Namespace, *, gate_id: str = "") -> None:
    retry_seconds = float(getattr(args, "gate_retry_seconds", 300.0))
    if retry_seconds <= 0:
        return
    deadline = time.monotonic() + retry_seconds
    while True:
        if gate_id and _gate_resume_requested(args, gate_id):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def _gate_resume_requested(args: argparse.Namespace, gate_id: str) -> bool:
    service = GateService.load(_gate_state_path(args))
    record = service.records.get(gate_id)
    return bool(record and record.status in {"passed", "resume_requested"})


def _has_provider_token(
    vault_path: Path,
    args: argparse.Namespace,
    handoff: ProviderHandoff,
) -> bool:
    if os.environ.get(handoff.token_env):
        return True
    if not vault_path.exists():
        return False
    try:
        vault = Vault.open(vault_path, _passphrase(args))
        vault.require(handoff.token_record_id)
    except FuseKitError:
        return False
    return True


def _handoff_for_provider_args(args: argparse.Namespace, provider: str) -> ProviderHandoff:
    if args.capability_pack:
        return handoff_from_provider_pack(load_provider_pack(args.capability_pack))
    try:
        return handoff_for(provider)
    except FuseKitError:
        app_path = args.app.resolve()
        pack_path = pack_default_path(app_path, provider)
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        return handoff_from_provider_pack(load_provider_pack(pack_path))


def _handoff_for_service(
    args: argparse.Namespace,
    provider: str,
    service: ServiceRequirement | None,
    app_path: Path,
) -> ProviderHandoff | None:
    if service is None:
        try:
            return handoff_for(provider)
        except FuseKitError:
            return None
    provider = service.provider.lower()
    try:
        return handoff_for(provider)
    except FuseKitError:
        pack_hint = str(service.settings.get("capability_pack", ""))
        if not pack_hint:
            return None
        pack_path = Path(pack_hint)
        if not pack_path.is_absolute():
            pack_path = app_path / pack_path
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        return handoff_from_provider_pack(load_provider_pack(pack_path))


def _ensure_provider_packs(app_path: Path, manifest: SetupManifest) -> list[Path]:
    written: list[Path] = []
    for service in manifest.services:
        provider = service.provider.lower()
        pack_path = _provider_pack_path(app_path, provider, service)
        if pack_path.exists():
            validate_provider_pack(load_provider_pack(pack_path))
            continue
        pack = synthesize_provider_pack(provider, app_path)
        write_provider_pack(pack, pack_path)
        written.append(pack_path)
    if manifest.domains:
        pack_path = pack_default_path(app_path, "cloudflare")
        if not pack_path.exists():
            write_provider_pack(synthesize_provider_pack("cloudflare", app_path), pack_path)
            written.append(pack_path)
    return written


def _provider_setup_inputs(args: argparse.Namespace) -> dict[str, str]:
    return {
        "app_source": str(getattr(args, "app_source", "")),
        "github_repo": str(getattr(args, "github_repo", "")),
        "vercel_project": str(getattr(args, "vercel_project", "")),
        "vercel_framework": str(getattr(args, "vercel_framework", "")),
        "vercel_git_repo_id": str(getattr(args, "vercel_git_repo_id", "")),
        "vercel_git_ref": str(getattr(args, "vercel_git_ref", "main")),
        "dns_zone": str(getattr(args, "dns_zone", "")),
    }


def _run_manifest_provider_pack_setup(
    args: argparse.Namespace,
    manifest: SetupManifest,
    context: ProviderSetupContext,
) -> None:
    app_path = Path(manifest.app_path)
    strategy_runs: list[dict[str, object]] = []
    providers = {service.provider.lower(): service for service in manifest.services}
    if manifest.domains and not any(provider in providers for provider in {"cloudflare", "dns"}):
        providers["cloudflare"] = ServiceRequirement(
            provider="cloudflare",
            kind="dns",
            name="dns",
            capabilities=("capability_pack", "dns"),
            secrets=("CLOUDFLARE_API_TOKEN",),
            settings={"capability_pack": str(pack_default_path(app_path, "cloudflare"))},
        )
    for provider, service in _ordered_provider_services(providers):
        if provider in {"cloudflare", "dns"}:
            _maybe_await_control_room_dns_approval(args, manifest, context)
        pack_path = _provider_pack_path(app_path, provider, service)
        if not pack_path.exists():
            write_provider_pack(synthesize_provider_pack(provider, app_path), pack_path)
        pack = load_provider_pack(pack_path)
        required_input = _missing_required_pack_input(provider, args, manifest)
        if required_input:
            if not args.allow_incomplete:
                raise FuseKitError(required_input)
            context.receipt.add_action(
                f"{provider}.setup", "skipped", {"reason": required_input}
            )
            continue
        result = run_provider_pack_setup(pack, context)
        strategy_runs.append(_provider_strategy_record(result))
        _write_provider_strategy_artifact(args, strategy_runs)
        _record_provider_strategy_checkpoints(args, strategy_runs)
        _record_provider_strategy_gates(args, pack, result)
        context.audit.record("provider_pack.setup", result)
        context.receipt.add_action("provider_pack.setup", "ok", result)
        if _provider_setup_needs_human_gate(result):
            context.receipt.add_action(
                "provider_pack.setup.paused",
                "needs_human_gate",
                {
                    "provider": provider,
                    "reason": (
                        "Downstream providers are waiting until this provider gate "
                        "is completed."
                    ),
                },
            )
            break
    if not strategy_runs:
        _write_provider_strategy_artifact(args, strategy_runs)


def _maybe_await_control_room_dns_approval(
    args: argparse.Namespace,
    manifest: SetupManifest,
    context: ProviderSetupContext,
) -> None:
    if context.approve_dns or bool(getattr(args, "approve_dns", False)):
        context.approve_dns = True
        return
    if not bool(getattr(args, "control_room", False)):
        return
    if not manifest.domains:
        return
    domain = str(getattr(args, "dns_zone", "") or manifest.domains[0].domain)
    _await_dns_approval(args, domain, manifest=manifest, context=context)
    context.approve_dns = True


def _provider_setup_needs_human_gate(result: dict[str, Any]) -> bool:
    return any(
        isinstance(item, dict) and item.get("status") == "needs_human_gate"
        for item in result.get("setup", [])
    )


def _ordered_provider_services(
    providers: dict[str, ServiceRequirement],
) -> list[tuple[str, ServiceRequirement]]:
    """Return provider setup order with DNS after providers that emit records/env."""

    priority = {
        "github": 10,
        "resend": 20,
        "vercel": 30,
        "cloudflare": 90,
        "dns": 90,
    }
    return sorted(providers.items(), key=lambda item: (priority.get(item[0], 50), item[0]))


def _attach_generated_dns_records(
    args: argparse.Namespace,
    context: ProviderSetupContext,
) -> None:
    """Expose provider-generated DNS records to later verification steps."""

    records = [
        _dns_record_to_input(record)
        for records_for_domain in context.generated_dns_records.values()
        for record in records_for_domain
    ]
    args.generated_dns_records_json = json.dumps(records, sort_keys=True)


def _provider_strategy_record(result: dict[str, Any]) -> dict[str, object]:
    strategies: list[dict[str, object]] = []
    for item in result.get("setup", []):
        if not isinstance(item, dict):
            continue
        decision = item.get("strategy_decision")
        if not isinstance(decision, dict):
            continue
        selected = decision.get("selected", {})
        strategy: dict[str, object] = {
            "recipe": str(item.get("kind", decision.get("recipe_kind", ""))),
            "status": str(item.get("status", "")),
            "strategy": str(item.get("strategy", selected.get("kind", "")))
            if isinstance(selected, dict)
            else str(item.get("strategy", "")),
            "decision": decision,
        }
        for key in ("resume_url", "target", "next_action", "resume_hint"):
            value = str(item.get(key, "") or "").strip()
            if value:
                strategy[key] = value
        follow_steps = item.get("follow_steps")
        if isinstance(follow_steps, (list, tuple)):
            steps = [str(step).strip() for step in follow_steps if str(step).strip()]
            if steps:
                strategy["follow_steps"] = steps
        success_criteria = item.get("success_criteria")
        if isinstance(success_criteria, (list, tuple)):
            criteria = [
                str(step).strip() for step in success_criteria if str(step).strip()
            ]
            if criteria:
                strategy["success_criteria"] = criteria
        avoid_steps = item.get("avoid_steps")
        if isinstance(avoid_steps, (list, tuple)):
            avoid = [str(step).strip() for step in avoid_steps if str(step).strip()]
            if avoid:
                strategy["avoid_steps"] = avoid
        strategies.append(strategy)
    return {"provider": str(result.get("provider", "")), "strategies": strategies}


def _record_provider_strategy_gates(
    args: argparse.Namespace,
    pack: ProviderCapabilityPack,
    result: dict[str, Any],
) -> None:
    provider = str(result.get("provider", pack.provider)).lower()
    default_resume_url = _provider_strategy_resume_url(pack)
    for item in result.get("setup", []):
        if not isinstance(item, dict):
            continue
        strategy = str(item.get("strategy", ""))
        if item.get("status") != "needs_human_gate":
            continue
        if strategy not in {"browser_guided", "human_follow_me"}:
            continue
        recipe = str(item.get("kind", "setup"))
        reason = str(
            item.get("reason")
            or item.get("next_action")
            or f"{provider} authorization is required for {recipe}."
        )
        resume_url = (
            str(item.get("resume_url") or "")
            or default_resume_url
            or _provider_strategy_decision_url(item)
        )
        item_steps = item.get("follow_steps")
        follow_steps = (
            tuple(str(step) for step in item_steps if str(step).strip())
            if isinstance(item_steps, (list, tuple))
            else _provider_strategy_follow_steps(pack)
        )
        target = str(item.get("target", "") or "").strip().upper()
        next_action = str(item.get("next_action", "") or "") or _provider_strategy_next_action(
            pack,
            target=target,
        )
        resume_hint = str(item.get("resume_hint", "") or "") or (
            "FuseKit will retry this provider route after you finish the gate."
        )
        gate_id = f"provider.{provider}.{_strategy_gate_slug(recipe)}"
        _record_gate_waiting(
            args,
            gate_id,
            provider=provider,
            reason=reason,
            resume_url=resume_url,
            classification="provider-authorization",
            target=target,
            follow_steps=follow_steps,
            next_action=next_action,
            resume_hint=resume_hint,
        )


def _record_provider_strategy_checkpoints(
    args: argparse.Namespace,
    strategy_runs: list[dict[str, object]],
) -> None:
    job_state = getattr(args, "job_state", None)
    if job_state is None:
        return
    job_path = Path(job_state)
    if not job_path.exists():
        return
    try:
        job = JobState.load(job_path)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return
    changed = False
    for record in strategy_runs:
        provider = str(record.get("provider", "") or "").strip().lower()
        strategies = _checkpoint_strategy_items(record)
        if not provider or not strategies:
            continue
        status, mascot_state = _provider_strategy_checkpoint_status(strategies)
        detail = _provider_strategy_checkpoint_detail(strategies)
        next_action = _provider_strategy_checkpoint_next_action(provider, strategies, status)
        resume_hint = _provider_strategy_checkpoint_resume_hint(provider, strategies, status)
        job.upsert_checkpoint(
            f"provider.{_strategy_gate_slug(provider)}.routes",
            f"Provider route: {provider}",
            status=status,
            detail=detail,
            next_action=next_action,
            resume_hint=resume_hint,
            mascot_state=mascot_state,
        )
        changed = True
    if changed:
        args.job_state = job_path
        _save_launch_job(args, job)


def _checkpoint_strategy_items(record: dict[str, object]) -> list[dict[str, object]]:
    raw_strategies = record.get("strategies", [])
    if not isinstance(raw_strategies, list):
        return []
    strategies: list[dict[str, object]] = []
    for item in raw_strategies:
        if isinstance(item, dict):
            strategies.append({str(key): value for key, value in item.items()})
    return strategies


def _provider_strategy_checkpoint_status(
    strategies: list[dict[str, object]],
) -> tuple[str, str]:
    statuses = {str(item.get("status", "") or "").strip() for item in strategies}
    if "needs_human_gate" in statuses:
        has_secret_target = any(
            str(item.get("target", "") or "").strip() for item in strategies
        )
        mascot = "privacy" if has_secret_target else "gate"
        return "waiting", mascot
    if statuses and statuses <= {"ok"}:
        return "done", "verify"
    if statuses & {"failed", "error"}:
        return "failed", "gate"
    return "running", "working"


def _provider_strategy_checkpoint_detail(strategies: list[dict[str, object]]) -> str:
    parts = []
    for item in strategies:
        recipe = str(item.get("recipe", "setup") or "setup").strip()
        route = str(item.get("strategy", "") or "").strip() or "planned route"
        status = str(item.get("status", "") or "").strip() or "pending"
        parts.append(f"{recipe} uses {route} ({status})")
    return "; ".join(parts)


def _provider_strategy_checkpoint_next_action(
    provider: str,
    strategies: list[dict[str, object]],
    status: str,
) -> str:
    human_gate = _first_strategy_with_status(strategies, "needs_human_gate")
    if human_gate is not None:
        return str(human_gate.get("next_action", "") or "") or _provider_strategy_next_action(
            target=str(human_gate.get("target", "") or ""),
        )
    if provider == "resend":
        return (
            "Nothing to do manually in Resend; FuseKit creates or reuses the domain by API, "
            "then waits for DNS approval after Resend records exist."
        )
    if provider == "vercel":
        return (
            "Nothing to copy manually into Vercel; FuseKit writes required runtime env vars "
            "after upstream provider values exist."
        )
    if provider in {"cloudflare", "dns"}:
        return (
            "Review and approve the DNS apply gate in the control room when FuseKit shows "
            "the exact app and provider-generated records."
        )
    if status == "failed":
        return (
            "Open the provider route details in the control room and retry the failed "
            "setup path."
        )
    return "Nothing to do manually unless FuseKit surfaces a provider-owned gate."


def _provider_strategy_checkpoint_resume_hint(
    provider: str,
    strategies: list[dict[str, object]],
    status: str,
) -> str:
    human_gate = _first_strategy_with_status(strategies, "needs_human_gate")
    if human_gate is not None:
        return str(human_gate.get("resume_hint", "") or "") or (
            "FuseKit will retry this provider route after you finish the gate."
        )
    if provider == "resend":
        return (
            "If this resurfaces, keep the live control room open; FuseKit will retry "
            "Resend setup, carry the Resend records into the DNS approval gate, and "
            "pause there before Cloudflare/DNS apply."
        )
    if provider == "vercel":
        return (
            "If this resurfaces, keep the live control room open while FuseKit waits "
            "for upstream provider values, then reapplies the required Vercel env "
            "wiring deterministically."
        )
    if provider in {"cloudflare", "dns"}:
        return (
            "If DNS is waiting, approve the exact generated records in the launcher; FuseKit "
            "will keep verifying propagation instead of giving up early."
        )
    if status == "failed":
        return (
            "Use the provider-route card in the live control room to resolve the "
            "provider-owned blocker; FuseKit will recheck the strategy from there."
        )
    return "FuseKit recorded the deterministic provider route for resume and audit."


def _first_strategy_with_status(
    strategies: list[dict[str, object]],
    status: str,
) -> dict[str, object] | None:
    for item in strategies:
        if str(item.get("status", "") or "") == status:
            return item
    return None


def _provider_strategy_follow_steps(pack: ProviderCapabilityPack) -> tuple[str, ...]:
    steps = tuple(
        step
        for step in (*pack.handoff.account_steps, *pack.handoff.secret_steps)
        if step.strip()
    )
    if steps:
        return steps
    return (
        f"Click Open provider gate in VM so {pack.display_name} opens in the VM browser.",
        (
            "Complete provider-owned login, MFA, CAPTCHA, consent, billing, or verification "
            "steps in that VM browser."
        ),
        (
            "If FuseKit shows exact env-named Capture buttons, copy each provider "
            "value inside the VM browser and click the visible button for that "
            "value, for example Capture CUSTOM_API_KEY from VM clipboard. "
            "Do not paste it into your computer; Capture reads the VM clipboard directly."
        ),
        (
            "If FuseKit shows I finished this step, click it only after the provider "
            "confirms the gate."
        ),
    )


def _provider_strategy_next_action(
    pack: ProviderCapabilityPack | None = None,
    *,
    target: str = "",
) -> str:
    capture_targets = _provider_strategy_capture_targets(pack, target)
    if capture_targets:
        capture_labels = [
            f"Capture {capture_target} from VM clipboard"
            for capture_target in capture_targets
        ]
        capture_copy = (
            f"click {capture_labels[0]}"
            if len(capture_labels) == 1
            else "click these exact buttons: " + ", ".join(capture_labels)
        )
    else:
        capture_copy = "click the exact env-named Capture button shown here"
    return (
        "Click Open provider gate in VM, complete the provider-owned gate in the VM browser, "
        "then follow the exact FuseKit control shown here: "
        f"{capture_copy} for secret values, or click "
        "I finished this step for non-secret gates."
    )


def _provider_strategy_capture_targets(
    pack: ProviderCapabilityPack | None,
    target: str = "",
) -> tuple[str, ...]:
    candidates: list[str] = []
    normalized_target = target.strip().upper()
    if normalized_target:
        candidates.append(normalized_target)
    if pack is not None:
        if pack.handoff.token_env:
            candidates.append(pack.handoff.token_env.strip().upper())
        candidates.extend(secret.strip().upper() for secret in pack.required_secrets)
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))


def _provider_strategy_resume_url(pack: ProviderCapabilityPack) -> str:
    for value in (
        pack.handoff.token_url,
        pack.handoff.project_url,
        pack.handoff.login_url,
        pack.handoff.signup_url,
    ):
        if value:
            return value
    return ""


def _provider_strategy_decision_url(item: dict[str, Any]) -> str:
    decision = item.get("strategy_decision", {})
    if not isinstance(decision, dict):
        return ""
    selected = decision.get("selected", {})
    if not isinstance(selected, dict):
        return ""
    evidence = selected.get("evidence", {})
    if not isinstance(evidence, dict):
        return ""
    return str(evidence.get("handoff_url", ""))


def _strategy_gate_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "setup"


def _write_provider_strategy_artifact(
    args: argparse.Namespace,
    strategy_runs: list[dict[str, object]],
) -> Path:
    path = _provider_strategy_artifact_path(Path(args.vault))
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "fusekit.provider-strategies.v1",
        "playbook": _provider_playbook(strategy_runs),
        "providers": strategy_runs,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _provider_playbook(strategy_runs: list[dict[str, object]]) -> dict[str, object]:
    """Build the durable plain-language provider playbook for the control room."""

    records = list(_iter_provider_strategy_items(strategy_runs))
    steps: list[dict[str, object]] = []
    if any(_is_resend_domain_api_record(record) for record in records):
        steps.append(
            _playbook_step(
                "resend.capture_key",
                (
                    "Capture RESEND_API_KEY from VM clipboard if the Resend API route "
                    "is not already authorized."
                ),
                control="Capture RESEND_API_KEY from VM clipboard",
                provider="resend",
            )
        )
        steps.append(
            _playbook_step(
                "resend.domain_api",
                "FuseKit creates or reuses the Resend sending domain through the Resend API.",
                provider="resend",
                route="api",
            )
        )
    if any(_is_resend_audience_api_record(record) for record in records):
        steps.append(
            _playbook_step(
                "resend.audience_api",
                (
                    "FuseKit creates or reuses a Resend audience by API only when the "
                    "app requires one."
                ),
                provider="resend",
                route="api",
            )
        )
    if any(_is_dns_record(record) for record in records):
        steps.append(
            _playbook_step(
                "dns.approval",
                (
                    "FuseKit carries app and provider-generated DNS records into the "
                    "DNS approval gate before apply."
                ),
                control="Approve DNS apply",
                provider="dns",
            )
        )
    if any(_is_vercel_env_record(record) for record in records):
        steps.append(
            _playbook_step(
                "vercel.env_api",
                (
                    "FuseKit writes required runtime variables into Vercel after "
                    "upstream provider values exist."
                ),
                provider="vercel",
                route="api",
            )
        )
    for target in _human_gate_targets(records):
        steps.append(
            _playbook_step(
                f"capture.{target.lower()}",
                (
                    "Open the provider gate in the VM browser, copy the approved value "
                    f"there, then click Capture {target} from VM clipboard."
                ),
                control=f"Capture {target} from VM clipboard",
            )
        )
    if any(_is_non_secret_human_gate(record) for record in records):
        steps.append(
            _playbook_step(
                "provider.finished_step",
                (
                    "For provider-owned login, MFA, consent, billing, or verification gates, "
                    "finish the prompt in the VM browser, then click I finished this step."
                ),
                control="I finished this step",
            )
        )
    if not steps and records:
        steps.append(
            _playbook_step(
                "provider.routes",
                (
                    "FuseKit recorded deterministic provider routes; no user action "
                    "is needed unless a gate appears."
                ),
            )
        )
    return {
        "schema_version": "fusekit.provider-playbook.v1",
        "steps": steps,
        "safety_notes": [
            "Use the launcher and shared VM browser for provider gates.",
            (
                "Do not create Resend domains or audiences manually; FuseKit owns "
                "those API setup steps."
            ),
            "Do not paste provider secrets into the host computer; Capture reads the VM clipboard.",
        ],
    }


def _playbook_step(
    step_id: str,
    instruction: str,
    *,
    control: str = "",
    provider: str = "",
    route: str = "",
) -> dict[str, object]:
    payload: dict[str, object] = {"id": step_id, "instruction": instruction}
    if control:
        payload["control"] = control
    if provider:
        payload["provider"] = provider
    if route:
        payload["route"] = route
    return payload


def _iter_provider_strategy_items(
    strategy_runs: list[dict[str, object]],
) -> Iterable[dict[str, object]]:
    for provider_record in strategy_runs:
        provider = str(provider_record.get("provider", "") or "").strip().lower()
        strategies = provider_record.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        for strategy in strategies:
            if not isinstance(strategy, dict):
                continue
            item = {str(key): value for key, value in strategy.items()}
            item["provider"] = provider
            yield item


def _strategy_evidence(item: dict[str, object]) -> dict[str, object]:
    decision = item.get("decision", {})
    if not isinstance(decision, dict):
        return {}
    selected = decision.get("selected", {})
    if not isinstance(selected, dict):
        return {}
    evidence = selected.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    return evidence


def _strategy_route_kind(item: dict[str, object]) -> str:
    return str(item.get("strategy", "") or "").strip()


def _strategy_recipe(item: dict[str, object]) -> str:
    return str(item.get("recipe", "") or "").strip()


def _is_resend_domain_api_record(item: dict[str, object]) -> bool:
    return (
        str(item.get("provider", "")) == "resend"
        and _strategy_recipe(item) == "resend-domain"
        and _strategy_route_kind(item) == "api"
        and str(_strategy_evidence(item).get("downstream_order", "")) == "before_dns_apply"
    )


def _is_resend_audience_api_record(item: dict[str, object]) -> bool:
    return (
        str(item.get("provider", "")) == "resend"
        and _strategy_recipe(item) == "resend-audience"
        and _strategy_route_kind(item) == "api"
        and str(_strategy_evidence(item).get("api_owns", "")) == "audience"
    )


def _is_dns_record(item: dict[str, object]) -> bool:
    provider = str(item.get("provider", ""))
    return provider in {"cloudflare", "dns"} or "dns" in _strategy_recipe(item)


def _is_vercel_env_record(item: dict[str, object]) -> bool:
    return (
        str(item.get("provider", "")) == "vercel"
        and _strategy_route_kind(item) == "api"
        and "env" in _strategy_recipe(item)
    )


def _human_gate_targets(records: list[dict[str, object]]) -> list[str]:
    targets = {
        str(item.get("target", "") or "").strip().upper()
        for item in records
        if _strategy_route_kind(item) in {"browser_guided", "human_follow_me"}
        and str(item.get("target", "") or "").strip()
    }
    return sorted(target for target in targets if target)


def _is_non_secret_human_gate(item: dict[str, object]) -> bool:
    return (
        _strategy_route_kind(item) in {"browser_guided", "human_follow_me"}
        and not str(item.get("target", "") or "").strip()
    )


def _provider_strategy_artifact_path(vault_path: Path) -> Path:
    return vault_path.parent / "provider_strategies.json"


def _provider_pack_path(app_path: Path, provider: str, service: ServiceRequirement) -> Path:
    pack_hint = service.settings.get("capability_pack", "")
    pack_path = Path(pack_hint) if pack_hint else pack_default_path(app_path, provider)
    if not pack_path.is_absolute():
        pack_path = app_path / pack_path
    return pack_path


def _apply_magic_defaults(
    args: argparse.Namespace,
    manifest: SetupManifest,
    app_path: Path,
) -> None:
    """Fill launch inputs that a non-technical user should not need to know."""

    if not getattr(args, "app_source", ""):
        args.app_source = _infer_app_source(app_path)
    repo_slug = _normalize_github_repo_slug(str(getattr(args, "github_repo", ""))) or (
        _normalize_github_repo_slug(str(getattr(args, "app_source", "")))
    )
    if repo_slug and not getattr(args, "github_repo", ""):
        args.github_repo = repo_slug
    if not getattr(args, "vercel_project", ""):
        args.vercel_project = _slugify_project_name(repo_slug.split("/", 1)[1] if repo_slug else "")
    if not getattr(args, "vercel_project", ""):
        args.vercel_project = _slugify_project_name(manifest.app_name)
    default_domain = _default_manifest_domain(manifest)
    if default_domain and not getattr(args, "live_url", ""):
        args.live_url = f"https://{default_domain}"
    if not getattr(args, "dns_zone", ""):
        host = default_domain or _hostname_from_url(getattr(args, "live_url", ""))
        args.dns_zone = _infer_dns_zone(host)


def _normalize_github_repo_slug(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    raw = raw.removesuffix(".git")
    if raw.startswith("git@github.com:"):
        raw = raw.removeprefix("git@github.com:")
    elif "github.com/" in raw:
        raw = raw.split("github.com/", 1)[1]
    raw = raw.strip("/")
    parts = raw.split("/")
    if len(parts) >= 2 and all(parts[:2]):
        return f"{parts[0]}/{parts[1]}"
    return ""


def _slugify_project_name(value: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug[:100]


def _default_manifest_domain(manifest: SetupManifest) -> str:
    if manifest.domains:
        return manifest.domains[0].domain.strip().lower().removeprefix("www.")
    return ""


def _hostname_from_url(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").strip().lower().removeprefix("www.")


def _infer_dns_zone(hostname: str) -> str:
    host = hostname.strip().lower().removeprefix("www.")
    if not host:
        return ""
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def _missing_required_pack_input(
    provider: str,
    args: argparse.Namespace,
    manifest: SetupManifest,
) -> str:
    if provider == "github" and not args.github_repo:
        return (
            "Real GitHub setup is required by the manifest. FuseKit could not infer the "
            "GitHub repository from --app-source or the app git remote. Add the app repo URL, "
            "push the app to GitHub first, or use --allow-incomplete for an explicit local "
            "rehearsal."
        )
    if provider == "vercel" and not args.vercel_project:
        return (
            "Real Vercel setup is required by the manifest. FuseKit could not infer a project "
            "name from the repo URL or app name. Add --app-source, ensure the manifest has an "
            "app_name, or use --allow-incomplete for an explicit local rehearsal."
        )
    if provider in {"cloudflare", "dns"} and manifest.domains:
        has_cloudflare = bool(os.environ.get("CLOUDFLARE_API_TOKEN"))
        if not has_cloudflare and not args.vault.exists():
            return (
                "Real Cloudflare DNS setup is required by the manifest. Authorize "
                "Cloudflare first, or use --allow-incomplete for an explicit local rehearsal."
            )
    return ""


def _verify_provider_packs(
    args: argparse.Namespace,
    manifest: SetupManifest,
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
    verification_report: VerificationReport,
) -> None:
    app_path = Path(manifest.app_path)
    services_by_provider = {service.provider.lower(): service for service in manifest.services}
    has_dns_service = any(provider in {"cloudflare", "dns"} for provider in services_by_provider)
    if manifest.domains and not has_dns_service:
        services_by_provider["cloudflare"] = ServiceRequirement(
            provider="cloudflare",
            kind="dns",
            name="dns",
            capabilities=("capability_pack", "dns"),
            settings={"capability_pack": str(pack_default_path(app_path, "cloudflare"))},
        )
    ordered_services = _ordered_provider_services(services_by_provider)
    active_gate = _pending_provider_gate(args)
    active_gate_provider = active_gate.provider.lower() if active_gate is not None else ""
    active_gate_index = next(
        (
            index
            for index, (ordered_provider, _service) in enumerate(ordered_services)
            if ordered_provider == active_gate_provider
        ),
        None,
    )
    for index, (provider, service) in enumerate(ordered_services):
        pack_path = _provider_pack_path(app_path, provider, service)
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        pack = load_provider_pack(pack_path)
        pending_gate = _pending_provider_gate(args, provider)
        if pending_gate is not None:
            results = [
                VerificationResult(
                    provider=pack.provider,
                    kind="provider-gate",
                    target=pending_gate.id,
                    status="needs_human_gate",
                    details={
                        "reason": pending_gate.reason,
                        "resume_url": pending_gate.resume_url,
                        "service_gate": True,
                    },
                )
            ]
        elif (
            active_gate is not None
            and active_gate_index is not None
            and index > active_gate_index
        ):
            results = [_provider_waiting_on_upstream_gate_result(pack.provider, active_gate)]
        else:
            verify_attempts, verify_retry_seconds = _provider_verification_attempt_config(args)
            results = verify_provider_pack(
                pack,
                vault,
                live_url=getattr(args, "live_url", ""),
                inputs=_verification_inputs(args, manifest),
                attempts=verify_attempts,
                retry_seconds=verify_retry_seconds,
            )
        payload = {"provider": pack.provider, "results": [result.to_dict() for result in results]}
        audit.record("provider_pack.verify", payload)
        overall = _provider_verification_overall(results)
        attempted_repair_or_fallback = False
        if not _provider_verification_acceptable(results):
            repaired = _attempt_provider_verification_repair(
                args,
                pack,
                results,
                vault,
                audit,
                receipt,
            )
            if repaired:
                attempted_repair_or_fallback = True
                results = _rerun_provider_verification(args, manifest, pack, vault)
                payload = {
                    "provider": pack.provider,
                    "results": [result.to_dict() for result in results],
                }
                audit.record("provider_pack.verify_after_repair", payload)
                overall = _provider_verification_overall(results)
        if not _provider_verification_acceptable(results):
            fallback = _attempt_provider_api_fallback(
                args,
                manifest,
                pack,
                results,
                vault,
                audit,
                receipt,
            )
            if fallback:
                attempted_repair_or_fallback = True
                results = _rerun_provider_verification(args, manifest, pack, vault)
                payload = {
                    "provider": pack.provider,
                    "results": [result.to_dict() for result in results],
                }
                audit.record("provider_pack.verify_after_api_fallback", payload)
                overall = _provider_verification_overall(results)
        verification_gates = _record_provider_verification_gates(
            args,
            manifest,
            pack,
            results,
        )
        if verification_gates:
            audit.record(
                "provider_pack.verification_gates",
                {"provider": pack.provider, "gates": verification_gates},
            )
        verification_report.add_provider_results(
            pack.provider,
            results,
            repaired=attempted_repair_or_fallback
            and not _provider_verification_acceptable(results)
            and overall != "pending-safe",
        )
        receipt.add_action("provider_pack.verify", overall, payload)
        if not _provider_verification_acceptable(results) and not args.allow_incomplete:
            raise FuseKitError(
                f"Provider verification failed for {pack.provider}. See redacted receipt/audit."
            )
    _verify_webhook_secret_checks(manifest, vault, verification_report)


def _provider_waiting_on_upstream_gate_result(
    provider: str,
    gate: GateRecord,
) -> VerificationResult:
    gate_provider = gate.provider.lower() or "provider"
    return VerificationResult(
        provider=provider,
        kind="provider-gate",
        target=gate.id,
        status="pending",
        details={
            "pending_safe": True,
            "service_gate": True,
            "blocked_by_gate": gate.id,
            "blocked_by_provider": gate_provider,
            "reason": (
                f"Waiting for the {gate_provider} gate before verifying {provider}."
            ),
        },
    )


def _record_provider_verification_gates(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    results: list[VerificationResult],
) -> list[dict[str, object]]:
    """Surface verification-time human gates in the live control room."""

    recorded: list[dict[str, object]] = []
    for result in results:
        if (
            result.status != "needs_human_gate"
            and not _failed_provider_result_has_guided_repair(result)
        ) or result.kind == "provider-gate":
            continue
        gate = _provider_verification_gate(args, manifest, pack, result)
        _record_gate_waiting(
            args,
            gate["id"],
            provider=gate["provider"],
            reason=gate["reason"],
            resume_url=gate["resume_url"],
            classification=gate["classification"],
            target=gate["target"],
            follow_steps=gate["follow_steps"],
            next_action=gate.get("next_action", ""),
            resume_hint=gate.get("resume_hint", ""),
        )
        recorded.append(
            {
                "id": gate["id"],
                "provider": gate["provider"],
                "classification": gate["classification"],
                "target": gate["target"],
            }
        )
    return recorded


def _failed_provider_result_has_guided_repair(result: VerificationResult) -> bool:
    return (
        result.status == "failed"
        and result.provider == "resend"
        and result.kind == "resend-domain"
        and result.details.get("repair") == "rerun_resend_domain_setup"
    )


def _provider_verification_gate(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    result: VerificationResult,
) -> dict[str, Any]:
    del args
    reason = str(result.details.get("reason") or "").strip()
    env_names = _verification_gate_env_names(reason)
    resend_env_names = tuple(name for name in env_names if name.startswith("RESEND_"))
    domain = _default_manifest_domain(manifest)
    if "RESEND_API_KEY" in resend_env_names:
        return {
            "id": "provider.resend.runtime-values",
            "provider": "resend",
            "reason": (
                "Capture the Resend setup key so FuseKit can generate the remaining "
                "Resend runtime values through the API."
            ),
            "resume_url": "https://resend.com/api-keys",
            "classification": "provider-runtime-values",
            "target": "RESEND_API_KEY",
            "follow_steps": _resend_runtime_follow_steps(domain, ("RESEND_API_KEY",)),
            "next_action": (
                "Capture RESEND_API_KEY from VM clipboard; FuseKit will generate "
                "Resend sender and audience values after the setup key is stored."
            ),
            "resume_hint": (
                "FuseKit resumes automatically after Capture succeeds, then reruns "
                "Resend API setup before reapplying downstream provider env."
            ),
        }
    if _only_api_owned_resend_runtime_values(resend_env_names):
        missing = ", ".join(resend_env_names)
        return {
            "id": "provider.resend.runtime-setup-retry",
            "provider": "resend",
            "reason": (
                "FuseKit needs to regenerate Resend-owned runtime values before "
                f"reapplying the downstream provider environment: {missing}."
            ),
            "resume_url": "https://resend.com/api-keys",
            "classification": "provider-setup-retry",
            "target": "",
            "follow_steps": _resend_runtime_setup_retry_follow_steps(domain, resend_env_names),
            "next_action": (
                "No manual Resend value copy is needed. Click I finished this step so "
                "FuseKit retries Resend API setup and reapplies the generated values."
            ),
            "resume_hint": (
                "FuseKit will regenerate the Resend sender/audience values through the "
                "API, then retry Vercel and GitHub environment setup."
            ),
        }
    if resend_env_names:
        missing = ", ".join(resend_env_names)
        return {
            "id": "provider.resend.runtime-values",
            "provider": "resend",
            "reason": (
                "Finish Resend email configuration so FuseKit can apply the missing "
                f"runtime values: {missing}."
            ),
            "resume_url": _resend_runtime_resume_url(resend_env_names),
            "classification": "provider-runtime-values",
            "target": ",".join(resend_env_names),
            "follow_steps": _resend_runtime_follow_steps(domain, resend_env_names),
            "next_action": (
                "Click "
                + _capture_controls_for_env_names(resend_env_names)
                + " so FuseKit can update the provider environment without exposing "
                "the values."
            ),
            "resume_hint": (
                "FuseKit resumes automatically after every requested Resend value is "
                "captured, then reapplies the values to Vercel and GitHub as needed."
            ),
        }
    if pack.provider == "resend" and result.kind == "http-json":
        return {
            "id": "provider.resend.api-key-domain-access",
            "provider": "resend",
            "reason": _resend_api_key_gate_reason(reason),
            "resume_url": "https://resend.com/api-keys",
            "classification": "provider-authorization",
            "target": "RESEND_API_KEY",
            "follow_steps": _resend_api_key_follow_steps(domain),
            "next_action": (
                "Capture RESEND_API_KEY from VM clipboard; do not click I finished "
                "this step for copy-once secrets."
            ),
            "resume_hint": (
                "FuseKit resumes automatically after Capture succeeds, then creates or "
                "reuses the Resend sending domain before Cloudflare DNS runs."
            ),
        }
    if pack.provider == "resend" and result.kind == "resend-domain":
        target = result.target if "${input:" not in result.target else domain
        needs_setup_retry = (
            result.details.get("missing")
            or result.details.get("repair") == "rerun_resend_domain_setup"
        )
        if needs_setup_retry:
            return {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "reason": reason
                or (
                    f"FuseKit has a valid Resend setup key, but {target or domain} was not "
                    "created yet."
                ),
                "resume_url": "https://resend.com/api-keys",
                "classification": "provider-setup-retry",
                "target": "",
                "follow_steps": _resend_domain_setup_retry_follow_steps(target or domain),
                "next_action": (
                    "No manual Resend domain work is needed. Click I finished this step so "
                    "FuseKit retries Resend domain setup through the API."
                ),
                "resume_hint": (
                    "FuseKit will rerun Resend API setup, pull the returned DNS records, "
                    "and only then continue to Cloudflare DNS."
                ),
            }
        return {
            "id": "provider.resend.domain-verification",
            "provider": "resend",
            "reason": reason
            or (
                f"Review the existing Resend sending domain {target or domain}; "
                "FuseKit creates or reuses it by API before DNS."
            ),
            "resume_url": "https://resend.com/domains",
            "classification": "provider-domain",
            "target": target,
            "follow_steps": _resend_domain_follow_steps(target or domain),
            "next_action": (
                f"Finish the Resend domain gate for {target or domain}, then click "
                "I finished this step."
            ),
            "resume_hint": (
                "FuseKit will recheck Resend, read any DNS records returned by the API, "
                "and keep Cloudflare DNS behind Resend until the records are known."
            ),
        }
    return {
        "id": f"provider.{pack.provider}.{_strategy_gate_slug(result.kind)}",
        "provider": pack.provider,
        "reason": reason or f"{pack.display_name} needs a provider-owned verification step.",
        "resume_url": _provider_strategy_resume_url(pack),
        "classification": "provider-verification",
        "target": result.target,
        "follow_steps": _provider_strategy_follow_steps(pack),
        "next_action": (
            "Click Open provider gate in VM, complete the provider-owned verification "
            "in the VM browser, then click I finished this step when FuseKit shows that button."
        ),
        "resume_hint": "FuseKit will recheck the provider state before continuing.",
    }


def _verification_gate_env_names(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text)))


def _resend_api_key_follow_steps(domain: str) -> tuple[str, ...]:
    domain_note = f" for {domain}" if domain else ""
    return (
        "Use the live VM browser, not a local browser tab.",
        "Open Resend API Keys and create a new key named FuseKit email setup.",
        (
            "Choose Permission: Full access and Domain: All domains for this first setup "
            f"key so FuseKit can create or reuse the sending domain and audience{domain_note}."
        ),
        (
            "If an existing key already says Permission: Full access and Domain: All "
            "domains but you cannot copy its raw value, create a new setup key; Resend "
            "does not reveal old key secrets again."
        ),
        (
            "If Resend shows No domains yet, stay on API Keys and do not click Add domain; "
            "FuseKit creates or reuses the domain after Capture succeeds."
        ),
        (
            "Copy the API key only inside the VM browser, then click "
            "Capture RESEND_API_KEY from VM clipboard. Do not paste it into your "
            "computer; Capture reads the VM clipboard directly."
        ),
        (
            "FuseKit stores the key in the encrypted vault and uses Resend's API before "
            "DNS is applied."
        ),
        "FuseKit resumes automatically after Capture reports success.",
    )


def _resend_api_key_gate_reason(reason: str) -> str:
    """Return launcher-safe Resend API-key guidance even for stale provider errors."""

    exact = (
        "Create or capture a Resend API key with Permission: Full access and "
        "Domain: All domains for the first setup so FuseKit can create or reuse "
        "domains and audiences."
    )
    if not reason:
        return f"Resend rejected the captured setup key. {exact}"
    if "Permission: Full access" in reason and "Domain: All domains" in reason:
        return reason
    return f"{reason} {exact}"


def _resend_domain_follow_steps(domain: str) -> tuple[str, ...]:
    named_domain = domain or "the app sending domain"
    return (
        "Use the live VM browser, not a local browser tab.",
        (
            f"Open Resend Domains only to review the existing {named_domain} domain "
            "and any provider-owned verification prompt shown there."
        ),
        (
            "Do not create the domain or DNS records by hand in this step; FuseKit creates "
            "or reuses the domain through Resend's API and keeps Cloudflare DNS behind it."
        ),
        "FuseKit reads Resend DNS records through the API and asks Cloudflare to apply them.",
        (
            "After Resend shows the domain as verified or pending DNS, click the visible "
            "I finished this step button in the control room."
        ),
    )


def _resend_domain_setup_retry_follow_steps(domain: str) -> tuple[str, ...]:
    named_domain = domain or "the app sending domain"
    return (
        "Use the live VM browser, not a local browser tab.",
        (
            "No manual Resend domain or DNS step is needed here; FuseKit already has a "
            "valid setup key and needs a retry wake-up."
        ),
        (
            f"Do not manually create {named_domain} in Resend for this step; FuseKit is "
            "supposed to create or reuse it through Resend's API."
        ),
        (
            "Click I finished this step. FuseKit will retry the Resend API setup, capture "
            "the domain DNS records, and pass those records to Cloudflare."
        ),
    )


def _resend_runtime_follow_steps(
    domain: str,
    env_names: tuple[str, ...],
) -> tuple[str, ...]:
    steps = [
        "Use the live VM browser, not a local browser tab.",
    ]
    capture_controls = ", ".join(
        f"Capture {env_name} from VM clipboard" for env_name in env_names
    ) or "the visible env-named Capture buttons"
    if "RESEND_API_KEY" in env_names:
        steps.extend(
            [
                (
                    "Open Resend API Keys and create a setup key named FuseKit email setup "
                    "with Permission: Full access and Domain: All domains."
                ),
                (
                    "Copy the API key only inside the VM browser so FuseKit can store "
                    "RESEND_API_KEY."
                ),
            ]
        )
    if "RESEND_FROM_EMAIL" in env_names:
        named_domain = domain or "the app sending domain"
        from_address = f"rsvp@{domain}" if domain else "the verified sending address"
        steps.extend(
            [
                (
                    "RESEND_FROM_EMAIL is normally generated by FuseKit after Resend "
                    f"domain setup. Use {from_address} unless the app requires a "
                    "different verified sender."
                ),
                (
                    f"Do not create {named_domain} by hand for this value. If you need "
                    "to recover a different sender, open Resend Domains only to copy an "
                    "already-verified sender address."
                ),
                (
                    "Do not create a Resend audience unless RESEND_AUDIENCE_ID is listed "
                    "as a missing value."
                ),
            ]
        )
    if "RESEND_AUDIENCE_ID" in env_names:
        steps.extend(
            [
                (
                    "RESEND_AUDIENCE_ID is normally created or reused by FuseKit through "
                    "Resend's API when the app needs an audience."
                ),
                (
                    "If this recovery gate still appears, open Resend Audiences only to "
                    "copy the existing audience ID for this app; do not create unrelated "
                    "audiences."
                ),
            ]
        )
    steps.extend(
        [
            (
                "Copy each requested value inside the VM browser, then click these "
                f"exact controls: {capture_controls}. Do not paste values into your "
                "computer; Capture reads the VM clipboard directly."
            ),
            (
                "FuseKit will apply the captured values to Vercel and GitHub after "
                "the capture gate completes."
            ),
            "FuseKit resumes automatically once every requested value has been captured.",
        ]
    )
    return tuple(steps)


def _capture_controls_for_env_names(env_names: Iterable[str]) -> str:
    controls = [
        f"Capture {env_name.strip().upper()} from VM clipboard"
        for env_name in env_names
        if env_name.strip()
    ]
    if not controls:
        return "the exact env-named Capture button shown on the active launcher gate"
    if len(controls) == 1:
        return controls[0]
    return "these exact Capture buttons: " + ", ".join(controls)


def _resend_runtime_setup_retry_follow_steps(
    domain: str,
    env_names: tuple[str, ...],
) -> tuple[str, ...]:
    named_domain = domain or "the app sending domain"
    missing = ", ".join(env_names)
    return (
        "Use the live VM browser, not a local browser tab.",
        (
            f"Do not copy {missing} from Resend for this recovery step; those values "
            "are FuseKit-owned runtime settings."
        ),
        (
            f"Do not manually create {named_domain}, DNS records, or audiences here. "
            "FuseKit should create or reuse them through Resend's API."
        ),
        (
            "Click I finished this step so FuseKit reruns Resend setup, stores the "
            "generated values in the encrypted vault, and reapplies them downstream."
        ),
    )


def _only_api_owned_resend_runtime_values(env_names: tuple[str, ...]) -> bool:
    if not env_names:
        return False
    names = set(env_names)
    return "RESEND_API_KEY" not in names and names <= _api_owned_resend_runtime_names()


def _resend_runtime_resume_url(env_names: tuple[str, ...]) -> str:
    if "RESEND_API_KEY" in env_names:
        return "https://resend.com/api-keys"
    if "RESEND_AUDIENCE_ID" in env_names:
        return "https://resend.com/audiences"
    return "https://resend.com/domains"


def _verification_inputs(args: argparse.Namespace, manifest: SetupManifest) -> dict[str, str]:
    inputs = _provider_setup_inputs(args)
    provider_names = _required_providers(manifest)
    app_env_names = _app_env_names_for_verification(manifest, provider_names)
    default_domain = _default_manifest_domain(manifest)
    generated = json.loads(str(getattr(args, "generated_dns_records_json", "[]") or "[]"))
    generated_records = generated if isinstance(generated, list) else []
    records = [
        _dns_record_to_input(record)
        for domain in manifest.domains
        for record in domain.records
    ] + [item for item in generated_records if isinstance(item, dict)]
    inputs.update(
        {
            "app_env_names": ",".join(app_env_names),
            "dns_records_json": json.dumps(records, sort_keys=True),
            "live_url_dns_pending_safe": (
                "true" if _live_url_waiting_on_dns_approval(args, manifest) else "false"
            ),
            "resend_domain": default_domain,
        }
    )
    return inputs


def _dns_record_to_input(record: DnsRecord) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": record.name,
        "type": record.type,
        "value": record.value,
    }
    if record.priority is not None:
        payload["priority"] = record.priority
    return payload


def _provider_verification_attempt_config(args: argparse.Namespace) -> tuple[int, float]:
    if _has_pending_provider_gate(args):
        return 1, 0.0
    return (
        int(getattr(args, "verify_attempts", 1)),
        float(getattr(args, "verify_retry_seconds", 0.0)),
    )


def _rerun_provider_verification(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    vault: Vault,
) -> list[VerificationResult]:
    verify_attempts, verify_retry_seconds = _provider_verification_attempt_config(args)
    return verify_provider_pack(
        pack,
        vault,
        live_url=getattr(args, "live_url", ""),
        inputs=_verification_inputs(args, manifest),
        attempts=verify_attempts,
        retry_seconds=verify_retry_seconds,
    )


def _provider_verification_acceptable(results: list[VerificationResult]) -> bool:
    return all(
        result.status in {"ok", "skipped", "needs_human_gate"}
        or (
            result.status == "pending"
            and bool(result.to_dict().get("details", {}).get("pending_safe"))
        )
        for result in results
    )


def _provider_verification_overall(results: list[VerificationResult]) -> str:
    if all(result.status in {"ok", "skipped"} for result in results):
        return "ok"
    if any(result.status == "needs_human_gate" for result in results):
        return "needs_human_gate"
    if _provider_verification_acceptable(results):
        return "pending-safe"
    if any(result.status == "pending" for result in results):
        return "pending"
    return "failed"


def _app_env_names_for_verification(
    manifest: SetupManifest,
    provider_names: set[str],
) -> tuple[str, ...]:
    from fusekit.providers.secret_routing import classify_secret_name

    names: set[str] = set(manifest.required_env)
    for service in manifest.services:
        names.update(service.secrets)
        names.update(service.env)
    for webhook in manifest.webhooks:
        names.add(webhook.secret_name)
    allowed = [
        name
        for name in names
        if classify_secret_name(name, provider_names).route in {"app_env", "webhook_secret"}
    ]
    return tuple(sorted(allowed))


def _verify_webhook_secret_checks(
    manifest: SetupManifest,
    vault: Vault,
    verification_report: VerificationReport,
) -> None:
    if not manifest.webhooks:
        return
    results: list[VerificationResult] = []
    for webhook in manifest.webhooks:
        available = _webhook_secret_available(vault, webhook.secret_name)
        results.append(
            VerificationResult(
                provider="webhook",
                kind="webhook-secret",
                target=webhook.secret_name,
                status="ok" if available else "missing",
                details={
                    "webhook": webhook.name,
                    "secret_name": webhook.secret_name,
                },
            )
        )
    verification_report.add_provider_results("webhook", results)


def _webhook_secret_available(vault: Vault, name: str) -> bool:
    if os.environ.get(name):
        return True
    for record in vault.public_index():
        if record.get("label") == name or record.get("id") == name:
            return True
    return False


def _attempt_provider_api_fallback(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    results: list[VerificationResult],
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
) -> bool:
    """Retry provider-native setup when UI repair is stuck and a token exists."""

    regenerated_resend = _attempt_resend_runtime_generation_before_downstream(
        args,
        manifest,
        pack,
        results,
        vault,
        audit,
        receipt,
    )
    if not _has_pack_provider_token(pack, vault):
        receipt.add_action(
            "provider_pack.api_fallback",
            "skipped",
            {"provider": pack.provider, "reason": "provider token is not available"},
        )
        return regenerated_resend
    try:
        context = ProviderSetupContext(
            manifest=manifest,
            vault=vault,
            audit=audit,
            receipt=receipt,
            secrets=_runtime_env_secrets(args, manifest, vault),
            provider_names=_required_providers(manifest),
            inputs=_provider_setup_inputs(args),
            approve_dns=bool(getattr(args, "approve_dns", False)),
            allow_incomplete=bool(getattr(args, "allow_incomplete", False)),
            fusekit_gates=str(getattr(args, "fusekit_gates", "service-only")),
        )
        result = run_provider_pack_setup(pack, context)
    except FuseKitError as exc:
        payload: dict[str, object] = {
            "provider": pack.provider,
            "status": "blocked",
            "error": _redact_cli_error(str(exc)),
        }
        audit.record("provider_pack.api_fallback", payload)
        receipt.add_action("provider_pack.api_fallback", "blocked", payload)
        return regenerated_resend
    payload = {
        "provider": pack.provider,
        "status": "attempted",
        "upstream_resend_runtime_regenerated": regenerated_resend,
        "result": result,
    }
    audit.record("provider_pack.api_fallback", payload)
    receipt.add_action("provider_pack.api_fallback", "attempted", payload)
    return True


def _attempt_resend_runtime_generation_before_downstream(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    results: list[VerificationResult],
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
) -> bool:
    """Regenerate API-owned Resend runtime values before downstream provider repair."""

    if pack.provider.lower() == "resend":
        return False
    missing = _missing_api_owned_resend_runtime_values(results)
    if not missing:
        return False
    resend_service = next(
        (service for service in manifest.services if service.provider.lower() == "resend"),
        None,
    )
    if resend_service is None:
        return False
    app_path = Path(manifest.app_path)
    pack_path = _provider_pack_path(app_path, "resend", resend_service)
    if pack_path.exists():
        resend_pack = load_provider_pack(pack_path)
    else:
        resend_pack = synthesize_provider_pack("resend", app_path)
        write_provider_pack(resend_pack, pack_path)
    if not _has_pack_provider_token(resend_pack, vault):
        receipt.add_action(
            "provider_pack.resend_runtime_regeneration",
            "skipped",
            {
                "provider": pack.provider,
                "missing": list(missing),
                "reason": "Resend setup key is not available",
            },
        )
        return False
    try:
        context = ProviderSetupContext(
            manifest=manifest,
            vault=vault,
            audit=audit,
            receipt=receipt,
            secrets=_runtime_env_secrets(args, manifest, vault),
            provider_names=_required_providers(manifest),
            inputs=_provider_setup_inputs(args),
            approve_dns=bool(getattr(args, "approve_dns", False)),
            allow_incomplete=bool(getattr(args, "allow_incomplete", False)),
            fusekit_gates=str(getattr(args, "fusekit_gates", "service-only")),
        )
        result = run_provider_pack_setup(resend_pack, context)
    except FuseKitError as exc:
        payload: dict[str, object] = {
            "provider": pack.provider,
            "missing": list(missing),
            "status": "blocked",
            "error": _redact_cli_error(str(exc)),
        }
        audit.record("provider_pack.resend_runtime_regeneration", payload)
        receipt.add_action("provider_pack.resend_runtime_regeneration", "blocked", payload)
        return False
    payload = {
        "provider": pack.provider,
        "missing": list(missing),
        "status": "attempted",
        "result": result,
    }
    audit.record("provider_pack.resend_runtime_regeneration", payload)
    receipt.add_action("provider_pack.resend_runtime_regeneration", "attempted", payload)
    return True


def _missing_api_owned_resend_runtime_values(
    results: list[VerificationResult],
) -> tuple[str, ...]:
    """Return missing Resend values FuseKit can create from the Resend API key."""

    missing: list[str] = []
    for result in results:
        if result.status in {"ok", "skipped"}:
            continue
        reason = str(result.details.get("reason", "") or "")
        for name in _verification_gate_env_names(reason):
            if name in _api_owned_resend_runtime_names():
                missing.append(name)
    return tuple(dict.fromkeys(missing))


def _api_owned_resend_runtime_names() -> set[str]:
    return {"RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"}


def _has_pack_provider_token(pack: ProviderCapabilityPack, vault: Vault) -> bool:
    token_ids = {
        f"provider.{pack.provider}.token",
        pack.handoff.token_record_id,
    }
    for record_id in token_ids:
        if record_id:
            try:
                vault.require(record_id)
                return True
            except FuseKitError:
                pass
    env_names = {
        name
        for name in (pack.handoff.token_env, *pack.required_secrets)
        if name
    }
    return any(bool(os.environ.get(name)) for name in env_names)


def _attempt_provider_verification_repair(
    args: argparse.Namespace,
    pack: ProviderCapabilityPack,
    results: list[VerificationResult],
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
) -> bool:
    """Run a bounded UI repair pass when provider verification fails."""

    if not bool(getattr(args, "infer_ui", False)):
        return False
    if getattr(args, "spine", "openclaw") == "system":
        receipt.add_action(
            "provider_pack.repair",
            "skipped",
            {"provider": pack.provider, "reason": "computer-use spine is system-only"},
        )
        return False
    failed = [result for result in results if result.status not in {"ok", "skipped"}]
    if not failed:
        return False
    start_url = _provider_repair_start_url(pack)
    if not start_url:
        receipt.add_action(
            "provider_pack.repair",
            "skipped",
            {"provider": pack.provider, "reason": "no provider repair URL"},
        )
        return False
    goal = _provider_repair_goal(pack, failed)
    try:
        events = _run_provider_repair_navigation(args, pack, vault, start_url, goal)
    except FuseKitError as exc:
        blocked_payload = {
            "provider": pack.provider,
            "status": "blocked",
            "error": _redact_cli_error(str(exc)),
        }
        audit.record("provider_pack.repair", blocked_payload)
        receipt.add_action("provider_pack.repair", "blocked", blocked_payload)
        return False
    payload: dict[str, object] = {
        "provider": pack.provider,
        "status": "attempted",
        "start_url": start_url,
        "events": [event.to_dict() for event in events],
    }
    audit.record("provider_pack.repair", payload)
    repair_ok = _repair_navigation_completed(events)
    receipt.add_action("provider_pack.repair", "attempted" if repair_ok else "blocked", payload)
    return repair_ok


def _repair_navigation_completed(events: list[BrowserPlaybookEvent]) -> bool:
    if any(event.status in {"blocked", "max-attempts", "failed"} for event in events):
        return False
    if any(
        event.action in {"gate", "human.takeover"} and event.status == "waiting"
        for event in events
    ):
        return False
    return any(event.action == "stop" and event.status == "done" for event in events)


def _redact_cli_error(text: str) -> str:
    patterns = (
        r"sk-[A-Za-z0-9_-]{12,}",
        r"sk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"pk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}",
        r"gh[pousr]_[A-Za-z0-9_]{12,}",
        r"github_pat_[A-Za-z0-9_]{12,}",
        r"whsec_[A-Za-z0-9_]{12,}",
        r"rk_[A-Za-z0-9_-]{12,}",
        r"re_[A-Za-z0-9_-]{12,}",
        r"plaid-[A-Za-z0-9_-]{12,}",
        r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}",
        r"\b[A-Za-z0-9_-]{36,}\b",
        r"([?&](?:token|key|secret|code|password|passphrase|signature)=)[^&#\s]+",
    )
    redacted = text
    for pattern in patterns:
        replacement = r"\1[redacted]" if pattern.startswith("([?&]") else "[redacted]"
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def _run_provider_repair_navigation(
    args: argparse.Namespace,
    pack: ProviderCapabilityPack,
    vault: Vault,
    start_url: str,
    goal: str,
) -> list[BrowserPlaybookEvent]:
    max_steps = max(1, int(getattr(args, "repair_ui_steps", 12)))
    if _use_playwright_browser_spine(args):
        spine = PlaywrightBrowserSpine(
            headless=_playwright_headless(args),
            dry_run=bool(getattr(args, "dry_run_spine", False)),
        )
        try:
            return run_inferred_navigation(
                provider=pack.provider,
                goal=goal,
                start_url=start_url,
                spine=spine,
                navigator=_ui_navigator_from_vault(args, vault),
                max_steps=max_steps,
                gate_retry_seconds=float(getattr(args, "gate_retry_seconds", 300.0)),
                max_gate_attempts=int(getattr(args, "gate_max_attempts", 0)),
                gate_recorder=_gate_recorder(args),
                gate_passed=_gate_passed_checker(args),
                provider_memory_path=_provider_memory_path(args, pack.provider),
            )
        finally:
            spine.close()
    openclaw_spine = OpenClawBrowserSpine(
        profile=getattr(args, "openclaw_profile", "openclaw"),
        dry_run=bool(getattr(args, "dry_run_spine", False)),
    )
    return run_inferred_navigation(
        provider=pack.provider,
        goal=goal,
        start_url=start_url,
        spine=openclaw_spine,
        navigator=_ui_navigator_from_vault(args, vault),
        max_steps=max_steps,
        gate_retry_seconds=float(getattr(args, "gate_retry_seconds", 300.0)),
        max_gate_attempts=int(getattr(args, "gate_max_attempts", 0)),
        gate_recorder=_gate_recorder(args),
        gate_passed=_gate_passed_checker(args),
        provider_memory_path=_provider_memory_path(args, pack.provider),
    )


def _provider_repair_start_url(pack: ProviderCapabilityPack) -> str:
    return (
        pack.handoff.project_url
        or pack.handoff.token_url
        or pack.handoff.login_url
        or pack.handoff.signup_url
    )


def _provider_repair_goal(
    pack: ProviderCapabilityPack,
    failed: list[VerificationResult],
) -> str:
    failures = [
        {
            "kind": result.kind,
            "target": result.target,
            "status": result.status,
            "details": result.to_dict().get("details", {}),
        }
        for result in failed
    ]
    return json.dumps(
        {
            "task": (
                "Repair only the missing provider setup needed for verification to pass. "
                "Use provider UI controls when safe, stop at service-created human gates, "
                "do not bypass MFA/CAPTCHA/passkeys/payment/fraud/consent, and do not type "
                "raw secrets except through approved hidden capture flows."
            ),
            "provider": pack.provider,
            "setup_goals": list(pack.setup_goals),
            "required_secrets": list(pack.required_secrets),
            "failed_verification": failures,
            "service_gates": list(pack.handoff.service_gates),
        },
        sort_keys=True,
    )


def _append_gitignore(path: Path) -> None:
    entries = [
        ".fusekit/*.vault.json",
        ".fusekit/*.vault",
        ".fusekit/audit*.jsonl",
        ".fusekit/*receipt*.json",
        ".fusekit/*receipt*.md",
        ".fusekit/worker/",
        ".fusekit/tmp/",
    ]
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    additions = [entry for entry in entries if entry not in existing]
    if additions:
        with path.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write("\n# FuseKit secret artifacts and worker state\n")
            for entry in additions:
                handle.write(f"{entry}\n")


def _rebase_setup_artifacts(args: argparse.Namespace, app_path: Path) -> None:
    fusekit_dir = app_path / ".fusekit"
    if args.vault == Path(".fusekit/fusekit.vault.json"):
        args.vault = fusekit_dir / "fusekit.vault.json"
    if args.audit_log == Path(".fusekit/audit.jsonl"):
        args.audit_log = fusekit_dir / "audit.jsonl"
    if args.receipt_json == Path(".fusekit/setup_receipt.json"):
        args.receipt_json = fusekit_dir / "setup_receipt.json"
    if args.receipt_md == Path(".fusekit/setup_receipt.md"):
        args.receipt_md = fusekit_dir / "setup_receipt.md"
    if args.rollback_json == Path(".fusekit/rollback_plan.json"):
        args.rollback_json = fusekit_dir / "rollback_plan.json"
    if args.verification_report == Path(".fusekit/verification_report.json"):
        args.verification_report = fusekit_dir / "verification_report.json"
    if getattr(args, "plan_json", None) == Path(".fusekit/setup_plan.json"):
        args.plan_json = fusekit_dir / "setup_plan.json"
    if getattr(args, "job_state", None) == Path(".fusekit/job.json"):
        args.job_state = fusekit_dir / "job.json"


def _capture_provider_tokens(vault: Vault, manifest: SetupManifest) -> None:
    app_path = Path(manifest.app_path)
    token_env_by_provider = _manifest_provider_token_envs(manifest, app_path)
    if manifest.domains:
        token_env_by_provider.setdefault("cloudflare", set()).add("CLOUDFLARE_API_TOKEN")
    for provider, env_names in sorted(token_env_by_provider.items()):
        for env_name in sorted(env_names):
            if not env_name:
                continue
            value = os.environ.get(env_name)
            if value:
                vault.put(
                    f"provider.{provider}.token",
                    "provider_token",
                    provider,
                    f"{provider} API token",
                    value,
                    {"source": f"env:{env_name}"},
                )
                break


def _manifest_provider_token_envs(
    manifest: SetupManifest,
    app_path: Path,
) -> dict[str, set[str]]:
    token_env_by_provider: dict[str, set[str]] = {
        "github": {"GITHUB_TOKEN"},
        "vercel": {"VERCEL_TOKEN"},
        "cloudflare": {"CLOUDFLARE_API_TOKEN"},
        "dns": {"CLOUDFLARE_API_TOKEN"},
    }
    for service in manifest.services:
        provider = service.provider.lower()
        envs = token_env_by_provider.setdefault(provider, set())
        handoff = _handoff_for_manifest_service(provider, service, app_path)
        if handoff is not None:
            envs.add(handoff.token_env)
        envs.update(
            name
            for name in service.secrets
            if any(marker in name for marker in ("TOKEN", "API_KEY", "SECRET_KEY"))
        )
    return token_env_by_provider


def _handoff_for_manifest_service(
    provider: str,
    service: ServiceRequirement,
    app_path: Path,
) -> ProviderHandoff | None:
    try:
        return handoff_for(provider)
    except FuseKitError:
        pass
    if "capability_pack" not in service.capabilities and not service.settings.get(
        "capability_pack"
    ):
        return None
    pack_hint = str(service.settings.get("capability_pack", ""))
    pack_path = Path(pack_hint) if pack_hint else pack_default_path(app_path, provider)
    if not pack_path.is_absolute():
        pack_path = app_path / pack_path
    if pack_path.exists():
        return handoff_from_provider_pack(load_provider_pack(pack_path))
    return handoff_from_provider_pack(synthesize_provider_pack(provider, app_path))


def _capture_manifest_provider_env(vault: Vault, manifest: SetupManifest) -> None:
    for service in manifest.services:
        provider = service.provider.lower()
        for env_name in sorted({*service.secrets, *service.env}):
            value = os.environ.get(env_name)
            if value:
                vault.put(
                    f"provider.{provider}.{env_name.lower()}",
                    "provider_secret",
                    provider,
                    env_name,
                    value,
                    {"source": f"env:{env_name}", "service": service.name},
                )


def _capture_llm(args: argparse.Namespace, vault: Vault, require: bool) -> None:
    config = _llm_config_from_args(args)
    api_key = None
    if not os.environ.get(config.api_key_env) and args.capture_llm_key:
        api_key = getpass.getpass(f"Paste {config.provider} LLM API key: ").strip()
    captured = capture_llm_config(vault, config, api_key=api_key)
    if captured:
        return
    mode = getattr(args, "llm_auth_mode", "auto")
    if mode in {"auto", "openclaw"} and require and _openclaw_llm_profile_available(
        vault,
        config,
    ):
        return
    if mode in {"auto", "openclaw"} and require:
        _await_openclaw_llm_authorization(args, vault, config)
        return
    if require:
        raise FuseKitError(
            f"LLM authorization is required. Set {config.api_key_env}, rerun with "
            "--capture-llm-key, or use --llm-auth-mode openclaw for the default "
            "OpenAI/OpenClaw human-gated authorization lane. OpenAI is the default, "
            "but --llm-provider, --llm-model, --llm-base-url, and --llm-api-key-env "
            "can target another LLM."
        )


def _llm_config_from_args(args: argparse.Namespace) -> LlmConfig:
    return LlmConfig(
        provider=args.llm_provider,
        model=args.llm_model,
        base_url=args.llm_base_url,
        api_key_env=args.llm_api_key_env,
    )


def _openclaw_llm_profile_available(vault: Vault, config: LlmConfig) -> bool:
    if not config.can_use_openclaw_auth():
        return False
    try:
        vault.require("llm.openai.openclaw_profile")
    except FuseKitError:
        return False
    return True


def _ui_navigator_from_vault(args: argparse.Namespace, vault: Vault) -> UiNavigator:
    config = _llm_config_from_args(args)
    try:
        vault.require(config.record_id)
    except FuseKitError:
        pass
    else:
        return OpenAiUiNavigator(config, vault)
    try:
        vault.require("llm.openai.openclaw_profile")
    except FuseKitError as exc:
        raise FuseKitError(
            f"UI inference needs {config.record_id} or an OpenClaw OAuth profile. "
            "Authorize OpenClaw/OpenAI or provide an LLM API key."
        ) from exc
    return StaticUiNavigator(
        [
            InferredUiAction(
                "gate",
                reason=(
                    "OpenClaw/OpenAI OAuth is authorized, but local OpenClaw model "
                    "inference is not available to FuseKit in this runtime. Follow "
                    "the visible provider checklist in the VM browser; FuseKit will "
                    "keep the gate durable and verify afterward."
                ),
            )
        ]
    )


def _await_openclaw_llm_authorization(
    args: argparse.Namespace,
    vault: Vault,
    config: LlmConfig,
) -> None:
    gate_id = "llm.openclaw-authorization"
    attempt = 0
    while True:
        attempt += 1
        try:
            result = authorize_openclaw_llm(
                vault,
                config,
                device_code=bool(getattr(args, "llm_openclaw_device_code", False)),
            )
        except FuseKitError as exc:
            resume_url, follow_steps = _openclaw_llm_auth_gate_handoff(
                args,
                config,
                exc,
                start_terminal=attempt == 1 and not _gate_record_exists(args, gate_id),
            )
            _record_gate_waiting(
                args,
                gate_id,
                provider=config.provider,
                reason="OpenAI/OpenClaw browser or device-code authorization",
                resume_url=resume_url,
                follow_steps=follow_steps,
                classification="interactive-terminal",
            )
            _ensure_gate_attempt_allowed(args, attempt, "OpenAI/OpenClaw LLM authorization")
            print(
                "Waiting for OpenAI/OpenClaw LLM authorization. Complete the OpenClaw "
                "browser/device-code login gate, then FuseKit will retry."
            )
            _sleep_for_gate(args, gate_id=gate_id)
            continue
        _record_gate_passed(
            args,
            gate_id,
            provider=config.provider,
            reason="OpenAI/OpenClaw browser or device-code authorization",
            resume_url=config.base_url,
        )
        print(
            "Captured OpenAI/OpenClaw LLM authorization into encrypted vault "
            f"({len(result.captured_state_files)} auth-state file(s))."
        )
        args._detonate_openclaw_state = True
        return


def _openclaw_llm_auth_gate_handoff(
    args: argparse.Namespace,
    config: LlmConfig,
    error: FuseKitError,
    *,
    start_terminal: bool = True,
) -> tuple[str, tuple[str, ...]]:
    visual = _current_visual_payload(args)
    novnc_url = str(visual.get("novnc_url", "") or "")
    provider = os.environ.get("FUSEKIT_OPENCLAW_LLM_AUTH_PROVIDER", "openai")
    device_code = bool(getattr(args, "llm_openclaw_device_code", False))
    terminal_started = False
    if start_terminal:
        terminal_started = _start_openclaw_auth_terminal(provider=provider, device_code=device_code)
    if terminal_started:
        return (
            novnc_url or config.base_url,
            (
                "Open the live VM browser.",
                "Enter the noVNC password if prompted.",
                (
                    "Use the visible FuseKit OpenClaw authorization terminal to complete "
                    "OpenAI login."
                ),
                (
                    "Leave the terminal open after it finishes; FuseKit retries this gate "
                    "automatically."
                ),
            ),
        )
    detail = str(error).strip()
    if "interactive TTY" in detail:
        return (
            novnc_url or config.base_url,
            (
                "Open the live VM browser if one is available.",
                (
                    "Open a terminal in the VM and run: openclaw models auth login "
                    "--provider openai --set-default"
                ),
                "FuseKit retries this gate automatically after the configured wait interval.",
            ),
        )
    return (
        config.base_url,
        (
            "Complete OpenClaw/OpenAI authorization, then leave FuseKit running.",
            "FuseKit retries this gate automatically after the configured wait interval.",
        ),
    )


def _current_visual_payload(args: argparse.Namespace) -> dict[str, Any]:
    path = _gate_state_path(args).parent / "visual.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _start_openclaw_auth_terminal(*, provider: str, device_code: bool) -> bool:
    display = os.environ.get("DISPLAY", "")
    openclaw = shutil.which("openclaw")
    if not display or not openclaw:
        return False
    state_home = openclaw_state_home()
    visual_dir = Path(os.environ.get("FUSEKIT_VISUAL_STATE_DIR", "/var/lib/fusekit-runner/visual"))
    script_log_path = visual_dir / "openclaw-auth-pty.log"
    xterm_log_path = visual_dir / "openclaw-auth-xterm.log"
    try:
        visual_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        visual_dir = Path(os.devnull)
        script_log_path = Path(os.devnull)
        xterm_log_path = Path(os.devnull)
    login_command = (
        f"OPENCLAW_HOME={shlex_quote(str(state_home))} "
        f"{shlex_quote(openclaw)} models auth login --provider {shlex_quote(provider)} "
        f"--set-default{' --device-code' if device_code else ''}"
    )
    env = {**os.environ, "DISPLAY": display, "OPENCLAW_HOME": str(state_home)}
    if _start_openclaw_auth_pty(
        login_command=login_command,
        log_path=script_log_path,
        env=env,
    ):
        _launch_visual_chrome_to_openclaw_auth(log_path=script_log_path, env=env)
        _start_openclaw_auth_tail_window(log_path=script_log_path, env=env)
        return True
    return _start_openclaw_auth_xterm(
        login_command=login_command,
        log_path=xterm_log_path,
        env=env,
    )


def _start_openclaw_auth_pty(
    *,
    login_command: str,
    log_path: Path,
    env: dict[str, str],
) -> bool:
    script_bin = shutil.which("script")
    if not script_bin:
        return False
    try:
        subprocess.Popen(
            [script_bin, "-qfec", login_command, str(log_path)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def _launch_visual_chrome_to_openclaw_auth(*, log_path: Path, env: dict[str, str]) -> bool:
    url = ""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            text = log_path.read_text(errors="ignore")
        except OSError:
            text = ""
        match = re.search(r"https://auth\.openai\.com/oauth/authorize[^\s\x1b]+", text)
        if match:
            url = match.group(0)
            break
        time.sleep(0.5)
    if not url:
        return False
    chrome = _visual_chrome_binary()
    if not chrome:
        return False
    try:
        subprocess.Popen(
            [
                str(chrome),
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--start-maximized",
                f"--user-data-dir={log_path.parent / 'chrome-auth-profile'}",
                url,
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def _visual_chrome_binary() -> Path | None:
    browser_root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""))
    candidates: list[Path] = []
    if browser_root:
        candidates.extend(browser_root.glob("chromium-*/chrome-linux*/chrome"))
        candidates.extend(browser_root.glob("chromium-*/chrome-linux64/chrome"))
    candidates.extend(Path("/opt/fusekit-playwright-browsers").glob("chromium-*/chrome-linux*/chrome"))
    candidates.extend(Path("/opt/fusekit-playwright-browsers").glob("chromium-*/chrome-linux64/chrome"))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _start_openclaw_auth_tail_window(*, log_path: Path, env: dict[str, str]) -> bool:
    xterm = shutil.which("xterm")
    if not xterm:
        return False
    tail_script = (
        "echo 'FuseKit OpenClaw/OpenAI authorization'; "
        "echo; "
        "echo 'FuseKit opened the OpenAI sign-in page in the VM browser.'; "
        "echo 'Finish sign-in there. This window mirrors the auth listener log.'; "
        "echo; "
        f"tail -f {shlex_quote(str(log_path))}; "
    )
    try:
        subprocess.Popen(
            [
                xterm,
                "-geometry",
                "132x36+80+80",
                "-fa",
                "Monospace",
                "-fs",
                "12",
                "-title",
                "FuseKit OpenClaw OpenAI Authorization",
                "-e",
                "bash",
                "-lc",
                tail_script,
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def _start_openclaw_auth_xterm(
    *,
    login_command: str,
    log_path: Path,
    env: dict[str, str],
) -> bool:
    xterm = shutil.which("xterm")
    if not xterm:
        return False
    script = (
        "echo 'FuseKit OpenClaw/OpenAI authorization'; "
        "echo; "
        "echo 'Complete the login shown here. When it finishes, leave this window open.'; "
        "echo; "
        f"{login_command}; "
        "status=$?; "
        "echo; "
        "echo \"Auth command exited with status $status\"; "
        "echo 'FuseKit will retry automatically. You can close this terminal after "
        "the gate passes.'; "
        "read -r -p 'Press Enter to close this terminal...' _; "
        "exit $status"
    )
    log_file = None
    stdout_target: Any = subprocess.DEVNULL
    try:
        log_file = log_path.open("ab")
        stdout_target = log_file
    except OSError:
        pass
    try:
        subprocess.Popen(
            [
                xterm,
                "-geometry",
                "132x36+80+80",
                "-fa",
                "Monospace",
                "-fs",
                "12",
                "-title",
                "FuseKit OpenClaw OpenAI Authorization",
                "-e",
                "bash",
                "-lc",
                script,
            ],
            env=env,
            stdout=stdout_target,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        if log_file is not None:
            log_file.close()
        return False
    if log_file is not None:
        log_file.close()
    return True


def shlex_quote(value: str) -> str:
    """Quote a value for the small VM-local shell handoff script."""

    return "'" + value.replace("'", "'\"'\"'") + "'"


def _provider_token(vault: Vault, provider: str, env_name: str) -> str:
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value
    return vault.require(f"provider.{provider}.token").value


def _passphrase(args: argparse.Namespace) -> str:
    cached = getattr(args, "_cached_passphrase", "")
    if cached:
        return str(cached)
    path = getattr(args, "passphrase_file", None)
    if path:
        return str(Path(path).read_text(encoding="utf-8")).strip()
    env = os.environ.get("FUSEKIT_PASSPHRASE")
    if env:
        return env
    return getpass.getpass("FuseKit vault passphrase: ")


def _optional_passphrase(args: argparse.Namespace) -> str | None:
    path = getattr(args, "passphrase_file", None)
    if path:
        return str(Path(path).read_text(encoding="utf-8")).strip()
    env = os.environ.get("FUSEKIT_PASSPHRASE")
    if env:
        return env
    return None


def _default_token_env(provider: str) -> str:
    return {
        "github": "GITHUB_TOKEN",
        "vercel": "VERCEL_TOKEN",
        "cloudflare": "CLOUDFLARE_API_TOKEN",
    }[provider]


def _print_handoff(handoff: ProviderHandoff, include_project: bool = False) -> None:
    guidance = provider_gate_guidance(handoff.provider)
    print(guidance.title)
    print(guidance.body)
    print("What you need to do:")
    for step in guidance.actions:
        print(f"- {step}")
    print(guidance.reassurance)
    print("FuseKit is asking the provider for only this access:")
    for scope in handoff.required_scopes:
        print(f"- {scope}")
    print("Provider pages FuseKit may open:")
    for url in handoff.urls(include_project=include_project):
        print(f"- {url}")


if __name__ == "__main__":
    raise SystemExit(main())
