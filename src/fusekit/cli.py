"""Command line entry point for FuseKit."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
import uuid
import webbrowser
from collections.abc import Callable
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
)
from fusekit.errors import ApprovalRequired, FuseKitError, ProviderError
from fusekit.harness import run_acceptance
from fusekit.llm import LlmConfig, authorize_openclaw_llm, capture_llm_config
from fusekit.manifest import ServiceRequirement, SetupManifest, load_manifest, write_manifest
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
from fusekit.runner import JobState, RunnerResolution, resolve_runner
from fusekit.runner.cloud_shell import build_cloud_shell_launch_plan, write_cloud_shell_launcher
from fusekit.runner.control_room import write_control_room
from fusekit.runner.gate_guidance import provider_gate_guidance
from fusekit.runner.gates import GateService
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
from fusekit.runner.run_state import LaunchRunState, update_run_state
from fusekit.runner.server import serve_control_room
from fusekit.runtime import bootstrap_runtime, doctor
from fusekit.runtime.bootstrap import openclaw_state_home
from fusekit.scanner import scan_repo
from fusekit.security import scan_for_secret_leaks
from fusekit.source import (
    fetch_github_source_archive,
    is_github_https_source,
    token_from_env,
)
from fusekit.spine import (
    BrowserPlaybookEvent,
    OpenAiUiNavigator,
    OpenClawBrowserSpine,
    PlaywrightBrowserSpine,
    execute_provider_ui_playbook,
    provider_authorization_playbook,
    provider_handoff_playbook,
    provider_ui_playbook,
    run_inferred_navigation,
)
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
        help="capture the approved provider token from a hidden prompt",
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
        help="capture approved provider secrets through hidden prompts by default",
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
        help="capture the LLM API key from a hidden prompt when it is not in env",
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
                "Sign in to GitHub.",
                "Install or authorize the FuseKit GitHub App for only the selected repository.",
                (
                    "Complete the highlighted GitHub passkey, MFA, CAPTCHA, organization, "
                    "or consent gate."
                ),
            ),
            secret_steps=(
                "Return the app-issued installation token or approved access token to FuseKit.",
                "FuseKit captures it through a hidden prompt or environment variable.",
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
    if args.handoff:
        _run_handoff(args, provider, handoff, include_project)

    token, source = _await_provider_token(args, provider, handoff, include_project)
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
        if not args.no_detonate:
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
        else:
            job.mark(
                "detonate.workspace",
                "skipped",
                "worker scratch state retained by --no-detonate",
            )
        _save_launch_job(args, job)
        return 0
    except FuseKitError:
        job.mark("setup.execute", "failed", "local setup worker did not complete")
        _save_launch_job(args, job)
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
    secrets = _collect_secrets(args.secret)
    secrets.update(_collect_manifest_env_secrets(manifest))

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

        if args.live_url:
            _verify_apply_live_url(args, audit, receipt, verification_report)

        _verify_provider_packs(args, manifest, vault, audit, receipt, verification_report)
        provider_checks_safe = verification_report_allows_detonation(
            verification_report.to_dict()
        )
        if hasattr(args, "job_state"):
            _mark_run_state(
                args,
                provider_checks_passed_or_pending_safe=provider_checks_safe,
            )
        if not provider_checks_safe and not args.allow_incomplete:
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
) -> None:
    url = str(args.live_url)
    try:
        result = verify_live_url(url)
    except ProviderError as exc:
        if not bool(getattr(args, "allow_incomplete", False)):
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
        job.mark("detonate.workspace", "done", f"{args.scope} detonation requested")
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
    return 0


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
            _sleep_for_gate(args)


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
        _sleep_for_gate(args)


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


def _save_launch_job(args: argparse.Namespace, job: JobState) -> None:
    """Persist job, checkpoints, and the static control room when requested."""

    args.job_state.parent.mkdir(parents=True, exist_ok=True)
    run_state_path = _run_state_path(args)
    if run_state_path.exists() and job.artifacts.get("run_state") != str(run_state_path):
        job.add_artifact("run_state", run_state_path)
    checkpoints_path = args.job_state.with_name("checkpoints.json")
    if job.artifacts.get("checkpoints") != str(checkpoints_path):
        job.add_artifact("checkpoints", checkpoints_path)
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
            job.mark("detonate.workspace", "done", "workspace detonation attempted after failure")
        else:
            job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
        _save_launch_job(args, job)
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
    if verification_report.exists():
        job.add_artifact("verification_report", verification_report)
        provider_checks_safe = _verification_report_path_allows_detonation(verification_report)
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
        provider_checks_passed_or_pending_safe=provider_checks_safe,
        receipt_written=receipt_path.exists(),
    )
    if not provider_checks_safe:
        job.mark(
            "verify.live",
            "failed",
            "remote verification did not reach a passed or pending-safe state",
        )
        if not args.no_detonate:
            remote_deleted = _detonate_oci_workspace(args, workspace, vault)
            job.mark(
                "detonate.workspace",
                "done",
                "workspace detonation attempted after failed verification",
            )
        else:
            job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
        _save_launch_job(args, job)
        raise FuseKitError(
            "Remote verification did not reach a passed or pending-safe state."
        )
    job.mark("verify.live", "done", "remote verification is passed or pending-safe")
    if args.no_detonate:
        job.mark("detonate.workspace", "skipped", "workspace retained by --no-detonate")
    else:
        _run_remote_detonation_preflight(args, Path(artifacts["output_dir"]))
        _mark_run_state(args, detonation_safe=True)
        remote_deleted = _detonate_oci_workspace(args, workspace, vault)
        job.mark("detonate.workspace", "done", "remote worker and OCI workspace detonated")
    _save_launch_job(args, job)
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
    for service in manifest.services:
        for name in service.secrets:
            value = os.environ.get(name)
            if value:
                secrets[name] = value
    return secrets


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
                    navigator=OpenAiUiNavigator(_llm_config_from_args(args), vault),
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
                navigator=OpenAiUiNavigator(_llm_config_from_args(args), vault),
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
) -> None:
    GateService.load(_gate_state_path(args)).wait(
        gate_id,
        provider=provider,
        reason=reason,
        resume_url=resume_url,
        classification=classification,
        target=target,
        follow_steps=follow_steps,
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
        return bool(record and record.status == "passed")

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
) -> tuple[str, str]:
    token_env = args.token_env or handoff.token_env
    gate_id = f"provider.{provider}.authorization"
    resume_url = handoff.token_url or handoff.signup_url
    attempt = 0
    while True:
        attempt += 1
        token = os.environ.get(token_env)
        source = f"env:{token_env}"
        if not token and args.capture_stdin:
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
        )
        _ensure_gate_attempt_allowed(args, attempt, f"{provider} authorization")
        guidance = provider_gate_guidance(provider)
        print(
            f"Waiting: {guidance.title}. {guidance.reassurance} "
            f"When the provider reveals the approved key, provide {token_env}. "
            "Retrying handoff..."
        )
        _sleep_for_gate(args)
        _run_handoff(args, provider, handoff, include_project, goal=goal)


def _await_plan_approval(args: argparse.Namespace) -> None:
    gate_id = "fusekit.plan-approval"
    attempt = 0
    while True:
        attempt += 1
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
        )
        _ensure_gate_attempt_allowed(args, attempt, "setup plan approval")
        print("Waiting for setup plan approval. FuseKit will keep this launch alive.")
        _sleep_for_gate(args)


def _await_dns_approval(args: argparse.Namespace, domain: str) -> None:
    gate_id = f"dns.{domain}.approval"
    attempt = 0
    while True:
        attempt += 1
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
        )
        _ensure_gate_attempt_allowed(args, attempt, f"DNS approval for {domain}")
        print(f"Waiting for DNS approval for {domain}. FuseKit will retry this gate.")
        _sleep_for_gate(args)


def _ensure_gate_attempt_allowed(args: argparse.Namespace, attempt: int, label: str) -> None:
    max_attempts = int(getattr(args, "gate_max_attempts", 0))
    if max_attempts and attempt >= max_attempts:
        raise ApprovalRequired(f"{label} was not passed after {attempt} attempt(s).")


def _sleep_for_gate(args: argparse.Namespace) -> None:
    retry_seconds = float(getattr(args, "gate_retry_seconds", 300.0))
    if retry_seconds > 0:
        time.sleep(retry_seconds)


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
    for provider, service in sorted(providers.items()):
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
        _record_provider_strategy_gates(args, pack, result)
        context.audit.record("provider_pack.setup", result)
        context.receipt.add_action("provider_pack.setup", "ok", result)
    if not strategy_runs:
        _write_provider_strategy_artifact(args, strategy_runs)


def _provider_strategy_record(result: dict[str, Any]) -> dict[str, object]:
    strategies: list[dict[str, object]] = []
    for item in result.get("setup", []):
        if not isinstance(item, dict):
            continue
        decision = item.get("strategy_decision")
        if not isinstance(decision, dict):
            continue
        selected = decision.get("selected", {})
        strategies.append(
            {
                "recipe": str(item.get("kind", decision.get("recipe_kind", ""))),
                "status": str(item.get("status", "")),
                "strategy": str(item.get("strategy", selected.get("kind", "")))
                if isinstance(selected, dict)
                else str(item.get("strategy", "")),
                "decision": decision,
            }
        )
    return {"provider": str(result.get("provider", "")), "strategies": strategies}


def _record_provider_strategy_gates(
    args: argparse.Namespace,
    pack: ProviderCapabilityPack,
    result: dict[str, Any],
) -> None:
    provider = str(result.get("provider", pack.provider)).lower()
    follow_steps = _provider_strategy_follow_steps(pack)
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
        resume_url = default_resume_url or _provider_strategy_decision_url(item)
        gate_id = f"provider.{provider}.{_strategy_gate_slug(recipe)}"
        _record_gate_waiting(
            args,
            gate_id,
            provider=provider,
            reason=reason,
            resume_url=resume_url,
            classification="provider-authorization",
            follow_steps=follow_steps,
        )


def _provider_strategy_follow_steps(pack: ProviderCapabilityPack) -> tuple[str, ...]:
    steps = tuple(
        step
        for step in (*pack.handoff.account_steps, *pack.handoff.secret_steps)
        if step.strip()
    )
    if steps:
        return steps
    return (
        f"Open the {pack.display_name} provider gate.",
        "Complete provider-owned login, MFA, CAPTCHA, consent, billing, or verification steps.",
        "Return to FuseKit and mark the gate finished once the approved capability exists.",
    )


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
        "providers": strategy_runs,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


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
    services = list(manifest.services)
    has_dns_service = any(service.provider in {"cloudflare", "dns"} for service in services)
    if manifest.domains and not has_dns_service:
        services.append(
            ServiceRequirement(
                provider="cloudflare",
                kind="dns",
                name="dns",
                capabilities=("capability_pack", "dns"),
                settings={"capability_pack": str(pack_default_path(app_path, "cloudflare"))},
            )
        )
    for service in services:
        provider = service.provider.lower()
        pack_path = _provider_pack_path(app_path, provider, service)
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        pack = load_provider_pack(pack_path)
        results = verify_provider_pack(
            pack,
            vault,
            live_url=getattr(args, "live_url", ""),
            inputs=_verification_inputs(args, manifest),
            attempts=int(getattr(args, "verify_attempts", 1)),
            retry_seconds=float(getattr(args, "verify_retry_seconds", 0.0)),
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


def _verification_inputs(args: argparse.Namespace, manifest: SetupManifest) -> dict[str, str]:
    inputs = _provider_setup_inputs(args)
    provider_names = _required_providers(manifest)
    app_env_names = _app_env_names_for_verification(manifest, provider_names)
    default_domain = _default_manifest_domain(manifest)
    records = [
        {
            "name": record.name,
            "type": record.type,
            "value": record.value,
        }
        for domain in manifest.domains
        for record in domain.records
    ]
    inputs.update(
        {
            "app_env_names": ",".join(app_env_names),
            "dns_records_json": json.dumps(records, sort_keys=True),
            "resend_domain": default_domain,
        }
    )
    return inputs


def _rerun_provider_verification(
    args: argparse.Namespace,
    manifest: SetupManifest,
    pack: ProviderCapabilityPack,
    vault: Vault,
) -> list[VerificationResult]:
    return verify_provider_pack(
        pack,
        vault,
        live_url=getattr(args, "live_url", ""),
        inputs=_verification_inputs(args, manifest),
        attempts=int(getattr(args, "verify_attempts", 1)),
        retry_seconds=float(getattr(args, "verify_retry_seconds", 0.0)),
    )


def _provider_verification_acceptable(results: list[VerificationResult]) -> bool:
    return all(
        result.status in {"ok", "skipped"}
        or (
            result.status == "pending"
            and bool(result.to_dict().get("details", {}).get("pending_safe"))
        )
        for result in results
    )


def _provider_verification_overall(results: list[VerificationResult]) -> str:
    if all(result.status in {"ok", "skipped"} for result in results):
        return "ok"
    if _provider_verification_acceptable(results):
        return "pending-safe"
    if any(result.status == "needs_human_gate" for result in results):
        return "needs_human_gate"
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
    vault: Vault,
    audit: AuditLog,
    receipt: Receipt,
) -> bool:
    """Retry provider-native setup when UI repair is stuck and a token exists."""

    if not _has_pack_provider_token(pack, vault):
        receipt.add_action(
            "provider_pack.api_fallback",
            "skipped",
            {"provider": pack.provider, "reason": "provider token is not available"},
        )
        return False
    try:
        context = ProviderSetupContext(
            manifest=manifest,
            vault=vault,
            audit=audit,
            receipt=receipt,
            secrets={
                **_collect_secrets(getattr(args, "secret", [])),
                **_collect_manifest_env_secrets(manifest),
            },
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
        return False
    payload = {"provider": pack.provider, "status": "attempted", "result": result}
    audit.record("provider_pack.api_fallback", payload)
    receipt.add_action("provider_pack.api_fallback", "attempted", payload)
    return True


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
                navigator=OpenAiUiNavigator(_llm_config_from_args(args), vault),
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
        navigator=OpenAiUiNavigator(_llm_config_from_args(args), vault),
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
        for env_name in service.secrets:
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
        except FuseKitError:
            _record_gate_waiting(
                args,
                gate_id,
                provider=config.provider,
                reason="OpenAI/OpenClaw browser or device-code authorization",
                resume_url=config.base_url,
            )
            _ensure_gate_attempt_allowed(args, attempt, "OpenAI/OpenClaw LLM authorization")
            print(
                "Waiting for OpenAI/OpenClaw LLM authorization. Complete the OpenClaw "
                "browser/device-code login gate, then FuseKit will retry."
            )
            _sleep_for_gate(args)
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
