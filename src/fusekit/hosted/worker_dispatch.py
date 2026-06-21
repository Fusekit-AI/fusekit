"""Hosted worker dispatch receiver."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from wsgiref.simple_server import make_server

from fusekit.errors import FuseKitError

HOSTED_WORKER_DISPATCH_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch.v1"
HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch-receipt.v1"

StartResponse = Callable[[str, list[tuple[str, str]]], object]


class WorkerSpawner(Protocol):
    """Spawn a hosted worker command without waiting for completion."""

    def __call__(self, args: tuple[str, ...], env: dict[str, str]) -> object: ...


@dataclass(frozen=True)
class HostedWorkerDispatchSettings:
    """Settings for the hosted worker dispatch receiver."""

    worker_secret: str = ""
    worker_id: str = "hosted-worker-dispatch"
    workspace: Path | None = None
    spawner: WorkerSpawner | None = None

    @classmethod
    def from_env(cls) -> HostedWorkerDispatchSettings:
        """Load dispatch receiver settings from environment variables."""

        workspace = os.environ.get("FUSEKIT_HOSTED_WORKER_WORKSPACE", "")
        return cls(
            worker_secret=os.environ.get("FUSEKIT_HOSTED_WORKER_SECRET", ""),
            worker_id=os.environ.get("FUSEKIT_HOSTED_WORKER_ID", "hosted-worker-dispatch"),
            workspace=Path(workspace) if workspace else None,
        )


@dataclass(frozen=True)
class HostedWorkerDispatch:
    """Verified worker dispatch request."""

    action: str
    origin: str
    job_id: str
    job_token: str

    def command(self, settings: HostedWorkerDispatchSettings) -> tuple[str, ...]:
        """Build the private worker command. The worker secret stays in env."""

        args: tuple[str, ...] = (
            "fusekit-hosted-worker",
            "--origin",
            self.origin,
            "--job-id",
            self.job_id,
            "--action",
            self.action,
            "--worker-id",
            settings.worker_id,
        )
        if settings.workspace is not None:
            args += ("--workspace", str(settings.workspace))
        return args

    def public_command(self, settings: HostedWorkerDispatchSettings) -> list[str]:
        """Return a command label safe for receipts and logs."""

        return [
            "<fusekit-hosted-worker>",
            "--origin",
            self.origin,
            "--job-id",
            self.job_id,
            "--action",
            self.action,
            "--worker-id",
            settings.worker_id,
        ]


def application(
    environ: dict[str, object],
    start_response: StartResponse,
) -> Iterable[bytes]:
    """WSGI application for a hosted worker dispatch service."""

    return hosted_worker_dispatch_application(HostedWorkerDispatchSettings.from_env())(
        environ,
        start_response,
    )


def hosted_worker_dispatch_application(
    settings: HostedWorkerDispatchSettings,
) -> Callable[[dict[str, object], StartResponse], Iterable[bytes]]:
    """Build a configured WSGI dispatch receiver."""

    def app(environ: dict[str, object], start_response: StartResponse) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/") or "/")
        if path == "/healthz" and method == "GET":
            return _response(start_response, 200, {"ok": True})
        if path != "/dispatch":
            return _response(start_response, 404, {"error": "not_found"})
        if method != "POST":
            return _response(start_response, 405, {"error": "method_not_allowed"})
        try:
            dispatch = _verified_dispatch_from_wsgi(environ, settings=settings)
            receipt = accept_hosted_worker_dispatch(dispatch, settings=settings)
        except FuseKitError as exc:
            return _response(start_response, 400, {"error": str(exc)})
        return _response(start_response, 202, receipt)

    return app


def accept_hosted_worker_dispatch(
    dispatch: HostedWorkerDispatch,
    *,
    settings: HostedWorkerDispatchSettings,
) -> dict[str, object]:
    """Start the requested hosted worker and return a redacted dispatch receipt."""

    if len(settings.worker_secret) < 16:
        raise FuseKitError("hosted_worker_secret_required")
    args = dispatch.command(settings)
    env = dict(os.environ)
    env["FUSEKIT_HOSTED_WORKER_SECRET"] = settings.worker_secret
    env["FUSEKIT_HOSTED_JOB_TOKEN"] = dispatch.job_token
    spawner = settings.spawner or _spawn_worker
    spawned = spawner(args, env)
    return {
        "schema_version": HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
        "accepted": True,
        "action": dispatch.action,
        "job_id": dispatch.job_id,
        "worker_id": settings.worker_id,
        "worker_command": dispatch.public_command(settings),
        "spawned": _public_spawn_label(spawned),
        "secret_boundary": (
            "Dispatch receipts omit job tokens, worker secrets, HMAC signatures, "
            "provider credentials, GitHub installation tokens, and vault material."
        ),
    }


def verify_hosted_worker_dispatch(
    raw_body: bytes,
    *,
    signature: str,
    schema: str,
    secret: str,
) -> HostedWorkerDispatch:
    """Verify a signed dispatch envelope and return the private dispatch request."""

    if schema != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        raise FuseKitError("unsupported_dispatch_schema")
    if len(secret) < 16:
        raise FuseKitError("hosted_worker_secret_required")
    expected = _dispatch_signature(secret, raw_body)
    if not hmac.compare_digest(signature, expected):
        raise FuseKitError("invalid_dispatch_signature")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("invalid_dispatch_json") from exc
    if not isinstance(payload, dict):
        raise FuseKitError("invalid_dispatch_json")
    if payload.get("schema_version") != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        raise FuseKitError("unsupported_dispatch_schema")
    action = _required_str(payload, "action")
    origin = _required_str(payload, "origin")
    job_id = _required_str(payload, "job_id")
    job_token = _required_str(payload, "job_token")
    if action not in {"start", "rollback", "detonate"}:
        raise FuseKitError("unsupported_dispatch_action")
    if not _valid_https_origin(origin):
        raise FuseKitError("invalid_dispatch_origin")
    if not job_id.startswith("hosted-"):
        raise FuseKitError("invalid_dispatch_job_id")
    return HostedWorkerDispatch(
        action=action,
        origin=origin,
        job_id=job_id,
        job_token=job_token,
    )


def _verified_dispatch_from_wsgi(
    environ: dict[str, object],
    *,
    settings: HostedWorkerDispatchSettings,
) -> HostedWorkerDispatch:
    raw = _request_body(environ)
    signature = str(environ.get("HTTP_X_FUSEKIT_DISPATCH_SIGNATURE", ""))
    schema = str(environ.get("HTTP_X_FUSEKIT_DISPATCH_SCHEMA", ""))
    return verify_hosted_worker_dispatch(
        raw,
        signature=signature,
        schema=schema,
        secret=settings.worker_secret,
    )


def _request_body(environ: dict[str, object]) -> bytes:
    try:
        length = int(str(environ.get("CONTENT_LENGTH", "0") or "0"))
    except ValueError as exc:
        raise FuseKitError("invalid_content_length") from exc
    body = environ.get("wsgi.input")
    if not hasattr(body, "read"):
        raise FuseKitError("missing_request_body")
    raw = cast(Any, body).read(max(length, 0))
    return cast(bytes, raw)


def _dispatch_signature(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise FuseKitError(f"missing_dispatch_{key}")
    return value


def _valid_https_origin(value: str) -> bool:
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


def _spawn_worker(args: tuple[str, ...], env: dict[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(args, env=env)


def _public_spawn_label(spawned: object) -> dict[str, object]:
    pid = getattr(spawned, "pid", None)
    return {"pid": pid if isinstance(pid, int) and pid > 0 else None}


def _response(
    start_response: StartResponse,
    status: int,
    payload: dict[str, object],
) -> Iterable[bytes]:
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    reason = {
        200: "OK",
        202: "Accepted",
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
    }.get(status, "OK")
    start_response(
        f"{status} {reason}",
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Content-Length", str(len(raw))),
        ],
    )
    return [raw]


def main(argv: list[str] | None = None) -> int:
    """Run a local hosted worker dispatch receiver."""

    parser = argparse.ArgumentParser(description="Run FuseKit hosted worker dispatch server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    app = hosted_worker_dispatch_application(HostedWorkerDispatchSettings.from_env())
    with make_server(args.host, args.port, app) as server:
        print(f"Serving FuseKit hosted worker dispatch on http://{args.host}:{args.port}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
