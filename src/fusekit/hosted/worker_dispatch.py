"""Hosted worker dispatch receiver."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import subprocess
import threading
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from wsgiref.simple_server import make_server

from fusekit.errors import FuseKitError

HOSTED_WORKER_DISPATCH_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch.v1"
HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch-receipt.v1"
HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch-readiness.v1"
HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES = 16_384
HOSTED_WORKER_DISPATCH_BINDING_FIELDS = (
    "job_id",
    "action",
    "lane",
    "payment_status",
    "plan_fingerprint",
    "stripe_price_id_hash",
    "price_label_hash",
)
HOSTED_WORKER_DISPATCH_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "action",
        "origin",
        "job_id",
        "job_token",
        "dispatch_binding",
        "worker_command",
        "worker_request_url",
        "secret_boundary",
    }
)

StartResponse = Callable[[str, list[tuple[str, str]]], object]


class WorkerSpawner(Protocol):
    """Spawn a hosted worker command without waiting for completion."""

    def __call__(self, args: tuple[str, ...], env: dict[str, str]) -> object: ...


_DISPATCH_LOCK = threading.Lock()
_ACCEPTED_DISPATCHES: set[tuple[str, str, str]] = set()


@dataclass(frozen=True)
class HostedWorkerDispatchSettings:
    """Settings for the hosted worker dispatch receiver."""

    worker_secret: str = ""
    worker_id: str = "hosted-worker-dispatch"
    workspace: Path | None = None
    dispatch_state_dir: Path | None = None
    spawner: WorkerSpawner | None = None

    @classmethod
    def from_env(cls) -> HostedWorkerDispatchSettings:
        """Load dispatch receiver settings from environment variables."""

        workspace = os.environ.get("FUSEKIT_HOSTED_WORKER_WORKSPACE", "")
        state_dir = os.environ.get("FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR", "")
        return cls(
            worker_secret=os.environ.get("FUSEKIT_HOSTED_WORKER_SECRET", ""),
            worker_id=os.environ.get("FUSEKIT_HOSTED_WORKER_ID", "hosted-worker-dispatch"),
            workspace=Path(workspace) if workspace else None,
            dispatch_state_dir=Path(state_dir) if state_dir else None,
        )

    def readiness(self) -> dict[str, object]:
        """Return public, redacted dispatch receiver readiness metadata."""

        idempotency = self.idempotency_contract()
        configured = {
            "FUSEKIT_HOSTED_WORKER_SECRET": bool(self.worker_secret),
            "FUSEKIT_HOSTED_WORKER_ID": bool(self.worker_id),
            "FUSEKIT_HOSTED_WORKER_WORKSPACE": self.workspace is not None,
            "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR": self.dispatch_state_dir is not None,
        }
        invalid = []
        if self.worker_secret and len(self.worker_secret) < 16:
            invalid.append("hosted_worker_secret_too_short")
        if not self.worker_id:
            invalid.append("hosted_worker_id_required")
        idempotency_ready = idempotency.get("ready") is True
        return {
            "schema_version": HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION,
            "ready": bool(self.worker_secret) and bool(self.worker_id) and not invalid,
            "production_ready": (
                bool(self.worker_secret)
                and bool(self.worker_id)
                and not invalid
                and idempotency["durable"] is True
                and idempotency_ready
            ),
            "configured": configured,
            "invalid": invalid,
            "dispatch_binding": {
                "required": True,
                "required_fields": list(HOSTED_WORKER_DISPATCH_BINDING_FIELDS),
                "required_for_actions": ["start", "rollback", "detonate"],
                "lane": "managed-fusekit-run",
                "payment_status": "paid",
                "hash_fields": [
                    "plan_fingerprint",
                    "stripe_price_id_hash",
                    "price_label_hash",
                ],
                "secret_boundary": (
                    "Dispatch binding contains only public job/action/lane/payment labels "
                    "and SHA-256 public hashes; job tokens and worker secrets are excluded."
                ),
            },
            "idempotency": idempotency,
            "optional_runtime_env": [
                "FUSEKIT_HOSTED_WORKER_WORKSPACE",
                "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR",
            ],
            "required_runtime_env": [
                "FUSEKIT_HOSTED_WORKER_SECRET",
                "FUSEKIT_HOSTED_WORKER_ID",
            ],
            "secret_boundary": (
                "Dispatch readiness reports only configuration presence and shape errors. "
                "It never renders worker secrets, signed job tokens, HMAC signatures, "
                "provider credentials, GitHub installation tokens, or vault material."
            ),
        }

    def idempotency_contract(self) -> dict[str, object]:
        """Return public dispatch idempotency metadata without exposing paths."""

        if self.dispatch_state_dir is not None:
            metadata = _dispatch_state_metadata(self.dispatch_state_dir)
            return {
                "mode": "dispatch-state-dir",
                "durable": True,
                "ready": metadata["ready"],
                "scope": "worker deployment",
                "storage": metadata["public"],
                "blockers": metadata["blockers"],
                "proof": (
                    "Duplicate job/action dispatches are reserved through a configured "
                    "private non-secret state directory before worker spawn."
                ),
            }
        if self.workspace is not None:
            metadata = _dispatch_state_metadata(self.workspace)
            return {
                "mode": "workspace",
                "durable": True,
                "ready": metadata["ready"],
                "scope": "worker workspace",
                "storage": metadata["public"],
                "blockers": metadata["blockers"],
                "proof": (
                    "Duplicate job/action dispatches are reserved through a non-secret "
                    "marker in a private worker workspace before worker spawn."
                ),
            }
        return {
            "mode": "process",
            "durable": False,
            "ready": False,
            "scope": "single receiver process",
            "storage": {
                "exists": False,
                "directory": False,
                "symlink": False,
                "mode": "",
                "private_enough": False,
                "writable": False,
            },
            "blockers": ["worker_dispatch_durable_state_dir_required"],
            "proof": (
                "Duplicate job/action dispatches are guarded in process only; configure "
                "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR or FUSEKIT_HOSTED_WORKER_WORKSPACE "
                "for production."
            ),
        }


@dataclass(frozen=True)
class HostedWorkerDispatch:
    """Verified worker dispatch request."""

    action: str
    origin: str
    job_id: str
    job_token: str
    dispatch_binding: dict[str, str]

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
        if path == "/readiness" and method == "GET":
            return _response(start_response, 200, settings.readiness())
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
    reservation = _reserve_dispatch(dispatch, settings=settings)
    if reservation["duplicate"]:
        return {
            "schema_version": HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
            "accepted": True,
            "duplicate": True,
            "action": dispatch.action,
            "job_id": dispatch.job_id,
            "dispatch_binding": dispatch.dispatch_binding,
            "worker_id": settings.worker_id,
            "worker_command": dispatch.public_command(settings),
            "spawned": {"pid": None},
            "idempotency": reservation,
            "secret_boundary": (
                "Dispatch receipts omit job tokens, worker secrets, HMAC signatures, "
                "provider credentials, GitHub installation tokens, and vault material."
            ),
        }
    args = dispatch.command(settings)
    env = dict(os.environ)
    env["FUSEKIT_HOSTED_WORKER_SECRET"] = settings.worker_secret
    env["FUSEKIT_HOSTED_JOB_TOKEN"] = dispatch.job_token
    spawner = settings.spawner or _spawn_worker
    spawned = spawner(args, env)
    return {
        "schema_version": HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
        "accepted": True,
        "duplicate": False,
        "action": dispatch.action,
        "job_id": dispatch.job_id,
        "dispatch_binding": dispatch.dispatch_binding,
        "worker_id": settings.worker_id,
        "worker_command": dispatch.public_command(settings),
        "spawned": _public_spawn_label(spawned),
        "idempotency": reservation,
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
    if len(raw_body) > HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES:
        raise FuseKitError("dispatch_body_too_large")
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
    unexpected = sorted(
        str(key) for key in payload if key not in HOSTED_WORKER_DISPATCH_ENVELOPE_FIELDS
    )
    if unexpected:
        raise FuseKitError("unexpected_dispatch_field")
    if payload.get("schema_version") != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        raise FuseKitError("unsupported_dispatch_schema")
    action = _required_str(payload, "action")
    origin = _required_str(payload, "origin")
    job_id = _required_str(payload, "job_id")
    job_token = _required_str(payload, "job_token")
    dispatch_binding = _dispatch_binding_from_payload(payload, action=action, job_id=job_id)
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
        dispatch_binding=dispatch_binding,
    )


def _reserve_dispatch(
    dispatch: HostedWorkerDispatch,
    *,
    settings: HostedWorkerDispatchSettings,
) -> dict[str, object]:
    key = (dispatch.origin, dispatch.job_id, dispatch.action)
    state_dir = settings.dispatch_state_dir or (
        settings.workspace / ".fusekit/hosted-worker-dispatches"
        if settings.workspace is not None
        else None
    )
    if state_dir is None:
        with _DISPATCH_LOCK:
            duplicate = key in _ACCEPTED_DISPATCHES
            if not duplicate:
                _ACCEPTED_DISPATCHES.add(key)
        return {
            "mode": "process",
            "durable": False,
            "scope": "process",
            "duplicate": duplicate,
            "proof": "in-process dispatch guard accepted this job/action once.",
        }
    mode = "dispatch-state-dir" if settings.dispatch_state_dir is not None else "workspace"
    scope = "worker deployment" if mode == "dispatch-state-dir" else "worker workspace"
    proof = (
        "non-secret worker dispatch marker recorded in the configured state directory "
        "before worker spawn."
        if mode == "dispatch-state-dir"
        else (
            "non-secret worker dispatch marker recorded in the worker workspace "
            "before worker spawn."
        )
    )
    digest = hashlib.sha256(
        f"{dispatch.origin}:{dispatch.job_id}:{dispatch.action}".encode()
    ).hexdigest()
    path = state_dir / f"{digest}.json"
    try:
        _prepare_dispatch_state_dir(state_dir)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        with os.fdopen(os.open(path, flags, 0o640), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema_version": HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
                    "origin": dispatch.origin,
                    "job_id": dispatch.job_id,
                    "action": dispatch.action,
                    "dispatch_binding": dispatch.dispatch_binding,
                    "worker_id": settings.worker_id,
                },
                handle,
                sort_keys=True,
            )
            handle.write("\n")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    except FileExistsError:
        if not _dispatch_marker_matches(path, dispatch=dispatch, settings=settings):
            raise FuseKitError("hosted_worker_dispatch_marker_mismatch") from None
        duplicate = True
    except OSError as exc:
        raise FuseKitError("hosted_worker_dispatch_state_unavailable") from exc
    else:
        duplicate = False
    return {
        "mode": mode,
        "durable": True,
        "scope": scope,
        "duplicate": duplicate,
        "proof": proof,
    }


def _dispatch_marker_matches(
    path: Path,
    *,
    dispatch: HostedWorkerDispatch,
    settings: HostedWorkerDispatchSettings,
) -> bool:
    try:
        marker_stat = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(marker_stat.st_mode) or stat.S_ISLNK(marker_stat.st_mode):
        return False
    if marker_stat.st_size > HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES:
        return False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, flags)
    except OSError:
        return False
    try:
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            marker = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
    if not isinstance(marker, dict):
        return False
    return (
        marker.get("schema_version") == HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION
        and marker.get("origin") == dispatch.origin
        and marker.get("job_id") == dispatch.job_id
        and marker.get("action") == dispatch.action
        and marker.get("dispatch_binding") == dispatch.dispatch_binding
        and marker.get("worker_id") == settings.worker_id
    )


def _prepare_dispatch_state_dir(path: Path) -> None:
    path.mkdir(mode=0o750, parents=True, exist_ok=True)
    metadata = _dispatch_state_metadata(path)
    if metadata["ready"] is not True:
        raise FuseKitError("hosted_worker_dispatch_state_unavailable")


def _dispatch_state_metadata(path: Path) -> dict[str, object]:
    blockers: list[str] = []
    public: dict[str, object] = {
        "exists": False,
        "directory": False,
        "symlink": False,
        "mode": "",
        "private_enough": False,
        "writable": False,
    }
    try:
        path_stat = path.lstat()
    except OSError:
        blockers.append("worker_dispatch_state_dir_missing")
        return {"ready": False, "public": public, "blockers": blockers}
    mode = stat.S_IMODE(path_stat.st_mode)
    public["exists"] = True
    public["directory"] = stat.S_ISDIR(path_stat.st_mode)
    public["symlink"] = stat.S_ISLNK(path_stat.st_mode)
    public["mode"] = f"{mode:04o}"
    public["private_enough"] = (
        stat.S_ISDIR(path_stat.st_mode)
        and not stat.S_ISLNK(path_stat.st_mode)
        and mode & (stat.S_IWGRP | stat.S_IRWXO) == 0
    )
    public["writable"] = os.access(path, os.W_OK)
    if public["symlink"] is True:
        blockers.append("worker_dispatch_state_dir_must_not_be_symlink")
    if public["directory"] is not True:
        blockers.append("worker_dispatch_state_dir_must_be_directory")
    if public["private_enough"] is not True:
        blockers.append("worker_dispatch_state_dir_not_private_enough")
    if public["writable"] is not True:
        blockers.append("worker_dispatch_state_dir_not_writable")
    return {"ready": not blockers, "public": public, "blockers": blockers}


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
    if length < 0:
        raise FuseKitError("invalid_content_length")
    if length > HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES:
        raise FuseKitError("dispatch_body_too_large")
    body = environ.get("wsgi.input")
    if not hasattr(body, "read"):
        raise FuseKitError("missing_request_body")
    raw = cast(Any, body).read(length)
    if not isinstance(raw, bytes):
        raise FuseKitError("invalid_request_body")
    if len(raw) != length:
        raise FuseKitError("incomplete_request_body")
    return raw


def _dispatch_signature(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise FuseKitError(f"missing_dispatch_{key}")
    return value


def _dispatch_binding_from_payload(
    payload: dict[str, Any],
    *,
    action: str,
    job_id: str,
) -> dict[str, str]:
    value = payload.get("dispatch_binding")
    if not isinstance(value, dict):
        raise FuseKitError("missing_dispatch_binding")
    unexpected = sorted(
        str(key) for key in value if key not in HOSTED_WORKER_DISPATCH_BINDING_FIELDS
    )
    if unexpected:
        raise FuseKitError("unexpected_dispatch_binding_field")
    binding: dict[str, str] = {}
    for key in HOSTED_WORKER_DISPATCH_BINDING_FIELDS:
        raw = value.get(key)
        if not isinstance(raw, str) or not raw:
            raise FuseKitError(f"missing_dispatch_binding_{key}")
        if len(raw) > 256 or not all(ch.isprintable() for ch in raw):
            raise FuseKitError(f"invalid_dispatch_binding_{key}")
        binding[key] = raw
    if binding["job_id"] != job_id:
        raise FuseKitError("dispatch_binding_job_id_mismatch")
    if binding["action"] != action:
        raise FuseKitError("dispatch_binding_action_mismatch")
    if binding["lane"] != "managed-fusekit-run":
        raise FuseKitError("dispatch_binding_lane_mismatch")
    if binding["payment_status"] != "paid":
        raise FuseKitError("dispatch_binding_payment_not_paid")
    if not _valid_sha256_label(binding["plan_fingerprint"]):
        raise FuseKitError("invalid_dispatch_binding_plan_fingerprint")
    if not _valid_sha256_label(binding["stripe_price_id_hash"]):
        raise FuseKitError("invalid_dispatch_binding_stripe_price_id_hash")
    if not _valid_sha256_label(binding["price_label_hash"]):
        raise FuseKitError("invalid_dispatch_binding_price_label_hash")
    return {key: binding[key] for key in sorted(binding)}


def _valid_sha256_label(value: str) -> bool:
    digest = value.removeprefix("sha256:")
    return (
        value.startswith("sha256:")
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


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
    return {
        "pid": (
            pid
            if isinstance(pid, int)
            and not isinstance(pid, bool)
            and pid > 0
            else None
        )
    }


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
        _headers(len(raw)),
    )
    return [raw]


def _headers(content_length: int) -> list[tuple[str, str]]:
    return [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Content-Length", str(content_length)),
    ]


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
