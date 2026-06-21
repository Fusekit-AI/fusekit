from __future__ import annotations

import hashlib
import hmac
import io
import json

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.worker_dispatch import (
    HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION,
    HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION,
    HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
    HostedWorkerDispatchSettings,
    accept_hosted_worker_dispatch,
    hosted_worker_dispatch_application,
    verify_hosted_worker_dispatch,
)

WORKER_SECRET = "hosted-worker-secret"


class FakeSpawned:
    pid = 4242


class FakeSpawner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def __call__(self, args: tuple[str, ...], env: dict[str, str]) -> FakeSpawned:
        self.calls.append((args, dict(env)))
        return FakeSpawned()


def test_verify_hosted_worker_dispatch_accepts_signed_envelope_without_leaks() -> None:
    body = _dispatch_body(action="start")
    dispatch = verify_hosted_worker_dispatch(
        body,
        signature=_signature(body),
        schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        secret=WORKER_SECRET,
    )

    assert dispatch.action == "start"
    assert dispatch.origin == "https://fusekit.snowmanai.org"
    assert dispatch.job_id == "hosted-test"
    assert dispatch.job_token == "signed-public-job-token"


def test_hosted_worker_dispatch_readiness_reports_presence_without_secrets() -> None:
    settings = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
    )
    readiness = settings.readiness()
    serialized = json.dumps(readiness)

    assert readiness["schema_version"] == HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION
    assert readiness["ready"] is True
    assert readiness["configured"] == {
        "FUSEKIT_HOSTED_WORKER_SECRET": True,
        "FUSEKIT_HOSTED_WORKER_ID": True,
        "FUSEKIT_HOSTED_WORKER_WORKSPACE": False,
    }
    assert readiness["required_runtime_env"] == [
        "FUSEKIT_HOSTED_WORKER_SECRET",
        "FUSEKIT_HOSTED_WORKER_ID",
    ]
    assert WORKER_SECRET not in serialized
    assert "signed-public-job-token" not in serialized


def test_hosted_worker_dispatch_readiness_reports_shape_errors_only() -> None:
    readiness = HostedWorkerDispatchSettings(
        worker_secret="short",
        worker_id="worker-01",
    ).readiness()
    serialized = json.dumps(readiness)

    assert readiness["ready"] is False
    assert readiness["invalid"] == ["hosted_worker_secret_too_short"]
    assert '"short"' not in serialized


def test_verify_hosted_worker_dispatch_rejects_tampering() -> None:
    body = _dispatch_body(action="rollback")

    with pytest.raises(FuseKitError, match="invalid_dispatch_signature"):
        verify_hosted_worker_dispatch(
            body.replace(b"rollback", b"detonate"),
            signature=_signature(body),
            schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            secret=WORKER_SECRET,
        )


def test_accept_hosted_worker_dispatch_spawns_env_backed_worker_and_redacts_receipt() -> None:
    body = _dispatch_body(action="detonate")
    dispatch = verify_hosted_worker_dispatch(
        body,
        signature=_signature(body),
        schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        secret=WORKER_SECRET,
    )
    spawner = FakeSpawner()
    settings = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        spawner=spawner,
    )

    receipt = accept_hosted_worker_dispatch(dispatch, settings=settings)
    serialized = json.dumps(receipt)
    args, env = spawner.calls[0]

    assert receipt["schema_version"] == HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION
    assert receipt["accepted"] is True
    assert receipt["action"] == "detonate"
    assert receipt["worker_command"] == [
        "<fusekit-hosted-worker>",
        "--origin",
        "https://fusekit.snowmanai.org",
        "--job-id",
        "hosted-test",
        "--action",
        "detonate",
        "--worker-id",
        "worker-01",
    ]
    assert args == (
        "fusekit-hosted-worker",
        "--origin",
        "https://fusekit.snowmanai.org",
        "--job-id",
        "hosted-test",
        "--action",
        "detonate",
        "--worker-id",
        "worker-01",
    )
    assert env["FUSEKIT_HOSTED_WORKER_SECRET"] == WORKER_SECRET
    assert env["FUSEKIT_HOSTED_JOB_TOKEN"] == "signed-public-job-token"
    assert WORKER_SECRET not in serialized
    assert "signed-public-job-token" not in serialized
    assert "sha256=" not in serialized


def test_hosted_worker_dispatch_wsgi_accepts_signed_post() -> None:
    body = _dispatch_body(action="start")
    spawner = FakeSpawner()
    app = hosted_worker_dispatch_application(
        HostedWorkerDispatchSettings(
            worker_secret=WORKER_SECRET,
            worker_id="worker-01",
            spawner=spawner,
        )
    )
    status_headers: dict[str, object] = {}

    response = b"".join(
        app(
            {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": "/dispatch",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
                "HTTP_X_FUSEKIT_DISPATCH_SIGNATURE": _signature(body),
                "HTTP_X_FUSEKIT_DISPATCH_SCHEMA": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            },
            lambda status, headers: status_headers.update(status=status, headers=headers),
        )
    )
    payload = json.loads(response.decode("utf-8"))

    assert status_headers["status"] == "202 Accepted"
    assert payload["schema_version"] == HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION
    assert payload["accepted"] is True
    assert payload["action"] == "start"
    assert len(spawner.calls) == 1


def test_hosted_worker_dispatch_wsgi_serves_readiness_without_secret_values() -> None:
    app = hosted_worker_dispatch_application(
        HostedWorkerDispatchSettings(
            worker_secret=WORKER_SECRET,
            worker_id="worker-01",
        )
    )
    status_headers: dict[str, object] = {}

    response = b"".join(
        app(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/readiness",
                "wsgi.input": io.BytesIO(b""),
            },
            lambda status, headers: status_headers.update(status=status, headers=headers),
        )
    )
    payload = json.loads(response.decode("utf-8"))

    assert status_headers["status"] == "200 OK"
    assert payload["schema_version"] == HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION
    assert payload["ready"] is True
    assert WORKER_SECRET not in response.decode("utf-8")


def _dispatch_body(*, action: str) -> bytes:
    return json.dumps(
        {
            "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            "action": action,
            "origin": "https://fusekit.snowmanai.org",
            "job_id": "hosted-test",
            "job_token": "signed-public-job-token",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _signature(body: bytes) -> str:
    digest = hmac.new(WORKER_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"
