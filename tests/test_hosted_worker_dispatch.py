from __future__ import annotations

import hashlib
import hmac
import io
import json
from pathlib import Path

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted.worker_dispatch import (
    HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES,
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
    assert dispatch.dispatch_binding == _dispatch_binding(action="start")


def test_verify_hosted_worker_dispatch_rejects_binding_drift() -> None:
    body = _dispatch_body(action="start", binding={"job_id": "hosted-other"})

    with pytest.raises(FuseKitError, match="dispatch_binding_job_id_mismatch"):
        verify_hosted_worker_dispatch(
            body,
            signature=_signature(body),
            schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            secret=WORKER_SECRET,
        )


def test_verify_hosted_worker_dispatch_rejects_unexpected_envelope_fields() -> None:
    body = _dispatch_body(
        action="start",
        envelope={"provider_token": "ghs_should_not_be_in_dispatch"},
    )

    with pytest.raises(FuseKitError, match="unexpected_dispatch_field"):
        verify_hosted_worker_dispatch(
            body,
            signature=_signature(body),
            schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            secret=WORKER_SECRET,
        )


def test_verify_hosted_worker_dispatch_rejects_unexpected_binding_fields() -> None:
    body = _dispatch_body(
        action="start",
        binding={"stripe_price_id": "price_should_not_be_in_dispatch"},
    )

    with pytest.raises(FuseKitError, match="unexpected_dispatch_binding_field"):
        verify_hosted_worker_dispatch(
            body,
            signature=_signature(body),
            schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            secret=WORKER_SECRET,
        )


def test_hosted_worker_dispatch_readiness_reports_presence_without_secrets() -> None:
    settings = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
    )
    readiness = settings.readiness()
    serialized = json.dumps(readiness)

    assert readiness["schema_version"] == HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION
    assert readiness["ready"] is True
    assert readiness["production_ready"] is False
    assert readiness["configured"] == {
        "FUSEKIT_HOSTED_WORKER_SECRET": True,
        "FUSEKIT_HOSTED_WORKER_ID": True,
        "FUSEKIT_HOSTED_WORKER_WORKSPACE": False,
        "FUSEKIT_HOSTED_WORKER_DISPATCH_STATE_DIR": False,
    }
    assert readiness["dispatch_binding"] == {
        "required": True,
        "required_fields": [
            "job_id",
            "action",
            "lane",
            "payment_status",
            "plan_fingerprint",
            "price_label_hash",
        ],
        "required_for_actions": ["start", "rollback", "detonate"],
        "lane": "managed-fusekit-run",
        "payment_status": "paid",
        "hash_fields": ["plan_fingerprint", "price_label_hash"],
        "secret_boundary": (
            "Dispatch binding contains only public job/action/lane/payment labels "
            "and SHA-256 public hashes; job tokens and worker secrets are excluded."
        ),
    }
    assert readiness["idempotency"] == {
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
    assert readiness["required_runtime_env"] == [
        "FUSEKIT_HOSTED_WORKER_SECRET",
        "FUSEKIT_HOSTED_WORKER_ID",
    ]
    assert WORKER_SECRET not in serialized
    assert "signed-public-job-token" not in serialized


def test_hosted_worker_dispatch_readiness_reports_durable_idempotency(tmp_path: Path) -> None:
    state_dir = tmp_path / "dispatch-state"
    state_dir.mkdir(mode=0o750)

    readiness = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        dispatch_state_dir=state_dir,
    ).readiness()
    serialized = json.dumps(readiness)

    assert readiness["ready"] is True
    assert readiness["production_ready"] is True
    assert readiness["idempotency"]["mode"] == "dispatch-state-dir"
    assert readiness["idempotency"]["durable"] is True
    assert readiness["idempotency"]["ready"] is True
    assert readiness["idempotency"]["scope"] == "worker deployment"
    assert readiness["idempotency"]["storage"]["exists"] is True
    assert readiness["idempotency"]["storage"]["directory"] is True
    assert readiness["idempotency"]["storage"]["symlink"] is False
    assert readiness["idempotency"]["storage"]["private_enough"] is True
    assert readiness["idempotency"]["storage"]["writable"] is True
    assert readiness["idempotency"]["blockers"] == []
    assert "private non-secret state directory before worker spawn" in readiness[
        "idempotency"
    ]["proof"]
    assert str(tmp_path) not in serialized
    assert WORKER_SECRET not in serialized


def test_hosted_worker_dispatch_readiness_blocks_missing_or_public_state_dir(
    tmp_path: Path,
) -> None:
    missing = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        dispatch_state_dir=tmp_path / "missing",
    ).readiness()
    public_dir = tmp_path / "public"
    public_dir.mkdir(mode=0o777)
    public_dir.chmod(0o777)
    public = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        dispatch_state_dir=public_dir,
    ).readiness()

    assert missing["production_ready"] is False
    assert missing["idempotency"]["blockers"] == ["worker_dispatch_state_dir_missing"]
    assert public["production_ready"] is False
    assert "worker_dispatch_state_dir_not_private_enough" in public["idempotency"][
        "blockers"
    ]


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


def test_verify_hosted_worker_dispatch_rejects_oversized_body_before_signature() -> None:
    body = b"{" + b'"padding":"' + (b"x" * HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES) + b'"}'

    with pytest.raises(FuseKitError, match="dispatch_body_too_large"):
        verify_hosted_worker_dispatch(
            body,
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
    assert receipt["duplicate"] is False
    assert receipt["action"] == "detonate"
    assert receipt["dispatch_binding"] == _dispatch_binding(action="detonate")
    assert receipt["idempotency"] == {
        "mode": "process",
        "durable": False,
        "scope": "process",
        "duplicate": False,
        "proof": "in-process dispatch guard accepted this job/action once.",
    }
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


def test_accept_hosted_worker_dispatch_is_idempotent_per_job_action(tmp_path: Path) -> None:
    body = _dispatch_body(action="start")
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
        dispatch_state_dir=tmp_path / "dispatch-state",
        spawner=spawner,
    )

    first = accept_hosted_worker_dispatch(dispatch, settings=settings)
    second = accept_hosted_worker_dispatch(dispatch, settings=settings)
    serialized = json.dumps(second)
    markers = list((tmp_path / "dispatch-state").glob("*.json"))
    marker_payload = json.loads(markers[0].read_text(encoding="utf-8"))

    assert first["duplicate"] is False
    assert second["accepted"] is True
    assert second["duplicate"] is True
    assert second["dispatch_binding"] == _dispatch_binding(action="start")
    assert second["spawned"] == {"pid": None}
    assert second["idempotency"] == {
        "mode": "dispatch-state-dir",
        "durable": True,
        "scope": "worker deployment",
        "duplicate": True,
        "proof": (
            "non-secret worker dispatch marker recorded in the configured state directory "
            "before worker spawn."
        ),
    }
    assert len(markers) == 1
    assert markers[0].stat().st_mode & 0o777 == 0o640
    assert marker_payload["origin"] == "https://fusekit.snowmanai.org"
    assert marker_payload["dispatch_binding"] == _dispatch_binding(action="start")
    assert "signed-public-job-token" not in json.dumps(marker_payload)
    assert (tmp_path / "dispatch-state").stat().st_mode & 0o777 in {0o700, 0o750}
    assert len(spawner.calls) == 1
    assert WORKER_SECRET not in serialized
    assert "signed-public-job-token" not in serialized


def test_accept_hosted_worker_dispatch_rejects_duplicate_marker_binding_drift(
    tmp_path: Path,
) -> None:
    first_body = _dispatch_body(action="start")
    drift_body = _dispatch_body(
        action="start",
        binding={"price_label_hash": "sha256:" + ("c" * 64)},
    )
    first_dispatch = verify_hosted_worker_dispatch(
        first_body,
        signature=_signature(first_body),
        schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        secret=WORKER_SECRET,
    )
    drift_dispatch = verify_hosted_worker_dispatch(
        drift_body,
        signature=_signature(drift_body),
        schema=HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
        secret=WORKER_SECRET,
    )
    spawner = FakeSpawner()
    settings = HostedWorkerDispatchSettings(
        worker_secret=WORKER_SECRET,
        worker_id="worker-01",
        dispatch_state_dir=tmp_path / "dispatch-state",
        spawner=spawner,
    )

    first = accept_hosted_worker_dispatch(first_dispatch, settings=settings)
    with pytest.raises(FuseKitError, match="hosted_worker_dispatch_marker_mismatch"):
        accept_hosted_worker_dispatch(drift_dispatch, settings=settings)

    assert first["duplicate"] is False
    assert len(spawner.calls) == 1


def test_accept_hosted_worker_dispatch_receipt_labels_workspace_idempotency(
    tmp_path: Path,
) -> None:
    body = _dispatch_body(action="start")
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
        workspace=tmp_path / "workspace",
        spawner=spawner,
    )

    receipt = accept_hosted_worker_dispatch(dispatch, settings=settings)
    serialized = json.dumps(receipt)

    assert receipt["idempotency"] == {
        "mode": "workspace",
        "durable": True,
        "scope": "worker workspace",
        "duplicate": False,
        "proof": (
            "non-secret worker dispatch marker recorded in the worker workspace "
            "before worker spawn."
        ),
    }
    assert str(tmp_path) not in serialized
    assert WORKER_SECRET not in serialized
    assert "signed-public-job-token" not in serialized


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
    headers = dict(status_headers["headers"])

    assert status_headers["status"] == "202 Accepted"
    _assert_dispatch_security_headers(headers)
    assert payload["schema_version"] == HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION
    assert payload["accepted"] is True
    assert payload["action"] == "start"
    assert len(spawner.calls) == 1


def test_hosted_worker_dispatch_wsgi_rejects_oversized_body_without_spawning() -> None:
    body = b"{}"
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
                "CONTENT_LENGTH": str(HOSTED_WORKER_DISPATCH_MAX_BODY_BYTES + 1),
                "wsgi.input": io.BytesIO(body),
                "HTTP_X_FUSEKIT_DISPATCH_SIGNATURE": _signature(body),
                "HTTP_X_FUSEKIT_DISPATCH_SCHEMA": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            },
            lambda status, headers: status_headers.update(status=status, headers=headers),
        )
    )
    payload = json.loads(response.decode("utf-8"))

    assert status_headers["status"] == "400 Bad Request"
    assert payload == {"error": "dispatch_body_too_large"}
    assert spawner.calls == []


def test_hosted_worker_dispatch_wsgi_rejects_truncated_body_without_spawning() -> None:
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
                "CONTENT_LENGTH": str(len(body) + 1),
                "wsgi.input": io.BytesIO(body),
                "HTTP_X_FUSEKIT_DISPATCH_SIGNATURE": _signature(body),
                "HTTP_X_FUSEKIT_DISPATCH_SCHEMA": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            },
            lambda status, headers: status_headers.update(status=status, headers=headers),
        )
    )
    payload = json.loads(response.decode("utf-8"))

    assert status_headers["status"] == "400 Bad Request"
    assert payload == {"error": "incomplete_request_body"}
    assert spawner.calls == []


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
    headers = dict(status_headers["headers"])

    assert status_headers["status"] == "200 OK"
    _assert_dispatch_security_headers(headers)
    assert payload["schema_version"] == HOSTED_WORKER_DISPATCH_READINESS_SCHEMA_VERSION
    assert payload["ready"] is True
    assert WORKER_SECRET not in response.decode("utf-8")


def _assert_dispatch_security_headers(headers: dict[str, str]) -> None:
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Permissions-Policy"] == (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def _dispatch_body(
    *,
    action: str,
    binding: dict[str, str] | None = None,
    envelope: dict[str, object] | None = None,
) -> bytes:
    return json.dumps(
        {
            "schema_version": HOSTED_WORKER_DISPATCH_SCHEMA_VERSION,
            "action": action,
            "origin": "https://fusekit.snowmanai.org",
            "job_id": "hosted-test",
            "job_token": "signed-public-job-token",
            "dispatch_binding": _dispatch_binding(action=action) | (binding or {}),
        }
        | (envelope or {}),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _dispatch_binding(*, action: str) -> dict[str, str]:
    return {
        "action": action,
        "job_id": "hosted-test",
        "lane": "managed-fusekit-run",
        "payment_status": "paid",
        "plan_fingerprint": "sha256:" + ("a" * 64),
        "price_label_hash": "sha256:" + ("b" * 64),
    }


def _signature(body: bytes) -> str:
    digest = hmac.new(WORKER_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"
