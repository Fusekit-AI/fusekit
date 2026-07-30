"""Durable public hosted job snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from fusekit.errors import FuseKitError
from fusekit.hosted.job import HostedLaunchJob, hosted_launch_job_from_dict
from fusekit.security.redaction import (
    contains_durable_secret_text,
    contains_private_marker_text,
)

HOSTED_JOB_STORE_SCHEMA_VERSION = "fusekit.hosted-job-store.v1"
HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION = (
    "fusekit.hosted-job-store-stripe-webhook-receipt.v1"
)
HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION = (
    "fusekit.hosted-job-store-managed-start-response.v1"
)
HOSTED_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-stripe-webhook.v1"
HOSTED_STRIPE_WEBHOOK_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "action",
        "event_type",
        "accepted",
        "payment_applied",
        "job_id",
        "payment_status",
        "managed_worker_dispatch_unlocked",
        "worker_dispatch_sent",
        "next_required_proof",
        "receipt_statement",
        "secret_boundary",
    }
)
HOSTED_JOB_SCHEMA_VERSION = "fusekit.hosted-job.v1"
HOSTED_WORKER_DISPATCH_SCHEMA_VERSION = "fusekit.hosted-worker-dispatch.v1"
HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION = (
    "fusekit.hosted-worker-dispatch-receipt.v1"
)
MANAGED_FUSEKIT_RUN_LANE = "managed-fusekit-run"
HOSTED_JOB_STORE_SECRET_BOUNDARY = (
    "Hosted job snapshots contain public job state, lane contracts, public payment "
    "receipt labels, and hashes only. They must not contain Stripe keys, GitHub "
    "installation tokens, provider credentials, worker secrets, or vault material."
)
HOSTED_JOB_STORE_WEBHOOK_RECEIPT_BOUNDARY = (
    "Hosted Stripe webhook proof artifacts contain only the redacted webhook receipt, "
    "public job id, receipt hash, and schema labels. They must not contain Stripe keys, "
    "webhook signing secrets, raw payloads, card data, payment method ids, provider "
    "credentials, worker secrets, or vault material."
)
HOSTED_JOB_STORE_MANAGED_START_RESPONSE_BOUNDARY = (
    "Hosted managed start proof artifacts contain only the redacted start response, "
    "public job id, response hash, payment labels, and worker-dispatch acceptance. "
    "They must not contain signed job tokens, Stripe keys, webhook signing secrets, "
    "provider credentials, worker secrets, HMAC signatures, or vault material."
)

_HOSTED_JOB_ID_RE = re.compile(r"\Ahosted-[A-Za-z0-9_-]{8,160}\Z")
_OWNER_ONLY_DIR_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
_OWNER_ONLY_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
_MAX_PUBLIC_JSON_BYTES = 1_048_576


class HostedJobStore:
    """Filesystem-backed storage for public hosted job state."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = _normalized_store_root(root)

    def get(self, job_id: str) -> HostedLaunchJob | None:
        """Return a validated stored job, or None when it is absent."""

        path = self._job_path(job_id)
        try:
            payload = _read_public_json_object(path)
        except FileNotFoundError:
            return None
        if payload.get("schema_version") != HOSTED_JOB_STORE_SCHEMA_VERSION:
            raise FuseKitError("Hosted job store snapshot schema is unsupported.")
        job_payload = payload.get("job")
        if not isinstance(job_payload, dict):
            raise FuseKitError("Hosted job store snapshot is missing job state.")
        expected_hash = payload.get("job_sha256")
        actual_hash = _job_payload_hash(job_payload)
        if expected_hash != actual_hash:
            raise FuseKitError("Hosted job store snapshot hash mismatch.")
        job = hosted_launch_job_from_dict(job_payload)
        if job.job_id != job_id:
            raise FuseKitError("Hosted job store snapshot id mismatch.")
        return job

    def put(self, job: HostedLaunchJob) -> None:
        """Atomically write a validated public hosted job snapshot."""

        _validated_job_id(job.job_id)
        job_payload = job.to_dict()
        hosted_launch_job_from_dict(job_payload)
        _assert_public_job_snapshot(job_payload)
        payload: dict[str, object] = {
            "schema_version": HOSTED_JOB_STORE_SCHEMA_VERSION,
            "job_id": job.job_id,
            "job_sha256": _job_payload_hash(job_payload),
            "job": job_payload,
            "secret_boundary": HOSTED_JOB_STORE_SECRET_BOUNDARY,
        }
        _write_public_payload(
            self.root,
            self._job_path(job.job_id),
            payload,
            error="Hosted job store snapshot could not be written.",
        )

    def put_stripe_webhook_receipt(
        self,
        *,
        job_id: str,
        receipt: dict[str, object],
    ) -> Path:
        """Atomically write the redacted Stripe webhook receipt for live proof."""

        _validated_job_id(job_id)
        _validate_stripe_webhook_receipt(job_id=job_id, receipt=receipt)
        _assert_public_snapshot_text(json.dumps(receipt, sort_keys=True))
        payload = {
            "schema_version": HOSTED_JOB_STORE_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION,
            "job_id": job_id,
            "receipt_schema_version": receipt.get("schema_version"),
            "receipt_sha256": _job_payload_hash(receipt),
            "receipt": receipt,
            "secret_boundary": HOSTED_JOB_STORE_WEBHOOK_RECEIPT_BOUNDARY,
        }
        target = self.stripe_webhook_receipt_path(job_id)
        _write_public_payload(
            self.root,
            target,
            payload,
            error="Hosted Stripe webhook receipt could not be written.",
        )
        return target

    def put_managed_start_response(
        self,
        *,
        job_id: str,
        response: dict[str, object],
    ) -> Path:
        """Atomically write the redacted managed start response for live proof."""

        _validated_job_id(job_id)
        _validate_managed_start_response(job_id=job_id, response=response)
        _assert_public_snapshot_text(json.dumps(response, sort_keys=True))
        payload = {
            "schema_version": HOSTED_JOB_STORE_MANAGED_START_RESPONSE_SCHEMA_VERSION,
            "job_id": job_id,
            "response_schema_version": response.get("schema_version"),
            "response_sha256": _job_payload_hash(response),
            "response": response,
            "secret_boundary": HOSTED_JOB_STORE_MANAGED_START_RESPONSE_BOUNDARY,
        }
        target = self.managed_start_response_path(job_id)
        _write_public_payload(
            self.root,
            target,
            payload,
            error="Hosted managed start response could not be written.",
        )
        return target

    def status(self) -> dict[str, object]:
        """Return public readiness for the configured job store."""

        configured = bool(str(self.root))
        writable = False
        error = ""
        try:
            _ensure_store_root(self.root)
            fd, probe_name = tempfile.mkstemp(
                prefix=".fusekit-write-check.",
                suffix=".tmp",
                dir=self.root,
                text=True,
            )
            probe = Path(probe_name)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("ok\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(probe, _OWNER_ONLY_FILE_MODE)
            probe.unlink(missing_ok=True)
            writable = True
        except (OSError, FuseKitError) as exc:
            error = exc.__class__.__name__
        return {
            "configured": configured,
            "writable": writable,
            "path_configured": configured,
            "stores_public_snapshots_only": True,
            "secret_boundary": HOSTED_JOB_STORE_SECRET_BOUNDARY,
            **({"error": error} if error else {}),
        }

    def _job_path(self, job_id: str) -> Path:
        return self.root / f"{_validated_job_id(job_id)}.json"

    def stripe_webhook_receipt_path(self, job_id: str) -> Path:
        return self.root / f"{_validated_job_id(job_id)}.stripe-webhook-receipt.json"

    def managed_start_response_path(self, job_id: str) -> Path:
        return self.root / f"{_validated_job_id(job_id)}.managed-start-response.json"


def hosted_job_store_status(root: str) -> dict[str, object]:
    """Return public status for an optional hosted job store path."""

    if not root.strip():
        return {
            "configured": False,
            "writable": False,
            "path_configured": False,
            "stores_public_snapshots_only": True,
            "secret_boundary": HOSTED_JOB_STORE_SECRET_BOUNDARY,
        }
    return HostedJobStore(root).status()


def _normalized_store_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root)
    if not str(path).strip():
        raise FuseKitError("Hosted job store root is not configured.")
    if not path.is_absolute():
        raise FuseKitError("Hosted job store root must be an absolute path.")
    return path


def _validated_job_id(job_id: str) -> str:
    if not _HOSTED_JOB_ID_RE.fullmatch(job_id):
        raise FuseKitError("Hosted job store id is invalid.")
    return job_id


def _job_payload_hash(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _assert_public_job_snapshot(payload: dict[str, Any]) -> None:
    _assert_public_snapshot_text(json.dumps(payload, sort_keys=True))


def _assert_public_snapshot_text(text: str) -> None:
    if contains_durable_secret_text(text) or contains_private_marker_text(text):
        raise FuseKitError("Hosted job store snapshot contains private-looking text.")


def _read_public_json_object(path: Path) -> dict[str, object]:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise FuseKitError("Hosted job store snapshot is unreadable.") from exc
    if stat.S_ISLNK(file_stat.st_mode):
        raise FuseKitError("Hosted job store snapshot must be a regular file.")
    if not stat.S_ISREG(file_stat.st_mode):
        raise FuseKitError("Hosted job store snapshot must be a regular file.")
    if file_stat.st_size > _MAX_PUBLIC_JSON_BYTES:
        raise FuseKitError("Hosted job store snapshot is too large.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FuseKitError("Hosted job store snapshot is unreadable.") from exc
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise FuseKitError("Hosted job store snapshot must be a regular file.")
        if opened_stat.st_size > _MAX_PUBLIC_JSON_BYTES:
            raise FuseKitError("Hosted job store snapshot is too large.")
        raw = os.read(fd, _MAX_PUBLIC_JSON_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_PUBLIC_JSON_BYTES:
        raise FuseKitError("Hosted job store snapshot is too large.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuseKitError("Hosted job store snapshot is unreadable.") from exc
    if not isinstance(payload, dict):
        raise FuseKitError("Hosted job store snapshot is invalid.")
    return payload


def _validate_stripe_webhook_receipt(
    *,
    job_id: str,
    receipt: dict[str, object],
) -> None:
    if set(str(key) for key in receipt) != HOSTED_STRIPE_WEBHOOK_RECEIPT_KEYS:
        raise FuseKitError("Hosted Stripe webhook receipt shape is invalid.")
    if receipt.get("schema_version") != HOSTED_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION:
        raise FuseKitError("Hosted Stripe webhook receipt schema is unsupported.")
    if receipt.get("action") != "payment_webhook":
        raise FuseKitError("Hosted Stripe webhook receipt action is invalid.")
    if receipt.get("event_type") != "checkout.session.completed":
        raise FuseKitError("Hosted Stripe webhook receipt event type is invalid.")
    if receipt.get("accepted") is not True:
        raise FuseKitError("Hosted Stripe webhook receipt was not accepted.")
    if receipt.get("payment_applied") is not True:
        raise FuseKitError("Hosted Stripe webhook receipt did not apply payment.")
    if receipt.get("job_id") != job_id:
        raise FuseKitError("Hosted Stripe webhook receipt job id mismatch.")
    if receipt.get("payment_status") != "paid":
        raise FuseKitError("Hosted Stripe webhook receipt payment status is invalid.")
    if receipt.get("managed_worker_dispatch_unlocked") is not True:
        raise FuseKitError("Hosted Stripe webhook receipt did not unlock dispatch.")
    if receipt.get("worker_dispatch_sent") is not False:
        raise FuseKitError("Hosted Stripe webhook receipt must not dispatch workers.")


def _validate_managed_start_response(
    *,
    job_id: str,
    response: dict[str, object],
) -> None:
    if "job_token" in response:
        raise FuseKitError("Hosted managed start response must not contain job token.")
    if response.get("schema_version") != HOSTED_JOB_SCHEMA_VERSION:
        raise FuseKitError("Hosted managed start response schema is unsupported.")
    if response.get("job_id") != job_id:
        raise FuseKitError("Hosted managed start response job id mismatch.")
    if response.get("launch_lane") != MANAGED_FUSEKIT_RUN_LANE:
        raise FuseKitError("Hosted managed start response lane is invalid.")
    if response.get("status") != "waiting_for_provider_gates":
        raise FuseKitError("Hosted managed start response status is invalid.")
    payment = response.get("payment")
    if not isinstance(payment, dict):
        raise FuseKitError("Hosted managed start response payment is missing.")
    if payment.get("required") is not True or payment.get("status") != "paid":
        raise FuseKitError("Hosted managed start response payment is not paid.")
    receipt = payment.get("receipt")
    if not isinstance(receipt, dict):
        raise FuseKitError("Hosted managed start response payment receipt is missing.")
    if receipt.get("client_reference_id") != job_id:
        raise FuseKitError("Hosted managed start response payment job id mismatch.")
    metadata = receipt.get("metadata")
    if not isinstance(metadata, dict):
        raise FuseKitError("Hosted managed start response payment metadata is missing.")
    if metadata.get("job_id") != job_id:
        raise FuseKitError("Hosted managed start response payment metadata job mismatch.")
    if metadata.get("lane") != MANAGED_FUSEKIT_RUN_LANE:
        raise FuseKitError("Hosted managed start response payment metadata lane is invalid.")
    action_receipt = response.get("action_receipt")
    if not isinstance(action_receipt, dict) or action_receipt.get("action") != "start":
        raise FuseKitError("Hosted managed start response action receipt is invalid.")
    dispatch = response.get("worker_dispatch")
    if not isinstance(dispatch, dict):
        raise FuseKitError("Hosted managed start response dispatch receipt is missing.")
    if dispatch.get("schema_version") != HOSTED_WORKER_DISPATCH_SCHEMA_VERSION:
        raise FuseKitError("Hosted managed start response dispatch schema is invalid.")
    if dispatch.get("action") != "start":
        raise FuseKitError("Hosted managed start response dispatch action is invalid.")
    if dispatch.get("dispatched") is not True or dispatch.get("accepted") is not True:
        raise FuseKitError("Hosted managed start response dispatch was not accepted.")
    if dispatch.get("receiver_schema_version") != HOSTED_WORKER_DISPATCH_RECEIPT_SCHEMA_VERSION:
        raise FuseKitError("Hosted managed start response dispatch receiver is invalid.")
    binding = dispatch.get("dispatch_binding")
    if not isinstance(binding, dict):
        raise FuseKitError("Hosted managed start response dispatch binding is missing.")
    if binding.get("job_id") != job_id:
        raise FuseKitError("Hosted managed start response dispatch job id mismatch.")
    if binding.get("lane") != MANAGED_FUSEKIT_RUN_LANE:
        raise FuseKitError("Hosted managed start response dispatch lane is invalid.")
    if binding.get("payment_status") != "paid":
        raise FuseKitError("Hosted managed start response dispatch payment is invalid.")
    for field in ("plan_fingerprint", "stripe_price_id_hash", "price_label_hash"):
        if binding.get(field) != metadata.get(field):
            raise FuseKitError("Hosted managed start response dispatch binding mismatch.")
    idempotency = dispatch.get("idempotency")
    if not isinstance(idempotency, dict):
        raise FuseKitError("Hosted managed start response dispatch idempotency is missing.")
    if idempotency.get("mode") != "dispatch-state-dir":
        raise FuseKitError("Hosted managed start response dispatch idempotency is invalid.")
    if idempotency.get("durable") is not True:
        raise FuseKitError("Hosted managed start response dispatch idempotency is not durable.")
    if idempotency.get("scope") != "worker deployment":
        raise FuseKitError("Hosted managed start response dispatch idempotency scope is invalid.")
    proof = idempotency.get("proof")
    if not isinstance(proof, str) or "before worker spawn" not in proof:
        raise FuseKitError("Hosted managed start response dispatch idempotency proof is missing.")


def _write_public_payload(
    root: Path,
    target: Path,
    payload: dict[str, object],
    *,
    error: str,
) -> None:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    _assert_public_snapshot_text(serialized)
    tmp_path: Path | None = None
    try:
        _ensure_store_root(root)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.stem}.",
            suffix=".tmp",
            dir=root,
            text=True,
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, _OWNER_ONLY_FILE_MODE)
        os.replace(tmp_path, target)
        os.chmod(target, _OWNER_ONLY_FILE_MODE)
    except OSError as exc:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise FuseKitError(error) from exc


def _ensure_store_root(root: Path) -> None:
    try:
        root.mkdir(mode=_OWNER_ONLY_DIR_MODE, parents=True, exist_ok=True)
        root_stat = root.lstat()
    except OSError as exc:
        raise FuseKitError("Hosted job store root is unavailable.") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise FuseKitError("Hosted job store root must not be a symlink.")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise FuseKitError("Hosted job store root must be a directory.")
    try:
        os.chmod(root, _OWNER_ONLY_DIR_MODE)
    except OSError as exc:
        raise FuseKitError("Hosted job store root permissions could not be hardened.") from exc
