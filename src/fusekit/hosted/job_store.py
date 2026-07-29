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
HOSTED_STRIPE_WEBHOOK_RECEIPT_SCHEMA_VERSION = "fusekit.hosted-stripe-webhook.v1"
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

_HOSTED_JOB_ID_RE = re.compile(r"\Ahosted-[A-Za-z0-9_-]{8,160}\Z")
_OWNER_ONLY_DIR_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
_OWNER_ONLY_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR


class HostedJobStore:
    """Filesystem-backed storage for public hosted job state."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = _normalized_store_root(root)

    def get(self, job_id: str) -> HostedLaunchJob | None:
        """Return a validated stored job, or None when it is absent."""

        path = self._job_path(job_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FuseKitError("Hosted job store snapshot is unreadable.") from exc
        if not isinstance(payload, dict):
            raise FuseKitError("Hosted job store snapshot is invalid.")
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

    def status(self) -> dict[str, object]:
        """Return public readiness for the configured job store."""

        configured = bool(str(self.root))
        writable = False
        error = ""
        try:
            self.root.mkdir(mode=_OWNER_ONLY_DIR_MODE, parents=True, exist_ok=True)
            os.chmod(self.root, _OWNER_ONLY_DIR_MODE)
            probe = self.root / ".fusekit-write-check"
            probe.write_text("ok\n", encoding="utf-8")
            os.chmod(probe, _OWNER_ONLY_FILE_MODE)
            probe.unlink()
            writable = True
        except OSError as exc:
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


def _validate_stripe_webhook_receipt(
    *,
    job_id: str,
    receipt: dict[str, object],
) -> None:
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
        root.mkdir(mode=_OWNER_ONLY_DIR_MODE, parents=True, exist_ok=True)
        os.chmod(root, _OWNER_ONLY_DIR_MODE)
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
