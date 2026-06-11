"""Live local control-room server."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Iterable
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse

from fusekit.audit import AuditLog
from fusekit.errors import FuseKitError
from fusekit.runner.control_room import (
    control_room_payload as build_control_room_payload,
)
from fusekit.runner.control_room import (
    render_control_room,
)
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState
from fusekit.security.url import require_safe_url
from fusekit.vault import Vault

VISUAL_DISPLAY_PATTERN = re.compile(r"^(?:[A-Za-z0-9_.-]+)?:[0-9]+(?:\.[0-9]+)?$")
CONTROL_ROOM_GATE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
TOKEN_PROVIDER_BY_ENV = {
    "CLOUDFLARE_API_TOKEN": "cloudflare",
    "GITHUB_TOKEN": "github",
    "OPENAI_API_KEY": "openai",
    "RESEND_API_KEY": "resend",
    "VERCEL_TOKEN": "vercel",
}
TOKEN_PREFIXES_BY_ENV = {
    "GITHUB_TOKEN": ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"),
    "OPENAI_API_KEY": ("sk-",),
    "RESEND_API_KEY": ("re_",),
}
PLACEHOLDER_TOKEN_VALUES = {
    "api key",
    "api_key",
    "copied",
    "hidden",
    "n/a",
    "none",
    "null",
    "redacted",
    "secret",
    "token",
    "undefined",
}
MASKED_TOKEN_PATTERN = re.compile(r"^(?:[*xX]|\u2022|\u25cf){6,}$")
SENSITIVE_BROWSER_ENV_MARKERS = (
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "KEY",
    "PASS",
    "PASSWORD",
    "SECRET",
    "SESSION",
    "TOKEN",
)
REMOTE_CONTROL_ROOM_TOKEN_ERROR = (
    "Remote control room token must be generated with secrets.token_urlsafe "
    "and contain at least 32 URL-safe characters."
)
CONTROL_ROOM_PERMISSIONS_POLICY = (
    "accelerometer=(), "
    "bluetooth=(), "
    "camera=(), "
    "geolocation=(), "
    "gyroscope=(), "
    "hid=(), "
    "magnetometer=(), "
    "microphone=(), "
    "payment=(), "
    "serial=(), "
    "usb=()"
)


def serve_control_room(job_state: Path, host: str = "127.0.0.1", port: int = 8765) -> str:
    """Serve a live control room until interrupted."""

    if not _is_loopback(host):
        if os.environ.get("FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM") != "1":
            raise FuseKitError(
                "Control room serves local job metadata and is local-only by default. "
                "Set FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM=1 to bind a non-loopback host."
            )
        token = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
        if not token:
            raise FuseKitError("Remote control room binding requires FUSEKIT_CONTROL_ROOM_TOKEN.")
        if not _safe_remote_control_room_token(token):
            raise FuseKitError(REMOTE_CONTROL_ROOM_TOKEN_ERROR)
    handler = _handler(job_state)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}"
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return url


def control_room_payload(job_state: Path) -> dict[str, Any]:
    """Return the live control-room payload."""

    job = JobState.load(job_state)
    return build_control_room_payload(job, gate_path=job_state.parent / "gates.json")


def _handler(job_state: Path) -> type[BaseHTTPRequestHandler]:
    action_token = _control_room_action_token(job_state)

    class ControlRoomHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(405)
            self._write_security_headers()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            route = urlparse(self.path)
            if not self._authorize_request(route):
                return
            if _should_clean_query_token(route, self):
                self._write_redirect(_clean_query_token_location(route))
                return
            if route.path == "/api/job":
                self._write_json(control_room_payload(job_state))
                return
            if route.path in {"/", "/index.html"}:
                job = JobState.load(job_state)
                csp_nonce = secrets.token_urlsafe(24)
                self._write_html(_live_html(job, job_state, csp_nonce), csp_nonce=csp_nonce)
                return
            self._write_not_found()

        def do_POST(self) -> None:  # noqa: N802
            route = urlparse(self.path)
            if not self._authorize_request(route):
                return
            if self.headers.get("x-fusekit-control-room") != "resume":
                self._write_json({"ok": False, "error": "missing control-room header"}, status=403)
                return
            if not _trusted_browser_origin(self.headers.get("Origin"), self.headers.get("Host")):
                self._write_json({"ok": False, "error": "untrusted origin"}, status=403)
                return
            if not _trusted_fetch_site(self.headers.get("Sec-Fetch-Site")):
                self._write_json({"ok": False, "error": "cross-site request"}, status=403)
                return
            if not _trusted_action_token(
                self.headers.get("x-fusekit-action-token"),
                action_token,
            ):
                self._write_json({"ok": False, "error": "invalid action token"}, status=403)
                return
            gate_id = _control_room_gate_id(route.path, "/pass")
            if gate_id is not None:
                if not gate_id:
                    self._write_not_found()
                    return
                service = GateService.load(job_state.parent / "gates.json")
                if gate_id not in service.records:
                    self._write_json({"ok": False, "error": "gate not found"}, status=404)
                    return
                gate = service.records[gate_id]
                blocked = _uncaptured_gate_targets(gate.target, gate.captured_targets)
                if blocked:
                    self._write_json(
                        {
                            "ok": False,
                            "gate_id": gate_id,
                            "error": (
                                "This gate needs safe secret capture before it can resume."
                            ),
                            "missing_targets": sorted(blocked),
                            "next_action": _blocked_capture_next_action(blocked),
                        },
                        status=400,
                    )
                    return
                service.request_resume(gate_id)
                gate = service.records[gate_id]
                _append_gate_audit(job_state, "control_room.gate_resume_requested", gate)
                self._write_json(
                    {
                        "ok": True,
                        "gate_id": gate_id,
                        "status": "resume_requested",
                        "message": _gate_resume_message(gate),
                    }
                )
                return
            gate_id = _control_room_gate_id(route.path, "/open")
            if gate_id is not None:
                if not gate_id:
                    self._write_not_found()
                    return
                service = GateService.load(job_state.parent / "gates.json")
                open_gate = service.records.get(gate_id)
                if open_gate is None:
                    self._write_json({"ok": False, "error": "gate not found"}, status=404)
                    return
                try:
                    safe_url = require_safe_url(open_gate.resume_url, label="Provider gate URL")
                except FuseKitError as exc:
                    self._write_json({"ok": False, "error": str(exc)}, status=400)
                    return
                if _active_gate_url_is_open(open_gate, safe_url):
                    _append_gate_audit(
                        job_state,
                        "control_room.gate_open",
                        open_gate,
                        reused=True,
                    )
                    self._write_json(
                        {
                            "ok": True,
                            "gate_id": gate_id,
                            "browser": "",
                            "reused": True,
                            "message": (
                                "Provider gate is already open in the shared VM browser. "
                                "Use the live VM browser instead of opening another tab."
                            ),
                        }
                    )
                    return
                try:
                    browser = _open_gate_url_in_visual_browser(job_state, safe_url)
                except FuseKitError as exc:
                    self._write_json({"ok": False, "error": str(exc)}, status=400)
                    return
                service.mark_opened(gate_id, safe_url)
                gate = service.records[gate_id]
                _append_gate_audit(job_state, "control_room.gate_open", gate, reused=False)
                self._write_json(
                    {
                        "ok": True,
                        "gate_id": gate_id,
                        "browser": _visual_browser_label(browser),
                        "reused": False,
                        "message": "Provider gate opened inside the shared VM browser.",
                    }
                )
                return
            gate_id = _control_room_gate_id(route.path, "/capture-clipboard")
            if gate_id is not None:
                if not gate_id:
                    self._write_not_found()
                    return
                try:
                    body = self._read_json_body()
                    captured = _capture_gate_clipboard_secret(
                        job_state,
                        gate_id,
                        str(body.get("target", "")),
                    )
                except FuseKitError as exc:
                    self._write_json({"ok": False, "error": str(exc)}, status=400)
                    return
                self._write_json({"ok": True, **captured})
                return
            self._write_not_found()

        def log_message(self, format: str, *args: object) -> None:
            return

        def _authorize_request(self, route: Any) -> bool:
            expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
            if not expected:
                return True
            if not _safe_remote_control_room_token(expected):
                self._write_json(
                    {"ok": False, "error": REMOTE_CONTROL_ROOM_TOKEN_ERROR},
                    status=403,
                )
                return False
            token = self._request_token(route)
            if token and secrets.compare_digest(token, expected):
                if token == _query_token(route):
                    self._set_control_room_cookie = True
                return True
            self._write_json({"ok": False, "error": "invalid control-room token"}, status=403)
            return False

        def _request_token(self, route: Any) -> str:
            query_token = _query_token(route)
            if query_token:
                return query_token
            authorization = self.headers.get("Authorization", "")
            if authorization.lower().startswith("bearer "):
                return authorization[7:].strip()
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                cookies = SimpleCookie()
                cookies.load(cookie_header)
                morsel = cookies.get("fusekit_control_room")
                if morsel is not None:
                    return morsel.value
            return ""

        def _write_json(self, payload: dict[str, Any], status: int = 200) -> None:
            data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers()
            self._write_control_room_cookie()
            self.end_headers()
            self.wfile.write(data)

        def _write_not_found(self) -> None:
            self.send_response(404)
            self.send_header("content-length", "0")
            self._write_security_headers()
            self._write_control_room_cookie()
            self.end_headers()

        def _write_html(self, html: str, *, csp_nonce: str = "") -> None:
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self._write_security_headers(csp_nonce=csp_nonce)
            self._write_control_room_cookie()
            self.end_headers()
            self.wfile.write(data)

        def _write_redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("location", location)
            self.send_header("content-length", "0")
            self._write_security_headers()
            self._write_control_room_cookie()
            self.end_headers()

        def _read_json_body(self) -> dict[str, Any]:
            content_type = self.headers.get("content-type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise FuseKitError("Control-room request body must use application/json.")
            try:
                length = int(self.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            if length > 4096:
                raise FuseKitError("Control-room request body is too large.")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise FuseKitError("Control-room request body must be JSON.") from exc
            if not isinstance(data, dict):
                raise FuseKitError("Control-room request body must be a JSON object.")
            return data

        def _write_control_room_cookie(self) -> None:
            expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
            if not expected or not getattr(self, "_set_control_room_cookie", False):
                return
            if not _safe_remote_control_room_token(expected):
                return
            self.send_header(
                "set-cookie",
                f"fusekit_control_room={expected}; HttpOnly; SameSite=Strict; Path=/",
            )

        def _write_security_headers(self, *, csp_nonce: str = "") -> None:
            if csp_nonce:
                style_src = f"'nonce-{csp_nonce}'"
                script_src = f"'nonce-{csp_nonce}'"
            else:
                style_src = "'none'"
                script_src = "'none'"
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.send_header("permissions-policy", CONTROL_ROOM_PERMISSIONS_POLICY)
            self.send_header("x-frame-options", "DENY")
            self.send_header(
                "content-security-policy",
                "default-src 'self'; "
                "connect-src 'self'; "
                "img-src 'self' data:; "
                "frame-src http: https:; "
                f"style-src {style_src}; "
                "style-src-attr 'none'; "
                f"script-src {script_src}; "
                "script-src-attr 'none'; "
                "base-uri 'none'; "
                "object-src 'none'; "
                "form-action 'none'; "
                "frame-ancestors 'none'",
            )

    return ControlRoomHandler


def _control_room_gate_id(path: str, suffix: str) -> str | None:
    """Return a safe gate id from a state-changing control-room route."""

    prefix = "/api/gates/"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    encoded = path[len(prefix) : -len(suffix)]
    decoded = unquote(encoded)
    if not CONTROL_ROOM_GATE_ID_PATTERN.fullmatch(decoded):
        return ""
    return decoded


def _live_html(job: JobState, job_state: Path, csp_nonce: str = "") -> str:
    return render_control_room(
        job,
        gate_path=job_state.parent / "gates.json",
        action_token=_control_room_action_token(job_state),
        csp_nonce=csp_nonce,
    )


def _control_room_action_token(job_state: Path) -> str:
    token_path = job_state.parent / "control-room-action-token"
    try:
        existing = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        existing = ""
    if _safe_action_token(existing):
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
        return existing
    token = secrets.token_urlsafe(32)
    try:
        token_path.write_text(token, encoding="utf-8")
        os.chmod(token_path, 0o600)
    except OSError:
        return token
    return token


def _open_gate_url_in_visual_browser(job_state: Path, url: str) -> str:
    safe_url = require_safe_url(url, label="Provider gate URL")
    browser = _visual_browser_binary()
    if not browser:
        raise FuseKitError("No VM browser binary is available for provider gate launch.")
    profile_dir = _shared_visual_provider_profile(job_state)
    try:
        profile_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FuseKitError(f"Could not prepare VM browser profile: {exc}") from exc
    display = _visual_display(job_state)
    command = [
        browser,
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
            env=_visual_browser_env(display),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise FuseKitError(f"Could not open provider gate in VM browser: {exc}") from exc
    return browser


def _shared_visual_provider_profile(job_state: Path) -> Path:
    configured = os.environ.get("FUSEKIT_PROVIDER_BROWSER_PROFILE", "").strip()
    if configured:
        configured_path = Path(configured)
        if configured_path.is_absolute():
            return configured_path
        return job_state.parent.parent / configured_path
    return job_state.parent.parent / "visual" / "chrome-provider-profile"


def _active_gate_url_is_open(gate: Any, safe_url: str) -> bool:
    """Return whether this active gate already owns the shared VM browser tab."""

    if str(getattr(gate, "last_opened_url", "") or "") != safe_url:
        return False
    opened_at = float(getattr(gate, "last_opened_at", 0.0) or 0.0)
    if opened_at <= 0:
        return False
    status = str(getattr(gate, "status", "") or "").strip().lower()
    return status in {"waiting", "resurfaced", "resume_requested"}


def _capture_gate_clipboard_secret(
    job_state: Path,
    gate_id: str,
    target: str,
) -> dict[str, Any]:
    service = GateService.load(job_state.parent / "gates.json")
    gate = service.records.get(gate_id)
    if gate is None:
        raise FuseKitError("Gate not found.")
    if gate.status == "resume_requested":
        raise FuseKitError(
            "Gate already captured all required values and is waiting for verification. "
            "Wait for FuseKit to continue or follow the next guided gate."
        )
    if gate.status not in {"waiting", "resurfaced"}:
        raise FuseKitError("Gate is not waiting for capture. Follow the visible next step.")
    target = target.strip().upper()
    allowed_targets = _gate_capture_targets(gate.target)
    if target not in allowed_targets:
        allowed = _capture_button_labels(allowed_targets)
        raise FuseKitError(
            "This gate is not allowed to capture that value. Use the matching "
            f"visible button: {allowed}."
        )
    _validate_gate_capture_target(gate, target)
    value = _vm_clipboard_text(job_state).strip()
    if not value:
        raise FuseKitError(
            "The VM clipboard is empty. Copy the provider value inside the VM browser, "
            f"then click Capture {target} from VM clipboard again."
        )
    if len(value) > 8192:
        raise FuseKitError(
            "The VM clipboard value is too large to capture. Copy only the provider value "
            f"inside the VM browser, then click Capture {target} from VM clipboard again."
        )
    if "\x00" in value:
        raise FuseKitError(
            "The VM clipboard value is not valid text. Copy the provider value inside "
            f"the VM browser, then click Capture {target} from VM clipboard again."
        )
    _validate_clipboard_capture_value(target, value)
    vault_path = _job_vault_path(job_state)
    passphrase = _control_room_vault_passphrase(job_state)
    vault = Vault.open(vault_path, passphrase) if vault_path.exists() else Vault.empty()
    record_id, kind, provider = _capture_record_for_target(gate.provider, target)
    vault.put(record_id, kind, provider, target, value, {"env": target, "source": "vm-clipboard"})
    canonical_record_id = _canonical_provider_token_record(provider, target)
    if canonical_record_id and canonical_record_id != record_id:
        vault.put(
            canonical_record_id,
            "provider_token",
            provider,
            f"{provider} API token",
            value,
            {"env": target, "source": "vm-clipboard", "alias_of": record_id},
        )
    vault.save(vault_path, passphrase)
    service.mark_captured(gate_id, target)
    gate = service.records[gate_id]
    captured_targets = set(gate.captured_targets)
    status = "captured"
    message = (
        f"{target} captured into the encrypted vault. "
        "Capture the remaining required values to continue."
    )
    if allowed_targets.issubset(captured_targets):
        service.request_resume(gate_id)
        status = "resume_requested"
        message = (
            "All required values were captured into the encrypted vault. "
            "FuseKit will retry provider verification."
        )
    _append_capture_audit(job_state, gate_id, target, record_id)
    return {
        "gate_id": gate_id,
        "target": target,
        "record_id": record_id,
        "status": status,
        "captured_targets": sorted(captured_targets),
        "message": message,
    }


def _gate_resume_message(gate: Any) -> str:
    next_action = str(getattr(gate, "next_action", "") or "").strip()
    if next_action:
        return next_action
    classification = str(getattr(gate, "classification", "") or "").lower()
    provider = str(getattr(gate, "provider", "") or "").lower()
    if classification == "dns-approval" or provider == "dns":
        return "FuseKit is applying the approved DNS records now."
    if classification == "setup-approval" or provider == "fusekit":
        return "FuseKit is continuing with the approved setup plan now."
    return "Resume requested. FuseKit will retry provider verification."


def _gate_capture_targets(raw_target: str) -> set[str]:
    return {
        item
        for item in (part.strip().upper() for part in raw_target.split(","))
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", item) and "_" in item
    }


def _validate_gate_capture_target(gate: Any, target: str) -> None:
    """Reject stale capture gates that should be provider API setup retries."""

    provider = str(getattr(gate, "provider", "") or "").strip().lower()
    normalized_target = target.strip().upper()
    if (
        provider == "resend"
        and normalized_target in {"RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"}
    ):
        raise FuseKitError(
            f"{normalized_target} is generated by Resend API setup. Capture only "
            "RESEND_API_KEY from VM clipboard, then let FuseKit retry Resend setup "
            "and apply generated values. Do not create Resend domains or audiences by hand."
        )


def _capture_retry_action(target: str, value_name: str = "provider value") -> str:
    return (
        f"Copy only the {value_name} inside the VM browser, then click "
        f"Capture {target} from VM clipboard again."
    )


def _validate_clipboard_capture_value(target: str, value: str) -> None:
    """Reject obvious wrong clipboard values before they enter the encrypted vault."""

    normalized_target = target.strip().upper()
    if normalized_target.endswith(("_API_KEY", "_TOKEN")):
        if _looks_like_placeholder_token(value):
            raise FuseKitError(
                f"{normalized_target} looks like a placeholder or masked value, not a "
                "copy-once token. "
                f"{_capture_retry_action(normalized_target, 'real token value')}"
            )
        if value.lstrip().startswith(("{", "[", "<")):
            raise FuseKitError(
                f"{normalized_target} looks like copied page or response text, not a token. "
                f"{_capture_retry_action(normalized_target, 'copy-once token value')}"
            )
        if re.search(r"\s", value):
            raise FuseKitError(
                f"{normalized_target} must be one copied token with no spaces or line breaks. "
                f"{_capture_retry_action(normalized_target, 'copy-once token')}"
            )
        if value.lower().startswith(("http://", "https://")):
            raise FuseKitError(
                f"{normalized_target} looks like a URL. "
                f"{_capture_retry_action(normalized_target, 'provider key value')}"
            )
        if "," in value or ";" in value:
            raise FuseKitError(
                f"{normalized_target} looks like multiple copied values, not one token. "
                f"{_capture_retry_action(normalized_target, 'single provider key value')}"
            )
        if len(value) < 8:
            raise FuseKitError(
                f"{normalized_target} is too short to be a provider token. "
                f"{_capture_retry_action(normalized_target, 'full provider token')}"
            )
        expected_prefixes = TOKEN_PREFIXES_BY_ENV.get(normalized_target, ())
        if expected_prefixes and not value.startswith(expected_prefixes):
            readable = " or ".join(expected_prefixes)
            raise FuseKitError(
                f"{normalized_target} does not look like the expected provider token. "
                f"Copy the value that starts with {readable} inside the VM browser, "
                f"then click Capture {normalized_target} from VM clipboard again."
            )
        _reject_cross_provider_token_prefix(normalized_target, value)
    if normalized_target == "RESEND_FROM_EMAIL":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise FuseKitError(
                "RESEND_FROM_EMAIL must be a single sender email address. "
                f"{_capture_retry_action(normalized_target, 'sender email address')}"
            )
    if normalized_target == "RESEND_AUDIENCE_ID":
        if re.search(r"\s", value) or len(value) < 3:
            raise FuseKitError(
                "RESEND_AUDIENCE_ID must be one copied audience id. "
                f"{_capture_retry_action(normalized_target, 'audience id')}"
            )


def _reject_cross_provider_token_prefix(target: str, value: str) -> None:
    for prefix_target, prefixes in TOKEN_PREFIXES_BY_ENV.items():
        if prefix_target == target:
            continue
        if value.startswith(prefixes):
            source = prefix_target.removesuffix("_API_KEY").removesuffix("_TOKEN")
            raise FuseKitError(
                f"{target} looks like a {source} token. Copy the value from the "
                "provider page named by this gate inside the VM browser, then click "
                f"Capture {target} from VM clipboard again."
            )


def _looks_like_placeholder_token(value: str) -> bool:
    candidate = value.strip()
    lowered = candidate.lower()
    return (
        lowered in PLACEHOLDER_TOKEN_VALUES
        or MASKED_TOKEN_PATTERN.fullmatch(candidate) is not None
    )


def _uncaptured_gate_targets(
    raw_target: str,
    captured_targets: tuple[str, ...],
) -> set[str]:
    """Return capture targets that must exist before a gate can resume."""

    required = _gate_capture_targets(raw_target)
    captured = {target.strip().upper() for target in captured_targets}
    return required - captured


def _blocked_capture_next_action(missing_targets: set[str]) -> str:
    """Return visible launcher guidance when a user clicks resume too early."""

    targets = sorted(missing_targets)
    if not targets:
        return "Use the matching launcher control to continue this gate."
    if len(targets) == 1:
        return f"Click Capture {targets[0]} from VM clipboard, then FuseKit will continue."
    return (
        "Click these exact Capture buttons: "
        + _capture_button_labels(targets)
        + ". FuseKit continues after every required value is captured."
    )


def _capture_button_labels(targets: Iterable[str]) -> str:
    """Return exact visible clipboard-capture button labels for targets."""

    labels = [
        f"Capture {target.strip().upper()} from VM clipboard"
        for target in sorted(targets)
        if target.strip()
    ]
    if not labels:
        return (
            "the visible env-named Capture button, for example "
            "Capture RESEND_API_KEY from VM clipboard"
        )
    return ", ".join(labels)


def _vm_clipboard_text(job_state: Path) -> str:
    display = _visual_display(job_state)
    for command in (("xclip", "-selection", "clipboard", "-o"), ("xsel", "-ob")):
        if not shutil.which(command[0]):
            continue
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env=_visual_browser_env(display),
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return completed.stdout
    raise FuseKitError("Could not read the VM clipboard.")


def _job_vault_path(job_state: Path) -> Path:
    try:
        job = JobState.load(job_state)
    except (OSError, ValueError):
        job = None
    if job is not None:
        vault = job.artifacts.get("vault")
        if vault:
            return Path(vault)
    return job_state.parent / "fusekit.vault.json"


def _control_room_vault_passphrase(job_state: Path) -> str:
    candidates = [Path(os.environ.get("FUSEKIT_PASSPHRASE_FILE", ""))]
    try:
        job = JobState.load(job_state)
    except (OSError, ValueError):
        job = None
    if job is not None:
        passphrase_file = job.artifacts.get("passphrase_file")
        if passphrase_file:
            candidates.append(Path(passphrase_file))
    candidates.append(job_state.parent.parent.parent / "passphrase")
    for path in candidates:
        if str(path) and path.is_file():
            return path.read_text(encoding="utf-8").strip()
    raise FuseKitError("Vault passphrase file is not available to the control room.")


def _capture_record_for_target(
    gate_provider: str,
    target: str,
) -> tuple[str, str, str]:
    provider = _capture_provider_for_target(gate_provider, target)
    if target.endswith("_API_KEY") or target.endswith("_TOKEN"):
        record_id = f"provider.{provider}.{target.lower()}"
        return record_id, "provider_token", provider
    record_id = f"app.{provider}.{target.lower()}"
    return record_id, "app_env", provider


def _capture_provider_for_target(gate_provider: str, target: str) -> str:
    normalized_target = target.strip().upper()
    canonical_provider = TOKEN_PROVIDER_BY_ENV.get(normalized_target)
    if canonical_provider:
        return canonical_provider
    return gate_provider.strip().lower() or target.split("_", 1)[0].lower()


def _canonical_provider_token_record(provider: str, target: str) -> str:
    """Return the provider token alias older setup loops expect after capture."""

    if target.endswith("_API_KEY") or target.endswith("_TOKEN"):
        return f"provider.{provider}.token"
    return ""


def _append_gate_audit(
    job_state: Path,
    event: str,
    gate: Any,
    **extra: Any,
) -> None:
    payload = _gate_audit_payload(gate)
    payload["protected_action"] = True
    payload.update(extra)
    _append_control_room_audit(job_state, event, payload)


def _gate_audit_payload(gate: Any) -> dict[str, Any]:
    target = str(getattr(gate, "target", "") or "")
    captured_targets = getattr(gate, "captured_targets", ())
    if not isinstance(captured_targets, tuple):
        captured_targets = ()
    return {
        "gate_id": str(getattr(gate, "id", "") or ""),
        "provider": str(getattr(gate, "provider", "") or ""),
        "classification": str(getattr(gate, "classification", "") or ""),
        "status": str(getattr(gate, "status", "") or ""),
        "attempts": int(getattr(gate, "attempts", 0) or 0),
        "target_count": len(_gate_capture_targets(target)),
        "captured_count": len(captured_targets),
        "has_resume_url": bool(str(getattr(gate, "resume_url", "") or "")),
        "has_last_opened_url": bool(str(getattr(gate, "last_opened_url", "") or "")),
    }


def _append_capture_audit(
    job_state: Path,
    gate_id: str,
    target: str,
    record_id: str,
) -> None:
    _append_control_room_audit(
        job_state,
        "control_room.clipboard_capture",
        {
            "gate_id": gate_id,
            "target": target,
            "record_id": record_id,
            "protected_action": True,
            "source": "vm-clipboard",
            "storage": "encrypted-vault",
        },
    )


def _append_control_room_audit(
    job_state: Path,
    event: str,
    payload: dict[str, Any],
) -> None:
    try:
        job = JobState.load(job_state)
    except (OSError, ValueError):
        job = None
    audit_path = job.artifacts.get("audit_log") if job is not None else ""
    path = Path(audit_path) if audit_path else job_state.parent / "audit.jsonl"
    try:
        AuditLog(path).record(event, payload)
    except OSError:
        return


def _visual_browser_binary() -> str:
    configured = os.environ.get("FUSEKIT_VISUAL_BROWSER", "").strip()
    configured_binary = _configured_visual_browser_binary(configured)
    if configured_binary:
        return configured_binary
    for root in (
        Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")),
        Path("/opt/fusekit-playwright-browsers"),
    ):
        if not str(root):
            continue
        for candidate in sorted(root.glob("chromium-*/chrome-linux*/chrome")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    for name in ("google-chrome", "google-chrome-stable", "chromium-browser", "chromium"):
        resolved = shutil.which(name)
        if resolved and _is_supported_visual_browser_binary(resolved):
            return resolved
    return ""


def _configured_visual_browser_binary(configured: str) -> str:
    if not configured or not _is_supported_visual_browser_binary(configured):
        return ""
    if os.sep in configured or (os.altsep and os.altsep in configured):
        candidate = Path(configured)
        return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else ""
    resolved = shutil.which(configured)
    if resolved and _is_supported_visual_browser_binary(resolved):
        return resolved
    return ""


def _is_supported_visual_browser_binary(path: str) -> bool:
    """Return whether a configured browser path is a Chrome/Chromium executable."""

    name = Path(path).name.lower()
    if name in {"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}:
        return True
    return "chrome" in name or "chromium" in name


def _visual_browser_label(path: str) -> str:
    return Path(path).name or "chrome"


def _visual_browser_env(display: str) -> dict[str, str]:
    """Return a browser environment without provider or vault secrets."""

    env = {
        key: value
        for key, value in os.environ.items()
        if not _is_sensitive_browser_env_name(key)
    }
    env["DISPLAY"] = display
    return env


def _is_sensitive_browser_env_name(name: str) -> bool:
    upper_name = name.upper()
    if upper_name == "XAUTHORITY":
        return False
    return any(marker in upper_name for marker in SENSITIVE_BROWSER_ENV_MARKERS)


def _visual_display(job_state: Path) -> str:
    visual_path = job_state.parent / "visual.json"
    try:
        visual = json.loads(visual_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        visual = {}
    if isinstance(visual, dict):
        display = str(visual.get("display", "") or "").strip()
        if display and _safe_visual_display(display):
            return display
    env_display = os.environ.get("FUSEKIT_VISUAL_DISPLAY", "").strip()
    if env_display and _safe_visual_display(env_display):
        return env_display
    return ":99"


def _safe_visual_display(value: str) -> bool:
    return bool(VISUAL_DISPLAY_PATTERN.fullmatch(value))


def _is_loopback(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "localhost", "::1"}


def _trusted_browser_origin(origin: str | None, host: str | None) -> bool:
    """Allow same-origin browser posts while preserving curl/test compatibility."""

    if not origin:
        return True
    parsed_origin = urlparse(origin.strip())
    if (
        parsed_origin.scheme not in {"http", "https"}
        or not parsed_origin.netloc
        or parsed_origin.username
        or parsed_origin.password
        or parsed_origin.path
        or parsed_origin.params
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        return False
    origin_authority = _parsed_host_port(parsed_origin)
    host_authority = _header_host_port(host or "")
    if origin_authority is None or host_authority is None:
        return False
    origin_host, origin_port = origin_authority
    host_name, host_port = host_authority
    same_origin = origin_host == host_name and (
        host_port is None or origin_port == host_port
    )
    if os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN") and same_origin:
        return True
    return same_origin and _is_loopback(host_name)


def _trusted_fetch_site(value: str | None) -> bool:
    """Reject browser-declared cross-site state changes."""

    if not value:
        return True
    return value.strip().lower() in {"same-origin", "none"}


def _trusted_action_token(value: str | None, expected: str) -> bool:
    """Require explicit action intent for every state-changing request."""

    return value is not None and secrets.compare_digest(value, expected)


def _safe_action_token(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{32,256}", value))


def _safe_remote_control_room_token(value: str) -> bool:
    return _safe_action_token(value)


def _query_token(route: Any) -> str:
    values = parse_qs(getattr(route, "query", ""), keep_blank_values=False).get("token", [])
    return values[0] if values else ""


def _should_clean_query_token(route: Any, handler: Any) -> bool:
    if not _query_token(route):
        return False
    expected = os.environ.get("FUSEKIT_CONTROL_ROOM_TOKEN", "")
    return bool(
        getattr(handler, "_set_control_room_cookie", False)
    ) and _safe_remote_control_room_token(expected)


def _clean_query_token_location(route: Any) -> str:
    query = urlencode(
        [
            (key, value)
            for key, value in parse_qsl(getattr(route, "query", ""), keep_blank_values=False)
            if key != "token"
        ]
    )
    path = getattr(route, "path", "") or "/"
    return f"{path}?{query}" if query else path


def _hostname_without_port(value: str) -> str:
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    return value.split(":", 1)[0]


def _parsed_host_port(route: Any) -> tuple[str, int | None] | None:
    try:
        hostname = getattr(route, "hostname", None)
        port = getattr(route, "port", None)
    except ValueError:
        return None
    if not hostname:
        return None
    return hostname.strip().lower().strip("[]"), port


def _header_host_port(value: str) -> tuple[str, int | None] | None:
    parsed = urlparse(f"//{value.strip()}")
    return _parsed_host_port(parsed)
